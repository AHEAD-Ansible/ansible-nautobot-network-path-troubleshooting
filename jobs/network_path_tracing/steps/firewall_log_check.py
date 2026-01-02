"""Step: Optional Panorama firewall traffic log check (DENY logs)."""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional

from ..config import NetworkPathSettings
from ..interfaces.palo_alto import PaloAltoClient


_QUERY_PARAM_SECRET_RE = re.compile(r"(\b(?:key|user|password)=)[^&\s]+", re.IGNORECASE)


def _redact_secret_query_params(text: str) -> str:
    """Redact common Palo Alto secret query params in arbitrary strings."""

    return _QUERY_PARAM_SECRET_RE.sub(r"\1***redacted***", text)


def _redact_known_secrets(text: str, *, secrets: tuple[str, ...]) -> str:
    """Redact known secret values from arbitrary strings."""

    redacted = text
    for secret in secrets:
        if not secret:
            continue
        redacted = redacted.replace(secret, "***redacted***")
    return redacted


def _env_positive_int(name: str, default: int) -> int:
    """Return integer value from environment or default, enforcing >= 1."""

    raw = os.getenv(name)
    if raw is None:
        return default
    raw = raw.strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value >= 1 else default


class FirewallLogCheckStep:
    """Query Panorama traffic logs for DENY entries matching src/dst/port.

    This step is best-effort: runtime failures are converted to an `"error"` payload
    instead of raising and crashing the entire network path trace.
    """

    _PROVIDER = "panorama"
    _SINCE_HOURS = 24
    _MAX_RESULTS = 10
    _ACTION = "deny"

    def __init__(self, logger: Optional[logging.Logger] = None):
        self._logger = logger

    @classmethod
    def disabled_payload(cls) -> Dict[str, Any]:
        """Return the stable payload used when the check is disabled."""

        return {
            "enabled": False,
            "status": "disabled",
            "provider": cls._PROVIDER,
            "panorama": None,
            "query": None,
            "found": False,
            "entries": [],
            "message": "Panorama log check disabled.",
            "errors": [],
        }

    def run(
        self,
        settings: NetworkPathSettings,
        *,
        panorama_host: str,
        destination_port: int,
        panorama_name: Optional[str] = None,
        max_wait_seconds: Optional[int] = None,
        fetch_limit: Optional[int] = None,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute the Panorama DENY log check and return the `firewall_logs` payload object."""

        host = (panorama_host or "").strip()
        safe_max_results = max_results
        try:
            if safe_max_results is not None:
                safe_max_results = int(safe_max_results)
        except (TypeError, ValueError):
            safe_max_results = None
        if safe_max_results is None or safe_max_results < 1:
            safe_max_results = self._MAX_RESULTS

        safe_max_wait_seconds = max_wait_seconds
        try:
            if safe_max_wait_seconds is not None:
                safe_max_wait_seconds = int(safe_max_wait_seconds)
        except (TypeError, ValueError):
            safe_max_wait_seconds = None
        if safe_max_wait_seconds is None or safe_max_wait_seconds < 1:
            safe_max_wait_seconds = _env_positive_int("PANORAMA_LOG_QUERY_MAX_WAIT_SECONDS", 30)

        safe_fetch_limit = fetch_limit
        try:
            if safe_fetch_limit is not None:
                safe_fetch_limit = int(safe_fetch_limit)
        except (TypeError, ValueError):
            safe_fetch_limit = None
        if safe_fetch_limit is None or safe_fetch_limit < 1:
            safe_fetch_limit = _env_positive_int("PANORAMA_LOG_QUERY_FETCH_LIMIT", safe_max_results)
        query: Dict[str, Any] = {
            "source_ip": settings.source_ip,
            "destination_ip": settings.destination_ip,
            "destination_port": int(destination_port),
            "since_hours": self._SINCE_HOURS,
            "max_results": safe_max_results,
            "action": self._ACTION,
            "max_wait_seconds": safe_max_wait_seconds,
            "fetch_limit": safe_fetch_limit,
        }
        panorama: Dict[str, Any] = {"name": panorama_name, "host": host}

        if not host:
            return self._error_payload(
                panorama=panorama,
                query=query,
                error="Panorama host is required when firewall log check is enabled.",
            )

        if destination_port < 0 or destination_port > 65535:
            return self._error_payload(
                panorama=panorama,
                query=query,
                error=f"Invalid destination port '{destination_port}' (expected integer 0-65535).",
            )

        pa_settings = settings.pa_settings()
        if pa_settings is None:
            return self._error_payload(
                panorama=panorama,
                query=query,
                error="Palo Alto credentials are not configured (set PA_USERNAME/PA_PASSWORD).",
            )

        client = PaloAltoClient(
            host,
            verify_ssl=pa_settings.verify_ssl,
            logger=self._logger,
        )

        try:
            api_key = client.keygen(pa_settings.username, pa_settings.password)
        except Exception as exc:
            safe_error = _redact_secret_query_params(str(exc))
            safe_error = _redact_known_secrets(
                safe_error,
                secrets=(pa_settings.username, pa_settings.password),
            )
            if self._logger:
                self._logger.debug(
                    "Panorama firewall log check failed during keygen: %s",
                    safe_error,
                    extra={"grouping": "firewall-log-check"},
                )
            return self._error_payload(panorama=panorama, query=query, error=safe_error)

        entries: list[dict[str, Any]]
        retry_suffix = ""
        retried_with_fetch_limit_1 = False
        try:
            entries = client.traffic_logs_deny_for_flow(
                api_key,
                src_ip=settings.source_ip,
                dst_ip=settings.destination_ip,
                dst_port=destination_port,
                since_hours=self._SINCE_HOURS,
                max_results=safe_max_results,
                max_wait_seconds=safe_max_wait_seconds,
                fetch_limit=safe_fetch_limit,
            )
        except Exception as exc:
            safe_error = _redact_secret_query_params(str(exc))
            safe_error = _redact_known_secrets(
                safe_error,
                secrets=(pa_settings.username, pa_settings.password),
            )

            if "timed out after" in safe_error.lower() and safe_fetch_limit > 1:
                retried_with_fetch_limit_1 = True
                if self._logger:
                    self._logger.debug(
                        "Panorama traffic log query timed out with fetch_limit=%s; retrying with fetch_limit=1.",
                        safe_fetch_limit,
                        extra={"grouping": "firewall-log-check"},
                    )
                try:
                    entries = client.traffic_logs_deny_for_flow(
                        api_key,
                        src_ip=settings.source_ip,
                        dst_ip=settings.destination_ip,
                        dst_port=destination_port,
                        since_hours=self._SINCE_HOURS,
                        max_results=safe_max_results,
                        max_wait_seconds=safe_max_wait_seconds,
                        fetch_limit=1,
                    )
                    query["fetch_limit"] = 1
                    retry_suffix = " (retried with fetch_limit=1 after timeout)"
                except Exception as retry_exc:
                    safe_error = _redact_secret_query_params(str(retry_exc))
                    safe_error = _redact_known_secrets(
                        safe_error,
                        secrets=(pa_settings.username, pa_settings.password),
                    )
                    safe_error = f"Retry with fetch_limit=1 failed: {safe_error}"

            if not retry_suffix:
                if "timed out after" in safe_error.lower():
                    hint_parts = []
                    effective_fetch_limit = 1 if retried_with_fetch_limit_1 else safe_fetch_limit
                    if effective_fetch_limit > 1:
                        hint_parts.append(
                            "lower fetch_limit (Job: firewall_log_fetch_limit; env: PANORAMA_LOG_QUERY_FETCH_LIMIT) (try 1)"
                        )
                    hint_parts.append(
                        "increase max_wait_seconds (Job: firewall_log_max_wait_seconds; env: PANORAMA_LOG_QUERY_MAX_WAIT_SECONDS) (e.g. 120)"
                    )
                    hint = "; ".join(hint_parts)
                    safe_error = f"{safe_error} (hint: {hint})"
                if self._logger:
                    self._logger.debug(
                        "Panorama firewall log check failed: %s",
                        safe_error,
                        extra={"grouping": "firewall-log-check"},
                    )
                return self._error_payload(panorama=panorama, query=query, error=safe_error)

        found = bool(entries)
        panorama_label = panorama_name or host
        if found:
            message = (
                f"Found {len(entries)} DENY traffic log(s) in the last {self._SINCE_HOURS} hours "
                f"for src={settings.source_ip} dst={settings.destination_ip} dport={destination_port} "
                f"on Panorama {panorama_label}."
            )
        else:
            message = (
                f"No DENY traffic logs found in the last {self._SINCE_HOURS} hours "
                f"for src={settings.source_ip} dst={settings.destination_ip} dport={destination_port} "
                f"on Panorama {panorama_label}."
            )
        message = f"{message}{retry_suffix}"

        return {
            "enabled": True,
            "status": "success",
            "provider": self._PROVIDER,
            "panorama": panorama,
            "query": query,
            "found": found,
            "entries": entries,
            "message": message,
            "errors": [],
        }

    def _error_payload(self, *, panorama: Dict[str, Any], query: Dict[str, Any], error: str) -> Dict[str, Any]:
        safe_error = (error or "Unknown error").strip()
        if not safe_error:
            safe_error = "Unknown error"
        return {
            "enabled": True,
            "status": "error",
            "provider": self._PROVIDER,
            "panorama": panorama,
            "query": query,
            "found": False,
            "entries": [],
            "message": f"Panorama log check failed: {safe_error}",
            "errors": [safe_error],
        }
