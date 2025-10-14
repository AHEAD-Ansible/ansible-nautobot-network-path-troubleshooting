"""Interface statistics collection helpers."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, Optional, Sequence

from ..config import NetworkPathSettings
from ..exceptions import InterfaceStatsError
from .f5_bigip import F5APIError, F5Client
from .nautobot import DeviceRecord, NautobotDataSource
from .palo_alto import PaloAltoClient
from .platform_utils import (
    is_f5_bigip,
    is_palo_alto,
    napalm_driver_attempts,
    napalm_optional_args,
    select_napalm_driver,
)

try:
    import napalm  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    napalm = None


@dataclass(frozen=True)
class InterfaceStats:
    """Normalized view of per-interface statistics."""

    name: str
    admin_up: Optional[bool] = None
    oper_up: Optional[bool] = None
    speed_mbps: Optional[int] = None
    mac_address: Optional[str] = None
    mtu: Optional[int] = None
    rx_bytes: Optional[int] = None
    tx_bytes: Optional[int] = None
    rx_unicast: Optional[int] = None
    tx_unicast: Optional[int] = None
    rx_errors: Optional[int] = None
    tx_errors: Optional[int] = None
    rx_discards: Optional[int] = None
    tx_discards: Optional[int] = None

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-friendly representation."""
        return {key: value for key, value in asdict(self).items() if value is not None}


class InterfaceStatsService:
    """Collect interface statistics across supported platform types."""

    def __init__(
        self,
        data_source: NautobotDataSource,
        settings: NetworkPathSettings,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._data_source = data_source
        self._settings = settings
        self._logger = logger
        self._palo_sessions: Dict[str, tuple[PaloAltoClient, str]] = {}

    def collect_by_device_name(self, device_name: str, interfaces: Sequence[str]) -> Dict[str, InterfaceStats]:
        """Collect interface statistics for a device identified by name."""
        device = self._data_source.get_device(device_name)
        if not device:
            raise InterfaceStatsError(f"Device '{device_name}' not found in Nautobot.")
        return self.collect(device, interfaces)

    def collect(self, device: DeviceRecord, interfaces: Sequence[str]) -> Dict[str, InterfaceStats]:
        """Collect interface statistics for the provided device."""
        if not device.primary_ip:
            raise InterfaceStatsError(f"Device '{device.name}' does not have a primary IP configured.")
        if not interfaces:
            return {}

        try:
            if is_palo_alto(device):
                return self._collect_palo_alto(device, interfaces)
            if is_f5_bigip(device):
                return self._collect_f5(device, interfaces)
            return self._collect_napalm(device, interfaces)
        except InterfaceStatsError:
            raise
        except Exception as exc:  # pragma: no cover - defensive conversion
            raise InterfaceStatsError(f"Failed to collect statistics for '{device.name}': {exc}") from exc

    # ----------------------------------------------------------------------
    # NAPALM-backed platforms
    # ----------------------------------------------------------------------

    def _collect_napalm(self, device: DeviceRecord, interfaces: Sequence[str]) -> Dict[str, InterfaceStats]:
        if napalm is None:
            raise InterfaceStatsError("NAPALM is not installed; cannot gather interface statistics.")

        napalm_settings = self._settings.napalm_settings()
        if not napalm_settings:
            raise InterfaceStatsError("NAPALM credentials are not configured.")

        driver_name = select_napalm_driver(device)
        last_error: Optional[Exception] = None

        for candidate in napalm_driver_attempts(driver_name):
            try:
                driver = napalm.get_network_driver(candidate)
                optional_args = napalm_optional_args(candidate)
                with driver(
                    hostname=device.primary_ip,
                    username=napalm_settings.username,
                    password=napalm_settings.password,
                    optional_args=optional_args,
                ) as device_conn:
                    interface_info = device_conn.get_interfaces()
                    try:
                        counters = device_conn.get_interfaces_counters()
                    except NotImplementedError:
                        counters = {}
                    except Exception as exc:  # pragma: no cover - driver specific
                        counters = {}
                        if self._logger:
                            self._logger.debug(
                                f"Unable to fetch interface counters via NAPALM for '{device.name}': {exc}",
                                extra={"grouping": "interface-stats"},
                            )
                    return self._build_napalm_stats(interface_info, counters, interfaces)
            except Exception as exc:  # pragma: no cover - driver specific
                last_error = exc
                if self._logger:
                    self._logger.warning(
                        f"NAPALM driver '{candidate}' failed for {device.name}: {exc}",
                        extra={"grouping": "interface-stats"},
                    )
                continue

        raise InterfaceStatsError(f"NAPALM interface statistics failed for '{device.name}': {last_error}")

    @staticmethod
    def _build_napalm_stats(
        interface_info: Dict[str, Dict[str, object]],
        counters: Dict[str, Dict[str, object]],
        requested: Iterable[str],
    ) -> Dict[str, InterfaceStats]:
        stats: Dict[str, InterfaceStats] = {}
        normalized = {key.lower(): key for key in interface_info.keys()}
        counter_keys = {key.lower(): key for key in counters.keys()}

        for name in requested:
            info_key = normalized.get(name.lower())
            info = interface_info.get(info_key) if info_key else interface_info.get(name)
            if info is None:
                for candidate_name, candidate_info in interface_info.items():
                    if candidate_name.lower() == name.lower():
                        info = candidate_info
                        break
            counter_key = counter_keys.get(name.lower())
            counter = counters.get(counter_key) if counter_key else counters.get(name)
            if counter is None:
                for candidate_name, candidate_counter in counters.items():
                    if candidate_name.lower() == name.lower():
                        counter = candidate_counter
                        break
            if counter is None:
                counter = {}

            stats[name] = InterfaceStats(
                name=name,
                admin_up=_coerce_bool(info.get("is_enabled")) if info else None,
                oper_up=_coerce_bool(info.get("is_up")) if info else None,
                speed_mbps=_coerce_int(info.get("speed")) if info else None,
                mac_address=_coerce_str(info.get("mac_address")) if info else None,
                mtu=_coerce_int(info.get("mtu")) if info else None,
                rx_bytes=_coerce_int(counter.get("rx_octets")) if counter else None,
                tx_bytes=_coerce_int(counter.get("tx_octets")) if counter else None,
                rx_unicast=_coerce_int(counter.get("rx_unicast_packets")) if counter else None,
                tx_unicast=_coerce_int(counter.get("tx_unicast_packets")) if counter else None,
                rx_errors=_coerce_int(counter.get("rx_errors")) if counter else None,
                tx_errors=_coerce_int(counter.get("tx_errors")) if counter else None,
                rx_discards=_coerce_int(counter.get("rx_discards")) if counter else None,
                tx_discards=_coerce_int(counter.get("tx_discards")) if counter else None,
            )
        return stats

    # ----------------------------------------------------------------------
    # Palo Alto
    # ----------------------------------------------------------------------

    def _collect_palo_alto(self, device: DeviceRecord, interfaces: Sequence[str]) -> Dict[str, InterfaceStats]:
        pa_settings = self._settings.pa_settings()
        if not pa_settings:
            raise InterfaceStatsError("Palo Alto credentials are not configured.")

        session = self._palo_sessions.get(device.primary_ip)
        if not session:
            client = PaloAltoClient(
                host=device.primary_ip,
                verify_ssl=pa_settings.verify_ssl,
                timeout=10,
                logger=self._logger,
            )
            try:
                api_key = client.keygen(pa_settings.username, pa_settings.password)
            except RuntimeError as exc:
                raise InterfaceStatsError(f"Palo Alto authentication failed for '{device.name}': {exc}") from exc
            session = (client, api_key)
            self._palo_sessions[device.primary_ip] = session

        client, api_key = session
        raw_stats = client.get_interface_statistics(api_key, interfaces)
        stats: Dict[str, InterfaceStats] = {}

        for name in interfaces:
            payload = raw_stats.get(name, {})
            counters = payload.get("counters", {}) if isinstance(payload, dict) else {}

            stats[name] = InterfaceStats(
                name=name,
                admin_up=_coerce_bool(payload.get("admin_up")) if isinstance(payload, dict) else None,
                oper_up=_coerce_bool(payload.get("oper_up")) if isinstance(payload, dict) else None,
                speed_mbps=_coerce_int(payload.get("speed_mbps")) if isinstance(payload, dict) else None,
                mac_address=_coerce_str(payload.get("mac_address") or payload.get("mac")) if isinstance(payload, dict) else None,
                mtu=_coerce_int(payload.get("mtu")) if isinstance(payload, dict) else None,
                rx_bytes=_coerce_int(payload.get("rx_bytes")) if isinstance(payload, dict) else None,
                tx_bytes=_coerce_int(payload.get("tx_bytes")) if isinstance(payload, dict) else None,
                rx_unicast=_coerce_int(payload.get("rx_unicast")) if isinstance(payload, dict) else None,
                tx_unicast=_coerce_int(payload.get("tx_unicast")) if isinstance(payload, dict) else None,
                rx_errors=_coerce_int(payload.get("rx_errors")) if isinstance(payload, dict) else None,
                tx_errors=_coerce_int(payload.get("tx_errors")) if isinstance(payload, dict) else None,
                rx_discards=_coerce_int(payload.get("rx_discards")) if isinstance(payload, dict) else None,
                tx_discards=_coerce_int(payload.get("tx_discards")) if isinstance(payload, dict) else None,
            )

            # Use nested counters as fallback if top-level fields missing
            stats_entry = stats[name]
            if isinstance(counters, dict):
                stats[name] = InterfaceStats(
                    name=name,
                    admin_up=stats_entry.admin_up,
                    oper_up=stats_entry.oper_up,
                    speed_mbps=stats_entry.speed_mbps,
                    mac_address=stats_entry.mac_address,
                    mtu=stats_entry.mtu,
                    rx_bytes=stats_entry.rx_bytes or _coerce_int(counters.get("bytes_received")),
                    tx_bytes=stats_entry.tx_bytes or _coerce_int(counters.get("bytes_transmitted")),
                    rx_unicast=stats_entry.rx_unicast or _coerce_int(counters.get("rx_unicast")) or _coerce_int(counters.get("packets_received")),
                    tx_unicast=stats_entry.tx_unicast or _coerce_int(counters.get("tx_unicast")) or _coerce_int(counters.get("packets_transmitted")),
                    rx_errors=stats_entry.rx_errors or _coerce_int(counters.get("errors_received")),
                    tx_errors=stats_entry.tx_errors or _coerce_int(counters.get("errors_transmitted")),
                    rx_discards=stats_entry.rx_discards or _coerce_int(counters.get("drops_received")),
                    tx_discards=stats_entry.tx_discards or _coerce_int(counters.get("drops_transmitted")),
                )

        return stats

    # ----------------------------------------------------------------------
    # F5 BIG-IP
    # ----------------------------------------------------------------------

    def _collect_f5(self, device: DeviceRecord, interfaces: Sequence[str]) -> Dict[str, InterfaceStats]:
        f5_settings = self._settings.f5_settings()
        if not f5_settings:
            raise InterfaceStatsError("F5 credentials are not configured.")

        client = F5Client(
            host=device.primary_ip,
            username=f5_settings.username,
            password=f5_settings.password,
            verify_ssl=f5_settings.verify_ssl,
        )

        try:
            raw_stats = client.get_interface_stats(interfaces, partitions=f5_settings.partitions_list())
        except (F5APIError, Exception) as exc:
            raise InterfaceStatsError(f"F5 statistics lookup failed for '{device.name}': {exc}") from exc

        stats: Dict[str, InterfaceStats] = {}
        for name in interfaces:
            payload = raw_stats.get(name, {})
            counters = payload.get("counters", {})
            stats[name] = InterfaceStats(
                name=name,
                admin_up=_coerce_bool(payload.get("admin_state")),
                oper_up=_coerce_bool(payload.get("oper_state")),
                speed_mbps=_coerce_int(payload.get("speed_mbps")),
                mac_address=_coerce_str(payload.get("mac_address")),
                mtu=_coerce_int(payload.get("mtu")),
                rx_bytes=_coerce_int(counters.get("rx_bytes")),
                tx_bytes=_coerce_int(counters.get("tx_bytes")),
                rx_errors=_coerce_int(counters.get("rx_errors")),
                tx_errors=_coerce_int(counters.get("tx_errors")),
                rx_discards=_coerce_int(counters.get("rx_discards")),
                tx_discards=_coerce_int(counters.get("tx_discards")),
            )
        return stats


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------


def _coerce_bool(value: object) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        value_lower = value.strip().lower()
        if value_lower in {"true", "up", "enabled", "yes", "on"}:
            return True
        if value_lower in {"false", "down", "disabled", "no", "off"}:
            return False
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _coerce_int(value: object) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.replace(",", ""))
        except ValueError:
            return None
    return None


def _coerce_str(value: object) -> Optional[str]:
    if value is None:
        return None
    return str(value)
