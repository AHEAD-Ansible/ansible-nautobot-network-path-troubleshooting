"""Nautobot App configuration for Network Path Tracing."""

from nautobot.apps import NautobotAppConfig


class NetworkPathTracingConfig(NautobotAppConfig):
    """App configuration for the Network Path Tracing app."""

    name = "my_app"
    verbose_name = "Network Path Tracing"
    description = "A Nautobot App for tracing network paths between IP addresses."
    version = "1.0.0"
    author = "Your Name"
    author_email = "your.email@example.com"
    base_url = "network-path-tracing"
    jobs = "my_app.jobs"

    def ready(self):
        """Initialize the app."""
        super().ready()