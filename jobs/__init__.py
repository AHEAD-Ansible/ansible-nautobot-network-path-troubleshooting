"""Network Path Tracing Job package."""
from nautobot.apps.jobs import register_jobs

register_jobs(NetworkPathTracerJob)