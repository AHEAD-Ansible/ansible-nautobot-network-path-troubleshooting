"""Network Path Tracing Jobs for Nautobot."""

from .network_path_tracer_job import NetworkPathTracerJob
from nautobot.core.jobs import register_jobs  # Updated to core.jobs

# Register the Job for Nautobot to discover
register_jobs(NetworkPathTracerJob)