"""Network Path Tracing Jobs for Nautobot."""

from .network_path_tracer_job import NetworkPathTracerJob
from nautobot.apps.jobs import register_jobs

# Register the Job for Nautobot to discover
register_jobs(NetworkPathTracerJob)