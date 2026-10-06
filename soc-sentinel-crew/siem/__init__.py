"""
siem — pluggable, read-only SIEM log-search connectors.

Select the backend with ``SIEM_BACKEND``:

    chronicle_mock (default) | splunk | elastic | sentinel
"""

from __future__ import annotations

from config import Settings

from .base import SIEMConnector, SIEMError, validate_entity, validate_event_type
from .chronicle_mock import ChronicleMockConnector

BACKENDS = ("chronicle_mock", "splunk", "elastic", "sentinel")


def get_connector(settings: Settings) -> SIEMConnector:
    """Instantiate the configured connector. Raises SIEMError if misconfigured."""
    backend = settings.siem_backend
    common = {"timeout": settings.http_timeout,
              "lookback_hours": settings.siem_lookback_hours,
              "max_events": settings.siem_max_events}

    if settings.force_mock or backend in ("", "chronicle_mock", "mock"):
        return ChronicleMockConnector()
    if backend == "splunk":
        from .splunk import SplunkConnector
        return SplunkConnector(settings.splunk_url, settings.splunk_token,
                               index=settings.splunk_index,
                               verify_tls=settings.splunk_verify_tls, **common)
    if backend == "elastic":
        from .elastic import ElasticConnector
        return ElasticConnector(settings.elastic_url, settings.elastic_api_key,
                                index=settings.elastic_index, **common)
    if backend == "sentinel":
        from .sentinel import SentinelConnector
        return SentinelConnector(settings.sentinel_workspace_id,
                                 settings.sentinel_tenant_id,
                                 settings.sentinel_client_id,
                                 settings.sentinel_client_secret, **common)
    raise SIEMError(f"Unknown SIEM_BACKEND {backend!r}. Choose one of {BACKENDS}.")


__all__ = ["BACKENDS", "SIEMConnector", "SIEMError", "get_connector",
           "validate_entity", "validate_event_type"]
