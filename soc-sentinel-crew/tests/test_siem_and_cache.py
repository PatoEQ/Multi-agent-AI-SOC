"""SIEM connectors (mocked HTTP), backend selection, cache and rate limiter."""

from __future__ import annotations

import json

import pytest

import config
from cache import RateLimiter, TTLCache
from siem import SIEMError, get_connector
from siem.base import quote_for_query, validate_entity
from siem.elastic import ElasticConnector
from siem.sentinel import SentinelConnector
from siem.splunk import SplunkConnector

GUID = "11111111-2222-3333-4444-555555555555"


class FakeResp:
    def __init__(self, status=200, text="", payload=None):
        self.status_code, self.text, self._payload = status, text, payload

    def json(self):
        return self._payload


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def test_validate_entity_accepts_domain_user():
    assert validate_entity("CORP\\j.alvarez") == "CORP\\j.alvarez"


@pytest.mark.parametrize("bad", ['a"b', "a b", "x|y", "a'b", "a`b", "x" * 300])
def test_validate_entity_rejects(bad):
    with pytest.raises(ValueError):
        validate_entity(bad)


def test_quote_for_query_escapes_backslash():
    assert quote_for_query("CORP\\bob") == "CORP\\\\bob"


# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #
def test_force_mock_always_uses_chronicle_mock(monkeypatch):
    monkeypatch.setenv("SIEM_BACKEND", "splunk")
    config.reset_caches()
    assert get_connector(config.get_settings()).name == "chronicle-mock"


@pytest.mark.parametrize("backend", ["splunk", "elastic", "sentinel"])
def test_misconfigured_backend_raises(monkeypatch, backend):
    monkeypatch.setenv("FORCE_MOCK", "0")
    monkeypatch.setenv("SIEM_BACKEND", backend)
    config.reset_caches()
    with pytest.raises(SIEMError):
        get_connector(config.get_settings())


def test_unknown_backend(monkeypatch):
    monkeypatch.setenv("FORCE_MOCK", "0")
    monkeypatch.setenv("SIEM_BACKEND", "qradar")
    config.reset_caches()
    with pytest.raises(SIEMError):
        get_connector(config.get_settings())


# --------------------------------------------------------------------------- #
# Splunk
# --------------------------------------------------------------------------- #
def test_splunk_query_and_parsing(monkeypatch):
    seen = {}

    def fake_post(url, headers, data, timeout, verify):
        seen.update(url=url, headers=headers, data=data, verify=verify)
        lines = [json.dumps({"result": {"host": "FIN-WKS-0423", "EventCode": "1"}}),
                 json.dumps({"preview": False}), "not json"]
        return FakeResp(200, "\n".join(lines))

    monkeypatch.setattr("siem.splunk.requests.post", fake_post)
    conn = SplunkConnector("https://splunk.local:8089/", "test-dummy-key", index="main")
    out = conn.search("FIN-WKS-0423", "sysmon")
    assert seen["url"] == "https://splunk.local:8089/services/search/jobs/export"
    assert seen["headers"]["Authorization"] == "Bearer test-dummy-key"
    assert seen["data"]["search"].startswith('search index=main "FIN-WKS-0423" sourcetype=')
    assert out["events"] == [{"host": "FIN-WKS-0423", "EventCode": "1"}]


def test_splunk_auth_error(monkeypatch):
    monkeypatch.setattr("siem.splunk.requests.post", lambda *a, **k: FakeResp(401))
    with pytest.raises(SIEMError, match="token"):
        SplunkConnector("https://s:8089", "k").search("host1")


def test_splunk_rejects_bad_index():
    with pytest.raises(SIEMError):
        SplunkConnector("https://s:8089", "k", index="main | delete")


# --------------------------------------------------------------------------- #
# Elastic
# --------------------------------------------------------------------------- #
def test_elastic_body_keeps_entity_as_json_value(monkeypatch):
    seen = {}

    def fake_post(url, headers, json, timeout):
        seen.update(url=url, headers=headers, body=json)
        return FakeResp(200, payload={"hits": {"hits": [{"_source": {"host.name": "h"}}]}})

    monkeypatch.setattr("siem.elastic.requests.post", fake_post)
    out = ElasticConnector("https://es.local", "test-dummy-key").search("10.0.0.5", "sysmon")
    must = seen["body"]["query"]["bool"]["must"][0]["multi_match"]
    assert must["query"] == "10.0.0.5"
    assert seen["headers"]["Authorization"] == "ApiKey test-dummy-key"
    assert {"term": {"event.dataset": "windows.sysmon_operational"}} in seen["body"]["query"]["bool"]["filter"]
    assert out["events"] == [{"host.name": "h"}]


# --------------------------------------------------------------------------- #
# Sentinel
# --------------------------------------------------------------------------- #
def test_sentinel_token_and_query(monkeypatch):
    calls = []

    def fake_post(url, timeout, data=None, json=None, headers=None):
        calls.append((url, data, json, headers))
        if "login.microsoftonline.com" in url:
            return FakeResp(200, payload={"access_token": "tok", "expires_in": 3600})
        return FakeResp(200, payload={"tables": [{"columns": [{"name": "Computer"}, {"name": "EventID"}],
                                                  "rows": [["FIN-WKS-0423", 1]]}]})

    monkeypatch.setattr("siem.sentinel.requests.post", fake_post)
    conn = SentinelConnector(GUID, GUID, "client", "test-dummy-key")
    out = conn.search("FIN-WKS-0423")
    conn.search("FIN-WKS-0423")  # token is reused
    assert sum("login" in c[0] for c in calls) == 1
    assert calls[1][2]["query"] == 'search "FIN-WKS-0423" | take 50'
    assert calls[1][3]["Authorization"] == "Bearer tok"
    assert out["events"] == [{"Computer": "FIN-WKS-0423", "EventID": 1}]


def test_sentinel_requires_guids():
    with pytest.raises(SIEMError):
        SentinelConnector("not-a-guid", GUID, "c", "s")


# --------------------------------------------------------------------------- #
# Cache / rate limiter
# --------------------------------------------------------------------------- #
def test_ttl_cache_expiry():
    now = [0.0]
    cache = TTLCache(ttl_seconds=10, clock=lambda: now[0])
    cache.set("k", "v")
    assert cache.get("k") == "v"
    now[0] = 11
    assert cache.get("k") is None
    assert cache.hits == 1 and cache.misses == 1


def test_ttl_cache_eviction():
    cache = TTLCache(ttl_seconds=100, max_items=2)
    for k in "abc":
        cache.set(k, k)
    assert sum(cache.get(k) is not None for k in "abc") == 2


def test_rate_limiter_spaces_calls():
    now, slept = [0.0], []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(15, clock=lambda: now[0], sleep=sleep)
    limiter.wait()
    limiter.wait()
    limiter.wait()
    assert slept == [15, 15]
