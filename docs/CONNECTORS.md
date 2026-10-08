# SIEM connectors

The DFIR and Triage agents read logs through one tool, `siem_log_search`. That
tool delegates to a **connector** chosen with `SIEM_BACKEND`.

| Backend | Status | Auth | Notes |
|---|---|---|---|
| `chronicle_mock` | ✅ default | none | Simulated UDM + Sysmon fixtures for demos and tests |
| `splunk` | 🧪 beta | Bearer token | REST export endpoint (`/services/search/jobs/export`) |
| `elastic` | 🧪 beta | API key | `_search` with a `multi_match` query |
| `sentinel` | 🧪 beta | Entra ID app (client credentials) | Log Analytics query API, KQL `search` |

"Beta" means the connector is unit-tested with mocked HTTP responses but has
**not yet been validated against a live instance**. If you run one against your
SIEM, please open an issue or PR with what you found.

## Security model

- Connectors are **read-only**. Give them read-only credentials.
- `siem/base.py::validate_entity` only accepts letters, digits and `. _ : @ \ -`.
  This blocks query injection such as `x" | delete`. Each connector also escapes
  values for its query language.
- Errors are raised as `SIEMError`. The tool turns them into an `ERROR: ...` string
  for the agent, and never crashes the crew.

## Adding a connector (example: QRadar)

1. Create `siem/qradar.py`:

   ```python
   from .base import SIEMConnector, SIEMError

   class QRadarConnector(SIEMConnector):
       name = "qradar"
       beta = True

       def __init__(self, url, token, timeout=20, lookback_hours=24, max_events=50):
           if not url or not token:
               raise SIEMError("QRadar needs QRADAR_URL and QRADAR_TOKEN.")
           ...

       def search(self, entity: str, event_type: str = "all") -> dict:
           # entity is already validated; build the AQL query safely
           ...
           return {"entity": entity, "events": events, "_meta": {"backend": self.name}}
   ```

2. Add its settings to `config.py` and placeholders to `.env.example`.
3. Register it in `siem/__init__.py::get_connector` and add it to `BACKENDS`.
4. Add tests in `tests/test_siem_and_cache.py` with a mocked `requests.post`/`get`.
   Check the request URL, headers and query, response parsing, and auth errors.
5. Document it in the table above.
