"""
siem/chronicle_mock.py
======================
Simulated Google SecOps (Chronicle) UDM + Sysmon search — the default backend.

Fixtures mirror the bundled sample and evaluation alerts so demos tell a
coherent story; any unknown entity gets clearly labelled synthetic baseline
activity. Replace with a real Chronicle Search API connector for production.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Any

from .base import SIEMConnector

_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

FIXTURES: dict[str, dict[str, list[dict[str, Any]]]] = {
    "FIN-WKS-0423": {
        "udm": [
            {
                "metadata": {"event_timestamp": "2026-10-06T14:58:10Z",
                             "event_type": "PROCESS_LAUNCH",
                             "product_name": "Microsoft-Windows-Sysmon"},
                "principal": {
                    "hostname": "FIN-WKS-0423", "ip": "10.20.14.57",
                    "user": "CORP\\j.alvarez",
                    "process": {
                        "command_line": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
                        "file": {"full_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                 "sha256": _SHA},
                        "parent_process": {"file": {"full_path": "WINWORD.EXE"}},
                    },
                },
                "target": {"ip": "185.220.101.47", "port": 443},
                "security_result": {"category": "COMMAND_AND_CONTROL"},
            },
            {
                "metadata": {"event_timestamp": "2026-10-06T14:59:02Z",
                             "event_type": "NETWORK_CONNECTION",
                             "product_name": "Microsoft-Windows-Sysmon"},
                "principal": {"hostname": "FIN-WKS-0423", "ip": "10.20.14.57"},
                "target": {"ip": "185.220.101.47", "port": 443,
                           "domain": "cdn-telemetry-sync.net"},
                "network": {"direction": "OUTBOUND", "application_protocol": "TLS"},
            },
        ],
        "sysmon": [
            {"EventID": 1, "name": "Process Create", "Image": "powershell.exe",
             "ParentImage": "WINWORD.EXE",
             "CommandLine": "powershell.exe -nop -w hidden -enc <base64>",
             "User": "CORP\\j.alvarez", "Hashes": f"SHA256={_SHA}",
             "UtcTime": "2026-10-06 14:58:10.112"},
            {"EventID": 3, "name": "Network Connection", "Image": "powershell.exe",
             "DestinationIp": "185.220.101.47", "DestinationPort": 443,
             "DestinationHostname": "cdn-telemetry-sync.net", "Protocol": "tcp",
             "UtcTime": "2026-10-06 14:59:02.771"},
            {"EventID": 11, "name": "File Create", "Image": "powershell.exe",
             "TargetFilename": "C:\\Users\\j.alvarez\\AppData\\Roaming\\svch0st.lnk",
             "UtcTime": "2026-10-06 14:59:05.004"},
            {"EventID": 13, "name": "Registry Value Set (Run key persistence)",
             "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
             "Details": "powershell -w hidden -enc <base64>",
             "UtcTime": "2026-10-06 14:59:06.233"},
        ],
    },
    "NESSUS-SCANNER": {
        "udm": [
            {
                "metadata": {"event_timestamp": "2026-10-06T15:02:00Z",
                             "event_type": "NETWORK_CONNECTION",
                             "product_name": "Zeek"},
                "principal": {"hostname": "NESSUS-SCANNER", "ip": "10.10.50.5",
                              "asset_role": "Authorised vulnerability scanner (change ticket CHG-20431)"},
                "target": {"ip": "10.20.14.0/24", "port": "1-65535"},
                "network": {"direction": "INTERNAL", "application_protocol": "TCP SYN scan"},
            }
        ],
        "sysmon": [
            {"EventID": 1, "name": "Process Create", "Image": "/opt/nessus/sbin/nessusd",
             "User": "svc_nessus", "UtcTime": "2026-10-06 15:00:00.000",
             "_note": "Scheduled weekly scan job 'Weekly-Internal-Full'."}
        ],
    },
}


def _is_internal_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


class ChronicleMockConnector(SIEMConnector):
    name = "chronicle-mock"
    beta = False

    @staticmethod
    def _synthesize(entity: str) -> dict[str, list[dict[str, Any]]]:
        return {
            "udm": [{
                "metadata": {"event_timestamp": "2026-10-06T13:10:00Z",
                             "event_type": "USER_LOGIN",
                             "product_name": "Windows-Security-Auditing"},
                "principal": {"entity": entity},
                "security_result": {"action": "ALLOW"},
                "_note": "No high-fidelity fixture for this entity; synthetic baseline record.",
            }],
            "sysmon": [{
                "EventID": 1, "name": "Process Create", "Image": "explorer.exe",
                "entity": entity, "UtcTime": "2026-10-06 13:10:05.000",
                "_note": "Synthetic baseline activity.",
            }],
        }

    def search(self, entity: str, event_type: str = "all") -> dict[str, Any]:
        record = None
        needle = entity.lower()
        for key, value in FIXTURES.items():
            # Exact host match, or the entity (IP, user, hash...) appears in the
            # fixture. Very short strings are ignored to avoid accidental matches.
            if needle == key.lower() or (len(needle) >= 6 and needle in json.dumps(value).lower()):
                record = value
                break
        synthetic = record is None
        if record is None:
            record = self._synthesize(entity)

        payload: dict[str, Any] = {"entity": entity}
        if event_type in ("udm", "all"):
            payload["udm_events"] = record["udm"]
        if event_type in ("sysmon", "all"):
            payload["sysmon_events"] = record["sysmon"]
        payload["_meta"] = {
            "backend": self.name,
            "synthetic": synthetic,
            "entity_is_internal_ip": _is_internal_ip(entity),
            "disclaimer": "Simulated telemetry for lab/demo use only.",
        }
        return payload
