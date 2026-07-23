from __future__ import annotations

import base64
import http.client
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from presaga.crypto.hpke_kem_stub import HPKEKEMStub
from presaga.provider.server import create_server


class ProviderHttpServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.state_file = Path(self.tempdir.name) / "provider-state.json"
        self.server = create_server(port=0, state_file=self.state_file)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tempdir.cleanup()

    def request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, data

    def test_service_persists_issue_and_audits_a_data_token_flow(self):
        backend = HPKEKEMStub()
        owner = backend.generate_keypair()
        requester = backend.generate_keypair()
        owner_aid = "alice@example.com:calendar"
        requester_aid = "bob@example.com:scheduler"
        for aid, key in ((owner_aid, owner.public_key), (requester_aid, requester.public_key)):
            status, _ = self.request("POST", "/v1/agents", {"aid": aid, "public_key_b64": _b64(key)})
            self.assertEqual(201, status)
        status, _ = self.request("POST", "/v1/contact-rulebooks", {
            "owner_aid": owner_aid, "rulebook": [{"pattern": "bob@example.com:*", "budget": 1}],
        })
        self.assertEqual(201, status)
        status, contact = self.request("POST", "/v1/contact-sessions", {
            "owner_aid": owner_aid, "requester_aid": requester_aid,
        })
        self.assertEqual(201, status)
        self.assertTrue(contact["contact_token"]["token_id"].startswith("ctok-"))

        now = datetime.now(timezone.utc)
        policy = {
            "policy_id": "calendar-meeting-read",
            "owner_aid": owner_aid,
            "requester_selector": {"type": "aid_exact", "value": requester_aid},
            "data_scope": {"data_classes": ["calendar"], "data_subclasses": ["meeting"], "record_ids": ["cal-1"]},
            "purposes": ["schedule_meeting"],
            "validity": {"not_before": (now - timedelta(minutes=1)).isoformat(), "not_after": (now + timedelta(minutes=5)).isoformat()},
            "limits": {"max_uses": 1},
            "version_constraints": {"min_version": 1, "max_version": 1},
        }
        status, _ = self.request("POST", "/v1/data-policies", policy)
        self.assertEqual(201, status)
        request = {
            "request_id": "req-1", "owner_aid": owner_aid, "requester_aid": requester_aid, "record_id": "cal-1",
            "data_class": "calendar", "data_subclass": "meeting", "purpose": "schedule_meeting", "version": 1,
            "requester_public_key_b64": _b64(requester.public_key), "timestamp": now.isoformat(),
        }
        status, issued = self.request("POST", "/v1/data-tokens", request)
        self.assertEqual(201, status)
        token_id = issued["data_token"]["token_id"]
        dek = b"d" * 32
        encrypted = backend.wrap_dek(dek, owner.public_key, b"cal-1")
        rekey = backend.generate_rekey(owner.private_key, requester.public_key, b"cal-1")
        status, transformed = self.request("POST", "/v1/re-encryptions", {
            "token_id": token_id, "request": request, "encrypted_dek_owner_b64": _b64(encrypted), "rekey_b64": _b64(rekey),
        })
        self.assertEqual(200, status)
        self.assertEqual("allow", transformed["decision"])
        self.assertEqual(dek, backend.unwrap_dek(base64.b64decode(transformed["transformed_encrypted_dek_b64"]), requester.private_key, b"cal-1"))
        status, audit = self.request("GET", "/v1/audit?decision=allow")
        self.assertEqual(200, status)
        self.assertEqual(1, audit["count"])
        self.assertTrue(self.state_file.exists())

        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = create_server(port=0, state_file=self.state_file)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        status, audit = self.request("GET", "/v1/audit")
        self.assertEqual(200, status)
        self.assertEqual(1, audit["count"])


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


if __name__ == "__main__":
    unittest.main()
