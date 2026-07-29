from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from experiments.e2e.mongodb_e2e import run_mongodb_e2e


def _mongodb_available(uri: str = "mongodb://127.0.0.1:27017") -> bool:
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=1000)
        client.admin.command("ping")
        client.close()
        return True
    except PyMongoError:
        return False


MONGODB_URI = os.environ.get(
    "PRESAGA_MONGODB_URI",
    "mongodb://127.0.0.1:27017",
)


@unittest.skipUnless(_mongodb_available(MONGODB_URI), f"local MongoDB is not running at {MONGODB_URI}")
class MongoDBE2ETest(unittest.TestCase):
    def test_mongodb_backed_e2e_normal_and_attack_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_mongodb_e2e(
                uri=MONGODB_URI,
                db_name=f"presaga_e2e_test_{uuid.uuid4().hex}",
                output_root=Path(temp_dir),
            )
        self.assertTrue(result.mongo_connected)
        self.assertTrue(result.normal_success)
        self.assertTrue(result.attack_blocked)
        self.assertEqual("requester_mismatch", result.denial_reason)
        self.assertFalse(result.provider_plaintext_data_visible)
        self.assertFalse(result.provider_plaintext_dek_visible)
        self.assertGreaterEqual(result.persisted_agents, 3)
        self.assertGreaterEqual(result.persisted_policies, 1)
        self.assertGreaterEqual(result.persisted_contact_tokens, 1)
        self.assertGreaterEqual(result.persisted_data_tokens, 1)
        self.assertGreaterEqual(result.persisted_audit_events, 2)
        self.assertGreaterEqual(result.persisted_encrypted_objects, 1)


if __name__ == "__main__":
    unittest.main()
