from __future__ import annotations

import unittest
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


@unittest.skipUnless(_mongodb_available(), "local MongoDB is not running on 127.0.0.1:27017")
class MongoDBE2ETest(unittest.TestCase):
    def test_mongodb_backed_e2e_normal_and_attack_paths(self):
        result = run_mongodb_e2e(db_name="presaga_e2e_test", output_root=Path("results"))
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
