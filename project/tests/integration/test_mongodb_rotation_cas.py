from __future__ import annotations

import os
import unittest

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from presaga.crypto.key_custody import OwnerRewrapApproval, UmbralOwnerKeyCustody
from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.app import PREProviderApp
from presaga.provider.mongo_repository import MongoProviderRepository
from presaga.storage.mongo_encrypted_store import MongoEncryptedStore


def _approval(request) -> OwnerRewrapApproval:
    return OwnerRewrapApproval(
        request_digest=request.request_digest,
        owner_aid=request.owner_aid,
        rotation_id=request.rotation_id,
        store_id=request.store_id,
        record_id=request.record_id,
        expected_object_revision=request.expected_object_revision,
        source_registration_id=request.source_registration_id,
        source_registration_version=request.source_registration_version,
        target_registration_id=request.target_registration_id,
        target_registration_version=request.target_registration_version,
        target_public_key_fingerprint=request.target_public_key_fingerprint,
        target_public_key=request.target_public_key,
    )


class MongoRotationCASTest(unittest.TestCase):
    def test_live_mongodb_rotation_journal_and_object_cas(self) -> None:
        uri = os.environ.get("PRESAGA_MONGODB_URI", "mongodb://127.0.0.1:27017")
        try:
            client = MongoClient(uri, serverSelectionTimeoutMS=1000)
            client.admin.command("ping")
        except PyMongoError as error:
            self.skipTest(f"MongoDB unavailable at {uri}: {error}")
        db_name = "presaga_core004_rotation_test"
        client.drop_database(db_name)
        try:
            db = client[db_name]
            backend = UmbralPREBackend()
            custody = UmbralOwnerKeyCustody(backend)
            app = PREProviderApp(backend)
            owner_v1 = backend.generate_keypair()
            owner_v2 = backend.generate_keypair()
            owner_aid = "alice@example.com:calendar"
            app.management.register_agent(owner_aid, owner_v1.public_key)
            store = MongoEncryptedStore(backend, db, app.registry)
            repository = MongoProviderRepository(db)
            stored = store.put(
                DataRecord(
                    "mongo-rotation-1",
                    owner_aid,
                    "calendar",
                    "availability",
                    1,
                ),
                b"available",
            )
            prepared = app.management.prepare_agent_replacement(
                owner_aid,
                owner_v2.public_key,
                expected_version=1,
            )
            repository.save_rotation(prepared)
            request = app.management.build_agent_rewrap_request(
                owner_aid,
                expected_version=1,
                rotation_id=prepared.rotation_id,
                store=store,
                record_id=stored.record.record_id,
                expected_object_revision=stored.object_revision,
            )
            artifact = custody.rewrap(request, owner_v1.private_key, _approval(request))
            staged = app.management.stage_agent_rewrap(
                owner_aid,
                expected_version=1,
                rotation_id=prepared.rotation_id,
                store=store,
                record_id=stored.record.record_id,
                artifact=artifact,
                expected_object_revision=stored.object_revision,
            )
            stale = store.collection.replace_one(
                {
                    "record.record_id": stored.record.record_id,
                    "object_revision": stored.object_revision,
                },
                store._serialize(staged),
                upsert=False,
            )
            self.assertEqual(0, stale.matched_count)

            app.management.commit_agent_replacement(
                owner_aid,
                expected_version=1,
                rotation_id=prepared.rotation_id,
            )
            committed = app.management.rotation_journal()[0]
            repository.replace_rotation(
                committed,
                expected_status="prepared",
                expected_cleanup_completed=False,
            )
            app.management.cleanup_agent_rotation(
                owner_aid,
                rotation_id=prepared.rotation_id,
            )
            cleaned = app.management.rotation_journal()[0]
            repository.replace_rotation(
                cleaned,
                expected_status="committed",
                expected_cleanup_completed=False,
            )
            with self.assertRaisesRegex(ValueError, "rotation_state_conflict"):
                repository.replace_rotation(
                    cleaned,
                    expected_status="committed",
                    expected_cleanup_completed=False,
                )

            client.close()
            client = MongoClient(uri, serverSelectionTimeoutMS=1000)
            client.admin.command("ping")
            persisted = client[db_name]["encrypted_objects"].find_one(
                {"record.record_id": stored.record.record_id}
            )
            journal = client[db_name]["rotation_journal"].find_one(
                {"rotation_id": prepared.rotation_id}
            )
            self.assertEqual(3, persisted["object_revision"])
            self.assertEqual(1, len(persisted["owner_wraps"]))
            self.assertEqual("committed", journal["status"])
            self.assertTrue(journal["cleanup_completed"])
        finally:
            try:
                client.drop_database(db_name)
            finally:
                client.close()


if __name__ == "__main__":
    unittest.main()
