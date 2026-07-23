from __future__ import annotations

import unittest

from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import DataRecord
from presaga.storage import CalendarStore, DataAccessDenied, DocumentStore, MailStore, MemoryStore


class PolicyAwareStoreTest(unittest.TestCase):
    def setUp(self):
        self.backend = ToyPRE()
        self.owner = self.backend.generate_keypair()
        self.calendar = CalendarStore(self.backend)
        self.record = DataRecord(
            record_id="cal-available",
            owner_aid="alice:calendar",
            data_class="calendar",
            data_subclass="availability",
            version=1,
        )
        self.stored = self.calendar.put_payload(
            self.record,
            {"availability": "10:00-11:00", "private_note": "medical appointment"},
            self.owner.public_key,
            purposes=["schedule_meeting"],
        )
        self.dek = self.backend.unwrap_dek(
            self.stored.encrypted_dek_owner,
            self.owner.private_key,
            self.calendar.context(self.record),
        )

    def test_authorized_projection_returns_only_allowed_field(self):
        grant = self.calendar.grant_access(
            requester_aid="bob:scheduler",
            purpose="schedule_meeting",
            data_class="calendar",
            record_scope=["cal-available"],
            allowed_fields=["availability"],
        )
        self.assertEqual(self.calendar.list_records(grant), [self.record])
        result = self.calendar.read_projection(
            grant=grant,
            record_id="cal-available",
            dek=self.dek,
            requested_fields=["availability"],
        )
        self.assertEqual(result, {"availability": "10:00-11:00"})
        self.assertNotIn("private_note", result)

    def test_denies_unauthorized_record_and_field(self):
        grant = self.calendar.grant_access(
            requester_aid="bob:scheduler",
            purpose="schedule_meeting",
            data_class="calendar",
            record_scope=["cal-available"],
            allowed_fields=["availability"],
        )
        with self.assertRaisesRegex(DataAccessDenied, "record_out_of_scope"):
            self.calendar.read_projection(
                grant=grant,
                record_id="cal-private",
                dek=self.dek,
                requested_fields=["availability"],
            )
        with self.assertRaisesRegex(DataAccessDenied, "field_not_allowed"):
            self.calendar.read_projection(
                grant=grant,
                record_id="cal-available",
                dek=self.dek,
                requested_fields=["private_note"],
            )

    def test_denies_purpose_mismatch(self):
        with self.assertRaisesRegex(DataAccessDenied, "purpose_mismatch"):
            self.calendar.grant_access(
                requester_aid="bob:expense",
                purpose="expense_report",
                data_class="calendar",
                record_scope=["cal-available"],
                allowed_fields=["availability"],
            )

    def test_domain_stores_reject_wrong_data_class(self):
        for store, data_class in ((MailStore(self.backend), "mail"), (DocumentStore(self.backend), "document"), (MemoryStore(self.backend), "memory")):
            record = DataRecord("wrong", "alice", "calendar", "availability", 1)
            with self.assertRaises(ValueError):
                store.put_payload(record, {"availability": "x"}, self.owner.public_key, purposes=["schedule_meeting"])
            self.assertEqual(store.data_class, data_class)


if __name__ == "__main__":
    unittest.main()
