from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from presaga.provider.json_repository import JsonProviderRepository
from presaga.provider.repository import RepositoryConflict


class ProviderRepositoryTest(unittest.TestCase):
    def test_json_aggregate_revision_rejects_stale_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "provider-state.json"
            first = JsonProviderRepository(path)
            stale = JsonProviderRepository(path)
            first_state = first.load()
            stale_state = stale.load()

            revision = first.save(first_state, expected_revision=0)
            self.assertEqual(1, revision)
            with self.assertRaises(RepositoryConflict):
                stale.save(stale_state, expected_revision=0)
            self.assertEqual(1, first.load()["state_revision"])


if __name__ == "__main__":
    unittest.main()
