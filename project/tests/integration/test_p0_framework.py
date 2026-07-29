from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.baselines.presaga import run_baseline as run_presaga
from experiments.baselines.saga_contact_only import run_baseline as run_saga_contact_only
from experiments.baselines.token_plaintext_server import run_baseline as run_token_plaintext_server
from experiments.tasks.run_all import run_all as run_tasks
from presaga.crypto.hpke_kem_stub import HPKEKEMStub
from presaga.provider.app import PREProviderApp


ROOT = Path(__file__).resolve().parents[2]


class P0FrameworkTest(unittest.TestCase):
    def test_required_framework_paths_exist(self):
        required = [
            ROOT / "configs" / "local.yaml",
            ROOT / "configs" / "experiment.yaml",
            ROOT / "configs" / "policies" / "contact_policy_examples.yaml",
            ROOT / "configs" / "policies" / "data_sharing_policy_examples.yaml",
            ROOT / "experiments" / "data" / "calendar_seed.jsonl",
            ROOT / "experiments" / "tasks" / "schedule_meeting.py",
            ROOT / "experiments" / "baselines" / "saga_contact_only.py",
            ROOT / "proofs" / "presaga_token_secrecy.pv",
        ]
        for path in required:
            with self.subTest(str(path)):
                self.assertTrue(path.exists())

    def test_provider_app_and_hpke_stub_are_instantiable(self):
        backend = HPKEKEMStub()
        app = PREProviderApp(backend)
        keypair = backend.generate_keypair()
        app.management.register_agent("alice@mail.com:test_agent", keypair.public_key)
        self.assertEqual(keypair.public_key, app.registry.get("alice@mail.com:test_agent").public_key)

    def test_task_scripts_run(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            results, _ = run_tasks(
                Path(temp_dir) / "task_results.csv"
            )
        self.assertEqual(4, len(results))
        for result in results:
            with self.subTest(result.task):
                self.assertTrue(result.success)
                self.assertEqual("task_completed", result.reason)
                self.assertTrue(result.plaintext)

    def test_baselines_run(self):
        self.assertTrue(run_saga_contact_only().contact_allowed)
        self.assertTrue(run_token_plaintext_server().provider_plaintext_data_visible)
        presaga = run_presaga()
        self.assertTrue(presaga.success)
        self.assertFalse(
            presaga.cryptographic_provider_confidentiality_established
        )


if __name__ == "__main__":
    unittest.main()
