from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROOFS = ROOT / "proofs"


class FormalArtifactTest(unittest.TestCase):
    def test_dek_secrecy_model_contains_required_queries(self):
        content = (PROOFS / "presaga_dek_secrecy.pv").read_text(encoding="utf-8")
        self.assertIn("query attacker(secret_dek).", content)
        self.assertIn("event PolicyAllow", content)
        self.assertIn("event TransformIssued", content)
        self.assertIn("==> event(PolicyAllow", content)

    def test_rekey_authentication_model_contains_binding_events(self):
        content = (PROOFS / "presaga_rekey_authentication.pv").read_text(encoding="utf-8")
        self.assertIn("event TokenIssued", content)
        self.assertIn("event TransformAccepted", content)
        self.assertIn("event TransformRejected", content)
        self.assertIn("requester", content)
        self.assertIn("purpose", content)
        self.assertIn("version", content)

    def test_formal_readme_states_boundaries(self):
        content = (PROOFS / "README.md").read_text(encoding="utf-8")
        self.assertIn("not a proof of a new proxy re-encryption primitive", content)
        self.assertIn("metadata privacy", content)
        self.assertIn("toy PRE backend", content)


if __name__ == "__main__":
    unittest.main()
