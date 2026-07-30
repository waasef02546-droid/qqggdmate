"""Evidence-backed bridge from the reproduced SAGA runtime to PRE-SAGA.

This runner deliberately does not start a SAGA socket.  Instead, it imports
facts from the checked-in SAGA reproduction logs, then runs the PRE-SAGA
extension for the same Alice/Bob/Mallory narrative.  It therefore separates
what has actually been reproduced (SAGA contact authorization) from what this
prototype adds (data-layer authorization after contact succeeds).
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from experiments.provider_harness import AuthoritativeProviderHarness
from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import (
    DataAccessRequest,
    DataRecord,
    DataScope,
    DataSharingPolicy,
    Limits,
    RequesterSelector,
    Validity,
    VersionConstraints,
)


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SAGA_E2E_EVIDENCE = WORKSPACE_ROOT / "saga_reproduction" / "saga_e2e_terminal_output.txt"
SAGA_MULTI_AGENT_EVIDENCE = WORKSPACE_ROOT / "saga_reproduction" / "saga_multi_agent_terminal_output.txt"


@dataclass(frozen=True)
class SagaBaselineEvidence:
    case: str
    evidence_path: str
    conclusion: str
    contact_authorized: bool
    token_lifecycle_observed: bool


@dataclass(frozen=True)
class SagaBridgeResult:
    case: str
    baseline_evidence_path: str
    baseline_conclusion: str
    saga_contact_allowed: bool
    presaga_data_allowed: bool
    data_layer_decision: str
    reason: str
    plaintext_released: bool
    provider_plaintext_data_visible: bool
    provider_plaintext_dek_visible: bool


def load_saga_baseline_evidence(workspace_root: Path = WORKSPACE_ROOT) -> list[SagaBaselineEvidence]:
    """Load only reproducible facts from the recorded SAGA terminal outputs."""

    sources = (
        (
            "saga_e2e_alice_bob",
            workspace_root / "saga_reproduction" / "saga_e2e_terminal_output.txt",
            "Alice and Bob completed certificate-verified contact, token issuance, quota consumption, and token invalidation.",
            ("POST /access HTTP/1.1 -> 200", "Connected to 127.0.0.1:7000 with verified certificate."),
        ),
        (
            "saga_multi_agent_alice_bob_mallory",
            workspace_root / "saga_reproduction" / "saga_multi_agent_terminal_output.txt",
            "Alice accepted separately authorized Bob and Mallory contact sessions; both consumed and invalidated SAGA tokens.",
            ("[2] Bob -> Alice", "[3] Mallory -> Alice", "Received token: <redacted>"),
        ),
    )
    evidence: list[SagaBaselineEvidence] = []
    for case, path, conclusion, required_markers in sources:
        if not path.is_file():
            raise FileNotFoundError(f"SAGA baseline evidence is missing: {path}")
        text = path.read_text(encoding="utf-8")
        if not all(marker in text for marker in required_markers):
            raise ValueError(f"SAGA baseline evidence lacks required markers: {path}")
        evidence.append(
            SagaBaselineEvidence(
                case=case,
                evidence_path=path.relative_to(workspace_root).as_posix(),
                conclusion=conclusion,
                contact_authorized=True,
                token_lifecycle_observed="Token invalidated from the initiating side." in text,
            )
        )
    return evidence


def run_saga_bridge(*, output_root: Path = Path("results"), workspace_root: Path = WORKSPACE_ROOT) -> list[SagaBridgeResult]:
    """Run the PRE-SAGA extension for SAGA-reproduced Alice/Bob/Mallory cases."""

    evidence = {item.case: item for item in load_saga_baseline_evidence(workspace_root)}
    backend = UmbralPREBackend()
    alice, bob, mallory = (backend.generate_keypair() for _ in range(3))
    provider = AuthoritativeProviderHarness(backend)
    owner_aid = "alice@mail.com:calendar_agent"
    bob_aid = "bob@mail.com:scheduler_agent"
    mallory_aid = "mallory@mail.com:research_agent"
    for aid, keypair in ((owner_aid, alice), (bob_aid, bob), (mallory_aid, mallory)):
        provider.register_agent(aid, keypair.public_key)
    # Both Bob and Mallory may pass the SAGA-style contact gate, matching the
    # multi-agent baseline.  PRE-SAGA must still distinguish their data rights.
    provider.set_contact_rulebook(
        owner_aid,
        [{"pattern": "*@mail.com:*_agent", "budget": 3}],
    )

    record = DataRecord(
        record_id="calendar-availability-001",
        owner_aid=owner_aid,
        data_class="calendar",
        data_subclass="availability",
        version=1,
    )
    store = provider.store
    stored = store.put(record, b"Alice is free from 10:00 to 11:00.")
    now = datetime.now(timezone.utc)
    provider.add_data_policy(
        DataSharingPolicy(
            policy_id="bridge-calendar-bob-only",
            owner_aid=owner_aid,
            requester_selector=RequesterSelector(type="aid_exact", value=bob_aid),
            data_scope=DataScope(data_classes=["calendar"], data_subclasses=["availability"], record_ids=[record.record_id]),
            purposes=["schedule_meeting"],
            validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
            limits=Limits(max_uses=1, max_records=1),
            version_constraints=VersionConstraints(min_version=1, max_version=1),
            obligations={"projection": ["availability"], "audit": True},
        )
    )

    results = [
        _run_case(
            provider=provider, backend=backend, stored=stored, record=record,
            owner_aid=owner_aid, requester_aid=bob_aid, requester_private_key=bob.private_key,
            requester_public_key=bob.public_key, owner_private_key=alice.private_key,
            case="alice_bob_authorized_calendar", evidence=evidence["saga_e2e_alice_bob"],
        ),
        _run_case(
            provider=provider, backend=backend, stored=stored, record=record,
            owner_aid=owner_aid, requester_aid=mallory_aid, requester_private_key=mallory.private_key,
            requester_public_key=mallory.public_key, owner_private_key=alice.private_key,
            case="alice_mallory_contact_allowed_data_denied", evidence=evidence["saga_multi_agent_alice_bob_mallory"],
        ),
    ]
    _write_outputs(results, output_root)
    return results


def _run_case(*, provider: AuthoritativeProviderHarness, backend: UmbralPREBackend, stored, record: DataRecord,
              owner_aid: str, requester_aid: str, requester_private_key: bytes, requester_public_key: bytes,
              owner_private_key: bytes, case: str, evidence: SagaBaselineEvidence) -> SagaBridgeResult:
    contact = provider.issue_contact_session(owner_aid, requester_aid)
    contact_allowed = contact is not None and provider.app.validate_contact_session(
        contact, owner_aid=owner_aid, requester_aid=requester_aid
    ).effect == "allow"
    request = DataAccessRequest(
        request_id=f"bridge-{case}", owner_aid=owner_aid, requester_aid=requester_aid,
        record_id=record.record_id, data_class=record.data_class, data_subclass=record.data_subclass,
        purpose="schedule_meeting", version=record.version, requester_public_key=requester_public_key,
    )
    plaintext_released = False
    if contact is None:
        data_layer_decision = "deny"
        reason = "contact_denied"
    else:
        issuance = provider.issue_data_token(contact, request)
        data_layer_decision = issuance.decision
        reason = issuance.reason
        token = issuance.token
    if contact is not None and data_layer_decision == "allow":
        if token is None:
            raise RuntimeError(reason)
        owner_wrap = provider.store.resolve_active_owner_wrap(stored)
        wrap_context = provider.store.wrap_context(
            stored.record,
            owner_wrap.provenance,
        )
        rekey = backend.generate_rekey(owner_private_key, requester_public_key, wrap_context)
        transform = provider.request_re_encryption(
            token,
            request,
            rekey,
        )
        if (
            transform.decision == "allow"
            and transform.transformed_encrypted_dek
        ):
            dek = backend.unwrap_dek(
                transform.transformed_encrypted_dek,
                requester_private_key,
                wrap_context,
            )
            plaintext_released = (
                provider.store.decrypt_with_dek(stored, dek)
                == b"Alice is free from 10:00 to 11:00."
            )
    audit_events = provider.app.audit_query()
    return SagaBridgeResult(
        case=case, baseline_evidence_path=evidence.evidence_path, baseline_conclusion=evidence.conclusion,
        saga_contact_allowed=contact_allowed,
        presaga_data_allowed=data_layer_decision == "allow",
        data_layer_decision=data_layer_decision, reason=reason, plaintext_released=plaintext_released,
        provider_plaintext_data_visible=any(event.provider_saw_plaintext_data for event in audit_events),
        provider_plaintext_dek_visible=any(event.provider_saw_plaintext_dek for event in audit_events),
    )


def _write_outputs(results: list[SagaBridgeResult], output_root: Path) -> None:
    tables = output_root / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    with (tables / "saga_bridge_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        writer.writerows(asdict(result) for result in results)
    report_lines = [
        "# SAGA baseline to PRE-SAGA bridge report", "",
        "This artifact does not claim that PRE-SAGA started a live SAGA socket. It imports recorded SAGA reproduction evidence, then executes the PRE-SAGA data-layer extension for the same Alice/Bob/Mallory narrative.", "",
        "## Evidence boundary", "",
        "The listed baseline paths are recorded terminal outputs for SAGA Provider access, certificate-verified communication, token issuance, quota consumption, and invalidation. PRE-SAGA results below are local extension results, not retroactive claims about the SAGA implementation.", "",
        "## Cases", "",
    ]
    for result in results:
        report_lines.extend([
            f"### {result.case}", "",
            f"- SAGA baseline evidence: `{result.baseline_evidence_path}`",
            f"- Baseline conclusion: {result.baseline_conclusion}",
            f"- SAGA contact allowed: `{result.saga_contact_allowed}`",
            f"- PRE-SAGA data decision: `{result.data_layer_decision}` ({result.reason})",
            f"- Plaintext released: `{result.plaintext_released}`",
            f"- Provider saw plaintext data/DEK: `{result.provider_plaintext_data_visible}` / `{result.provider_plaintext_dek_visible}`", "",
        ])
    report_lines.extend([
        "## Interpretation", "",
        "Bob's already-authorized contact session obtains the narrowly scoped calendar availability record. Mallory's SAGA-compatible contact session is intentionally allowed, but the PRE-SAGA data policy denies the same record because the policy binds access to Bob's AID. This is the measured contact-layer/data-layer separation; it is not a claim that SAGA itself exposes or stores this calendar record.",
    ])
    (output_root / "saga_bridge_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    for result in run_saga_bridge():
        print(result)
