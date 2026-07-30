"""Shared fixtures and result helpers for PRE-SAGA attack experiments."""

from __future__ import annotations

import csv
import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import (
    ContactToken,
    DataAccessRequest,
    DataRecord,
    DataScope,
    DataSharingPolicy,
    Limits,
    RequesterSelector,
    Validity,
    VersionConstraints,
)
from presaga.storage.encrypted_store import EncryptedStore, StoredObject

from experiments.provider_harness import AuthoritativeProviderHarness


OWNER_AID = "alice@mail.com:calendar_agent"
REQUESTER_AID = "bob@mail.com:scheduler_agent"
INTRUDER_AID = "carol@mail.com:research_agent"


@dataclass(frozen=True)
class AttackResult:
    attack: str
    path_kind: str
    observation_source: str
    baseline_contact_allowed: bool
    expected_blocked: bool
    blocked: bool
    success: bool
    reason: str
    latency_ms: float
    audit_id: str
    strength_note: str

    def to_csv_row(self) -> dict[str, str | float | bool]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)


@dataclass
class AttackEnvironment:
    provider: AuthoritativeProviderHarness
    backend: UmbralPREBackend
    owner_keypair: object
    requester_keypair: object
    intruder_keypair: object
    store: EncryptedStore
    stored: StoredObject
    policy: DataSharingPolicy
    contact_token: ContactToken
    intruder_contact_token: ContactToken


def make_environment(*, max_uses: int = 1) -> AttackEnvironment:
    backend = UmbralPREBackend()
    owner = backend.generate_keypair()
    requester = backend.generate_keypair()
    intruder = backend.generate_keypair()
    record = DataRecord(
        record_id="cal-001",
        owner_aid=OWNER_AID,
        data_class="calendar",
        data_subclass="availability",
        version=1,
    )
    now = datetime.now(timezone.utc)
    policy = DataSharingPolicy(
        policy_id="policy-calendar-v1",
        owner_aid=OWNER_AID,
        requester_selector=RequesterSelector(type="aid_exact", value=REQUESTER_AID),
        data_scope=DataScope(data_classes=["calendar"], data_subclasses=["availability"], record_ids=["cal-001"]),
        purposes=["schedule_meeting"],
        validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
        limits=Limits(max_uses=max_uses, max_records=1),
        version_constraints=VersionConstraints(min_version=1, max_version=1),
    )
    provider = AuthoritativeProviderHarness(backend)
    provider.register_agent(OWNER_AID, owner.public_key)
    provider.register_agent(REQUESTER_AID, requester.public_key)
    provider.register_agent(INTRUDER_AID, intruder.public_key)
    store = provider.store
    stored = store.put(record, b"Alice is free from 10:00 to 11:00.")
    provider.add_data_policy(policy)
    provider.set_contact_rulebook(
        OWNER_AID,
        [
            {"pattern": REQUESTER_AID, "budget": 100},
            {"pattern": INTRUDER_AID, "budget": 100},
        ],
    )
    contact_token = provider.issue_contact_session(OWNER_AID, REQUESTER_AID)
    intruder_contact_token = provider.issue_contact_session(OWNER_AID, INTRUDER_AID)
    if contact_token is None or intruder_contact_token is None:
        raise RuntimeError("fixture contact policy should issue requester and intruder Contact tokens")
    return AttackEnvironment(
        provider=provider,
        backend=backend,
        owner_keypair=owner,
        requester_keypair=requester,
        intruder_keypair=intruder,
        store=store,
        stored=stored,
        policy=policy,
        contact_token=contact_token,
        intruder_contact_token=intruder_contact_token,
    )


def allowed_request(env: AttackEnvironment) -> DataAccessRequest:
    return DataAccessRequest(
        request_id="req-allowed",
        owner_aid=OWNER_AID,
        requester_aid=REQUESTER_AID,
        record_id="cal-001",
        data_class="calendar",
        data_subclass="availability",
        purpose="schedule_meeting",
        version=1,
        requester_public_key=env.requester_keypair.public_key,  # type: ignore[attr-defined]
    )


def issue_allowed_token(env: AttackEnvironment):
    request = allowed_request(env)
    issuance = env.provider.issue_data_token(env.contact_token, request)
    if issuance.token is None:
        raise RuntimeError(
            f"authoritative Provider path denied fixture request: {issuance.reason}"
        )
    return issuance.token


def rekey_for_requester(env: AttackEnvironment) -> bytes:
    owner_wrap = env.store.resolve_active_owner_wrap(env.stored)
    return env.backend.generate_rekey(
        env.owner_keypair.private_key,  # type: ignore[attr-defined]
        env.requester_keypair.public_key,  # type: ignore[attr-defined]
        env.store.wrap_context(env.stored.record, owner_wrap.provenance),
    )


def contact_authorized(env: AttackEnvironment, contact_token: ContactToken) -> bool:
    decision = env.provider.app.validate_contact_session(
        contact_token,
        owner_aid=contact_token.owner_aid,
        requester_aid=contact_token.requester_aid,
    )
    return decision.effect == "allow"


def run_with_timer(attack_name: str, fn) -> AttackResult:
    started = time.perf_counter()
    result = fn()
    latency_ms = (time.perf_counter() - started) * 1000
    return AttackResult(
        attack=attack_name,
        path_kind=result.get("path_kind", "provider_service"),
        observation_source=result.get(
            "observation_source",
            "provider_decision_and_audit",
        ),
        baseline_contact_allowed=result["baseline_contact_allowed"],
        expected_blocked=result.get("expected_blocked", True),
        blocked=result["blocked"],
        success=(
            result["blocked"]
            if result.get("expected_blocked", True)
            else not result["blocked"]
        ),
        reason=result["reason"],
        latency_ms=round(latency_ms, 3),
        audit_id=result["audit_id"],
        strength_note=result["strength_note"],
    )


def write_security_matrix(results: list[AttackResult], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(asdict(results[0]).keys()) if results else []
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result.to_csv_row())
