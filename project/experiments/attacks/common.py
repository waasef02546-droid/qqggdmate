"""Shared fixtures and result helpers for PRE-SAGA attack experiments."""

from __future__ import annotations

import csv
import json
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from presaga.crypto.toy_pre import ToyPRE
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
from presaga.provider.audit import AuditLogger
from presaga.provider.contact_policy import SAGAStyleContactPolicy
from presaga.provider.data_policy import DataPolicyEvaluator
from presaga.provider.pre_proxy import PREProxy
from presaga.provider.token_service import TokenService
from presaga.storage.encrypted_store import EncryptedStore, StoredObject


OWNER_AID = "alice@mail.com:calendar_agent"
REQUESTER_AID = "bob@mail.com:scheduler_agent"
INTRUDER_AID = "carol@mail.com:research_agent"


@dataclass(frozen=True)
class AttackResult:
    attack: str
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
    backend: ToyPRE
    owner_keypair: object
    requester_keypair: object
    intruder_keypair: object
    store: EncryptedStore
    stored: StoredObject
    policy: DataSharingPolicy
    token_service: TokenService
    audit: AuditLogger
    proxy: PREProxy
    contact_policy: SAGAStyleContactPolicy


def make_environment(*, max_uses: int = 1) -> AttackEnvironment:
    backend = ToyPRE()
    owner = backend.generate_keypair()
    requester = backend.generate_keypair()
    intruder = backend.generate_keypair()
    store = EncryptedStore(backend)
    record = DataRecord(
        record_id="cal-001",
        owner_aid=OWNER_AID,
        data_class="calendar",
        data_subclass="availability",
        version=1,
    )
    stored = store.put(record, b"Alice is free from 10:00 to 11:00.", owner.public_key)
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
    token_service = TokenService(b"issuer-secret")
    audit = AuditLogger()
    return AttackEnvironment(
        backend=backend,
        owner_keypair=owner,
        requester_keypair=requester,
        intruder_keypair=intruder,
        store=store,
        stored=stored,
        policy=policy,
        token_service=token_service,
        audit=audit,
        proxy=PREProxy(backend, token_service, audit),
        contact_policy=SAGAStyleContactPolicy([{"pattern": "*@mail.com:*_agent", "budget": 100}]),
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
    decision = DataPolicyEvaluator([env.policy]).evaluate(request)
    if decision.effect != "allow":
        raise RuntimeError(f"fixture policy should allow the base request, got {decision.reason}")
    return env.token_service.issue_data_token(decision, request)


def rekey_for_requester(env: AttackEnvironment) -> bytes:
    return env.backend.generate_rekey(
        env.owner_keypair.private_key,  # type: ignore[attr-defined]
        env.requester_keypair.public_key,  # type: ignore[attr-defined]
        env.store.context(env.stored.record),
    )


def record_policy_denial(env: AttackEnvironment, request: DataAccessRequest, reason: str, policy_id: str | None) -> str:
    event = env.audit.record(
        event_type="data_policy_evaluation",
        decision="deny",
        reason=reason,
        owner_aid=request.owner_aid,
        requester_aid=request.requester_aid,
        record_id=request.record_id,
        data_class=request.data_class,
        purpose=request.purpose,
        policy_id=policy_id,
        token_id=None,
    )
    return event.audit_id


def run_with_timer(attack_name: str, fn) -> AttackResult:
    started = time.perf_counter()
    result = fn()
    latency_ms = (time.perf_counter() - started) * 1000
    return AttackResult(
        attack=attack_name,
        baseline_contact_allowed=result["baseline_contact_allowed"],
        expected_blocked=True,
        blocked=result["blocked"],
        success=result["blocked"],
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
