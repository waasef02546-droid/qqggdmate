"""Shared task fixtures for task-level PRE-SAGA experiments."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
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
from presaga.provider.app import PREProviderApp
from presaga.storage.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class TaskResult:
    task: str
    success: bool
    reason: str
    latency_ms: float
    plaintext: str
    audit_events: int


def load_seed(filename: str) -> dict:
    path = Path(__file__).resolve().parents[1] / "data" / filename
    with path.open(encoding="utf-8") as handle:
        return json.loads(handle.readline())


def run_authorized_task(
    *,
    task_name: str,
    seed_file: str,
    requester_aid: str,
    allowed_purpose: str,
) -> TaskResult:
    started = time.perf_counter()
    seed = load_seed(seed_file)
    backend = ToyPRE()
    owner = backend.generate_keypair()
    requester = backend.generate_keypair()
    app = PREProviderApp(backend)
    store = EncryptedStore(backend)

    owner_aid = seed["owner_aid"]
    app.register_agent(owner_aid, owner.public_key)
    app.register_agent(requester_aid, requester.public_key)
    app.set_contact_rulebook(owner_aid, [{"pattern": requester_aid, "budget": 10}])
    contact = app.issue_contact_session(owner_aid, requester_aid)
    if contact is None:
        return TaskResult(task_name, False, "contact_denied", 0.0, "", 0)

    record = DataRecord(
        record_id=seed["record_id"],
        owner_aid=owner_aid,
        data_class=seed["data_class"],
        data_subclass=seed["data_subclass"],
        version=int(seed["version"]),
    )
    stored = store.put(record, seed["plaintext"].encode("utf-8"), owner.public_key)
    now = datetime.now(timezone.utc)
    app.add_data_policy(
        DataSharingPolicy(
            policy_id=f"policy-{task_name}",
            owner_aid=owner_aid,
            requester_selector=RequesterSelector(type="aid_exact", value=requester_aid),
            data_scope=DataScope(
                data_classes=[seed["data_class"]],
                data_subclasses=[seed["data_subclass"]],
                record_ids=[seed["record_id"]],
            ),
            purposes=[allowed_purpose],
            validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
            limits=Limits(max_uses=1, max_records=1),
            version_constraints=VersionConstraints(min_version=record.version, max_version=record.version),
        )
    )
    request = DataAccessRequest(
        request_id=f"task-{task_name}",
        owner_aid=owner_aid,
        requester_aid=requester_aid,
        record_id=record.record_id,
        data_class=record.data_class,
        data_subclass=record.data_subclass,
        purpose=allowed_purpose,
        version=record.version,
        requester_public_key=requester.public_key,
    )
    decision = app.evaluate_data_request(request)
    if decision.effect != "allow":
        return TaskResult(task_name, False, decision.reason, 0.0, "", len(app.audit_query()))

    token = app.issue_data_token(decision, request)
    rekey = backend.generate_rekey(owner.private_key, requester.public_key, store.context(record))
    result = app.request_re_encryption(
        token=token,
        request=request,
        encrypted_dek_owner=stored.encrypted_dek_owner,
        rekey=rekey,
    )
    if result.decision != "allow" or result.transformed_encrypted_dek is None:
        return TaskResult(task_name, False, result.reason, 0.0, "", len(app.audit_query()))

    dek = backend.unwrap_dek(result.transformed_encrypted_dek, requester.private_key, store.context(record))
    plaintext = store.decrypt_with_dek(stored, dek).decode("utf-8")
    latency_ms = round((time.perf_counter() - started) * 1000, 3)
    return TaskResult(task_name, True, "task_completed", latency_ms, plaintext, len(app.audit_query()))
