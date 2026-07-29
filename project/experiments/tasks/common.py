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
from presaga.storage import CalendarStore, DocumentStore, MailStore, MemoryStore, PolicyAwareStore

from experiments.provider_harness import AuthoritativeProviderHarness


@dataclass(frozen=True)
class TaskResult:
    task: str
    success: bool
    reason: str
    latency_ms: float
    plaintext: str
    audit_events: int
    contact_ms: float = 0.0
    authorization_ms: float = 0.0
    pre_transform_ms: float = 0.0
    decrypt_ms: float = 0.0


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

    owner_aid = seed["owner_aid"]
    provider = AuthoritativeProviderHarness(
        backend,
        store_factory=lambda selected_backend, registry: _store_for_data_class(
            selected_backend,
            registry,
            seed["data_class"],
        ),
    )
    provider.register_agent(owner_aid, owner.public_key)
    provider.register_agent(requester_aid, requester.public_key)
    provider.set_contact_rulebook(
        owner_aid,
        [{"pattern": requester_aid, "budget": 10}],
    )
    store = provider.store

    contact_started = time.perf_counter()
    contact = provider.issue_contact_session(owner_aid, requester_aid)
    if contact is None:
        return TaskResult(task_name, False, "contact_denied", 0.0, "", 0)
    contact_ms = round((time.perf_counter() - contact_started) * 1000, 3)

    record = DataRecord(
        record_id=seed["record_id"],
        owner_aid=owner_aid,
        data_class=seed["data_class"],
        data_subclass=seed["data_subclass"],
        version=int(seed["version"]),
    )
    allowed_fields = [seed["data_subclass"]]
    stored = store.put_payload(
        record,
        {
            seed["data_subclass"]: seed["plaintext"],
            "owner_internal_note": "not released to delegated agents",
        },
        purposes=[seed["purpose"]],
    )
    now = datetime.now(timezone.utc)
    provider.add_data_policy(
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
    authorization_started = time.perf_counter()
    issuance = provider.issue_data_token(contact, request)
    authorization_ms = round(
        (time.perf_counter() - authorization_started) * 1000,
        3,
    )
    if issuance.token is None:
        return TaskResult(
            task_name,
            False,
            issuance.reason,
            0.0,
            "",
            len(provider.app.audit_query()),
            contact_ms=contact_ms,
            authorization_ms=authorization_ms,
        )
    token = issuance.token
    owner_wrap = store.resolve_active_owner_wrap(stored)
    wrap_context = store.wrap_context(stored.record, owner_wrap.provenance)
    rekey = backend.generate_rekey(owner.private_key, requester.public_key, wrap_context)

    transform_started = time.perf_counter()
    result = provider.request_re_encryption(token, request, rekey)
    pre_transform_ms = round((time.perf_counter() - transform_started) * 1000, 3)
    if result.decision != "allow" or result.transformed_encrypted_dek is None:
        return TaskResult(
            task_name,
            False,
            result.reason,
            0.0,
            "",
            len(provider.app.audit_query()),
            contact_ms=contact_ms,
            authorization_ms=authorization_ms,
            pre_transform_ms=pre_transform_ms,
        )

    decrypt_started = time.perf_counter()
    dek = backend.unwrap_dek(result.transformed_encrypted_dek, requester.private_key, wrap_context)
    # This is the tool-facing data access point: it applies the approved
    # requester, purpose, record scope, data class, and field projection.
    grant = store.grant_access(
        requester_aid=request.requester_aid,
        purpose=request.purpose,
        data_class=request.data_class,
        record_scope=[request.record_id],
        allowed_fields=allowed_fields,
    )
    projected = store.read_projection(
        grant=grant,
        record_id=request.record_id,
        dek=dek,
        requested_fields=allowed_fields,
    )
    plaintext = json.dumps(projected, sort_keys=True)
    decrypt_ms = round((time.perf_counter() - decrypt_started) * 1000, 3)
    latency_ms = round((time.perf_counter() - started) * 1000, 3)
    return TaskResult(
        task_name,
        True,
        "task_completed",
        latency_ms,
        plaintext,
        len(provider.app.audit_query()),
        contact_ms=contact_ms,
        authorization_ms=authorization_ms,
        pre_transform_ms=pre_transform_ms,
        decrypt_ms=decrypt_ms,
    )


def _store_for_data_class(backend: ToyPRE, registry, data_class: str) -> PolicyAwareStore:
    stores: dict[str, type[PolicyAwareStore]] = {
        "calendar": CalendarStore,
        "mail": MailStore,
        "document": DocumentStore,
        "memory": MemoryStore,
    }
    try:
        return stores[data_class](backend, registry)
    except KeyError as exc:
        raise ValueError(f"No policy-aware tool store for {data_class!r}") from exc
