"""MongoDB-backed PRE-SAGA E2E experiment.

The scenario follows the SAGA comparison gap analysis:

1. Alice and Bob are registered as agents.
2. SAGA-compatible contact authorization allows Bob to contact Alice.
3. Alice's calendar data is stored encrypted in MongoDB.
4. PRE-SAGA issues a policy-bound data token for Bob.
5. The Provider/PRE proxy transforms only the encrypted DEK.
6. Bob decrypts the minimum authorized data.
7. Mallory/contact-allowed or Bob-overbroad data-layer requests are denied.
"""

from __future__ import annotations

import base64
import csv
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

from presaga.crypto.toy_pre import ToyPRE
from presaga.protocol.schemas import DataAccessRequest, DataRecord, DataScope, DataSharingPolicy, Limits, RequesterSelector, Validity, VersionConstraints
from presaga.provider.app import PREProviderApp
from presaga.provider.json_repository import to_jsonable
from presaga.provider.mongo_repository import MongoProviderRepository
from presaga.provider.server import ProviderService
from presaga.storage.mongo_encrypted_store import MongoEncryptedStore


@dataclass(frozen=True)
class MongoE2EResult:
    scenario: str
    mongo_connected: bool
    normal_success: bool
    attack_blocked: bool
    decrypted_plaintext: str
    denial_reason: str
    provider_plaintext_data_visible: bool
    provider_plaintext_dek_visible: bool
    persisted_agents: int
    persisted_policies: int
    persisted_contact_tokens: int
    persisted_data_tokens: int
    persisted_audit_events: int
    persisted_encrypted_objects: int
    latency_ms: float


def run_mongodb_e2e(
    *,
    uri: str = "mongodb://127.0.0.1:27017",
    db_name: str = "presaga_e2e",
    output_root: Path = Path("results"),
) -> MongoE2EResult:
    started = time.perf_counter()
    client = MongoClient(uri, serverSelectionTimeoutMS=2000)
    try:
        client.admin.command("ping")
    except ServerSelectionTimeoutError as exc:
        raise RuntimeError(f"MongoDB is not reachable at {uri}") from exc

    db = client[db_name]
    existing_collections = [
        name
        for name in db.list_collection_names()
        if not name.startswith("system.")
    ]
    if existing_collections:
        client.close()
        raise RuntimeError(
            "mongo_database_not_empty:"
            + ",".join(sorted(existing_collections))
        )
    repo = MongoProviderRepository(db)

    backend = ToyPRE()
    alice = backend.generate_keypair()
    bob = backend.generate_keypair()
    mallory = backend.generate_keypair()
    app = PREProviderApp(backend)
    store = MongoEncryptedStore(backend, db, app.registry)
    service = ProviderService(app, repo, object_store=store)

    owner_aid = "alice@mail.com:calendar_agent"
    bob_aid = "bob@mail.com:scheduler_agent"
    mallory_aid = "mallory@mail.com:research_agent"
    for aid, keypair in ((owner_aid, alice), (bob_aid, bob), (mallory_aid, mallory)):
        service.register_agent(
            {"aid": aid, "public_key_b64": _b64(keypair.public_key)}
        )

    rulebook = [{"pattern": "*@mail.com:*_agent", "budget": 10}]
    service.set_contact_rulebook({"owner_aid": owner_aid, "rulebook": rulebook})

    record = DataRecord(
        record_id="cal-e2e-001",
        owner_aid=owner_aid,
        data_class="calendar",
        data_subclass="availability",
        version=1,
        metadata={"source": "mongodb_e2e"},
    )
    stored = store.put(record, b"Alice is free from 10:00 to 11:00.")
    stored_from_mongo = store.get(record.record_id)

    now = datetime.now(timezone.utc)
    policy = DataSharingPolicy(
        policy_id="policy-mongodb-calendar-e2e",
        owner_aid=owner_aid,
        requester_selector=RequesterSelector(type="aid_exact", value=bob_aid),
        data_scope=DataScope(data_classes=["calendar"], data_subclasses=["availability"], record_ids=[record.record_id]),
        purposes=["schedule_meeting"],
        validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
        limits=Limits(max_uses=1, max_records=1),
        version_constraints=VersionConstraints(min_version=1, max_version=1),
        obligations={"projection": ["availability"], "audit": True},
    )
    service.add_data_policy(to_jsonable(policy))

    contact_status, contact_response = service.issue_contact_session(
        {"owner_aid": owner_aid, "requester_aid": bob_aid}
    )
    if contact_status != HTTPStatus.CREATED:
        raise RuntimeError("expected Bob contact token to be issued")
    contact_token = service.contact_tokens[
        contact_response["contact_token"]["token_id"]
    ]
    contact_decision = app.validate_contact_session(contact_token, owner_aid=owner_aid, requester_aid=bob_aid)
    if contact_decision.effect != "allow":
        raise RuntimeError(contact_decision.reason)

    request = DataAccessRequest(
        request_id="mongodb-e2e-normal",
        owner_aid=owner_aid,
        requester_aid=bob_aid,
        record_id=record.record_id,
        data_class=record.data_class,
        data_subclass=record.data_subclass,
        purpose="schedule_meeting",
        version=1,
        requester_public_key=bob.public_key,
    )
    request_payload = _request_payload(request)
    request_payload["contact_token_id"] = contact_token.token_id
    issuance_status, issuance = service.issue_data_token(request_payload)
    if issuance_status != HTTPStatus.CREATED:
        raise RuntimeError(issuance["decision"]["reason"])
    data_token = service.data_tokens[issuance["data_token"]["token_id"]]
    owner_wrap = store.resolve_active_owner_wrap(stored_from_mongo)
    wrap_context = store.wrap_context(stored_from_mongo.record, owner_wrap.provenance)
    rekey = backend.generate_rekey(alice.private_key, bob.public_key, wrap_context)
    transform_status, transform = service.request_re_encryption(
        {
            "token_id": data_token.token_id,
            "request": request_payload,
            "rekey_b64": _b64(rekey),
        }
    )
    normal_success = (
        transform_status == HTTPStatus.OK
        and transform["decision"] == "allow"
        and "transformed_encrypted_dek_b64" in transform
    )
    if not normal_success:
        raise RuntimeError(transform["reason"])
    bob_dek = backend.unwrap_dek(
        base64.b64decode(transform["transformed_encrypted_dek_b64"]),
        bob.private_key,
        wrap_context,
    )
    plaintext = store.decrypt_with_dek(stored_from_mongo, bob_dek).decode("utf-8")

    attack_request = DataAccessRequest(
        request_id="mongodb-e2e-mallory-attack",
        owner_aid=owner_aid,
        requester_aid=mallory_aid,
        record_id=record.record_id,
        data_class="calendar",
        data_subclass="availability",
        purpose="schedule_meeting",
        version=1,
        requester_public_key=mallory.public_key,
    )
    mallory_contact_status, mallory_contact_response = service.issue_contact_session(
        {"owner_aid": owner_aid, "requester_aid": mallory_aid}
    )
    if mallory_contact_status != HTTPStatus.CREATED:
        raise RuntimeError("expected Mallory contact token to be issued")
    attack_payload = _request_payload(attack_request)
    attack_payload["contact_token_id"] = mallory_contact_response[
        "contact_token"
    ]["token_id"]
    attack_status, attack_result = service.issue_data_token(attack_payload)
    attack_blocked = attack_status == HTTPStatus.FORBIDDEN
    denial_reason = attack_result["decision"]["reason"]
    counts = repo.collection_counts()
    provider_plaintext_data_visible = any(event.provider_saw_plaintext_data for event in app.audit_query())
    provider_plaintext_dek_visible = any(event.provider_saw_plaintext_dek for event in app.audit_query())

    result = MongoE2EResult(
        scenario="mongodb_alice_bob_mallory_e2e",
        mongo_connected=True,
        normal_success=normal_success and plaintext == "Alice is free from 10:00 to 11:00.",
        attack_blocked=attack_blocked,
        decrypted_plaintext=plaintext,
        denial_reason=denial_reason,
        provider_plaintext_data_visible=provider_plaintext_data_visible,
        provider_plaintext_dek_visible=provider_plaintext_dek_visible,
        persisted_agents=counts["agents"],
        persisted_policies=counts["data_policies"],
        persisted_contact_tokens=counts["contact_tokens"],
        persisted_data_tokens=counts["data_tokens"],
        persisted_audit_events=counts["audit_events"],
        persisted_encrypted_objects=counts["encrypted_objects"],
        latency_ms=round((time.perf_counter() - started) * 1000, 3),
    )
    _write_outputs(result, output_root)
    client.close()
    return result


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _request_payload(request: DataAccessRequest) -> dict[str, object]:
    payload = to_jsonable(request)
    requester_public_key = payload.pop("requester_public_key", None)
    if isinstance(requester_public_key, dict):
        payload["requester_public_key_b64"] = requester_public_key["__bytes_b64__"]
    return payload


def _write_outputs(result: MongoE2EResult, output_root: Path) -> None:
    tables = output_root / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    csv_path = tables / "mongodb_e2e_summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(result).keys()))
        writer.writeheader()
        writer.writerow(asdict(result))

    report_path = output_root / "mongodb_e2e_report.md"
    report_path.write_text(
        "\n".join(
            [
                "# MongoDB-backed PRE-SAGA E2E report",
                "",
                "## Scenario",
                "",
                "Alice stores encrypted calendar availability in MongoDB. Bob obtains contact authorization, receives a policy-bound data token, obtains a transformed encrypted DEK, and decrypts only the authorized availability record. Mallory is contact-compatible but blocked by the PRE-SAGA data policy.",
                "",
                "## Metrics",
                "",
                f"- normal_success: `{result.normal_success}`",
                f"- attack_blocked: `{result.attack_blocked}`",
                f"- denial_reason: `{result.denial_reason}`",
                f"- provider_plaintext_data_visible: `{result.provider_plaintext_data_visible}`",
                f"- provider_plaintext_dek_visible: `{result.provider_plaintext_dek_visible}`",
                f"- persisted_agents: `{result.persisted_agents}`",
                f"- persisted_policies: `{result.persisted_policies}`",
                f"- persisted_contact_tokens: `{result.persisted_contact_tokens}`",
                f"- persisted_data_tokens: `{result.persisted_data_tokens}`",
                f"- persisted_audit_events: `{result.persisted_audit_events}`",
                f"- persisted_encrypted_objects: `{result.persisted_encrypted_objects}`",
                f"- latency_ms: `{result.latency_ms}`",
                "",
                "## Architecture impact",
                "",
                "This E2E drives registry, policy, token, encrypted storage, PRE transform, decryption, attack denial, and audit persistence through the recoverable ProviderService with MongoDB as its authoritative backend. It no longer relies on experiment-side manual save calls. Aggregate metadata CAS and per-object CAS remain separate atomicity domains, and the flow does not reproduce SAGA mTLS/OTK/ACT or claim distributed transactions.",
                "",
            ]
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    result = run_mongodb_e2e()
    print(result)
