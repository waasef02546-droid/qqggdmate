"""Deterministic evidence probe for the owner/KMS rewrap boundary.

The probe exercises the public Provider service facade for every rotation
operation.  The initial encrypted object is provisioned through the store's
public ``put`` API because the Provider service intentionally has no object
ingestion endpoint.  No rotation state is mutated through store internals.

This is prototype process-boundary evidence.  It is not an HSM/KMS,
side-channel, secure-memory, or production-cryptography claim.
"""

from __future__ import annotations

import base64
import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from presaga.crypto.key_custody import OwnerRewrapRequest, UmbralOwnerKeyCustody
from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import DataRecord
from presaga.provider.app import PREProviderApp
from presaga.provider.json_repository import to_jsonable
from presaga.provider.registry import RegistrationError
from presaga.provider.server import ProviderService
from presaga.storage.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class KeyCustodyProbeResult:
    scenario: str
    backend: str
    request_schema_version: int
    custody_algorithm: str
    custody_version: int
    custody_key_id_matches_authoritative_source: bool
    signed_artifact_verified: bool
    exact_retry_idempotent: bool
    conflicting_retry_rejected: bool
    conflicting_retry_reason: str
    legacy_private_key_input_rejected: bool
    legacy_rejection_reason: str
    target_decrypt_succeeded: bool
    provider_received_source_private_key: bool
    provider_saw_plaintext_dek: bool
    provider_secret_encodings_checked: str
    provider_view_scope: str
    success: bool
    limitation: str


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _contains_secret(provider_view: bytes, secret: bytes) -> bool:
    return any(
        candidate in provider_view
        for candidate in (
            secret,
            base64.b64encode(secret),
            secret.hex().encode("ascii"),
        )
    )


def run_key_custody_probe(output_root: Path) -> KeyCustodyProbeResult:
    """Run one Umbral owner-key rotation and write its single-row summary."""

    output_root = Path(output_root)
    backend = UmbralPREBackend()
    custody = UmbralOwnerKeyCustody(backend)
    app = PREProviderApp(backend)
    store = EncryptedStore(backend, app.registry, store_id="key-custody-probe-store")
    service = ProviderService(app, object_store=store)

    owner_aid = "alice@example.com:calendar"
    record = DataRecord(
        record_id="key-custody-probe-record",
        owner_aid=owner_aid,
        data_class="calendar",
        data_subclass="availability",
        version=1,
    )
    plaintext = b"available"
    source = backend.generate_keypair()
    target = backend.generate_keypair()

    service.register_agent(
        {"aid": owner_aid, "public_key_b64": _b64(source.public_key)}
    )
    stored = store.put(record, plaintext)
    source_wrap = stored.owner_wraps[0]
    source_context = store.wrap_context(record, source_wrap.provenance)
    plaintext_dek = backend.unwrap_dek(
        source_wrap.encrypted_dek,
        source.private_key,
        source_context,
    )

    prepared = service.prepare_agent_replacement(
        {
            "aid": owner_aid,
            "public_key_b64": _b64(target.public_key),
            "expected_version": 1,
        }
    )
    rotation_id = str(prepared["rotation_id"])
    request_payload = service.export_agent_rewrap_request(
        {
            "aid": owner_aid,
            "record_id": record.record_id,
            "expected_version": 1,
            "rotation_id": rotation_id,
            "expected_object_revision": stored.object_revision,
        }
    )
    request = OwnerRewrapRequest.from_payload(request_payload)
    artifact = custody.rewrap(request, source.private_key)
    artifact_payload = artifact.to_payload()
    stage_payload = {
        "aid": owner_aid,
        "record_id": record.record_id,
        "expected_version": 1,
        "rotation_id": rotation_id,
        "expected_object_revision": stored.object_revision,
        "artifact": artifact_payload,
    }

    first_stage = service.stage_agent_rewrap(stage_payload)
    repeated_stage = service.stage_agent_rewrap(stage_payload)
    signed_artifact_verified = int(first_stage["object_revision"]) == 2
    exact_retry_idempotent = repeated_stage == first_stage

    conflicting = custody.rewrap(request, source.private_key)
    conflicting_retry_reason = ""
    try:
        service.stage_agent_rewrap(
            {**stage_payload, "artifact": conflicting.to_payload()}
        )
    except RegistrationError as error:
        conflicting_retry_reason = error.reason
    conflicting_retry_rejected = (
        conflicting_retry_reason == "custody_artifact_conflict"
    )

    legacy_rejection_reason = ""
    try:
        service.stage_agent_rewrap(
            {
                **stage_payload,
                # Exercise legacy-field rejection without transmitting the real
                # source secret into the Provider process even for this probe.
                "source_private_key_b64": "forbidden-legacy-field",
            }
        )
    except RegistrationError as error:
        legacy_rejection_reason = error.reason
    legacy_private_key_input_rejected = (
        legacy_rejection_reason == "source_private_key_forbidden"
    )

    service.commit_agent_replacement(
        {
            "aid": owner_aid,
            "expected_version": 1,
            "rotation_id": rotation_id,
        }
    )
    active = store.resolve_active_owner_wrap(record.record_id)
    target_context = store.wrap_context(record, active.provenance)
    target_dek = backend.unwrap_dek(
        active.encrypted_dek,
        target.private_key,
        target_context,
    )
    target_decrypt_succeeded = (
        store.decrypt_with_dek(store.get(record.record_id), target_dek) == plaintext
    )

    provider_view = json.dumps(
        to_jsonable(
            {
                "request": request_payload,
                "artifact": artifact_payload,
                "objects": store.snapshot(),
                "journal": app.management.rotation_journal(),
                "audit": app.audit_query(),
                "first_stage": first_stage,
                "repeated_stage": repeated_stage,
                "legacy_rejection_reason": legacy_rejection_reason,
                "conflicting_retry_reason": conflicting_retry_reason,
            }
        ),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    provider_received_source_private_key = _contains_secret(
        provider_view, source.private_key
    )
    provider_saw_plaintext_dek = _contains_secret(provider_view, plaintext_dek)

    success = all(
        (
            artifact.custody_version == 1,
            artifact.custody_key_id == request.source_registration_id,
            signed_artifact_verified,
            exact_retry_idempotent,
            conflicting_retry_rejected,
            legacy_private_key_input_rejected,
            target_decrypt_succeeded,
            not provider_received_source_private_key,
            not provider_saw_plaintext_dek,
        )
    )
    result = KeyCustodyProbeResult(
        scenario="umbral_owner_kms_rewrap_boundary_v1",
        backend=backend.name,
        request_schema_version=request.schema_version,
        custody_algorithm=artifact.custody_algorithm,
        custody_version=artifact.custody_version,
        custody_key_id_matches_authoritative_source=(
            artifact.custody_key_id == request.source_registration_id
        ),
        signed_artifact_verified=signed_artifact_verified,
        exact_retry_idempotent=exact_retry_idempotent,
        conflicting_retry_rejected=conflicting_retry_rejected,
        conflicting_retry_reason=conflicting_retry_reason,
        legacy_private_key_input_rejected=legacy_private_key_input_rejected,
        legacy_rejection_reason=legacy_rejection_reason,
        target_decrypt_succeeded=target_decrypt_succeeded,
        provider_received_source_private_key=provider_received_source_private_key,
        provider_saw_plaintext_dek=provider_saw_plaintext_dek,
        provider_secret_encodings_checked="raw|base64|hex",
        provider_view_scope="request|artifact|objects|journal|audit|results|errors",
        success=success,
        limitation=(
            "Prototype process-boundary probe only; the owner process materializes the "
            "source key and DEK, reuses the source Umbral key for domain-separated "
            "attestation, and provides no HSM, memory-forensics, side-channel, or "
            "production-security assurance."
        ),
    )

    tables = output_root / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    with (tables / "key_custody_summary.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(result)))
        writer.writeheader()
        writer.writerow(asdict(result))
    return result


__all__ = ["KeyCustodyProbeResult", "run_key_custody_probe"]
