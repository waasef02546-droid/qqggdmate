"""Bounded regression probe over Provider-visible state and PRE artifacts."""

from __future__ import annotations

import base64
import json

from presaga.crypto.pre_interface import PREBackendError
from presaga.provider.json_repository import to_jsonable

from experiments.attacks.common import (
    allowed_request,
    contact_authorized,
    issue_allowed_token,
    make_environment,
    rekey_for_requester,
    run_with_timer,
)


def run_attack():
    def scenario():
        env = make_environment()
        request = allowed_request(env)
        token = issue_allowed_token(env)
        rekey = rekey_for_requester(env)
        result = env.provider.request_re_encryption(
            token,
            request,
            rekey,
        )
        if result.transformed_encrypted_dek is None:
            raise RuntimeError("authorized fixture did not return transformed material")
        owner_wrap = env.store.resolve_active_owner_wrap(env.stored)
        context = env.store.wrap_context(env.stored.record, owner_wrap.provenance)
        actual_dek = env.backend.unwrap_dek(
            owner_wrap.encrypted_dek,
            env.owner_keypair.private_key,  # type: ignore[attr-defined]
            context,
        )
        requester_dek = env.backend.unwrap_dek(
            result.transformed_encrypted_dek,
            env.requester_keypair.private_key,  # type: ignore[attr-defined]
            context,
        )

        # Model a malicious data-plane process that can inspect the service's
        # current registrations, policies, tokens, encrypted objects, audit
        # metadata, and ephemeral PRE artifacts, but not either private key.
        # This is an exposed-state/public-API regression probe: it detects
        # literal DEK leakage and direct public-key misuse, not cryptanalysis,
        # memory forensics, side channels, or management-plane compromise.
        recovered_candidates: list[bytes] = []
        for artifact in (owner_wrap.encrypted_dek, result.transformed_encrypted_dek):
            for public_key in (
                env.owner_keypair.public_key,  # type: ignore[attr-defined]
                env.requester_keypair.public_key,  # type: ignore[attr-defined]
                env.intruder_keypair.public_key,  # type: ignore[attr-defined]
            ):
                try:
                    recovered_candidates.append(
                        env.backend.unwrap_dek(artifact, public_key, context)
                    )
                except (PREBackendError, TypeError, ValueError):
                    pass
        provider_state = {
            "schema_version": 3,
            "agents": env.provider.app.management.registrations(),
            "contact_rulebooks": env.provider.service.contact_rulebooks,
            "data_policies": env.provider.app._data_policies,
            "contact_tokens": env.provider.service.contact_tokens,
            "data_tokens": env.provider.service.data_tokens,
            "audit_events": env.provider.app.audit_query(),
            "rotation_journal": env.provider.app.management.rotation_journal(),
            "encrypted_objects": env.provider.store.snapshot(),
            "ephemeral_transform_material": {
                "rekey": rekey,
                "transformed_encrypted_dek": result.transformed_encrypted_dek,
                "context": context,
            },
        }
        serialized_provider_state = json.dumps(
            to_jsonable(provider_state),
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8")
        provider_visible_bytes = (
            owner_wrap.encrypted_dek,
            rekey,
            result.transformed_encrypted_dek,
            env.owner_keypair.public_key,  # type: ignore[attr-defined]
            env.requester_keypair.public_key,  # type: ignore[attr-defined]
            env.intruder_keypair.public_key,  # type: ignore[attr-defined]
            context,
            result.audit_id.encode("utf-8"),
            serialized_provider_state,
        )
        encoded_dek_markers = (
            base64.b64encode(actual_dek),
            actual_dek.hex().encode("ascii"),
        )
        public_material_recovery = (
            actual_dek in recovered_candidates
            or any(actual_dek in value for value in provider_visible_bytes)
            or any(
                marker in serialized_provider_state
                for marker in encoded_dek_markers
            )
        )
        confidentiality_gate = (
            result.decision == "allow"
            and requester_dek == actual_dek
            and not public_material_recovery
        )
        return {
            "path_kind": "provider_service",
            "observation_source": "provider_exposed_state_regression_probe",
            "baseline_contact_allowed": contact_authorized(env, env.contact_token),
            "expected_blocked": True,
            "blocked": confidentiality_gate,
            "reason": (
                "provider_public_material_recovery_blocked"
                if confidentiality_gate
                else "provider_public_material_recovery_succeeded_or_requester_failed"
            ),
            "audit_id": result.audit_id,
            "strength_note": (
                "The bounded Umbral regression probe snapshots registrations, "
                "policies, tokens, encrypted objects, complete audit metadata, "
                "the owner wrap, public keys, context, KFrag envelope, and "
                "CFrag output. It finds no raw/base64/hex DEK and public keys "
                "cannot use the unwrap API, while the intended requester "
                "decrypts. This is exposed-state empirical evidence, not "
                "cryptanalysis, memory forensics, or a whole-process proof."
            ),
        }

    return run_with_timer("provider_plaintext_probe", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
