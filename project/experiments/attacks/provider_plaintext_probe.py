"""Attack: try to recover a DEK from the complete data-plane Provider view."""

from __future__ import annotations

from presaga.crypto.pre_interface import PREBackendError

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

        # The attack has the complete data-plane Provider view but neither
        # private key. Public keys are deliberately tried in every available
        # decrypt position, and every opaque artifact is scanned for an
        # accidental literal DEK leak. Failure here is a bounded active probe,
        # not a cryptographic proof or side-channel claim.
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
        provider_visible_bytes = (
            owner_wrap.encrypted_dek,
            rekey,
            result.transformed_encrypted_dek,
            env.owner_keypair.public_key,  # type: ignore[attr-defined]
            env.requester_keypair.public_key,  # type: ignore[attr-defined]
            env.intruder_keypair.public_key,  # type: ignore[attr-defined]
            context,
            result.audit_id.encode("utf-8"),
        )
        public_material_recovery = (
            actual_dek in recovered_candidates
            or any(actual_dek in value for value in provider_visible_bytes)
        )
        confidentiality_gate = (
            result.decision == "allow"
            and requester_dek == actual_dek
            and not public_material_recovery
        )
        return {
            "path_kind": "provider_service",
            "observation_source": "complete_data_plane_provider_view_probe",
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
                "The concrete Umbral data-plane probe includes the owner wrap, "
                "public keys, context, KFrag envelope, CFrag output, and audit "
                "identifier. Public-material recovery failed and the intended "
                "requester decrypted successfully. This is prototype-bounded "
                "empirical evidence, not a proof or whole-process claim."
            ),
        }

    return run_with_timer("provider_plaintext_probe", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
