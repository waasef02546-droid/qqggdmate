"""Attack: probe whether the Provider/PRE proxy can observe plaintext."""

from __future__ import annotations

from experiments.attacks.common import allowed_request, contact_authorized, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        request = allowed_request(env)
        token = issue_allowed_token(env)
        result = env.provider.request_re_encryption(
            token,
            request,
            rekey_for_requester(env),
        )
        owner_wrap = env.store.resolve_active_owner_wrap(env.stored)
        context = env.store.wrap_context(env.stored.record, owner_wrap.provenance)
        actual_dek = env.backend.unwrap_dek(
            owner_wrap.encrypted_dek,
            env.owner_keypair.private_key,  # type: ignore[attr-defined]
            context,
        )
        public_material_recovery = env.backend.wrap_dek(
            owner_wrap.encrypted_dek,
            env.owner_keypair.public_key,  # type: ignore[attr-defined]
            context,
        )
        confidentiality_established = public_material_recovery != actual_dek
        return {
            "path_kind": "provider_service_with_toy_pre",
            "observation_source": "active_public_material_recovery_probe",
            "baseline_contact_allowed": contact_authorized(env, env.contact_token),
            "expected_blocked": False,
            "blocked": result.decision == "allow" and confidentiality_established,
            "reason": (
                "provider_confidentiality_established"
                if confidentiality_established
                else "toy_backend_public_material_recovers_dek"
            ),
            "audit_id": result.audit_id,
            "strength_note": "The service control flow does not explicitly pass plaintext, but the toy backend's public mask allows DEK recovery; cryptographic Provider confidentiality is therefore not established.",
        }

    return run_with_timer("provider_plaintext_probe", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
