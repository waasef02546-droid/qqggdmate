"""Attack: probe whether the Provider/PRE proxy can observe plaintext."""

from __future__ import annotations

from experiments.attacks.common import REQUESTER_AID, allowed_request, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        contact = env.contact_policy.evaluate(REQUESTER_AID)
        request = allowed_request(env)
        token = issue_allowed_token(env)
        result = env.app.request_re_encryption(
            contact_token=env.contact_token,
            token=token,
            request=request,
            encrypted_dek_owner=env.stored.encrypted_dek_owner,
            rekey=rekey_for_requester(env),
        )
        event = env.audit.events[-1]
        plaintext_hidden = not event.provider_saw_plaintext_dek and not event.provider_saw_plaintext_data
        return {
            "baseline_contact_allowed": contact.effect == "allow",
            "blocked": result.decision == "allow" and plaintext_hidden,
            "reason": "provider_plaintext_not_observed" if plaintext_hidden else "provider_plaintext_visible",
            "audit_id": result.audit_id,
            "strength_note": "A valid transform succeeds, but the proxy audit confirms no plaintext DEK or data is exposed to the Provider.",
        }

    return run_with_timer("provider_plaintext_probe", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
