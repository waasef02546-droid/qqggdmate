"""Attack: reuse a max-use exhausted data token."""

from __future__ import annotations

from experiments.attacks.common import REQUESTER_AID, allowed_request, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment(max_uses=1)
        contact = env.contact_policy.evaluate(REQUESTER_AID)
        request = allowed_request(env)
        token = issue_allowed_token(env)
        rekey = rekey_for_requester(env)
        first = env.proxy.transform(
            token=token,
            request=request,
            encrypted_dek_owner=env.stored.encrypted_dek_owner,
            rekey=rekey,
        )
        second = env.proxy.transform(
            token=token,
            request=request,
            encrypted_dek_owner=env.stored.encrypted_dek_owner,
            rekey=rekey,
        )
        return {
            "baseline_contact_allowed": contact.effect == "allow",
            "blocked": first.decision == "allow" and second.decision == "deny" and second.reason == "token_exhausted",
            "reason": second.reason,
            "audit_id": second.audit_id,
            "strength_note": "The first authorized transform consumes the only allowed use; the replay is rejected.",
        }

    return run_with_timer("token_reuse", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
