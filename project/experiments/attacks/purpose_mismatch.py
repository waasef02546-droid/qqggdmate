"""Attack: reuse a valid meeting-purpose data token for a different purpose."""

from __future__ import annotations

from dataclasses import replace

from experiments.attacks.common import REQUESTER_AID, allowed_request, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        contact = env.contact_policy.evaluate(REQUESTER_AID)
        token = issue_allowed_token(env)
        attack_request = replace(allowed_request(env), request_id="attack-purpose-mismatch", purpose="expense_report")
        result = env.app.request_re_encryption(
            contact_token=env.contact_token,
            token=token,
            request=attack_request,
            encrypted_dek_owner=env.stored.encrypted_dek_owner,
            rekey=rekey_for_requester(env),
        )
        return {
            "baseline_contact_allowed": contact.effect == "allow",
            "blocked": result.decision == "deny" and result.reason == "purpose_mismatch",
            "reason": result.reason,
            "audit_id": result.audit_id,
            "strength_note": "A valid token is first issued, then misused with a different purpose to test token binding.",
        }

    return run_with_timer("purpose_mismatch", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
