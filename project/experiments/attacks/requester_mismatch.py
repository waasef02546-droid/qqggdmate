"""Attack: another contact-allowed agent tries to use Bob's data token."""

from __future__ import annotations

from dataclasses import replace

from experiments.attacks.common import INTRUDER_AID, allowed_request, contact_authorized, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        token = issue_allowed_token(env)
        attack_request = replace(
            allowed_request(env),
            request_id="attack-requester-mismatch",
            requester_aid=INTRUDER_AID,
            requester_public_key=env.intruder_keypair.public_key,  # type: ignore[attr-defined]
        )
        result = env.provider.request_re_encryption(token, attack_request, rekey_for_requester(env))
        return {
            "baseline_contact_allowed": contact_authorized(
                env,
                env.intruder_contact_token,
            ),
            "blocked": (
                result.decision == "deny"
                and result.reason == "contact_requester_mismatch"
            ),
            "reason": result.reason,
            "audit_id": result.audit_id,
            "strength_note": "Carol can obtain her own Contact session, but the service resolves Bob's token-bound Contact session and rejects the requester substitution before PRE transform.",
        }

    return run_with_timer("requester_mismatch", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
