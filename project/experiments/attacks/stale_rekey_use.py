"""Attack: reuse a stale token/rekey after the protected record version moves."""

from __future__ import annotations

from dataclasses import replace

from experiments.attacks.common import allowed_request, contact_authorized, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        stale_token = issue_allowed_token(env)
        stale_rekey = rekey_for_requester(env)
        rotated_request = replace(
            allowed_request(env),
            request_id="attack-stale-rekey-use",
            version=2,
        )
        result = env.provider.request_re_encryption(
            stale_token,
            rotated_request,
            stale_rekey,
        )
        return {
            "baseline_contact_allowed": contact_authorized(env, env.contact_token),
            "blocked": result.decision == "deny" and result.reason == "version_out_of_bounds",
            "reason": result.reason,
            "audit_id": result.audit_id,
            "strength_note": "A stale rekey is coupled with a stale version-bound token; PRE-SAGA rejects before PRE transform.",
        }

    return run_with_timer("stale_rekey_use", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
