"""Attack: another contact-allowed agent tries to use Bob's data token."""

from __future__ import annotations

from dataclasses import replace

from experiments.attacks.common import INTRUDER_AID, allowed_request, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        contact = env.contact_policy.evaluate(INTRUDER_AID)
        token = issue_allowed_token(env)
        attack_request = replace(
            allowed_request(env),
            request_id="attack-requester-mismatch",
            requester_aid=INTRUDER_AID,
            requester_public_key=env.intruder_keypair.public_key,  # type: ignore[attr-defined]
        )
        result = env.proxy.transform(
            token=token,
            request=attack_request,
            encrypted_dek_owner=env.stored.encrypted_dek_owner,
            rekey=rekey_for_requester(env),
        )
        return {
            "baseline_contact_allowed": contact.effect == "allow",
            "blocked": result.decision == "deny" and result.reason == "requester_mismatch",
            "reason": result.reason,
            "audit_id": result.audit_id,
            "strength_note": "Carol also passes contact policy, but cannot use Bob's data token.",
        }

    return run_with_timer("requester_mismatch", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
