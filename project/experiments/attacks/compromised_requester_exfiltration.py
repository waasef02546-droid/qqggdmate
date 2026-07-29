"""Attack: a compromised authorized requester tries to broaden exfiltration."""

from __future__ import annotations

from dataclasses import replace

from experiments.attacks.common import REQUESTER_AID, allowed_request, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment(max_uses=2)
        contact = env.contact_policy.evaluate(REQUESTER_AID)
        token = issue_allowed_token(env)
        exfiltration_request = replace(
            allowed_request(env),
            request_id="attack-compromised-requester-exfiltration",
            data_class="mail",
            data_subclass="body",
            purpose="bulk_exfiltration",
        )
        result = env.app.request_re_encryption(
            contact_token=env.contact_token,
            token=token,
            request=exfiltration_request,
            stored=env.stored,
            rekey=rekey_for_requester(env),
        )
        return {
            "baseline_contact_allowed": contact.effect == "allow",
            "blocked": result.decision == "deny" and result.reason == "data_class_denied",
            "reason": result.reason,
            "audit_id": result.audit_id,
            "strength_note": "A compromised requester keeps its identity/key but cannot broaden the token to another data class or exfiltration purpose.",
        }

    return run_with_timer("compromised_requester_exfiltration", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
