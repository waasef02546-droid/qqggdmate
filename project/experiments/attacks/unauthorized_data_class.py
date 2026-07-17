"""Attack: contact is allowed, but requester asks for an unauthorized data class."""

from __future__ import annotations

from presaga.protocol.schemas import DataAccessRequest
from presaga.provider.data_policy import DataPolicyEvaluator

from experiments.attacks.common import REQUESTER_AID, allowed_request, make_environment, record_policy_denial, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        contact = env.contact_policy.evaluate(REQUESTER_AID)
        base = allowed_request(env)
        attack_request = DataAccessRequest(
            request_id="attack-unauthorized-data-class",
            owner_aid=base.owner_aid,
            requester_aid=base.requester_aid,
            record_id=base.record_id,
            data_class="mail",
            data_subclass="body",
            purpose=base.purpose,
            version=base.version,
            requester_public_key=base.requester_public_key,
        )
        decision = DataPolicyEvaluator([env.policy]).evaluate(attack_request)
        audit_id = record_policy_denial(env, attack_request, decision.reason, decision.policy_id)
        return {
            "baseline_contact_allowed": contact.effect == "allow",
            "blocked": decision.effect == "deny" and decision.reason == "data_class_denied",
            "reason": decision.reason,
            "audit_id": audit_id,
            "strength_note": "SAGA-style contact gate allows the requester; PRE-SAGA blocks at Data Sharing Policy.",
        }

    return run_with_timer("unauthorized_data_class", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
