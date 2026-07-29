"""Attack: contact is allowed, but requester asks for an unauthorized data class."""

from __future__ import annotations

from presaga.protocol.schemas import DataAccessRequest
from experiments.attacks.common import (
    allowed_request,
    contact_authorized,
    make_environment,
    run_with_timer,
)


def run_attack():
    def scenario():
        env = make_environment()
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
        issuance = env.provider.issue_data_token(env.contact_token, attack_request)
        return {
            "baseline_contact_allowed": contact_authorized(
                env,
                env.contact_token,
            ),
            "blocked": (
                issuance.decision == "deny"
                and issuance.reason == "data_class_denied"
                and issuance.token is None
            ),
            "reason": issuance.reason,
            "audit_id": issuance.audit_id,
            "strength_note": "The Provider service validates the issued Contact session and denies DataToken issuance at the authoritative Data Sharing Policy path.",
        }

    return run_with_timer("unauthorized_data_class", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
