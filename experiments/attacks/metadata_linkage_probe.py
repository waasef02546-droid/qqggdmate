"""Attack: use a valid relationship to probe a record outside token scope."""

from __future__ import annotations

from dataclasses import replace

from experiments.attacks.common import REQUESTER_AID, allowed_request, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        contact = env.contact_policy.evaluate(REQUESTER_AID)
        token = issue_allowed_token(env)
        probe_request = replace(
            allowed_request(env),
            request_id="attack-metadata-linkage-probe",
            record_id="cal-secret",
        )
        result = env.proxy.transform(
            token=token,
            request=probe_request,
            encrypted_dek_owner=env.stored.encrypted_dek_owner,
            rekey=rekey_for_requester(env),
        )
        return {
            "baseline_contact_allowed": contact.effect == "allow",
            "blocked": result.decision == "deny" and result.reason == "record_scope_denied",
            "reason": result.reason,
            "audit_id": result.audit_id,
            "strength_note": "The requester has contact permission but cannot use a data token as an oracle for records outside its bound scope.",
        }

    return run_with_timer("metadata_linkage_probe", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
