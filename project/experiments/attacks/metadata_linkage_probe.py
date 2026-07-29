"""Attack: use a valid relationship to probe a record outside token scope."""

from __future__ import annotations

from dataclasses import replace

from presaga.protocol.schemas import DataRecord

from experiments.attacks.common import allowed_request, contact_authorized, issue_allowed_token, make_environment, rekey_for_requester, run_with_timer


def run_attack():
    def scenario():
        env = make_environment()
        token = issue_allowed_token(env)
        env.store.put(
            DataRecord(
                record_id="cal-secret",
                owner_aid=env.stored.record.owner_aid,
                data_class=env.stored.record.data_class,
                data_subclass=env.stored.record.data_subclass,
                version=env.stored.record.version,
            ),
            b"Secret calendar entry outside the delegated record scope.",
        )
        probe_request = replace(
            allowed_request(env),
            request_id="attack-metadata-linkage-probe",
            record_id="cal-secret",
        )
        result = env.provider.request_re_encryption(token, probe_request, rekey_for_requester(env))
        return {
            "baseline_contact_allowed": contact_authorized(env, env.contact_token),
            "blocked": result.decision == "deny" and result.reason == "record_scope_denied",
            "reason": result.reason,
            "audit_id": result.audit_id,
            "strength_note": "The requester has contact permission but cannot use a data token as an oracle for records outside its bound scope.",
        }

    return run_with_timer("metadata_linkage_probe", scenario)


if __name__ == "__main__":
    print(run_attack().to_json())
