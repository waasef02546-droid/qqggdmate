from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pre_saga import (  # noqa: E402
    Agent,
    DataSharingPolicy,
    DataSharingRule,
    PolicyError,
    ProviderPREProxy,
    ToyPRE,
    decrypt_record,
    encrypt_record,
)


def build_world() -> Tuple[ProviderPREProxy, Dict[str, Agent], dict]:
    provider = ProviderPREProxy(provider_secret=b"pre-saga-provider-secret")
    agents = {
        "calendar_owner": Agent.create("alice@company.com:calendar_agent"),
        "meeting_agent": Agent.create("bob@company.com:meeting_agent"),
        "mail_agent": Agent.create("bob@company.com:mail_agent"),
    }
    provider.register_agent(agents["calendar_owner"], allowed_contacts=[agents["meeting_agent"].agent_id])
    provider.register_agent(agents["meeting_agent"], allowed_contacts=[])
    provider.register_agent(agents["mail_agent"], allowed_contacts=[])
    provider.set_data_policy(
        DataSharingPolicy(
            owner_agent=agents["calendar_owner"].agent_id,
            rules=[
                DataSharingRule(
                    requester_agent=agents["meeting_agent"].agent_id,
                    data_class="calendar.free_busy",
                    purpose="meeting_scheduling",
                    ttl_seconds=600,
                    max_uses=3,
                )
            ],
        )
    )
    records = {
        "free_busy": encrypt_record(
            agents["calendar_owner"],
            record_id="calendar-2026-07-14-freebusy",
            data_class="calendar.free_busy",
            plaintext="2026-07-14 10:00-10:30 busy; 15:00-16:00 free",
        )[0],
        "email_body": encrypt_record(
            agents["calendar_owner"],
            record_id="mail-sensitive-001",
            data_class="email.body",
            plaintext="Expense report contains private card digits and vendor notes.",
        )[0],
    }
    return provider, agents, records


def scenario_normal_data_sharing() -> bool:
    provider, agents, records = build_world()
    token = provider.issue_contact_token(
        owner_agent=agents["calendar_owner"].agent_id,
        requester_agent=agents["meeting_agent"].agent_id,
        max_uses=3,
    )
    converted = provider.re_encrypt_data_key(
        token=token,
        record=records["free_busy"],
        requester_agent=agents["meeting_agent"].agent_id,
        purpose="meeting_scheduling",
    )
    plaintext = decrypt_record(agents["meeting_agent"], records["free_busy"], converted)
    return "15:00-16:00 free" in plaintext


def scenario_denied_by_data_policy() -> bool:
    provider, agents, records = build_world()
    token = provider.issue_contact_token(
        owner_agent=agents["calendar_owner"].agent_id,
        requester_agent=agents["meeting_agent"].agent_id,
    )
    try:
        provider.re_encrypt_data_key(
            token=token,
            record=records["email_body"],
            requester_agent=agents["meeting_agent"].agent_id,
            purpose="meeting_scheduling",
        )
        return False
    except PolicyError:
        return True


def scenario_provider_plaintext_blindness() -> bool:
    provider, agents, records = build_world()
    token = provider.issue_contact_token(
        owner_agent=agents["calendar_owner"].agent_id,
        requester_agent=agents["meeting_agent"].agent_id,
    )
    converted = provider.re_encrypt_data_key(
        token=token,
        record=records["free_busy"],
        requester_agent=agents["meeting_agent"].agent_id,
        purpose="meeting_scheduling",
    )
    wrong_dek = ToyPRE.decrypt_key("provider-public-key", converted)
    wrong_plaintext = bytes(
        a ^ b for a, b in zip(records["free_busy"].ciphertext, wrong_dek * 4)
    )
    audit_contains_plaintext = any("15:00-16:00 free" in item for item in provider.audit_log)
    return b"15:00-16:00 free" not in wrong_plaintext and not audit_contains_plaintext


def scenario_token_misuse_blocked() -> bool:
    provider, agents, records = build_world()
    token = provider.issue_contact_token(
        owner_agent=agents["calendar_owner"].agent_id,
        requester_agent=agents["meeting_agent"].agent_id,
        max_uses=1,
    )
    provider.re_encrypt_data_key(
        token=token,
        record=records["free_busy"],
        requester_agent=agents["meeting_agent"].agent_id,
        purpose="meeting_scheduling",
    )
    try:
        provider.re_encrypt_data_key(
            token=token,
            record=records["free_busy"],
            requester_agent=agents["meeting_agent"].agent_id,
            purpose="meeting_scheduling",
        )
        return False
    except PolicyError:
        return True


SCENARIOS: Dict[str, Callable[[], bool]] = {
    "normal_data_sharing": scenario_normal_data_sharing,
    "denied_by_data_policy": scenario_denied_by_data_policy,
    "provider_plaintext_blindness": scenario_provider_plaintext_blindness,
    "token_misuse_blocked": scenario_token_misuse_blocked,
}


def run(repeats: int = 20) -> None:
    rows: List[Tuple[str, int, int, float]] = []
    for name, scenario in SCENARIOS.items():
        passes = 0
        elapsed: List[float] = []
        for _ in range(repeats):
            started = time.perf_counter()
            ok = scenario()
            elapsed.append((time.perf_counter() - started) * 1000)
            passes += int(ok)
        rows.append((name, passes, repeats, statistics.mean(elapsed)))

    print("PRE-SAGA experiment summary")
    print("scenario,success,total,success_rate,avg_elapsed_ms")
    for name, passes, total, avg_ms in rows:
        print(f"{name},{passes},{total},{passes / total:.2f},{avg_ms:.3f}")

    if any(passes != total for _, passes, total, _ in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    run()
