"""Task experiment: schedule a meeting from calendar availability."""

from __future__ import annotations

from experiments.tasks.common import run_authorized_task


def run_task():
    return run_authorized_task(
        task_name="schedule_meeting",
        seed_file="calendar_seed.jsonl",
        requester_aid="bob@mail.com:scheduler_agent",
        allowed_purpose="schedule_meeting",
    )


if __name__ == "__main__":
    print(run_task())
