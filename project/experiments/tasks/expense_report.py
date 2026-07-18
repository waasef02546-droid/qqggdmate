"""Task experiment: extract receipt summary for an expense report."""

from __future__ import annotations

from experiments.tasks.common import run_authorized_task


def run_task():
    return run_authorized_task(
        task_name="expense_report",
        seed_file="mail_seed.jsonl",
        requester_aid="bob@mail.com:expense_agent",
        allowed_purpose="expense_report",
    )


if __name__ == "__main__":
    print(run_task())
