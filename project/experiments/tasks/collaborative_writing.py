"""Task experiment: retrieve a document outline for collaborative writing."""

from __future__ import annotations

from experiments.tasks.common import run_authorized_task


def run_task():
    return run_authorized_task(
        task_name="collaborative_writing",
        seed_file="documents_seed.jsonl",
        requester_aid="bob@mail.com:writing_agent",
        allowed_purpose="collaborative_writing",
    )


if __name__ == "__main__":
    print(run_task())
