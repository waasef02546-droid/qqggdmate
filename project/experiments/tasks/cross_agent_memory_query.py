"""Task experiment: query another agent's memory summary."""

from __future__ import annotations

from experiments.tasks.common import run_authorized_task


def run_task():
    return run_authorized_task(
        task_name="cross_agent_memory_query",
        seed_file="memory_seed.jsonl",
        requester_aid="bob@mail.com:memory_query_agent",
        allowed_purpose="memory_query",
    )


if __name__ == "__main__":
    print(run_task())
