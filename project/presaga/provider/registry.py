"""Simple agent registry."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentRecord:
    aid: str
    public_key: bytes


class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, AgentRecord] = {}

    def register(self, record: AgentRecord) -> None:
        self._agents[record.aid] = record

    def get(self, aid: str) -> AgentRecord:
        return self._agents[aid]
