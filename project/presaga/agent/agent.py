"""Minimal agent identity object."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Agent:
    aid: str
    public_key: bytes
    private_key: bytes
