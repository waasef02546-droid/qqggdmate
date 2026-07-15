"""Tiny timing helper."""

from __future__ import annotations

from contextlib import contextmanager
from time import perf_counter


class Metrics:
    def __init__(self):
        self.values: dict[str, float] = {}

    @contextmanager
    def time(self, name: str):
        start = perf_counter()
        yield
        self.values[name] = perf_counter() - start
