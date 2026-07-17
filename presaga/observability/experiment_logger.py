"""Experiment result logger."""

from __future__ import annotations


class ExperimentLogger:
    def __init__(self):
        self.rows: list[dict[str, object]] = []

    def log(self, **row: object) -> None:
        self.rows.append(row)
