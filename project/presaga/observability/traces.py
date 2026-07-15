"""Trace collection helper."""


class Traces:
    def __init__(self):
        self.events: list[str] = []

    def add(self, event: str) -> None:
        self.events.append(event)
