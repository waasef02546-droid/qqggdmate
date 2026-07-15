"""Simple data index helper."""

from presaga.protocol.schemas import DataRecord


class DataIndex:
    def __init__(self):
        self.records: dict[str, DataRecord] = {}

    def add(self, record: DataRecord) -> None:
        self.records[record.record_id] = record

    def get(self, record_id: str) -> DataRecord:
        return self.records[record_id]
