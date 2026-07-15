"""Message factory helpers."""

from __future__ import annotations

from presaga.protocol.schemas import DataAccessRequest


def request_summary(request: DataAccessRequest) -> dict[str, str | int]:
    return {
        "request_id": request.request_id,
        "owner_aid": request.owner_aid,
        "requester_aid": request.requester_aid,
        "record_id": request.record_id,
        "data_class": request.data_class,
        "data_subclass": request.data_subclass,
        "purpose": request.purpose,
        "version": request.version,
    }
