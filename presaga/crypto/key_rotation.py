"""Helpers for versioned data contexts."""

from __future__ import annotations

import hashlib


def data_context(owner_aid: str, record_id: str, data_class: str, version: int) -> bytes:
    material = f"{owner_aid}|{record_id}|{data_class}|{version}".encode("utf-8")
    return hashlib.sha256(material).digest()
