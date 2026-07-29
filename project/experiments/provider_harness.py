"""Authoritative in-process Provider service harness for experiments.

The harness deliberately crosses the same ``ProviderService`` boundary used by
the HTTP adapter. Experiment code may prepare trusted owner data directly, but
it must not synthesize Provider policy or token decisions.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from http import HTTPStatus
from typing import Callable

from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import (
    ContactToken,
    DataAccessRequest,
    DataSharingPolicy,
    DataToken,
)
from presaga.provider.app import PREProviderApp
from presaga.provider.json_repository import to_jsonable
from presaga.provider.server import ProviderService
from presaga.provider.registry import AgentRegistry
from presaga.storage.encrypted_store import EncryptedStore


@dataclass(frozen=True)
class TokenIssuanceObservation:
    status: int
    decision: str
    reason: str
    audit_id: str
    token: DataToken | None


@dataclass(frozen=True)
class TransformObservation:
    status: int
    decision: str
    reason: str
    audit_id: str
    transformed_encrypted_dek: bytes | None
    provider_saw_plaintext_dek: bool
    provider_saw_plaintext_data: bool


class AuthoritativeProviderHarness:
    """Small experiment adapter over the production Provider service facade."""

    def __init__(
        self,
        backend: PREBackend,
        *,
        store: EncryptedStore | None = None,
        store_factory: (
            Callable[[PREBackend, AgentRegistry], EncryptedStore] | None
        ) = None,
    ):
        if store is not None and store_factory is not None:
            raise ValueError("supply either store or store_factory, not both")
        self.backend = backend
        self.app = PREProviderApp(backend)
        self.store = (
            store
            or (
                store_factory(backend, self.app.registry)
                if store_factory is not None
                else EncryptedStore(backend, self.app.registry)
            )
        )
        self.service = ProviderService(self.app, object_store=self.store)

    def register_agent(self, aid: str, public_key: bytes) -> None:
        self.service.register_agent(
            {
                "aid": aid,
                "public_key_b64": _b64(public_key),
            }
        )

    def set_contact_rulebook(
        self,
        owner_aid: str,
        rulebook: list[dict[str, int | str]],
    ) -> None:
        self.service.set_contact_rulebook(
            {
                "owner_aid": owner_aid,
                "rulebook": rulebook,
            }
        )

    def add_data_policy(self, policy: DataSharingPolicy) -> None:
        self.service.add_data_policy(to_jsonable(policy))

    def replace_fixture_data_policies(
        self,
        policies: list[DataSharingPolicy],
    ) -> None:
        """Load a synthetic benchmark policy set through the management path.

        The clear operation is confined to this non-persistent experiment
        harness; every replacement policy is validated by ``ProviderService``.
        """
        self.app._data_policies.clear()
        for policy in policies:
            self.add_data_policy(policy)

    def issue_contact_session(
        self,
        owner_aid: str,
        requester_aid: str,
    ) -> ContactToken | None:
        status, response = self.service.issue_contact_session(
            {
                "owner_aid": owner_aid,
                "requester_aid": requester_aid,
            }
        )
        if status != HTTPStatus.CREATED:
            return None
        token_id = response["contact_token"]["token_id"]
        return self.service.contact_tokens[token_id]

    def issue_data_token(
        self,
        contact_token: ContactToken,
        request: DataAccessRequest,
    ) -> TokenIssuanceObservation:
        status, response = self.service.issue_data_token(
            {
                **_request_payload(request),
                "contact_token_id": contact_token.token_id,
            }
        )
        decision = response["decision"]
        token_payload = response.get("data_token")
        token = (
            self.service.data_tokens[token_payload["token_id"]]
            if token_payload is not None
            else None
        )
        return TokenIssuanceObservation(
            status=int(status),
            decision=decision["effect"],
            reason=decision["reason"],
            audit_id=response["audit_id"],
            token=token,
        )

    def request_re_encryption(
        self,
        token: DataToken,
        request: DataAccessRequest,
        rekey: bytes,
    ) -> TransformObservation:
        status, response = self.service.request_re_encryption(
            {
                "token_id": token.token_id,
                "request": _request_payload(request),
                "rekey_b64": _b64(rekey),
            }
        )
        transformed = response.get("transformed_encrypted_dek_b64")
        return TransformObservation(
            status=int(status),
            decision=response.get("decision", "deny"),
            reason=response.get("reason", response.get("error", "unknown_error")),
            audit_id=response.get("audit_id", ""),
            transformed_encrypted_dek=(
                base64.b64decode(transformed) if transformed is not None else None
            ),
            provider_saw_plaintext_dek=bool(
                response.get("provider_saw_plaintext_dek", False)
            ),
            provider_saw_plaintext_data=bool(
                response.get("provider_saw_plaintext_data", False)
            ),
        )


def _request_payload(request: DataAccessRequest) -> dict[str, object]:
    if request.requester_public_key is None:
        raise ValueError("experiment requests require requester_public_key")
    return {
        "request_id": request.request_id,
        "owner_aid": request.owner_aid,
        "requester_aid": request.requester_aid,
        "record_id": request.record_id,
        "data_class": request.data_class,
        "data_subclass": request.data_subclass,
        "purpose": request.purpose,
        "version": request.version,
        "requester_public_key_b64": _b64(request.requester_public_key),
        "timestamp": request.timestamp.isoformat(),
    }


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")
