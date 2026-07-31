"""Dependency-free JSON-over-HTTP Provider service for PRE-SAGA.

The HTTP layer is intentionally thin: all authorization and PRE operations are
delegated to :class:`PREProviderApp`.  State is stored locally in a JSON file so
the service can be stopped and restarted without requiring MongoDB.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
from dataclasses import asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import parse_qs, urlparse

from pymongo import MongoClient

from presaga.crypto import envelope
from presaga.crypto.key_custody import KeyCustodyError, OwnerRewrapArtifact
from presaga.crypto.pre_interface import PREBackend
from presaga.crypto.umbral_pre import UmbralPREBackend
from presaga.protocol.schemas import (
    AuditEvent,
    ContactToken,
    DataAccessRequest,
    DataRecord,
    DataScope,
    DataSharingPolicy,
    DataToken,
    Limits,
    RequesterSelector,
    Validity,
    VersionConstraints,
)
from presaga.provider.app import PREProviderApp
from presaga.provider.json_repository import JsonProviderRepository, from_b64, to_jsonable
from presaga.provider.mongo_repository import MongoProviderRepository
from presaga.provider.repository import (
    ProviderRepository,
    RepositoryConflict,
    RepositoryError,
    RepositoryUnavailable,
)
from presaga.provider.registry import AgentRecord, PreparedReplacement, RegistrationError
from presaga.storage.encrypted_store import (
    EncryptedStore,
    OwnerKeyProvenance,
    OwnerWrappedDEK,
    StoredObject,
)
from presaga.storage.mongo_encrypted_store import MongoEncryptedStore


class ProviderService:
    """Stateful application service used by the HTTP handler and tests."""

    def __init__(
        self,
        app: PREProviderApp,
        repository: ProviderRepository | None = None,
        *,
        object_store=None,
    ):
        self.app = app
        self.repository = repository
        self.object_store = object_store
        self.contact_tokens: dict[str, ContactToken] = {}
        self.data_tokens: dict[str, DataToken] = {}
        self.contact_rulebooks: dict[str, list[dict[str, int | str]]] = {}
        self._lock = RLock()
        self._repository_revision = 0
        self._persistence_fenced = False
        if object_store is not None:
            self.app.management.attach_store(object_store)
        if repository:
            state = repository.load()
            self._repository_revision = int(state.get("state_revision", 0))
            if (
                self._repository_revision == 0
                and object_store is not None
                and object_store.snapshot()
            ):
                raise RepositoryUnavailable()
            self._restore(state)

    def register_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        aid = _required_str(payload, "aid")
        public_key = from_b64(_required_str(payload, "public_key_b64"))
        with self._lock:
            record = self.app.management.register_agent(aid, public_key)
            self._persist()
        return _registration_to_payload(record)

    def replace_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        aid = _required_str(payload, "aid")
        public_key = from_b64(_required_str(payload, "public_key_b64"))
        expected_version = int(payload["expected_version"])
        with self._lock:
            record = self.app.management.replace_agent(
                aid,
                public_key,
                expected_version=expected_version,
            )
            self._persist()
        return _registration_to_payload(record)

    def prepare_agent_replacement(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        aid = _required_str(payload, "aid")
        public_key = from_b64(_required_str(payload, "public_key_b64"))
        expected_version = int(payload["expected_version"])
        with self._lock:
            prepared = self.app.management.prepare_agent_replacement(
                aid,
                public_key,
                expected_version=expected_version,
            )
            self._persist()
        return {
            "rotation_id": prepared.rotation_id,
            "candidate": _registration_to_payload(prepared.candidate),
        }

    def stage_agent_rewrap(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        if self.object_store is None:
            raise RegistrationError("trusted_store_required")
        if "source_private_key_b64" in payload:
            raise RegistrationError("source_private_key_forbidden")
        aid = _required_str(payload, "aid")
        record_id = _required_str(payload, "record_id")
        artifact = OwnerRewrapArtifact.from_payload(
            _required_dict(payload, "artifact")
        )
        with self._lock:
            stored = self.app.management.stage_agent_rewrap(
                aid,
                expected_version=int(payload["expected_version"]),
                rotation_id=_required_str(payload, "rotation_id"),
                store=self.object_store,
                record_id=record_id,
                artifact=artifact,
                expected_object_revision=int(payload["expected_object_revision"]),
            )
            self._persist()
        return {
            "aid": aid,
            "record_id": record_id,
            "object_revision": stored.object_revision,
            "rotation_id": _required_str(payload, "rotation_id"),
        }

    def export_agent_rewrap_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        if self.object_store is None:
            raise RegistrationError("trusted_store_required")
        if "source_private_key_b64" in payload:
            raise RegistrationError("source_private_key_forbidden")
        request = self.app.management.build_agent_rewrap_request(
            _required_str(payload, "aid"),
            expected_version=int(payload["expected_version"]),
            rotation_id=_required_str(payload, "rotation_id"),
            store=self.object_store,
            record_id=_required_str(payload, "record_id"),
            expected_object_revision=int(payload["expected_object_revision"]),
        )
        return request.to_payload()

    def commit_agent_replacement(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        aid = _required_str(payload, "aid")
        with self._lock:
            record = self.app.management.commit_agent_replacement(
                aid,
                expected_version=int(payload["expected_version"]),
                rotation_id=_required_str(payload, "rotation_id"),
            )
            self._persist()
        return _registration_to_payload(record)

    def abort_agent_replacement(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        aid = _required_str(payload, "aid")
        rotation_id = _required_str(payload, "rotation_id")
        with self._lock:
            self.app.management.abort_agent_replacement(
                aid,
                expected_version=int(payload["expected_version"]),
                rotation_id=rotation_id,
            )
            self._persist()
        return {
            "aid": aid,
            "rotation_id": rotation_id,
            "status": "aborted",
        }

    def cleanup_agent_rotation(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        aid = _required_str(payload, "aid")
        rotation_id = _required_str(payload, "rotation_id")
        with self._lock:
            rotation = self.app.management.cleanup_agent_rotation(
                aid,
                rotation_id=rotation_id,
            )
            self._persist()
        return {
            "aid": aid,
            "rotation_id": rotation.rotation_id,
            "status": rotation.status,
            "cleanup_completed": rotation.cleanup_completed,
        }

    def revoke_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        aid = _required_str(payload, "aid")
        expected_version = int(payload["expected_version"])
        with self._lock:
            record = self.app.management.revoke_agent(aid, expected_version=expected_version)
            self._persist()
        return _registration_to_payload(record)

    def add_data_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        policy = _policy_from_payload(payload)
        self.app.management.add_data_policy(policy)
        self._persist()
        return to_jsonable(policy)

    def set_contact_rulebook(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_consistent_state()
        owner_aid = _required_str(payload, "owner_aid")
        rulebook = payload["rulebook"]
        if not isinstance(rulebook, list) or not all(isinstance(item, dict) for item in rulebook):
            raise ValueError("rulebook must be a list of objects")
        self.app.management.set_contact_rulebook(owner_aid, rulebook)
        self.contact_rulebooks[owner_aid] = [dict(item) for item in rulebook]
        self._persist()
        return {"owner_aid": owner_aid, "rulebook": rulebook}

    def issue_contact_session(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._require_consistent_state()
        token = self.app.issue_contact_session(_required_str(payload, "owner_aid"), _required_str(payload, "requester_aid"))
        if token is None:
            return HTTPStatus.FORBIDDEN, {"error": "contact_not_authorized"}
        self.contact_tokens[token.token_id] = token
        self._persist()
        return HTTPStatus.CREATED, {"contact_token": to_jsonable(token)}

    def issue_data_token(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._require_consistent_state()
        request = _request_from_payload(payload)
        contact_token_id = payload.get("contact_token_id")
        if not isinstance(contact_token_id, str) or not contact_token_id:
            return HTTPStatus.FORBIDDEN, {"decision": {"effect": "deny", "reason": "contact_session_required"}}
        contact_token = self.contact_tokens.get(contact_token_id)
        if contact_token is None:
            return HTTPStatus.FORBIDDEN, {"decision": {"effect": "deny", "reason": "contact_session_not_found"}}
        issuance = self.app.request_data_token(contact_token=contact_token, request=request)
        response: dict[str, Any] = {
            "decision": to_jsonable(issuance.decision),
            "audit_id": issuance.audit_id,
        }
        if issuance.token is None:
            self._persist()
            return HTTPStatus.FORBIDDEN, response
        token = issuance.token
        self.data_tokens[token.token_id] = token
        self._persist()
        response["data_token"] = to_jsonable(token)
        return HTTPStatus.CREATED, response

    def request_re_encryption(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self._require_consistent_state()
        token_id = _required_str(payload, "token_id")
        token = self.data_tokens.get(token_id)
        if token is None:
            return HTTPStatus.NOT_FOUND, {"error": "data_token_not_found"}
        request = _request_from_payload(_required_dict(payload, "request"))
        contact_token = self.contact_tokens.get(token.contact_token_id)
        if "encrypted_dek_owner_b64" in payload:
            return HTTPStatus.FORBIDDEN, {"error": "raw_owner_wrap_forbidden"}
        if self.object_store is None:
            return HTTPStatus.FORBIDDEN, {"error": "trusted_store_required"}
        try:
            stored = self.object_store.get(request.record_id)
        except KeyError:
            return HTTPStatus.NOT_FOUND, {"error": "stored_object_not_found"}
        except Exception as error:
            if str(error) == "stored_object_not_found":
                return HTTPStatus.NOT_FOUND, {"error": "stored_object_not_found"}
            return HTTPStatus.FORBIDDEN, {"error": "owner_store_unavailable"}
        result = self.app.request_re_encryption(
            contact_token=contact_token,
            token=token,
            request=request,
            stored=stored,
            rekey=from_b64(_required_str(payload, "rekey_b64")),
        )
        self._persist()
        response = to_jsonable(result)
        if result.transformed_encrypted_dek is not None:
            response["transformed_encrypted_dek_b64"] = _b64(result.transformed_encrypted_dek)
            response.pop("transformed_encrypted_dek", None)
        return (HTTPStatus.OK if result.decision == "allow" else HTTPStatus.FORBIDDEN), response

    def audit_query(self, query: dict[str, list[str]]) -> dict[str, Any]:
        self._require_consistent_state()
        events = self.app.audit_query()
        for field in ("owner_aid", "requester_aid", "decision", "event_type"):
            value = query.get(field, [None])[0]
            if value:
                events = [event for event in events if getattr(event, field) == value]
        return {"audit_events": to_jsonable(events), "count": len(events)}

    def _restore(self, state: dict[str, Any]) -> None:
        schema_version = int(state.get("schema_version", 1))
        for record in state["agents"]:
            if schema_version < 2 or "registration_version" not in record:
                self.app.management.import_legacy_registration(
                    record["aid"],
                    from_b64(record["public_key_b64"]),
                )
                continue
            self.app.management.restore_registration(_registration_from_payload(record))
        if state.get("encrypted_objects"):
            if self.object_store is None:
                raise RegistrationError("trusted_store_required")
            for raw_object in state["encrypted_objects"]:
                self.object_store.restore(_stored_object_from_payload(raw_object))
        for raw_rotation in state.get("rotation_journal", []):
            self.app.management.restore_rotation(_rotation_from_payload(raw_rotation))
        for owner_aid, rulebook in state["contact_rulebooks"].items():
            try:
                self.app.management.set_contact_rulebook(owner_aid, rulebook)
            except RegistrationError:
                continue
            self.contact_rulebooks[owner_aid] = [dict(item) for item in rulebook]
        for raw_policy in state["data_policies"]:
            try:
                self.app.management.add_data_policy(_policy_from_payload(raw_policy))
            except RegistrationError:
                continue
        self.contact_tokens = {raw["token_id"]: _contact_token_from_payload(raw) for raw in state["contact_tokens"]}
        self.data_tokens = {raw["token_id"]: _data_token_from_payload(raw) for raw in state["data_tokens"]}
        self.app.audit.events.extend(_audit_event_from_payload(raw) for raw in state["audit_events"])

    def _persist(self) -> None:
        if not self.repository:
            return
        self.contact_rulebooks = {
            owner_aid: [dict(rule) for rule in policy.rulebook]
            for owner_aid, policy in self.app.saga_adapter._rulebooks.items()
        }
        state = {
            "schema_version": 3,
            "state_revision": self._repository_revision,
            "agents": [
                _registration_to_payload(record)
                for record in self.app.management.registrations()
            ],
            "contact_rulebooks": self.contact_rulebooks,
            "data_policies": self.app._data_policies,
            "contact_tokens": list(self.contact_tokens.values()),
            "data_tokens": list(self.data_tokens.values()),
            "audit_events": self.app.audit_query(),
            "rotation_journal": [
                _rotation_to_payload(rotation)
                for rotation in self.app.management.rotation_journal()
            ],
            "encrypted_objects": (
                [
                    _stored_object_to_payload(stored)
                    for stored in self.object_store.snapshot()
                ]
                if self.object_store is not None
                else []
            ),
        }
        try:
            self._repository_revision = self.repository.save(
                state,
                expected_revision=self._repository_revision,
            )
        except RepositoryConflict:
            self._persistence_fenced = True
            raise
        except Exception as error:
            self._persistence_fenced = True
            raise RepositoryUnavailable() from error

    def _require_consistent_state(self) -> None:
        if self._persistence_fenced:
            raise RepositoryUnavailable()

    @property
    def persistence_fenced(self) -> bool:
        return self._persistence_fenced


class ProviderHTTPServer(ThreadingHTTPServer):
    """HTTP server that owns and closes its optional Mongo client."""

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        mongo_client=None,
    ):
        self.mongo_client = mongo_client
        super().__init__(server_address, handler)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            if self.mongo_client is not None:
                self.mongo_client.close()


def make_handler(service: ProviderService, management_token: str) -> type[BaseHTTPRequestHandler]:
    class ProviderRequestHandler(BaseHTTPRequestHandler):
        server_version = "PRE-SAGA-Provider/0.1"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                status = (
                    HTTPStatus.SERVICE_UNAVAILABLE
                    if service.persistence_fenced
                    else HTTPStatus.OK
                )
                self._write_json(
                    status,
                    {
                        "status": (
                            "repository_recovery_required"
                            if service.persistence_fenced
                            else "ok"
                        )
                    },
                )
                return
            if parsed.path == "/v1/audit":
                self._write_json(HTTPStatus.OK, service.audit_query(parse_qs(parsed.query)))
                return
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                payload = self._read_json()
                if self.path.startswith("/v1/management/"):
                    if not self._management_authorized(management_token):
                        self._write_json(HTTPStatus.UNAUTHORIZED, {"error": "management_authentication_required"})
                        return
                if self.path == "/v1/management/agents":
                    self._write_json(HTTPStatus.CREATED, {"agent": service.register_agent(payload)})
                elif self.path == "/v1/management/agent-replacements":
                    self._write_json(HTTPStatus.OK, {"agent": service.replace_agent(payload)})
                elif self.path == "/v1/management/agent-rotation-preparations":
                    self._write_json(
                        HTTPStatus.CREATED,
                        {"agent": service.prepare_agent_replacement(payload)},
                    )
                elif self.path == "/v1/management/agent-rotation-rewraps":
                    self._write_json(
                        HTTPStatus.OK,
                        {"rewrap": service.stage_agent_rewrap(payload)},
                    )
                elif self.path == "/v1/management/agent-rotation-rewrap-requests":
                    self._write_json(
                        HTTPStatus.OK,
                        {"request": service.export_agent_rewrap_request(payload)},
                    )
                elif self.path == "/v1/management/agent-rotation-commits":
                    self._write_json(
                        HTTPStatus.OK,
                        {"agent": service.commit_agent_replacement(payload)},
                    )
                elif self.path == "/v1/management/agent-rotation-aborts":
                    self._write_json(
                        HTTPStatus.OK,
                        {"rotation": service.abort_agent_replacement(payload)},
                    )
                elif self.path == "/v1/management/agent-rotation-cleanups":
                    self._write_json(
                        HTTPStatus.OK,
                        {"rotation": service.cleanup_agent_rotation(payload)},
                    )
                elif self.path == "/v1/management/agent-revocations":
                    self._write_json(HTTPStatus.OK, {"agent": service.revoke_agent(payload)})
                elif self.path == "/v1/management/contact-rulebooks":
                    self._write_json(HTTPStatus.CREATED, {"contact_rulebook": service.set_contact_rulebook(payload)})
                elif self.path == "/v1/management/data-policies":
                    self._write_json(HTTPStatus.CREATED, {"data_policy": service.add_data_policy(payload)})
                elif self.path == "/v1/contact-sessions":
                    status, response = service.issue_contact_session(payload)
                    self._write_json(status, response)
                elif self.path == "/v1/data-tokens":
                    status, response = service.issue_data_token(payload)
                    self._write_json(status, response)
                elif self.path == "/v1/re-encryptions":
                    status, response = service.request_re_encryption(payload)
                    self._write_json(status, response)
                else:
                    self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            except RepositoryError as error:
                status = (
                    HTTPStatus.CONFLICT
                    if isinstance(error, RepositoryConflict)
                    else HTTPStatus.SERVICE_UNAVAILABLE
                )
                self._write_json(status, {"error": error.reason})
            except RegistrationError as error:
                if error.reason == "source_private_key_forbidden":
                    status = HTTPStatus.BAD_REQUEST
                elif error.reason in {
                    "registration_exists",
                    "registration_version_conflict",
                    "registration_key_unchanged",
                    "registration_replacement_pending",
                    "prepared_rotation_mismatch",
                    "owner_rotation_required",
                    "owner_object_revision_conflict",
                    "owner_rotation_object_set_changed",
                    "owner_rewrap_incomplete",
                    "custody_artifact_conflict",
                }:
                    status = HTTPStatus.CONFLICT
                else:
                    status = HTTPStatus.FORBIDDEN
                self._write_json(status, {"error": error.reason})
            except KeyCustodyError as error:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": error.reason})
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "detail": str(error)})

        def _management_authorized(self, expected_token: str) -> bool:
            authorization = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not authorization.startswith(prefix):
                return False
            supplied = authorization[len(prefix):]
            return bool(supplied) and hmac.compare_digest(supplied, expected_token)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                raise ValueError("request body is required")
            value = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("JSON body must be an object")
            return value

        def _write_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(to_jsonable(payload), ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ProviderRequestHandler


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    state_file: str | Path = "provider-state.json",
    backend: PREBackend | None = None,
    management_token: str | None = None,
    object_store=None,
    mongo_uri: str | None = None,
    mongo_db: str = "presaga_provider",
) -> ProviderHTTPServer:
    if not management_token:
        raise ValueError("management_token is required")
    selected_backend = backend or UmbralPREBackend()
    app = PREProviderApp(selected_backend)
    mongo_client = None
    if mongo_uri:
        if object_store is not None:
            raise ValueError("object_store cannot be supplied with mongo_uri")
        mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        mongo_client.admin.command("ping")
        database = mongo_client[mongo_db]
        repository: ProviderRepository = MongoProviderRepository(database)
        selected_store = MongoEncryptedStore(
            selected_backend,
            database,
            app.registry,
        )
    else:
        repository = JsonProviderRepository(state_file)
        selected_store = object_store or EncryptedStore(selected_backend, app.registry)
    try:
        service = ProviderService(
            app,
            repository,
            object_store=selected_store,
        )
    except Exception:
        if mongo_client is not None:
            mongo_client.close()
        raise
    server = ProviderHTTPServer(
        (host, port),
        make_handler(service, management_token),
        mongo_client=mongo_client,
    )
    server.provider_service = service  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PRE-SAGA Provider HTTP service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state-file", default="provider-state.json")
    parser.add_argument("--mongo-uri")
    parser.add_argument("--mongo-db", default="presaga_provider")
    parser.add_argument("--management-token-env", default="PRESAGA_MANAGEMENT_TOKEN")
    args = parser.parse_args()
    management_token = os.environ.get(args.management_token_env)
    if not management_token:
        parser.error(f"environment variable {args.management_token_env} is required")
    server = create_server(
        args.host,
        args.port,
        state_file=args.state_file,
        management_token=management_token,
        mongo_uri=args.mongo_uri,
        mongo_db=args.mongo_db,
    )
    print(f"PRE-SAGA Provider listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _required_str(payload: dict[str, Any], field: str) -> str:
    value = payload[field]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _required_dict(payload: dict[str, Any], field: str) -> dict[str, Any]:
    value = payload[field]
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _request_from_payload(payload: dict[str, Any]) -> DataAccessRequest:
    requester_public_key_b64 = payload.get("requester_public_key_b64")
    if requester_public_key_b64 is not None and (
        not isinstance(requester_public_key_b64, str) or not requester_public_key_b64
    ):
        raise ValueError("requester_public_key_b64 must be a non-empty string when supplied")
    return DataAccessRequest(
        request_id=_required_str(payload, "request_id"),
        owner_aid=_required_str(payload, "owner_aid"),
        requester_aid=_required_str(payload, "requester_aid"),
        record_id=_required_str(payload, "record_id"),
        data_class=_required_str(payload, "data_class"),
        data_subclass=_required_str(payload, "data_subclass"),
        purpose=_required_str(payload, "purpose"),
        version=int(payload["version"]),
        requester_public_key=from_b64(requester_public_key_b64) if requester_public_key_b64 else None,
        timestamp=_parse_datetime(payload["timestamp"]) if payload.get("timestamp") else datetime.now().astimezone(),
    )


def _policy_from_payload(payload: dict[str, Any]) -> DataSharingPolicy:
    selector = _required_dict(payload, "requester_selector")
    scope = _required_dict(payload, "data_scope")
    validity = _required_dict(payload, "validity")
    limits = _required_dict(payload, "limits")
    versions = _required_dict(payload, "version_constraints")
    return DataSharingPolicy(
        policy_id=_required_str(payload, "policy_id"),
        owner_aid=_required_str(payload, "owner_aid"),
        requester_selector=RequesterSelector(type=selector["type"], value=selector["value"]),
        data_scope=DataScope(
            data_classes=list(scope["data_classes"]), data_subclasses=list(scope.get("data_subclasses", [])),
            record_ids=list(scope.get("record_ids", [])), record_prefixes=list(scope.get("record_prefixes", [])),
        ),
        purposes=list(payload["purposes"]),
        validity=Validity(not_before=_parse_datetime(validity["not_before"]), not_after=_parse_datetime(validity["not_after"])),
        limits=Limits(max_uses=int(limits["max_uses"]), max_records=int(limits.get("max_records", 1)), allow_bulk_export=bool(limits.get("allow_bulk_export", False))),
        version_constraints=VersionConstraints(min_version=int(versions["min_version"]), max_version=int(versions["max_version"])),
        effect=payload.get("effect", "allow"),
        obligations=dict(payload.get("obligations", {})),
    )


def _contact_token_from_payload(payload: dict[str, Any]) -> ContactToken:
    return ContactToken(
        token_id=payload["token_id"], owner_aid=payload["owner_aid"], requester_aid=payload["requester_aid"],
        contact_session_ref=payload["contact_session_ref"], matched_pattern=payload["matched_pattern"],
        not_before=_parse_datetime(payload["not_before"]), expires_at=_parse_datetime(payload["expires_at"]),
        remaining_budget_after_issue=payload["remaining_budget_after_issue"], issuer_signature=payload["issuer_signature"],
    )


def _data_token_from_payload(payload: dict[str, Any]) -> DataToken:
    return DataToken(
        token_id=payload["token_id"], owner_aid=payload["owner_aid"], requester_aid=payload["requester_aid"], policy_id=payload["policy_id"],
        contact_token_id=payload.get("contact_token_id", ""), contact_session_ref=payload.get("contact_session_ref", ""),
        allowed_record_ids=list(payload["allowed_record_ids"]), allowed_data_classes=list(payload["allowed_data_classes"]),
        allowed_data_subclasses=list(payload["allowed_data_subclasses"]), purpose=payload["purpose"],
        not_before=_parse_datetime(payload["not_before"]), expires_at=_parse_datetime(payload["expires_at"]), max_uses=int(payload["max_uses"]),
        remaining_uses=int(payload["remaining_uses"]), min_version=int(payload["min_version"]), max_version=int(payload["max_version"]),
        requester_public_key_hash=payload["requester_public_key_hash"],
        requester_registration_version=int(payload.get("requester_registration_version", 0)),
        owner_public_key_fingerprint=payload.get("owner_public_key_fingerprint", ""),
        owner_registration_version=int(payload.get("owner_registration_version", 0)),
        owner_registration_id=payload.get("owner_registration_id", ""),
        owner_key_algorithm=payload.get("owner_key_algorithm", ""),
        issuer_signature=payload["issuer_signature"],
    )


def _registration_to_payload(record: AgentRecord) -> dict[str, Any]:
    return {
        "aid": record.aid,
        "public_key_b64": _b64(record.public_key),
        "public_key_fingerprint": record.public_key_fingerprint,
        "registration_version": record.registration_version,
        "status": record.status,
        "registered_by": record.registered_by,
        "registration_id": record.registration_id,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "key_algorithm": record.key_algorithm,
    }


def _registration_from_payload(payload: dict[str, Any]) -> AgentRecord:
    return AgentRecord(
        aid=_required_str(payload, "aid"),
        public_key=from_b64(_required_str(payload, "public_key_b64")),
        public_key_fingerprint=_required_str(payload, "public_key_fingerprint"),
        registration_version=int(payload["registration_version"]),
        status=payload["status"],
        registered_by=_required_str(payload, "registered_by"),
        registration_id=_required_str(payload, "registration_id"),
        created_at=_parse_datetime(payload["created_at"]),
        updated_at=_parse_datetime(payload["updated_at"]),
        key_algorithm=_required_str(payload, "key_algorithm"),
    )


def _rotation_to_payload(rotation: PreparedReplacement) -> dict[str, Any]:
    return {
        "current_registration_id": rotation.current_registration_id,
        "current_version": rotation.current_version,
        "candidate": _registration_to_payload(rotation.candidate),
        "prepared_by": rotation.prepared_by,
        "rotation_id": rotation.rotation_id,
        "owner_object_revisions": [
            {
                "store_id": store_id,
                "objects": dict(sorted(revisions.items())),
            }
            for store_id, revisions in rotation.owner_object_revisions
        ],
        "status": rotation.status,
        "created_at": rotation.created_at.isoformat(),
        "updated_at": rotation.updated_at.isoformat(),
        "cleanup_completed": rotation.cleanup_completed,
    }


def _rotation_from_payload(payload: dict[str, Any]) -> PreparedReplacement:
    raw_inventory = payload["owner_object_revisions"]
    if not isinstance(raw_inventory, list):
        raise ValueError("rotation inventory must be a list")
    inventory: list[tuple[str, dict[str, int]]] = []
    for raw_store in raw_inventory:
        store_id = _required_str(raw_store, "store_id")
        raw_objects = _required_dict(raw_store, "objects")
        inventory.append(
            (
                store_id,
                {
                    str(record_id): int(revision)
                    for record_id, revision in raw_objects.items()
                },
            )
        )
    return PreparedReplacement(
        current_registration_id=_required_str(payload, "current_registration_id"),
        current_version=int(payload["current_version"]),
        candidate=_registration_from_payload(_required_dict(payload, "candidate")),
        prepared_by=_required_str(payload, "prepared_by"),
        rotation_id=_required_str(payload, "rotation_id"),
        owner_object_revisions=tuple(inventory),
        status=payload["status"],
        created_at=_parse_datetime(payload["created_at"]),
        updated_at=_parse_datetime(payload["updated_at"]),
        cleanup_completed=bool(payload.get("cleanup_completed", False)),
    )


def _stored_object_to_payload(stored: StoredObject) -> dict[str, Any]:
    return {
        "schema_version": stored.schema_version,
        "object_revision": stored.object_revision,
        "record": asdict(stored.record),
        "ciphertext": stored.ciphertext.to_dict(),
        "owner_wraps": [
            {
                "encrypted_dek_b64": _b64(wrapped.encrypted_dek),
                "provenance": asdict(wrapped.provenance),
                "rotation_id": wrapped.rotation_id,
                "custody_request_digest_b64": (
                    _b64(wrapped.custody_request_digest)
                    if wrapped.custody_request_digest is not None
                    else None
                ),
            }
            for wrapped in stored.owner_wraps
        ],
    }


def _stored_object_from_payload(payload: dict[str, Any]) -> StoredObject:
    record = DataRecord(**_required_dict(payload, "record"))
    ciphertext = envelope.EnvelopeCiphertext.from_dict(
        _required_dict(payload, "ciphertext")
    )
    raw_wraps = payload["owner_wraps"]
    if not isinstance(raw_wraps, list):
        raise ValueError("owner_wraps must be a list")
    wraps = tuple(
        OwnerWrappedDEK(
            encrypted_dek=from_b64(_required_str(raw, "encrypted_dek_b64")),
            provenance=OwnerKeyProvenance(
                **_required_dict(raw, "provenance")
            ),
            rotation_id=raw.get("rotation_id"),
            custody_request_digest=(
                from_b64(_required_str(raw, "custody_request_digest_b64"))
                if raw.get("custody_request_digest_b64") is not None
                else None
            ),
        )
        for raw in raw_wraps
    )
    return StoredObject(
        record=record,
        ciphertext=ciphertext,
        owner_wraps=wraps,
        object_revision=int(payload["object_revision"]),
        schema_version=int(payload["schema_version"]),
    )


def _audit_event_from_payload(payload: dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        audit_id=payload["audit_id"], timestamp=_parse_datetime(payload["timestamp"]), event_type=payload["event_type"], decision=payload["decision"],
        reason=payload["reason"], owner_aid=payload["owner_aid"], requester_aid=payload["requester_aid"], record_id=payload["record_id"],
        data_class=payload["data_class"], purpose=payload["purpose"], policy_id=payload.get("policy_id"), token_id=payload.get("token_id"),
        provider_saw_plaintext_dek=bool(payload["provider_saw_plaintext_dek"]), provider_saw_plaintext_data=bool(payload["provider_saw_plaintext_data"]),
    )


if __name__ == "__main__":
    main()
