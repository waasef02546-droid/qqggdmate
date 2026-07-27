"""Dependency-free JSON-over-HTTP Provider service for PRE-SAGA.

The HTTP layer is intentionally thin: all authorization and PRE operations are
delegated to :class:`PREProviderApp`.  State is stored locally in a JSON file so
the service can be stopped and restarted without requiring MongoDB.
"""

from __future__ import annotations

import argparse
import base64
import json
from dataclasses import asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from presaga.crypto.hpke_kem_stub import HPKEKEMStub
from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import (
    AuditEvent,
    ContactToken,
    DataAccessRequest,
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
from presaga.provider.registry import AgentRecord


class ProviderService:
    """Stateful application service used by the HTTP handler and tests."""

    def __init__(self, app: PREProviderApp, repository: JsonProviderRepository | None = None):
        self.app = app
        self.repository = repository
        self.contact_tokens: dict[str, ContactToken] = {}
        self.data_tokens: dict[str, DataToken] = {}
        self.contact_rulebooks: dict[str, list[dict[str, int | str]]] = {}
        if repository:
            self._restore(repository.load())

    def register_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        aid = _required_str(payload, "aid")
        public_key = from_b64(_required_str(payload, "public_key_b64"))
        self.app.register_agent(aid, public_key)
        self._persist()
        return {"aid": aid, "public_key_b64": _b64(public_key)}

    def add_data_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        policy = _policy_from_payload(payload)
        self.app.add_data_policy(policy)
        self._persist()
        return to_jsonable(policy)

    def set_contact_rulebook(self, payload: dict[str, Any]) -> dict[str, Any]:
        owner_aid = _required_str(payload, "owner_aid")
        rulebook = payload["rulebook"]
        if not isinstance(rulebook, list) or not all(isinstance(item, dict) for item in rulebook):
            raise ValueError("rulebook must be a list of objects")
        self.app.set_contact_rulebook(owner_aid, rulebook)
        self.contact_rulebooks[owner_aid] = [dict(item) for item in rulebook]
        self._persist()
        return {"owner_aid": owner_aid, "rulebook": rulebook}

    def issue_contact_session(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        token = self.app.issue_contact_session(_required_str(payload, "owner_aid"), _required_str(payload, "requester_aid"))
        if token is None:
            return HTTPStatus.FORBIDDEN, {"error": "contact_not_authorized"}
        self.contact_tokens[token.token_id] = token
        self._persist()
        return HTTPStatus.CREATED, {"contact_token": to_jsonable(token)}

    def issue_data_token(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        request = _request_from_payload(payload)
        contact_token_id = payload.get("contact_token_id")
        if not isinstance(contact_token_id, str) or not contact_token_id:
            return HTTPStatus.FORBIDDEN, {"decision": {"effect": "deny", "reason": "contact_session_required"}}
        contact_token = self.contact_tokens.get(contact_token_id)
        if contact_token is None:
            return HTTPStatus.FORBIDDEN, {"decision": {"effect": "deny", "reason": "contact_session_not_found"}}
        issuance = self.app.request_data_token(contact_token=contact_token, request=request)
        response: dict[str, Any] = {"decision": to_jsonable(issuance.decision)}
        if issuance.token is None:
            return HTTPStatus.FORBIDDEN, response
        token = issuance.token
        self.data_tokens[token.token_id] = token
        self._persist()
        response["data_token"] = to_jsonable(token)
        return HTTPStatus.CREATED, response

    def request_re_encryption(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        token_id = _required_str(payload, "token_id")
        token = self.data_tokens.get(token_id)
        if token is None:
            return HTTPStatus.NOT_FOUND, {"error": "data_token_not_found"}
        request = _request_from_payload(_required_dict(payload, "request"))
        contact_token = self.contact_tokens.get(token.contact_token_id)
        result = self.app.request_re_encryption(
            contact_token=contact_token,
            token=token,
            request=request,
            encrypted_dek_owner=from_b64(_required_str(payload, "encrypted_dek_owner_b64")),
            rekey=from_b64(_required_str(payload, "rekey_b64")),
        )
        self._persist()
        response = to_jsonable(result)
        if result.transformed_encrypted_dek is not None:
            response["transformed_encrypted_dek_b64"] = _b64(result.transformed_encrypted_dek)
            response.pop("transformed_encrypted_dek", None)
        return (HTTPStatus.OK if result.decision == "allow" else HTTPStatus.FORBIDDEN), response

    def audit_query(self, query: dict[str, list[str]]) -> dict[str, Any]:
        events = self.app.audit_query()
        for field in ("owner_aid", "requester_aid", "decision", "event_type"):
            value = query.get(field, [None])[0]
            if value:
                events = [event for event in events if getattr(event, field) == value]
        return {"audit_events": to_jsonable(events), "count": len(events)}

    def _restore(self, state: dict[str, Any]) -> None:
        for record in state["agents"]:
            self.app.registry.register(AgentRecord(aid=record["aid"], public_key=from_b64(record["public_key_b64"])))
        for owner_aid, rulebook in state["contact_rulebooks"].items():
            self.app.set_contact_rulebook(owner_aid, rulebook)
            self.contact_rulebooks[owner_aid] = [dict(item) for item in rulebook]
        for raw_policy in state["data_policies"]:
            self.app.add_data_policy(_policy_from_payload(raw_policy))
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
            "agents": [
                {"aid": record.aid, "public_key_b64": _b64(record.public_key)}
                for record in self.app.registry._agents.values()
            ],
            "contact_rulebooks": self.contact_rulebooks,
            "data_policies": self.app._data_policies,
            "contact_tokens": list(self.contact_tokens.values()),
            "data_tokens": list(self.data_tokens.values()),
            "audit_events": self.app.audit_query(),
        }
        self.repository.save(state)


def make_handler(service: ProviderService) -> type[BaseHTTPRequestHandler]:
    class ProviderRequestHandler(BaseHTTPRequestHandler):
        server_version = "PRE-SAGA-Provider/0.1"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                self._write_json(HTTPStatus.OK, {"status": "ok"})
                return
            if parsed.path == "/v1/audit":
                self._write_json(HTTPStatus.OK, service.audit_query(parse_qs(parsed.query)))
                return
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                payload = self._read_json()
                if self.path == "/v1/agents":
                    self._write_json(HTTPStatus.CREATED, {"agent": service.register_agent(payload)})
                elif self.path == "/v1/contact-rulebooks":
                    self._write_json(HTTPStatus.CREATED, {"contact_rulebook": service.set_contact_rulebook(payload)})
                elif self.path == "/v1/data-policies":
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
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "detail": str(error)})

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
    host: str = "127.0.0.1", port: int = 8080, *, state_file: str | Path = "provider-state.json", backend: PREBackend | None = None
) -> ThreadingHTTPServer:
    app = PREProviderApp(backend or HPKEKEMStub())
    service = ProviderService(app, JsonProviderRepository(state_file))
    return ThreadingHTTPServer((host, port), make_handler(service))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PRE-SAGA Provider HTTP service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state-file", default="provider-state.json")
    args = parser.parse_args()
    server = create_server(args.host, args.port, state_file=args.state_file)
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
    return DataAccessRequest(
        request_id=_required_str(payload, "request_id"),
        owner_aid=_required_str(payload, "owner_aid"),
        requester_aid=_required_str(payload, "requester_aid"),
        record_id=_required_str(payload, "record_id"),
        data_class=_required_str(payload, "data_class"),
        data_subclass=_required_str(payload, "data_subclass"),
        purpose=_required_str(payload, "purpose"),
        version=int(payload["version"]),
        requester_public_key=from_b64(_required_str(payload, "requester_public_key_b64")),
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
        requester_public_key_hash=payload["requester_public_key_hash"], issuer_signature=payload["issuer_signature"],
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
