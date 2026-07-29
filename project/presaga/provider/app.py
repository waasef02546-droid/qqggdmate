"""Provider application with separate trusted-management and data-plane interfaces."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import ContactToken, DataAccessRequest, DataSharingPolicy, DataToken, PolicyDecision, TokenDecision
from presaga.provider.audit import AuditLogger
from presaga.provider.data_policy import DataPolicyEvaluator
from presaga.provider.pre_proxy import PREProxy, TransformResult
from presaga.provider.registry import (
    AgentRecord,
    AgentRegistry,
    PreparedReplacement,
    RegistrationError,
)
from presaga.provider.saga_adapter import SagaCompatibleAdapter
from presaga.provider.token_service import TokenService
from presaga.storage.encrypted_store import StoredObject


@dataclass(frozen=True)
class DataTokenRequestResult:
    decision: PolicyDecision
    token: DataToken | None
    audit_id: str


class TrustedManagementPlane:
    """Capability object for trusted configuration and registration mutations."""

    def __init__(self, app: "PREProviderApp", *, principal_id: str):
        self._app = app
        self.principal_id = principal_id

    def register_agent(self, aid: str, public_key: bytes) -> AgentRecord:
        return self._app._registry.create(aid, public_key, actor=self.principal_id)

    def replace_agent(self, aid: str, public_key: bytes, *, expected_version: int) -> AgentRecord:
        """Replace only when no attached store has owner-wrapped objects."""
        return self._app._registry.replace(
            aid,
            public_key,
            actor=self.principal_id,
            expected_version=expected_version,
        )

    def attach_store(self, store) -> None:
        self._app._registry.attach_store(store)

    def prepare_agent_replacement(
        self,
        aid: str,
        public_key: bytes,
        *,
        expected_version: int,
    ) -> PreparedReplacement:
        self._app._registry.prepare_replace(
            aid,
            public_key,
            actor=self.principal_id,
            expected_version=expected_version,
        )
        return self._app._registry.prepared_replacement(aid)

    def stage_agent_rewrap(
        self,
        aid: str,
        *,
        expected_version: int,
        rotation_id: str,
        store,
        record_id: str,
        source_private_key: bytes,
        expected_object_revision: int,
    ) -> StoredObject:
        return cast(
            StoredObject,
            self._app._registry.stage_prepared_rewrap(
                aid,
                actor=self.principal_id,
                expected_version=expected_version,
                rotation_id=rotation_id,
                store=store,
                record_id=record_id,
                source_private_key=source_private_key,
                expected_object_revision=expected_object_revision,
            ),
        )

    def commit_agent_replacement(
        self,
        aid: str,
        *,
        expected_version: int,
        rotation_id: str,
    ) -> AgentRecord:
        return self._app._registry.commit_prepared_replace(
            aid,
            actor=self.principal_id,
            expected_version=expected_version,
            rotation_id=rotation_id,
        )

    def abort_agent_replacement(
        self,
        aid: str,
        *,
        expected_version: int,
        rotation_id: str,
    ) -> None:
        self._app._registry.abort_prepared_replace(
            aid,
            actor=self.principal_id,
            expected_version=expected_version,
            rotation_id=rotation_id,
        )

    def cleanup_agent_rotation(
        self,
        aid: str,
        *,
        rotation_id: str,
    ) -> PreparedReplacement:
        return self._app._registry.cleanup_rotation(
            aid,
            actor=self.principal_id,
            rotation_id=rotation_id,
        )

    def revoke_agent(self, aid: str, *, expected_version: int) -> AgentRecord:
        return self._app._registry.revoke(
            aid,
            actor=self.principal_id,
            expected_version=expected_version,
        )

    def set_contact_rulebook(self, owner_aid: str, rulebook: list[dict[str, int | str]]) -> None:
        self._app._registry.resolve_active(owner_aid)
        self._app.saga_adapter.set_rulebook(owner_aid, rulebook)

    def add_data_policy(self, policy: DataSharingPolicy) -> None:
        self._app._registry.resolve_active(policy.owner_aid)
        self._app._data_policies.append(policy)

    def restore_registration(self, record: AgentRecord) -> None:
        self._app._registry.restore(record)

    def import_legacy_registration(self, aid: str, public_key: bytes) -> AgentRecord:
        return self._app._registry.import_legacy(aid, public_key)

    def registrations(self) -> tuple[AgentRecord, ...]:
        return self._app._registry.snapshot()

    def rotation_journal(self) -> tuple[PreparedReplacement, ...]:
        return self._app._registry.rotation_journal()

    def restore_rotation(self, rotation: PreparedReplacement) -> None:
        self._app._registry.restore_rotation(rotation)


class PREProviderApp:
    """Data-plane facade; mutations are available only through ``management``."""

    def __init__(
        self,
        backend: PREBackend,
        *,
        issuer_secret: bytes = b"issuer-secret",
        management_principal_id: str = "local-trusted-manager",
    ):
        self.backend = backend
        self._registry = AgentRegistry()
        self.audit = AuditLogger()
        self.saga_adapter = SagaCompatibleAdapter(issuer_secret)
        self.token_service = TokenService(issuer_secret, self._registry)
        self.proxy = PREProxy(
            backend,
            self.token_service,
            self.saga_adapter,
            self.audit,
            self._registry,
        )
        self._data_policies: list[DataSharingPolicy] = []
        self.management = TrustedManagementPlane(self, principal_id=management_principal_id)

    @property
    def registry(self) -> AgentRegistry:
        """Read/resolve access for evidence and persistence; mutations are not exposed here."""
        return self._registry

    def issue_contact_session(self, owner_aid: str, requester_aid: str) -> ContactToken | None:
        try:
            self._registry.resolve_active(owner_aid)
            self._registry.resolve_active(requester_aid)
        except RegistrationError:
            return None
        return self.saga_adapter.issue_contact_token(owner_aid=owner_aid, requester_aid=requester_aid)

    def validate_contact_session(
        self,
        contact_token: ContactToken,
        *,
        owner_aid: str,
        requester_aid: str,
        now: datetime | None = None,
    ) -> TokenDecision:
        try:
            self._registry.resolve_active(owner_aid)
            self._registry.resolve_active(requester_aid)
        except RegistrationError as error:
            return TokenDecision(effect="deny", reason=error.reason)
        return self.saga_adapter.validate_contact_token(
            contact_token,
            owner_aid=owner_aid,
            requester_aid=requester_aid,
            now=now,
        )

    def evaluate_data_request(self, request: DataAccessRequest, now: datetime | None = None) -> PolicyDecision:
        binding_error = self._request_binding_error(request)
        if binding_error:
            return PolicyDecision(effect="deny", reason=binding_error)
        return DataPolicyEvaluator(self._data_policies).evaluate(request, now=now)

    def request_data_token(
        self,
        *,
        contact_token: ContactToken | None,
        request: DataAccessRequest,
        now: datetime | None = None,
    ) -> DataTokenRequestResult:
        if contact_token is None:
            return self._record_data_token_issuance(
                request,
                PolicyDecision(effect="deny", reason="contact_session_required"),
            )
        binding_error = self._request_binding_error(request)
        if binding_error:
            return self._record_data_token_issuance(
                request,
                PolicyDecision(effect="deny", reason=binding_error),
            )
        contact_decision = self.validate_contact_session(
            contact_token,
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            now=now,
        )
        if contact_decision.effect != "allow":
            return self._record_data_token_issuance(
                request,
                PolicyDecision(effect="deny", reason=contact_decision.reason),
            )
        decision = DataPolicyEvaluator(self._data_policies).evaluate(request, now=now)
        if decision.effect != "allow":
            return self._record_data_token_issuance(request, decision)
        token = self.token_service._issue_data_token(decision, request, contact_token, now=now)
        return self._record_data_token_issuance(request, decision, token)

    def _record_data_token_issuance(
        self,
        request: DataAccessRequest,
        decision: PolicyDecision,
        token: DataToken | None = None,
    ) -> DataTokenRequestResult:
        event = self.audit.record(
            event_type="data_token_issuance",
            decision=decision.effect,
            reason=decision.reason,
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            record_id=request.record_id,
            data_class=request.data_class,
            purpose=request.purpose,
            policy_id=decision.policy_id,
            token_id=token.token_id if token is not None else None,
        )
        return DataTokenRequestResult(
            decision=decision,
            token=token,
            audit_id=event.audit_id,
        )

    def request_re_encryption(
        self,
        *,
        contact_token: ContactToken | None,
        token: DataToken,
        request: DataAccessRequest,
        stored: StoredObject,
        rekey: bytes,
        now: datetime | None = None,
    ) -> TransformResult:
        return self.proxy.transform(
            contact_token=contact_token,
            token=token,
            request=request,
            stored=stored,
            rekey=rekey,
            now=now,
        )

    def audit_query(self):
        return list(self.audit.events)

    def _request_binding_error(self, request: DataAccessRequest) -> str | None:
        try:
            self._registry.resolve_active(request.owner_aid)
            requester = self._registry.resolve_active(request.requester_aid)
        except RegistrationError as error:
            return error.reason
        if request.requester_public_key is not None and not hmac.compare_digest(
            request.requester_public_key,
            requester.public_key,
        ):
            return "requester_key_mismatch"
        return None
