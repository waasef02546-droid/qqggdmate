"""In-memory Provider application facade for PRE-SAGA experiments."""

from __future__ import annotations

from dataclasses import dataclass

from presaga.crypto.pre_interface import PREBackend
from presaga.protocol.schemas import DataAccessRequest, DataSharingPolicy, DataToken, PolicyDecision
from presaga.provider.audit import AuditLogger
from presaga.provider.contact_policy import SAGAStyleContactPolicy
from presaga.provider.data_policy import DataPolicyEvaluator
from presaga.provider.pre_proxy import PREProxy, TransformResult
from presaga.provider.registry import AgentRecord, AgentRegistry
from presaga.provider.token_service import TokenService


@dataclass(frozen=True)
class ContactSession:
    owner_aid: str
    requester_aid: str
    reason: str
    remaining_budget: int | None


class PREProviderApp:
    """Provider facade that separates contact and data authorization."""

    def __init__(self, backend: PREBackend, *, issuer_secret: bytes = b"issuer-secret"):
        self.backend = backend
        self.registry = AgentRegistry()
        self.audit = AuditLogger()
        self.token_service = TokenService(issuer_secret)
        self.proxy = PREProxy(backend, self.token_service, self.audit)
        self._contact_rulebooks: dict[str, SAGAStyleContactPolicy] = {}
        self._data_policies: list[DataSharingPolicy] = []

    def register_agent(self, aid: str, public_key: bytes) -> None:
        self.registry.register(AgentRecord(aid=aid, public_key=public_key))

    def set_contact_rulebook(self, owner_aid: str, rulebook: list[dict[str, int | str]]) -> None:
        self._contact_rulebooks[owner_aid] = SAGAStyleContactPolicy(rulebook)

    def add_data_policy(self, policy: DataSharingPolicy) -> None:
        self._data_policies.append(policy)

    def issue_contact_session(self, owner_aid: str, requester_aid: str) -> ContactSession | None:
        policy = self._contact_rulebooks.get(owner_aid)
        if policy is None:
            return None
        decision = policy.evaluate(requester_aid)
        if decision.effect != "allow":
            return None
        return ContactSession(owner_aid, requester_aid, decision.reason, decision.remaining_budget)

    def evaluate_data_request(self, request: DataAccessRequest) -> PolicyDecision:
        return DataPolicyEvaluator(self._data_policies).evaluate(request)

    def issue_data_token(self, decision: PolicyDecision, request: DataAccessRequest) -> DataToken:
        return self.token_service.issue_data_token(decision, request)

    def request_re_encryption(
        self,
        *,
        token: DataToken,
        request: DataAccessRequest,
        encrypted_dek_owner: bytes,
        rekey: bytes,
    ) -> TransformResult:
        return self.proxy.transform(token=token, request=request, encrypted_dek_owner=encrypted_dek_owner, rekey=rekey)

    def audit_query(self):
        return list(self.audit.events)
