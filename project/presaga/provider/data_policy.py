"""Data Sharing Policy evaluator."""

from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch

from presaga.protocol.schemas import DataAccessRequest, DataSharingPolicy, PolicyDecision


class DataPolicyEvaluator:
    def __init__(self, policies: list[DataSharingPolicy]):
        self.policies = policies

    def evaluate(self, request: DataAccessRequest, now: datetime | None = None) -> PolicyDecision:
        now = now or datetime.now(timezone.utc)
        owner_policies = [p for p in self.policies if p.owner_aid == request.owner_aid]
        if not owner_policies:
            return PolicyDecision(effect="deny", reason="policy_not_found")

        for policy in owner_policies:
            reason = self._match(policy, request, now)
            if reason == "policy_match":
                if policy.effect == "deny":
                    return PolicyDecision(effect="deny", reason="explicit_deny", policy_id=policy.policy_id)
                return PolicyDecision(
                    effect="allow",
                    reason="policy_match",
                    policy_id=policy.policy_id,
                    max_uses=policy.limits.max_uses,
                    expires_at=policy.validity.not_after,
                    obligations=policy.obligations,
                )
            if reason in {"requester_mismatch", "data_class_denied", "purpose_mismatch", "version_out_of_bounds"}:
                continue

        return PolicyDecision(effect="deny", reason=self._first_denial_reason(owner_policies, request, now))

    def _first_denial_reason(
        self, policies: list[DataSharingPolicy], request: DataAccessRequest, now: datetime
    ) -> str:
        reasons = [self._match(policy, request, now) for policy in policies]
        priority = [
            "policy_not_active",
            "requester_mismatch",
            "data_class_denied",
            "record_scope_denied",
            "purpose_mismatch",
            "version_out_of_bounds",
        ]
        for reason in priority:
            if reason in reasons:
                return reason
        return reasons[0] if reasons else "policy_not_found"

    def _match(self, policy: DataSharingPolicy, request: DataAccessRequest, now: datetime) -> str:
        if not (policy.validity.not_before <= now <= policy.validity.not_after):
            return "policy_not_active"
        if not self._requester_matches(policy, request.requester_aid):
            return "requester_mismatch"
        if request.data_class not in policy.data_scope.data_classes:
            return "data_class_denied"
        if policy.data_scope.data_subclasses and request.data_subclass not in policy.data_scope.data_subclasses:
            return "data_class_denied"
        if not self._record_matches(policy, request.record_id):
            return "record_scope_denied"
        if "*" not in policy.purposes and request.purpose not in policy.purposes:
            return "purpose_mismatch"
        if not (policy.version_constraints.min_version <= request.version <= policy.version_constraints.max_version):
            return "version_out_of_bounds"
        return "policy_match"

    def _requester_matches(self, policy: DataSharingPolicy, requester_aid: str) -> bool:
        selector = policy.requester_selector
        if selector.type == "aid_exact":
            return requester_aid == selector.value
        if selector.type == "aid_pattern":
            return fnmatch(requester_aid, selector.value)
        return False

    def _record_matches(self, policy: DataSharingPolicy, record_id: str) -> bool:
        scope = policy.data_scope
        if not scope.record_ids and not scope.record_prefixes:
            return True
        if record_id in scope.record_ids:
            return True
        return any(record_id.startswith(prefix) for prefix in scope.record_prefixes)
