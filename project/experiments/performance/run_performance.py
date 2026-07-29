"""Run small reproducible PRE-SAGA performance experiments.

The goal is not to claim production performance. The goal is to provide a
repeatable evaluation harness that compares SAGA-style contact-only, plaintext
token server, and PRE-SAGA data authorization paths.
"""

from __future__ import annotations

import csv
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from experiments.attacks.common import make_environment, rekey_for_requester
from presaga.protocol.schemas import (
    DataAccessRequest,
    DataScope,
    DataSharingPolicy,
    Limits,
    RequesterSelector,
    Validity,
    VersionConstraints,
)
from presaga.provider.contact_policy import SAGAStyleContactPolicy
from presaga.provider.data_policy import DataPolicyEvaluator


@dataclass(frozen=True)
class PerformanceRow:
    experiment: str
    baseline: str
    path_kind: str
    observation_source: str
    policy_rules: int
    iterations: int
    avg_latency_ms: float
    p95_latency_ms: float
    provider_plaintext_data_visible: bool
    provider_plaintext_dek_visible: bool
    cryptographic_provider_confidentiality_established: bool | None
    data_layer_control: bool


def _measure(iterations: int, fn, *, validate=None) -> tuple[float, float, object]:
    samples: list[float] = []
    last_result: object = None
    for _ in range(iterations):
        started = time.perf_counter()
        last_result = fn()
        samples.append((time.perf_counter() - started) * 1000)
        if validate is not None and not validate(last_result):
            raise RuntimeError("measured operation failed its correctness predicate")
    avg = statistics.fmean(samples)
    p95 = sorted(samples)[max(0, int(len(samples) * 0.95) - 1)]
    return round(avg, 4), round(p95, 4), last_result


def _policy(owner: str, requester: str, policy_id: str, now: datetime, data_class: str = "calendar") -> DataSharingPolicy:
    return DataSharingPolicy(
        policy_id=policy_id,
        owner_aid=owner,
        requester_selector=RequesterSelector(type="aid_exact", value=requester),
        data_scope=DataScope(data_classes=[data_class], data_subclasses=["availability"], record_ids=["cal-001"]),
        purposes=["schedule_meeting"],
        validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
        limits=Limits(max_uses=10, max_records=1),
        version_constraints=VersionConstraints(min_version=1, max_version=1),
    )


def _make_policy_set(rule_count: int, owner: str, requester: str) -> list[DataSharingPolicy]:
    now = datetime.now(timezone.utc)
    policies = [
        _policy(owner, f"nonmatch-{idx}@mail.com:agent", f"policy-noise-{idx}", now)
        for idx in range(max(0, rule_count - 1))
    ]
    policies.append(_policy(owner, requester, "policy-target", now))
    return policies


def _request(env) -> DataAccessRequest:
    return DataAccessRequest(
        request_id="perf-req",
        owner_aid=env.stored.record.owner_aid,
        requester_aid="bob@mail.com:scheduler_agent",
        record_id=env.stored.record.record_id,
        data_class=env.stored.record.data_class,
        data_subclass=env.stored.record.data_subclass,
        purpose="schedule_meeting",
        version=env.stored.record.version,
        requester_public_key=env.requester_keypair.public_key,
    )


def run_performance(
    output_root: Path = Path("results"),
    *,
    iterations: int = 50,
    rule_counts: tuple[int, ...] = (10, 100, 1000),
) -> list[PerformanceRow]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    if not rule_counts or any(count < 1 for count in rule_counts):
        raise ValueError("rule_counts must contain positive values")
    rows: list[PerformanceRow] = []

    for rule_count in rule_counts:
        env = make_environment(max_uses=1000)
        request = _request(env)
        policies = _make_policy_set(rule_count, request.owner_aid, request.requester_aid)
        env.provider.replace_fixture_data_policies(policies)

        contact_policy = SAGAStyleContactPolicy([{"pattern": "*@mail.com:*_agent", "budget": 100000}])
        avg, p95, _ = _measure(
            iterations,
            lambda: contact_policy.evaluate(
                request.requester_aid,
                consume=False,
            ),
            validate=lambda decision: decision.effect == "allow",
        )
        rows.append(
            PerformanceRow(
                "baseline_comparison",
                "saga_contact_only",
                "modeled_contact_baseline",
                "contact_policy_decision",
                rule_count,
                iterations,
                avg,
                p95,
                provider_plaintext_data_visible=False,
                provider_plaintext_dek_visible=False,
                cryptographic_provider_confidentiality_established=None,
                data_layer_control=False,
            )
        )

        evaluator = DataPolicyEvaluator(policies)
        avg, p95, _ = _measure(
            iterations,
            lambda: evaluator.evaluate(request),
            validate=lambda decision: decision.effect == "allow",
        )
        rows.append(
            PerformanceRow(
                "policy_scalability",
                "presaga_policy_only",
                "policy_microbenchmark",
                "data_policy_decision",
                rule_count,
                iterations,
                avg,
                p95,
                provider_plaintext_data_visible=False,
                provider_plaintext_dek_visible=False,
                cryptographic_provider_confidentiality_established=None,
                data_layer_control=True,
            )
        )

        avg, p95, _ = _measure(
            iterations,
            lambda: _plaintext_token_server(env, evaluator, request),
            validate=lambda plaintext: bool(plaintext),
        )
        rows.append(
            PerformanceRow(
                "baseline_comparison",
                "plaintext_token_server",
                "modeled_plaintext_baseline",
                "active_server_decryption",
                rule_count,
                iterations,
                avg,
                p95,
                provider_plaintext_data_visible=True,
                provider_plaintext_dek_visible=True,
                cryptographic_provider_confidentiality_established=False,
                data_layer_control=True,
            )
        )

        avg, p95, observation = _measure(
            iterations,
            lambda: _presaga_flow(env, request),
            validate=lambda result: (
                result.decision == "allow"
                and result.transformed_encrypted_dek is not None
            ),
        )
        rows.append(
            PerformanceRow(
                "baseline_comparison",
                "presaga",
                "provider_service",
                "provider_transform_audit",
                rule_count,
                iterations,
                avg,
                p95,
                provider_plaintext_data_visible=observation.provider_saw_plaintext_data,
                provider_plaintext_dek_visible=observation.provider_saw_plaintext_dek,
                cryptographic_provider_confidentiality_established=False,
                data_layer_control=True,
            )
        )

    _write_rows(rows, output_root / "tables" / "performance.csv")
    _write_scalability(rows, output_root / "tables" / "scalability_policy_rules.csv")
    _write_latency_svg(rows, output_root / "figures" / "latency_breakdown.svg")
    _write_scalability_svg(rows, output_root / "figures" / "scalability_policy_rules.svg")
    return rows


def _plaintext_token_server(env, evaluator: DataPolicyEvaluator, request: DataAccessRequest) -> bytes:
    decision = evaluator.evaluate(request)
    if decision.effect != "allow":
        raise RuntimeError(decision.reason)
    # Intentionally insecure comparison baseline: unlike PRE-SAGA, this path
    # unwraps the owner DEK in the server process and exposes plaintext.
    owner_wrap = env.store.resolve_active_owner_wrap(env.stored)
    wrap_context = env.store.wrap_context(env.stored.record, owner_wrap.provenance)
    dek = env.backend.unwrap_dek(
        owner_wrap.encrypted_dek,
        env.owner_keypair.private_key,
        wrap_context,
    )
    return env.store.decrypt_with_dek(env.stored, dek)


def _presaga_flow(env, request: DataAccessRequest):
    issuance = env.provider.issue_data_token(env.contact_token, request)
    if issuance.token is None:
        raise RuntimeError(issuance.reason)
    return env.provider.request_re_encryption(
        issuance.token,
        request,
        rekey_for_requester(env),
    )


def _write_rows(rows: list[PerformanceRow], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(PerformanceRow.__dataclass_fields__.keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)


def _write_scalability(rows: list[PerformanceRow], path: Path) -> None:
    selected = [row for row in rows if row.baseline == "presaga_policy_only"]
    _write_rows(selected, path)


def _write_latency_svg(rows: list[PerformanceRow], path: Path) -> None:
    selected = [row for row in rows if row.experiment == "baseline_comparison" and row.policy_rules == 100]
    _write_bar_svg(
        selected,
        path,
        title="Latency Comparison at 100 Policy Rules",
        x_label="Baseline",
        y_label="Average latency (ms)",
    )


def _write_scalability_svg(rows: list[PerformanceRow], path: Path) -> None:
    selected = [row for row in rows if row.baseline == "presaga_policy_only"]
    _write_bar_svg(
        selected,
        path,
        title="Policy Evaluation Scalability",
        x_label="Policy rules",
        y_label="Average latency (ms)",
        label_fn=lambda row: str(row.policy_rules),
    )


def _write_bar_svg(
    rows: list[PerformanceRow],
    path: Path,
    *,
    title: str,
    x_label: str,
    y_label: str,
    label_fn=None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    label_fn = label_fn or (lambda row: row.baseline)
    width, height = 860, 420
    margin_left, margin_bottom, margin_top = 80, 80, 60
    chart_h = height - margin_top - margin_bottom
    chart_w = width - margin_left - 40
    max_value = max((row.avg_latency_ms for row in rows), default=1.0) or 1.0
    bar_gap = 24
    bar_w = max(30, int((chart_w - bar_gap * (len(rows) + 1)) / max(1, len(rows))))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#f9fafb"/>',
        f'<text x="{width/2}" y="34" text-anchor="middle" font-family="Arial" font-size="22" font-weight="700">{title}</text>',
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height-margin_bottom}" stroke="#374151"/>',
        f'<line x1="{margin_left}" y1="{height-margin_bottom}" x2="{width-40}" y2="{height-margin_bottom}" stroke="#374151"/>',
        f'<text x="24" y="{height/2}" transform="rotate(-90 24 {height/2})" text-anchor="middle" font-family="Arial" font-size="13">{y_label}</text>',
        f'<text x="{width/2}" y="{height-22}" text-anchor="middle" font-family="Arial" font-size="13">{x_label}</text>',
    ]
    for idx, row in enumerate(rows):
        x = margin_left + bar_gap + idx * (bar_w + bar_gap)
        bar_h = 0 if max_value == 0 else (row.avg_latency_ms / max_value) * (chart_h - 20)
        y = height - margin_bottom - bar_h
        parts.append(f'<rect x="{x}" y="{y:.2f}" width="{bar_w}" height="{bar_h:.2f}" fill="#2563eb" rx="4"/>')
        parts.append(f'<text x="{x + bar_w/2}" y="{y - 8:.2f}" text-anchor="middle" font-family="Arial" font-size="12">{row.avg_latency_ms}</text>')
        parts.append(f'<text x="{x + bar_w/2}" y="{height-margin_bottom+20}" text-anchor="middle" font-family="Arial" font-size="11">{label_fn(row)}</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


if __name__ == "__main__":
    rows = run_performance()
    for row in rows:
        print(row)
