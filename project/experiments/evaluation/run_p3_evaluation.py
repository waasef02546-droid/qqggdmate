"""P3 task-level evaluation harness.

This module turns the prototype experiments into paper-facing evaluation
artifacts: task success summaries, denial-reason summaries, latency breakdowns,
and synthetic agent/policy/record scalability measurements.
"""

from __future__ import annotations

import csv
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from experiments.attacks.common import AttackResult, make_environment, rekey_for_requester
from experiments.attacks.run_all import run_all as run_attacks
from experiments.tasks.common import TaskResult
from experiments.tasks.run_all import run_all as run_tasks
from presaga.protocol.schemas import DataAccessRequest, DataScope, DataSharingPolicy, Limits, RequesterSelector, Validity, VersionConstraints
from presaga.provider.contact_policy import SAGAStyleContactPolicy
from presaga.provider.data_policy import DataPolicyEvaluator


@dataclass(frozen=True)
class ScalabilityRow:
    dimension: str
    agent_count: int
    policy_count: int
    record_count: int
    iterations: int
    avg_latency_ms: float
    p95_latency_ms: float
    success_rate: float
    denial_reasons: str


@dataclass(frozen=True)
class P3EvaluationOutputs:
    task_summary_path: Path
    denial_summary_path: Path
    task_latency_breakdown_path: Path
    task_scalability_path: Path
    task_latency_figure_path: Path
    task_scalability_figure_path: Path
    task_success_rate: str
    scalability_rows: int


def run_p3_evaluation(
    output_root: Path = Path("results"),
    *,
    task_results: list[TaskResult] | None = None,
    attack_results: list[AttackResult] | None = None,
) -> P3EvaluationOutputs:
    tables = output_root / "tables"
    figures = output_root / "figures"
    tables.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)

    if task_results is None:
        task_results, _ = run_tasks(tables / "task_results.csv")
    if attack_results is None:
        attack_results, _ = run_attacks(tables / "security_matrix.csv")

    task_summary_path = tables / "task_summary.csv"
    denial_summary_path = tables / "denial_reason_summary.csv"
    task_latency_path = tables / "task_latency_breakdown.csv"
    scalability_path = tables / "task_scalability.csv"
    latency_figure_path = figures / "task_latency_breakdown.svg"
    scalability_figure_path = figures / "task_scalability.svg"

    _write_task_summary(task_results, task_summary_path)
    _write_denial_summary(attack_results, denial_summary_path)
    _write_task_latency_breakdown(task_results, task_latency_path)
    _write_task_latency_svg(task_results, latency_figure_path)

    scalability_rows = run_task_scalability()
    _write_scalability(scalability_rows, scalability_path)
    _write_scalability_svg(scalability_rows, scalability_figure_path)

    success_count = sum(1 for result in task_results if result.success)
    return P3EvaluationOutputs(
        task_summary_path=task_summary_path,
        denial_summary_path=denial_summary_path,
        task_latency_breakdown_path=task_latency_path,
        task_scalability_path=scalability_path,
        task_latency_figure_path=latency_figure_path,
        task_scalability_figure_path=scalability_figure_path,
        task_success_rate=f"{success_count}/{len(task_results)}",
        scalability_rows=len(scalability_rows),
    )


def run_task_scalability(iterations: int = 20) -> list[ScalabilityRow]:
    rows: list[ScalabilityRow] = []
    for agent_count in (2, 8, 32):
        rows.append(_measure_scalability("agent_count", agent_count, 100, 100, iterations))
    for policy_count in (10, 100, 500):
        rows.append(_measure_scalability("policy_count", 8, policy_count, 100, iterations))
    for record_count in (10, 100, 500):
        rows.append(_measure_scalability("record_count", 8, 100, record_count, iterations))
    return rows


def _measure_scalability(
    dimension: str,
    agent_count: int,
    policy_count: int,
    record_count: int,
    iterations: int,
) -> ScalabilityRow:
    env = make_environment(max_uses=iterations + 5)
    request = _scalability_request(env)
    contact_policy = SAGAStyleContactPolicy(_synthetic_contact_rulebook(agent_count, request.requester_aid))
    policies = _synthetic_policies(agent_count, policy_count, record_count, request)
    evaluator = DataPolicyEvaluator(policies)
    env.app._data_policies[:] = policies
    samples: list[float] = []
    success = 0
    denials: Counter[str] = Counter()

    for _ in range(iterations):
        started = time.perf_counter()
        contact = contact_policy.evaluate(request.requester_aid, consume=False)
        if contact.effect != "allow":
            denials[contact.reason] += 1
            samples.append((time.perf_counter() - started) * 1000)
            continue
        decision = evaluator.evaluate(request)
        if decision.effect != "allow":
            denials[decision.reason] += 1
            samples.append((time.perf_counter() - started) * 1000)
            continue
        issuance = env.app.request_data_token(contact_token=env.contact_token, request=request)
        if issuance.token is None:
            denials[issuance.decision.reason] += 1
            samples.append((time.perf_counter() - started) * 1000)
            continue
        result = env.app.request_re_encryption(
            contact_token=env.contact_token,
            token=issuance.token,
            request=request,
            encrypted_dek_owner=env.stored.encrypted_dek_owner,
            rekey=rekey_for_requester(env),
        )
        if result.decision == "allow":
            success += 1
        else:
            denials[result.reason] += 1
        samples.append((time.perf_counter() - started) * 1000)

    avg = round(statistics.fmean(samples), 4)
    p95 = round(sorted(samples)[max(0, int(len(samples) * 0.95) - 1)], 4)
    denial_text = ";".join(f"{reason}:{count}" for reason, count in sorted(denials.items()))
    return ScalabilityRow(
        dimension=dimension,
        agent_count=agent_count,
        policy_count=policy_count,
        record_count=record_count,
        iterations=iterations,
        avg_latency_ms=avg,
        p95_latency_ms=p95,
        success_rate=round(success / iterations, 4),
        denial_reasons=denial_text,
    )


def _scalability_request(env) -> DataAccessRequest:
    return DataAccessRequest(
        request_id="p3-scalability-request",
        owner_aid=env.stored.record.owner_aid,
        requester_aid="bob@mail.com:scheduler_agent",
        record_id=env.stored.record.record_id,
        data_class=env.stored.record.data_class,
        data_subclass=env.stored.record.data_subclass,
        purpose="schedule_meeting",
        version=env.stored.record.version,
        requester_public_key=env.requester_keypair.public_key,
    )


def _synthetic_policies(
    agent_count: int,
    policy_count: int,
    record_count: int,
    request: DataAccessRequest,
) -> list[DataSharingPolicy]:
    now = datetime.now(timezone.utc)
    policies = []
    for idx in range(max(0, policy_count - 1)):
        requester = f"user{idx % max(1, agent_count)}@mail.com:agent_{idx % max(1, agent_count)}"
        policies.append(
            _policy(
                policy_id=f"noise-policy-{idx}",
                owner_aid=request.owner_aid,
                requester_aid=requester,
                record_ids=[f"record-{idx % max(1, record_count):04d}"],
                data_class=request.data_class,
                data_subclass=request.data_subclass,
                purpose=request.purpose,
                now=now,
            )
        )
    policies.append(
        _policy(
            policy_id="target-policy",
            owner_aid=request.owner_aid,
            requester_aid=request.requester_aid,
            record_ids=[f"record-scope-{idx:04d}" for idx in range(max(0, record_count - 1))] + [request.record_id],
            data_class=request.data_class,
            data_subclass=request.data_subclass,
            purpose=request.purpose,
            now=now,
        )
    )
    return policies


def _synthetic_contact_rulebook(agent_count: int, target_requester: str) -> list[dict[str, int | str]]:
    rules = [
        {"pattern": f"user{idx}@mail.com:agent_{idx}", "budget": 100000}
        for idx in range(max(0, agent_count - 1))
    ]
    rules.append({"pattern": target_requester, "budget": 100000})
    return rules


def _policy(
    *,
    policy_id: str,
    owner_aid: str,
    requester_aid: str,
    record_ids: list[str],
    data_class: str,
    data_subclass: str,
    purpose: str,
    now: datetime,
) -> DataSharingPolicy:
    return DataSharingPolicy(
        policy_id=policy_id,
        owner_aid=owner_aid,
        requester_selector=RequesterSelector(type="aid_exact", value=requester_aid),
        data_scope=DataScope(data_classes=[data_class], data_subclasses=[data_subclass], record_ids=record_ids),
        purposes=[purpose],
        validity=Validity(not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10)),
        limits=Limits(max_uses=10, max_records=1),
        version_constraints=VersionConstraints(min_version=1, max_version=1),
    )


def _write_task_summary(results: list[TaskResult], path: Path) -> None:
    successes = sum(1 for result in results if result.success)
    total = len(results)
    rows = [
        {"metric": "total_tasks", "value": total},
        {"metric": "successful_tasks", "value": successes},
        {"metric": "failed_tasks", "value": total - successes},
        {"metric": "task_success_rate", "value": f"{successes}/{total}"},
        {"metric": "total_audit_events", "value": sum(result.audit_events for result in results)},
    ]
    _write_dict_rows(rows, path, ["metric", "value"])


def _write_denial_summary(results: list[AttackResult], path: Path) -> None:
    grouped: dict[str, list[str]] = defaultdict(list)
    for result in results:
        grouped[result.reason].append(result.attack)
    rows = [
        {"reason": reason, "count": len(attacks), "attacks": ";".join(attacks)}
        for reason, attacks in sorted(grouped.items())
    ]
    _write_dict_rows(rows, path, ["reason", "count", "attacks"])


def _write_task_latency_breakdown(results: list[TaskResult], path: Path) -> None:
    rows = [
        {
            "task": result.task,
            "contact_ms": result.contact_ms,
            "policy_ms": result.policy_ms,
            "token_issue_ms": result.token_issue_ms,
            "pre_transform_ms": result.pre_transform_ms,
            "decrypt_ms": result.decrypt_ms,
            "total_latency_ms": result.latency_ms,
        }
        for result in results
    ]
    _write_dict_rows(
        rows,
        path,
        ["task", "contact_ms", "policy_ms", "token_issue_ms", "pre_transform_ms", "decrypt_ms", "total_latency_ms"],
    )


def _write_scalability(rows: list[ScalabilityRow], path: Path) -> None:
    _write_dict_rows([row.__dict__ for row in rows], path, list(ScalabilityRow.__dataclass_fields__.keys()))


def _write_dict_rows(rows: list[dict], path: Path, fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_task_latency_svg(results: list[TaskResult], path: Path) -> None:
    labels = [result.task for result in results]
    totals = [max(result.latency_ms, 0.001) for result in results]
    _write_bar_svg(labels, totals, path, "Task-level Latency", "Task", "Total latency (ms)")


def _write_scalability_svg(rows: list[ScalabilityRow], path: Path) -> None:
    labels = [f"{row.dimension}:{_dimension_value(row)}" for row in rows]
    values = [row.avg_latency_ms for row in rows]
    _write_bar_svg(labels, values, path, "Task Scalability", "Dimension:value", "Average latency (ms)")


def _dimension_value(row: ScalabilityRow) -> int:
    if row.dimension == "agent_count":
        return row.agent_count
    if row.dimension == "policy_count":
        return row.policy_count
    return row.record_count


def _write_bar_svg(labels: list[str], values: list[float], path: Path, title: str, x_label: str, y_label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    width, height = 980, 460
    margin_left, margin_bottom, margin_top = 80, 110, 60
    chart_h = height - margin_top - margin_bottom
    chart_w = width - margin_left - 40
    max_value = max(values, default=1.0) or 1.0
    gap = 18
    bar_w = max(24, int((chart_w - gap * (len(values) + 1)) / max(1, len(values))))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#f9fafb"/>',
        f'<text x="{width/2}" y="34" text-anchor="middle" font-family="Arial" font-size="22" font-weight="700">{title}</text>',
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{height-margin_bottom}" stroke="#374151"/>',
        f'<line x1="{margin_left}" y1="{height-margin_bottom}" x2="{width-40}" y2="{height-margin_bottom}" stroke="#374151"/>',
        f'<text x="24" y="{height/2}" transform="rotate(-90 24 {height/2})" text-anchor="middle" font-family="Arial" font-size="13">{y_label}</text>',
        f'<text x="{width/2}" y="{height-18}" text-anchor="middle" font-family="Arial" font-size="13">{x_label}</text>',
    ]
    for idx, (label, value) in enumerate(zip(labels, values)):
        x = margin_left + gap + idx * (bar_w + gap)
        bar_h = (value / max_value) * (chart_h - 20)
        y = height - margin_bottom - bar_h
        parts.append(f'<rect x="{x}" y="{y:.2f}" width="{bar_w}" height="{bar_h:.2f}" fill="#0f766e" rx="4"/>')
        parts.append(f'<text x="{x + bar_w/2}" y="{y - 8:.2f}" text-anchor="middle" font-family="Arial" font-size="11">{value}</text>')
        parts.append(
            f'<text x="{x + bar_w/2}" y="{height-margin_bottom+18}" transform="rotate(35 {x + bar_w/2} {height-margin_bottom+18})" text-anchor="start" font-family="Arial" font-size="10">{label}</text>'
        )
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


if __name__ == "__main__":
    outputs = run_p3_evaluation()
    print(f"task_success_rate={outputs.task_success_rate}")
    print(f"task_summary={outputs.task_summary_path}")
    print(f"denial_summary={outputs.denial_summary_path}")
    print(f"task_latency_breakdown={outputs.task_latency_breakdown_path}")
    print(f"task_scalability_rows={outputs.scalability_rows}")
    print(f"task_scalability={outputs.task_scalability_path}")
