"""Prompt builder: AlertContext + runbook profile + policy + read functions -> LLM-ready package.

Why: one deterministic place turns an alert id into compact system/user messages. The user message only
identifies (alert, entities, informative logs) and points to read functions that return the relevant columns;
the output schema travels as `response_schema` and the SQL stays in the executor (`tools.py`).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from string import Template
from typing import Any

from .context import AlertContext, ContextSource
from .policy import Policy, load_policy, most_critical
from .runbooks import DEFAULT_PROFILE, PROFILES, Runbook, RunbookProfile, load_runbooks
from .schema import BASE_QUERIES, QUERIES, SchemaMap
from .templates import SYSTEM_TEMPLATE, USER_TEMPLATE
from .tools import TOOL_NAME, tool_definition

UNTRUSTED_CLOSE = "</datos_no_confiables>"
GENERIC_QUERIES = ("log_detail", "user_profile", "asset_profile", "indicator", "severity_matrix")
MAX_ENTITY_VALUES = 10


@dataclass(frozen=True)
class PromptConfig:
    """Parameters of the prompt."""

    data_dir: Path = Path("docs")
    company: str = "Tarvia Group"
    language: str = "español"
    window_hours: int = 24
    max_logs: int = 40
    inline_runbook: bool = False  # True: paste checks/decisions instead of pointing to runbook_text
    schema_map: SchemaMap = field(default_factory=SchemaMap)
    system_template: str = SYSTEM_TEMPLATE
    user_template: str = USER_TEMPLATE


@dataclass
class RenderedQuery:
    name: str
    purpose: str
    sql: str
    params: list[str]
    example: list[str] | None  # concrete values for the first binding, when all are known


@dataclass
class PromptPackage:
    """What gets sent to the LLM, plus the executor-side queries and metadata."""

    alert_id: str
    runbook_id: str
    system: str
    user: str
    response_schema: dict[str, Any]
    tool: dict[str, Any]
    queries: list[RenderedQuery]
    metadata: dict[str, Any]

    def to_messages(self) -> list[dict[str, str]]:
        return [{"role": "system", "content": self.system}, {"role": "user", "content": self.user}]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"messages": self.to_messages()}


def _untrusted(text: str) -> str:
    """Neutralise attempts to close the untrusted-data block from inside the data."""
    return text.replace(UNTRUSTED_CLOSE, "</datos_no_confiables_>")


def _short_ts(ts: str) -> str:
    return ts[:16] + "Z" if len(ts) >= 16 else ts


def compress_ids(ids: list[str]) -> str:
    """Exact, compact list of event ids: consecutive runs become 'VPN-0010543–0010557'."""
    out: list[str] = []
    run: list[str] = []

    def flush() -> None:
        if run:
            out.append(run[0] if len(run) == 1 else f"{run[0]}–{run[-1].split('-')[-1]}")
            run.clear()

    for eid in sorted(ids):
        prefix, _, num = eid.rpartition("-")
        if run:
            p_prefix, _, p_num = run[-1].rpartition("-")
            if not (prefix == p_prefix and num.isdigit() and p_num.isdigit() and int(num) == int(p_num) + 1):
                flush()
        run.append(eid)
    flush()
    return ", ".join(out)


class PromptBuilder:
    """Build compact prompts for alerts from a ContextSource."""

    def __init__(self, source: ContextSource, config: PromptConfig | None = None) -> None:
        self.source = source
        self.cfg = config or PromptConfig()
        ctx_dir = self.cfg.data_dir / "01_contexto"
        self.runbooks: dict[str, Runbook] = load_runbooks(ctx_dir / "runbooks")
        self.policy: Policy = load_policy(ctx_dir / "politica_soc.md")
        self.output_schema = json.loads((ctx_dir / "ticket_salida.schema.json").read_text(encoding="utf-8"))
        self.system = Template(self.cfg.system_template).substitute(
            company=self.cfg.company, language=self.cfg.language, tool=TOOL_NAME, policy=self.policy.compact()
        )

    # ------------------------------------------------------------ identifiers and functions
    def _bindings(self, ctx: AlertContext) -> dict[str, list[str]]:
        created = datetime.fromisoformat(ctx.created_at.replace("Z", "+00:00"))
        delta, fmt, e = timedelta(hours=self.cfg.window_hours), "%Y-%m-%dT%H:%M:%S.000Z", ctx.entities
        indicators = e.get("ips", []) + e.get("domains", []) + e.get("urls", []) + e.get("files", [])
        users = [u.user_key for u in ctx.users] + ctx.unknown_users
        hosts = [h.hostname for h in ctx.hosts] + ctx.unknown_hosts
        return {
            "alert_id": [ctx.alert_id], "rule_id": [ctx.rule_id], "rule_severity": [ctx.rule_severity],
            "window_start": [(created - delta).strftime(fmt)], "window_end": [(created + delta).strftime(fmt)],
            "user_key": users, "hostname": hosts, "ip": e.get("ips", []), "indicator": indicators,
            "sha256": [v for v in e.get("files", []) if len(v) == 64], "customer": e.get("customers", []),
            "entity_value": users + hosts + indicators, "ref_id": e.get("ai_session", []),
            "event_id": [log.event_id for log in ctx.informative_logs],
        }  # fmt: skip

    def _identifiers(self, b: dict[str, list[str]]) -> str:
        """Each parameter value once; derived lists (entity_value, event_id) are described, not repeated."""
        skip = {"alert_id", "entity_value", "event_id", "rule_severity"}
        parts = []
        for name, values in b.items():
            if name == "indicator" and b["ip"]:  # indicator = ip + domains/urls/files: list only the extras
                values = [v for v in values if v not in b["ip"]]
                parts.append("indicator=ip" + (f" + [{', '.join(_untrusted(v) for v in values)}]" if values else ""))
                continue
            if name in skip or not values:
                continue
            shown = [_untrusted(v) for v in values[:MAX_ENTITY_VALUES]]
            more = f" (+{len(values) - MAX_ENTITY_VALUES})" if len(values) > MAX_ENTITY_VALUES else ""
            parts.append(f"{name}={shown[0]}" if len(shown) == 1 and not more else f"{name}=[{', '.join(shown)}]{more}")
        return "; ".join(parts) + "; entity_value=cualquier entidad; event_id=logs informativos"

    def _query_names(self, prof: RunbookProfile) -> list[str]:
        names = list(BASE_QUERIES)
        names += sorted({n for qs in prof.check_queries.values() for n in qs} - set(names))
        return names + [n for n in GENERIC_QUERIES if n not in names]

    def _render_queries(self, names: list[str], b: dict[str, list[str]]) -> list[RenderedQuery]:
        out = []
        for name in names:
            spec = QUERIES[name]
            values = [b.get(p, []) for p in spec.params]
            example = [v[0] for v in values] if all(values) else None
            out.append(
                RenderedQuery(name, spec.purpose, self.cfg.schema_map.render(spec.sql), list(spec.params), example)
            )
        return out

    # ------------------------------------------------------------ sections
    def _affected(self, ctx: AlertContext) -> str:
        items = [f"{h.hostname} (activo {h.criticality}, {h.business_service}, {h.zone})" for h in ctx.hosts]
        items += [f"{h} (activo fuera de inventario)" for h in ctx.unknown_hosts]
        items += [f"«{s.name}» (servicio {s.criticality})" for s in ctx.services]
        for u in ctx.users:
            flags = [f for f, on in (("privilegiada", u.privileged), ("VIP", u.vip)) if on]
            flags += [f"RRHH {u.hr_event}"] if u.hr_event else []
            items.append(f"{u.user_key} (identidad {u.account_type}{', ' + ', '.join(flags) if flags else ''})")
        items += [f"{u} (identidad fuera del directorio)" for u in ctx.unknown_users]
        return "; ".join(items) or "sin entidades resueltas (usa alert_entities)"

    def _severity(self, ctx: AlertContext) -> dict[str, str]:
        crit = most_critical([h.criticality for h in ctx.hosts] + [s.criticality for s in ctx.services])
        origin = "activo o servicio más crítico"
        if crit is None:
            crit = "Alta" if any(u.vip or u.privileged for u in ctx.users) else "Media"
            origin = "sin activo: VIP o privilegiada = Alta, resto = Media"
        flags = [f"{u.user_key} VIP o privilegiada" for u in ctx.users if u.vip or u.privileged]
        flags += [f"{u.user_key} RRHH {u.hr_event}" for u in ctx.users if u.hr_event]
        return {
            "base_severity": self.policy.base_severity(ctx.rule_severity, crit) or "no calculable",
            "matrix_row": self.policy.row(ctx.rule_severity), "criticality": crit, "criticality_origin": origin,
            "severity_flags": "; ".join(flags) or "sin factores detectados en la identificación",
        }  # fmt: skip

    def _runbook(self, ctx: AlertContext, prof: RunbookProfile) -> dict[str, str]:
        rb = self.runbooks.get(ctx.runbook_id)
        plan = " · ".join(f"C{i}→{', '.join(qs)}" for i, qs in sorted(prof.check_queries.items()))
        if self.cfg.inline_runbook and rb:
            checks = " ".join(f"C{i}. {c}" for i, c in enumerate(rb.checks, 1))
            plan = f"{checks} Decisión: {' '.join(rb.decisions)} Consultas: {plan}"
        else:
            plan = f"lee comprobaciones y decisión con runbook_text(rule_id); {plan}"
        notes = f" Notas: {' '.join(prof.notes)}" if prof.notes else ""
        return {"runbook_focus": prof.focus.rstrip("."), "runbook_plan": plan, "runbook_notes": notes}

    def _logs(self, ctx: AlertContext) -> dict[str, str]:
        """Informative logs grouped by (source, reason) with exact compressed ids and time range."""
        logs = ctx.informative_logs[: self.cfg.max_logs]
        groups: dict[tuple[str, str], list[Any]] = {}
        for lg in logs:
            groups.setdefault((lg.source, lg.reason), []).append(lg)
        rows = []
        for (source, reason), items in sorted(groups.items()):
            ts = sorted(_short_ts(i.timestamp) for i in items)
            span = (
                ts[0]
                if ts[0] == ts[-1]
                else f"{ts[0]}→{ts[-1][11:]}"
                if ts[0][:10] == ts[-1][:10]
                else f"{ts[0]}→{ts[-1]}"
            )
            rows.append(f"{source} [{reason}] ×{len(items)} {span}: {compress_ids([i.event_id for i in items])}")
        hidden = len(ctx.informative_logs) - len(logs)
        rows += [f"+{hidden} más (alert_events)"] if hidden > 0 else []
        aside = []
        for stage, ids in sorted(ctx.set_aside.items()):
            refs = sorted({ctx.explanations[i] for i in ids if i in ctx.explanations})
            aside.append(f"{stage} ×{len(ids)} {compress_ids(ids)}{' (' + '; '.join(refs) + ')' if refs else ''}")
        return {
            "informative_logs": " | ".join(rows) or "ninguno",
            "set_aside": " | ".join(aside) or "ninguno",
            "informative_count": str(len(ctx.informative_logs)),
            "cited_count": str(len(ctx.informative_logs) + sum(len(v) for v in ctx.set_aside.values())),
        }

    def _similar(self, ctx: AlertContext) -> dict[str, str]:
        """Resolved neighbours in the embedding space: a consistency reference, never evidence for this alert."""
        if not ctx.similar_alerts:
            return {"similar_alerts": ""}
        items = [
            f"{s['alert_id']} {s['rule_id']} → {s['verdict']}/{s['severity']} (sim {s['similarity']:.2f})"
            for s in ctx.similar_alerts
        ]
        return {"similar_alerts": "Alertas similares ya resueltas (referencia de coherencia, no evidencia): "
                + "; ".join(items) + "\n"}  # fmt: skip

    # ------------------------------------------------------------ public API
    def build(self, alert_id: str) -> PromptPackage:
        """Prompt package for one alert."""
        ctx = self.source.get(alert_id)
        prof = PROFILES.get(ctx.runbook_id, DEFAULT_PROFILE)
        bindings, names = self._bindings(ctx), self._query_names(prof)
        severity = self._severity(ctx)
        values = {
            "alert_id": ctx.alert_id, "created_at": ctx.created_at, "rule_id": ctx.rule_id, "rule_name": ctx.rule_name,
            "rule_severity": ctx.rule_severity, "source_product": ctx.source_product, "technique_id": ctx.technique_id,
            "tactic": ctx.tactic, "runbook_id": ctx.runbook_id, "description": _untrusted(ctx.description),
            "evidence": _untrusted(ctx.evidence), "identifiers": self._identifiers(bindings),
            "affected": self._affected(ctx),
        } | severity | self._runbook(ctx, prof) | self._logs(ctx) | self._similar(ctx)  # fmt: skip
        user = Template(self.cfg.user_template).substitute(values)
        meta = {"rule_id": ctx.rule_id, "informative_logs": len(ctx.informative_logs),
                "set_aside": {k: len(v) for k, v in ctx.set_aside.items()}, "base_severity": severity["base_severity"],
                "similar_alerts": ctx.similar_alerts,
                "chars": {"system": len(self.system), "user": len(user)}}  # fmt: skip
        return PromptPackage(
            ctx.alert_id, ctx.runbook_id, self.system, user, self.output_schema, tool_definition(names),
            self._render_queries(names, bindings), meta,
        )  # fmt: skip

    def build_many(self, alert_ids: list[str]) -> list[PromptPackage]:
        return [self.build(a) for a in alert_ids]
