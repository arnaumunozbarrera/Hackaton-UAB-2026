"""Write the 20-alert debug feed (dev/alertas_debug.jsonl) served by the dev mock API.

The selection covers every runbook (RB-01..RB-10), the three reference alerts of the brief, alerts the basic checks
should auto-close (scanner blocked, Private Relay, notified trip, NESSUS window, Logisoft change, sandbox clean,
benign TIP domain, pentest) and alerts the safety guards must keep for the LLM (OT, high/critical rule, malicious
TIP indicator). Alerts are copied verbatim from docs/03_alertas/alertas.jsonl (read-only) and sorted by time, so the
±24 h guard sees them in the order an analyst would. The raw log rows they cite (plus the emails their clicks point
to) go to dev/alertas_debug_events.jsonl, so tests can replay the API without loading the 814k-event dataset. Rows
marked "context" are not cited by any alert; they are earlier sign-ins of the same device, which the basic checks
look up through the API log search.

Usage: python scripts/make_debug_alerts.py [--out dev/alertas_debug.jsonl]
"""

import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

DEBUG_ALERTS = {
    "ALR-20261009-011791": "RB-02 Latrodectus execution (true positive)",
    "ALR-20261007-011785": "RB-01 phishing click (high)",
    "ALR-20261005-000301": "RB-02 SCCM PowerShell (benign, needs the LLM)",
    "ALR-20261005-000440": "RB-05 internet scanner blocked by the WAF (auto-close)",
    "ALR-20261008-011833": "RB-05 pentest source IP during CHG-2026-1042",
    "ALR-20261009-001917": "RB-03 impossible travel via Private Relay with a known device (auto-close)",
    "ALR-20261011-011873": "RB-03 impossible travel with a trip notified to HR (auto-close)",
    "ALR-20261007-011851": "RB-09 NESSUS01 Wednesday scan CHG-2026-1049 (auto-close)",
    "ALR-20261016-011922": "RB-03 VPN covered by change CHG-2026-1071 (auto-close)",
    "ALR-20261028-009418": "RB-02 sandbox clean and EDR blocked (auto-close)",
    "ALR-20261011-002565": "RB-09 benign TIP domain (auto-close)",
    "ALR-20261023-011915": "RB-03 high rule explained by CHG-2026-1078 (guard: high rule)",
    "ALR-20261009-002231": "RB-08 OT access from an authorised host (guard: OT)",
    "ALR-20261005-000105": "RB-01 reported phishing with a malicious TIP domain (guard: TIP)",
    "ALR-20261007-001237": "RB-04 DLP (high)",
    "ALR-20261101-010863": "RB-06 cloud (medium)",
    "ALR-20261010-002437": "RB-07 AI gateway (medium)",
    "ALR-20261012-003200": "RB-10 CI/CD (medium)",
    "ALR-20261006-011826": "RB-09 network (high)",
    "ALR-20261010-011795": "RB-02 EDR (critical)",
}


def read_rows(path: Path):
    with path.open(encoding="utf-8") as stream:
        if path.suffix == ".csv":
            yield from csv.DictReader(stream)
        else:
            yield from (json.loads(line) for line in stream if line.strip())


def collect_events(wanted: set[str]) -> list[dict]:
    """Raw rows (as GET /logs/{source} returns them) of the wanted events and of the emails their clicks reference."""
    found: list[dict] = []
    messages: set[str] = set()
    for path in sorted((DOCS / "04_logs").iterdir()):
        for row in read_rows(path):
            if row["event_id"] in wanted:
                found.append({"source": path.stem, "row": row})
                if path.stem == "email_clicks":
                    messages.add(row["message_id"])
    have = {f["row"]["event_id"] for f in found}
    for row in read_rows(DOCS / "04_logs" / "email.jsonl"):
        if row["message_id"] in messages and row["event_id"] not in have:
            found.append({"source": "email", "row": row})
    # Earlier sign-ins with the same device: what GET /logs/idp_signins?q=<upn> shows the checks ("known device").
    devices = {(f["row"]["user_upn"], f["row"]["device_id"]) for f in found if f["source"] == "idp_signins"}
    extra: dict[tuple[str, str], int] = {}
    for row in read_rows(DOCS / "04_logs" / "idp_signins.jsonl"):
        key = (row["user_upn"], row["device_id"])
        if key in devices and row["event_id"] not in have and extra.get(key, 0) < 3:
            extra[key] = extra.get(key, 0) + 1
            found.append({"source": "idp_signins", "row": row, "context": True})
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "dev" / "alertas_debug.jsonl")
    args = parser.parse_args()
    selected = []
    with (DOCS / "03_alertas" / "alertas.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            alert = json.loads(line)
            if alert["alert_id"] in DEBUG_ALERTS:
                selected.append(alert)
    missing_alerts = set(DEBUG_ALERTS) - {a["alert_id"] for a in selected}
    if missing_alerts:
        raise SystemExit(f"Alerts not found in the dataset: {sorted(missing_alerts)}")
    wanted = {e for a in selected for e in a["related_events"]}
    events = collect_events(wanted)
    missing_events = sorted(wanted - {e["row"]["event_id"] for e in events})
    if missing_events:
        raise SystemExit(f"Related events not found in docs/04_logs: {missing_events}")
    runbooks = {a["runbook"] for a in selected}
    expected = {f"RB-{n:02d}" for n in range(1, 11)}
    if runbooks != expected:
        raise SystemExit(f"Runbooks not covered: {sorted(expected - runbooks)}")
    selected.sort(key=lambda a: a["created_at"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as out:
        for alert in selected:
            out.write(json.dumps(alert, ensure_ascii=False) + "\n")
    events_path = args.out.with_name(args.out.stem + "_events.jsonl")
    with events_path.open("w", encoding="utf-8", newline="\n") as out:
        for event in events:
            out.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"Wrote {len(selected)} alerts to {args.out} and {len(events)} log rows to {events_path}")


if __name__ == "__main__":
    main()
