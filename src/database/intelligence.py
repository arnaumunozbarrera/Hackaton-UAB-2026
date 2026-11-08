"""Ingest local intelligence without downloading external catalogs or filling gaps."""

from .core import Sources, Writer, fields, timestamp

TI_FIELDS = {
    "indicator_type",
    "value",
    "reputation",
    "confidence",
    "malware_family",
    "tags",
    "first_seen",
    "last_seen",
    "source",
    "note",
}
SANDBOX_FIELDS = {
    "sha256",
    "md5",
    "file_name",
    "verdict",
    "score",
    "malware_family",
    "behaviors",
    "network",
    "mitre",
    "dropped_files",
    "analysis_env",
    "analyzed_at",
    "note",
}
NETWORK_TYPES = {"domains": "domain", "ips": "ip", "urls": "url"}


def load_feed(writer: Writer, sources: Sources, issues: list[dict]) -> None:
    for intelligence_id, source in enumerate(sources.records("05_inteligencia/ti_feed.jsonl"), 1):
        fields(source, TI_FIELDS, "ti_feed.jsonl")
        row = {key: value for key, value in source.items() if key != "tags"}
        row["intelligence_id"] = intelligence_id
        writer.add("threat_intelligence", row)
        for tag in source["tags"].split(","):
            if tag.strip():
                writer.add("threat_intelligence_tags", {"intelligence_id": intelligence_id, "tag": tag.strip()})
        if source["first_seen"] > source["last_seen"]:
            issues.append(
                {
                    "code": "source_date_inversion",
                    "table": "threat_intelligence",
                    "intelligence_id": intelligence_id,
                    "detail": "first_seen is later than last_seen; original values preserved",
                }
            )


def load_sandbox(writer: Writer, sources: Sources) -> None:
    for report_id, source in enumerate(sources.records("05_inteligencia/sandbox_informes.jsonl"), 1):
        fields(source, SANDBOX_FIELDS, "sandbox_informes.jsonl")
        row = {
            key: value for key, value in source.items() if key not in {"behaviors", "network", "mitre", "dropped_files"}
        }
        row.update(report_id=report_id, analyzed_at=timestamp(source["analyzed_at"]))
        writer.add("sandbox_reports", row)
        for description in source["behaviors"]:
            writer.add("sandbox_behaviors", {"report_id": report_id, "description": description})
        for technique in source["mitre"]:
            writer.add("sandbox_mitre", {"report_id": report_id, "technique_id": technique})
        fields(source["network"], set(NETWORK_TYPES), "sandbox network")
        for key, values in source["network"].items():
            for value in values:
                writer.add(
                    "sandbox_network_indicators",
                    {"report_id": report_id, "indicator_type": NETWORK_TYPES[key], "value": value},
                )
        for item in source["dropped_files"]:
            fields(item, {"name", "sha256"}, "sandbox dropped_files")
            writer.add(
                "sandbox_dropped_files", {"report_id": report_id, "file_name": item["name"], "sha256": item["sha256"]}
            )


def load_intelligence(writer: Writer, sources: Sources, issues: list[dict]) -> None:
    load_feed(writer, sources, issues)
    for row in sources.records("05_inteligencia/geoip_asn.csv"):
        writer.add("geoip", row)
    load_sandbox(writer, sources)
