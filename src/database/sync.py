"""Pull new alerts and the log events they reference from the SOC API into an existing database."""

import os
import sqlite3
from collections.abc import Callable
from pathlib import Path

from ..soc_api import SocApi
from .alerts import load_alert
from .core import Directory, Writer
from .logs import load_one
from .schema import ROOT

# event_id prefix -> log source, as served by GET /logs/{source}
EVENT_SOURCES = {
    "ADE": "ad_events",
    "AIG": "ai_gateway",
    "CI": "cicd_builds",
    "CT": "cloudtrail",
    "DLP": "dlp",
    "DNS": "dns",
    "ECO": "ecom_account",
    "ECA": "ecom_auth",
    "EDR": "edr_events",
    "EML": "email",
    "CLK": "email_clicks",
    "FW": "firewall",
    "AUD": "idp_audit",
    "SIGN": "idp_signins",
    "PRX": "proxy",
    "SQL": "sql_audit",
    "VPN": "vpn",
    "WAF": "waf",
}


def event_source(event_id: str) -> str:
    source = EVENT_SOURCES.get(event_id.split("-", 1)[0])
    if source is None:
        raise ValueError(f"Unknown log source for event {event_id}")
    return source


def directory_from_db(connection: sqlite3.Connection) -> Directory:
    """Rebuild the identity resolver from the inventory already stored in the database."""
    connection.row_factory = sqlite3.Row
    users = [dict(row) for row in connection.execute("SELECT user_id, upn, username, display_name FROM users")]
    assets = [dict(row) for row in connection.execute("SELECT asset_id, hostname, ip FROM assets")]
    directory = Directory(users, assets)
    directory.zones = {zone for (zone,) in connection.execute("SELECT zone_id FROM network_zones")}
    directory.messages = dict(connection.execute("SELECT message_id, event_id FROM email_logs"))
    return directory


def rules_from_db(connection: sqlite3.Connection) -> dict[str, dict]:
    connection.row_factory = sqlite3.Row
    return {row["rule_id"]: dict(row) for row in connection.execute("SELECT * FROM detection_rules")}


class AlertIngestor:
    """Insert one alert at a time, each in its own transaction, so a rejected alert leaves no partial rows."""

    def __init__(self, connection: sqlite3.Connection, api: SocApi):
        self.connection = connection
        self.api = api
        self.directory = directory_from_db(connection)
        self.rules = rules_from_db(connection)
        connection.row_factory = None
        self.writer = Writer(connection)
        self.known_alerts = {alert for (alert,) in connection.execute("SELECT alert_id FROM alerts")}
        self.known_events = {event for (event,) in connection.execute("SELECT event_id FROM logs")}

    def fetch_event(self, event_id: str) -> tuple[str, dict]:
        source = event_source(event_id)
        row = self.api.find_event(source, event_id)
        if row is None:
            raise ValueError(f"Event {event_id} not found in API source {source}")
        return source, row

    def queue_event(self, event_id: str, added: list[str]) -> None:
        if event_id in self.known_events or event_id in added:
            return
        source, row = self.fetch_event(event_id)
        if source == "email_clicks" and row["message_id"] not in self.directory.messages:
            email = self.api.find_log("email", "message_id", row["message_id"])
            if email is None:
                raise ValueError(f"Clicked email {row['message_id']} not found in API")
            self.queue_row("email", email, added)
        self.queue_row(source, row, added)

    def queue_row(self, source: str, row: dict, added: list[str]) -> None:
        if row["event_id"] not in self.known_events and row["event_id"] not in added:
            load_one(self.writer, source, row, self.directory)
            added.append(row["event_id"])

    def ingest(self, alert: dict) -> int:
        """Store the alert and its missing events; return how many events were added."""
        added: list[str] = []
        messages = dict(self.directory.messages)
        try:
            for event_id in alert["related_events"]:
                self.queue_event(event_id, added)
            self.writer.flush_all()
            load_alert(self.writer, alert, self.directory, self.rules)
            self.writer.flush_all()
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            for buffer in self.writer.buffers.values():
                buffer.clear()
            self.directory.messages = messages
            raise
        self.known_alerts.add(alert["alert_id"])
        self.known_events.update(added)
        return len(added)


class AlertFeed:
    """Walk the API queue of `new` alerts one at a time and store those the database lacks.

    The database must already exist with its inventory (scripts/create_db.sh). Alerts already stored are
    skipped; an alert the strict loaders reject is rolled back and reported.
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        api: SocApi | None = None,
        progress: Callable[[str], None] = print,
    ):
        path = Path(db_path or os.environ.get("TARVIA_DB") or ROOT / "data" / "tarvia.sqlite")
        if not path.exists():
            raise FileNotFoundError(f"Database not found: {path}. Create it first with scripts/create_db.sh")
        self.api = api or SocApi()
        self.progress = progress
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.ingestor = AlertIngestor(self.connection, self.api)
        self.queue = self.api.alerts(status="new")
        self.summary = {"seen": 0, "already_stored": 0, "alerts_added": 0, "events_added": 0, "rejected": {}}

    def __enter__(self) -> "AlertFeed":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self.connection.close()
        self.progress(
            f"API sync: {self.summary['seen']} alerts read from the queue, {self.summary['already_stored']} already "
            f"stored, {self.summary['alerts_added']} added with {self.summary['events_added']} log events, "
            f"{len(self.summary['rejected'])} rejected"
        )

    def next_alert(self) -> dict | None:
        """Return the next `new` alert from the API that the database lacks; None when the queue is exhausted."""
        for alert in self.queue:
            self.summary["seen"] += 1
            if alert["alert_id"] not in self.ingestor.known_alerts:
                return alert
            self.summary["already_stored"] += 1
        return None

    def store(self, alert: dict) -> bool:
        """Store the alert with its log events; False if the loaders reject it (nothing is written)."""
        try:
            self.summary["events_added"] += self.ingestor.ingest(alert)
        except (ValueError, KeyError, TypeError, sqlite3.IntegrityError) as error:
            self.summary["rejected"][alert["alert_id"]] = str(error)
            self.progress(f"Rejected {alert['alert_id']}: {error}")
            return False
        self.summary["alerts_added"] += 1
        self.progress(f"Stored {alert['alert_id']} ({alert['rule_id']}, {alert['severity']})")
        return True
