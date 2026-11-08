-- Triage pipeline tables. Applied idempotently by src.database.enrich after the base schema.
-- They hold derived results only: dropping them never loses source data.

CREATE TABLE IF NOT EXISTS "alert_log_selection" (
  "alert_id" TEXT NOT NULL,
  "event_id" TEXT NOT NULL,
  "source" TEXT,
  "timestamp" TEXT,
  "state" TEXT NOT NULL,
  "reason" TEXT,
  "reference" TEXT,
  PRIMARY KEY ("alert_id", "event_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id"),
  CHECK (state IN ('kept', 'N1', 'N2', 'N3', 'N4', 'unfiltered'))
);

CREATE TABLE IF NOT EXISTS "triage_tickets" (
  "alert_id" TEXT NOT NULL,
  "ticket_json" TEXT NOT NULL CHECK (json_valid("ticket_json")),
  "valid" INTEGER NOT NULL,
  "errors_json" TEXT,
  "route" TEXT NOT NULL CHECK (route IN ('llm', 'discriminator')),
  "model" TEXT,
  "verdict" TEXT,
  "severity" TEXT,
  "confidence" REAL,
  "escalate" INTEGER,
  "attempts" INTEGER,
  "usage_json" TEXT,
  "transcript_json" TEXT,
  "elapsed_s" REAL,
  "created_at" TEXT NOT NULL,
  "decision" TEXT CHECK (decision IS NULL OR decision IN ('approve', 'reject', 'escalate', 'investigate')),
  "decision_comment" TEXT,
  "decided_by" TEXT,
  "decided_at" TEXT,
  PRIMARY KEY ("alert_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id")
);

CREATE TABLE IF NOT EXISTS "alert_embeddings" (
  "alert_id" TEXT NOT NULL,
  "model" TEXT NOT NULL,
  "dim" INTEGER NOT NULL,
  "vector" BLOB NOT NULL,
  "text_hash" TEXT NOT NULL,
  PRIMARY KEY ("alert_id", "model"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id")
);

-- L2 correlation links. Filled from duplicate groups and authorised changes by src.database.enrich.
CREATE TABLE IF NOT EXISTS "alert_incidents" (
  "alert_id" TEXT NOT NULL,
  "incident_id" TEXT NOT NULL,
  "link_reason" TEXT NOT NULL,
  "link_score" REAL,
  "is_duplicate" INTEGER NOT NULL DEFAULT 0,
  "is_authorised" INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY ("alert_id", "incident_id")
);

CREATE INDEX IF NOT EXISTS "idx_alert_log_selection_event" ON "alert_log_selection" ("event_id");
CREATE INDEX IF NOT EXISTS "idx_triage_tickets_severity" ON "triage_tickets" ("severity", "created_at");

-- Policy automation (src.triage_flow.automation): SLA clock, deterministic policy changes, simulated
-- notification outbox and containment actions sent to the SOC API.
CREATE TABLE IF NOT EXISTS "alert_received" (
  "alert_id" TEXT PRIMARY KEY,
  "received_at" TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "ticket_automation" (
  "alert_id" TEXT PRIMARY KEY,
  "base_severity" TEXT,
  "severity_before" TEXT,
  "severity" TEXT,
  "sla_minutes" INTEGER,
  "sla_label" TEXT,
  "received_at" TEXT,
  "sla_due_at" TEXT,
  "escalation_path" TEXT,
  "escalation_to" TEXT,
  "reasons_json" TEXT,
  "changes_json" TEXT,
  "created_at" TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "soc_notifications" (
  "id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "alert_id" TEXT NOT NULL,
  "recipient" TEXT NOT NULL,
  "channel" TEXT,
  "reason" TEXT,
  "status" TEXT NOT NULL,
  "created_at" TEXT NOT NULL,
  UNIQUE ("alert_id", "recipient")
);

CREATE TABLE IF NOT EXISTS "soc_actions" (
  "id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "alert_id" TEXT NOT NULL,
  "action" TEXT NOT NULL,
  "target" TEXT,
  "mode" TEXT NOT NULL CHECK (mode IN ('auto', 'approved')),
  "status" TEXT NOT NULL,
  "reason" TEXT,
  "detail" TEXT,
  "approval_token" TEXT,
  "created_at" TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS "idx_soc_actions_alert" ON "soc_actions" ("alert_id");
CREATE INDEX IF NOT EXISTS "idx_ticket_automation_due" ON "ticket_automation" ("sla_due_at");

-- Demo scenario (src.database.scenario): alerts already handled before a new batch arrives. They keep their
-- real ticket (no invented verdict or decision) but no longer appear as pending in the queue or the batch runner.
CREATE TABLE IF NOT EXISTS "backlog_closed" (
  "alert_id" TEXT PRIMARY KEY,
  "closed_at" TEXT NOT NULL,
  "reason" TEXT
);
