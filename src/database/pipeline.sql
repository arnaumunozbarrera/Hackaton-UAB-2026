-- Triage pipeline tables. Applied idempotently by src.database.enrich after the base schema.
-- Lookups are derived; tickets and severity assessments retain decision/audit history.

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

-- Append a new assessment for every valid triage; never replace previous justifications.
CREATE TABLE IF NOT EXISTS "severity_assessments" (
  "assessment_id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "alert_id" TEXT NOT NULL REFERENCES "alerts" ("alert_id"),
  "rule_severity" TEXT NOT NULL CHECK ("rule_severity" IN ('informational','low','medium','high','critical')),
  "criticality" TEXT NOT NULL CHECK ("criticality" IN ('Baja','Media','Alta','Crítica')),
  "base_severity" TEXT NOT NULL CHECK ("base_severity" IN ('informational','low','medium','high','critical')),
  "adjustment" INTEGER CHECK ("adjustment" IN (-1,0,1)),
  "final_severity" TEXT NOT NULL CHECK ("final_severity" IN ('informational','low','medium','high','critical')),
  "verdict" TEXT CHECK ("verdict" IN ('true_positive','benign_true_positive','false_positive','needs_more_info')),
  "method" TEXT NOT NULL CHECK ("method" IN ('matrix','adjustment','authorised_activity','discriminator')),
  "rationale" TEXT NOT NULL CHECK (length(trim("rationale")) > 0),
  "rules_version" TEXT NOT NULL,
  "policy_hash" TEXT NOT NULL,
  "input_snapshot_json" TEXT NOT NULL CHECK (json_valid("input_snapshot_json")),
  "observation_start" TEXT,
  "observation_end" TEXT,
  "assessed_at" TEXT NOT NULL,
  CHECK ("method" <> 'matrix' OR ("adjustment" IS NOT NULL AND "adjustment" = 0 AND "final_severity" = "base_severity"))
);

CREATE TABLE IF NOT EXISTS "severity_evidence" (
  "evidence_id" INTEGER PRIMARY KEY AUTOINCREMENT,
  "assessment_id" INTEGER NOT NULL REFERENCES "severity_assessments" ("assessment_id"),
  "condition" TEXT NOT NULL,
  "status" TEXT NOT NULL CHECK ("status" IN ('confirmed','refuted','unknown','not_evaluated')),
  "source" TEXT NOT NULL,
  "source_key" TEXT,
  "event_id" TEXT REFERENCES "logs" ("event_id"),
  "change_id" TEXT REFERENCES "changes" ("change_id"),
  "asset_id" TEXT REFERENCES "assets" ("asset_id"),
  "service_id" INTEGER REFERENCES "business_services" ("service_id"),
  "reference" TEXT NOT NULL,
  "finding" TEXT NOT NULL CHECK (length(trim("finding")) > 0),
  "details_json" TEXT NOT NULL CHECK (json_valid("details_json"))
);

CREATE INDEX IF NOT EXISTS "idx_severity_assessments_alert" ON "severity_assessments" ("alert_id", "assessment_id");
CREATE INDEX IF NOT EXISTS "idx_severity_evidence_assessment" ON "severity_evidence" ("assessment_id");
