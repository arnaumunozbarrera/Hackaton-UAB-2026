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
