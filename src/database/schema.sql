-- New Tarvia schema. Source: implementation_docs/trazabilidad_bd.md

PRAGMA foreign_keys = ON;

CREATE TABLE "users" (
  "user_id" TEXT NOT NULL,
  "username" TEXT NOT NULL COLLATE NOCASE UNIQUE,
  "upn" TEXT NOT NULL COLLATE NOCASE UNIQUE,
  "display_name" TEXT,
  "department" TEXT,
  "title" TEXT,
  "location" TEXT,
  "manager_user_id" TEXT,
  "account_type" TEXT,
  "privileged" INTEGER CHECK ("privileged" IN (0, 1)),
  "vip" INTEGER CHECK ("vip" IN (0, 1)),
  "mfa_method" TEXT,
  "status" TEXT,
  "created" TEXT,
  "workstation_asset_id" TEXT,
  "notes" TEXT,
  PRIMARY KEY ("user_id"),
  FOREIGN KEY ("manager_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("workstation_asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "assets" (
  "asset_id" TEXT NOT NULL,
  "hostname" TEXT UNIQUE,
  "ip" TEXT,
  "type" TEXT,
  "os" TEXT,
  "criticality" TEXT,
  "zone_id" TEXT,
  "store_id" TEXT,
  "location" TEXT,
  "business_service" TEXT,
  "owner_user_id" TEXT,
  "internet_facing" INTEGER CHECK ("internet_facing" IN (0, 1)),
  "edr_installed" INTEGER CHECK ("edr_installed" IN (0, 1)),
  "description" TEXT,
  PRIMARY KEY ("asset_id"),
  FOREIGN KEY ("owner_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("zone_id") REFERENCES "network_zones" ("zone_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("store_id") REFERENCES "stores" ("store_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "hr_events" (
  "hr_event_id" INTEGER NOT NULL,
  "user_id" TEXT,
  "recorded_date" TEXT,
  "event_type" TEXT,
  "details" TEXT,
  "effective_date" TEXT,
  PRIMARY KEY ("hr_event_id"),
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "network_zones" (
  "zone_id" TEXT NOT NULL,
  "cidr" TEXT,
  "location" TEXT,
  "description" TEXT,
  PRIMARY KEY ("zone_id")
);

CREATE TABLE "business_services" (
  "service_id" INTEGER NOT NULL,
  "name" TEXT,
  "criticality" TEXT,
  "impact" TEXT,
  "owner_role" TEXT,
  "asset_references" TEXT,
  PRIMARY KEY ("service_id")
);

CREATE TABLE "asset_services" (
  "asset_id" TEXT NOT NULL,
  "service_id" INTEGER NOT NULL,
  PRIMARY KEY ("asset_id", "service_id"),
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("service_id") REFERENCES "business_services" ("service_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "vulnerabilities" (
  "vulnerability_id" INTEGER NOT NULL,
  "asset_id" TEXT,
  "reference" TEXT,
  "product" TEXT,
  "cvss" TEXT,
  "status" TEXT,
  "detected_date" TEXT,
  "notes" TEXT,
  PRIMARY KEY ("vulnerability_id"),
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "stores" (
  "store_id" TEXT NOT NULL,
  "name" TEXT,
  "city" TEXT,
  "cidr" TEXT,
  PRIMARY KEY ("store_id")
);

CREATE TABLE "changes" (
  "change_id" TEXT NOT NULL,
  "title" TEXT,
  "start_at" TEXT,
  "end_at" TEXT,
  "requester" TEXT,
  "details" TEXT,
  "scope" TEXT,
  PRIMARY KEY ("change_id")
);

CREATE TABLE "threat_intelligence" (
  "intelligence_id" INTEGER NOT NULL,
  "indicator_type" TEXT,
  "value" TEXT,
  "reputation" TEXT,
  "confidence" INTEGER CHECK ("confidence" BETWEEN 0 AND 100),
  "malware_family" TEXT,
  "first_seen" TEXT,
  "last_seen" TEXT,
  "source" TEXT,
  "note" TEXT,
  PRIMARY KEY ("intelligence_id")
);

CREATE TABLE "threat_intelligence_tags" (
  "intelligence_id" INTEGER NOT NULL,
  "tag" TEXT NOT NULL,
  PRIMARY KEY ("intelligence_id", "tag"),
  FOREIGN KEY ("intelligence_id") REFERENCES "threat_intelligence" ("intelligence_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "geoip" (
  "ip" TEXT NOT NULL,
  "country" TEXT,
  "city" TEXT,
  "asn" TEXT,
  "as_org" TEXT,
  "is_tor" INTEGER CHECK ("is_tor" IN (0, 1)),
  "is_vpn_provider" INTEGER CHECK ("is_vpn_provider" IN (0, 1)),
  "is_hosting" INTEGER CHECK ("is_hosting" IN (0, 1)),
  "is_residential_proxy" INTEGER CHECK ("is_residential_proxy" IN (0, 1)),
  PRIMARY KEY ("ip")
);

CREATE TABLE "sandbox_reports" (
  "report_id" INTEGER NOT NULL,
  "sha256" TEXT,
  "md5" TEXT,
  "file_name" TEXT,
  "verdict" TEXT,
  "score" INTEGER CHECK ("score" BETWEEN 0 AND 100),
  "malware_family" TEXT,
  "analysis_env" TEXT,
  "analyzed_at" TEXT,
  "note" TEXT,
  PRIMARY KEY ("report_id")
);

CREATE TABLE "sandbox_behaviors" (
  "report_id" INTEGER NOT NULL,
  "description" TEXT NOT NULL,
  PRIMARY KEY ("report_id", "description"),
  FOREIGN KEY ("report_id") REFERENCES "sandbox_reports" ("report_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "sandbox_network_indicators" (
  "report_id" INTEGER NOT NULL,
  "indicator_type" TEXT NOT NULL,
  "value" TEXT NOT NULL,
  PRIMARY KEY ("report_id", "indicator_type", "value"),
  FOREIGN KEY ("report_id") REFERENCES "sandbox_reports" ("report_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "sandbox_mitre" (
  "report_id" INTEGER NOT NULL,
  "technique_id" TEXT NOT NULL,
  PRIMARY KEY ("report_id", "technique_id"),
  FOREIGN KEY ("report_id") REFERENCES "sandbox_reports" ("report_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "sandbox_dropped_files" (
  "report_id" INTEGER NOT NULL,
  "file_name" TEXT NOT NULL,
  "sha256" TEXT NOT NULL,
  PRIMARY KEY ("report_id", "file_name", "sha256"),
  FOREIGN KEY ("report_id") REFERENCES "sandbox_reports" ("report_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "detection_rules" (
  "rule_id" TEXT NOT NULL,
  "name" TEXT,
  "source_product" TEXT,
  "base_severity" TEXT,
  "tactic" TEXT,
  "technique_id" TEXT,
  "technique_name" TEXT,
  "runbook_id" TEXT,
  "detection_logic" TEXT,
  PRIMARY KEY ("rule_id"),
  FOREIGN KEY ("runbook_id") REFERENCES "runbooks" ("runbook_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "runbooks" (
  "runbook_id" TEXT NOT NULL,
  "title" TEXT,
  "checks_text" TEXT,
  "decision_guidance_text" TEXT,
  PRIMARY KEY ("runbook_id")
);

CREATE TABLE "change_assets" (
  "change_id" TEXT NOT NULL,
  "asset_id" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  PRIMARY KEY ("change_id", "asset_id", "role"),
  FOREIGN KEY ("change_id") REFERENCES "changes" ("change_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK (role IN ('target', 'source', 'access_path'))
);

CREATE TABLE "change_users" (
  "change_id" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  PRIMARY KEY ("change_id", "user_id"),
  FOREIGN KEY ("change_id") REFERENCES "changes" ("change_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alerts" (
  "alert_id" TEXT NOT NULL,
  "created_at" TEXT,
  "rule_id" TEXT NOT NULL,
  "severity" TEXT,
  "status" TEXT,
  "description" TEXT,
  "evidence_json" TEXT CHECK ("evidence_json" IS NULL OR json_valid("evidence_json")),
  "reported_user_count" INTEGER,
  PRIMARY KEY ("alert_id"),
  FOREIGN KEY ("rule_id") REFERENCES "detection_rules" ("rule_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_users" (
  "alert_id" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  PRIMARY KEY ("alert_id", "user_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_assets" (
  "alert_id" TEXT NOT NULL,
  "asset_id" TEXT NOT NULL,
  PRIMARY KEY ("alert_id", "asset_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_indicators" (
  "alert_id" TEXT NOT NULL,
  "indicator_type" TEXT NOT NULL,
  "value" TEXT NOT NULL,
  PRIMARY KEY ("alert_id", "indicator_type", "value"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_files" (
  "alert_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "file_name" TEXT,
  "sha256" TEXT,
  "path" TEXT,
  PRIMARY KEY ("alert_id", "position"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_processes" (
  "alert_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "name" TEXT,
  "parent_name" TEXT,
  "command_line" TEXT,
  "pid" INTEGER,
  PRIMARY KEY ("alert_id", "position"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_customers" (
  "alert_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "customer_id" TEXT,
  "role" TEXT,
  PRIMARY KEY ("alert_id", "position"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_cloud" (
  "alert_id" TEXT NOT NULL,
  "cloud_account" TEXT,
  "identity" TEXT,
  "bucket" TEXT,
  "access_key" TEXT,
  "new_user" TEXT,
  PRIMARY KEY ("alert_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_ai_sessions" (
  "alert_id" TEXT NOT NULL,
  "session_id" TEXT,
  PRIMARY KEY ("alert_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_events" (
  "alert_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "event_id" TEXT,
  PRIMARY KEY ("alert_id", "position"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id")
);

CREATE TABLE "logs" (
  "event_id" TEXT NOT NULL,
  "timestamp" TEXT NOT NULL,
  "source" TEXT NOT NULL,
  PRIMARY KEY ("event_id"),
  CHECK (source IN ('ad_events', 'ai_gateway', 'cicd_builds', 'cloudtrail', 'dlp', 'dns', 'ecom_account', 'ecom_auth', 'edr_events', 'email', 'email_clicks', 'firewall', 'idp_audit', 'idp_signins', 'proxy', 'sql_audit', 'vpn', 'waf'))
);

CREATE TABLE "vpn_logs" (
  "event_id" TEXT NOT NULL,
  "user_id" TEXT,
  "src_ip" TEXT,
  "assigned_ip" TEXT,
  "action" TEXT,
  "country" TEXT,
  "bytes" INTEGER,
  "mfa_result" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "idp_signins_logs" (
  "event_id" TEXT NOT NULL,
  "user_id" TEXT,
  "app" TEXT,
  "result" TEXT,
  "failure_reason" TEXT,
  "mfa_method" TEXT,
  "mfa_result" TEXT,
  "src_ip" TEXT,
  "country" TEXT,
  "city" TEXT,
  "asn" TEXT,
  "user_agent" TEXT,
  "device_id" TEXT,
  "device_compliant" INTEGER CHECK ("device_compliant" IN (0, 1)),
  "session_id" TEXT,
  "risk_level" TEXT,
  "conditional_access" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "idp_audit_logs" (
  "event_id" TEXT NOT NULL,
  "actor_user_id" TEXT,
  "operation" TEXT,
  "target_user_id" TEXT,
  "target_resource" TEXT,
  "src_ip" TEXT,
  "details_json" TEXT CHECK ("details_json" IS NULL OR json_valid("details_json")),
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("actor_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("target_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK ("target_user_id" IS NULL OR "target_resource" IS NULL)
);

CREATE TABLE "ad_events_logs" (
  "event_id" TEXT NOT NULL,
  "dc_asset_id" TEXT,
  "event_code" INTEGER,
  "event_description" TEXT,
  "subject_user_id" TEXT,
  "subject_unresolved" TEXT,
  "target_user_id" TEXT,
  "target_unresolved" TEXT,
  "source_asset_id" TEXT,
  "details_json" TEXT CHECK ("details_json" IS NULL OR json_valid("details_json")),
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("dc_asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("subject_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("target_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("source_asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK ("subject_user_id" IS NULL OR "subject_unresolved" IS NULL),
  CHECK ("target_user_id" IS NULL OR "target_unresolved" IS NULL)
);

CREATE TABLE "edr_logs" (
  "event_id" TEXT NOT NULL,
  "event_type" TEXT,
  "asset_id" TEXT,
  "user_id" TEXT,
  "unresolved_user" TEXT,
  "process_name" TEXT,
  "process_path" TEXT,
  "command_line" TEXT,
  "parent_name" TEXT,
  "pid" INTEGER,
  "parent_pid" INTEGER,
  "sha256" TEXT,
  "signer" TEXT,
  "integrity" TEXT,
  "details_json" TEXT CHECK ("details_json" IS NULL OR json_valid("details_json")),
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK ("user_id" IS NULL OR "unresolved_user" IS NULL)
);

CREATE TABLE "proxy_logs" (
  "event_id" TEXT NOT NULL,
  "src_ip" TEXT,
  "asset_id" TEXT,
  "user_id" TEXT,
  "unresolved_user" TEXT,
  "method" TEXT,
  "url" TEXT,
  "domain" TEXT,
  "dst_ip" TEXT,
  "http_status" INTEGER,
  "bytes_out" INTEGER,
  "bytes_in" INTEGER,
  "category" TEXT,
  "action" TEXT,
  "user_agent" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK ("user_id" IS NULL OR "unresolved_user" IS NULL)
);

CREATE TABLE "dns_logs" (
  "event_id" TEXT NOT NULL,
  "src_ip" TEXT,
  "asset_id" TEXT,
  "query" TEXT,
  "qtype" TEXT,
  "response" TEXT,
  "rcode" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "firewall_logs" (
  "event_id" TEXT NOT NULL,
  "src_ip" TEXT,
  "src_port" INTEGER,
  "dst_ip" TEXT,
  "dst_port" INTEGER,
  "proto" TEXT,
  "action" TEXT,
  "firewall_rule" TEXT,
  "bytes" INTEGER,
  "src_zone_id" TEXT,
  "dst_zone_id" TEXT,
  "dst_zone_unresolved" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("src_zone_id") REFERENCES "network_zones" ("zone_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("dst_zone_id") REFERENCES "network_zones" ("zone_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK ("dst_zone_id" IS NULL OR "dst_zone_unresolved" IS NULL)
);

CREATE TABLE "email_logs" (
  "event_id" TEXT NOT NULL,
  "direction" TEXT,
  "message_id" TEXT UNIQUE,
  "sender_user_id" TEXT,
  "sender_unresolved" TEXT,
  "subject" TEXT,
  "verdict" TEXT,
  "action" TEXT,
  "spf" TEXT,
  "dkim" TEXT,
  "dmarc" TEXT,
  "sender_ip" TEXT,
  "body_excerpt" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("sender_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK ("sender_user_id" IS NULL OR "sender_unresolved" IS NULL)
);

CREATE TABLE "email_recipients" (
  "event_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "recipient_user_id" TEXT,
  "recipient_unresolved" TEXT,
  PRIMARY KEY ("event_id", "position"),
  FOREIGN KEY ("event_id") REFERENCES "email_logs" ("event_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("recipient_user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK ("recipient_user_id" IS NULL OR "recipient_unresolved" IS NULL)
);

CREATE TABLE "email_attachments" (
  "event_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "file_name" TEXT,
  "sha256" TEXT,
  "size" INTEGER,
  PRIMARY KEY ("event_id", "position"),
  FOREIGN KEY ("event_id") REFERENCES "email_logs" ("event_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "email_attachment_contents" (
  "event_id" TEXT NOT NULL,
  "attachment_position" INTEGER NOT NULL,
  "position" INTEGER NOT NULL,
  "file_name" TEXT,
  "sha256" TEXT,
  PRIMARY KEY ("event_id", "attachment_position", "position"),
  FOREIGN KEY ("event_id", "attachment_position") REFERENCES "email_attachments" ("event_id", "position") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "email_urls" (
  "event_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "url" TEXT,
  PRIMARY KEY ("event_id", "position"),
  FOREIGN KEY ("event_id") REFERENCES "email_logs" ("event_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "email_clicks_logs" (
  "event_id" TEXT NOT NULL,
  "user_id" TEXT,
  "url" TEXT,
  "email_event_id" TEXT,
  "action" TEXT,
  "verdict_at_click" TEXT,
  "src_ip" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("email_event_id") REFERENCES "email_logs" ("event_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "dlp_logs" (
  "event_id" TEXT NOT NULL,
  "user_id" TEXT,
  "asset_id" TEXT,
  "channel" TEXT,
  "destination" TEXT,
  "file_name" TEXT,
  "file_size" INTEGER,
  "policy" TEXT,
  "matches_json" TEXT CHECK ("matches_json" IS NULL OR json_valid("matches_json")),
  "action" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "sql_audit_logs" (
  "event_id" TEXT NOT NULL,
  "user_id" TEXT,
  "client_asset_id" TEXT,
  "database" TEXT,
  "statement_type" TEXT,
  "object" TEXT,
  "rows_returned" INTEGER,
  "statement" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("user_id") REFERENCES "users" ("user_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("client_asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "waf_logs" (
  "event_id" TEXT NOT NULL,
  "src_ip" TEXT,
  "country" TEXT,
  "method" TEXT,
  "host" TEXT,
  "uri" TEXT,
  "http_status" INTEGER,
  "waf_rule_id" TEXT,
  "waf_rule_message" TEXT,
  "action" TEXT,
  "user_agent" TEXT,
  "bytes" INTEGER,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id")
);

CREATE TABLE "ecom_auth_logs" (
  "event_id" TEXT NOT NULL,
  "customer_id" TEXT,
  "email" TEXT,
  "src_ip" TEXT,
  "result" TEXT,
  "failure_reason" TEXT,
  "user_agent" TEXT,
  "device_fp" TEXT,
  "captcha" TEXT,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id")
);

CREATE TABLE "ecom_account_logs" (
  "event_id" TEXT NOT NULL,
  "customer_id" TEXT,
  "event_type" TEXT,
  "details_json" TEXT CHECK ("details_json" IS NULL OR json_valid("details_json")),
  "src_ip" TEXT,
  "amount" REAL,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id")
);

CREATE TABLE "ai_gateway_logs" (
  "event_id" TEXT NOT NULL,
  "session_id" TEXT,
  "customer_id" TEXT,
  "authenticated" INTEGER CHECK ("authenticated" IN (0, 1)),
  "src_ip" TEXT,
  "prompt" TEXT,
  "response_summary" TEXT,
  "guardrail_triggered" INTEGER CHECK ("guardrail_triggered" IN (0, 1)),
  "guardrail_category" TEXT,
  "guardrail_action" TEXT,
  "model" TEXT,
  "tokens_in" INTEGER,
  "tokens_out" INTEGER,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id")
);

CREATE TABLE "ai_tool_calls" (
  "event_id" TEXT NOT NULL,
  "position" INTEGER NOT NULL,
  "name" TEXT,
  "arguments_json" TEXT CHECK ("arguments_json" IS NULL OR json_valid("arguments_json")),
  "result" TEXT,
  PRIMARY KEY ("event_id", "position"),
  FOREIGN KEY ("event_id") REFERENCES "ai_gateway_logs" ("event_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "cloudtrail_logs" (
  "event_id" TEXT NOT NULL,
  "event_name" TEXT,
  "event_source" TEXT,
  "aws_region" TEXT,
  "src_ip" TEXT,
  "user_agent" TEXT,
  "identity_type" TEXT,
  "identity_name" TEXT,
  "access_key_id" TEXT,
  "request_parameters_json" TEXT CHECK ("request_parameters_json" IS NULL OR json_valid("request_parameters_json")),
  "error_code" TEXT,
  "bytes_transferred" INTEGER,
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id")
);

CREATE TABLE "cicd_builds_logs" (
  "event_id" TEXT NOT NULL,
  "pipeline" TEXT,
  "build_id" TEXT,
  "runner_asset_id" TEXT,
  "step" TEXT,
  "status" TEXT,
  "details_json" TEXT CHECK ("details_json" IS NULL OR json_valid("details_json")),
  PRIMARY KEY ("event_id"),
  FOREIGN KEY ("event_id") REFERENCES "logs" ("event_id"),
  FOREIGN KEY ("runner_asset_id") REFERENCES "assets" ("asset_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "alert_history" (
  "alert_id" TEXT NOT NULL,
  "verdict" TEXT NOT NULL,
  PRIMARY KEY ("alert_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK (verdict IN ('true_positive', 'false_positive', 'benign_true_positive'))
);

CREATE TABLE "triage_runs" (
  "run_id" INTEGER NOT NULL,
  "alert_id" TEXT NOT NULL,
  "stage" TEXT NOT NULL CHECK ("stage" IN ('auto_check', 'llm')),
  "model" TEXT,
  "status" TEXT NOT NULL CHECK ("status" IN ('running', 'done', 'error')),
  "started_at" TEXT NOT NULL,
  "finished_at" TEXT,
  "valid" INTEGER CHECK ("valid" IN (0, 1)),
  "errors_json" TEXT CHECK ("errors_json" IS NULL OR json_valid("errors_json")),
  "usage_json" TEXT CHECK ("usage_json" IS NULL OR json_valid("usage_json")),
  "elapsed_s" REAL,
  "transcript_json" TEXT CHECK ("transcript_json" IS NULL OR json_valid("transcript_json")),
  PRIMARY KEY ("run_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "triage_checks" (
  "run_id" INTEGER NOT NULL,
  "discard" INTEGER NOT NULL CHECK ("discard" IN (0, 1)),
  "verdict" TEXT CHECK ("verdict" IN ('benign_true_positive', 'false_positive')),
  "severity" TEXT CHECK ("severity" IN ('informational', 'low', 'medium', 'high', 'critical')),
  "reasons_json" TEXT CHECK ("reasons_json" IS NULL OR json_valid("reasons_json")),
  "references_json" TEXT CHECK ("references_json" IS NULL OR json_valid("references_json")),
  "guards_json" TEXT CHECK ("guards_json" IS NULL OR json_valid("guards_json")),
  PRIMARY KEY ("run_id"),
  FOREIGN KEY ("run_id") REFERENCES "triage_runs" ("run_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "triage_tickets" (
  "run_id" INTEGER NOT NULL,
  "alert_id" TEXT NOT NULL,
  "ticket_id" TEXT,
  "ticket_json" TEXT NOT NULL CHECK ("ticket_json" IS NULL OR json_valid("ticket_json")),
  "verdict" TEXT NOT NULL CHECK ("verdict" IN ('true_positive', 'false_positive', 'benign_true_positive', 'needs_more_info')),
  "severity" TEXT NOT NULL CHECK ("severity" IN ('informational', 'low', 'medium', 'high', 'critical')),
  "ticket_confidence" REAL CHECK ("ticket_confidence" BETWEEN 0 AND 1),
  "valid" INTEGER CHECK ("valid" IN (0, 1)),
  "created_at" TEXT,
  PRIMARY KEY ("run_id"),
  FOREIGN KEY ("run_id") REFERENCES "triage_runs" ("run_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "triage_context_requests" (
  "run_id" INTEGER NOT NULL,
  "n" INTEGER NOT NULL,
  "motivo" TEXT,
  "comprobacion" TEXT,
  "consultas_json" TEXT CHECK ("consultas_json" IS NULL OR json_valid("consultas_json")),
  "rows_json" TEXT CHECK ("rows_json" IS NULL OR json_valid("rows_json")),
  "is_error" INTEGER CHECK ("is_error" IN (0, 1)),
  PRIMARY KEY ("run_id", "n"),
  FOREIGN KEY ("run_id") REFERENCES "triage_runs" ("run_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE "analyst_decisions" (
  "decision_id" INTEGER NOT NULL,
  "alert_id" TEXT NOT NULL,
  "run_id" INTEGER,
  "item" TEXT NOT NULL,
  "decision" TEXT NOT NULL CHECK ("decision" IN ('accepted', 'rejected')),
  "override_verdict" TEXT CHECK ("override_verdict" IN ('true_positive', 'false_positive', 'benign_true_positive')),
  "analyst" TEXT NOT NULL,
  "comment" TEXT,
  "decided_at" TEXT NOT NULL,
  PRIMARY KEY ("decision_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("run_id") REFERENCES "triage_tickets" ("run_id") DEFERRABLE INITIALLY DEFERRED,
  CHECK (item = 'verdict' OR (item GLOB 'action:[0-9]*' AND run_id IS NOT NULL))
);

CREATE TABLE "executed_actions" (
  "execution_id" INTEGER NOT NULL,
  "alert_id" TEXT NOT NULL,
  "run_id" INTEGER,
  "action_index" INTEGER,
  "action" TEXT NOT NULL,
  "target" TEXT NOT NULL,
  "approval_token" TEXT,
  "status" TEXT NOT NULL CHECK ("status" IN ('ok', 'refused', 'error')),
  "api_result_json" TEXT CHECK ("api_result_json" IS NULL OR json_valid("api_result_json")),
  "executed_at" TEXT NOT NULL,
  PRIMARY KEY ("execution_id"),
  FOREIGN KEY ("alert_id") REFERENCES "alerts" ("alert_id") DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY ("run_id") REFERENCES "triage_tickets" ("run_id") DEFERRABLE INITIALLY DEFERRED
);

CREATE TRIGGER "ad_events_logs_source_insert" BEFORE INSERT ON "ad_events_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ad_events'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ad_events_logs'); END;

CREATE TRIGGER "ad_events_logs_source_update" BEFORE UPDATE OF event_id ON "ad_events_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ad_events'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ad_events_logs'); END;

CREATE TRIGGER "ai_gateway_logs_source_insert" BEFORE INSERT ON "ai_gateway_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ai_gateway'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ai_gateway_logs'); END;

CREATE TRIGGER "ai_gateway_logs_source_update" BEFORE UPDATE OF event_id ON "ai_gateway_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ai_gateway'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ai_gateway_logs'); END;

CREATE TRIGGER "cicd_builds_logs_source_insert" BEFORE INSERT ON "cicd_builds_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'cicd_builds'
BEGIN SELECT RAISE(ABORT, 'Wrong source for cicd_builds_logs'); END;

CREATE TRIGGER "cicd_builds_logs_source_update" BEFORE UPDATE OF event_id ON "cicd_builds_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'cicd_builds'
BEGIN SELECT RAISE(ABORT, 'Wrong source for cicd_builds_logs'); END;

CREATE TRIGGER "cloudtrail_logs_source_insert" BEFORE INSERT ON "cloudtrail_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'cloudtrail'
BEGIN SELECT RAISE(ABORT, 'Wrong source for cloudtrail_logs'); END;

CREATE TRIGGER "cloudtrail_logs_source_update" BEFORE UPDATE OF event_id ON "cloudtrail_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'cloudtrail'
BEGIN SELECT RAISE(ABORT, 'Wrong source for cloudtrail_logs'); END;

CREATE TRIGGER "dlp_logs_source_insert" BEFORE INSERT ON "dlp_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'dlp'
BEGIN SELECT RAISE(ABORT, 'Wrong source for dlp_logs'); END;

CREATE TRIGGER "dlp_logs_source_update" BEFORE UPDATE OF event_id ON "dlp_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'dlp'
BEGIN SELECT RAISE(ABORT, 'Wrong source for dlp_logs'); END;

CREATE TRIGGER "dns_logs_source_insert" BEFORE INSERT ON "dns_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'dns'
BEGIN SELECT RAISE(ABORT, 'Wrong source for dns_logs'); END;

CREATE TRIGGER "dns_logs_source_update" BEFORE UPDATE OF event_id ON "dns_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'dns'
BEGIN SELECT RAISE(ABORT, 'Wrong source for dns_logs'); END;

CREATE TRIGGER "ecom_account_logs_source_insert" BEFORE INSERT ON "ecom_account_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ecom_account'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ecom_account_logs'); END;

CREATE TRIGGER "ecom_account_logs_source_update" BEFORE UPDATE OF event_id ON "ecom_account_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ecom_account'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ecom_account_logs'); END;

CREATE TRIGGER "ecom_auth_logs_source_insert" BEFORE INSERT ON "ecom_auth_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ecom_auth'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ecom_auth_logs'); END;

CREATE TRIGGER "ecom_auth_logs_source_update" BEFORE UPDATE OF event_id ON "ecom_auth_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'ecom_auth'
BEGIN SELECT RAISE(ABORT, 'Wrong source for ecom_auth_logs'); END;

CREATE TRIGGER "edr_logs_source_insert" BEFORE INSERT ON "edr_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'edr_events'
BEGIN SELECT RAISE(ABORT, 'Wrong source for edr_logs'); END;

CREATE TRIGGER "edr_logs_source_update" BEFORE UPDATE OF event_id ON "edr_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'edr_events'
BEGIN SELECT RAISE(ABORT, 'Wrong source for edr_logs'); END;

CREATE TRIGGER "email_logs_source_insert" BEFORE INSERT ON "email_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'email'
BEGIN SELECT RAISE(ABORT, 'Wrong source for email_logs'); END;

CREATE TRIGGER "email_logs_source_update" BEFORE UPDATE OF event_id ON "email_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'email'
BEGIN SELECT RAISE(ABORT, 'Wrong source for email_logs'); END;

CREATE TRIGGER "email_clicks_logs_source_insert" BEFORE INSERT ON "email_clicks_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'email_clicks'
BEGIN SELECT RAISE(ABORT, 'Wrong source for email_clicks_logs'); END;

CREATE TRIGGER "email_clicks_logs_source_update" BEFORE UPDATE OF event_id ON "email_clicks_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'email_clicks'
BEGIN SELECT RAISE(ABORT, 'Wrong source for email_clicks_logs'); END;

CREATE TRIGGER "firewall_logs_source_insert" BEFORE INSERT ON "firewall_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'firewall'
BEGIN SELECT RAISE(ABORT, 'Wrong source for firewall_logs'); END;

CREATE TRIGGER "firewall_logs_source_update" BEFORE UPDATE OF event_id ON "firewall_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'firewall'
BEGIN SELECT RAISE(ABORT, 'Wrong source for firewall_logs'); END;

CREATE TRIGGER "idp_audit_logs_source_insert" BEFORE INSERT ON "idp_audit_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'idp_audit'
BEGIN SELECT RAISE(ABORT, 'Wrong source for idp_audit_logs'); END;

CREATE TRIGGER "idp_audit_logs_source_update" BEFORE UPDATE OF event_id ON "idp_audit_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'idp_audit'
BEGIN SELECT RAISE(ABORT, 'Wrong source for idp_audit_logs'); END;

CREATE TRIGGER "idp_signins_logs_source_insert" BEFORE INSERT ON "idp_signins_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'idp_signins'
BEGIN SELECT RAISE(ABORT, 'Wrong source for idp_signins_logs'); END;

CREATE TRIGGER "idp_signins_logs_source_update" BEFORE UPDATE OF event_id ON "idp_signins_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'idp_signins'
BEGIN SELECT RAISE(ABORT, 'Wrong source for idp_signins_logs'); END;

CREATE TRIGGER "proxy_logs_source_insert" BEFORE INSERT ON "proxy_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'proxy'
BEGIN SELECT RAISE(ABORT, 'Wrong source for proxy_logs'); END;

CREATE TRIGGER "proxy_logs_source_update" BEFORE UPDATE OF event_id ON "proxy_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'proxy'
BEGIN SELECT RAISE(ABORT, 'Wrong source for proxy_logs'); END;

CREATE TRIGGER "sql_audit_logs_source_insert" BEFORE INSERT ON "sql_audit_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'sql_audit'
BEGIN SELECT RAISE(ABORT, 'Wrong source for sql_audit_logs'); END;

CREATE TRIGGER "sql_audit_logs_source_update" BEFORE UPDATE OF event_id ON "sql_audit_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'sql_audit'
BEGIN SELECT RAISE(ABORT, 'Wrong source for sql_audit_logs'); END;

CREATE TRIGGER "vpn_logs_source_insert" BEFORE INSERT ON "vpn_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'vpn'
BEGIN SELECT RAISE(ABORT, 'Wrong source for vpn_logs'); END;

CREATE TRIGGER "vpn_logs_source_update" BEFORE UPDATE OF event_id ON "vpn_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'vpn'
BEGIN SELECT RAISE(ABORT, 'Wrong source for vpn_logs'); END;

CREATE TRIGGER "waf_logs_source_insert" BEFORE INSERT ON "waf_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'waf'
BEGIN SELECT RAISE(ABORT, 'Wrong source for waf_logs'); END;

CREATE TRIGGER "waf_logs_source_update" BEFORE UPDATE OF event_id ON "waf_logs"
WHEN (SELECT source FROM logs WHERE event_id = NEW.event_id) <> 'waf'
BEGIN SELECT RAISE(ABORT, 'Wrong source for waf_logs'); END;

CREATE TRIGGER logs_source_immutable BEFORE UPDATE OF source ON logs WHEN NEW.source <> OLD.source BEGIN SELECT RAISE(ABORT, 'Event source is immutable'); END;
