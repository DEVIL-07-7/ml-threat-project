import { relations } from "drizzle-orm";
import { integer, pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";

// 1. Multi-Role SOC Users Table (Linked to Firebase Auth UID)
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  uid: text("uid").notNull().unique(),
  email: text("email").notNull(),
  fullName: text("full_name").notNull().default("Lead SOC Analyst"),
  role: text("role").notNull().default("SOC Lead"), // "Tier-1 Analyst" | "Tier-3 Threat Hunter" | "SOC Lead"
  createdAt: timestamp("created_at").defaultNow(),
});

// 2. Persistent IOC Store & Triage Dispositions
export const iocRecordsTable = pgTable("ioc_records", {
  id: serial("id").primaryKey(),
  iocValue: text("ioc_value").notNull().unique(),
  iocType: text("ioc_type").notNull().default("url"),
  threatType: text("threat_type").notNull().default("malware_download"),
  tagsJson: text("tags_json").notNull().default("[]"),
  sourceFeedsJson: text("source_feeds_json").notNull().default("[]"),
  status: text("status").notNull().default("online"),
  sightingCount: integer("sighting_count").notNull().default(1),
  feedConfidence: integer("feed_confidence").notNull().default(82),
  mlMaliciousProb: text("ml_malicious_prob").notNull().default("0.85"),
  isAnomaly: integer("is_anomaly").notNull().default(0),
  riskScore: integer("risk_score").notNull().default(80),
  triageStatus: text("triage_status").notNull().default("needs_review"),
  firstSeen: text("first_seen").notNull(),
  lastSeen: text("last_seen").notNull(),
});

// 3. RBAC Audit Logs (Tracks who approved, escalated, or dismissed each indicator)
export const rbacAuditLogs = pgTable("rbac_audit_logs", {
  id: serial("id").primaryKey(),
  userUid: text("user_uid").notNull(),
  userEmail: text("user_email").notNull(),
  userRole: text("user_role").notNull(),
  action: text("action").notNull(),
  targetIoc: text("target_ioc").notNull(),
  details: text("details").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// 4. Active Learning & Custom Training Corpus
export const trainingCorpus = pgTable("training_corpus", {
  id: serial("id").primaryKey(),
  iocValue: text("ioc_value").notNull().unique(),
  label: integer("label").notNull(), // 1 = Malicious, 0 = Benign
  source: text("source").notNull().default("active_learning"),
  addedByEmail: text("added_by_email").notNull().default("lead_analyst@threatops.io"),
  createdAt: timestamp("created_at").defaultNow(),
});

// 5. Automated SOAR Playbooks (Outbound Webhooks triggered when riskScore >= minRiskThreshold)
export const soarPlaybooks = pgTable("soar_playbooks", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  channel: text("channel").notNull(), // "slack" | "pagerduty" | "cloudflare_waf" | "gmail_quarantine"
  webhookUrl: text("webhook_url").notNull(),
  minRiskThreshold: integer("min_risk_threshold").notNull().default(85),
  enabled: integer("enabled").notNull().default(1),
  triggerCount: integer("trigger_count").notNull().default(0),
  lastTriggeredAt: text("last_triggered_at").notNull().default("Never"),
});

// 6. SOAR Webhook Dispatch Execution Logs
export const soarExecutionLogs = pgTable("soar_execution_logs", {
  id: serial("id").primaryKey(),
  playbookName: text("playbook_name").notNull(),
  channel: text("channel").notNull(),
  iocValue: text("ioc_value").notNull(),
  riskScore: integer("risk_score").notNull(),
  deliveryStatus: text("delivery_status").notNull(),
  payloadPreview: text("payload_preview").notNull(),
  executedAt: timestamp("executed_at").defaultNow(),
});

export const usersRelations = relations(users, ({ many }) => ({
  auditLogs: many(rbacAuditLogs),
}));
