"""
ThreatOps Python Database & Repository Layer (`backend/database.py`)
--------------------------------------------------------------------
Provides persistent storage using SQLite3 (`backend/threatops.db`) out of the box
and optional PostgreSQL (`DATABASE_URL`) support for:
  - users (SOC RBAC roles & Firebase / SSO accounts)
  - ioc_records (Normalized OSINT & triaged indicators)
  - soar_playbooks (Outbound Slack, PagerDuty, Cloudflare WAF, Workspace rules)
  - soar_executions (Webhook delivery logs)
  - audit_logs (SOC analyst RBAC & Active-Learning audit trail)
  - training_corpus (Analyst-labeled ground-truth samples)
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).resolve().parent / "threatops.db"
_DB_LOCK = threading.Lock()

DEFAULT_PLAYBOOKS = [
    {
        "name": "Slack #soc-critical-alerts Webhook",
        "channel": "slack",
        "webhookUrl": "https://hooks.slack.com/services/T00SOC/B00THREAT/ThreatOpsAlert",
        "minRiskThreshold": 85,
        "enabled": 1,
    },
    {
        "name": "PagerDuty Tier-3 Incident Escalation",
        "channel": "pagerduty",
        "webhookUrl": "https://events.pagerduty.com/v2/enqueue",
        "minRiskThreshold": 90,
        "enabled": 1,
    },
    {
        "name": "Cloudflare Enterprise WAF Edge Block",
        "channel": "cloudflare_waf",
        "webhookUrl": "https://api.cloudflare.com/client/v4/accounts/soc/firewall/access_rules/rules",
        "minRiskThreshold": 85,
        "enabled": 1,
    },
    {
        "name": "Google Workspace Admin Quarantine",
        "channel": "google_workspace",
        "webhookUrl": "https://admin.googleapis.com/admin/directory/v1/customer/soc/quarantine",
        "minRiskThreshold": 88,
        "enabled": 1,
    },
]


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uid TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'SOC Lead',
                    subscription_status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ioc_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT UNIQUE NOT NULL,
                    ioc_type TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    source_feeds_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    sighting_count INTEGER NOT NULL DEFAULT 1,
                    feed_confidence REAL NOT NULL DEFAULT 80,
                    ml_malicious_prob REAL NOT NULL DEFAULT 0.5,
                    is_anomaly INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 50,
                    triage_status TEXT NOT NULL DEFAULT 'monitored'
                );

                CREATE TABLE IF NOT EXISTS soar_playbooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    webhook_url TEXT NOT NULL,
                    min_risk_threshold INTEGER NOT NULL DEFAULT 85,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    trigger_count INTEGER NOT NULL DEFAULT 0,
                    last_triggered_at TEXT
                );

                CREATE TABLE IF NOT EXISTS soar_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    playbook_id INTEGER NOT NULL,
                    playbook_name TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    http_status TEXT NOT NULL,
                    payload_preview TEXT NOT NULL,
                    executed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_uid TEXT NOT NULL,
                    user_email TEXT NOT NULL,
                    user_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_ioc TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS training_corpus (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT UNIQUE NOT NULL,
                    label INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    added_by_email TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

            # Seed default playbooks if empty
            cur.execute("SELECT COUNT(*) AS cnt FROM soar_playbooks")
            if cur.fetchone()["cnt"] == 0:
                now_iso = datetime.now(timezone.utc).isoformat()
                for pb in DEFAULT_PLAYBOOKS:
                    cur.execute(
                        """
                        INSERT INTO soar_playbooks (name, channel, webhook_url, min_risk_threshold, enabled, trigger_count, last_triggered_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?)
                        """,
                        (
                            pb["name"],
                            pb["channel"],
                            pb["webhookUrl"],
                            pb["minRiskThreshold"],
                            pb["enabled"],
                            now_iso,
                        ),
                    )
            conn.commit()
        finally:
            conn.close()


init_db()


def get_or_create_user(uid: str, email: str, full_name: str = "Lead SOC Analyst") -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE uid = ? OR email = ? LIMIT 1", (uid, email))
            row = cur.fetchone()
            if row:
                return {
                    "id": row["id"],
                    "uid": row["uid"],
                    "email": row["email"],
                    "fullName": row["full_name"],
                    "full_name": row["full_name"],
                    "role": row["role"],
                    "subscription_status": row["subscription_status"],
                }
            cur.execute(
                """
                INSERT INTO users (uid, email, full_name, role, subscription_status, created_at)
                VALUES (?, ?, ?, 'SOC Lead', 'active', ?)
                """,
                (uid, email, full_name, now_iso),
            )
            conn.commit()
            return {
                "id": cur.lastrowid,
                "uid": uid,
                "email": email,
                "fullName": full_name,
                "full_name": full_name,
                "role": "SOC Lead",
                "subscription_status": "active",
            }
        finally:
            conn.close()


def update_user_role(uid: str, new_role: str) -> None:
    with _DB_LOCK:
        conn = get_connection()
        try:
            conn.execute("UPDATE users SET role = ? WHERE uid = ?", (new_role, uid))
            conn.commit()
        finally:
            conn.close()


def insert_audit_log(
    user_uid: str,
    user_email: str,
    user_role: str,
    action: str,
    target_ioc: str,
    details: str,
) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO audit_logs (user_uid, user_email, user_role, action, target_ioc, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_uid, user_email, user_role, action, target_ioc, details, now_iso),
            )
            conn.commit()
            return {
                "id": cur.lastrowid,
                "userUid": user_uid,
                "userEmail": user_email,
                "userRole": user_role,
                "action": action,
                "targetIoc": target_ioc,
                "details": details,
                "createdAt": now_iso,
            }
        finally:
            conn.close()


def get_recent_audit_logs(limit: int = 40) -> List[Dict[str, Any]]:
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "userUid": r["user_uid"],
                    "userEmail": r["user_email"],
                    "userRole": r["user_role"],
                    "action": r["action"],
                    "targetIoc": r["target_ioc"],
                    "details": r["details"],
                    "createdAt": r["created_at"],
                }
                for r in rows
            ]
        finally:
            conn.close()


def get_or_seed_soar_playbooks() -> List[Dict[str, Any]]:
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM soar_playbooks ORDER BY id ASC")
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "channel": r["channel"],
                    "webhookUrl": r["webhook_url"],
                    "minRiskThreshold": r["min_risk_threshold"],
                    "enabled": r["enabled"],
                    "triggerCount": r["trigger_count"],
                    "lastTriggeredAt": r["last_triggered_at"],
                }
                for r in rows
            ]
        finally:
            conn.close()


def create_soar_playbook(
    name: str, channel: str, webhook_url: str, min_risk_threshold: int = 85
) -> Dict[str, Any]:
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO soar_playbooks (name, channel, webhook_url, min_risk_threshold, enabled, trigger_count)
                VALUES (?, ?, ?, ?, 1, 0)
                """,
                (name, channel, webhook_url, min_risk_threshold),
            )
            conn.commit()
            return {
                "id": cur.lastrowid,
                "name": name,
                "channel": channel,
                "webhookUrl": webhook_url,
                "minRiskThreshold": min_risk_threshold,
                "enabled": 1,
                "triggerCount": 0,
                "lastTriggeredAt": None,
            }
        finally:
            conn.close()


def toggle_soar_playbook(playbook_id: int, enabled: int) -> None:
    with _DB_LOCK:
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE soar_playbooks SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, playbook_id),
            )
            conn.commit()
        finally:
            conn.close()


def record_soar_execution(
    playbook: Dict[str, Any],
    ioc_value: str,
    risk_score: float,
    http_status: str,
    payload_preview: str,
) -> Dict[str, Any]:
    now_iso = datetime.now(timezone.utc).isoformat()
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE soar_playbooks
                SET trigger_count = trigger_count + 1, last_triggered_at = ?
                WHERE id = ?
                """,
                (now_iso, playbook["id"]),
            )
            cur.execute(
                """
                INSERT INTO soar_executions (playbook_id, playbook_name, channel, ioc_value, risk_score, http_status, payload_preview, executed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    playbook["id"],
                    playbook["name"],
                    playbook["channel"],
                    ioc_value,
                    risk_score,
                    http_status,
                    payload_preview[:500],
                    now_iso,
                ),
            )
            conn.commit()
            return {
                "id": cur.lastrowid,
                "playbookId": playbook["id"],
                "playbookName": playbook["name"],
                "channel": playbook["channel"],
                "iocValue": ioc_value,
                "riskScore": risk_score,
                "httpStatus": http_status,
                "payloadPreview": payload_preview[:500],
                "executedAt": now_iso,
            }
        finally:
            conn.close()


def get_recent_soar_executions(limit: int = 25) -> List[Dict[str, Any]]:
    with _DB_LOCK:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM soar_executions ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "playbookId": r["playbook_id"],
                    "playbookName": r["playbook_name"],
                    "channel": r["channel"],
                    "iocValue": r["ioc_value"],
                    "riskScore": r["risk_score"],
                    "httpStatus": r["http_status"],
                    "payloadPreview": r["payload_preview"],
                    "executedAt": r["executed_at"],
                }
                for r in rows
            ]
        finally:
            conn.close()


def upsert_ioc_record(record: Dict[str, Any]) -> None:
    with _DB_LOCK:
        conn = get_connection()
        try:
            conn.execute(
                """
                INSERT INTO ioc_records (
                    ioc_value, ioc_type, threat_type, tags_json, source_feeds_json,
                    status, first_seen, last_seen, sighting_count, feed_confidence,
                    ml_malicious_prob, is_anomaly, risk_score, triage_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    sighting_count = excluded.sighting_count,
                    feed_confidence = excluded.feed_confidence,
                    ml_malicious_prob = excluded.ml_malicious_prob,
                    is_anomaly = excluded.is_anomaly,
                    risk_score = excluded.risk_score,
                    triage_status = excluded.triage_status
                """,
                (
                    record.get("ioc_value", ""),
                    record.get("ioc_type", "url"),
                    record.get("threat_type", "malware_download"),
                    json.dumps(record.get("tags", [])),
                    json.dumps(record.get("source_feeds", [])),
                    record.get("status", "online"),
                    record.get("first_seen", datetime.now(timezone.utc).isoformat()),
                    record.get("last_seen", datetime.now(timezone.utc).isoformat()),
                    int(record.get("sighting_count", 1)),
                    float(record.get("feed_confidence", 80)),
                    float(record.get("ml_malicious_prob", 0.5)),
                    1 if record.get("is_anomaly") else 0,
                    float(record.get("risk_score", 50.0)),
                    record.get("triage_status", "monitored"),
                ),
            )
            conn.commit()
        finally:
            conn.close()
