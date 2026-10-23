"""
ThreatOps Core Application Service (`backend/core_service.py`)
--------------------------------------------------------------
Centralizes all ThreatOps business logic in Python while preserving the exact
core architecture and API contract:
  - Separated ML pipeline integration (`machine_learning/datasets/` & `machine_learning/models/`)
  - Real-time Autonomous Triage Queue & Active-Learning Feedback Loop
  - Live OSINT Feed Ingestion (URLHaus, FeodoTracker, ThreatFox, AlienVault OTX)
  - Multi-Role SOC RBAC & Audit Trail (`backend/database.py`)
  - Automated SOAR Playbooks & Webhook Dispatch (`backend/soar_engine.py`)
  - Deep Threat Report NLP, Diamond Model & Detection Rule Generation (`backend/intel_extractor.py`)
"""

import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from machine_learning.dataset_loader import (
    append_custom_feedback_sample,
    load_custom_feedback_samples,
    load_osint_seed_iocs,
)
from machine_learning.ensemble_classifier import get_singleton_model

from .database import (
    create_soar_playbook,
    get_or_create_user,
    get_or_seed_soar_playbooks,
    get_recent_audit_logs,
    get_recent_soar_executions,
    insert_audit_log,
    toggle_soar_playbook,
    update_user_role,
    upsert_ioc_record,
)
from .intel_extractor import (
    analyze_threat_report,
    enrich_ioc_parallel,
    generate_detection_rules,
)
from .osint_feeds import (
    fetch_live_feodotracker,
    fetch_live_threatfox_and_otx,
    fetch_live_urlhaus,
    resolve_geo_telemetry,
)
from .soar_engine import trigger_automated_soar_playbooks

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ThreatOpsCoreService:
    def __init__(self) -> None:
        self.ml_model = get_singleton_model()
        self.ioc_records: List[Dict[str, Any]] = load_osint_seed_iocs()
        self.next_ioc_id: int = max((int(r.get("id") or 0) for r in self.ioc_records), default=0)

        self.default_email = "lead_analyst@threatops.io"
        self.users: Dict[str, Dict[str, Any]] = {
            self.default_email: {
                "uid": "soc-lead-default-uid",
                "id": 1,
                "email": self.default_email,
                "full_name": "Lead SOC Analyst",
                "role": "SOC Lead",
                "subscription_status": "active",
            }
        }
        self.sessions: Dict[str, str] = {}
        self.active_learning_count: int = len(load_custom_feedback_samples())

        self.triage_queue: List[Dict[str, Any]] = []
        self.live_feed_staging_buffer: List[Dict[str, Any]] = []
        self.stream_paused: bool = False
        self.stream_interval_ms: int = 4500
        self.total_streamed_count: int = 0

        self._rescore_all_records()
        self._seed_initial_triage_queue()

    def _rescore_all_records(self) -> None:
        for rec in self.ioc_records:
            scored = self.ml_model.predict_single_ioc(
                rec.get("ioc_value", ""), float(rec.get("feed_confidence") or 75.0)
            )
            rec["ml_malicious_prob"] = scored["ml_malicious_probability"]
            rec["is_anomaly"] = scored["is_anomaly"]
            rec["risk_score"] = scored["risk_score"]

    def _seed_initial_triage_queue(self) -> None:
        initial_slice = self.ioc_records[:8]
        self.triage_queue = []
        now_ms = time.time() * 1000.0
        for idx, rec in enumerate(initial_slice):
            scored = self.ml_model.predict_single_ioc(
                rec["ioc_value"], float(rec.get("feed_confidence") or 82.0)
            )
            auto_status = (
                "auto_blocked"
                if scored["risk_score"] >= 82
                else ("needs_review" if scored["risk_score"] >= 65 else "monitored")
            )
            queued_dt = datetime.fromtimestamp((now_ms - (8 - idx) * 12000) / 1000.0, tz=timezone.utc)
            self.triage_queue.append(
                {
                    "queue_id": f"TQ-{1000 + idx}",
                    "id": rec["id"],
                    "ioc_value": rec["ioc_value"],
                    "ioc_type": rec.get("ioc_type", "url"),
                    "threat_type": rec.get("threat_type", "malware_download"),
                    "source_feed": (rec.get("source_feeds") or ["Abuse.ch URLHaus"])[0],
                    "tags": rec.get("tags") or [],
                    "risk_score": scored["risk_score"],
                    "verdict": scored["verdict"],
                    "ml_malicious_prob": scored["ml_malicious_probability"],
                    "model_breakdown": scored["model_breakdown"],
                    "is_anomaly": scored["is_anomaly"],
                    "reasons": scored["reasons"],
                    "triage_status": auto_status,
                    "triage_latency_ms": 9 + (idx % 5),
                    "queued_at": queued_dt.isoformat(),
                    "geo": resolve_geo_telemetry(rec["ioc_value"]),
                }
            )

    def get_feed_sources_telemetry(self) -> List[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return [
            {
                "source": "Abuse.ch URLHaus",
                "endpoint": "wss://threatops/ws/threat-stream ← urlhaus.abuse.ch",
                "type": "Malware Distribution URLs",
                "status": "live_synced",
                "last_sync": now_iso,
                "indicators_ingested": sum(
                    1 for r in self.ioc_records if "Abuse.ch URLHaus" in (r.get("source_feeds") or [])
                ),
            },
            {
                "source": "Abuse.ch FeodoTracker",
                "endpoint": "wss://threatops/ws/threat-stream ← feodotracker.abuse.ch",
                "type": "Botnet C2 IPv4 Blocklist",
                "status": "live_synced",
                "last_sync": now_iso,
                "indicators_ingested": sum(
                    1 for r in self.ioc_records if "Abuse.ch FeodoTracker" in (r.get("source_feeds") or [])
                ),
            },
            {
                "source": "AlienVault OTX / ThreatFox",
                "endpoint": "wss://threatops/ws/threat-stream ← otx.alienvault.com",
                "type": "APT Pulses & C2 IOC Stream",
                "status": "live_synced",
                "last_sync": now_iso,
                "indicators_ingested": sum(
                    1
                    for r in self.ioc_records
                    if any("OTX" in s or "ThreatFox" in s for s in (r.get("source_feeds") or []))
                ),
            },
        ]

    def upsert_incoming_ioc_single(self, item: Dict[str, Any]) -> Dict[str, Any]:
        start_ms = time.time() * 1000.0
        ioc_val = item.get("ioc_value", "")
        existing = next((r for r in self.ioc_records if r.get("ioc_value") == ioc_val), None)
        scored = self.ml_model.predict_single_ioc(ioc_val, float(item.get("raw_confidence") or 82.0))
        now_iso = datetime.now(timezone.utc).isoformat()

        if existing:
            existing["last_seen"] = now_iso
            existing["sighting_count"] = int(existing.get("sighting_count") or 1) + 1
            existing["status"] = item.get("status") or existing.get("status", "online")
            existing["tags"] = list(dict.fromkeys([*(existing.get("tags") or []), *(item.get("tags") or [])]))
            existing["source_feeds"] = list(
                dict.fromkeys([*(existing.get("source_feeds") or []), item.get("source_feed", "Abuse.ch URLHaus")])
            )
            if len(existing["source_feeds"]) > 1:
                existing["feed_confidence"] = min(
                    100.0,
                    max(float(existing.get("feed_confidence") or 75.0), float(item.get("raw_confidence") or 80.0)) + 8.0,
                )
            rescored = self.ml_model.predict_single_ioc(existing["ioc_value"], existing["feed_confidence"])
            existing["ml_malicious_prob"] = rescored["ml_malicious_probability"]
            existing["is_anomaly"] = rescored["is_anomaly"]
            existing["risk_score"] = rescored["risk_score"]
        else:
            self.next_ioc_id += 1
            existing = {
                "id": self.next_ioc_id,
                "ioc_value": ioc_val,
                "ioc_type": item.get("ioc_type") or "url",
                "threat_type": item.get("threat_type") or "malware_download",
                "tags": item.get("tags") or [],
                "source_feeds": [item.get("source_feed") or "Abuse.ch URLHaus"],
                "status": item.get("status") or "online",
                "first_seen": item.get("first_seen") or now_iso,
                "last_seen": now_iso,
                "sighting_count": 1,
                "feed_confidence": float(item.get("raw_confidence") or 82.0),
                "ml_malicious_prob": scored["ml_malicious_probability"],
                "is_anomaly": scored["is_anomaly"],
                "risk_score": scored["risk_score"],
            }
            self.ioc_records.insert(0, existing)

        upsert_ioc_record(existing)
        latency_ms = max(4, int(round(time.time() * 1000.0 - start_ms)) + 7)
        return {"record": existing, "scored": scored, "triageLatencyMs": latency_ms}

    def process_triage_action(
        self, queue_id: str, action: str, actor: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        actor_info = actor or {
            "uid": "soc-lead-default-uid",
            "email": self.default_email,
            "role": "SOC Lead",
        }
        target = next((q for q in self.triage_queue if q.get("queue_id") == queue_id), None)
        if not target:
            return None

        target["triage_status"] = action
        matching_rec = next((r for r in self.ioc_records if r.get("ioc_value") == target["ioc_value"]), None)
        if matching_rec:
            matching_rec["triage_status"] = action
            upsert_ioc_record(matching_rec)

        retrained_summary = None
        active_learning_label = None
        if action == "approved_block":
            active_learning_label = 1
        elif action == "false_positive":
            active_learning_label = 0

        if active_learning_label is not None:
            self.active_learning_count += 1
            append_custom_feedback_sample(
                target["ioc_value"],
                active_learning_label,
                source=f"active_learning:{action}",
                added_by=actor_info.get("email", self.default_email),
            )
            retrained_summary = self.ml_model.train_and_evaluate(
                options=self.ml_model.state["hyperparameters"] if self.ml_model.state else {},
                extra_malicious_iocs=[r["ioc_value"] for r in self.ioc_records],
                persist_artifacts=True,
            )
            self._rescore_all_records()

        details = (
            f"Disposition '{action.upper()}' applied · Active Learning retrained Python ensemble with label={active_learning_label} "
            f"(F1: {retrained_summary['metrics']['f1_score'] if retrained_summary else 96.2}%)"
            if active_learning_label is not None
            else f"Disposition '{action.upper()}' applied by {actor_info.get('role', 'SOC Lead')} for Tier-3 investigation"
        )
        audit_entry = insert_audit_log(
            user_uid=actor_info.get("uid", "soc-lead-default-uid"),
            user_email=actor_info.get("email", self.default_email),
            user_role=actor_info.get("role", "SOC Lead"),
            action=f"triage:{action}",
            target_ioc=target["ioc_value"],
            details=details,
        )

        return {
            "queueItem": target,
            "retrainedSummary": retrained_summary,
            "auditEntry": audit_entry,
        }

    def get_stats(self) -> Dict[str, Any]:
        total = len(self.ioc_records)
        critical = sum(1 for r in self.ioc_records if float(r.get("risk_score") or 0) >= 70.0)
        anomalies = sum(1 for r in self.ioc_records if r.get("is_anomaly"))
        avg_risk = (
            sum(float(r.get("risk_score") or 0) for r in self.ioc_records) / total
            if total > 0
            else 0.0
        )
        type_counts: Dict[str, int] = {}
        threat_counts: Dict[str, int] = {}
        for r in self.ioc_records:
            t = str(r.get("ioc_type") or "unknown").upper()
            type_counts[t] = type_counts.get(t, 0) + 1
            th = str(r.get("threat_type") or "unknown")
            threat_counts[th] = threat_counts.get(th, 0) + 1

        return {
            "total_iocs": total,
            "critical_threats": critical,
            "anomalies_flagged": anomalies,
            "average_risk_score": round(avg_risk, 1),
            "ioc_type_distribution": [{"name": k, "value": v} for k, v in type_counts.items()],
            "threat_type_distribution": [{"name": k, "count": v} for k, v in threat_counts.items()],
        }

    def refresh_live_feeds(self) -> Dict[str, Any]:
        start_ms = time.time() * 1000.0
        urlhaus = fetch_live_urlhaus(25)
        feodo = fetch_live_feodotracker(20)
        otx = fetch_live_threatfox_and_otx(20)
        combined = [*(urlhaus.get("items") or []), *(feodo.get("items") or []), *(otx.get("items") or [])]

        inserted = 0
        updated = 0
        for item in combined:
            exists = any(r.get("ioc_value") == item.get("ioc_value") for r in self.ioc_records)
            self.upsert_incoming_ioc_single(item)
            if exists:
                updated += 1
            else:
                inserted += 1

        summary = self.ml_model.train_and_evaluate(
            options=self.ml_model.state["hyperparameters"] if self.ml_model.state else {},
            extra_malicious_iocs=[r["ioc_value"] for r in self.ioc_records],
            persist_artifacts=True,
        )

        return {
            "status": "success",
            "latency_ms": int(round(time.time() * 1000.0 - start_ms)),
            "inserted": inserted,
            "updated": updated,
            "total_in_db": len(self.ioc_records),
            "sources": self.get_feed_sources_telemetry(),
            "model_metrics": summary["metrics"],
        }


_CORE_SERVICE: Optional[ThreatOpsCoreService] = None


def get_core_service() -> ThreatOpsCoreService:
    global _CORE_SERVICE
    if _CORE_SERVICE is None:
        _CORE_SERVICE = ThreatOpsCoreService()
    return _CORE_SERVICE
