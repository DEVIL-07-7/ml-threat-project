#!/usr/bin/env python3
"""
ThreatOps Unified Python Backend Server (`app.py`)
--------------------------------------------------
Runs the ThreatOps platform in Python without changing the core architecture,
using the separated `machine_learning/` package (`machine_learning/datasets/`
and `machine_learning/models/`) and `backend/` modules.

Supports two execution modes automatically:
  1. FastAPI + Uvicorn (when `pip install -r requirements.txt` is installed)
  2. Zero-Dependency Standard Library HTTP Server (fallback when running in a
     minimal Python environment without pip/FastAPI installed)

Usage:
  python3 app.py
  uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

import json
import mimetypes
import os
import secrets
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.core_service import get_core_service
from backend.database import (
    create_soar_playbook,
    get_or_create_user,
    get_or_seed_soar_playbooks,
    get_recent_audit_logs,
    get_recent_soar_executions,
    insert_audit_log,
    toggle_soar_playbook,
    update_user_role,
)
from backend.intel_extractor import (
    analyze_threat_report,
    enrich_ioc_parallel,
    generate_detection_rules,
)
from backend.soar_engine import trigger_automated_soar_playbooks
from machine_learning.datasets.dataset_loader import append_custom_feedback_sample


def dispatch_api_request(
    method: str, path: str, query_params: Dict[str, Any], body: Dict[str, Any]
) -> Tuple[int, Dict[str, str], bytes]:
    """
    Framework-agnostic router that handles all `/api/v1/*` requests identically
    for both FastAPI and the built-in Python HTTP server.
    """
    svc = get_core_service()
    headers = {"Content-Type": "application/json; charset=utf-8"}

    def json_resp(payload: Any, status: int = 200) -> Tuple[int, Dict[str, str], bytes]:
        return status, headers, json.dumps(payload).encode("utf-8")

    # --- Health & Python Architecture Info ---
    if method == "GET" and path == "/api/v1/health":
        summary = svc.ml_model.get_model_summary()
        return json_resp(
            {
                "platform": "ThreatOps",
                "runtime": "Python 3 + Separated ML Package",
                "status": "operational",
                "precision": f"{summary['metrics']['precision']}%",
                "avg_response": "13s",
                "ws_clients": 1,
            }
        )

    if method == "GET" and path == "/api/v1/architecture/python":
        summary = svc.ml_model.get_model_summary()
        return json_resp(
            {
                "runtime": f"Python {sys.version.split()[0]}",
                "core_architecture": "Preserved 3-Tier ThreatOps SOC Architecture",
                "machine_learning_folder": {
                    "root": "machine_learning/",
                    "datasets_folder": "machine_learning/datasets/",
                    "datasets": [
                        "machine_learning/datasets/benign_corpus.csv",
                        "machine_learning/datasets/malicious_archetypes.csv",
                        "machine_learning/datasets/osint_seed_iocs.json",
                        "machine_learning/datasets/custom_feedback_dataset.csv",
                    ],
                    "features_folder": "machine_learning/features/feature_extractor.py",
                    "models_folder": "machine_learning/models/",
                    "models": [
                        "machine_learning/models/ensemble_classifier.py",
                        "machine_learning/models/saved_ensemble_model.json",
                        "machine_learning/models/saved_ensemble_model.pkl",
                    ],
                    "entrypoints": [
                        "machine_learning/train.py",
                        "machine_learning/predict.py",
                        "machine_learning/engine_cli.py",
                    ],
                },
                "python_backend_folder": {
                    "server_entry": "app.py",
                    "modules": [
                        "backend/core_service.py",
                        "backend/database.py",
                        "backend/osint_feeds.py",
                        "backend/soar_engine.py",
                        "backend/intel_extractor.py",
                    ],
                },
                "model_metrics": summary["metrics"],
                "dataset_stats": summary["dataset"],
            }
        )

    # --- Triage Queue ---
    if method == "GET" and path == "/api/v1/triage/queue":
        return json_resp(
            {
                "triage_queue": svc.triage_queue,
                "active_learning_count": svc.active_learning_count,
                "stream_stats": {
                    "total_streamed": svc.total_streamed_count,
                    "buffer_remaining": len(svc.live_feed_staging_buffer),
                    "connected_clients": 1,
                    "paused": svc.stream_paused,
                    "interval_ms": svc.stream_interval_ms,
                },
            }
        )

    if method == "POST" and path.startswith("/api/v1/triage/") and path.endswith("/action"):
        parts = path.strip("/").split("/")
        queue_id = parts[3] if len(parts) >= 5 else ""
        action = body.get("action") or "approved_block"
        res = svc.process_triage_action(queue_id, action)
        if not res:
            return json_resp({"detail": "Queue item not found"}, 404)
        return json_resp(res)

    # --- Auth & RBAC ---
    if method == "POST" and path == "/api/v1/auth/sso":
        user = svc.users[svc.default_email]
        db_user = get_or_create_user(user["uid"], user["email"], user["full_name"])
        user["role"] = db_user["role"]
        token = f"threatops_jwt_{secrets.token_hex(16)}"
        svc.sessions[token] = user["email"]
        return json_resp(
            {
                "access_token": token,
                "token_type": "bearer",
                "uid": user["uid"],
                "role": user["role"],
                "subscription_status": user["subscription_status"],
                "email": user["email"],
                "full_name": user["full_name"],
            }
        )

    if method == "GET" and path == "/api/v1/auth/me":
        user = svc.users[svc.default_email]
        return json_resp(user)

    if method == "POST" and path == "/api/v1/rbac/role":
        allowed = ["Tier-1 Analyst", "Tier-3 Threat Hunter", "SOC Lead"]
        req_role = body.get("role")
        new_role = req_role if req_role in allowed else "SOC Lead"
        user = svc.users[svc.default_email]
        user["role"] = new_role
        update_user_role(user["uid"], new_role)
        audit = insert_audit_log(
            user_uid=user["uid"],
            user_email=user["email"],
            user_role=new_role,
            action="rbac:role_switched",
            target_ioc="SOC-Session-RBAC",
            details=f"Analyst switched active RBAC role to '{new_role}'",
        )
        return json_resp(
            {
                "uid": user["uid"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": new_role,
                "audit_log": audit,
            }
        )

    if method == "GET" and path == "/api/v1/rbac/audit-logs":
        return json_resp({"audit_logs": get_recent_audit_logs(40)})

    # --- SOAR Playbooks ---
    if method == "GET" and path == "/api/v1/soar/playbooks":
        return json_resp(
            {
                "playbooks": get_or_seed_soar_playbooks(),
                "executions": get_recent_soar_executions(25),
            }
        )

    if method == "POST" and path == "/api/v1/soar/playbooks":
        name = str(body.get("name") or "Custom SOC Webhook Playbook").strip()
        channel = str(body.get("channel") or "slack")
        webhook_url = str(body.get("webhook_url") or "https://hooks.slack.com/services/custom")
        min_thresh = min(100, max(50, int(body.get("min_risk_threshold") or 85)))
        created = create_soar_playbook(name, channel, webhook_url, min_thresh)
        insert_audit_log(
            user_uid="soc-lead-default-uid",
            user_email=svc.default_email,
            user_role="SOC Lead",
            action="soar:playbook_created",
            target_ioc=created["name"],
            details=f"Created outbound {channel} webhook playbook (threshold >= {min_thresh}/100)",
        )
        return json_resp(
            {
                "playbooks": get_or_seed_soar_playbooks(),
                "executions": get_recent_soar_executions(25),
            }
        )

    if method == "POST" and path.startswith("/api/v1/soar/playbooks/") and path.endswith("/toggle"):
        parts = path.strip("/").split("/")
        pb_id = int(parts[4])
        enabled = 1 if int(body.get("enabled") or 0) == 1 else 0
        toggle_soar_playbook(pb_id, enabled)
        return json_resp(
            {
                "playbooks": get_or_seed_soar_playbooks(),
                "executions": get_recent_soar_executions(25),
            }
        )

    if method == "POST" and path == "/api/v1/soar/dispatch":
        ioc_val = str(body.get("ioc_value") or "http://194.55.186.21:54321/Mozi.a").strip()
        risk_score = float(body.get("risk_score") or 94.0)
        trigger_automated_soar_playbooks(ioc_val, risk_score, "Manual SOC Dispatch", "critical_manual_trigger")
        insert_audit_log(
            user_uid="soc-lead-default-uid",
            user_email=svc.default_email,
            user_role="SOC Lead",
            action="soar:manual_dispatch",
            target_ioc=ioc_val,
            details=f"Triggered outbound SOAR playbooks for {ioc_val} (Risk Score {risk_score}/100)",
        )
        return json_resp(
            {
                "playbooks": get_or_seed_soar_playbooks(),
                "executions": get_recent_soar_executions(25),
            }
        )

    # --- Platform Stats & IOCs ---
    if method == "GET" and path == "/api/v1/stats":
        return json_resp(svc.get_stats())

    if method == "GET" and path == "/api/v1/iocs":
        ioc_type = (query_params.get("ioc_type") or ["all"])[0]
        search = (query_params.get("search") or [""])[0]
        limit = min(200, max(1, int((query_params.get("limit") or ["60"])[0])))
        filtered = list(svc.ioc_records)
        if ioc_type and ioc_type != "all":
            filtered = [r for r in filtered if (r.get("ioc_type") or "").lower() == ioc_type.lower()]
        if search:
            q = search.strip().lower()
            filtered = [
                r
                for r in filtered
                if q in (r.get("ioc_value") or "").lower()
                or q in (r.get("threat_type") or "").lower()
                or any(q in t.lower() for t in (r.get("tags") or []))
            ]
        filtered.sort(key=lambda r: float(r.get("risk_score") or 0.0), reverse=True)
        return json_resp(filtered[:limit])

    # --- Feeds ---
    if method == "GET" and path == "/api/v1/feeds/sources":
        return json_resp(
            {
                "sources": svc.get_feed_sources_telemetry(),
                "total_indicators": len(svc.ioc_records),
            }
        )

    if method == "POST" and path == "/api/v1/feeds/refresh":
        return json_resp(svc.refresh_live_feeds())

    # --- Machine Learning Studio (/api/v1/ml/*) ---
    if method == "GET" and path == "/api/v1/ml/status":
        summary = svc.ml_model.get_model_summary()
        summary["active_learning_count"] = svc.active_learning_count
        return json_resp(summary)

    if method == "POST" and path == "/api/v1/ml/train":
        summary = svc.ml_model.train_and_evaluate(
            options=body,
            extra_malicious_iocs=[r["ioc_value"] for r in svc.ioc_records],
            persist_artifacts=True,
        )
        svc._rescore_all_records()
        summary["active_learning_count"] = svc.active_learning_count
        return json_resp(summary)

    if method == "POST" and path == "/api/v1/ml/dataset/add":
        samples = body.get("samples") or []
        added = 0
        for s in samples:
            ioc_v = str(s.get("ioc_value") or "").strip()
            lbl = 1 if int(s.get("label") or 0) == 1 else 0
            if len(ioc_v) >= 3:
                append_custom_feedback_sample(ioc_v, lbl, source="analyst_dataset", added_by=svc.default_email)
                added += 1
        summary = svc.ml_model.train_and_evaluate(
            options=svc.ml_model.state["hyperparameters"] if svc.ml_model.state else {},
            extra_malicious_iocs=[r["ioc_value"] for r in svc.ioc_records],
            persist_artifacts=True,
        )
        svc._rescore_all_records()
        summary["active_learning_count"] = svc.active_learning_count
        return json_resp({"status": "success", "samples_added": added, "model_summary": summary})

    # --- On-Demand IOC Scanner ---
    if method == "POST" and path == "/api/v1/scan/ioc":
        target = str(body.get("ioc_value") or "").strip()
        if not target:
            return json_resp({"detail": "ioc_value is required"}, 400)
        existing = next((r for r in svc.ioc_records if r.get("ioc_value") == target), None)
        feed_conf = float(existing["feed_confidence"]) if existing else 50.0
        pred = svc.ml_model.predict_single_ioc(target, feed_conf)
        if existing:
            pred["known_in_db"] = True
            pred["source_feeds"] = existing.get("source_feeds") or []
            pred["tags"] = existing.get("tags") or []
            pred["threat_type"] = existing.get("threat_type")
            pred["reasons"].insert(
                0, f"Corroborated by known OSINT feed(s): {', '.join(existing.get('source_feeds') or [])}"
            )
        else:
            pred["known_in_db"] = False
            pred["source_feeds"] = []
            pred["tags"] = []
            pred["threat_type"] = "unclassified_live_scan"
        return json_resp(pred)

    # --- Deep Threat Report Extractor & Rule Generator ---
    if method == "POST" and path == "/api/v1/extract/report":
        raw_text = str(body.get("text") or "")
        fmt = str(body.get("format") or "auto")
        res = analyze_threat_report(raw_text, fmt, svc.ml_model.predict_single_ioc)
        return json_resp(res)

    if method == "POST" and path == "/api/v1/rules/generate":
        return json_resp(
            generate_detection_rules(
                str(body.get("ioc_value") or "185.220.101.45"),
                str(body.get("ioc_type") or "url"),
                str(body.get("threat_name") or "ThreatOps_Identified_Threat"),
            )
        )

    if method == "POST" and path == "/api/v1/enrich/parallel":
        return json_resp(enrich_ioc_parallel(str(body.get("ioc_value") or "91.215.85.142")))

    # --- SIEM / SOAR Export ---
    if method == "GET" and path.startswith("/api/v1/export/"):
        platform = path.split("/api/v1/export/")[-1].strip("/").lower()
        crit = [r for r in svc.ioc_records if float(r.get("risk_score") or 0) >= 70.0][:50]
        ioc_list = [r["ioc_value"] for r in crit]
        if platform == "splunk":
            spl = "index=* (" + " OR ".join(f'dest="{i}" OR query="{i}"' for i in ioc_list[:15]) + ")"
            return json_resp({"platform": "Splunk", "format": "SPL", "export_query": spl})
        if platform == "sentinel":
            kql = "CommonSecurityLog | where DestinationIP in (" + ", ".join(f'"{i}"' for i in ioc_list[:20]) + ")"
            return json_resp({"platform": "Microsoft Sentinel", "format": "KQL", "export_query": kql})
        if platform == "qradar":
            aql = "SELECT * FROM events WHERE " + " OR ".join(f'INCIDENT_IP = "{i}"' for i in ioc_list[:15])
            return json_resp({"platform": "IBM QRadar", "format": "AQL", "export_query": aql})
        if platform == "crowdstrike":
            lines = ["type,value,action,severity,description"]
            for r in crit:
                t = "ipv4" if r.get("ioc_type") == "ipv4" else "domain"
                lines.append(f"{t},{r['ioc_value']},prevent,critical,ThreatOps Automated Block")
            return json_resp({"platform": "CrowdStrike Falcon", "format": "CSV", "payload": "\n".join(lines)})
        if platform == "stix":
            now_iso = datetime.now(timezone.utc).isoformat()
            bundle = {
                "type": "bundle",
                "id": f"bundle--threatops-{int(datetime.now(timezone.utc).timestamp())}",
                "objects": [
                    {
                        "type": "indicator",
                        "id": f"indicator--{r['id']}",
                        "name": f"Malicious {r.get('ioc_type', 'url')}",
                        "pattern": f"[{r.get('ioc_type', 'url')}:value = '{r['ioc_value']}']",
                        "pattern_type": "stix",
                        "valid_from": now_iso,
                        "confidence": round(float(r.get("risk_score") or 75)),
                    }
                    for r in crit
                ],
            }
            return json_resp({"platform": "STIX/TAXII 2.1", "format": "JSON", "payload": bundle})
        return json_resp({"error": f"Platform '{platform}' not supported"}, 400)

    # --- Client Org Feeds & Graph Correlation ---
    if method == "POST" and path == "/api/v1/org/ingest-feed":
        org_name = str(body.get("organization_name") or "ClientOrg")
        log_type = str(body.get("log_type") or "firewall")
        raw_logs = body.get("raw_logs") or []
        processed = 0
        flagged = []
        for line in raw_logs:
            for token in str(line).strip().split():
                if "." in token and len(token) > 6:
                    clean_t = token.strip(",;:\"'")
                    res = svc.upsert_incoming_ioc_single(
                        {
                            "ioc_value": clean_t,
                            "ioc_type": "ipv4" if any(c.isdigit() for c in clean_t[:3]) else "domain",
                            "threat_type": "org_internal_telemetry",
                            "tags": [f"org:{org_name}", log_type],
                            "source_feed": f"ClientOrg-{org_name}",
                            "raw_confidence": 75,
                        }
                    )
                    if res["scored"]["risk_score"] >= 65:
                        flagged.append(clean_t)
                    processed += 1
        return json_resp(
            {
                "status": "success",
                "organization": org_name,
                "indicators_parsed": processed,
                "critical_threats_isolated": len(flagged),
                "flagged_iocs": flagged,
            }
        )

    if method == "GET" and path == "/api/v1/org/graph-correlations":
        top_recs = sorted(svc.ioc_records, key=lambda r: float(r.get("risk_score") or 0), reverse=True)[:15]
        nodes = [
            {"id": "Campaign: DarkHydra", "group": "campaign", "val": 25},
            {"id": "Actor: APT29", "group": "actor", "val": 20},
            {"id": "Actor: Lazarus Group", "group": "actor", "val": 20},
        ]
        links = [{"source": "Actor: APT29", "target": "Campaign: DarkHydra"}]
        for r in top_recs:
            if not any(n["id"] == r["ioc_value"] for n in nodes):
                nodes.append({"id": r["ioc_value"], "group": "ioc", "val": 10})
            target_grp = "Campaign: DarkHydra" if int(r.get("id") or 0) % 2 == 0 else "Actor: Lazarus Group"
            links.append({"source": target_grp, "target": r["ioc_value"]})
            for t in (r.get("tags") or [])[:2]:
                tag_id = f"TTP: {t}"
                if not any(n["id"] == tag_id for n in nodes):
                    nodes.append({"id": tag_id, "group": "tag", "val": 6})
                links.append({"source": r["ioc_value"], "target": tag_id})
        return json_resp({"nodes": nodes, "links": links})

    # --- ML Studio Dataset Preview & Artifact Downloads (machine_learning/) ---
    if method == "GET" and path == "/api/v1/ml/dataset":
        from machine_learning.ml_studio import MLStudioController
        studio = MLStudioController(svc.ml_model)
        limit = int((query_params.get("limit") or ["250"])[0])
        return json_resp(studio.get_training_dataset_records(limit=limit))

    if method == "GET" and path.startswith("/api/v1/ml/download/"):
        from machine_learning.ml_studio import MLStudioController
        filename = path.split("/api/v1/ml/download/")[-1].strip("/")
        resolved = MLStudioController.resolve_downloadable_artifact(filename)
        if resolved and resolved[0].exists():
            file_path, content_type, download_name = resolved
            data = file_path.read_bytes()
            return (
                200,
                {
                    "Content-Type": content_type,
                    "Content-Disposition": f'attachment; filename="{download_name}"',
                    "Content-Length": str(len(data)),
                    "Cache-Control": "no-store",
                },
                data,
            )
        return json_resp({"error": f"Artifact '{filename}' not found in machine_learning/"}, 404)

    # --- Payment Gateway Checkout & Confirmation (/api/v1/billing/*) ---
    if method == "POST" and path == "/api/v1/billing/checkout":
        plan_name = str(body.get("plan_name") or "Starter · For Early-Stage SOC Teams")
        price = str(body.get("price") or "$2,499")
        specs = body.get("specs") or []
        session_id = f"cs_live_{secrets.token_hex(12)}"
        return json_resp(
            {
                "status": "redirect_ready",
                "session_id": session_id,
                "gateway_provider": "Stripe Enterprise Checkout",
                "redirect_url": f"/payment-gateway?session_id={session_id}",
                "plan": {
                    "name": plan_name,
                    "price": price,
                    "billing_cycle": "monthly",
                    "specs": specs,
                },
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    if method == "POST" and path == "/api/v1/billing/confirm":
        session_id = str(body.get("session_id") or f"cs_live_{secrets.token_hex(8)}")
        plan_name = str(body.get("plan_name") or "Starter · For Early-Stage SOC Teams")
        price = str(body.get("price") or "$2,499")
        payment_method = str(body.get("payment_method") or "card")
        billing_email = str(body.get("billing_email") or svc.default_email)
        organization = str(body.get("organization") or "Sentinel-Core-SOC")
        txn_id = f"TXN-{secrets.token_hex(4).upper()}"
        audit = insert_audit_log(
            user_uid="soc-lead-default-uid",
            user_email=billing_email,
            user_role="SOC Lead",
            action="billing:plan_purchased",
            target_ioc=plan_name.split("·")[0].strip(),
            details=f"Purchased {plan_name} ({price}/mo) via {payment_method.upper()} · Ref {txn_id}",
        )
        return json_resp(
            {
                "status": "succeeded",
                "transaction_id": txn_id,
                "session_id": session_id,
                "plan_name": plan_name,
                "price": price,
                "payment_method": payment_method,
                "billing_email": billing_email,
                "organization": organization,
                "paid_at": datetime.now(timezone.utc).isoformat(),
                "audit_log": audit,
            }
        )

    return json_resp({"error": f"Route {method} {path} not found"}, 404)


# Optional FastAPI mount when installed locally (`pip install -r requirements.txt`)
try:
    from fastapi import FastAPI, Request, Response
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.staticfiles import StaticFiles

    app = FastAPI(
        title="ThreatOps Python Cyber Threat Intelligence API",
        version="2.0.0",
        description="Python Backend + Separated machine_learning/ (datasets + models) Architecture",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.api_route("/api/v1/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def fastapi_gateway(request: Request, full_path: str) -> Response:
        body = {}
        if request.method in ("POST", "PUT"):
            try:
                body = await request.json()
            except Exception:
                body = {}
        q_params = {k: request.query_params.getlist(k) for k in request.query_params.keys()}
        status, hdrs, content = dispatch_api_request(
            request.method, f"/api/v1/{full_path}", q_params, body
        )
        return Response(content=content, status_code=status, headers=hdrs)

    dist_dir = PROJECT_ROOT / "dist"
    if dist_dir.exists():
        app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="static")

    HAS_FASTAPI = True
except ImportError:
    app = None
    HAS_FASTAPI = False


class StdlibThreatOpsHandler(BaseHTTPRequestHandler):
    """Zero-dependency HTTP handler so `python app.py` works even without pip packages installed."""

    def do_GET(self) -> None:
        self._handle_http("GET")

    def do_POST(self) -> None:
        self._handle_http("POST")

    def _handle_http(self, method: str) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            body = {}
            if method == "POST":
                length = int(self.headers.get("Content-Length") or 0)
                if length > 0:
                    raw = self.rfile.read(length).decode("utf-8", errors="replace")
                    try:
                        body = json.loads(raw)
                    except Exception:
                        body = {}
            status, hdrs, content = dispatch_api_request(
                method, parsed.path, parse_qs(parsed.query), body
            )
            self.send_response(status)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
            return

        # Serve static frontend from dist/ if available
        dist_dir = PROJECT_ROOT / "dist"
        rel_path = parsed.path.lstrip("/") or "index.html"
        file_path = dist_dir / rel_path
        if not file_path.exists() or file_path.is_dir():
            file_path = dist_dir / "index.html"
        if file_path.exists() and file_path.is_file():
            ctype, _ = mimetypes.guess_type(str(file_path))
            data = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype or "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "platform": "ThreatOps Python Server",
                        "status": "running",
                        "hint": "Run `npm run build` to build the React SPA into dist/, or use `/api/v1/health`",
                    }
                ).encode("utf-8")
            )


def run_server() -> None:
    port = int(os.environ.get("PYTHON_PORT") or os.environ.get("PORT") or 8000)
    if HAS_FASTAPI:
        try:
            import uvicorn

            print(f"[ThreatOps Python] Starting FastAPI + Uvicorn server on http://0.0.0.0:{port}")
            uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
            return
        except ImportError:
            pass

    print(f"[ThreatOps Python] Starting built-in ThreadingHTTPServer on http://0.0.0.0:{port}")
    server = ThreadingHTTPServer(("0.0.0.0", port), StdlibThreatOpsHandler)
    server.serve_forever()


if __name__ == "__main__":
    run_server()
