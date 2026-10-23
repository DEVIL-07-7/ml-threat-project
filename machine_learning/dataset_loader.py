"""
ThreatOps Unified Dataset Manager (`machine_learning/dataset_loader.py`)
------------------------------------------------------------------------
Manages the single unified training dataset CSV inside `machine_learning/datasets/`:
  - `machine_learning/datasets/training_dataset.csv`
"""

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.dont_write_bytecode = True

from machine_learning.feature_extractor import FEATURE_NAMES, extract_ioc_features

ML_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ML_ROOT.parent
DATASETS_DIR = ML_ROOT / "datasets"
TRAINING_DATASET_CSV_PATH = DATASETS_DIR / "training_dataset.csv"
SEED_IOCS_JSON_PATH = PROJECT_ROOT / "src" / "seedIocs.json"

DEFAULT_MALICIOUS_INDICATORS: List[Tuple[str, str]] = [
    ("http://61.54.235.31:36551/i", "osint_threat_feed"),
    ("http://103.140.87.105:45962/i", "osint_threat_feed"),
    ("http://60.17.117.178:52362/i", "osint_threat_feed"),
    ("http://191.243.174.35:44365/i", "osint_threat_feed"),
    ("http://61.52.1.72:59868/i", "osint_threat_feed"),
    ("http://210.208.111.36:33179/i", "osint_threat_feed"),
    ("http://119.102.73.19:43236/bin.sh", "osint_threat_feed"),
    ("http://61.53.135.7:46609/i", "osint_threat_feed"),
    ("http://46.163.181.104:54484/i", "osint_threat_feed"),
    ("http://109.236.44.237:53813/i", "osint_threat_feed"),
    ("http://58.255.43.51:48371/i", "osint_threat_feed"),
    ("http://60.16.174.24:43977/i", "osint_threat_feed"),
    ("http://60.17.117.178:52362/bin.sh", "osint_threat_feed"),
    ("http://220.168.236.38:60522/i", "osint_threat_feed"),
    ("http://221.202.107.18:41370/i", "osint_threat_feed"),
    ("http://219.156.115.143:33235/i", "osint_threat_feed"),
    ("http://109.236.44.237:53813/bin.sh", "osint_threat_feed"),
    ("http://120.28.153.108:41321/bin.sh", "osint_threat_feed"),
    ("http://113.53.69.165:46895/i", "osint_threat_feed"),
    ("http://113.53.69.165:46895/bin.sh", "osint_threat_feed"),
    ("http://185.220.101.45:44812/Mozi.m", "malicious_archetype"),
    ("http://45.155.205.233:8080/bins/mirai.x86", "malicious_archetype"),
    ("http://91.219.236.222/gate.php?id=botnet_c2", "malicious_archetype"),
    ("https://secure-login-update-microsoft-auth.xyz/verify/account", "malicious_archetype"),
    ("http://194.26.135.119:55912/bin.sh", "malicious_archetype"),
    ("https://paypal-identity-confirm-wallet.top/login.php", "malicious_archetype"),
    ("http://89.248.165.131:39121/Mozi.a", "malicious_archetype"),
    ("http://x9k8m2p4q7r1w3z5.ru/dropper/payload.exe", "malicious_archetype"),
    ("http://179.43.175.62:443/cobaltstrike/beacon.dll", "malicious_archetype"),
    ("https://chase-online-banking-security-alert.tk/auth/session", "malicious_archetype"),
]

DEFAULT_BENIGN_INDICATORS: List[Tuple[str, str]] = [
    ("https://www.google.com/search?q=cloud+security", "enterprise_benign_baseline"),
    ("https://github.com/torvalds/linux/releases", "enterprise_benign_baseline"),
    ("https://docs.python.org/3/library/sqlite3.html", "enterprise_benign_baseline"),
    ("https://learn.microsoft.com/en-us/azure/sentinel/overview", "enterprise_benign_baseline"),
    ("https://aws.amazon.com/security/security-bulletins/", "enterprise_benign_baseline"),
    ("https://cloudflare.com/learning/ddos/what-is-a-ddos-attack/", "enterprise_benign_baseline"),
    ("https://www.npmjs.com/package/react", "enterprise_benign_baseline"),
    ("https://stackoverflow.com/questions/tagged/cybersecurity", "enterprise_benign_baseline"),
    ("https://www.wikipedia.org/wiki/Intrusion_detection_system", "enterprise_benign_baseline"),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers", "enterprise_benign_baseline"),
    ("https://news.ycombinator.com/item?id=39841210", "enterprise_benign_baseline"),
    ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "enterprise_benign_baseline"),
    ("https://attack.mitre.org/matrices/enterprise/", "enterprise_benign_baseline"),
    ("https://nvd.nist.gov/vuln/search", "enterprise_benign_baseline"),
    ("https://www.owasp.org/index.php/Top_10-2021", "enterprise_benign_baseline"),
    ("https://registry.npmjs.org/express/-/express-4.19.2.tgz", "enterprise_benign_baseline"),
    ("https://pypi.org/project/scikit-learn/", "enterprise_benign_baseline"),
    ("https://ubuntu.com/security/notices", "enterprise_benign_baseline"),
    ("https://kubernetes.io/docs/concepts/security/", "enterprise_benign_baseline"),
    ("https://www.postgresql.org/docs/current/index.html", "enterprise_benign_baseline"),
    ("8.8.8.8", "enterprise_benign_baseline"),
    ("1.1.1.1", "enterprise_benign_baseline"),
    ("9.9.9.9", "enterprise_benign_baseline"),
    ("208.67.222.222", "enterprise_benign_baseline"),
    ("github.com", "enterprise_benign_baseline"),
    ("microsoft.com", "enterprise_benign_baseline"),
    ("cloudflare.com", "enterprise_benign_baseline"),
    ("googleapis.com", "enterprise_benign_baseline"),
    ("amazonaws.com", "enterprise_benign_baseline"),
    ("apple.com", "enterprise_benign_baseline"),
]


def load_osint_seed_iocs() -> List[Dict[str, Any]]:
    """Loads seeded OSINT IOC records for the SOC telemetry feed."""
    if SEED_IOCS_JSON_PATH.exists():
        try:
            with open(SEED_IOCS_JSON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list) and len(data) > 0:
                    return data
        except Exception:
            pass
    return [
        {
            "id": idx,
            "ioc_value": ioc,
            "ioc_type": "url" if ioc.startswith("http") else "ipv4",
            "threat_type": "malware_download",
            "tags": ["Mozi", "botnet", "elf"],
            "source_feeds": ["Abuse.ch URLHaus"],
            "status": "online",
            "first_seen": "2026-04-02T03:07:09Z",
            "last_seen": "2026-04-02T04:19:50Z",
            "sighting_count": 2,
            "feed_confidence": 88,
            "ml_malicious_prob": 0.92,
            "is_anomaly": True,
            "risk_score": 91.5,
        }
        for idx, (ioc, _) in enumerate(DEFAULT_MALICIOUS_INDICATORS[:15], start=1)
    ]


def _write_training_dataset_rows(rows_by_ioc: Dict[str, Dict[str, Any]]) -> Path:
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    fieldnames = ["sample_id", "ioc_value", "label", "class_name", "source", *FEATURE_NAMES]
    with open(TRAINING_DATASET_CSV_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for idx, rec in enumerate(rows_by_ioc.values(), start=1):
            ioc_val = rec["ioc_value"]
            lbl = 1 if int(rec.get("label", 0)) == 1 else 0
            src = str(rec.get("source") or "osint_threat_feed")
            if src.endswith((".csv", ".json")):
                if "benign" in src:
                    src = "enterprise_benign_baseline"
                elif "archetype" in src:
                    src = "malicious_archetype"
                elif "seed" in src:
                    src = "osint_threat_feed"
                else:
                    src = "analyst_active_learning"
            feats = extract_ioc_features(ioc_val)
            row = {
                "sample_id": idx,
                "ioc_value": ioc_val,
                "label": lbl,
                "class_name": "malicious" if lbl == 1 else "benign",
                "source": src,
            }
            for fn in FEATURE_NAMES:
                row[fn] = feats.get(fn, 0.0)
            writer.writerow(row)
    return TRAINING_DATASET_CSV_PATH


def ensure_unified_training_dataset_csv(
    extra_malicious_iocs: List[str] | None = None,
    extra_custom_samples: List[Dict[str, Any]] | None = None,
) -> Path:
    """
    Ensures `machine_learning/datasets/training_dataset.csv` exists as the single
    unified training dataset file and incorporates any newly added samples.
    """
    rows_by_ioc: Dict[str, Dict[str, Any]] = {}

    if TRAINING_DATASET_CSV_PATH.exists():
        try:
            with open(TRAINING_DATASET_CSV_PATH, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ioc_v = (row.get("ioc_value") or "").strip()
                    if ioc_v:
                        lbl = 1 if str(row.get("label", "0")).strip() == "1" else 0
                        rows_by_ioc[ioc_v] = {
                            "ioc_value": ioc_v,
                            "label": lbl,
                            "source": row.get("source") or ("osint_threat_feed" if lbl == 1 else "enterprise_benign_baseline"),
                        }
        except Exception:
            pass

    if not rows_by_ioc:
        for rec in load_osint_seed_iocs():
            ioc_v = (rec.get("ioc_value") or "").strip()
            if ioc_v:
                rows_by_ioc[ioc_v] = {"ioc_value": ioc_v, "label": 1, "source": "osint_threat_feed"}
        for ioc_v, src in DEFAULT_MALICIOUS_INDICATORS:
            rows_by_ioc[ioc_v] = {"ioc_value": ioc_v, "label": 1, "source": src}
        for ioc_v, src in DEFAULT_BENIGN_INDICATORS:
            rows_by_ioc[ioc_v] = {"ioc_value": ioc_v, "label": 0, "source": src}

    if extra_malicious_iocs:
        for ioc_v in extra_malicious_iocs:
            clean_v = str(ioc_v or "").strip()
            if clean_v and clean_v not in rows_by_ioc:
                rows_by_ioc[clean_v] = {"ioc_value": clean_v, "label": 1, "source": "live_osint_feed"}

    if extra_custom_samples:
        for sample in extra_custom_samples:
            clean_v = str(sample.get("ioc_value") or "").strip()
            if clean_v:
                lbl = 1 if int(sample.get("label", 0)) == 1 else 0
                rows_by_ioc[clean_v] = {
                    "ioc_value": clean_v,
                    "label": lbl,
                    "source": sample.get("source") or "analyst_active_learning",
                }

    return _write_training_dataset_rows(rows_by_ioc)


def export_unified_training_dataset_csv(
    extra_malicious_iocs: List[str] | None = None,
    extra_custom_samples: List[Dict[str, Any]] | None = None,
) -> Path:
    return ensure_unified_training_dataset_csv(
        extra_malicious_iocs=extra_malicious_iocs,
        extra_custom_samples=extra_custom_samples,
    )


def load_custom_feedback_samples() -> List[Dict[str, Any]]:
    """Returns analyst active-learning samples stored in `training_dataset.csv`."""
    ensure_unified_training_dataset_csv()
    custom: List[Dict[str, Any]] = []
    if TRAINING_DATASET_CSV_PATH.exists():
        with open(TRAINING_DATASET_CSV_PATH, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = (row.get("source") or "").strip()
                if src in ("active_learning", "analyst_dataset", "ml_studio_manual", "analyst_active_learning"):
                    custom.append(
                        {
                            "ioc_value": row.get("ioc_value", ""),
                            "label": 1 if str(row.get("label", "0")).strip() == "1" else 0,
                            "source": src,
                        }
                    )
    return custom


def append_custom_feedback_sample(
    ioc_value: str,
    label: int,
    source: str = "analyst_active_learning",
    added_by: str = "lead_analyst@threatops.io",
) -> Dict[str, Any]:
    """Appends or updates a labeled IOC directly in `machine_learning/datasets/training_dataset.csv`."""
    clean_val = str(ioc_value or "").strip()
    clean_label = 1 if int(label) == 1 else 0
    now_iso = datetime.now(timezone.utc).isoformat()

    ensure_unified_training_dataset_csv(
        extra_custom_samples=[
            {
                "ioc_value": clean_val,
                "label": clean_label,
                "source": source,
            }
        ]
    )
    custom_list = load_custom_feedback_samples()
    return {
        "ioc_value": clean_val,
        "label": clean_label,
        "source": source,
        "added_by": added_by,
        "added_at": now_iso,
        "total_custom_samples": len(custom_list),
    }


def load_combined_training_corpus(
    extra_malicious_iocs: List[str] | None = None,
    extra_custom_samples: List[Dict[str, Any]] | None = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """
    Loads the training dataset from the single CSV file:
      `machine_learning/datasets/training_dataset.csv`
    Returns (dataset_list, dataset_stats_dict).
    """
    ensure_unified_training_dataset_csv(
        extra_malicious_iocs=extra_malicious_iocs,
        extra_custom_samples=extra_custom_samples,
    )

    dataset: List[Dict[str, Any]] = []
    malicious_count = 0
    benign_count = 0
    custom_count = 0

    with open(TRAINING_DATASET_CSV_PATH, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ioc_v = (row.get("ioc_value") or "").strip()
            if not ioc_v:
                continue
            lbl = 1 if str(row.get("label", "0")).strip() == "1" else 0
            src = (row.get("source") or "").strip()
            dataset.append({"ioc": ioc_v, "label": lbl, "source": src})
            if lbl == 1:
                malicious_count += 1
            else:
                benign_count += 1
            if src in ("active_learning", "analyst_dataset", "ml_studio_manual", "analyst_active_learning"):
                custom_count += 1

    stats = {
        "total_samples": len(dataset),
        "malicious_samples": malicious_count,
        "benign_samples": benign_count,
        "custom_samples": custom_count,
    }
    return dataset, stats
