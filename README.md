# ThreatOps — Cyber Threat Intelligence & Autonomous SOC Platform (Python + Separated ML Architecture)

ThreatOps is a full-stack Cyber Threat Intelligence (CTI) and Autonomous Security Operations Center (SOC) platform with a **Python backend (`app.py`, `backend/`)** and a cleanly separated **Machine Learning package (`machine_learning/`)** containing a single unified dataset CSV in `machine_learning/datasets/` and one file per model in `machine_learning/models/`.

---

## Project Architecture

```text
├── app.py                                      # Python Backend Server (REST API + Static SPA host)
├── requirements.txt                            # Python dependencies
├── backend/                                    # Core Python Backend Services
│   ├── core_service.py                         # Central SOC orchestration, RBAC, triage, & ML Studio integration
│   ├── database.py                             # SQLite / PostgreSQL persistence layer
│   ├── osint_feeds.py                          # Live URLHaus, FeodoTracker, ThreatFox, OTX ingestion
│   ├── intel_extractor.py                      # Threat report NLP, Diamond Model, Sigma/YARA/Snort generator
│   └── soar_engine.py                          # Automated SOAR playbook dispatcher
├── machine_learning/                           # Separated Machine Learning Package (Used by ML Studio)
│   ├── ml_studio.py                            # Dedicated Python controller for Chapter 02 ML Studio
│   ├── ensemble_classifier.py                  # 4-Tier Hybrid Ensemble orchestrator
│   ├── dataset_loader.py                       # Dataset loader & active-learning updater
│   ├── feature_extractor.py                    # 18-dimensional lexical & Shannon entropy feature extractor
│   ├── train.py                                # CLI training entrypoint
│   ├── predict.py                              # CLI inference entrypoint
│   ├── engine_cli.py                           # JSON-RPC CLI bridge
│   ├── datasets/                               # Training Dataset Folder (Single CSV File)
│   │   └── training_dataset.csv                # Unified training dataset (170+ rows, 18 features + ground-truth labels)
│   └── models/                                 # Models Folder (One File Per Model)
│       ├── xgboost_model.py                    # XGBoost Gradient Boosted Decision Stumps model
│       ├── random_forest_model.py              # Random Forest Bootstrap Gini Decision Trees model
│       ├── neural_network_model.py             # 2-Layer Feedforward Neural Network (MLP) model
│       └── isolation_forest_model.py           # Isolation Forest Statistical Z-Score & Entropy Anomaly model
└── src/                                        # React 19 + Tailwind CSS v4 + Three.js SOC Console
    └── App.jsx                                 # 6-Chapter ThreatOps Interactive Console
```

---

## Running the Python ML Pipeline & Backend

1. **Train the Models & Refresh `training_dataset.csv`**:
   ```bash
   python3 machine_learning/train.py
   ```

2. **Score an IOC from the CLI**:
   ```bash
   python3 machine_learning/predict.py "http://115.55.236.110:45921/Mozi.m"
   ```

3. **Start the Python Backend Server (`app.py`)**:
   ```bash
   python3 app.py
   ```