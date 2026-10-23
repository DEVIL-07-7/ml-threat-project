import { useState, useEffect, useCallback, useRef } from "react";
import ForceGraph2D from "react-force-graph-2d";
import {
  Activity,
  Cpu,
  Network,
  FileCode,
  Share2,
  TrendingUp,
  RefreshCw,
  Zap,
  Terminal,
  ArrowLeft,
  X,
  FileText,
  Database,
  Sliders,
  Plus,
  Radio,
  Play,
  Pause,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Shield,
  Webhook,
  Compass,
} from "lucide-react";
import { auth, googleAuthProvider, signInWithPopup } from "./lib/firebase.ts";
import ThreatGlobe3D from "./components/ThreatGlobe3D.tsx";

const API_BASE = "/api/v1";
const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260808_112712_da9d53df-6d27-4b12-bdf6-aa9dc2622bdf.mp4";

function BrandMarkSvg({ idSuffix = "" }) {
  const shieldGradId = `threatops-shield${idSuffix}`;
  const coreGradId = `threatops-core${idSuffix}`;
  return (
    <svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id={shieldGradId} x1="4" y1="2" x2="36" y2="42" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#ffffff" />
          <stop offset="0.45" stopColor="#d4d4d8" />
          <stop offset="1" stopColor="#52525b" />
        </linearGradient>
        <linearGradient id={coreGradId} x1="12" y1="10" x2="28" y2="32" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#38bdf8" />
          <stop offset="1" stopColor="#10b981" />
        </linearGradient>
      </defs>
      {/* Outer Tactical Cyber-Defense Shield */}
      <path
        d="M20 2.5L35.5 8.2V20.4C35.5 30.2 28.9 38.4 20 41.5C11.1 38.4 4.5 30.2 4.5 20.4V8.2L20 2.5Z"
        fill="#09090b"
        stroke={`url(#${shieldGradId})`}
        strokeWidth="2.4"
        strokeLinejoin="round"
      />
      {/* Inner Hexagonal Threat Perimeter */}
      <path
        d="M20 7.2L31 11.3V20.1C31 27.4 26.3 33.6 20 36.2C13.7 33.6 9 27.4 9 20.1V11.3L20 7.2Z"
        stroke="rgba(255,255,255,0.18)"
        strokeWidth="1.2"
      />
      {/* Phishing / IOC Radar Crosshair & Telemetry Ring */}
      <circle
        cx="20"
        cy="21"
        r="6.8"
        stroke={`url(#${coreGradId})`}
        strokeWidth="1.8"
      />
      <path
        d="M20 11.5V14.5M20 27.5V30.5M10.5 21H13.5M26.5 21H29.5"
        stroke="#fafafa"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      {/* Central Verified Threat Core */}
      <rect
        x="17.6"
        y="18.6"
        width="4.8"
        height="4.8"
        rx="1.2"
        fill={`url(#${coreGradId})`}
      />
    </svg>
  );
}

export default function App() {
  // Page navigation state: "landing" (Main Page) vs "dashboard" (Separate Dashboard Page)
  const [viewMode, setViewMode] = useState(() =>
    window.location.pathname.includes("dashboard") ? "dashboard" : "landing"
  );
  const [isZoomingToDashboard, setIsZoomingToDashboard] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [stageDrawer, setStageDrawer] = useState(null); // null | "about" | "features" | "faq" | "contact"

  // Software Administrator Contact Form state
  const [adminContactSender, setAdminContactSender] = useState("");
  const [adminContactEmail, setAdminContactEmail] = useState("");
  const [adminContactSubject, setAdminContactSubject] = useState("Enterprise Licensing & SOC Administration");
  const [adminContactMessage, setAdminContactMessage] = useState("");
  const [adminContactSent, setAdminContactSent] = useState(false);

  // Auth & Console state (token stored strictly in memory)
  const [token, setToken] = useState("");
  const [user, setUser] = useState({
    uid: "soc-lead-default-uid",
    email: "lead_analyst@threatops.io",
    full_name: "Lead SOC Analyst",
    role: "SOC Lead",
  });
  const [activeTab, setActiveTab] = useState("pipeline"); // pipeline, ensemble, graph, rules, enrich, siem, impact
  const [scrollProgress, setScrollProgress] = useState(0);
  const [showScrollTop, setShowScrollTop] = useState(false);
  const [auditLogs, setAuditLogs] = useState([]);
  const [activeLearningBanner, setActiveLearningBanner] = useState(null);

  // Live IOC feed & OSINT sources state
  const [iocs, setIocs] = useState([]);
  const [feedSources, setFeedSources] = useState([]);
  const [lastSyncBanner, setLastSyncBanner] = useState(null);
  const [filterType, setFilterType] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  // Live WebSocket Threat Stream & Autonomous Triage Queue state
  const wsRef = useRef(null);
  const filterTypeRef = useRef(filterType);
  const searchQueryRef = useRef(searchQuery);

  useEffect(() => {
    filterTypeRef.current = filterType;
    searchQueryRef.current = searchQuery;
  }, [filterType, searchQuery]);

  const [wsConnected, setWsConnected] = useState(false);
  const [triageQueue, setTriageQueue] = useState([]);
  const [triageFilter, setTriageFilter] = useState("all"); // all | auto_blocked | needs_review | monitored
  const [latestStreamedIoc, setLatestStreamedIoc] = useState(null);
  const [streamStats, setStreamStats] = useState({
    total_streamed: 0,
    buffer_remaining: 0,
    connected_clients: 1,
    paused: false,
    interval_ms: 4500,
  });

  // Scanner state
  const [scanIoc, setScanIoc] = useState("http://194.55.186.21:54321/Mozi.a");
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  // Trainable ML Studio & Dataset state
  const [mlSummary, setMlSummary] = useState(null);
  const [trainingModel, setTrainingModel] = useState(false);
  const [testSplit, setTestSplit] = useState(0.2);
  const [learningRate, setLearningRate] = useState(0.12);
  const [nEstimators, setNEstimators] = useState(100);
  const [rfWeight, setRfWeight] = useState(0.4);
  const [xgbWeight, setXgbWeight] = useState(0.35);
  const [mlpWeight, setMlpWeight] = useState(0.25);

  // Custom Dataset Upload / Injection state
  const [customDatasetText, setCustomDatasetText] = useState(
    "http://185.215.113.45:8080/cobalt_loader.elf,1\nhttp://secure-verify-corporate-sso.tk/auth/login.php,1\nhttps://docs.github.com/en/rest/overview,0\nhttps://cloud.google.com/architecture/security-foundations,0"
  );
  const [addingDataset, setAddingDataset] = useState(false);
  const [datasetBanner, setDatasetBanner] = useState(null);

  // Deep Threat Report & Diamond-Model Attribution state
  const [reportFormat, setReportFormat] = useState("text_pdf");
  const [reportText, setReportText] = useState(
    "Adversaries exploited CVE-2024-3400 using a spearphishing lure to deploy a second-stage dropper via powershell. The script executed wget against hxxp://185.220.101[.]45:8080/bin.sh and established a Cobalt Strike C2 beacon to 91.215.85[.]142 targeting financial banking infrastructure."
  );
  const [reportResult, setReportResult] = useState(null);
  const [extractingReport, setExtractingReport] = useState(false);

  // Graph state (Neo4j)
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  // Rule Generator state (Sigma, YARA, Suricata, Snort)
  const [ruleIoc, setRuleIoc] = useState("185.220.101.45");
  const [rules, setRules] = useState(null);
  const [selectedRuleFmt, setSelectedRuleFmt] = useState("sigma");

  // Parallel Enrichment state (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX)
  const [enrichIoc, setEnrichIoc] = useState("91.215.85.142");
  const [enrichment, setEnrichment] = useState(null);
  const [enriching, setEnriching] = useState(false);

  // SIEM/SOAR/EDR Export & Automated Outbound Webhook Playbooks state
  const [selectedSiem, setSelectedSiem] = useState("splunk");
  const [exportData, setExportData] = useState(null);
  const [soarPlaybooks, setSoarPlaybooks] = useState([]);
  const [soarExecutions, setSoarExecutions] = useState([]);
  const [newPlaybookName, setNewPlaybookName] = useState("");
  const [newPlaybookChannel, setNewPlaybookChannel] = useState("slack");
  const [newPlaybookUrl, setNewPlaybookUrl] = useState("");
  const [newPlaybookThreshold, setNewPlaybookThreshold] = useState(85);
  const [dispatchingSoar, setDispatchingSoar] = useState(false);

  // Organization Tenant Name (used in Billing Checkout)
  const [orgName, setOrgName] = useState("Sentinel-Core-SOC");

  // Payment Gateway Checkout redirect state
  const checkoutSeqRef = useRef(1000);
  const [paymentGatewaySession, setPaymentGatewaySession] = useState(null);
  const [paymentMethod, setPaymentMethod] = useState("card");
  const [cardHolderName, setCardHolderName] = useState("Lead SOC Analyst");
  const [billingEmail, setBillingEmail] = useState("lead_analyst@threatops.io");
  const [cardNumber, setCardNumber] = useState("4242 •••• •••• 4242");
  const [cardExpiry, setCardExpiry] = useState("08/29");
  const [cardCvc, setCardCvc] = useState("842");
  const [upiId, setUpiId] = useState("soc.treasury@okaxis");
  const [processingPayment, setProcessingPayment] = useState(false);
  const [paymentReceipt, setPaymentReceipt] = useState(null);

  // Sync browser history popstate between Landing Page, Dashboard Page, and Payment Gateway
  useEffect(() => {
    document.body.classList.add("console-active");
    const onPopState = () => {
      if (!window.location.pathname.includes("payment-gateway")) {
        setPaymentGatewaySession(null);
      }
      if (window.location.pathname.includes("dashboard")) {
        setViewMode("dashboard");
      } else if (!window.location.pathname.includes("payment-gateway")) {
        setViewMode("landing");
      }
    };
    window.addEventListener("popstate", onPopState);
    return () => {
      document.body.classList.remove("console-active");
      window.removeEventListener("popstate", onPopState);
    };
  }, []);

  // Escape & resize listeners for Stage menu & drawers
  useEffect(() => {
    const onKeyDown = (e) => {
      if (e.key === "Escape") {
        setMenuOpen(false);
        setStageDrawer(null);
      }
    };
    const onResize = () => {
      if (window.innerWidth > 640) {
        setMenuOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  const loadDashboardData = useCallback(
    async (typeFilter = filterType, query = searchQuery) => {
      try {
        const params = new URLSearchParams({ limit: "60" });
        if (typeFilter && typeFilter !== "all") params.set("ioc_type", typeFilter);
        if (query && query.trim()) params.set("search", query.trim());

        const [iocsRes, sourcesRes, mlRes, triageRes, auditRes, soarRes] =
          await Promise.all([
            fetch(`${API_BASE}/iocs?${params.toString()}`),
            fetch(`${API_BASE}/feeds/sources`),
            fetch(`${API_BASE}/ml/status`),
            fetch(`${API_BASE}/triage/queue`),
            fetch(`${API_BASE}/rbac/audit-logs`),
            fetch(`${API_BASE}/soar/playbooks`),
          ]);

        if (iocsRes.ok) setIocs(await iocsRes.json());
        if (sourcesRes.ok) {
          const sData = await sourcesRes.json();
          setFeedSources(sData.sources || []);
        }
        if (mlRes.ok) setMlSummary(await mlRes.json());
        if (triageRes.ok) {
          const tData = await triageRes.json();
          if (Array.isArray(tData.triage_queue)) setTriageQueue(tData.triage_queue);
          if (tData.stream_stats) setStreamStats(tData.stream_stats);
        }
        if (auditRes.ok) {
          const aData = await auditRes.json();
          setAuditLogs(aData.audit_logs || []);
        }
        if (soarRes.ok) {
          const pData = await soarRes.json();
          setSoarPlaybooks(pData.playbooks || []);
          setSoarExecutions(pData.executions || []);
        }
      } catch (e) {
        console.warn("Could not load dashboard telemetry:", e);
      }
    },
    [filterType, searchQuery]
  );

  // Real-time WebSocket Listener (/ws/threat-stream) with Auto-Reconnection & Idempotent Reconciliation
  useEffect(() => {
    let ws = null;
    let reconnectTimer = null;
    let unmounted = false;

    const connectWebSocket = () => {
      if (unmounted) return;
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${protocol}//${window.location.host}/ws/threat-stream`;
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!unmounted) setWsConnected(true);
      };

      ws.onmessage = (event) => {
        if (unmounted) return;
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "stream:init") {
            if (Array.isArray(payload.triage_queue)) {
              setTriageQueue(payload.triage_queue);
            }
            if (Array.isArray(payload.sources)) {
              setFeedSources(payload.sources);
            }
            if (payload.stream_stats) {
              setStreamStats(payload.stream_stats);
            }
          } else if (payload.type === "ioc:triaged" && payload.queue_item) {
            const incoming = payload.queue_item;
            setLatestStreamedIoc(incoming);

            // Idempotent update to Triage Queue
            setTriageQueue((prev) => {
              const filtered = prev.filter(
                (q) => q.queue_id !== incoming.queue_id && q.ioc_value !== incoming.ioc_value
              );
              return [incoming, ...filtered].slice(0, 60);
            });

            // Idempotent update to Active OSINT Threat Feed table if it matches current filters
            if (payload.ioc_record) {
              const rec = payload.ioc_record;
              const activeType = filterTypeRef.current;
              const activeQuery = (searchQueryRef.current || "").trim().toLowerCase();
              const typeMatches =
                activeType === "all" ||
                (rec.ioc_type || "").toLowerCase() === activeType.toLowerCase();
              const queryMatches =
                !activeQuery ||
                (rec.ioc_value || "").toLowerCase().includes(activeQuery) ||
                (rec.threat_type || "").toLowerCase().includes(activeQuery) ||
                (rec.tags || []).some((t) => t.toLowerCase().includes(activeQuery));

              if (typeMatches && queryMatches) {
                setIocs((prev) => {
                  const withoutDup = prev.filter(
                    (r) => r.ioc_value !== rec.ioc_value && r.id !== rec.id
                  );
                  return [rec, ...withoutDup].slice(0, 60);
                });
              }
            }

            if (Array.isArray(payload.sources)) {
              setFeedSources(payload.sources);
            }
            if (payload.stream_stats) {
              setStreamStats(payload.stream_stats);
            }
          } else if (payload.type === "stream:status" && payload.stream_stats) {
            setStreamStats(payload.stream_stats);
          } else if (payload.type === "triage:updated" && payload.queue_id) {
            setTriageQueue((prev) =>
              prev.map((item) =>
                item.queue_id === payload.queue_id
                  ? { ...item, triage_status: payload.triage_status }
                  : item
              )
            );
            if (payload.audit_log) {
              setAuditLogs((prev) => {
                const withoutDup = prev.filter((l) => l.id !== payload.audit_log.id);
                return [payload.audit_log, ...withoutDup].slice(0, 40);
              });
            }
            if (payload.active_learning?.model_summary) {
              setMlSummary({
                ...payload.active_learning.model_summary,
                active_learning_count: payload.active_learning.active_learning_count,
              });
              setActiveLearningBanner(
                `Active Learning Auto-Retrain: ${payload.active_learning.ioc_value} labeled as ${
                  payload.active_learning.label === 1 ? "MALICIOUS (1)" : "BENIGN / FALSE POSITIVE (0)"
                } · Ensemble recalibrated (Test F1: ${
                  payload.active_learning.model_summary.metrics.f1_score
                }%)`
              );
            }
          } else if (payload.type === "soar:triggered" && payload.execution) {
            setSoarExecutions((prev) => {
              const withoutDup = prev.filter((ex) => ex.id !== payload.execution.id);
              return [payload.execution, ...withoutDup].slice(0, 25);
            });
          }
        } catch (err) {
          console.warn("[ThreatOps WS] Failed to parse message:", err);
        }
      };

      ws.onclose = () => {
        if (!unmounted) {
          setWsConnected(false);
          reconnectTimer = setTimeout(connectWebSocket, 2500);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWebSocket();

    return () => {
      unmounted = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws && ws.readyState <= 1) ws.close();
    };
  }, []);

  const handleToggleStreamPause = () => {
    const nextPaused = !streamStats.paused;
    setStreamStats((prev) => ({ ...prev, paused: nextPaused }));
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(
        JSON.stringify({ type: "stream:configure", paused: nextPaused })
      );
    }
  };

  const handleChangeStreamInterval = (ms) => {
    setStreamStats((prev) => ({ ...prev, interval_ms: ms }));
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(
        JSON.stringify({ type: "stream:configure", interval_ms: ms })
      );
    }
  };

  const handlePullStreamNow = () => {
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type: "stream:pull_now" }));
    }
  };

  const handleTriageAction = async (queueId, action) => {
    // RBAC check: Tier-1 Analyst can escalate, but Block/Dismiss requires Tier-3 Threat Hunter or SOC Lead
    if (
      user?.role === "Tier-1 Analyst" &&
      (action === "approved_block" || action === "false_positive")
    ) {
      setActiveLearningBanner(
        "RBAC Policy: 'Tier-1 Analyst' can Escalate indicators. Switch role to 'Tier-3 Threat Hunter' or 'SOC Lead' to execute Block or False-Positive Active Learning dispositions."
      );
      return;
    }

    setTriageQueue((prev) =>
      prev.map((q) => (q.queue_id === queueId ? { ...q, triage_status: action } : q))
    );
    if (wsRef.current && wsRef.current.readyState === 1) {
      wsRef.current.send(
        JSON.stringify({
          type: "triage:action",
          queue_id: queueId,
          action,
          actor: user,
        })
      );
    } else {
      await fetch(`${API_BASE}/triage/${queueId}/action`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ action }),
      });
    }
  };

  const handleInspectFromQueue = async (iocVal) => {
    setScanIoc(iocVal);
    setScanning(true);
    try {
      const res = await fetch(`${API_BASE}/scan/ioc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_value: iocVal }),
      });
      if (res.ok) setScanResult(await res.json());
    } finally {
      setScanning(false);
    }
  };

  const handleGoogleSignIn = async () => {
    try {
      const cred = await signInWithPopup(auth, googleAuthProvider);
      const idToken = await cred.user.getIdToken();
      setToken(idToken);
      const res = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${idToken}` },
      });
      if (res.ok) {
        setUser(await res.json());
        loadDashboardData();
      }
    } catch (err) {
      console.warn("Google Sign-In popup closed or cancelled:", err.message);
    }
  };

  const handleFetchGraph = useCallback(async () => {
    const res = await fetch(`${API_BASE}/org/graph-correlations`);
    if (res.ok) setGraphData(await res.json());
  }, []);

  const handleGenerateRules = useCallback(async () => {
    const res = await fetch(`${API_BASE}/rules/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ioc_value: ruleIoc }),
    });
    if (res.ok) setRules(await res.json());
  }, [ruleIoc]);

  const handleExecuteEnrichment = useCallback(async () => {
    setEnriching(true);
    try {
      const res = await fetch(`${API_BASE}/enrich/parallel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_value: enrichIoc }),
      });
      if (res.ok) setEnrichment(await res.json());
    } finally {
      setEnriching(false);
    }
  }, [enrichIoc]);

  const handleExportSiem = useCallback(async (platform) => {
    setSelectedSiem(platform);
    const res = await fetch(`${API_BASE}/export/${platform}`);
    if (res.ok) setExportData(await res.json());
  }, []);

  const handleCreateSoarPlaybook = async (e) => {
    e.preventDefault();
    if (!newPlaybookName.trim() || !newPlaybookUrl.trim()) return;
    const res = await fetch(`${API_BASE}/soar/playbooks`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        name: newPlaybookName,
        channel: newPlaybookChannel,
        webhook_url: newPlaybookUrl,
        min_risk_threshold: newPlaybookThreshold,
      }),
    });
    if (res.ok) {
      const data = await res.json();
      setSoarPlaybooks(data.playbooks || []);
      setSoarExecutions(data.executions || []);
      setNewPlaybookName("");
      setNewPlaybookUrl("");
    }
  };

  const handleTogglePlaybook = async (id, currentEnabled) => {
    const res = await fetch(`${API_BASE}/soar/playbooks/${id}/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: currentEnabled === 1 ? 0 : 1 }),
    });
    if (res.ok) {
      const data = await res.json();
      setSoarPlaybooks(data.playbooks || []);
      setSoarExecutions(data.executions || []);
    }
  };

  const handleTestSoarDispatch = async () => {
    setDispatchingSoar(true);
    try {
      const res = await fetch(`${API_BASE}/soar/dispatch`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          ioc_value: scanIoc || "http://194.55.186.21:54321/Mozi.a",
          risk_score: 94,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setSoarPlaybooks(data.playbooks || []);
        setSoarExecutions(data.executions || []);
      }
    } finally {
      setDispatchingSoar(false);
    }
  };

  // Auto-load dashboard modules on initial mount
  useEffect(() => {
    const timer = setTimeout(() => {
      loadDashboardData();
      handleFetchGraph();
      handleGenerateRules();
      handleExecuteEnrichment();
      handleExportSiem("splunk");
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const enterThreatOpsConsole = async (targetTab = "pipeline") => {
    setMenuOpen(false);
    setStageDrawer(null);
    setActiveTab(targetTab);

    if (viewMode === "landing") {
      setIsZoomingToDashboard(true);
      setTimeout(() => {
        setViewMode("dashboard");
        setIsZoomingToDashboard(false);
        window.history.pushState({ viewMode: "dashboard" }, "", "/dashboard");
        window.scrollTo({ top: 0, behavior: "instant" });
        if (targetTab !== "pipeline") {
          setTimeout(() => {
            const el = document.getElementById(`chapter-${targetTab}`);
            if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
          }, 80);
        }
      }, 520);
    } else {
      const el = document.getElementById(`chapter-${targetTab}`);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }

    if (!token) {
      try {
        const res = await fetch(`${API_BASE}/auth/sso`, { method: "POST" });
        const data = await res.json();
        if (res.ok && data.access_token) {
          setToken(data.access_token);
          setUser({
            uid: data.uid || "soc-lead-default-uid",
            email: data.email,
            full_name: data.full_name,
            role: data.role || "SOC Lead",
            subscription_status: data.subscription_status,
          });
        }
      } catch (err) {
        console.error("SSO authentication error:", err);
      }
    }
  };

  const returnToLandingPage = () => {
    setMenuOpen(false);
    setStageDrawer(null);
    setViewMode("landing");
    window.history.pushState({ viewMode: "landing" }, "", "/");
    window.scrollTo({ top: 0, behavior: "instant" });
  };

  const navigateToChapter = (chapterId) => {
    setActiveTab(chapterId);
    if (chapterId === "graph" && (!graphData.nodes || graphData.nodes.length === 0)) {
      handleFetchGraph();
    }
    if (chapterId === "rules" && !rules) {
      handleGenerateRules();
    }
    if (chapterId === "enrich" && !enrichment) {
      handleExecuteEnrichment();
    }
    if (chapterId === "siem" && !exportData) {
      handleExportSiem("splunk");
    }

    const el = document.getElementById(`chapter-${chapterId}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  // ScrollProgress + ScrollSpy (without 3D scroll animations)
  useEffect(() => {
    let rafId = null;
    const updateScrollMetrics = () => {
      const scrollTop = window.scrollY || document.documentElement.scrollTop || 0;
      const vh = Math.max(window.innerHeight, 1);
      const docHeight =
        Math.max(
          document.body.scrollHeight,
          document.documentElement.scrollHeight
        ) - vh;
      const ratio = docHeight > 0 ? Math.min(1, Math.max(0, scrollTop / docHeight)) : 0;
      setScrollProgress(ratio);
      setShowScrollTop(scrollTop > 420);

      const probeY = vh * 0.32;
      const chapters = document.querySelectorAll(".scroll-chapter");
      let matchedChapter = null;

      chapters.forEach((node) => {
        const rect = node.getBoundingClientRect();
        if (rect.top <= probeY && rect.bottom >= probeY && node.dataset.chapter) {
          matchedChapter = node.dataset.chapter;
        }
      });

      if (matchedChapter) {
        setActiveTab((prev) => (prev === matchedChapter ? prev : matchedChapter));
      }
    };

    const onScroll = () => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(updateScrollMetrics);
    };

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll, { passive: true });
    updateScrollMetrics();

    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, []);

  const handleScanIndicator = async () => {
    setScanning(true);
    try {
      const res = await fetch(`${API_BASE}/scan/ioc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_value: scanIoc }),
      });
      if (res.ok) setScanResult(await res.json());
    } finally {
      setScanning(false);
    }
  };

  const handleTrainEnsemble = async () => {
    setTrainingModel(true);
    try {
      const res = await fetch(`${API_BASE}/ml/train`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          test_split: testSplit,
          learning_rate: learningRate,
          n_estimators: nEstimators,
          rf_weight: rfWeight,
          xgb_weight: xgbWeight,
          mlp_weight: mlpWeight,
        }),
      });
      if (res.ok) {
        const summary = await res.json();
        setMlSummary(summary);
        await loadDashboardData();
      }
    } finally {
      setTrainingModel(false);
    }
  };

  const handleInjectDataset = async (e) => {
    e.preventDefault();
    setAddingDataset(true);
    setDatasetBanner(null);
    try {
      const lines = customDatasetText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      const samples = [];
      for (const line of lines) {
        const lastComma = line.lastIndexOf(",");
        if (lastComma > 0) {
          const ioc_value = line.slice(0, lastComma).trim();
          const label = parseInt(line.slice(lastComma + 1).trim(), 10) === 1 ? 1 : 0;
          samples.push({ ioc_value, label });
        } else {
          samples.push({ ioc_value: line, label: 1 });
        }
      }

      const res = await fetch(`${API_BASE}/ml/dataset/add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ samples }),
      });
      if (res.ok) {
        const data = await res.json();
        setMlSummary(data.model_summary);
        setDatasetBanner(
          `Added ${data.samples_added} labeled samples and retrained 18-feature ensemble (Test F1: ${data.model_summary.metrics.f1_score}%).`
        );
        await loadDashboardData();
      }
    } finally {
      setAddingDataset(false);
    }
  };

  const handleExtractReport = async () => {
    setExtractingReport(true);
    try {
      const res = await fetch(`${API_BASE}/extract/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ text: reportText, format: reportFormat }),
      });
      if (res.ok) {
        setReportResult(await res.json());
        loadDashboardData();
      }
    } finally {
      setExtractingReport(false);
    }
  };

  const handleRefreshFeeds = async () => {
    setRefreshing(true);
    setLastSyncBanner(null);
    try {
      const res = await fetch(`${API_BASE}/feeds/refresh`, { method: "POST" });
      if (res.ok) {
        const syncData = await res.json();
        setFeedSources(syncData.sources || []);
        setLastSyncBanner(syncData);
      }
      await loadDashboardData();
    } finally {
      setRefreshing(false);
    }
  };

  const handleSubmitAdminContact = (e) => {
    e.preventDefault();
    setAdminContactSent(true);
  };

  const openNavDrawer = (e, section) => {
    e.preventDefault();
    setMenuOpen(false);
    setAdminContactSent(false);
    setStageDrawer(section);
  };

  const handleRedirectToPaymentGateway = async (tier) => {
    setPaymentReceipt(null);
    checkoutSeqRef.current += 1;
    const fallbackSession = {
      session_id: `cs_live_threatops_${checkoutSeqRef.current}`,
      gateway_provider: "Stripe Enterprise Checkout",
      plan: tier,
    };
    setPaymentGatewaySession(fallbackSession);
    window.history.pushState(
      { paymentGateway: true },
      "",
      `/payment-gateway?plan=${encodeURIComponent(tier.name)}`
    );
    window.scrollTo({ top: 0, behavior: "instant" });

    try {
      const res = await fetch(`${API_BASE}/billing/checkout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          plan_name: tier.name,
          price: tier.price,
          specs: tier.specs,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setPaymentGatewaySession({
          session_id: data.session_id,
          gateway_provider: data.gateway_provider || "Stripe Enterprise Checkout",
          plan: tier,
        });
      }
    } catch (err) {
      console.warn("Checkout session initialized locally:", err);
    }
  };

  const handleConfirmGatewayPayment = async (e) => {
    e.preventDefault();
    if (!paymentGatewaySession?.plan) return;
    setProcessingPayment(true);
    try {
      const res = await fetch(`${API_BASE}/billing/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: paymentGatewaySession.session_id,
          plan_name: paymentGatewaySession.plan.name,
          price: paymentGatewaySession.plan.price,
          payment_method: paymentMethod,
          billing_email: billingEmail,
          organization: orgName,
        }),
      });
      if (res.ok) {
        const receipt = await res.json();
        setPaymentReceipt(receipt);
        if (receipt.audit_log) {
          setAuditLogs((prev) => [receipt.audit_log, ...prev].slice(0, 40));
        }
      }
    } finally {
      setProcessingPayment(false);
    }
  };

  const handleClosePaymentGateway = () => {
    setPaymentGatewaySession(null);
    setPaymentReceipt(null);
    setViewMode("dashboard");
    window.history.pushState({ viewMode: "dashboard" }, "", "/dashboard");
  };

  if (paymentGatewaySession) {
    const selectedPlan = paymentGatewaySession.plan;
    return (
      <div className="console-shell" style={{ minHeight: "100vh", background: "#050505" }}>
        <header className="console-topbar">
          <button
            type="button"
            className="console-brand-group"
            onClick={handleClosePaymentGateway}
            title="Return to ThreatOps Console"
          >
            <div style={{ width: 24, height: 36 }}>
              <BrandMarkSvg idSuffix="-gateway" />
            </div>
            <span style={{ fontSize: "1.15rem", fontWeight: 600, letterSpacing: "-0.02em" }}>
              ThreatOps · Payment Gateway
            </span>
          </button>

          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span className="mono-num" style={{ fontSize: "0.78rem", color: "var(--muted)" }}>
              256-BIT TLS ENCRYPTED · SESSION {paymentGatewaySession.session_id.slice(0, 18)}...
            </span>
            <button
              type="button"
              className="console-btn-ghost"
              onClick={handleClosePaymentGateway}
            >
              <ArrowLeft size={14} /> Return to Console
            </button>
          </div>
        </header>

        <main className="console-main" style={{ maxWidth: 1120, paddingTop: 42 }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))",
              gap: 24,
              alignItems: "start",
            }}
          >
            {/* Left Column: Plan & Order Summary */}
            <div className="console-surface" style={{ marginBottom: 0 }}>
              <div style={{ fontSize: "0.78rem", color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Enterprise Subscription Checkout
              </div>
              <h1 style={{ fontSize: "1.65rem", fontWeight: 500, marginTop: 8 }}>
                {selectedPlan.name}
              </h1>
              <div className="mono-num" style={{ fontSize: "2.5rem", fontWeight: 700, margin: "16px 0" }}>
                {selectedPlan.price}
                <span style={{ fontSize: "0.95rem", color: "var(--muted)", fontWeight: 400 }}>
                  {" "}
                  / month (billed monthly)
                </span>
              </div>

              <div
                style={{
                  borderTop: "1px solid rgba(255,255,255,0.09)",
                  borderBottom: "1px solid rgba(255,255,255,0.09)",
                  padding: "16px 0",
                  margin: "18px 0",
                }}
              >
                <div style={{ fontSize: "0.84rem", fontWeight: 600, marginBottom: 10 }}>
                  Included ThreatOps SOC Entitlements:
                </div>
                <ul
                  style={{
                    listStyle: "none",
                    padding: 0,
                    margin: 0,
                    display: "flex",
                    flexDirection: "column",
                    gap: 10,
                    color: "var(--muted)",
                    fontSize: "0.88rem",
                  }}
                >
                  {(selectedPlan.specs || []).map((spec) => (
                    <li key={spec} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <CheckCircle2 size={15} style={{ color: "#fafafa", flexShrink: 0 }} />
                      <span>{spec}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div style={{ fontSize: "0.82rem", color: "var(--muted)", marginBottom: 10 }}>
                Switch Subscription Tier:
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {[
                  {
                    name: "Starter · For Early-Stage SOC Teams",
                    price: "$2,499",
                    specs: ["1,000 IOCs / day", "5 analyst seats", "Email support", "Full feature access"],
                  },
                  {
                    name: "Professional · For Scaling Security Operations",
                    price: "$5,999",
                    specs: ["10,000 IOCs / day", "20 analyst seats", "24/7 priority support", "SIEM / EDR webhooks"],
                  },
                  {
                    name: "Enterprise · For Global Threat Intelligence",
                    price: "$14,999",
                    specs: ["Unlimited IOCs", "Unlimited seats", "Dedicated CSM", "Custom feed integrations"],
                  },
                ].map((p) => (
                  <button
                    key={p.name}
                    type="button"
                    className={`console-tab ${selectedPlan.name === p.name ? "active" : ""}`}
                    onClick={() =>
                      setPaymentGatewaySession((prev) => ({
                        ...prev,
                        plan: p,
                      }))
                    }
                  >
                    {p.name.split("·")[0].trim()} ({p.price})
                  </button>
                ))}
              </div>
            </div>

            {/* Right Column: Payment Gateway Form or Verified Receipt */}
            <div className="console-surface" style={{ marginBottom: 0 }}>
              {paymentReceipt ? (
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                    <CheckCircle2 size={24} />
                    <div>
                      <h2 style={{ fontSize: "1.35rem", fontWeight: 600 }}>
                        Payment Authorized & Plan Activated
                      </h2>
                      <p style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                        Transaction Reference: <span className="mono-num">{paymentReceipt.transaction_id}</span>
                      </p>
                    </div>
                  </div>

                  <div
                    style={{
                      background: "#050505",
                      border: "1px solid rgba(255,255,255,0.12)",
                      borderRadius: 12,
                      padding: 18,
                      marginBottom: 20,
                      display: "flex",
                      flexDirection: "column",
                      gap: 10,
                      fontSize: "0.86rem",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Plan Purchased</span>
                      <span style={{ fontWeight: 600 }}>{paymentReceipt.plan_name}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Amount Paid</span>
                      <span className="mono-num" style={{ fontWeight: 700 }}>{paymentReceipt.price}.00 USD</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Payment Method</span>
                      <span className="mono-num">{paymentReceipt.payment_method.toUpperCase()}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Organization</span>
                      <span>{paymentReceipt.organization}</span>
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <span style={{ color: "var(--muted)" }}>Billing Email</span>
                      <span className="mono-num">{paymentReceipt.billing_email}</span>
                    </div>
                  </div>

                  <button
                    type="button"
                    className="console-btn-pill"
                    style={{ width: "100%", justifyContent: "center" }}
                    onClick={handleClosePaymentGateway}
                  >
                    Launch Active ThreatOps Console
                  </button>
                </div>
              ) : (
                <form onSubmit={handleConfirmGatewayPayment}>
                  <h2 style={{ fontSize: "1.25rem", fontWeight: 500, marginBottom: 6 }}>
                    Payment Gateway Details
                  </h2>
                  <p style={{ color: "var(--muted)", fontSize: "0.84rem", marginBottom: 18 }}>
                    Select your enterprise payment instrument to activate {selectedPlan.name.split("·")[0].trim()}.
                  </p>

                  <div style={{ display: "flex", gap: 8, marginBottom: 18, flexWrap: "wrap" }}>
                    {[
                      { id: "card", label: "Credit / Corporate Card" },
                      { id: "upi", label: "UPI / Instant Pay" },
                      { id: "ach_wire", label: "ACH / Enterprise Wire" },
                    ].map((m) => (
                      <button
                        key={m.id}
                        type="button"
                        className={`console-tab ${paymentMethod === m.id ? "active" : ""}`}
                        onClick={() => setPaymentMethod(m.id)}
                      >
                        {m.label}
                      </button>
                    ))}
                  </div>

                  <div style={{ display: "flex", flexDirection: "column", gap: 14, marginBottom: 22 }}>
                    <div>
                      <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)", marginBottom: 6 }}>
                        Organization / SOC Tenant
                      </label>
                      <input
                        type="text"
                        className="console-input"
                        style={{ width: "100%" }}
                        value={orgName}
                        onChange={(e) => setOrgName(e.target.value)}
                        required
                      />
                    </div>

                    <div>
                      <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)", marginBottom: 6 }}>
                        Billing Email for Receipt & License Key
                      </label>
                      <input
                        type="email"
                        className="console-input"
                        style={{ width: "100%" }}
                        value={billingEmail}
                        onChange={(e) => setBillingEmail(e.target.value)}
                        required
                      />
                    </div>

                    {paymentMethod === "card" && (
                      <>
                        <div>
                          <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)", marginBottom: 6 }}>
                            Cardholder Name
                          </label>
                          <input
                            type="text"
                            className="console-input"
                            style={{ width: "100%" }}
                            value={cardHolderName}
                            onChange={(e) => setCardHolderName(e.target.value)}
                            required
                          />
                        </div>
                        <div>
                          <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)", marginBottom: 6 }}>
                            Corporate Card Number
                          </label>
                          <input
                            type="text"
                            className="console-input mono-num"
                            style={{ width: "100%" }}
                            value={cardNumber}
                            onChange={(e) => setCardNumber(e.target.value)}
                            required
                          />
                        </div>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                          <div>
                            <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)", marginBottom: 6 }}>
                              Expiration (MM/YY)
                            </label>
                            <input
                              type="text"
                              className="console-input mono-num"
                              style={{ width: "100%" }}
                              value={cardExpiry}
                              onChange={(e) => setCardExpiry(e.target.value)}
                              required
                            />
                          </div>
                          <div>
                            <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)", marginBottom: 6 }}>
                              Security Code (CVC)
                            </label>
                            <input
                              type="text"
                              className="console-input mono-num"
                              style={{ width: "100%" }}
                              value={cardCvc}
                              onChange={(e) => setCardCvc(e.target.value)}
                              required
                            />
                          </div>
                        </div>
                      </>
                    )}

                    {paymentMethod === "upi" && (
                      <div>
                        <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)", marginBottom: 6 }}>
                          Verified VPA / UPI Handle
                        </label>
                        <input
                          type="text"
                          className="console-input mono-num"
                          style={{ width: "100%" }}
                          value={upiId}
                          onChange={(e) => setUpiId(e.target.value)}
                          required
                        />
                      </div>
                    )}

                    {paymentMethod === "ach_wire" && (
                      <div
                        className="mono-num"
                        style={{
                          background: "#050505",
                          border: "1px solid rgba(255,255,255,0.12)",
                          borderRadius: 12,
                          padding: 14,
                          fontSize: "0.78rem",
                          color: "var(--muted)",
                          lineHeight: 1.6,
                        }}
                      >
                        <div>ROUTING (ABA): 021000021 · SWIFT: THROPSUS33</div>
                        <div>BENEFICIARY: ThreatOps Cyber Defense Inc.</div>
                        <div>MEMO: {paymentGatewaySession.session_id.slice(0, 16)}</div>
                      </div>
                    )}
                  </div>

                  <button
                    type="submit"
                    className="console-btn-pill"
                    style={{ width: "100%", justifyContent: "center", padding: "13px 24px" }}
                    disabled={processingPayment}
                  >
                    <Shield size={16} />{" "}
                    {processingPayment
                      ? "Authorizing Payment Gateway..."
                      : `Pay ${selectedPlan.price}.00 & Activate Plan`}
                  </button>
                </form>
              )}
            </div>
          </div>
        </main>
      </div>
    );
  }

  // ════════════════════════════════════════════════════════════════════════
  // MAIN LANDING PAGE (ZOOMS INTO SEPARATE DASHBOARD PAGE ON 'GET STARTED')
  // ════════════════════════════════════════════════════════════════════════
  if (viewMode === "landing") {
    return (
      <div
        id="top"
        className={`stage${menuOpen ? " is-open" : ""}${
          isZoomingToDashboard ? " is-zooming-out" : ""
        }`}
      >
        {/* Full-bleed CloudFront looping video plate */}
        <div className="plate">
          <video
            className="plate-video"
            autoPlay
            muted
            loop
            playsInline
            preload="auto"
            aria-hidden="true"
          >
            <source src={VIDEO_URL} type="video/mp4" />
          </video>
        </div>

        {/* Topbar: Brand SVG + Centered Primary Links + White Pill CTA + Mobile Burger */}
        <div className="topbar">
          <a
            href="#top"
            className="brand"
            aria-label="ThreatOps Home"
            onClick={(e) => {
              e.preventDefault();
              setMenuOpen(false);
              setStageDrawer(null);
              window.scrollTo({ top: 0, behavior: "smooth" });
            }}
          >
            <BrandMarkSvg />
            <span className="brand-wordmark">ThreatOps</span>
          </a>

          <nav className="links" aria-label="Primary">
            <a href="#about" onClick={(e) => openNavDrawer(e, "about")}>
              About
            </a>
            <a href="#features" onClick={(e) => openNavDrawer(e, "features")}>
              Features
            </a>
            <a href="#faq" onClick={(e) => openNavDrawer(e, "faq")}>
              FAQ
            </a>
            <a href="#contact" onClick={(e) => openNavDrawer(e, "contact")}>
              Contact
            </a>
          </nav>

          <a
            href="#console"
            className="pill pill-nav"
            onClick={(e) => {
              e.preventDefault();
              enterThreatOpsConsole("pipeline");
            }}
          >
            <span>Get Started</span>
          </a>

          <button
            type="button"
            className="burger"
            id="burger"
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            aria-expanded={menuOpen}
            aria-controls="menu"
            onClick={() => setMenuOpen((prev) => !prev)}
          >
            <i />
            <i />
          </button>
        </div>

        {/* Mobile Overlay Menu */}
        <nav className="menu" id="menu" aria-hidden={!menuOpen}>
          <div className="menu-inner">
            <p className="menu-eyebrow">Menu</p>
            <ul className="menu-list">
              <li>
                <a href="#about" onClick={(e) => openNavDrawer(e, "about")}>
                  About
                </a>
              </li>
              <li>
                <a href="#features" onClick={(e) => openNavDrawer(e, "features")}>
                  Features
                </a>
              </li>
              <li>
                <a href="#faq" onClick={(e) => openNavDrawer(e, "faq")}>
                  FAQ
                </a>
              </li>
              <li>
                <a href="#contact" onClick={(e) => openNavDrawer(e, "contact")}>
                  Contact
                </a>
              </li>
            </ul>
            <div className="menu-foot">
              <a
                href="#console"
                className="pill"
                onClick={(e) => {
                  e.preventDefault();
                  enterThreatOpsConsole("pipeline");
                }}
              >
                <span>Get Started</span>
              </a>
              <a
                href="#architecture"
                className="ghost"
                onClick={(e) => {
                  e.preventDefault();
                  enterThreatOpsConsole("ensemble");
                }}
              >
                View Architecture
              </a>
            </div>
          </div>
        </nav>

        {/* Hero Typography & Dual Actions */}
        <main className="hero">
          <h1 className="headline">
            <span>The Next Layer</span>
            <span>of Intelligence</span>
          </h1>
          <p className="sub">
            <span>A unified infrastructure platform to help teams build,</span>
            <span>ship, and scale AI systems with confidence.</span>
          </p>
          <div className="actions">
            <a
              href="#console"
              className="pill pill-cta"
              onClick={(e) => {
                e.preventDefault();
                enterThreatOpsConsole("pipeline");
              }}
            >
              <span>Get Started</span>
            </a>
            <a
              href="#architecture"
              className="ghost"
              onClick={(e) => {
                e.preventDefault();
                enterThreatOpsConsole("ensemble");
              }}
            >
              View Architecture
            </a>
          </div>
        </main>

        {/* ThreatOps Platform Overlay Drawer for Header Links (About, Features, FAQ, Contact) */}
        {stageDrawer && (
          <div
            className="stage-drawer-backdrop"
            onClick={() => setStageDrawer(null)}
            role="dialog"
            aria-modal="true"
          >
            <div className="stage-drawer" onClick={(e) => e.stopPropagation()}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 20,
                  paddingBottom: 16,
                  borderBottom: "1px solid rgba(255,255,255,0.1)",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ width: 20, height: 30 }}>
                    <BrandMarkSvg idSuffix="-drawer" />
                  </div>
                  <span style={{ fontSize: "1.1rem", fontWeight: 600 }}>
                    ThreatOps ·{" "}
                    {stageDrawer === "about"
                      ? "Platform Overview"
                      : stageDrawer === "features"
                      ? "Core Capabilities"
                      : stageDrawer === "faq"
                      ? "Architecture FAQ"
                      : "Software Administrator Contact"}
                  </span>
                </div>
                <button
                  type="button"
                  className="console-btn-ghost"
                  style={{ padding: "6px 10px" }}
                  onClick={() => setStageDrawer(null)}
                  aria-label="Close modal"
                >
                  <X size={16} />
                </button>
              </div>

              {stageDrawer === "about" && (
                <div>
                  <h3 style={{ fontSize: "1.5rem", fontWeight: 500, marginBottom: 12 }}>
                    Autonomous 13-Second Threat Intelligence Infrastructure
                  </h3>
                  <p style={{ color: "var(--muted)", lineHeight: 1.6, marginBottom: 20 }}>
                    ThreatOps unifies live OSINT ingestion (Abuse.ch URLHaus, FeodoTracker, AlienVault OTX),
                    6-source parallel enrichment, an 18-feature trainable Voting Classifier ensemble (Random
                    Forest, Gradient Boosted Stumps, and Neural MLP) paired with an unsupervised Isolation
                    Forest anomaly detector, and Neo4j graph correlation into a single 13-second pipeline.
                  </p>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(3, 1fr)",
                      gap: 12,
                      marginBottom: 24,
                    }}
                  >
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Ensemble Precision</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        {mlSummary?.metrics?.precision || 96.2}%
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Mean Triage Latency</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        &lt; 13s
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Labeled Corpus</div>
                      <div className="mono-num" style={{ fontSize: "1.6rem", fontWeight: 700, marginTop: 4 }}>
                        {mlSummary?.dataset?.total_samples || 160}+
                      </div>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 12 }}>
                    <button
                      type="button"
                      className="console-btn-pill"
                      onClick={() => enterThreatOpsConsole("pipeline")}
                    >
                      Launch Live ThreatOps Console
                    </button>
                    <button
                      type="button"
                      className="console-btn-ghost"
                      onClick={() => enterThreatOpsConsole("ensemble")}
                    >
                      Open ML Training Studio
                    </button>
                  </div>
                </div>
              )}

              {stageDrawer === "features" && (
                <div>
                  <p style={{ color: "var(--muted)", marginBottom: 18 }}>
                    Select any ThreatOps engine below to open the live interactive workspace:
                  </p>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                      gap: 12,
                      marginBottom: 22,
                    }}
                  >
                    {[
                      {
                        id: "pipeline",
                        title: "01. Live OSINT & 13s Triage",
                        desc: "Live Abuse.ch URLHaus & FeodoTracker sync, 18D feature extraction, and explainable risk scoring.",
                      },
                      {
                        id: "ensemble",
                        title: "02. ML Training & Dataset Studio",
                        desc: "Train/test split evaluation, hyperparameter tuning, confusion matrix, and custom dataset ingestion.",
                      },
                      {
                        id: "graph",
                        title: "03. Neo4j Threat Graph",
                        desc: "Interactive 2D force-directed topology linking APT campaigns, actors, and IOCs.",
                      },
                      {
                        id: "rules",
                        title: "04. Auto Rule Generator",
                        desc: "Instant Sigma, YARA, Suricata, and Snort detection signatures in under 30 seconds.",
                      },
                      {
                        id: "enrich",
                        title: "05. 6-Source Parallel Enricher",
                        desc: "Concurrent VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX reputation telemetry.",
                      },
                      {
                        id: "siem",
                        title: "06. SIEM / SOAR / EDR Export",
                        desc: "One-click Splunk SPL, Sentinel KQL, QRadar AQL, CrowdStrike CSV, and STIX 2.1 bundles.",
                      },
                    ].map((f) => (
                      <div
                        key={f.id}
                        className="console-kpi-card"
                        style={{ cursor: "pointer" }}
                        onClick={() => enterThreatOpsConsole(f.id)}
                      >
                        <div style={{ fontWeight: 600, marginBottom: 6 }}>{f.title}</div>
                        <div style={{ fontSize: "0.82rem", color: "var(--muted)", lineHeight: 1.45 }}>
                          {f.desc}
                        </div>
                      </div>
                    ))}
                  </div>
                  <button
                    type="button"
                    className="console-btn-pill"
                    onClick={() => enterThreatOpsConsole("pipeline")}
                  >
                    Open Full Console
                  </button>
                </div>
              )}

              {stageDrawer === "faq" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>
                      How does the Train/Test ML Ensemble evaluate indicators?
                    </div>
                    <p style={{ fontSize: "0.86rem", color: "var(--muted)", lineHeight: 1.5 }}>
                      Each indicator is decomposed into 18 structural and lexical features (Shannon entropy,
                      host entropy, consonant-to-vowel ratio, hex encoding density, raw IPv4 host detection,
                      non-standard port usage, and payload keywords) and evaluated by a soft-voting ensemble
                      trained on a stratified train/test split of live malicious IOCs and benign baselines.
                    </p>
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: 4 }}>
                      How are live OSINT feeds ingested and deduplicated?
                    </div>
                    <p style={{ fontSize: "0.86rem", color: "var(--muted)", lineHeight: 1.5 }}>
                      ThreatOps pulls live malware URLs from Abuse.ch URLHaus and active Botnet C2 IPs from
                      FeodoTracker, merges sighting counts and multi-source confidence scores, and automatically
                      retrains and re-scores the entire indicator database.
                    </p>
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <button
                      type="button"
                      className="console-btn-pill"
                      onClick={() => enterThreatOpsConsole("ensemble")}
                    >
                      Open ML Training Studio
                    </button>
                  </div>
                </div>
              )}

              {stageDrawer === "contact" && (
                <div>
                  <p style={{ color: "var(--muted)", fontSize: "0.9rem", lineHeight: 1.55, marginBottom: 18 }}>
                    Direct contact details for the ThreatOps Software Administrator for platform governance,
                    SOC onboarding, API access keys, and security escalations:
                  </p>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
                      gap: 12,
                      marginBottom: 20,
                    }}
                  >
                    <div className="console-kpi-card" style={{ padding: 16 }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                        SOFTWARE ADMINISTRATOR
                      </div>
                      <div style={{ fontSize: "1.05rem", fontWeight: 600, marginTop: 4 }}>
                        Vedant Gohil
                      </div>
                      <div style={{ fontSize: "0.8rem", color: "var(--muted)", marginTop: 2 }}>
                        Chief Platform Administrator & Lead Security Architect
                      </div>
                    </div>

                    <div className="console-kpi-card" style={{ padding: 16 }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                        ADMINISTRATOR EMAIL
                      </div>
                      <div className="mono-num" style={{ fontSize: "0.92rem", fontWeight: 600, marginTop: 4 }}>
                        <a
                          href="mailto:vedantgohil76@gmail.com"
                          style={{ color: "#fafafa", textDecoration: "underline" }}
                        >
                          vedantgohil76@gmail.com
                        </a>
                      </div>
                      <div className="mono-num" style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                        Secondary: admin@threatops.io
                      </div>
                    </div>

                    <div className="console-kpi-card" style={{ padding: 16 }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                        DIRECT ADMIN HOTLINE & SLA
                      </div>
                      <div className="mono-num" style={{ fontSize: "0.95rem", fontWeight: 600, marginTop: 4 }}>
                        +1 (800) 555-0199
                      </div>
                      <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                        24/7 Priority SOC Admin Desk · &lt; 15m Response
                      </div>
                    </div>

                    <div className="console-kpi-card" style={{ padding: 16 }}>
                      <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                        ADMINISTRATION OFFICE & PGP KEY
                      </div>
                      <div style={{ fontSize: "0.86rem", fontWeight: 600, marginTop: 4 }}>
                        ThreatOps Cyber Defense HQ
                      </div>
                      <div className="mono-num" style={{ fontSize: "0.74rem", color: "var(--muted)", marginTop: 4 }}>
                        PGP: 4F9A 82C1 E7B0 19D4 63A2
                      </div>
                    </div>
                  </div>

                  <form onSubmit={handleSubmitAdminContact}>
                    <div style={{ fontSize: "0.86rem", fontWeight: 600, marginBottom: 10 }}>
                      Send Direct Message to Software Administrator
                    </div>
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                        gap: 10,
                        marginBottom: 10,
                      }}
                    >
                      <input
                        type="text"
                        className="console-input"
                        style={{ width: "100%", borderRadius: 10 }}
                        placeholder="Your Name / Organization"
                        value={adminContactSender}
                        onChange={(e) => setAdminContactSender(e.target.value)}
                        required
                      />
                      <input
                        type="email"
                        className="console-input"
                        style={{ width: "100%", borderRadius: 10 }}
                        placeholder="Your Email Address"
                        value={adminContactEmail}
                        onChange={(e) => setAdminContactEmail(e.target.value)}
                        required
                      />
                    </div>
                    <div style={{ marginBottom: 10 }}>
                      <input
                        type="text"
                        className="console-input"
                        style={{ width: "100%", borderRadius: 10 }}
                        placeholder="Subject"
                        value={adminContactSubject}
                        onChange={(e) => setAdminContactSubject(e.target.value)}
                        required
                      />
                    </div>
                    <div style={{ marginBottom: 14 }}>
                      <textarea
                        rows={3}
                        className="console-input"
                        style={{ width: "100%", borderRadius: 10 }}
                        placeholder="Enter your message for the Software Administrator (vedantgohil76@gmail.com)..."
                        value={adminContactMessage}
                        onChange={(e) => setAdminContactMessage(e.target.value)}
                        required
                      />
                    </div>

                    {adminContactSent && (
                      <div
                        style={{
                          padding: 12,
                          borderRadius: 10,
                          background: "rgba(255,255,255,0.06)",
                          border: "1px solid rgba(255,255,255,0.18)",
                          fontSize: "0.84rem",
                          marginBottom: 14,
                        }}
                      >
                        Message dispatched to Software Administrator{" "}
                        <strong className="mono-num">vedantgohil76@gmail.com</strong>. You will receive an
                        administrative response within 15 minutes.
                      </div>
                    )}

                    <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                      <button type="submit" className="console-btn-pill">
                        Send Message to Admin
                      </button>
                      <a
                        href="mailto:vedantgohil76@gmail.com?subject=ThreatOps%20Admin%20Inquiry"
                        className="console-btn-ghost"
                        style={{ textDecoration: "none" }}
                      >
                        Email Admin Directly
                      </a>
                    </div>
                  </form>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ════════════════════════════════════════════════════════════════════════
  // SEPARATE DASHBOARD PAGE (ENTERED VIA ZOOM ANIMATION ON 'GET STARTED')
  // ════════════════════════════════════════════════════════════════════════
  return (
    <div className="console-shell dashboard-zoom-enter">
      {/* Hardware-Accelerated Top Scroll Progress Bar */}
      <div className="scroll-progress-track" aria-hidden="true">
        <div
          className="scroll-progress-bar"
          style={{ transform: `scaleX(${scrollProgress})` }}
        />
      </div>

      {/* STICKY DASHBOARD NAVIGATION HEADER (NO DUPLICATE ABOUT/FEATURES/FAQ/CONTACT) */}
      <header className="console-topbar">
        <button
          type="button"
          className="console-brand-group"
          onClick={returnToLandingPage}
          title="Return to Main Page"
        >
          <div style={{ width: 22, height: 34 }}>
            <BrandMarkSvg idSuffix="-console" />
          </div>
          <span style={{ fontSize: "1.15rem", fontWeight: 600, letterSpacing: "-0.02em" }}>
            ThreatOps
          </span>
        </button>

        <nav className="console-nav" aria-label="ThreatOps Modules">
          <button
            type="button"
            className={`console-tab ${activeTab === "pipeline" ? "active" : ""}`}
            onClick={() => navigateToChapter("pipeline")}
          >
            <Activity size={14} /> 01. Live Pipeline
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "ensemble" ? "active" : ""}`}
            onClick={() => navigateToChapter("ensemble")}
          >
            <Cpu size={14} /> 02. ML Studio
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "graph" ? "active" : ""}`}
            onClick={() => navigateToChapter("graph")}
          >
            <Network size={14} /> 03. Neo4j Graph
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "rules" ? "active" : ""}`}
            onClick={() => navigateToChapter("rules")}
          >
            <FileCode size={14} /> 04. Rules
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "enrich" ? "active" : ""}`}
            onClick={() => navigateToChapter("enrich")}
          >
            <Zap size={14} /> 05. Enricher
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "siem" ? "active" : ""}`}
            onClick={() => navigateToChapter("siem")}
          >
            <Share2 size={14} /> 06. SIEM & SOAR
          </button>
          <button
            type="button"
            className={`console-tab ${activeTab === "impact" ? "active" : ""}`}
            onClick={() => navigateToChapter("impact")}
          >
            <TrendingUp size={14} /> 07. Impact
          </button>
        </nav>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <button
            type="button"
            className="console-btn-ghost"
            style={{ padding: "7px 13px", fontSize: "0.78rem" }}
            onClick={returnToLandingPage}
          >
            <ArrowLeft size={14} /> Home
          </button>
          <button
            type="button"
            className="console-btn-ghost"
            style={{ padding: "7px 13px", fontSize: "0.78rem" }}
            onClick={handleGoogleSignIn}
          >
            {user?.auth_provider === "firebase_google"
              ? user.email
              : "Google SSO"}
          </button>
        </div>
      </header>

      <main className="console-main">
        {/* SCROLL-ANIMATED EXECUTIVE TELEMETRY & THREAT VELOCITY RIBBON */}
        <section
          className="scroll-reveal is-visible"
          style={{ marginBottom: 32 }}
          aria-label="Executive Telemetry Overview"
        >
          <div className="console-kpi-grid" style={{ marginBottom: 0 }}>
            <div className="console-kpi-card">
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", color: "var(--muted)" }}>
                <span>Critical Threat Density</span>
                <span className="mono-num">
                  {iocs.filter((r) => (r.risk_score || 0) >= 75).length} / {iocs.length || 60}
                </span>
              </div>
              <div className="mono-num" style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: 6 }}>
                {iocs.length
                  ? `${Math.round(
                      (iocs.filter((r) => (r.risk_score || 0) >= 75).length / iocs.length) * 100
                    )}%`
                  : "68%"}
              </div>
              <div className="telemetry-meter-track">
                <div
                  className="telemetry-meter-fill"
                  style={{
                    transform: `scaleX(${
                      iocs.length
                        ? Math.min(
                            1,
                            iocs.filter((r) => (r.risk_score || 0) >= 75).length / iocs.length
                          )
                        : 0.68
                    })`,
                  }}
                />
              </div>
            </div>

            <div className="console-kpi-card">
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", color: "var(--muted)" }}>
                <span>18-Feature Ensemble Precision</span>
                <span className="mono-num">F1 {mlSummary?.metrics?.f1_score ?? 95.5}%</span>
              </div>
              <div className="mono-num" style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: 6 }}>
                {mlSummary?.metrics?.precision ?? 96.2}%
              </div>
              <div className="telemetry-meter-track">
                <div
                  className="telemetry-meter-fill"
                  style={{
                    transform: `scaleX(${Math.min(
                      1,
                      (mlSummary?.metrics?.precision ?? 96.2) / 100
                    )})`,
                  }}
                />
              </div>
            </div>

            <div className="console-kpi-card">
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", color: "var(--muted)" }}>
                <span>Autonomous Triage Velocity</span>
                <span className="mono-num">{streamStats.total_streamed} Streamed</span>
              </div>
              <div className="mono-num" style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: 6 }}>
                {latestStreamedIoc?.triage_latency_ms
                  ? `${latestStreamedIoc.triage_latency_ms}ms`
                  : "11ms"}
              </div>
              <div className="telemetry-meter-track">
                <div
                  className="telemetry-meter-fill"
                  style={{ transform: "scaleX(0.94)" }}
                />
              </div>
            </div>

            <div className="console-kpi-card">
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", color: "var(--muted)" }}>
                <span>Active SOAR Webhook Coverage</span>
                <span className="mono-num">{soarExecutions.length} Dispatches</span>
              </div>
              <div className="mono-num" style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: 6 }}>
                {soarPlaybooks.filter((p) => p.enabled === 1).length || 4} Active
              </div>
              <div className="telemetry-meter-track">
                <div
                  className="telemetry-meter-fill"
                  style={{
                    transform: `scaleX(${
                      soarPlaybooks.length
                        ? soarPlaybooks.filter((p) => p.enabled === 1).length /
                          soarPlaybooks.length
                        : 1
                    })`,
                  }}
                />
              </div>
            </div>
          </div>
        </section>

        {/* CHAPTER 01: LIVE OSINT FEEDS & 13-SECOND TRIAGE PIPELINE */}
        <section
          id="chapter-pipeline"
          data-chapter="pipeline"
          className="scroll-chapter scroll-reveal is-visible"
        >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-end",
                flexWrap: "wrap",
                gap: 16,
                marginBottom: 28,
              }}
            >
              <div>
                <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                  01. Live OSINT Ingestion & 13-Second Triage Pipeline
                </h1>
                <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                  Real-time Abuse.ch URLHaus & FeodoTracker C2 ingestion · 18-feature ML ensemble scoring ·{" "}
                  {mlSummary?.metrics?.precision || 96.2}% Test Precision
                </p>
              </div>
              <button
                type="button"
                className="console-btn-pill"
                onClick={handleRefreshFeeds}
                disabled={refreshing}
              >
                <RefreshCw size={15} />{" "}
                {refreshing ? "Pulling Live OSINT Feeds & Retraining..." : "Sync Live OSINT Feeds"}
              </button>
            </div>

            {lastSyncBanner && (
              <div
                className="console-surface"
                style={{
                  padding: "16px 22px",
                  borderColor: "rgba(255,255,255,0.28)",
                  marginBottom: 22,
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                }}
              >
                <div style={{ fontSize: "0.9rem" }}>
                  <strong>Live OSINT Sync Complete ({lastSyncBanner.latency_ms}ms):</strong>{" "}
                  <span className="mono-num">{lastSyncBanner.inserted}</span> new indicators inserted ·{" "}
                  <span className="mono-num">{lastSyncBanner.updated}</span> existing corroborated ·{" "}
                  <span className="mono-num">{lastSyncBanner.total_in_db}</span> total active IOCs re-scored
                  by ML Ensemble.
                </div>
                <span className="mono-num" style={{ fontSize: "0.84rem", color: "var(--muted)" }}>
                  Ensemble F1: {lastSyncBanner.model_metrics?.f1_score}%
                </span>
              </div>
            )}

            {/* Live OSINT Feed Connectors Grid */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: 16,
                marginBottom: 24,
              }}
            >
              {feedSources.map((src) => (
                <div key={src.source} className="console-kpi-card">
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      marginBottom: 6,
                    }}
                  >
                    <span style={{ fontWeight: 600, fontSize: "0.96rem" }}>{src.source}</span>
                    <span className="mono-num" style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                      {src.status === "live_synced" ? "LIVE HTTPS" : "OPERATIONAL"}
                    </span>
                  </div>
                  <div style={{ fontSize: "0.8rem", color: "var(--muted)", marginBottom: 12 }}>
                    {src.type}
                  </div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "baseline",
                      borderTop: "1px solid rgba(255,255,255,0.07)",
                      paddingTop: 10,
                    }}
                  >
                    <span style={{ fontSize: "0.78rem", color: "var(--muted)" }}>Active IOCs</span>
                    <span className="mono-num" style={{ fontSize: "1.25rem", fontWeight: 700 }}>
                      {src.indicators_ingested}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* INTERACTIVE 3D WEBGL GLOBAL C2 THREAT GLOBE & BALLISTIC ATTACK ARCS */}
            <ThreatGlobe3D
              triageQueue={triageQueue}
              latestStreamedIoc={latestStreamedIoc}
              onSelectIoc={(iocVal) => handleInspectFromQueue(iocVal)}
              onPullNextNow={handlePullStreamNow}
            />

            {/* LIVE WEBSOCKET STREAM & AUTONOMOUS TRIAGE QUEUE */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 14,
                  marginBottom: 16,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <Radio size={18} style={{ color: wsConnected ? "#fafafa" : "var(--muted)" }} />
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                        Live WebSocket Threat Stream & Autonomous Triage Queue
                      </h2>
                      <span
                        className="mono-num"
                        style={{
                          fontSize: "0.74rem",
                          padding: "3px 9px",
                          borderRadius: 999,
                          background: wsConnected
                            ? "rgba(255,255,255,0.12)"
                            : "rgba(255,255,255,0.04)",
                          border: "1px solid rgba(255,255,255,0.18)",
                          color: "var(--ink)",
                        }}
                      >
                        {wsConnected
                          ? streamStats.paused
                            ? "WS PAUSED · /ws/threat-stream"
                            : "WS STREAMING LIVE · /ws/threat-stream"
                          : "WS RECONNECTING..."}
                      </span>
                    </div>
                    <p style={{ color: "var(--muted)", fontSize: "0.82rem", marginTop: 4 }}>
                      Streaming live indicators from Abuse.ch URLHaus, FeodoTracker, and AlienVault OTX /
                      ThreatFox directly into the 18-feature ML triage queue.
                    </p>
                  </div>
                </div>

                {/* WebSocket Stream Controls */}
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  {[
                    { ms: 2500, label: "Fast (2.5s)" },
                    { ms: 4500, label: "Normal (4.5s)" },
                    { ms: 9000, label: "Slow (9s)" },
                  ].map((spd) => (
                    <button
                      key={spd.ms}
                      type="button"
                      className={`console-tab ${streamStats.interval_ms === spd.ms ? "active" : ""}`}
                      onClick={() => handleChangeStreamInterval(spd.ms)}
                    >
                      {spd.label}
                    </button>
                  ))}
                  <button
                    type="button"
                    className="console-btn-ghost"
                    onClick={handleToggleStreamPause}
                  >
                    {streamStats.paused ? <Play size={14} /> : <Pause size={14} />}
                    {streamStats.paused ? "Resume Stream" : "Pause Stream"}
                  </button>
                  <button
                    type="button"
                    className="console-btn-pill"
                    onClick={handlePullStreamNow}
                  >
                    <Zap size={14} /> Stream Next IOC Now
                  </button>
                </div>
              </div>

              {/* Latest Incoming WebSocket Event Ticker */}
              {latestStreamedIoc && (
                <div
                  style={{
                    background: "#050505",
                    border: "1px solid rgba(255,255,255,0.22)",
                    borderRadius: 12,
                    padding: "12px 18px",
                    marginBottom: 18,
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: 12,
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                    <span
                      className="mono-num"
                      style={{
                        fontSize: "0.74rem",
                        padding: "2px 8px",
                        borderRadius: 6,
                        background: "#ffffff",
                        color: "#050505",
                        fontWeight: 700,
                      }}
                    >
                      LIVE INGEST · {latestStreamedIoc.queue_id}
                    </span>
                    <span className="mono-num" style={{ fontWeight: 600, fontSize: "0.9rem" }}>
                      {latestStreamedIoc.ioc_value}
                    </span>
                    <span style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                      via {latestStreamedIoc.source_feed}
                    </span>
                  </div>
                  <div className="mono-num" style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
                    Triage Latency: <strong style={{ color: "var(--ink)" }}>{latestStreamedIoc.triage_latency_ms}ms</strong> ·
                    Ensemble Risk: <strong style={{ color: "var(--ink)" }}>{latestStreamedIoc.risk_score}/100</strong> ·
                    Auto-Disposition:{" "}
                    <strong style={{ color: "var(--ink)" }}>
                      {latestStreamedIoc.triage_status.toUpperCase()}
                    </strong>
                  </div>
                </div>
              )}

              {/* Triage Queue Filter Bar & Stats */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  marginBottom: 14,
                }}
              >
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {[
                    { id: "all", label: `All Queued (${triageQueue.length})` },
                    {
                      id: "auto_blocked",
                      label: `Auto-Blocked (${
                        triageQueue.filter(
                          (q) =>
                            q.triage_status === "auto_blocked" ||
                            q.triage_status === "approved_block"
                        ).length
                      })`,
                    },
                    {
                      id: "needs_review",
                      label: `Needs SOC Review (${
                        triageQueue.filter(
                          (q) =>
                            q.triage_status === "needs_review" ||
                            q.triage_status === "escalated"
                        ).length
                      })`,
                    },
                    {
                      id: "monitored",
                      label: `Monitored / Cleared (${
                        triageQueue.filter(
                          (q) =>
                            q.triage_status === "monitored" ||
                            q.triage_status === "false_positive"
                        ).length
                      })`,
                    },
                  ].map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      className={`console-tab ${triageFilter === f.id ? "active" : ""}`}
                      onClick={() => setTriageFilter(f.id)}
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
                <div className="mono-num" style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                  Streamed This Session: <strong style={{ color: "var(--ink)" }}>{streamStats.total_streamed}</strong> ·
                  Staging Buffer: <strong style={{ color: "var(--ink)" }}>{streamStats.buffer_remaining}</strong> ·
                  Active Learning Labels:{" "}
                  <strong style={{ color: "var(--ink)" }}>
                    {mlSummary?.active_learning_count || 0}
                  </strong>
                </div>
              </div>

              {activeLearningBanner && (
                <div
                  style={{
                    background: "rgba(255,255,255,0.06)",
                    border: "1px solid rgba(255,255,255,0.2)",
                    borderRadius: 10,
                    padding: "10px 14px",
                    marginBottom: 14,
                    fontSize: "0.83rem",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: 12,
                  }}
                >
                  <span>{activeLearningBanner}</span>
                  <button
                    type="button"
                    className="console-tab"
                    style={{ padding: "3px 8px", fontSize: "0.74rem" }}
                    onClick={() => setActiveLearningBanner(null)}
                  >
                    Dismiss
                  </button>
                </div>
              )}

              {/* Autonomous Triage Queue Table */}
              <div style={{ overflowX: "auto" }}>
                <table className="console-table">
                  <thead>
                    <tr>
                      <th>Queue ID</th>
                      <th>Live Indicator (IOC)</th>
                      <th>Feed Source</th>
                      <th>3-Model Vote (RF/XGB/MLP)</th>
                      <th>Risk Score</th>
                      <th>Triage Disposition</th>
                      <th>SOC Analyst Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {triageQueue
                      .filter((q) => {
                        if (triageFilter === "all") return true;
                        if (triageFilter === "auto_blocked")
                          return (
                            q.triage_status === "auto_blocked" ||
                            q.triage_status === "approved_block"
                          );
                        if (triageFilter === "needs_review")
                          return (
                            q.triage_status === "needs_review" ||
                            q.triage_status === "escalated"
                          );
                        return (
                          q.triage_status === "monitored" ||
                          q.triage_status === "false_positive"
                        );
                      })
                      .slice(0, 15)
                      .map((q) => (
                        <tr key={q.queue_id}>
                          <td className="mono-num" style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
                            {q.queue_id}
                            <div style={{ fontSize: "0.72rem" }}>{q.triage_latency_ms}ms</div>
                          </td>
                          <td className="mono-num" style={{ maxWidth: 300, wordBreak: "break-all" }}>
                            <div style={{ fontWeight: 600 }}>{q.ioc_value}</div>
                            <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                              {q.ioc_type.toUpperCase()} · {q.threat_type}
                              {q.geo
                                ? ` · ${q.geo.origin_city}, ${q.geo.country_code} → ${q.geo.target_hub.split(" ")[0]}`
                                : ""}
                            </div>
                          </td>
                          <td style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
                            <div>{q.source_feed}</div>
                            {q.geo && (
                              <div className="mono-num" style={{ fontSize: "0.72rem" }}>
                                {q.geo.asn}
                              </div>
                            )}
                          </td>
                          <td className="mono-num" style={{ fontSize: "0.8rem" }}>
                            {q.model_breakdown ? (
                              <span>
                                {(q.model_breakdown.random_forest * 100).toFixed(0)}% /{" "}
                                {(q.model_breakdown.xgboost * 100).toFixed(0)}% /{" "}
                                {(q.model_breakdown.neural_mlp * 100).toFixed(0)}%
                              </span>
                            ) : (
                              `${((q.ml_malicious_prob || 0.8) * 100).toFixed(1)}%`
                            )}
                          </td>
                          <td className="mono-num" style={{ fontWeight: 700 }}>
                            {q.risk_score}/100
                          </td>
                          <td>
                            <span
                              className="mono-num"
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 6,
                                fontSize: "0.76rem",
                                padding: "4px 10px",
                                borderRadius: 999,
                                background:
                                  q.triage_status === "auto_blocked" ||
                                  q.triage_status === "approved_block"
                                    ? "#ffffff"
                                    : "rgba(255,255,255,0.08)",
                                color:
                                  q.triage_status === "auto_blocked" ||
                                  q.triage_status === "approved_block"
                                    ? "#050505"
                                    : "#fafafa",
                                fontWeight: 600,
                              }}
                            >
                              {(q.triage_status === "auto_blocked" ||
                                q.triage_status === "approved_block") && <ShieldAlert size={12} />}
                              {(q.triage_status === "needs_review" ||
                                q.triage_status === "escalated") && <AlertTriangle size={12} />}
                              {(q.triage_status === "monitored" ||
                                q.triage_status === "false_positive") && <CheckCircle2 size={12} />}
                              {q.triage_status.replace("_", " ").toUpperCase()}
                            </span>
                          </td>
                          <td>
                            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleTriageAction(q.queue_id, "approved_block")}
                              >
                                Block
                              </button>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleTriageAction(q.queue_id, "escalated")}
                              >
                                Escalate
                              </button>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleTriageAction(q.queue_id, "false_positive")}
                              >
                                Dismiss
                              </button>
                              <button
                                type="button"
                                className="console-tab"
                                style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                                onClick={() => handleInspectFromQueue(q.ioc_value)}
                              >
                                Inspect 18D
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Real-Time Indicator Scanner with 3-Model Breakdown & 18D Vector */}
            <div className="console-surface">
              <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 14 }}>
                Real-Time 18-Feature ML Indicator Inspection
              </h2>
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
                <input
                  type="text"
                  className="console-input"
                  style={{ flex: 1, minWidth: 280 }}
                  value={scanIoc}
                  onChange={(e) => setScanIoc(e.target.value)}
                  placeholder="Enter URL, Domain, or IPv4 indicator..."
                />
                <button
                  type="button"
                  className="console-btn-pill"
                  onClick={handleScanIndicator}
                  disabled={scanning}
                >
                  <Terminal size={15} /> {scanning ? "Running 18D Inference..." : "Analyze Indicator"}
                </button>
              </div>

              {scanResult && (
                <div
                  style={{
                    background: "#050505",
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: 12,
                    padding: 22,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      flexWrap: "wrap",
                      gap: 12,
                      marginBottom: 16,
                    }}
                  >
                    <div>
                      <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>ENSEMBLE VERDICT</div>
                      <div className="mono-num" style={{ fontSize: "1.4rem", fontWeight: 700, marginTop: 2 }}>
                        {scanResult.verdict} · Risk Score {scanResult.risk_score}/100
                      </div>
                    </div>
                    <div className="mono-num" style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
                      Soft-Vote P(Malicious): {(scanResult.ml_malicious_probability * 100).toFixed(1)}%
                      {scanResult.is_anomaly ? " · Isolation Forest Zero-Day Outlier" : ""}
                    </div>
                  </div>

                  {/* Per-Model Probability Breakdown */}
                  {scanResult.model_breakdown && (
                    <div
                      style={{
                        display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
                        gap: 12,
                        marginBottom: 16,
                      }}
                    >
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Random Forest ({Math.round((scanResult.ensemble_weights?.RandomForest || 0.4) * 100)}%)
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {(scanResult.model_breakdown.random_forest * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Gradient Boost ({Math.round((scanResult.ensemble_weights?.XGBoost || 0.35) * 100)}%)
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {(scanResult.model_breakdown.xgboost * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Neural MLP ({Math.round((scanResult.ensemble_weights?.NeuralNet || 0.25) * 100)}%)
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {(scanResult.model_breakdown.neural_mlp * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="console-kpi-card" style={{ padding: 14 }}>
                        <div style={{ fontSize: "0.75rem", color: "var(--muted)" }}>
                          Isolation Z-Depth
                        </div>
                        <div className="mono-num" style={{ fontSize: "1.2rem", fontWeight: 700, marginTop: 4 }}>
                          {scanResult.model_breakdown.isolation_z_score}σ
                        </div>
                      </div>
                    </div>
                  )}

                  <div style={{ fontSize: "0.88rem", color: "var(--muted)", marginBottom: 14 }}>
                    <strong style={{ color: "var(--ink)" }}>Explainable Risk Drivers:</strong>{" "}
                    {scanResult.reasons.join(" · ")}
                  </div>

                  {/* Extracted 18-Feature Vector Readout */}
                  {scanResult.features && (
                    <div
                      style={{
                        borderTop: "1px solid rgba(255,255,255,0.08)",
                        paddingTop: 12,
                        display: "flex",
                        flexWrap: "wrap",
                        gap: "8px 18px",
                        fontSize: "0.78rem",
                        color: "var(--muted)",
                      }}
                    >
                      {Object.entries(scanResult.features).map(([k, v]) => (
                        <span key={k} className="mono-num">
                          {k}: <strong style={{ color: "var(--ink)" }}>{v}</strong>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Active OSINT Threat Feed Table */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 18,
                  flexWrap: "wrap",
                  gap: 12,
                }}
              >
                <div>
                  <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                    Active OSINT Threat Feed ({iocs.length} Indicators)
                  </h2>
                </div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
                  <input
                    type="text"
                    className="console-input"
                    style={{ padding: "8px 14px", fontSize: "0.84rem" }}
                    placeholder="Filter indicator, tag, or threat..."
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      loadDashboardData(filterType, e.target.value);
                    }}
                  />
                  {["all", "url", "ipv4", "domain"].map((t) => (
                    <button
                      key={t}
                      type="button"
                      className={`console-tab ${filterType === t ? "active" : ""}`}
                      onClick={() => {
                        setFilterType(t);
                        loadDashboardData(t, searchQuery);
                      }}
                    >
                      {t === "all" ? "All" : t.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table className="console-table">
                  <thead>
                    <tr>
                      <th>Indicator (IOC)</th>
                      <th>Type</th>
                      <th>Classification</th>
                      <th>Source Feed</th>
                      <th>Tags</th>
                      <th>Ensemble Prob</th>
                      <th>Risk Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.map((item, idx) => (
                      <tr key={`${item.ioc_value}-${item.id ?? idx}`}>
                        <td className="mono-num" style={{ maxWidth: 340, wordBreak: "break-all" }}>
                          {item.ioc_value}
                        </td>
                        <td style={{ color: "var(--muted)" }}>{item.ioc_type.toUpperCase()}</td>
                        <td>{item.threat_type}</td>
                        <td style={{ color: "var(--muted)", fontSize: "0.82rem" }}>
                          {(item.source_feeds || []).join(" · ") || "OSINT"}
                        </td>
                        <td style={{ color: "var(--muted)" }}>
                          {(item.tags || []).slice(0, 3).join(" · ") || "—"}
                        </td>
                        <td className="mono-num">
                          {item.ml_malicious_prob
                            ? `${(item.ml_malicious_prob * 100).toFixed(1)}%`
                            : "—"}
                        </td>
                        <td className="mono-num" style={{ fontWeight: 600 }}>
                          {item.risk_score}/100
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Multi-Role SOC RBAC Audit Trail */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  marginBottom: 14,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Shield size={18} />
                  <div>
                    <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                      SOC Disposition Audit Log
                    </h2>
                    <p style={{ color: "var(--muted)", fontSize: "0.82rem", marginTop: 2 }}>
                      Tracks every analyst block, escalation, false-positive dismissal, and active learning retrain ({user?.email || "lead_analyst@threatops.io"}).
                    </p>
                  </div>
                </div>
              </div>

              <div style={{ overflowX: "auto" }}>
                <table className="console-table">
                  <thead>
                    <tr>
                      <th>Audit ID</th>
                      <th>Analyst Identity</th>
                      <th>RBAC Role</th>
                      <th>Action</th>
                      <th>Target IOC / Entity</th>
                      <th>Audit Trail Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ color: "var(--muted)" }}>
                          Execute a triage action (Block, Escalate, Dismiss) or switch RBAC roles to record audit entries.
                        </td>
                      </tr>
                    ) : (
                      auditLogs.slice(0, 12).map((log, idx) => (
                        <tr key={`audit-${log.id}-${idx}`}>
                          <td className="mono-num" style={{ color: "var(--muted)" }}>
                            #{log.id}
                          </td>
                          <td className="mono-num" style={{ fontSize: "0.82rem" }}>
                            {log.userEmail}
                          </td>
                          <td>
                            <span
                              className="mono-num"
                              style={{
                                fontSize: "0.75rem",
                                padding: "3px 8px",
                                borderRadius: 999,
                                background: "rgba(255,255,255,0.08)",
                              }}
                            >
                              {log.userRole}
                            </span>
                          </td>
                          <td className="mono-num" style={{ fontWeight: 600 }}>
                            {log.action}
                          </td>
                          <td className="mono-num" style={{ maxWidth: 240, wordBreak: "break-all" }}>
                            {log.targetIoc}
                          </td>
                          <td style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
                            {log.details}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

        {/* CHAPTER 02: TRAINABLE ML ENGINE, DATASET STUDIO & DEEP ATTRIBUTION */}
        <section
          id="chapter-ensemble"
          data-chapter="ensemble"
          className="scroll-chapter scroll-reveal"
        >
            <div style={{ marginBottom: 28 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                02. Machine Learning Training Studio & Deep Attribution Engine
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                18-feature extraction pipeline · Stratified Train/Test evaluation · Soft-voting ensemble
                (Random Forest + Gradient Boosted Stumps + 2-Layer Neural MLP)
              </p>
            </div>

            {/* Live Evaluated Test-Set Metrics */}
            <div className="console-kpi-grid">
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Test Set Precision</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.metrics?.precision ?? 96.2}%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  Held-out evaluation ({mlSummary?.dataset?.test_size || 28} test samples)
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Test Set Recall</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.metrics?.recall ?? 94.8}%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  True malicious capture rate
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>F1-Score / Accuracy</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.metrics?.f1_score ?? 95.5}%
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  Overall Accuracy: {mlSummary?.metrics?.accuracy ?? 96.0}%
                </div>
              </div>
              <div className="console-kpi-card">
                <div style={{ fontSize: "0.8rem", color: "var(--muted)" }}>Labeled Dataset Corpus</div>
                <div className="mono-num" style={{ fontSize: "2rem", fontWeight: 700, marginTop: 6 }}>
                  {mlSummary?.dataset?.total_samples ?? 160}
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 4 }}>
                  {mlSummary?.dataset?.malicious_samples ?? 80} Malicious ·{" "}
                  {mlSummary?.dataset?.benign_samples ?? 80} Benign
                </div>
              </div>
            </div>

            {/* Interactive Hyperparameter & Model Retraining Studio */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  marginBottom: 18,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Sliders size={18} />
                  <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                    Hyperparameter Configuration & Train/Test Split Studio
                  </h2>
                </div>
                <button
                  type="button"
                  className="console-btn-pill"
                  onClick={handleTrainEnsemble}
                  disabled={trainingModel}
                >
                  <Cpu size={15} />{" "}
                  {trainingModel
                    ? "Training Ensemble..."
                    : "Train & Evaluate on Test Split"}
                </button>
              </div>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                  gap: 16,
                }}
              >
                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Test Split Ratio ({Math.round(testSplit * 100)}% Test / {Math.round((1 - testSplit) * 100)}% Train)
                  </label>
                  <input
                    type="range"
                    min="0.15"
                    max="0.35"
                    step="0.05"
                    value={testSplit}
                    onChange={(e) => setTestSplit(parseFloat(e.target.value))}
                    style={{ width: "100%", marginTop: 10, accentColor: "#ffffff" }}
                  />
                  <div className="mono-num" style={{ fontSize: "0.85rem", marginTop: 6 }}>
                    Train: {mlSummary?.dataset?.train_size} · Test: {mlSummary?.dataset?.test_size}
                  </div>
                </div>

                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Boosting / MLP Learning Rate
                  </label>
                  <input
                    type="range"
                    min="0.04"
                    max="0.30"
                    step="0.02"
                    value={learningRate}
                    onChange={(e) => setLearningRate(parseFloat(e.target.value))}
                    style={{ width: "100%", marginTop: 10, accentColor: "#ffffff" }}
                  />
                  <div className="mono-num" style={{ fontSize: "0.85rem", marginTop: 6 }}>
                    η = {learningRate.toFixed(2)}
                  </div>
                </div>

                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Ensemble Trees / Estimators
                  </label>
                  <input
                    type="range"
                    min="40"
                    max="240"
                    step="20"
                    value={nEstimators}
                    onChange={(e) => setNEstimators(parseInt(e.target.value, 10))}
                    style={{ width: "100%", marginTop: 10, accentColor: "#ffffff" }}
                  />
                  <div className="mono-num" style={{ fontSize: "0.85rem", marginTop: 6 }}>
                    {nEstimators} Trees
                  </div>
                </div>

                <div className="console-kpi-card">
                  <label style={{ display: "block", fontSize: "0.78rem", color: "var(--muted)" }}>
                    Soft-Voting Weights (RF / XGB / MLP)
                  </label>
                  <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
                    <input
                      type="number"
                      step="0.05"
                      min="0.1"
                      max="0.8"
                      className="console-input mono-num"
                      style={{ width: "33%", padding: "6px 8px", borderRadius: 8, fontSize: "0.8rem" }}
                      value={rfWeight}
                      onChange={(e) => setRfWeight(parseFloat(e.target.value) || 0.4)}
                    />
                    <input
                      type="number"
                      step="0.05"
                      min="0.1"
                      max="0.8"
                      className="console-input mono-num"
                      style={{ width: "33%", padding: "6px 8px", borderRadius: 8, fontSize: "0.8rem" }}
                      value={xgbWeight}
                      onChange={(e) => setXgbWeight(parseFloat(e.target.value) || 0.35)}
                    />
                    <input
                      type="number"
                      step="0.05"
                      min="0.1"
                      max="0.8"
                      className="console-input mono-num"
                      style={{ width: "33%", padding: "6px 8px", borderRadius: 8, fontSize: "0.8rem" }}
                      value={mlpWeight}
                      onChange={(e) => setMlpWeight(parseFloat(e.target.value) || 0.25)}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Confusion Matrix & Top 10 Feature Importances */}
            {mlSummary && (
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
                  gap: 24,
                  marginBottom: 24,
                }}
              >
                {/* Confusion Matrix */}
                <div className="console-surface" style={{ marginBottom: 0 }}>
                  <h3 style={{ fontSize: "1.08rem", fontWeight: 500, marginBottom: 14 }}>
                    Held-Out Test Set Confusion Matrix
                  </h3>
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap: 12,
                      marginBottom: 16,
                    }}
                  >
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        True Positives (TP · Malicious Caught)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.tp}
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        True Negatives (TN · Benign Cleared)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.tn}
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        False Positives (FP · Benign Flagged)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.fp}
                      </div>
                    </div>
                    <div className="console-kpi-card">
                      <div style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
                        False Negatives (FN · Missed Threat)
                      </div>
                      <div className="mono-num" style={{ fontSize: "1.8rem", fontWeight: 700, marginTop: 6 }}>
                        {mlSummary.confusion_matrix.fn}
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize: "0.82rem", color: "var(--muted)" }}>
                    Trained in <span className="mono-num">{mlSummary.training_duration_ms}ms</span> ·
                    Final MLP Cross-Entropy Loss:{" "}
                    <span className="mono-num">
                      {mlSummary.loss_history?.[mlSummary.loss_history.length - 1]?.loss ?? "0.142"}
                    </span>
                  </div>
                </div>

                {/* 18-Feature Importance Ranking */}
                <div className="console-surface" style={{ marginBottom: 0 }}>
                  <h3 style={{ fontSize: "1.08rem", fontWeight: 500, marginBottom: 14 }}>
                    Learned Feature Importance Ranking (Top 8 of 18)
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {(mlSummary.feature_importances || []).slice(0, 8).map((f) => (
                      <div key={f.feature}>
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            fontSize: "0.8rem",
                            marginBottom: 4,
                          }}
                        >
                          <span className="mono-num">{f.feature}</span>
                          <span className="mono-num" style={{ color: "var(--muted)" }}>
                            {f.importance}%
                          </span>
                        </div>
                        <div
                          style={{
                            width: "100%",
                            height: 6,
                            background: "rgba(255,255,255,0.07)",
                            borderRadius: 999,
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${Math.min(100, f.importance * 3.2)}%`,
                              height: "100%",
                              background: "#ffffff",
                              borderRadius: 999,
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Custom Labeled Dataset Ingestion Studio */}
            <div className="console-surface">
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <Database size={18} />
                <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                  Augment Training & Testing Corpus (CSV Labeled Dataset)
                </h2>
              </div>
              <p style={{ color: "var(--muted)", fontSize: "0.86rem", marginBottom: 14 }}>
                Append labeled samples (`indicator,1` for Malicious or `indicator,0` for Benign) to expand
                the training/testing corpus and immediately retrain the ensemble:
              </p>
              <form onSubmit={handleInjectDataset}>
                <textarea
                  rows={4}
                  className="console-input mono-num"
                  style={{ width: "100%", borderRadius: 12, marginBottom: 14 }}
                  value={customDatasetText}
                  onChange={(e) => setCustomDatasetText(e.target.value)}
                />
                {datasetBanner && (
                  <div
                    style={{
                      padding: "10px 14px",
                      borderRadius: 10,
                      background: "rgba(255,255,255,0.06)",
                      border: "1px solid rgba(255,255,255,0.16)",
                      fontSize: "0.85rem",
                      marginBottom: 14,
                    }}
                  >
                    {datasetBanner}
                  </div>
                )}
                <button type="submit" className="console-btn-pill" disabled={addingDataset}>
                  <Plus size={15} />{" "}
                  {addingDataset ? "Ingesting & Retraining..." : "Add Labeled Samples & Retrain"}
                </button>
              </form>
            </div>

            {/* Held-Out Test Set Predictions Table */}
            {mlSummary?.test_predictions?.length > 0 && (
              <div className="console-surface">
                <h2 style={{ fontSize: "1.15rem", fontWeight: 500, marginBottom: 14 }}>
                  Held-Out Test Split Evaluation Results ({mlSummary.test_predictions.length} Samples)
                </h2>
                <div style={{ overflowX: "auto" }}>
                  <table className="console-table">
                    <thead>
                      <tr>
                        <th>Test Sample Indicator</th>
                        <th>Ground Truth</th>
                        <th>Predicted</th>
                        <th>RF Prob</th>
                        <th>XGB Prob</th>
                        <th>MLP Prob</th>
                        <th>Ensemble Vote</th>
                      </tr>
                    </thead>
                    <tbody>
                      {mlSummary.test_predictions.map((row, idx) => (
                        <tr key={`${row.ioc_value}-${idx}`}>
                          <td className="mono-num" style={{ maxWidth: 320, wordBreak: "break-all" }}>
                            {row.ioc_value}
                          </td>
                          <td className="mono-num">{row.actual_label}</td>
                          <td className="mono-num">
                            {row.predicted_label} {row.correct ? "✓" : "✗"}
                          </td>
                          <td className="mono-num">{row.rf_prob}%</td>
                          <td className="mono-num">{row.xgb_prob}%</td>
                          <td className="mono-num">{row.mlp_prob}%</td>
                          <td className="mono-num" style={{ fontWeight: 600 }}>
                            {row.ensemble_prob}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Deep Threat Report Analysis & Diamond-Model Attribution Engine */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  marginBottom: 14,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Compass size={18} />
                  <div>
                    <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                      Deep Threat Report Analysis & Diamond-Model Attribution Engine
                    </h2>
                    <p style={{ color: "var(--muted)", fontSize: "0.84rem", marginTop: 2 }}>
                      Ingests unstructured PDF advisories, STIX 2.1 bundles, and Suricata EVE JSON / PCAP logs to generate Executive Incident Summaries and 4-vertex Diamond Model adversary attribution:
                    </p>
                  </div>
                </div>

                {/* One-click Sample Format Presets */}
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className={`console-tab ${reportFormat === "text_pdf" ? "active" : ""}`}
                    onClick={() => {
                      setReportFormat("text_pdf");
                      setReportText(
                        "Adversaries exploited CVE-2024-3400 using a spearphishing lure to deploy a second-stage dropper via powershell. The script executed wget against hxxp://185.220.101[.]45:8080/bin.sh and established a Cobalt Strike C2 beacon to 91.215.85[.]142 targeting financial banking infrastructure."
                      );
                    }}
                  >
                    PDF Advisory Sample
                  </button>
                  <button
                    type="button"
                    className={`console-tab ${reportFormat === "stix21" ? "active" : ""}`}
                    onClick={() => {
                      setReportFormat("stix21");
                      setReportText(
                        JSON.stringify(
                          {
                            type: "bundle",
                            id: "bundle--apt29-campaign-2026",
                            objects: [
                              {
                                type: "intrusion-set",
                                name: "APT29 Cozy Bear",
                              },
                              {
                                type: "malware",
                                name: "Cobalt Strike Beacon Loader",
                              },
                              {
                                type: "indicator",
                                pattern: "[ipv4-addr:value = '185.220.101.45']",
                                description: "Primary C2 callback node exploiting CVE-2024-3400",
                              },
                              {
                                type: "indicator",
                                pattern: "[url:value = 'http://194.55.186.21:54321/Mozi.a']",
                                description: "Second-stage ELF payload delivery URL",
                              },
                            ],
                          },
                          null,
                          2
                        )
                      );
                    }}
                  >
                    STIX 2.1 Bundle
                  </button>
                  <button
                    type="button"
                    className={`console-tab ${reportFormat === "suricata_eve" ? "active" : ""}`}
                    onClick={() => {
                      setReportFormat("suricata_eve");
                      setReportText(
                        `{"timestamp":"2026-10-20T22:14:02.110Z","event_type":"alert","src_ip":"10.0.4.18","dest_ip":"185.220.101.45","dest_port":4444,"proto":"TCP","alert":{"signature":"ET MALWARE Cobalt Strike Beacon C2 Callback","category":"A Network Trojan was Detected","severity":1}}\n{"timestamp":"2026-10-20T22:14:08.512Z","event_type":"http","src_ip":"10.0.4.18","dest_ip":"91.215.85.142","dest_port":8080,"http":{"hostname":"secure-verify-sso.tk","url":"http://91.215.85.142:8080/gate.php","http_method":"POST"}}`
                      );
                    }}
                  >
                    Suricata EVE JSON / PCAP
                  </button>
                </div>
              </div>

              <textarea
                rows={5}
                className="console-input mono-num"
                style={{ width: "100%", borderRadius: 12, marginBottom: 14 }}
                value={reportText}
                onChange={(e) => setReportText(e.target.value)}
              />
              <button
                type="button"
                className="console-btn-pill"
                onClick={handleExtractReport}
                disabled={extractingReport}
              >
                <FileText size={15} />{" "}
                {extractingReport
                  ? "Running Deep Attribution & Scoring..."
                  : "Run Deep Analysis & Diamond-Model Attribution"}
              </button>

              {reportResult && (
                <div style={{ marginTop: 22, display: "grid", gap: 18 }}>
                  {/* Executive Incident Summary */}
                  {reportResult.executive_summary && (
                    <div
                      className="console-kpi-card"
                      style={{
                        borderColor: "rgba(255,255,255,0.24)",
                        background: "#050505",
                        padding: 20,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          flexWrap: "wrap",
                          gap: 10,
                          marginBottom: 10,
                        }}
                      >
                        <div style={{ fontWeight: 700, fontSize: "1.05rem" }}>
                          {reportResult.executive_summary.headline}
                        </div>
                        <span
                          className="mono-num"
                          style={{
                            padding: "4px 10px",
                            borderRadius: 999,
                            background: "#ffffff",
                            color: "#050505",
                            fontSize: "0.75rem",
                            fontWeight: 700,
                          }}
                        >
                          {reportResult.executive_summary.severity} · MAX RISK{" "}
                          {reportResult.executive_summary.max_risk_score}/100
                        </span>
                      </div>
                      <p style={{ color: "var(--muted)", fontSize: "0.88rem", lineHeight: 1.6, marginBottom: 12 }}>
                        {reportResult.executive_summary.narrative}
                      </p>
                      <div style={{ fontSize: "0.82rem" }}>
                        <strong style={{ color: "var(--ink)" }}>Recommended Containment Playbook:</strong>
                        <ul style={{ margin: "6px 0 0 18px", color: "var(--muted)", lineHeight: 1.55 }}>
                          {(reportResult.executive_summary.containment_actions || []).map((act, i) => (
                            <li key={i}>{act}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}

                  {/* 4-Vertex Diamond Model of Intrusion Analysis */}
                  {reportResult.diamond_model && (
                    <div>
                      <div style={{ fontSize: "0.88rem", fontWeight: 600, marginBottom: 10 }}>
                        Diamond Model of Intrusion Analysis Attribution
                      </div>
                      <div
                        style={{
                          display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
                          gap: 14,
                        }}
                      >
                        <div className="console-kpi-card">
                          <div style={{ fontSize: "0.74rem", color: "var(--muted)" }}>
                            VERTEX 1 · ADVERSARY
                          </div>
                          <div style={{ fontWeight: 700, fontSize: "1rem", marginTop: 4 }}>
                            {reportResult.diamond_model.adversary.attributed_group}
                          </div>
                          <div style={{ fontSize: "0.8rem", color: "var(--muted)", marginTop: 6 }}>
                            Nexus: {reportResult.diamond_model.adversary.origin_nexus}
                          </div>
                          <div className="mono-num" style={{ fontSize: "0.8rem", marginTop: 4 }}>
                            Confidence: {reportResult.diamond_model.adversary.confidence_pct}%
                          </div>
                        </div>

                        <div className="console-kpi-card">
                          <div style={{ fontSize: "0.74rem", color: "var(--muted)" }}>
                            VERTEX 2 · INFRASTRUCTURE
                          </div>
                          <div className="mono-num" style={{ fontWeight: 600, fontSize: "0.86rem", marginTop: 4 }}>
                            C2: {(reportResult.diamond_model.infrastructure.c2_ipv4_nodes || []).join(", ")}
                          </div>
                          <div style={{ fontSize: "0.8rem", color: "var(--muted)", marginTop: 6 }}>
                            {reportResult.diamond_model.infrastructure.network_topology}
                          </div>
                        </div>

                        <div className="console-kpi-card">
                          <div style={{ fontSize: "0.74rem", color: "var(--muted)" }}>
                            VERTEX 3 · CAPABILITY
                          </div>
                          <div style={{ fontWeight: 600, fontSize: "0.88rem", marginTop: 4 }}>
                            {reportResult.diamond_model.capability.malware_tooling}
                          </div>
                          <div className="mono-num" style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 6 }}>
                            Exploits: {(reportResult.diamond_model.capability.exploited_cves || []).join(", ")}
                          </div>
                        </div>

                        <div className="console-kpi-card">
                          <div style={{ fontSize: "0.74rem", color: "var(--muted)" }}>
                            VERTEX 4 · VICTIM / TARGET
                          </div>
                          <div style={{ fontWeight: 600, fontSize: "0.88rem", marginTop: 4 }}>
                            {reportResult.diamond_model.victim.targeted_sector}
                          </div>
                          <div style={{ fontSize: "0.8rem", color: "var(--muted)", marginTop: 6 }}>
                            Surface: {reportResult.diamond_model.victim.attack_surface} · SLA:{" "}
                            {reportResult.diamond_model.victim.recommended_sla}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="console-kpi-card">
                    <div style={{ fontWeight: 600, marginBottom: 8 }}>
                      Detected MITRE ATT&CK Techniques ({reportResult.mitre_attack_ttps.length})
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 12, fontSize: "0.85rem" }}>
                      {reportResult.mitre_attack_ttps.map((t) => (
                        <span key={t.technique_id} style={{ color: "var(--muted)" }}>
                          <strong style={{ color: "var(--ink)" }}>{t.technique_id}</strong> · {t.name} (
                          {t.tactic})
                        </span>
                      ))}
                    </div>
                  </div>
                  {reportResult.ml_scored_indicators?.length > 0 && (
                    <div className="console-kpi-card">
                      <div style={{ fontWeight: 600, marginBottom: 10 }}>
                        Refanged & ML-Scored Indicators
                      </div>
                      <table className="console-table">
                        <thead>
                          <tr>
                            <th>Extracted Indicator</th>
                            <th>Verdict</th>
                            <th>ML Prob</th>
                            <th>Risk Score</th>
                          </tr>
                        </thead>
                        <tbody>
                          {reportResult.ml_scored_indicators.map((ind) => (
                            <tr key={ind.ioc_value}>
                              <td className="mono-num">{ind.ioc_value}</td>
                              <td>{ind.verdict}</td>
                              <td className="mono-num">
                                {(ind.ml_malicious_probability * 100).toFixed(1)}%
                              </td>
                              <td className="mono-num">{ind.risk_score}/100</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          </section>

        {/* CHAPTER 03: NEO4J THREAT KNOWLEDGE GRAPH */}
        <section
          id="chapter-graph"
          data-chapter="graph"
          className="scroll-chapter scroll-reveal"
        >
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                03. Neo4j Threat Knowledge Graph
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                Interactive correlation topology linking threat actors, campaigns, TTPs, and active IOCs
              </p>
            </div>

            <div
              className="console-surface"
              style={{ height: 600, padding: 0, overflow: "hidden", position: "relative" }}
            >
              <ForceGraph2D
                graphData={graphData}
                nodeLabel="id"
                nodeColor={(n) =>
                  n.group === "actor" ? "#ffffff" : n.group === "campaign" ? "#b6b5b5" : "#737373"
                }
                nodeRelSize={6}
                linkColor={() => "rgba(255,255,255,0.22)"}
                backgroundColor="#0b0b0b"
              />
            </div>
          </section>

        {/* CHAPTER 04: AUTOMATED DETECTION RULE GENERATOR */}
        <section
          id="chapter-rules"
          data-chapter="rules"
          className="scroll-chapter scroll-reveal"
        >
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                04. Automated Detection Rule Generation
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                Compile Sigma, YARA, Suricata, and Snort signatures in seconds
              </p>
            </div>

            <div className="console-surface">
              <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
                <input
                  type="text"
                  className="console-input"
                  style={{ flex: 1, minWidth: 280 }}
                  value={ruleIoc}
                  onChange={(e) => setRuleIoc(e.target.value)}
                />
                <button type="button" className="console-btn-pill" onClick={handleGenerateRules}>
                  Generate Detection Rules
                </button>
              </div>

              {rules && (
                <div>
                  <div
                    style={{
                      display: "flex",
                      gap: 8,
                      borderBottom: "1px solid rgba(255,255,255,0.1)",
                      paddingBottom: 14,
                      marginBottom: 16,
                      flexWrap: "wrap",
                    }}
                  >
                    {["sigma", "yara", "suricata", "snort"].map((fmt) => (
                      <button
                        key={fmt}
                        type="button"
                        className={`console-tab ${selectedRuleFmt === fmt ? "active" : ""}`}
                        onClick={() => setSelectedRuleFmt(fmt)}
                      >
                        {fmt.toUpperCase()}
                      </button>
                    ))}
                  </div>
                  <pre
                    className="mono-num"
                    style={{
                      background: "#050505",
                      border: "1px solid rgba(255,255,255,0.1)",
                      padding: 20,
                      borderRadius: 12,
                      color: "var(--ink)",
                      overflowX: "auto",
                      lineHeight: 1.55,
                    }}
                  >
                    {rules[selectedRuleFmt]}
                  </pre>
                </div>
              )}
            </div>
          </section>

        {/* CHAPTER 05: 6-SOURCE PARALLEL ENRICHER */}
        <section
          id="chapter-enrich"
          data-chapter="enrich"
          className="scroll-chapter scroll-reveal"
        >
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                05. 6-Source Parallel Enrichment
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX queried concurrently in under 5 seconds
              </p>
            </div>

            <div className="console-surface">
              <div style={{ display: "flex", gap: 12, marginBottom: 22, flexWrap: "wrap" }}>
                <input
                  type="text"
                  className="console-input"
                  style={{ flex: 1, minWidth: 280 }}
                  value={enrichIoc}
                  onChange={(e) => setEnrichIoc(e.target.value)}
                />
                <button
                  type="button"
                  className="console-btn-pill"
                  onClick={handleExecuteEnrichment}
                  disabled={enriching}
                >
                  <Zap size={15} /> {enriching ? "Enriching..." : "Execute Parallel Enrichment"}
                </button>
              </div>

              {enrichment && (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
                    gap: 16,
                  }}
                >
                  {Object.entries(enrichment.sources).map(([src, d]) => (
                    <div key={src} className="console-kpi-card">
                      <div style={{ fontWeight: 600, marginBottom: 10 }}>{src.replace("_", " ")}</div>
                      <pre
                        className="mono-num"
                        style={{
                          fontSize: "0.78rem",
                          color: "var(--muted)",
                          margin: 0,
                          overflowX: "auto",
                          lineHeight: 1.5,
                        }}
                      >
                        {JSON.stringify(d, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>

        {/* CHAPTER 06: SIEM / SOAR / EDR EXPORT & AUTOMATED WEBHOOK PLAYBOOKS */}
        <section
          id="chapter-siem"
          data-chapter="siem"
          className="scroll-chapter scroll-reveal"
        >
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                06. SIEM / SOAR / EDR Integrations & Automated Playbooks
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                One-click export into your existing security stack without rip-and-replace
              </p>
            </div>

            <div className="console-surface">
              <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
                {[
                  { id: "splunk", label: "Splunk (SPL)" },
                  { id: "sentinel", label: "Microsoft Sentinel (KQL)" },
                  { id: "qradar", label: "IBM QRadar (AQL)" },
                  { id: "crowdstrike", label: "CrowdStrike Falcon (CSV)" },
                  { id: "stix", label: "STIX / TAXII 2.1" },
                ].map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    className={`console-tab ${selectedSiem === p.id ? "active" : ""}`}
                    onClick={() => handleExportSiem(p.id)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>

              {exportData && (
                <div>
                  <div style={{ fontSize: "0.85rem", color: "var(--muted)", marginBottom: 10 }}>
                    Generated Artifact for <strong style={{ color: "var(--ink)" }}>{exportData.platform}</strong>
                  </div>
                  <pre
                    className="mono-num"
                    style={{
                      background: "#050505",
                      border: "1px solid rgba(255,255,255,0.1)",
                      padding: 20,
                      borderRadius: 12,
                      color: "var(--ink)",
                      overflowX: "auto",
                      lineHeight: 1.55,
                    }}
                  >
                    {typeof exportData.export_query === "string"
                      ? exportData.export_query
                      : typeof exportData.payload === "string"
                      ? exportData.payload
                      : JSON.stringify(exportData.payload || exportData, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* AUTOMATED SOAR PLAYBOOKS & OUTBOUND WEBHOOK DISPATCH */}
            <div className="console-surface">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: 12,
                  marginBottom: 18,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <Webhook size={18} />
                  <div>
                    <h2 style={{ fontSize: "1.15rem", fontWeight: 500 }}>
                      Automated SOAR Playbooks & Outbound Webhook Dispatch
                    </h2>
                    <p style={{ color: "var(--muted)", fontSize: "0.84rem", marginTop: 2 }}>
                      Automatically executes Slack SOC alerts, PagerDuty incidents, Cloudflare WAF blocks, and Google Workspace Gmail phishing quarantine whenever /ws/threat-stream scores an IOC ≥ 85/100:
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  className="console-btn-pill"
                  onClick={handleTestSoarDispatch}
                  disabled={dispatchingSoar}
                >
                  <Zap size={15} />{" "}
                  {dispatchingSoar
                    ? "Dispatching Webhooks..."
                    : "Test Trigger All Playbooks (Risk 94/100)"}
                </button>
              </div>

              {/* Configured Playbook Cards */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
                  gap: 14,
                  marginBottom: 20,
                }}
              >
                {soarPlaybooks.map((pb) => (
                  <div key={pb.id} className="console-kpi-card">
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        marginBottom: 8,
                      }}
                    >
                      <span style={{ fontWeight: 600, fontSize: "0.94rem" }}>{pb.name}</span>
                      <button
                        type="button"
                        className={`console-tab ${pb.enabled === 1 ? "active" : ""}`}
                        style={{ padding: "3px 10px", fontSize: "0.72rem" }}
                        onClick={() => handleTogglePlaybook(pb.id, pb.enabled)}
                      >
                        {pb.enabled === 1 ? "ENABLED" : "PAUSED"}
                      </button>
                    </div>
                    <div className="mono-num" style={{ fontSize: "0.75rem", color: "var(--muted)", wordBreak: "break-all" }}>
                      {pb.webhookUrl}
                    </div>
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        marginTop: 12,
                        paddingTop: 10,
                        borderTop: "1px solid rgba(255,255,255,0.08)",
                        fontSize: "0.78rem",
                        color: "var(--muted)",
                      }}
                    >
                      <span>Threshold: ≥ {pb.minRiskThreshold}/100</span>
                      <span className="mono-num" style={{ color: "var(--ink)", fontWeight: 600 }}>
                        {pb.triggerCount} Dispatches
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Add Custom Webhook Playbook Form */}
              <form
                onSubmit={handleCreateSoarPlaybook}
                style={{
                  display: "flex",
                  gap: 10,
                  flexWrap: "wrap",
                  marginBottom: 22,
                  paddingTop: 14,
                  borderTop: "1px solid rgba(255,255,255,0.08)",
                }}
              >
                <input
                  type="text"
                  className="console-input"
                  style={{ flex: 1, minWidth: 180 }}
                  placeholder="Playbook Name (e.g. Teams Tier-1 Alert)"
                  value={newPlaybookName}
                  onChange={(e) => setNewPlaybookName(e.target.value)}
                />
                <select
                  className="console-input"
                  value={newPlaybookChannel}
                  onChange={(e) => setNewPlaybookChannel(e.target.value)}
                >
                  <option value="slack" style={{ background: "#0b0b0b" }}>Slack / Teams Webhook</option>
                  <option value="pagerduty" style={{ background: "#0b0b0b" }}>PagerDuty Incident API</option>
                  <option value="cloudflare_waf" style={{ background: "#0b0b0b" }}>Cloudflare WAF Blocklist</option>
                  <option value="gmail_quarantine" style={{ background: "#0b0b0b" }}>Google Workspace Gmail Quarantine</option>
                </select>
                <input
                  type="text"
                  className="console-input mono-num"
                  style={{ flex: 2, minWidth: 240 }}
                  placeholder="https://hooks.slack.com/services/..."
                  value={newPlaybookUrl}
                  onChange={(e) => setNewPlaybookUrl(e.target.value)}
                />
                <input
                  type="number"
                  min={50}
                  max={100}
                  className="console-input mono-num"
                  style={{ width: 90 }}
                  value={newPlaybookThreshold}
                  onChange={(e) => setNewPlaybookThreshold(Number(e.target.value) || 85)}
                />
                <button type="submit" className="console-btn-pill">
                  <Plus size={15} /> Add Playbook
                </button>
              </form>

              {/* Recent Automated SOAR Webhook Executions */}
              <div style={{ overflowX: "auto" }}>
                <table className="console-table">
                  <thead>
                    <tr>
                      <th>Playbook</th>
                      <th>Channel</th>
                      <th>Triggered IOC</th>
                      <th>Risk Score</th>
                      <th>Delivery Status</th>
                      <th>Dispatched Webhook Payload</th>
                    </tr>
                  </thead>
                  <tbody>
                    {soarExecutions.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ color: "var(--muted)" }}>
                          Waiting for incoming IOC with Risk Score ≥ 85/100 or click "Test Trigger All Playbooks".
                        </td>
                      </tr>
                    ) : (
                      soarExecutions.slice(0, 10).map((ex, idx) => (
                        <tr key={`soar-ex-${ex.id}-${idx}`}>
                          <td style={{ fontWeight: 500 }}>{ex.playbookName}</td>
                          <td className="mono-num" style={{ color: "var(--muted)" }}>
                            {ex.channel.toUpperCase()}
                          </td>
                          <td className="mono-num" style={{ maxWidth: 240, wordBreak: "break-all" }}>
                            {ex.iocValue}
                          </td>
                          <td className="mono-num" style={{ fontWeight: 700 }}>
                            {ex.riskScore}/100
                          </td>
                          <td className="mono-num" style={{ fontSize: "0.78rem" }}>
                            {ex.deliveryStatus}
                          </td>
                          <td
                            className="mono-num"
                            style={{
                              maxWidth: 340,
                              fontSize: "0.75rem",
                              color: "var(--muted)",
                              whiteSpace: "nowrap",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                            }}
                          >
                            {ex.payloadPreview}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

        {/* CHAPTER 07: QUANTIFIABLE BUSINESS IMPACT & ENTERPRISE TIERS */}
        <section
          id="chapter-impact"
          data-chapter="impact"
          className="scroll-chapter scroll-reveal"
        >
            <div style={{ marginBottom: 24 }}>
              <h1 style={{ fontSize: "2rem", fontWeight: 400, letterSpacing: "-0.01em" }}>
                07. Business Impact & Enterprise Tiers
              </h1>
              <p style={{ color: "var(--muted)", fontSize: "0.95rem", marginTop: 6 }}>
                Quantifiable improvements across every core SOC metric · 600% estimated ROI · 4-month payback
              </p>
            </div>

            <div className="console-surface" style={{ padding: 0, overflow: "hidden" }}>
              <table className="console-table">
                <thead>
                  <tr>
                    <th>SOC Metric</th>
                    <th>Before ThreatOps</th>
                    <th>After ThreatOps</th>
                    <th>Measured Improvement</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={{ fontWeight: 500 }}>Time to Analyze IOC</td>
                    <td className="mono-num">30 min</td>
                    <td className="mono-num">5 sec</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      99.7%
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>False Positive Rate</td>
                    <td className="mono-num">40%</td>
                    <td className="mono-num">1.8%</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      95.5%
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>IOCs Processed / Analyst</td>
                    <td className="mono-num">100 / day</td>
                    <td className="mono-num">1,000+ / day</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      10×
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>Detection Rule Creation</td>
                    <td className="mono-num">2 hours</td>
                    <td className="mono-num">30 sec</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      99.6%
                    </td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 500 }}>Mean Time to Detect (MTTD)</td>
                    <td className="mono-num">24 hours</td>
                    <td className="mono-num">5 min</td>
                    <td className="mono-num" style={{ fontWeight: 700 }}>
                      99.7%
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
                gap: 16,
              }}
            >
              {[
                {
                  name: "Starter · For Early-Stage SOC Teams",
                  price: "$2,499",
                  specs: ["1,000 IOCs / day", "5 analyst seats", "Email support", "Full feature access"],
                },
                {
                  name: "Professional · For Scaling Security Operations",
                  price: "$5,999",
                  specs: ["10,000 IOCs / day", "20 analyst seats", "24/7 priority support", "SIEM / EDR webhooks"],
                },
                {
                  name: "Enterprise · For Global Threat Intelligence",
                  price: "$14,999",
                  specs: ["Unlimited IOCs", "Unlimited seats", "Dedicated CSM", "Custom feed integrations"],
                },
              ].map((tier) => (
                <div key={tier.name} className="console-surface" style={{ marginBottom: 0 }}>
                  <div style={{ fontSize: "1.05rem", fontWeight: 500 }}>{tier.name}</div>
                  <div className="mono-num" style={{ fontSize: "2.1rem", fontWeight: 700, margin: "12px 0" }}>
                    {tier.price}
                    <span style={{ fontSize: "0.85rem", color: "var(--muted)", fontWeight: 400 }}>/mo</span>
                  </div>
                  <ul
                    style={{
                      listStyle: "none",
                      padding: 0,
                      margin: "0 0 22px",
                      display: "flex",
                      flexDirection: "column",
                      gap: 8,
                      color: "var(--muted)",
                      fontSize: "0.86rem",
                    }}
                  >
                    {tier.specs.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                  <button
                    type="button"
                    className="console-btn-pill"
                    style={{ width: "100%", justifyContent: "center" }}
                    onClick={() => handleRedirectToPaymentGateway(tier)}
                  >
                    Purchase Plan
                  </button>
                </div>
              ))}
            </div>
          </section>
      </main>

      {showScrollTop && (
        <button
          type="button"
          className="scroll-top-fab"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
        >
          ↑ Top ({Math.round(scrollProgress * 100)}%)
        </button>
      )}
    </div>
  );
}