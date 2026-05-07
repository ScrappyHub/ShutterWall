import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

const sections = {
  overview: {
    title: "Overview",
    desc: "Start here. Understand your local network without changing anything.",
    actions: [
      { cmd: "posture", title: "Protection Status", desc: "Shows your current protection mode and recommended next action." },
      { cmd: "quickstart", title: "Quickstart", desc: "Runs safe discovery and a home-safe preview." },
      { cmd: "inspect", title: "Inspect", desc: "Discovers devices. No firewall changes." },
      { cmd: "identity", title: "Identity", desc: "Labels devices with type and confidence." },
      { cmd: "registry", title: "Device Registry", desc: "Shows persistent network memory: labels, trust state, changes, and last seen." },
    ],
  },
  review: {
    title: "Review",
    desc: "Classify devices on your network and decide what belongs.",
    actions: [
      { cmd: "review", title: "Open Review", desc: "Load remembered devices, latest scan time, diffs, alerts, and next actions." },
      { cmd: "identity", title: "Refresh Identity", desc: "Update device identity hints before reviewing." },
    ],
  },
  security: {
    title: "Security",
    desc: "Create a trusted baseline, compare against it, and monitor for changes.",
    actions: [
      { cmd: "baseline", title: "Baseline", desc: "Stores current network as known-good." },
      { cmd: "diff", title: "Diff", desc: "Finds new, missing, or changed devices." },
      { cmd: "watch 1", title: "Watch", desc: "Runs one monitoring check." },
    ],
  },
  enforce: {
    title: "Enforce",
    desc: "Preview protections first. Apply and undo stay administrator-gated.",
    actions: [
      { cmd: "scan", title: "Scan Preview", desc: "Builds a protection plan without applying changes." },
      { cmd: "apply", title: "Apply Protection (Admin Required - Coming Soon)", desc: "Requires confirmation and administrator elevation. Applies ShutterWall firewall protection rules.", confirm: "APPLY" },
      { cmd: "undo", title: "Undo Protection (Admin Required - Coming Soon)", desc: "Requires confirmation and administrator elevation. Removes ShutterWall firewall rules.", confirm: "UNDO" },
    ],
  },
  activity: {
    title: "Activity",
    desc: "Review persistent alerts and recent protection events.",
    actions: [
      { cmd: "alerts", title: "Alert Center", desc: "Shows historical alerts, trust changes, and review events." },
    ],
  },
  evidence: {
    title: "Evidence",
    desc: "Review raw command output and evidence paths when needed.",
    actions: [],
  },
};

function parseOutput(text) {
  const lines = String(text || "").split(/\r?\n/);

  const alerts = lines.filter((line) =>
    line.trim().startsWith("ALERT_") && !line.trim().startsWith("ALERT_COUNT")
  );

  const identities = lines
    .filter((line) => line.trim().startsWith("DEVICE_IDENTITY ::"))
    .map((line) => {
      const parts = line.trim().split("::").map((p) => p.trim());
      return {
        ip: parts[1] || "",
        label: parts[2] || "Unknown Device",
        confidence: (parts[3] || "").replace("confidence=", ""),
        vendor: (parts[4] || "").replace("vendor=", ""),
        userLabel: (parts[5] || "").replace("user_label=", ""),
      };
    });

  const registryDevices = lines
    .filter((line) => line.trim().startsWith("DEVICE_REGISTRY ::"))
    .map((line) => {
      const parts = line.trim().split("::").map((p) => p.trim());
      return {
        ip: parts[1] || "",
        name: parts[2] || "Unknown Device",
        trust: (parts[3] || "").replace("trust=", ""),
        trustBadge: ((parts[3] || "").replace("trust=", "") || "unknown").toLowerCase(),
        changes: (parts[4] || "").replace("changes=", ""),
        lastSeen: (parts[5] || "").replace("last_seen=", ""),
      };
    });

  const posture = {
    mode: "",
    recommended: "",
    deviceCount: "",
    labeledCount: "",
    needsReview: "",
    latestAlerts: "",
    baselineExists: "",
    trustedCount: "",
    reviewTrustCount: "",
    blockedCount: "",
    unknownTrustCount: ""
  };

  lines.forEach((line) => {
    if (line.startsWith("POSTURE_MODE:")) posture.mode = line.replace("POSTURE_MODE:", "").trim();
    if (line.startsWith("RECOMMENDED_ACTION:")) posture.recommended = line.replace("RECOMMENDED_ACTION:", "").trim();
    if (line.startsWith("DEVICE_COUNT:")) posture.deviceCount = line.replace("DEVICE_COUNT:", "").trim();
    if (line.startsWith("LABELED_DEVICE_COUNT:")) posture.labeledCount = line.replace("LABELED_DEVICE_COUNT:", "").trim();
    if (line.startsWith("NEEDS_REVIEW_COUNT:")) posture.needsReview = line.replace("NEEDS_REVIEW_COUNT:", "").trim();
    if (line.startsWith("LATEST_ALERT_COUNT:")) posture.latestAlerts = line.replace("LATEST_ALERT_COUNT:", "").trim();
    if (line.startsWith("BASELINE_EXISTS:")) posture.baselineExists = line.replace("BASELINE_EXISTS:", "").trim();
    if (line.startsWith("TRUSTED_COUNT:")) posture.trustedCount = line.replace("TRUSTED_COUNT:", "").trim();
    if (line.startsWith("REVIEW_TRUST_COUNT:")) posture.reviewTrustCount = line.replace("REVIEW_TRUST_COUNT:", "").trim();
    if (line.startsWith("BLOCKED_COUNT:")) posture.blockedCount = line.replace("BLOCKED_COUNT:", "").trim();
    if (line.startsWith("UNKNOWN_TRUST_COUNT:")) posture.unknownTrustCount = line.replace("UNKNOWN_TRUST_COUNT:", "").trim();
  });

  const reviewDevices = lines
    .filter((line) => line.trim().startsWith("REVIEW_DEVICE ::"))
    .map((line) => {
      const parts = line.trim().split("::").map((p) => p.trim());
      return {
        ip: parts[1] || "",
        label: parts[2] || "Unrecognized Device",
        trust: (parts[3] || "").replace("trust=", ""),
        changes: (parts[4] || "").replace("changes=", ""),
        lastSeen: (parts[5] || "").replace("last_seen=", ""),
        action: (parts[6] || "").replace("action=", ""),
      };
    });

  const review = {
    posture: "",
    recommended: "",
    deviceCount: "",
    lastScanned: "",
    latestDiffPath: "",
    alertHistoryCount: "",
  };

  lines.forEach((line) => {
    if (line.startsWith("REVIEW_POSTURE:")) review.posture = line.replace("REVIEW_POSTURE:", "").trim();
    if (line.startsWith("REVIEW_RECOMMENDED_ACTION:")) review.recommended = line.replace("REVIEW_RECOMMENDED_ACTION:", "").trim();
    if (line.startsWith("REVIEW_DEVICE_COUNT:")) review.deviceCount = line.replace("REVIEW_DEVICE_COUNT:", "").trim();
    if (line.startsWith("REVIEW_LAST_SCANNED_UTC:")) review.lastScanned = line.replace("REVIEW_LAST_SCANNED_UTC:", "").trim();
    if (line.startsWith("REVIEW_LATEST_DIFF_PATH:")) review.latestDiffPath = line.replace("REVIEW_LATEST_DIFF_PATH:", "").trim();
    if (line.startsWith("REVIEW_ALERT_HISTORY_COUNT:")) review.alertHistoryCount = line.replace("REVIEW_ALERT_HISTORY_COUNT:", "").trim();
  });

  const alertItems = lines
    .filter((line) => line.trim().startsWith("ALERT_CENTER ::"))
    .map((line) => {
      const parts = line.trim().split("::").map((p) => p.trim());
      return {
        severity: parts[1] || "info",
        type: parts[2] || "alert",
        ip: parts[3] || "",
        message: parts[4] || "",
        ts: parts[5] || "",
      };
    });

  const summaryLines = lines.filter((line) =>
    line.startsWith("BASELINE_PATH:") ||
    line.startsWith("BASELINE_HASH:") ||
    line.startsWith("DEVICE_COUNT:") ||
    line.startsWith("FINGERPRINT_COUNT:") ||
    line.startsWith("CANDIDATE_HOSTS:") ||
    line.startsWith("FINDING_COUNT:") ||
    line.startsWith("ACTION_COUNT:") ||
    line.startsWith("TARGET_IPS:") ||
    line.startsWith("WATCH_TICK_STATE:") ||
    line.startsWith("WATCH_TICK_ALERTS:") ||
    line.endsWith("_OK")
  );

  const stable = lines.some((line) => line.trim() === "NETWORK_STATE_STABLE");
  const changed = lines.some((line) => line.trim() === "NETWORK_STATE_CHANGED");
  const ok = lines.some((line) => line.includes("_OK"));

  let stateLabel = "Ready";
  if (lines.some((l) => l.includes("SHUTTERWALL_IDENTITY_V1_OK"))) stateLabel = "Devices Identified";
  else if (lines.some((l) => l.includes("SHUTTERWALL_BASELINE_V1_OK"))) stateLabel = "Baseline Updated";
  else if (lines.some((l) => l.includes("SHUTTERWALL_PROTECT_OK"))) stateLabel = "Scan Preview Ready";
  else if (changed) stateLabel = "Network Changed";
  else if (stable) stateLabel = "Network Stable";
  else if (ok) stateLabel = "Command Complete";

  return {
    state: changed ? "changed" : stable ? "stable" : ok ? "ok" : "idle",
    stateLabel,
    alerts,
    identities,
    registryDevices,
    posture,
    review,
    reviewDevices,
    alertItems,
    summaryLines,
  };
}

function IdentityCard({ device }) {
  return (
    <div className="identity-card">
      <strong>{device.userLabel || device.label}</strong>
      {device.userLabel ? <span className="engine-guess">Engine guess: {device.label}</span> : null}
      {device.label === "Needs Review" ? (
        <div className="review-note">Not enough strong fingerprint evidence yet. Label this device if you recognize it.</div>
      ) : null}
      <span className="identity-ip">IP: {device.ip}</span>
      <div className="identity-meta">
        <span>Confidence: {device.confidence || "unknown"}</span>
        <span>Vendor: {device.vendor || "unknown"}</span>
      </div>
    </div>
  );
}

function DeviceRecommendation({ device }) {
  const trust = (device.trustBadge || "unknown").toLowerCase();

  let text = "Review this device before trusting it.";
  if (trust === "trusted") text = "This device is recognized and trusted on this network.";
  if (trust === "review") text = "Keep this device under review until you confirm what it is.";
  if (trust === "blocked") text = "This device is marked suspicious. Use enforcement only after review.";
  if (trust === "unknown") text = "This device has not been classified yet.";

  return <div className="device-recommendation">{text}</div>;
}

function RegistryCard({ device, onTrust }) {
  return (
    <div className="registry-card">
      <strong>{device.name}</strong>
      <span className="registry-ip">IP: {device.ip}</span>
      <div className={"trust-pill trust-" + (device.trustBadge || "unknown")}>
        {device.trust || "unknown"}
      </div>

      <div className="registry-meta">
        <span>Protection State: {device.trust || "unknown"}</span>
        <span>Changes: {device.changes || "0"}</span>
        <span>Last seen: {device.lastSeen || "unknown"}</span>
      </div>

      <DeviceRecommendation device={device} />

      <div className="registry-actions">
        <button type="button" className="trust-action trusted" onClick={() => onTrust(device.ip, "trusted")}>I Recognize This</button>
        <button type="button" className="trust-action review" onClick={() => onTrust(device.ip, "review")}>Needs Review</button>
        <button type="button" className="trust-action blocked" onClick={() => onTrust(device.ip, "blocked")}>Mark Suspicious</button>
        <button type="button" className="trust-action unknown" onClick={() => onTrust(device.ip, "unknown")}>Ignore For Now</button>
      </div>
    </div>
  );
}

function ReviewDeviceCard({ device, onTrust }) {
  return (
    <div className={"review-device-card trust-" + ((device.trust || "unknown").toLowerCase())}>
      <div className="review-device-top">
        <strong>{device.label}</strong>
        <span>{device.trust || "unknown"}</span>
      </div>
      <div className="review-device-ip">IP: {device.ip}</div>
      <p>{device.action || "Review this device."}</p>
      <div className="review-device-meta">
        <span>Changes: {device.changes || "0"}</span>
        <span>Last seen: {device.lastSeen || "unknown"}</span>
      </div>
      <div className="registry-actions">
        <button type="button" className="trust-action trusted" onClick={() => onTrust(device.ip, "trusted")}>I Recognize This</button>
        <button type="button" className="trust-action review" onClick={() => onTrust(device.ip, "review")}>Needs Review</button>
        <button type="button" className="trust-action blocked" onClick={() => onTrust(device.ip, "blocked")}>Mark Suspicious</button>
        <button type="button" className="trust-action unknown" onClick={() => onTrust(device.ip, "unknown")}>Ignore For Now</button>
      </div>
    </div>
  );
}

function AlertCard({ alert }) {
  return (
    <div className={"alert-card severity-" + (alert.severity || "info")}>
      <div className="alert-topline">
        <strong>{alert.type || "Alert"}</strong>
        <span>{alert.severity || "info"}</span>
      </div>
      <p>{alert.message || "No details available."}</p>
      <div className="alert-meta">
        {alert.ip ? <span>IP: {alert.ip}</span> : null}
        {alert.ts ? <span>{alert.ts}</span> : null}
      </div>
    </div>
  );
}

export default function App() {
  const [active, setActive] = useState("overview");
  const [output, setOutput] = useState("Ready. Choose an action.");
  const [running, setRunning] = useState(false);
  const [lastCommand, setLastCommand] = useState("");
  const [showRaw, setShowRaw] = useState(false);

  const parsed = useMemo(() => parseOutput(output), [output]);
  const current = sections[active];

  async function run(cmd) {
    setRunning(true);
    setLastCommand("shutterwall " + cmd);
    setOutput("RUNNING: shutterwall " + cmd + "\n");

    try {
      const result = await invoke("run_shutterwall", { cmd });
      setOutput(String(result || "NO_OUTPUT"));
    } catch (err) {
      setOutput("UI_COMMAND_FAILED:\n" + String(err));
    } finally {
      setRunning(false);
    }
  }

  async function setDeviceTrust(ip, trustState) {
    const cmd = "trust-set " + ip + " " + trustState;
    setRunning(true);
    setLastCommand("shutterwall " + cmd);
    setOutput("RUNNING: shutterwall " + cmd + "\n");

    try {
      const trustResult = await invoke("run_shutterwall", { cmd });
      const registryResult = await invoke("run_shutterwall", { cmd: "registry" });
      const postureResult = await invoke("run_shutterwall", { cmd: "posture" });

      setOutput(
        String(trustResult || "") +
        "\n" +
        String(registryResult || "") +
        "\n" +
        String(postureResult || "")
      );
    } catch (err) {
      setOutput("UI_COMMAND_FAILED:\n" + String(err));
    } finally {
      setRunning(false);
    }
  }

  return (
    <main className="app-layout">
      <aside className="sidebar">
        <div className="brand">
          <span>SHUTTERWALL</span>
          <strong>Network Protection</strong>
        </div>

        {Object.entries(sections).map(([key, section]) => (
          <button key={key} className={"nav-item " + (active === key ? "active" : "")} onClick={() => setActive(key)}>
            {section.title}
          </button>
        ))}

        <div className="side-state">
          <strong>{parsed.stateLabel}</strong>
          <span>{parsed.alerts.length} alert(s)</span>
        </div>
      </aside>

      <section className="main-panel">
        <section className="hero compact">
          <p className="eyebrow">ShutterWall</p>
          <h1>{current.title}</h1>
          <p className="sub">{current.desc}</p>
        </section>

        {parsed.posture.mode && active === "overview" ? (
          <section className="posture-section">
            <div className="posture-header">
              <span>Protection Status</span>
              <strong>{parsed.posture.mode}</strong>
            </div>
            <p>{parsed.posture.recommended}</p>
            <div className="posture-grid">
              <div className="posture-metric neutral"><strong>{parsed.posture.deviceCount || "0"}</strong><span>Known devices</span></div>
              <div className="posture-metric trusted"><strong>{parsed.posture.trustedCount || "0"}</strong><span>Trusted</span></div>
              <div className="posture-metric review"><strong>{parsed.posture.reviewTrustCount || "0"}</strong><span>In review</span></div>
              <div className="posture-metric unknown"><strong>{parsed.posture.unknownTrustCount || "0"}</strong><span>Unknown</span></div>
              <div className="posture-metric blocked"><strong>{parsed.posture.blockedCount || "0"}</strong><span>Blocked</span></div>
              <div className="posture-metric alert"><strong>{parsed.posture.latestAlerts || "0"}</strong><span>Latest alerts</span></div>
              <div className="posture-metric review wide"><strong>{parsed.posture.needsReview || "0"}</strong><span>Need review</span></div>
            </div>
          </section>
        ) : null}

        {active === "review" && parsed.review.posture ? (
          <section className="review-control-room">
            <div>
              <span>Review State</span>
              <strong>{parsed.review.posture}</strong>
              <p>{parsed.review.recommended}</p>
            </div>
            <div className="review-control-grid">
              <div><strong>{parsed.review.deviceCount || "0"}</strong><span>Remembered devices</span></div>
              <div><strong>{parsed.review.alertHistoryCount || "0"}</strong><span>Recorded alerts</span></div>
              <div><strong>{parsed.review.lastScanned || "unknown"}</strong><span>Last scanned</span></div>
            </div>
          </section>
        ) : null}

        {active === "review" && parsed.reviewDevices.length > 0 ? (
          <section className="review-device-section">
            <div className="section-title">
              <strong>Device Decisions</strong>
              <span>{parsed.reviewDevices.length} device(s)</span>
            </div>
            <div className="review-device-grid">
              {parsed.reviewDevices.map((device, index) => <ReviewDeviceCard key={index} device={device} onTrust={setDeviceTrust} />)}
            </div>
          </section>
        ) : null}

        {active === "review" ? (
          <section className="review-guidance">
            <strong>Device Review</strong>
            <p>Only mark a device trusted when you recognize what it is. Unknown devices stay in review until you label or trust them.</p>
            <div className="review-steps">
              <span>1. Identify the device</span>
              <span>2. Label it</span>
              <span>3. Trust, review, or mark suspicious</span>
            </div>
          </section>
        ) : null}

        {parsed.registryDevices.length > 0 && active === "review" ? (
          <section className="registry-section">
            <div className="section-title">
              <strong>Registered Devices</strong>
              <span>{parsed.registryDevices.length} registered device(s)</span>
            </div>
            <div className="registry-grid">
              {parsed.registryDevices.map((device, index) => <RegistryCard key={index} device={device} onTrust={setDeviceTrust} />)}
            </div>
          </section>
        ) : null}

        {parsed.identities.length > 0 && active === "review" ? (
          <section className="devices-section">
            <div className="section-title">
              <strong>Detected Devices</strong>
              <span>{parsed.identities.length} device(s)</span>
            </div>
            <div className="devices-grid">
              {parsed.identities.map((device, index) => <IdentityCard key={index} device={device} />)}
            </div>
          </section>
        ) : null}

        {active === "activity" && parsed.alertItems.length > 0 ? (
          <section className="activity-section">
            <div className="section-title">
              <strong>Persistent Alert Center</strong>
              <span>{parsed.alertItems.length} alert(s)</span>
            </div>
            <div className="alert-list">
              {parsed.alertItems.map((alert, index) => <AlertCard key={index} alert={alert} />)}
            </div>
          </section>
        ) : null}

        {active === "activity" && parsed.alertItems.length === 0 ? (
          <section className="activity-section">
            <div className="section-title">
              <strong>Persistent Alert Center</strong>
              <span>No alerts loaded</span>
            </div>
            <p className="empty-note">Run Alert Center to load historical protection events.</p>
          </section>
        ) : null}

        {current.actions.length > 0 ? (
          <section className="section-actions panel-actions">
            {current.actions.map((a) => (
              <button key={a.cmd} disabled={running} onClick={() => run(a.cmd)}>
                <strong>{a.title}</strong>
                <span>{a.desc}</span>
              </button>
            ))}
          </section>
        ) : null}

        {active === "enforce" ? (
          <section className="enforce-note">
            <strong>Apply / Undo</strong>
            <span>Manual only for now: use elevated PowerShell with <code>shutterwall apply</code> or <code>shutterwall undo</code>.</span>
          </section>
        ) : null}

        <section className="commandbar">
          <strong>Status:</strong> {running ? "Running..." : "Ready"}
          {lastCommand ? <span>Last command: {lastCommand}</span> : null}
        </section>

        {parsed.summaryLines.length > 0 ? (
          <section className="friendly-summary">
            <strong>Command Summary</strong>
            {parsed.summaryLines.map((line, index) => <span key={index}>{line}</span>)}
          </section>
        ) : null}

        {parsed.summaryLines.some((x) => x.includes("ALERT_FINGERPRINT_CHANGED")) ? (
          <div className="alert-explainer">
            <strong>Fingerprint Changed</strong>
            <div>A device identity signal changed since your baseline. Re-baseline only if you recognize and trust the change.</div>
          </div>
        ) : null}

        {active === "evidence" ? (
          <pre className="output">{output}</pre>
        ) : (
          <section className="raw-toggle">
            <button type="button" onClick={() => setShowRaw(!showRaw)}>
              {showRaw ? "Hide Raw Output" : "Show Raw Output"}
            </button>
          </section>
        )}

        {active !== "evidence" && showRaw ? <pre className="output">{output}</pre> : null}
      </section>
    </main>
  );
}
