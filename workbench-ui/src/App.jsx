import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

const sections = {
  overview: {
    title: "Overview",
    desc: "Start here. Understand your local network without changing anything.",
    actions: [
      { cmd: "quickstart", title: "Quickstart", desc: "Runs safe discovery and a home-safe preview." },
      { cmd: "inspect", title: "Inspect", desc: "Discovers devices. No firewall changes." },
      { cmd: "identity", title: "Identity", desc: "Labels devices with type and confidence." },
      { cmd: "registry", title: "Device Registry", desc: "Shows persistent network memory: labels, trust state, changes, and last seen." },
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
        changes: (parts[4] || "").replace("changes=", ""),
        lastSeen: (parts[5] || "").replace("last_seen=", ""),
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

function RegistryCard({ device }) {
  return (
    <div className="registry-card">
      <strong>{device.name}</strong>
      <span className="registry-ip">IP: {device.ip}</span>
      <div className="registry-meta">
        <span>Trust: {device.trust || "unknown"}</span>
        <span>Changes: {device.changes || "0"}</span>
        <span>Last seen: {device.lastSeen || "unknown"}</span>
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

        {parsed.registryDevices.length > 0 && active === "overview" ? (
          <section className="registry-section">
            <div className="section-title">
              <strong>Network Memory</strong>
              <span>{parsed.registryDevices.length} registered device(s)</span>
            </div>
            <div className="registry-grid">
              {parsed.registryDevices.map((device, index) => <RegistryCard key={index} device={device} />)}
            </div>
          </section>
        ) : null}

        {parsed.identities.length > 0 && active === "overview" ? (
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
