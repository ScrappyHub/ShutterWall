import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

const sections = [
  {
    title: "Overview",
    desc: "Start here. Understand what is on your local network without changing anything.",
    actions: [
      { cmd: "quickstart", title: "Quickstart", desc: "Runs safe discovery and a home-safe preview so you can understand the current network state." },
      { cmd: "inspect", title: "Inspect", desc: "Discovers local devices and writes evidence. No firewall changes. No enforcement." },
      { cmd: "identity", title: "Identity", desc: "Labels discovered devices with likely type, confidence, vendor hint, and IP address." },
    ],
  },
  {
    title: "Security",
    desc: "Create a trusted baseline, compare against it, and monitor for changes.",
    actions: [
      { cmd: "baseline", title: "Baseline", desc: "Stores the current network as the trusted known-good state." },
      { cmd: "diff", title: "Diff", desc: "Compares the current network against the baseline and reports new, missing, or changed devices." },
      { cmd: "watch 1", title: "Watch", desc: "Runs a monitoring tick using baseline + diff and reports whether the network changed." },
    ],
  },
  {
    title: "Enforce",
    desc: "Preview protections first. Actual apply and undo remain administrator-gated for safety.",
    actions: [
      { cmd: "scan", title: "Scan Preview", desc: "Builds a protection plan and shows target devices. No firewall changes are applied." },
    ],
  },
];

function parseOutput(text) {
  const lines = String(text || "").split(/\r?\n/);

  const alerts = lines.filter((line) =>
    line.trim().startsWith("ALERT_") && !line.trim().startsWith("ALERT_COUNT")
  );

  const identities = lines
    .filter((line) => line.trim().startsWith("DEVICE_IDENTITY ::"))
    .map((line) => {
      const parts = line.trim().split("::").map((p) => p.trim());
      const ip = parts[1] || "";
      const label = parts[2] || "Unknown Device";
      const confidence = (parts[3] || "").replace("confidence=", "");
      const vendor = (parts[4] || "").replace("vendor=", "");
      return { ip, label, confidence, vendor };
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

  if (lines.some((l) => l.includes("SHUTTERWALL_IDENTITY_V1_OK"))) {
    stateLabel = "Devices Identified";
  } else if (lines.some((l) => l.includes("SHUTTERWALL_BASELINE_V1_OK"))) {
    stateLabel = "Baseline Updated";
  } else if (lines.some((l) => l.includes("SHUTTERWALL_PROTECT_OK"))) {
    stateLabel = "Scan Preview Ready";
  } else if (changed) {
    stateLabel = "Network Changed";
  } else if (stable) {
    stateLabel = "Network Stable";
  } else if (ok) {
    stateLabel = "Command Complete";
  }

  return {
    state: changed ? "changed" : stable ? "stable" : ok ? "ok" : "idle",
    stateLabel,
    alerts,
    identities,
    summaryLines,
  };
}

function AlertCard({ alert }) {
  const parts = alert.split("::").map((p) => p.trim());
  const token = parts[0] || alert;
  const ip = parts[1] || "";
  const message = parts[2] || "";

  let label = "Network Alert";
  if (token === "ALERT_NEW_DEVICE") label = "New Device";
  if (token === "ALERT_DEVICE_MISSING") label = "Missing Device";
  if (token === "ALERT_FINGERPRINT_CHANGED") label = "Fingerprint Changed";
  if (token === "ALERT_NETWORK_STATE_CHANGED") label = "Network Changed";

  return (
    <div className="alert-card">
      <strong>{label}</strong>
      {ip ? <span>{ip}</span> : null}
      {message ? <p>{message}</p> : null}
    </div>
  );
}

function IdentityCard({ device }) {
  return (
    <div className="identity-card">
      <strong>{device.label}</strong>
      <span className="identity-ip">{device.ip}</span>
      <div className="identity-meta">
        <span>Confidence: {device.confidence || "unknown"}</span>
        <span>Vendor: {device.vendor || "unknown"}</span>
      </div>
    </div>
  );
}

export default function App() {
  const [output, setOutput] = useState("Ready. Choose an action.");
  const [running, setRunning] = useState(false);
  const [lastCommand, setLastCommand] = useState("");
  const [showRaw, setShowRaw] = useState(false);

  const parsed = useMemo(() => parseOutput(output), [output]);

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
    <main className="shell">
      <section className="hero">
        <p className="eyebrow">ShutterWall</p>
        <h1>Protect and monitor your local network.</h1>
        <p className="sub">Local-first network protection, baseline integrity, diff alerts, watch monitoring, and safe restore.</p>
      </section>

      <section className="summary">
        <div className={"state-card " + parsed.state}>
          <strong>{parsed.stateLabel}</strong>
          <span>{parsed.alerts.length} alert(s)</span>
        </div>
        <div className="state-card safe">
          <strong>Safe Commands</strong>
          <span>Overview and Security commands are safe by default and do not apply firewall changes.</span>
        </div>
        <div className="state-card locked">
          <strong>Protected Enforcement</strong>
          <span>Apply and undo stay administrator-gated so changes are intentional.</span>
        </div>
      </section>

      {parsed.alerts.length > 0 && (
        <section className="alerts">
          {parsed.alerts.map((alert, index) => <AlertCard key={index} alert={alert} />)}
        </section>
      )}

      {parsed.identities.length > 0 && (
        <section className="devices-section">
          <div className="section-title">
            <strong>Detected Devices</strong>
            <span>{parsed.identities.length} device(s)</span>
          </div>
          <div className="devices-grid">
            {parsed.identities.map((device, index) => <IdentityCard key={index} device={device} />)}
          </div>
        </section>
      )}

      <section className="sections">
        {sections.map((section) => (
          <div className="command-section" key={section.title}>
            <div className="section-heading">
              <strong>{section.title}</strong>
              <p>{section.desc}</p>
            </div>
            <div className="section-actions">
              {section.actions.map((a) => (
                <button key={a.cmd} disabled={running} onClick={() => run(a.cmd)}>
                  <strong>{a.title}</strong>
                  <span>{a.desc}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </section>

      <section className="enforce-note">
        <strong>Apply / Undo</strong>
        <span>Protection apply and restore are available through elevated PowerShell: <code>shutterwall apply</code> and <code>shutterwall undo</code>. They are intentionally not exposed as casual one-click actions yet.</span>
      </section>

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

      <section className="raw-toggle">
        <button type="button" onClick={() => setShowRaw(!showRaw)}>
          {showRaw ? "Hide Raw Output" : "Show Raw Output"}
        </button>
      </section>

      {showRaw ? <pre className="output">{output}</pre> : null}
    </main>
  );
}
