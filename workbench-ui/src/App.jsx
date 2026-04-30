import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

const actions = [
  { cmd: "quickstart", title: "Quickstart", desc: "Guided inspect plus home-safe scan." },
  { cmd: "inspect", title: "Inspect", desc: "Safe discovery only. No firewall changes." },
  { cmd: "baseline", title: "Baseline", desc: "Create trusted network baseline." },
  { cmd: "diff", title: "Diff", desc: "Compare current network to baseline." },
  { cmd: "watch 1", title: "Watch", desc: "Run one monitoring tick." },
  { cmd: "scan", title: "Scan", desc: "Home-safe protection preview." },
];

function parseOutput(text) {
  const lines = String(text || "").split(/\\r?\\n/);
  const alerts = lines.filter((line) => line.startsWith("ALERT_") && !line.startsWith("ALERT_COUNT"));
  const stable = lines.some((line) => line.trim() === "NETWORK_STATE_STABLE");
  const changed = lines.some((line) => line.trim() === "NETWORK_STATE_CHANGED");
  const ok = lines.some((line) => line.includes("_OK"));

  return {
    state: changed ? "changed" : stable ? "stable" : ok ? "ok" : "idle",
    alerts,
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

export default function App() {
  const [output, setOutput] = useState("Ready. Choose an action.");
  const [running, setRunning] = useState(false);
  const [lastCommand, setLastCommand] = useState("");

  const parsed = useMemo(() => parseOutput(output), [output]);

  async function run(cmd) {
    setRunning(true);
    setLastCommand("shutterwall " + cmd);
    setOutput("RUNNING: shutterwall " + cmd + "\\n");

    try {
      const result = await invoke("run_shutterwall", { cmd });
      setOutput(String(result || "NO_OUTPUT"));
    } catch (err) {
      setOutput("UI_COMMAND_FAILED:\\n" + String(err));
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
          <strong>{parsed.state === "changed" ? "Network Changed" : parsed.state === "stable" ? "Network Stable" : parsed.state === "ok" ? "Command Complete" : "Ready"}</strong>
          <span>{parsed.alerts.length} alert(s)</span>
        </div>
        <div className="state-card safe">
          <strong>Safe Commands</strong>
          <span>Inspect, baseline, diff, watch, and scan do not apply firewall changes.</span>
        </div>
        <div className="state-card locked">
          <strong>Protected Apply</strong>
          <span>Apply and undo stay admin-gated through the CLI.</span>
        </div>
      </section>

      {parsed.alerts.length > 0 ? (
        <section className="alerts">
          {parsed.alerts.map((alert, index) => <AlertCard key={index} alert={alert} />)}
        </section>
      ) : null}

      <section className="grid">
        {actions.map((a) => (
          <button key={a.cmd} disabled={running} onClick={() => run(a.cmd)}>
            <strong>{a.title}</strong>
            <span>{a.desc}</span>
          </button>
        ))}
      </section>

      <section className="warning">Apply and undo are intentionally not exposed as one-click buttons yet. Use elevated PowerShell and run shutterwall apply or shutterwall undo.</section>
      <section className="commandbar"><strong>Status:</strong> {running ? "Running..." : "Ready"} {lastCommand ? <span>Last command: {lastCommand}</span> : null}</section>
      <pre className="output">{output}</pre>
    </main>
  );
}
