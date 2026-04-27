import { useState } from "react";
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

export default function App() {
  const [output, setOutput] = useState("Ready. Choose an action.");
  const [running, setRunning] = useState(false);

  async function run(cmd) {
    setRunning(true);
    setOutput("RUNNING: shutterwall " + cmd + "\\n");
    try {
      const res = await invoke("run_shutterwall", { cmd });
      setOutput(String(res || "NO_OUTPUT"));
    } catch (e) {
      setOutput("UI_COMMAND_FAILED:\\n" + String(e));
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

      <section className="status">
        <div><strong>Safe default</strong><span>Inspect, baseline, diff, watch, and scan do not apply firewall changes.</span></div>
        <div><strong>Engine wired</strong><span>Desktop buttons now call the ShutterWall CLI engine.</span></div>
        <div><strong>Protected apply</strong><span>Apply and undo stay admin-gated through the CLI.</span></div>
      </section>

      <section className="grid">
        {actions.map((a) => (
          <button key={a.cmd} disabled={running} onClick={() => run(a.cmd)}>
            <strong>{a.title}</strong>
            <span>{a.desc}</span>
          </button>
        ))}
      </section>

      <section className="warning">Apply and undo are intentionally not exposed as one-click buttons yet. Use elevated PowerShell and run shutterwall apply or shutterwall undo.</section>
      <pre className="output">{output}</pre>
    </main>
  );
}
