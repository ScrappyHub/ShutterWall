import { useState } from "react";
import "./App.css";

const commands = [
  { key: "quickstart", title: "Quickstart", desc: "Guided inspect + home-safe scan." },
  { key: "inspect", title: "Inspect", desc: "Safe discovery only. No firewall changes." },
  { key: "baseline", title: "Baseline", desc: "Create trusted network baseline." },
  { key: "diff", title: "Diff", desc: "Compare current network to baseline." },
  { key: "watch 1", title: "Watch", desc: "Run one monitoring tick." },
  { key: "scan", title: "Scan", desc: "Home-safe preview." },
];

function commandText(cmd) {
  return "shutterwall " + cmd;
}

export default function App() {
  const [output, setOutput] = useState("Ready. Choose an action.");

  function preview(cmd) {
    setOutput("Desktop shell preview mode.\\n\\nRun this command now:\\n" + commandText(cmd));
  }

  return (
    <main className="shell">
      <section className="hero">
        <p className="eyebrow">ShutterWall</p>
        <h1>Protect and monitor your local network.</h1>
        <p className="sub">Camera-class network protection, baseline integrity, diff alerts, and safe restore. CLI engine is already live; desktop execution wiring comes next.</p>
      </section>

      <section className="status">
        <div>
          <strong>Safe default</strong>
          <span>Inspect, baseline, diff, watch, and scan do not apply firewall changes.</span>
        </div>
        <div>
          <strong>Apply protection</strong>
          <span>Use elevated PowerShell: shutterwall apply</span>
        </div>
        <div>
          <strong>Undo</strong>
          <span>Use elevated PowerShell: shutterwall undo</span>
        </div>
      </section>

      <section className="grid">
        {commands.map((item) => (
          <button key={item.key} onClick={() => preview(item.key)}>
            <strong>{item.title}</strong>
            <span>{item.desc}</span>
          </button>
        ))}
      </section>

      <section className="warning">
        Apply/undo are intentionally not one-click in this preview shell. They require administrator elevation to protect users from accidental network changes.
      </section>

      <pre className="output">{output}</pre>
    </main>
  );
}
