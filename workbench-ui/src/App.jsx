import { useState } from "react";
import "./App.css";

export default function App() {
  const [output, setOutput] = useState("Ready.");

  function preview(command) {
    setOutput(`Workbench preview mode.\n\nCLI command:\nshutterwall ${command}\n\nDesktop execution will be wired through Tauri next.`);
  }

  return (
    <main className="shell">
      <section className="hero">
        <p className="eyebrow">ShutterWall Camera Protection</p>
        <h1>Scan, preview, protect, restore.</h1>
        <p className="sub">
          A local-first camera security workbench for homeowners and small businesses.
          Preview is safe by default. Apply requires elevated PowerShell.
        </p>
      </section>

      <section className="grid">
        <button onClick={() => preview("doctor")}>Doctor</button>
        <button onClick={() => preview("protect")}>Protect Preview</button>
        <button onClick={() => preview("secure-force")}>Apply Protection</button>
        <button onClick={() => preview("restore")}>Restore</button>
      </section>

      <section className="warning">
        <strong>Safety:</strong> Apply can block device connectivity. Restore removes ShutterWall firewall rules.
      </section>

      <pre className="output">{output}</pre>
    </main>
  );
}