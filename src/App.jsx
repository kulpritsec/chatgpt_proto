import React, { useEffect, useMemo, useState } from "react";

const OWASP_LLM_TOP10 = [
  { id: "LLM01", name: "Prompt Injection" },
  { id: "LLM02", name: "Insecure Output Handling" },
  { id: "LLM03", name: "Training Data Poisoning" },
  { id: "LLM04", name: "Model Denial of Service" },
  { id: "LLM05", name: "Supply Chain Vulnerabilities" },
  { id: "LLM06", name: "Sensitive Information Disclosure" },
  { id: "LLM07", name: "Insecure Plugin Design" },
  { id: "LLM08", name: "Excessive Agency" },
  { id: "LLM09", name: "Overreliance" },
  { id: "LLM10", name: "Model Theft" },
];

const AI_PATTERNS = [
  { key: "llm_chat", label: "LLM Chat / Assistant" },
  { key: "rag", label: "RAG (retrieval over internal data)" },
  { key: "agent_tools", label: "Agentic (tool use / function calling)" },
  { key: "mcp", label: "MCP / Context Providers / Connectors" },
  { key: "ml_service", label: "Traditional ML / AI Service (non-LLM)" },
  { key: "training_pipeline", label: "Model Training / Fine-tuning Pipeline" },
];

const DATA_CLASSES = [
  { key: "public", label: "Public" },
  { key: "internal", label: "Internal" },
  { key: "confidential", label: "Confidential / IP" },
  { key: "regulated", label: "Regulated (PII/PHI/PCI/GLBA/etc.)" },
  { key: "trade_secret", label: "Trade Secret / Crown Jewels" },
];

const EXPOSURE = [
  { key: "internal_only", label: "Internal only" },
  { key: "auth_external", label: "Authenticated external users" },
  { key: "public_facing", label: "Public facing" },
];

const AUTONOMY = [
  { key: "advisory", label: "Advisory only (human decides)" },
  { key: "decision_assist", label: "Decision assist (recommendations used)" },
  { key: "autonomous_exec", label: "Autonomous execution (no approval)" },
];

const PRIVILEGE = [
  { key: "none", label: "No system access" },
  { key: "read", label: "Read-only access" },
  { key: "write", label: "Write access" },
  { key: "exec", label: "Exec / deploy / run commands" },
];

const TRAINING = [
  { key: "no_training", label: "No training on org data" },
  { key: "vendor_opt_in", label: "Vendor may use data to improve models (opt-in)" },
  { key: "vendor_opt_out", label: "Vendor contractually barred from training (opt-out)" },
  { key: "fine_tune_internal", label: "Fine-tuning on internal datasets" },
  { key: "pretrain_internal", label: "Pretraining on large internal corpora" },
];

const ISO_42001_CONTROLS = [
  {
    key: "roles_responsibilities",
    label: "Defined AI roles & responsibilities (accountability, owners, approvers)",
  },
  {
    key: "policy_acceptable_use",
    label: "AI acceptable use + data handling policy exists and is communicated",
  },
  {
    key: "risk_management_process",
    label: "Repeatable AI risk management process (assess → treat → monitor)",
  },
  {
    key: "incident_response",
    label: "AI incident response playbooks (prompt injection, leakage, vendor outage)",
  },
  {
    key: "monitoring_logging",
    label: "Monitoring/logging for AI interactions + periodic reviews (drift/abuse)",
  },
  {
    key: "supplier_mgmt",
    label: "Supplier assurance (contracts, DPAs, retention, training terms, audits)",
  },
  {
    key: "training_awareness",
    label: "Training/awareness for users, builders, and reviewers",
  },
];

const CONTROL_LIBRARY = [
  { key: "prompt_defense", label: "Prompt defense & tool-call allowlisting" },
  { key: "pii_dlp", label: "PII/regulated-data DLP controls" },
  { key: "least_privilege", label: "Least privilege + human approvals" },
  { key: "supplier_assurance", label: "Vendor assurance + contract controls" },
  { key: "monitoring", label: "Monitoring, anomaly detection, and alerting" },
  { key: "retention", label: "Retention and deletion enforcement" },
];

const ARTIFACT_LIBRARY = [
  { key: "dpa", label: "DPA / vendor contract terms" },
  { key: "pia", label: "PIA / DPIA" },
  { key: "threat_model", label: "Threat model / abuse-case test results" },
  { key: "runbook", label: "Incident response playbook" },
  { key: "logging_evidence", label: "Logging + monitoring evidence" },
  { key: "approval", label: "Governance approval memo" },
];

const LS_KEY = "ai_risk_assessments_v1";
const INVENTORY_KEY = "ai_inventory_v1";

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function scoreFromChoices(state) {
  const dataWeight =
    {
      public: 1,
      internal: 2,
      confidential: 3,
      regulated: 4,
      trade_secret: 5,
    }[state.dataClass] ?? 2;

  const exposureWeight =
    {
      internal_only: 1,
      auth_external: 2,
      public_facing: 3,
    }[state.exposure] ?? 1;

  const autonomyWeight =
    {
      advisory: 1,
      decision_assist: 2,
      autonomous_exec: 4,
    }[state.autonomy] ?? 1;

  const privilegeWeight =
    {
      none: 0,
      read: 2,
      write: 4,
      exec: 6,
    }[state.privilege] ?? 0;

  const trainingWeight =
    {
      no_training: 0,
      vendor_opt_out: 1,
      vendor_opt_in: 3,
      fine_tune_internal: 4,
      pretrain_internal: 5,
    }[state.training] ?? 0;

  const patternBonus =
    {
      llm_chat: 1,
      rag: 2,
      agent_tools: 4,
      mcp: 3,
      ml_service: 2,
      training_pipeline: 5,
    }[state.pattern] ?? 2;

  const raw = dataWeight * 3 + exposureWeight * 2 + autonomyWeight * 2 + privilegeWeight + trainingWeight + patternBonus;
  const score = clamp(Math.round((raw / 35) * 100), 0, 100);

  return { score, raw };
}

function owaspMapping(state) {
  const hits = new Set();

  if (state.exposure !== "internal_only") hits.add("LLM01");
  if (["agent_tools", "rag", "mcp"].includes(state.pattern)) hits.add("LLM01");
  if (["decision_assist", "autonomous_exec"].includes(state.autonomy)) hits.add("LLM02");

  if (["training_pipeline"].includes(state.pattern) || ["fine_tune_internal", "pretrain_internal"].includes(state.training)) {
    hits.add("LLM03");
  }

  if (state.exposure === "public_facing") hits.add("LLM04");
  if (["mcp", "agent_tools", "llm_chat", "rag"].includes(state.pattern)) hits.add("LLM05");
  if (["internal", "confidential", "regulated", "trade_secret"].includes(state.dataClass)) hits.add("LLM06");
  if (["agent_tools", "mcp"].includes(state.pattern)) hits.add("LLM07");
  if (["write", "exec"].includes(state.privilege) || state.autonomy === "autonomous_exec") hits.add("LLM08");
  if (["decision_assist", "autonomous_exec"].includes(state.autonomy)) hits.add("LLM09");
  if (state.exposure === "public_facing" || state.pattern === "training_pipeline") hits.add("LLM10");

  return OWASP_LLM_TOP10.map((x) => ({ ...x, triggered: hits.has(x.id) }));
}

function isoReadinessScore(isoAnswers) {
  const keys = ISO_42001_CONTROLS.map((c) => c.key);
  const yesCount = keys.filter((k) => isoAnswers[k] === "yes").length;
  const partialCount = keys.filter((k) => isoAnswers[k] === "partial").length;

  const points = yesCount + partialCount * 0.5;
  const pct = Math.round((points / keys.length) * 100);
  return { pct, yesCount, partialCount, total: keys.length };
}

function requiredControlsForSystem(system) {
  const needed = new Set(["monitoring", "supplier_assurance"]);

  if (["confidential", "regulated", "trade_secret"].includes(system.dataClass)) needed.add("pii_dlp");
  if (["autonomous_exec", "decision_assist"].includes(system.autonomy)) needed.add("least_privilege");
  if (["agent_tools", "rag", "mcp"].includes(system.pattern)) needed.add("prompt_defense");
  if (system.training === "vendor_opt_in" || system.training === "fine_tune_internal") needed.add("retention");

  return CONTROL_LIBRARY.filter((x) => needed.has(x.key));
}

function requiredArtifactsForSystem(system) {
  const needed = new Set(["approval", "runbook", "logging_evidence"]);

  if (["regulated", "trade_secret"].includes(system.dataClass)) needed.add("pia");
  if (system.vendor && system.vendor.trim()) needed.add("dpa");
  if (["agent_tools", "autonomous_exec"].includes(system.pattern) || system.autonomy === "autonomous_exec") {
    needed.add("threat_model");
  }

  return ARTIFACT_LIBRARY.filter((x) => needed.has(x.key));
}

function toCSVRow(obj) {
  const esc = (v) => `"${String(v ?? "").replaceAll("\"", '""')}"`;
  return Object.values(obj).map(esc).join(",");
}

export default function App() {
  const [step, setStep] = useState(0);
  const [state, setState] = useState({
    name: "New Assessment",
    pattern: "llm_chat",
    dataClass: "internal",
    exposure: "internal_only",
    autonomy: "advisory",
    privilege: "none",
    training: "vendor_opt_out",
    notes: "",
  });

  const [isoAnswers, setIsoAnswers] = useState(() => {
    const init = {};
    ISO_42001_CONTROLS.forEach((c) => (init[c.key] = "partial"));
    return init;
  });

  const [saved, setSaved] = useState([]);
  const [inventory, setInventory] = useState([]);
  const [selectedSystemId, setSelectedSystemId] = useState("");
  const [inventoryDraft, setInventoryDraft] = useState({
    name: "",
    owner: "",
    sourceSystem: "Core App",
    destination: "LLM Provider",
    vendor: "",
    pattern: "llm_chat",
    dataClass: "internal",
    exposure: "internal_only",
    autonomy: "advisory",
    privilege: "none",
    training: "vendor_opt_out",
    grcNotes: "",
  });

  useEffect(() => {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      try {
        setSaved(JSON.parse(raw));
      } catch {
        // ignore
      }
    }

    const inventoryRaw = localStorage.getItem(INVENTORY_KEY);
    if (inventoryRaw) {
      try {
        setInventory(JSON.parse(inventoryRaw));
      } catch {
        // ignore
      }
    }
  }, []);

  useEffect(() => {
    localStorage.setItem(LS_KEY, JSON.stringify(saved));
  }, [saved]);

  useEffect(() => {
    localStorage.setItem(INVENTORY_KEY, JSON.stringify(inventory));
  }, [inventory]);

  const scoring = useMemo(() => scoreFromChoices(state), [state]);
  const owasp = useMemo(() => owaspMapping(state), [state]);
  const iso = useMemo(() => isoReadinessScore(isoAnswers), [isoAnswers]);

  const selectedSystem = useMemo(
    () => inventory.find((x) => x.id === selectedSystemId),
    [inventory, selectedSystemId]
  );

  const riskBand = useMemo(() => {
    const s = scoring.score;
    if (s < 25) return { label: "Low", desc: "Routine controls likely sufficient." };
    if (s < 50) return { label: "Moderate", desc: "Add targeted controls and monitoring." };
    if (s < 75) return { label: "High", desc: "Formal review + strong mitigations required." };
    return { label: "Critical", desc: "Executive oversight + strict gating required." };
  }, [scoring.score]);

  function update(patch) {
    setState((prev) => ({ ...prev, ...patch }));
  }

  function saveAssessment() {
    const entry = {
      id: crypto?.randomUUID?.() ?? String(Date.now()),
      createdAt: new Date().toISOString(),
      linkedSystemId: selectedSystemId || null,
      linkedSystemName: selectedSystem?.name ?? null,
      state,
      isoAnswers,
      scoring,
      iso,
      owasp,
    };
    setSaved((prev) => [entry, ...prev]);
  }

  function loadAssessment(entry) {
    setState(entry.state);
    setIsoAnswers(entry.isoAnswers);
    setSelectedSystemId(entry.linkedSystemId ?? "");
    setStep(3);
  }

  function exportJSON() {
    const payload = {
      exportedAt: new Date().toISOString(),
      linkedSystem: selectedSystem ?? null,
      assessment: { state, isoAnswers, scoring, iso, owasp },
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.name.replaceAll(" ", "_")}_assessment.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportCSV() {
    const row = {
      name: state.name,
      linkedSystem: selectedSystem?.name ?? "",
      pattern: state.pattern,
      dataClass: state.dataClass,
      exposure: state.exposure,
      autonomy: state.autonomy,
      privilege: state.privilege,
      training: state.training,
      riskScore: scoring.score,
      riskBand: riskBand.label,
      isoReadinessPct: iso.pct,
      owaspTriggered: owasp.filter((x) => x.triggered).map((x) => x.id).join(" "),
      notes: state.notes,
    };

    const header = Object.keys(row).join(",");
    const body = toCSVRow(row);
    const blob = new Blob([header + "\n" + body + "\n"], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.name.replaceAll(" ", "_")}_assessment.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function addInventoryItem() {
    if (!inventoryDraft.name.trim()) return;

    const item = {
      ...inventoryDraft,
      id: crypto?.randomUUID?.() ?? String(Date.now()),
      createdAt: new Date().toISOString(),
    };

    setInventory((prev) => [item, ...prev]);
    setInventoryDraft((prev) => ({ ...prev, name: "", owner: "", vendor: "", grcNotes: "" }));
  }

  function loadInventoryIntoAssessment(item) {
    setSelectedSystemId(item.id);
    setState((prev) => ({
      ...prev,
      name: `${item.name} Assessment`,
      pattern: item.pattern,
      dataClass: item.dataClass,
      exposure: item.exposure,
      autonomy: item.autonomy,
      privilege: item.privilege,
      training: item.training,
      notes: item.grcNotes || prev.notes,
    }));
    setStep(1);
  }

  function deleteInventory(id) {
    setInventory((prev) => prev.filter((x) => x.id !== id));
    if (selectedSystemId === id) setSelectedSystemId("");
  }

  const Shell = ({ children }) => (
    <div style={styles.page}>
      <div style={styles.header}>
        <div>
          <div style={styles.h1}>AI Risk, Inventory & Governance Prototype</div>
          <div style={styles.sub}>
            Inventory + data flow mapping → control/artifact needs → OWASP + ISO readiness + assessment exports
          </div>
        </div>
        <div style={styles.pills}>
          <span style={styles.pill}>
            Risk Score: <b>{scoring.score}</b>
          </span>
          <span style={styles.pill}>
            Band: <b>{riskBand.label}</b>
          </span>
          <span style={styles.pill}>
            ISO Readiness: <b>{iso.pct}%</b>
          </span>
        </div>
      </div>

      <div style={styles.nav}>
        {["Inventory & Flows", "Intake", "ISO Readiness", "Results", "Saved"].map((t, i) => (
          <button key={t} onClick={() => setStep(i)} style={{ ...styles.tab, ...(step === i ? styles.tabActive : {}) }}>
            {t}
          </button>
        ))}
      </div>

      <div style={styles.card}>{children}</div>

      <div style={styles.footer}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button style={styles.btn} onClick={saveAssessment}>
            Save Assessment
          </button>
          <button style={styles.btn} onClick={exportJSON}>
            Export JSON
          </button>
          <button style={styles.btn} onClick={exportCSV}>
            Export CSV
          </button>
        </div>
        <div style={styles.small}>Heuristic prototype: use this to drive automated + hands-on control validation workflows.</div>
      </div>
    </div>
  );

  return (
    <Shell>
      {step === 0 && (
        <div style={styles.grid2}>
          <section>
            <div style={styles.sectionTitle}>Inventory & Data Flow Intake</div>
            <Field label="System name">
              <input
                style={styles.input}
                value={inventoryDraft.name}
                onChange={(e) => setInventoryDraft((prev) => ({ ...prev, name: e.target.value }))}
              />
            </Field>
            <Field label="System owner">
              <input
                style={styles.input}
                value={inventoryDraft.owner}
                onChange={(e) => setInventoryDraft((prev) => ({ ...prev, owner: e.target.value }))}
              />
            </Field>
            <Field label="Source system">
              <input
                style={styles.input}
                value={inventoryDraft.sourceSystem}
                onChange={(e) => setInventoryDraft((prev) => ({ ...prev, sourceSystem: e.target.value }))}
              />
            </Field>
            <Field label="Destination (AI endpoint/tool)">
              <input
                style={styles.input}
                value={inventoryDraft.destination}
                onChange={(e) => setInventoryDraft((prev) => ({ ...prev, destination: e.target.value }))}
              />
            </Field>
            <Field label="Vendor (if external)">
              <input
                style={styles.input}
                value={inventoryDraft.vendor}
                onChange={(e) => setInventoryDraft((prev) => ({ ...prev, vendor: e.target.value }))}
              />
            </Field>
            <Field label="AI pattern">
              <Select
                value={inventoryDraft.pattern}
                onChange={(v) => setInventoryDraft((prev) => ({ ...prev, pattern: v }))}
                options={AI_PATTERNS}
              />
            </Field>
            <Field label="Primary data class">
              <Select
                value={inventoryDraft.dataClass}
                onChange={(v) => setInventoryDraft((prev) => ({ ...prev, dataClass: v }))}
                options={DATA_CLASSES}
              />
            </Field>
            <Field label="Exposure">
              <Select
                value={inventoryDraft.exposure}
                onChange={(v) => setInventoryDraft((prev) => ({ ...prev, exposure: v }))}
                options={EXPOSURE}
              />
            </Field>
            <Field label="Autonomy">
              <Select
                value={inventoryDraft.autonomy}
                onChange={(v) => setInventoryDraft((prev) => ({ ...prev, autonomy: v }))}
                options={AUTONOMY}
              />
            </Field>
            <Field label="Privilege">
              <Select
                value={inventoryDraft.privilege}
                onChange={(v) => setInventoryDraft((prev) => ({ ...prev, privilege: v }))}
                options={PRIVILEGE}
              />
            </Field>
            <Field label="Training posture">
              <Select
                value={inventoryDraft.training}
                onChange={(v) => setInventoryDraft((prev) => ({ ...prev, training: v }))}
                options={TRAINING}
              />
            </Field>
            <Field label="GRC notes / known constraints">
              <textarea
                style={{ ...styles.input, height: 90 }}
                value={inventoryDraft.grcNotes}
                onChange={(e) => setInventoryDraft((prev) => ({ ...prev, grcNotes: e.target.value }))}
              />
            </Field>
            <button style={styles.btnPrimary} onClick={addInventoryItem}>
              Add to inventory
            </button>
          </section>

          <section>
            <div style={styles.sectionTitle}>Visual Path + Control/Artifact Coverage</div>
            <div style={styles.small}>Each inventory item maps source → AI destination and derives recommended controls and GRC artifacts.</div>

            <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
              {inventory.map((item) => {
                const controls = requiredControlsForSystem(item);
                const artifacts = requiredArtifactsForSystem(item);

                return (
                  <div key={item.id} style={styles.savedCard}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                      <div>
                        <div style={{ fontWeight: 700 }}>{item.name}</div>
                        <div style={styles.small}>Owner: {item.owner || "Unassigned"}</div>
                      </div>
                      <div style={{ display: "flex", gap: 8 }}>
                        <button style={styles.btn} onClick={() => loadInventoryIntoAssessment(item)}>
                          Assess this system
                        </button>
                        <button style={styles.btnDanger} onClick={() => deleteInventory(item.id)}>
                          Delete
                        </button>
                      </div>
                    </div>

                    <div style={styles.flowRow}>
                      <span style={styles.flowNode}>{item.sourceSystem || "Source"}</span>
                      <span style={styles.flowArrow}>→</span>
                      <span style={styles.flowNode}>AI: {item.destination || "Destination"}</span>
                      <span style={styles.flowArrow}>→</span>
                      <span style={styles.flowNode}>Business Output</span>
                    </div>

                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>Recommended Security/AI Controls</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {controls.map((x) => (
                          <span key={x.key} style={styles.pillSmall}>{x.label}</span>
                        ))}
                      </div>
                    </div>

                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>Recommended GRC Artifacts</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                        {artifacts.map((x) => (
                          <span key={x.key} style={styles.badge}>{x.label}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}

              {inventory.length === 0 && (
                <div style={styles.kpiBox}>No inventory yet. Add a system on the left to start building your visual governance map.</div>
              )}
            </div>
          </section>
        </div>
      )}

      {step === 1 && (
        <div style={styles.grid2}>
          <section>
            <div style={styles.sectionTitle}>Use Case Intake</div>
            <Field label="Assessment name">
              <input style={styles.input} value={state.name} onChange={(e) => update({ name: e.target.value })} />
            </Field>
            <Field label="Linked inventory system">
              <select
                style={styles.input}
                value={selectedSystemId}
                onChange={(e) => setSelectedSystemId(e.target.value)}
              >
                <option value="">Not linked</option>
                {inventory.map((item) => (
                  <option key={item.id} value={item.id}>{item.name}</option>
                ))}
              </select>
            </Field>
            <Field label="AI system pattern">
              <Select value={state.pattern} onChange={(v) => update({ pattern: v })} options={AI_PATTERNS} />
            </Field>
            <Field label="Primary data class">
              <Select value={state.dataClass} onChange={(v) => update({ dataClass: v })} options={DATA_CLASSES} />
            </Field>
            <Field label="Exposure">
              <Select value={state.exposure} onChange={(v) => update({ exposure: v })} options={EXPOSURE} />
            </Field>
            <Field label="Autonomy">
              <Select value={state.autonomy} onChange={(v) => update({ autonomy: v })} options={AUTONOMY} />
            </Field>
            <Field label="System privilege">
              <Select value={state.privilege} onChange={(v) => update({ privilege: v })} options={PRIVILEGE} />
            </Field>
            <Field label="Training / retention posture">
              <Select value={state.training} onChange={(v) => update({ training: v })} options={TRAINING} />
            </Field>
            <Field label="Notes / constraints (IP, policies, special requirements)">
              <textarea
                style={{ ...styles.input, height: 90 }}
                value={state.notes}
                onChange={(e) => update({ notes: e.target.value })}
              />
            </Field>
          </section>

          <section>
            <div style={styles.sectionTitle}>OWASP LLM Top 10 (Triggered)</div>
            <div style={styles.list}>
              {owasp.map((x) => (
                <div key={x.id} style={{ ...styles.row, ...(x.triggered ? styles.rowHit : {}) }}>
                  <div style={styles.rowLeft}>
                    <span style={styles.badge}>{x.id}</span>
                    <span>{x.name}</span>
                  </div>
                  <span style={styles.small}>{x.triggered ? "Triggered" : "Not triggered"}</span>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={styles.sectionTitle}>Summary</div>
              <div style={styles.kpiBox}>
                <div>
                  <b>Risk:</b> {scoring.score}/100 ({riskBand.label})
                </div>
                <div style={styles.small}>{riskBand.desc}</div>
                <div style={{ marginTop: 10 }}>
                  <b>Why:</b>
                </div>
                <ul style={{ marginTop: 6, paddingLeft: 18 }}>
                  <li>Data class: <b>{state.dataClass}</b></li>
                  <li>Exposure: <b>{state.exposure}</b></li>
                  <li>Autonomy: <b>{state.autonomy}</b></li>
                  <li>Privilege: <b>{state.privilege}</b></li>
                  <li>Training: <b>{state.training}</b></li>
                </ul>
              </div>
            </div>
          </section>
        </div>
      )}

      {step === 2 && (
        <div>
          <div style={styles.sectionTitle}>ISO/IEC 42001 Readiness (High-level)</div>
          <div style={styles.small}>
            Management-system lens for governance + evidence: roles, policies, supplier management, monitoring, incident response.
          </div>

          <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
            {ISO_42001_CONTROLS.map((c) => (
              <div key={c.key} style={styles.isoRow}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600 }}>{c.label}</div>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  {["no", "partial", "yes"].map((v) => (
                    <button
                      key={v}
                      onClick={() => setIsoAnswers((prev) => ({ ...prev, [c.key]: v }))}
                      style={{ ...styles.chip, ...(isoAnswers[c.key] === v ? styles.chipActive : {}) }}
                    >
                      {v.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 14 }}>
            <div style={styles.kpiBox}>
              <div><b>ISO readiness:</b> {iso.pct}%</div>
              <div style={styles.small}>Yes: {iso.yesCount} • Partial: {iso.partialCount} • Total: {iso.total}</div>
              <div style={{ marginTop: 10 }}>
                <b>Automation + hands-on idea:</b> attach evidence links for NO/PARTIAL, then request assessor signoff.
              </div>
            </div>
          </div>
        </div>
      )}

      {step === 3 && (
        <div style={styles.grid2}>
          <section>
            <div style={styles.sectionTitle}>Results</div>

            <div style={styles.kpiBox}>
              <div style={styles.big}>{scoring.score}/100</div>
              <div><b>{riskBand.label}</b> — {riskBand.desc}</div>
              <div style={{ marginTop: 10 }}><b>ISO/IEC 42001 readiness:</b> {iso.pct}%</div>
              <div style={{ marginTop: 10 }}><b>Linked inventory system:</b> {selectedSystem?.name ?? "None"}</div>
              <div style={{ marginTop: 10 }}><b>Triggered OWASP categories:</b></div>
              <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 6 }}>
                {owasp
                  .filter((x) => x.triggered)
                  .map((x) => (
                    <span key={x.id} style={styles.pillSmall}>{x.id}</span>
                  ))}
              </div>
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={styles.sectionTitle}>Auto Action Plan (Prototype)</div>
              <ul style={{ marginTop: 8, paddingLeft: 18 }}>
                {suggestActions(state, owasp, isoAnswers).map((a, idx) => (
                  <li key={idx} style={{ marginBottom: 6 }}>{a}</li>
                ))}
              </ul>
            </div>
          </section>

          <section>
            <div style={styles.sectionTitle}>Assessment Snapshot</div>
            <pre style={styles.pre}>
              {JSON.stringify(
                {
                  intake: state,
                  linkedSystem: selectedSystem?.name ?? null,
                  riskScore: scoring.score,
                  riskBand: riskBand.label,
                  isoReadinessPct: iso.pct,
                  owaspTriggered: owasp.filter((x) => x.triggered).map((x) => x.id),
                },
                null,
                2
              )}
            </pre>
          </section>
        </div>
      )}

      {step === 4 && (
        <div>
          <div style={styles.sectionTitle}>Saved Assessments</div>
          <div style={styles.small}>Stored in localStorage ({saved.length}).</div>

          <div style={{ marginTop: 12, display: "grid", gap: 10 }}>
            {saved.map((entry) => (
              <div key={entry.id} style={styles.savedCard}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <div>
                    <div style={{ fontWeight: 700 }}>{entry.state?.name ?? "Untitled"}</div>
                    <div style={styles.small}>
                      {new Date(entry.createdAt).toLocaleString()} • Score {entry.scoring?.score ?? "?"} • ISO {entry.iso?.pct ?? "?"}%
                    </div>
                    <div style={styles.small}>Linked system: {entry.linkedSystemName ?? "None"}</div>
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button style={styles.btn} onClick={() => loadAssessment(entry)}>Load</button>
                    <button style={styles.btnDanger} onClick={() => setSaved((prev) => prev.filter((x) => x.id !== entry.id))}>
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
            {saved.length === 0 && (
              <div style={styles.kpiBox}>No saved assessments yet. Click “Save Assessment” from any tab.</div>
            )}
          </div>
        </div>
      )}
    </Shell>
  );
}

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={styles.label}>{label}</div>
      {children}
    </div>
  );
}

function Select({ value, onChange, options }) {
  return (
    <select style={styles.input} value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => (
        <option key={o.key} value={o.key}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

function suggestActions(state, owasp, isoAnswers) {
  const actions = [];
  const triggered = new Set(owasp.filter((x) => x.triggered).map((x) => x.id));

  if (triggered.has("LLM01")) {
    actions.push("Add prompt-injection defenses: input filtering, system prompt hardening, and allowlist tool calls.");
  }
  if (triggered.has("LLM06")) {
    actions.push("Implement sensitive-data controls: redaction, DLP scanning, and strict access control mirroring for RAG/MCP connectors.");
  }
  if (triggered.has("LLM08")) {
    actions.push("Reduce agency: require human approval for write/exec actions; add sandboxing and least privilege for tools.");
  }
  if (triggered.has("LLM05")) {
    actions.push("Supplier controls: review vendor retention/training terms, DPAs, and security attestations; document in evidence locker.");
  }
  if (state.exposure === "public_facing") {
    actions.push("Add rate limiting + abuse detection to reduce model DoS risk and prompt exploitation.");
  }
  if (["fine_tune_internal", "pretrain_internal"].includes(state.training)) {
    actions.push("Run data lineage + licensing review for training datasets; test for memorization/inversion leakage.");
  }

  const isoGaps = Object.entries(isoAnswers).filter(([, v]) => v !== "yes").length;
  if (isoGaps > 0) {
    actions.push("Close ISO readiness gaps: create/confirm roles, policies, monitoring cadence, and incident playbooks; attach evidence artifacts.");
  }

  if (actions.length === 0) {
    actions.push("No major gaps detected by heuristics—validate with a manual review and targeted red-team tests.");
  }

  return actions;
}

const styles = {
  page: {
    fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif",
    padding: 18,
    maxWidth: 1200,
    margin: "0 auto",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: 12,
    flexWrap: "wrap",
    marginBottom: 12,
  },
  h1: { fontSize: 22, fontWeight: 800 },
  sub: { fontSize: 13, opacity: 0.75, marginTop: 4, maxWidth: 760 },
  nav: { display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" },
  tab: { padding: "8px 10px", borderRadius: 10, border: "1px solid #ddd", background: "white", cursor: "pointer" },
  tabActive: { borderColor: "#111", fontWeight: 700 },
  card: { border: "1px solid #e5e5e5", borderRadius: 16, padding: 14, background: "white" },
  footer: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
    flexWrap: "wrap",
    marginTop: 12,
  },
  btn: { padding: "8px 10px", borderRadius: 10, border: "1px solid #ddd", background: "white", cursor: "pointer" },
  btnPrimary: { padding: "8px 10px", borderRadius: 10, border: "1px solid #111", background: "#111", color: "white", cursor: "pointer" },
  btnDanger: {
    padding: "8px 10px",
    borderRadius: 10,
    border: "1px solid #f1c0c0",
    background: "#fff5f5",
    cursor: "pointer",
  },
  pills: { display: "flex", gap: 8, flexWrap: "wrap" },
  pill: { border: "1px solid #e5e5e5", borderRadius: 999, padding: "6px 10px", fontSize: 13, background: "white" },
  pillSmall: { border: "1px solid #e5e5e5", borderRadius: 999, padding: "4px 8px", fontSize: 12, background: "white" },
  grid2: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 },
  sectionTitle: { fontWeight: 800, marginBottom: 10 },
  label: { fontSize: 12, fontWeight: 700, marginBottom: 6, opacity: 0.85 },
  input: { width: "100%", padding: "10px 10px", borderRadius: 10, border: "1px solid #ddd", fontSize: 14 },
  list: { display: "grid", gap: 8 },
  row: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    border: "1px solid #eee",
    borderRadius: 12,
    padding: "8px 10px",
  },
  rowHit: { borderColor: "#111" },
  rowLeft: { display: "flex", alignItems: "center", gap: 10 },
  badge: { fontSize: 12, border: "1px solid #e5e5e5", borderRadius: 8, padding: "2px 6px", background: "white" },
  small: { fontSize: 12, opacity: 0.75 },
  kpiBox: { border: "1px solid #eee", borderRadius: 14, padding: 12, background: "#fafafa" },
  big: { fontSize: 30, fontWeight: 900, marginBottom: 4 },
  pre: {
    border: "1px solid #eee",
    borderRadius: 14,
    padding: 12,
    background: "#0b0b0b",
    color: "white",
    overflow: "auto",
    fontSize: 12,
  },
  isoRow: { display: "flex", gap: 12, alignItems: "center", border: "1px solid #eee", borderRadius: 12, padding: 10, background: "white" },
  chip: {
    padding: "8px 10px",
    borderRadius: 999,
    border: "1px solid #ddd",
    background: "white",
    cursor: "pointer",
    fontSize: 12,
  },
  chipActive: { borderColor: "#111", fontWeight: 800 },
  savedCard: { border: "1px solid #eee", borderRadius: 14, padding: 12, background: "white" },
  flowRow: { marginTop: 10, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" },
  flowNode: { border: "1px solid #ddd", borderRadius: 10, padding: "4px 8px", fontSize: 12, background: "#fafafa" },
  flowArrow: { fontWeight: 800, opacity: 0.7 },
};
