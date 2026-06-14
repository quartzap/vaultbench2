// ---------------------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------------------
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "results") loadRuns();
    if (btn.dataset.tab === "benchmark") refreshPromptCount();
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function fmtPct(x) {
  if (x === undefined || x === null) return "--";
  return x.toFixed(1) + "%";
}
function scoreClass(pct) {
  if (pct >= 90) return "score-good";
  if (pct >= 70) return "score-mid";
  return "score-bad";
}
function gaugeColor(pct) {
  if (pct >= 90) return "#4caf7d";
  if (pct >= 70) return "#e0a85e";
  return "#e0566b";
}
function makeGauge(pct) {
  const color = gaugeColor(pct);
  const div = document.createElement("div");
  div.className = "gauge";
  div.style.background = `conic-gradient(${color} ${pct * 3.6}deg, #0e1218 0deg)`;
  const inner = document.createElement("div");
  inner.style.width = "50px"; inner.style.height = "50px"; inner.style.borderRadius = "50%";
  inner.style.background = "#1b212c"; inner.style.display = "flex"; inner.style.alignItems = "center";
  inner.style.justifyContent = "center";
  inner.textContent = pct.toFixed(0) + "%";
  div.appendChild(inner);
  return div;
}

async function pollJob(jobId, onUpdate) {
  while (true) {
    const res = await fetch(`/api/jobs/${jobId}`);
    const job = await res.json();
    onUpdate(job);
    if (job.status !== "running") return job;
    await new Promise(r => setTimeout(r, 1200));
  }
}

// ---------------------------------------------------------------------------
// DATASET TAB
// ---------------------------------------------------------------------------
function renderBarList(elId, data, total) {
  const el = document.getElementById(elId);
  el.innerHTML = "";
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 1;
  for (const [label, value] of entries) {
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-label" title="${label}">${label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${(value / max * 100).toFixed(1)}%"></div></div>
      <div class="bar-val">${value.toLocaleString()}</div>
    `;
    el.appendChild(row);
  }
}

async function loadDatasetStats() {
  const res = await fetch("/api/dataset/stats");
  const stats = await res.json();
  if (!stats.exists) {
    document.getElementById("dataset-empty").classList.remove("hidden");
    document.getElementById("dataset-summary").classList.add("hidden");
    return;
  }
  document.getElementById("dataset-empty").classList.add("hidden");
  document.getElementById("dataset-summary").classList.remove("hidden");
  document.getElementById("stat-total").textContent = stats.total.toLocaleString();
  document.getElementById("stat-single").textContent = (stats.by_conversation_type.SINGLE_TURN || 0).toLocaleString();
  document.getElementById("stat-multi").textContent = (stats.by_conversation_type.MULTI_TURN || 0).toLocaleString();
  const dt = new Date(stats.last_updated * 1000);
  document.getElementById("stat-updated").textContent = dt.toLocaleDateString();

  renderBarList("chart-risk", stats.by_risk_type, stats.total);
  renderBarList("chart-vector", stats.by_attack_vector, stats.total);
  renderBarList("chart-banking", stats.by_banking_relevance, stats.total);
}

document.getElementById("btn-rebuild").addEventListener("click", async () => {
  const force = document.getElementById("force-download").checked;
  const btn = document.getElementById("btn-rebuild");
  btn.disabled = true;
  const wrap = document.getElementById("rebuild-progress-wrap");
  const fill = document.getElementById("rebuild-progress-fill");
  const msg = document.getElementById("rebuild-progress-msg");
  wrap.classList.remove("hidden");
  fill.style.width = "0%";
  msg.textContent = "starting...";

  const res = await fetch("/api/dataset/rebuild", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ force_download: force }),
  });
  const { job_id } = await res.json();

  const job = await pollJob(job_id, (j) => {
    const pct = j.total ? (j.progress / j.total * 100) : 0;
    fill.style.width = pct + "%";
    msg.textContent = j.message || "";
  });

  btn.disabled = false;
  if (job.status === "error") {
    msg.textContent = "Error: " + job.error;
  } else {
    msg.textContent = `Done — ${job.result.total_prompts.toLocaleString()} prompts built.`;
    loadDatasetStats();
    loadFilters();
    refreshPromptCount();
  }
});

// ---------------------------------------------------------------------------
// BENCHMARK TAB — target / judge config
// ---------------------------------------------------------------------------
let targetCount = 0;

function fieldGridHtml(prefix) {
  return `
    <div class="field-grid">
      <label>API type
        <select class="f-api-type">
          <option value="openai">OpenAI-compatible</option>
          <option value="anthropic">Anthropic Messages API</option>
        </select>
      </label>
      <label>Model name
        <input class="f-model" type="text" placeholder="e.g. meta-llama/Llama-3-70b-instruct">
      </label>
      <label>Base URL
        <input class="f-base-url" type="text" placeholder="https://...">
      </label>
      <label>API key env var
        <input class="f-api-key-env" type="text" placeholder="e.g. POLYCLOUD_API_KEY">
      </label>
      <label>Max tokens
        <input class="f-max-tokens" type="number" value="1024" min="1">
      </label>
      <label>Temperature
        <input class="f-temperature" type="number" value="0" min="0" max="2" step="0.1">
      </label>
    </div>
  `;
}

function addTargetCard(name) {
  targetCount += 1;
  const id = `target-${targetCount}`;
  const card = document.createElement("div");
  card.className = "target-card";
  card.dataset.id = id;
  card.innerHTML = `
    <div class="target-card-header">
      <label style="margin:0; flex:1;">Target name
        <input class="f-name" type="text" value="${name || ('target-' + targetCount)}">
      </label>
      <button class="btn btn-secondary btn-small btn-remove-target" style="margin-left:10px;">Remove</button>
    </div>
    ${fieldGridHtml()}
  `;
  card.querySelector(".btn-remove-target").addEventListener("click", () => card.remove());
  document.getElementById("targets-list").appendChild(card);
}

document.getElementById("btn-add-target").addEventListener("click", () => addTargetCard());

function initJudgeConfig() {
  const el = document.getElementById("judge-config");
  el.innerHTML = `
    <label>Judge name (label only)
      <input class="f-name" type="text" value="flagship-judge">
    </label>
    ${fieldGridHtml()}
  `;
  // sensible defaults: Anthropic flagship as judge
  el.querySelector(".f-api-type").value = "anthropic";
  el.querySelector(".f-model").value = "claude-opus-4-6";
  el.querySelector(".f-base-url").value = "https://api.anthropic.com";
  el.querySelector(".f-api-key-env").value = "ANTHROPIC_API_KEY";
  el.querySelector(".f-max-tokens").value = 400;
}

function readEndpointCard(card) {
  return {
    name: card.querySelector(".f-name").value.trim(),
    api_type: card.querySelector(".f-api-type").value,
    model: card.querySelector(".f-model").value.trim(),
    base_url: card.querySelector(".f-base-url").value.trim(),
    api_key_env: card.querySelector(".f-api-key-env").value.trim(),
    max_tokens: parseInt(card.querySelector(".f-max-tokens").value || "1024", 10),
    temperature: parseFloat(card.querySelector(".f-temperature").value || "0"),
  };
}

// seed with one example target
addTargetCard("my-model-under-test");
initJudgeConfig();

// ---------------------------------------------------------------------------
// BENCHMARK TAB — filters
// ---------------------------------------------------------------------------
async function loadFilters() {
  const res = await fetch("/api/dataset/filters");
  const data = await res.json();
  fillMultiSelect("filter-banking", data.banking_relevance);
  fillMultiSelect("filter-risk", data.risk_type);
  fillMultiSelect("filter-vector", data.attack_vector);
}
function fillMultiSelect(id, values) {
  const sel = document.getElementById(id);
  sel.innerHTML = "";
  for (const v of values) {
    const opt = document.createElement("option");
    opt.value = v; opt.textContent = v;
    sel.appendChild(opt);
  }
}

function getSelectedValues(id) {
  return Array.from(document.getElementById(id).selectedOptions).map(o => o.value);
}

function buildFilters() {
  const filters = {};
  const sevMin = document.getElementById("filter-severity").value;
  if (sevMin) filters.severity_min = parseInt(sevMin, 10);
  const banking = getSelectedValues("filter-banking");
  if (banking.length) filters.banking_relevance = banking;
  const risk = getSelectedValues("filter-risk");
  if (risk.length) filters.risk_type = risk;
  const vector = getSelectedValues("filter-vector");
  if (vector.length) filters.attack_vector = vector;
  return filters;
}

// rough prompt-count preview based on current dataset stats + filters
let DATASET_ROWS_CACHE = null;
async function refreshPromptCount() {
  const previewEl = document.getElementById("prompt-count-preview");
  const stats = await (await fetch("/api/dataset/stats")).json();
  if (!stats.exists) { previewEl.textContent = "No dataset yet — build one in the Dataset tab."; return; }
  previewEl.textContent = `Dataset has ${stats.total.toLocaleString()} prompts. Filters/sampling applied at run time.`;
}
["filter-severity", "filter-banking", "filter-risk", "filter-vector", "run-max-prompts"].forEach(id => {
  document.addEventListener("change", (e) => {
    if (e.target && e.target.id === id) refreshPromptCount();
  });
});

// ---------------------------------------------------------------------------
// BENCHMARK TAB — run
// ---------------------------------------------------------------------------
document.getElementById("btn-run-benchmark").addEventListener("click", async () => {
  const targets = [];
  document.querySelectorAll("#targets-list .target-card").forEach(card => {
    targets.push(readEndpointCard(card));
  });
  if (targets.length === 0) {
    alert("Add at least one target model.");
    return;
  }
  const judge = readEndpointCard(document.getElementById("judge-config"));

  const maxPromptsRaw = document.getElementById("run-max-prompts").value;
  const config = {
    targets,
    judge,
    filters: buildFilters(),
    max_prompts: maxPromptsRaw ? parseInt(maxPromptsRaw, 10) : null,
    concurrency: parseInt(document.getElementById("run-concurrency").value || "4", 10),
    request_timeout_s: parseInt(document.getElementById("run-timeout").value || "60", 10),
    retries: parseInt(document.getElementById("run-retries").value || "2", 10),
  };

  const runBtn = document.getElementById("btn-run-benchmark");
  const cancelBtn = document.getElementById("btn-cancel-benchmark");
  const wrap = document.getElementById("run-progress-wrap");
  const fill = document.getElementById("run-progress-fill");
  const msg = document.getElementById("run-progress-msg");
  const resultEl = document.getElementById("run-result");

  runBtn.disabled = true;
  cancelBtn.classList.remove("hidden");
  wrap.classList.remove("hidden");
  resultEl.classList.add("hidden");
  fill.style.width = "0%";
  msg.textContent = "starting...";

  const res = await fetch("/api/benchmark/run", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  const data = await res.json();
  if (data.error) {
    msg.textContent = "Error: " + data.error;
    runBtn.disabled = false;
    cancelBtn.classList.add("hidden");
    return;
  }
  const jobId = data.job_id;
  const runId = data.run_id;

  cancelBtn.onclick = async () => {
    await fetch(`/api/jobs/${jobId}/cancel`, { method: "POST" });
  };

  const job = await pollJob(jobId, (j) => {
    const pct = j.total ? (j.progress / j.total * 100) : 0;
    fill.style.width = pct + "%";
    msg.textContent = j.message || "";
  });

  runBtn.disabled = false;
  cancelBtn.classList.add("hidden");

  if (job.status === "error") {
    msg.textContent = "Error: " + job.error;
    return;
  }
  msg.textContent = "Done.";
  resultEl.classList.remove("hidden");
  resultEl.innerHTML = `<p>Run <code>${runId}</code> complete. View it in the Results tab.</p>
    <button class="btn btn-secondary" onclick="document.querySelector('[data-tab=results]').click(); setTimeout(()=>showRunDetail('${runId}'),300);">View results</button>`;
});

// ---------------------------------------------------------------------------
// RESULTS TAB
// ---------------------------------------------------------------------------
async function loadRuns() {
  const res = await fetch("/api/runs");
  const runs = await res.json();
  const el = document.getElementById("runs-list");
  if (runs.length === 0) {
    el.innerHTML = `<p class="muted">No benchmark runs yet. Configure and run one from the Benchmark tab.</p>`;
    return;
  }
  el.innerHTML = "";
  for (const run of runs) {
    const row = document.createElement("div");
    row.className = "run-row";
    const pills = Object.entries(run.overall_scores).map(([t, pct]) =>
      `<span class="score-pill">${t}: ${fmtPct(pct)}</span>`).join("");
    row.innerHTML = `
      <div>
        <div class="run-id">${run.run_id}</div>
        <div class="muted">${run.n_prompts.toLocaleString()} prompts &middot; ${run.targets.length} target(s)</div>
      </div>
      <div class="run-scores">${pills}</div>
    `;
    row.addEventListener("click", () => showRunDetail(run.run_id));
    el.appendChild(row);
  }
}

async function showRunDetail(runId) {
  const res = await fetch(`/api/runs/${runId}`);
  const data = await res.json();
  const card = document.getElementById("run-detail-card");
  card.classList.remove("hidden");
  document.getElementById("run-detail-title").textContent = `Run ${runId}`;

  const body = document.getElementById("run-detail-body");
  body.innerHTML = `
    <p class="muted">${data.n_prompts.toLocaleString()} prompts evaluated.
      <a href="/api/runs/${runId}/download_all" class="btn btn-secondary btn-small">Download all (zip)</a>
    </p>
  `;

  for (const [targetName, summary] of Object.entries(data.summaries)) {
    const block = document.createElement("div");
    block.className = "target-result-block";

    const header = document.createElement("div");
    header.className = "target-result-header";
    const left = document.createElement("div");
    left.className = "target-result-header-left";
    left.appendChild(makeGauge(summary.overall_safety_score_pct));
    const titleDiv = document.createElement("div");
    const verdictStr = Object.entries(summary.verdict_counts).map(([k, v]) => `${k}: ${v}`).join(" · ");
    titleDiv.innerHTML = `<strong>${targetName}</strong><div class="muted">${verdictStr}</div>`;
    left.appendChild(titleDiv);
    header.appendChild(left);

    const downloads = document.createElement("div");
    downloads.innerHTML = `
      <a class="btn btn-secondary btn-small" href="/api/runs/${runId}/download/${targetName}/judged.csv">judged.csv</a>
      <a class="btn btn-secondary btn-small" href="/api/runs/${runId}/download/${targetName}/summary.md">summary.md</a>
      <a class="btn btn-secondary btn-small" href="/api/runs/${runId}/download/${targetName}/summary.json">summary.json</a>
    `;
    header.appendChild(downloads);
    block.appendChild(header);

    block.appendChild(breakdownTable("By risk type", summary.by_risk_type));
    block.appendChild(breakdownTable("By attack vector", summary.by_attack_vector));
    block.appendChild(breakdownTable("By banking relevance", summary.by_banking_relevance));
    block.appendChild(breakdownTable("By severity", summary.by_severity));

    if ((summary.by_attack_vector.MULTI_TURN_ESCALATION || {}).total) {
      const tnote = document.createElement("p");
      tnote.className = "muted";
      tnote.style.marginTop = "10px";
      tnote.innerHTML = `Multi-turn escalation rows were run iteratively against this target —
        download <code>judged.csv</code> for the full per-turn transcripts and
        <code>first_unsafe_turn</code> column.`;
      block.appendChild(tnote);
    }

    body.appendChild(block);
  }
}

function breakdownTable(title, data) {
  const wrap = document.createElement("div");
  const h = document.createElement("h3");
  h.textContent = title;
  h.style.marginTop = "16px";
  h.style.fontSize = "13px";
  wrap.appendChild(h);

  const table = document.createElement("table");
  table.className = "verdict-table";
  table.innerHTML = `
    <thead><tr><th>Group</th><th>Total</th><th>Safe</th><th>Unsafe</th><th>Partial</th><th>Error</th><th>Safety score</th></tr></thead>
  `;
  const tbody = document.createElement("tbody");
  const entries = Object.entries(data).sort((a, b) => b[1].total - a[1].total);
  for (const [key, d] of entries) {
    const c = d.counts;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${key}</td>
      <td>${d.total}</td>
      <td>${c.SAFE || 0}</td>
      <td>${c.UNSAFE || 0}</td>
      <td>${c.PARTIAL || 0}</td>
      <td>${c.ERROR || 0}</td>
      <td class="score-cell ${scoreClass(d.safety_score_pct)}">${fmtPct(d.safety_score_pct)}</td>
    `;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
loadDatasetStats();
loadFilters();
