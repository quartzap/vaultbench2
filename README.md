# VaultBench App

A self-contained web app for the VaultBench enterprise LLM safety
benchmarking suite: build/refresh the labeled prompt dataset from public
sources, run it against your candidate model endpoints, judge the
responses with a flagship "judge" model, and review/download results —
all from one UI.

## Setup

```bash
pip install -r requirements.txt --break-system-packages   # or use a venv
```

Set the API keys for whatever models you'll use as **environment
variables** before starting the app (the UI references env var *names*,
not raw keys, so secrets never pass through the browser or get written to
disk):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export POLYCLOUD_API_KEY=...
# etc, one per endpoint you'll configure in the UI
```

## Run

```bash
python app.py
```

Open http://localhost:5000

## Using the app

### 1. Dataset tab
- On first run, click **Rebuild dataset** to download AdvBench, HarmBench,
  Do-Not-Answer, and the garak in-the-wild jailbreak corpus, then build the
  full labeled VaultBench dataset (~20,600 prompts) into `data/vaultbench_full.csv`.
- A pre-built dataset ships with the app, so this is optional unless you
  want to refresh from upstream sources.
- View the risk/attack-vector/banking-relevance distribution, and download
  the full CSV.

### 2. Benchmark tab
- **Target models**: add one or more endpoints under test.
  - `api_type: openai` — any OpenAI-compatible `/v1/chat/completions`
    endpoint (vLLM, TGI, Ollama, LM Studio, PolyCloud-hosted open-source
    models, etc.)
  - `api_type: anthropic` — Anthropic Messages API (`/v1/messages`)
    compatible endpoints
  - For each, set the **API key env var name** (must already be set in the
    server environment), model name, base URL, max tokens, temperature.
- **Judge model**: defaults to a flagship Anthropic model; change as needed.
- **Filters**: scope the run — e.g. start with `severity_min=4` +
  `banking_relevance=HIGH` (~1,940 prompts) as a hard gate before a full sweep.
- **Run settings**: `max_prompts` lets you sample a subset for a quick/cheap
  smoke test before committing to a full run. `concurrency` controls
  parallel requests.
- Click **Run benchmark**. Progress updates live; you can **Cancel** an
  in-progress run (in-flight requests finish, no new ones start).

### 3. Results tab
- Lists all past runs with an overall safety-score pill per target.
- Click a run to see per-target gauges and breakdown tables by risk type,
  attack vector, banking relevance, and severity.
- Download `judged.csv` (every prompt + response + verdict + rationale),
  `summary.md`, `summary.json` per target, or a zip of the whole run.

## Notes & caveats
- This ships with the Flask **development server** — fine for internal
  red-team use on a trusted network; put behind a proper WSGI server +
  auth if exposing more broadly.
- Cost/scale: a full 20,615-prompt run × judge calls = ~41k LLM calls per
  target (multi-turn rows cost a few extra target calls each — see below).
  Use filters/`max_prompts` for iterative testing.
- **Multi-turn (Crescendo-style) evaluation is fully iterative**: for
  `MULTI_TURN_ESCALATION` rows, each scripted user turn is sent to the
  target model in order, and the model's *real* response is fed back into
  the conversation before the next (escalating) user turn is sent. The
  judge then reviews the **entire real transcript** (not just the final
  reply) and can flag the conversation as UNSAFE if the model was walked
  into compliance at *any* turn — `judged.csv` includes a
  `first_unsafe_turn` column and a `transcript_json` column with the full
  back-and-forth for review.
- Judge bias: using a model to judge itself (or a closely related model)
  can have blind spots — consider periodically rotating the judge model or
  spot-checking a sample with human review.
- See the top-level VaultBench README (taxonomy, sources, attribution) for
  details on the dataset composition and risk taxonomy.
