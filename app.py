"""
app.py
------
VaultBench web app. Flask backend serving:
  - GET  /                          -> UI
  - GET  /api/dataset/stats         -> current dataset stats (for charts)
  - GET  /api/dataset/filters       -> distinct values for filter dropdowns
  - POST /api/dataset/rebuild       -> kick off dataset rebuild job
  - POST /api/benchmark/run         -> kick off benchmark job
  - POST /api/jobs/<job_id>/cancel  -> cancel a running job
  - GET  /api/jobs/<job_id>         -> poll job status/progress
  - GET  /api/runs                  -> list past benchmark runs
  - GET  /api/runs/<run_id>         -> run summary
  - GET  /api/runs/<run_id>/download/<target>/<fname> -> download a result file
  - GET  /api/runs/<run_id>/download_all -> zip of full run

Run with:  python app.py   (defaults to http://0.0.0.0:5000)
"""

import json
import os
import shutil
import threading
import time
import uuid
import zipfile

from flask import Flask, jsonify, request, send_file, abort, render_template

import dataset_core
import eval_core

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory job tracking
# ---------------------------------------------------------------------------
JOBS = {}          # job_id -> {type, status, progress, total, message, error, result, created}
JOBS_LOCK = threading.Lock()


def _new_job(job_type):
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "type": job_type, "status": "running",
            "progress": 0, "total": 100, "message": "starting...",
            "error": None, "result": None, "created": time.time(),
            "cancel_flag": threading.Event(),
        }
    return job_id


def _update_job(job_id, progress=None, total=None, message=None):
    with JOBS_LOCK:
        j = JOBS.get(job_id)
        if not j:
            return
        if progress is not None:
            j["progress"] = progress
        if total is not None:
            j["total"] = total
        if message is not None:
            j["message"] = message


def _finish_job(job_id, result=None, error=None):
    with JOBS_LOCK:
        j = JOBS.get(job_id)
        if not j:
            return
        j["status"] = "error" if error else "done"
        j["error"] = error
        j["result"] = result
        j["progress"] = j["total"]


def _job_public(job_id):
    with JOBS_LOCK:
        j = JOBS.get(job_id)
        if not j:
            return None
        return {k: v for k, v in j.items() if k != "cancel_flag"}


# ---------------------------------------------------------------------------
# Routes: UI
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Routes: dataset
# ---------------------------------------------------------------------------
@app.route("/api/dataset/stats")
def dataset_stats():
    stats = dataset_core.dataset_stats()
    if stats is None:
        return jsonify({"exists": False})
    stats["exists"] = True
    return jsonify(stats)


@app.route("/api/dataset/filters")
def dataset_filters():
    return jsonify(dataset_core.distinct_values())


@app.route("/api/dataset/rebuild", methods=["POST"])
def dataset_rebuild():
    body = request.get_json(silent=True) or {}
    force = bool(body.get("force_download", False))
    job_id = _new_job("dataset_rebuild")

    def worker():
        try:
            def cb(done, total, msg):
                _update_job(job_id, progress=done, total=total, message=msg)
            rows = dataset_core.run_full_rebuild(cb, force_download=force)
            _finish_job(job_id, result={"total_prompts": len(rows)})
        except Exception as e:  # noqa: BLE001
            _finish_job(job_id, error=f"{type(e).__name__}: {e}")

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id})


# ---------------------------------------------------------------------------
# Routes: benchmark run
# ---------------------------------------------------------------------------
@app.route("/api/benchmark/run", methods=["POST"])
def benchmark_run():
    config = request.get_json(force=True)
    if not config.get("targets"):
        return jsonify({"error": "no targets configured"}), 400
    if not config.get("judge"):
        return jsonify({"error": "no judge configured"}), 400

    run_id = time.strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]
    run_dir = os.path.join(RESULTS_DIR, run_id)
    os.makedirs(run_dir, exist_ok=True)

    # persist the config (minus raw api keys) alongside the run
    safe_config = json.loads(json.dumps(config))
    for section in ("targets",):
        for t in safe_config.get(section, []):
            t.pop("api_key", None)
    safe_config.get("judge", {}).pop("api_key", None)
    with open(os.path.join(run_dir, "config.json"), "w", encoding="utf-8") as f:
        json.dump(safe_config, f, indent=2)

    job_id = _new_job("benchmark_run")
    with JOBS_LOCK:
        JOBS[job_id]["run_id"] = run_id
    cancel_flag = JOBS[job_id]["cancel_flag"]

    def worker():
        try:
            def cb(done, total, msg):
                _update_job(job_id, progress=done, total=total, message=msg)
            summaries = eval_core.run_benchmark(config, run_dir, cb, cancel_flag)
            _finish_job(job_id, result={"run_id": run_id, "summaries": summaries})
        except Exception as e:  # noqa: BLE001
            _finish_job(job_id, error=f"{type(e).__name__}: {e}")

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id, "run_id": run_id})


# ---------------------------------------------------------------------------
# Routes: jobs
# ---------------------------------------------------------------------------
@app.route("/api/jobs/<job_id>")
def job_status(job_id):
    j = _job_public(job_id)
    if j is None:
        abort(404)
    return jsonify(j)


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def job_cancel(job_id):
    with JOBS_LOCK:
        j = JOBS.get(job_id)
        if not j:
            abort(404)
        j["cancel_flag"].set()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Routes: results / runs
# ---------------------------------------------------------------------------
@app.route("/api/runs")
def list_runs():
    runs = []
    if os.path.isdir(RESULTS_DIR):
        for run_id in sorted(os.listdir(RESULTS_DIR), reverse=True):
            run_dir = os.path.join(RESULTS_DIR, run_id)
            summary_path = os.path.join(run_dir, "run_summary.json")
            if not os.path.isfile(summary_path):
                continue
            with open(summary_path, encoding="utf-8") as f:
                data = json.load(f)
            runs.append({
                "run_id": run_id,
                "n_prompts": data.get("n_prompts"),
                "targets": data.get("targets"),
                "overall_scores": {
                    t: s.get("overall_safety_score_pct")
                    for t, s in data.get("summaries", {}).items()
                },
            })
    return jsonify(runs)


@app.route("/api/runs/<run_id>")
def run_detail(run_id):
    run_dir = os.path.join(RESULTS_DIR, run_id)
    summary_path = os.path.join(run_dir, "run_summary.json")
    if not os.path.isfile(summary_path):
        abort(404)
    with open(summary_path, encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)


@app.route("/api/runs/<run_id>/download/<target>/<fname>")
def download_file(run_id, target, fname):
    if fname not in ("judged.csv", "summary.json", "summary.md"):
        abort(400)
    path = os.path.join(RESULTS_DIR, run_id, target, fname)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True)


@app.route("/api/runs/<run_id>/download_all")
def download_all(run_id):
    run_dir = os.path.join(RESULTS_DIR, run_id)
    if not os.path.isdir(run_dir):
        abort(404)
    zip_path = os.path.join(RESULTS_DIR, f"{run_id}.zip")
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(run_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, run_dir)
                zf.write(fpath, arcname)
    return send_file(zip_path, as_attachment=True, download_name=f"vaultbench_run_{run_id}.zip")


@app.route("/api/dataset/download")
def download_dataset():
    path = os.path.join(dataset_core.DATA_DIR, "vaultbench_full.csv")
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name="vaultbench_full.csv")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
