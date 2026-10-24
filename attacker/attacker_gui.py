"""
attacker_gui.py — Flask web GUI for the attacker machine.
Run this ALONGSIDE attacker.py (they share event_store via import).
Open http://localhost:5001 in your browser.
"""

import sys
import os
import json
import time
import threading

# Make sure the parent folder (honeypot_sim) is on the path so we can import event_store
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import event_store

from flask import Flask, Response, render_template, jsonify

app = Flask(__name__, template_folder="templates")

LOG_FILE = os.path.join(os.path.dirname(__file__), "attacker_log.jsonl")


# ── SSE stream ────────────────────────────────────────────────────────────────

def sse_stream():
    q = event_store.subscribe()
    try:
        while True:
            try:
                payload = q.get(timeout=25)
                yield f"data: {payload}\n\n"
            except Exception:
                # heartbeat to keep connection alive
                yield "data: {\"event\":\"ping\"}\n\n"
    finally:
        event_store.unsubscribe(q)


@app.route("/stream")
def stream():
    return Response(sse_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Log API ───────────────────────────────────────────────────────────────────

@app.route("/logs")
def logs():
    entries = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
    return jsonify(entries)


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("attacker.html")


@app.route("/logview")
def logview():
    return render_template("attacker_logs.html")


if __name__ == "__main__":
    print("\n[ATTACKER GUI] Running at http://localhost:5001")
    print("[ATTACKER GUI] Open this URL in your browser.\n")
    app.run(host="0.0.0.0", port=5001, threaded=True, debug=False)
