"""
event_store.py — file-backed event bus.

Both attacker.py and honeypot_server.py call push() which appends a JSON line
to a shared file (events.jsonl in the honeypot_sim directory).

The Flask GUI apps tail that file via SSE — this works across separate OS
processes because the file is on the shared filesystem.
"""

import json
import os
import time
import queue
import threading
from datetime import datetime

# ── Shared event file ─────────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
EVENT_FILE  = os.path.join(_BASE_DIR, "events.jsonl")

# ── In-process subscriber registry (for the GUI process only) ─────────────────
_lock       = threading.Lock()
_listeners  = []          # list[queue.Queue]


def push(event: dict):
    """
    Called by attacker.py / honeypot_server.py.
    Appends the event as a JSON line to the shared file.
    Also fans out to any in-process subscribers (in case GUI and backend
    share the same process during testing).
    """
    event.setdefault("timestamp", datetime.now().isoformat())
    line = json.dumps(event) + "\n"

    # atomic-ish append — works on Windows and Linux
    with open(EVENT_FILE, "a", encoding="utf-8") as f:
        f.write(line)

    # fan-out to in-process listeners (no-op when running as a separate process)
    with _lock:
        dead = []
        for q in _listeners:
            try:
                q.put_nowait(line.strip())
            except queue.Full:
                dead.append(q)
        for q in dead:
            _listeners.remove(q)


def subscribe() -> queue.Queue:
    """
    Used by the GUI Flask process.
    Returns a Queue that receives every new event line written to EVENT_FILE.
    A background thread tails the file and feeds the queue.
    """
    q = queue.Queue(maxsize=500)

    with _lock:
        _listeners.append(q)

    # Start a file-tail thread dedicated to this subscriber
    t = threading.Thread(target=_tail_file, args=(q,), daemon=True)
    t.start()

    return q


def unsubscribe(q: queue.Queue):
    with _lock:
        try:
            _listeners.remove(q)
        except ValueError:
            pass


# ── File tailer ───────────────────────────────────────────────────────────────

def _tail_file(q: queue.Queue):
    """
    Reads EVENT_FILE from the beginning (so late-joining browsers get history),
    then polls for new lines, pushing each JSON line into q.
    Exits when the queue has been garbage-collected or unsubscribed.
    """
    # Wait for file to exist
    while not os.path.exists(EVENT_FILE):
        time.sleep(0.5)

    with open(EVENT_FILE, "r", encoding="utf-8") as f:
        # Replay history first
        for line in f:
            line = line.strip()
            if line:
                try:
                    q.put_nowait(line)
                except queue.Full:
                    pass

        # Then tail for new content
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        q.put(line, timeout=5)
                    except queue.Full:
                        pass
            else:
                # Check if queue was unsubscribed (removed from _listeners)
                with _lock:
                    if q not in _listeners:
                        return
                time.sleep(0.1)
