"""
event_store.py — thread-safe in-memory event bus.
Both attacker.py and honeypot_server.py import this and call push().
The Flask GUI apps subscribe to a queue and stream events via SSE.
"""

import queue
import threading
import json
from datetime import datetime
from collections import deque

# ── In-memory stores ──────────────────────────────────────────────────────────
_lock       = threading.Lock()
_listeners  = []          # list of queue.Queue — one per SSE subscriber
_history    = deque(maxlen=500)   # keep last 500 events for late-joining browsers


def push(event: dict):
    """Called by attacker.py / honeypot_server.py to emit an event."""
    event.setdefault("timestamp", datetime.now().isoformat())
    payload = json.dumps(event)

    with _lock:
        _history.append(payload)
        dead = []
        for q in _listeners:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _listeners.remove(q)


def subscribe() -> queue.Queue:
    """
    Create a new subscriber queue, pre-loaded with history,
    so a browser that connects mid-session sees everything so far.
    """
    q = queue.Queue(maxsize=200)
    with _lock:
        for payload in _history:
            try:
                q.put_nowait(payload)
            except queue.Full:
                break
        _listeners.append(q)
    return q


def unsubscribe(q: queue.Queue):
    with _lock:
        try:
            _listeners.remove(q)
        except ValueError:
            pass
