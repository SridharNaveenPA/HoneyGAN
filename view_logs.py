"""
view_logs.py — run on either machine to watch the simulation in real time
"""

import json
import sys
import time
import os

LOG_FILES = ["attacker_log.jsonl", "honeypot_log.jsonl"]

def tail(path: str, n: int = 50):
    if not os.path.exists(path):
        print(f"[!] Log file not found: {path}")
        return
    with open(path) as f:
        lines = f.readlines()
    for line in lines[-n:]:
        try:
            entry = json.loads(line)
            ts = entry.get("timestamp", "")[:19]
            ev = entry.get("event", "")
            if ev == "command_sent":
                print(f"[{ts}] ATTACK CMD  → {entry.get('command','')}")
            elif ev == "output_received":
                out = entry.get("output","")[:120].replace("\n"," ")
                print(f"[{ts}] OUTPUT      ← {out}")
            elif ev == "command_received":
                print(f"[{ts}] HONEYPOT    ← {entry.get('command','')}")
            elif ev == "fake_output_sent":
                out = entry.get("output","")[:120].replace("\n"," ")
                print(f"[{ts}] FAKE OUTPUT → {out}")
            elif ev == "auth_attempt":
                print(f"[{ts}] AUTH        user={entry.get('username')} pass={entry.get('password')}")
            elif ev == "session_start":
                print(f"[{ts}] SESSION START  scenario={entry.get('scenario','')[:60]}")
            elif ev == "mission_complete":
                print(f"[{ts}] MISSION COMPLETE in {entry.get('turns')} turns")
            else:
                print(f"[{ts}] {ev}")
        except Exception:
            print(line.strip())

if __name__ == "__main__":
    log = sys.argv[1] if len(sys.argv) > 1 else None
    if log:
        tail(log)
    else:
        for lf in LOG_FILES:
            if os.path.exists(lf):
                print(f"\n{'═'*60}")
                print(f"  {lf}")
                print("═"*60)
                tail(lf)
