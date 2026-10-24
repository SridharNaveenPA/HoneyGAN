"""
ATTACKER MACHINE - LLM-driven SSH attacker
Uses an interactive shell channel (invoke_shell) so the honeypot's
shell handler receives every command — same as a real terminal session.
GUI events are pushed to event_store so attacker_gui.py can stream them live.
"""

import sys
import os
import paramiko
import ollama
import time
import json
import re
from datetime import datetime

# ── event_store lives one level up (honeypot_sim/) ───────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import event_store

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
TARGET_HOST  = "192.168.137.217"
TARGET_PORT  = 2222
SSH_USERNAME = "admin"
SSH_PASSWORD = "password123"
OLLAMA_MODEL = "llama3"
MAX_TURNS    = 15
LOG_FILE     = "attacker_log.jsonl"
OUTPUT_WAIT_SECONDS = 45
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert cybersecurity penetration tester with 15 years of experience.
You have gained SSH access to a Linux target machine on the local network (192.168.137.0/24).
Your job is to conduct a thorough penetration test based on the scenario given.

Rules you MUST follow:
1. Output ONLY a single Linux shell command per response — nothing else. No explanation, no markdown, no prose.
2. The command must be a real, valid Linux shell command.
3. Adapt your next command based on the output you receive from the previous command.
4. Work methodically: reconnaissance → enumeration → exploitation → persistence → exfiltration.
5. Never repeat the same command twice.
6. When you have fully completed the objective, output exactly the word: DONE

You are connected to a real machine. Every command you type is executed live on the target."""


def log(entry: dict):
    entry.setdefault("timestamp", datetime.now().isoformat())
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    # also push to GUI event bus
    event_store.push(entry)


def get_llm_command(client: ollama.Client, messages: list) -> str:
    response = client.chat(
        model=OLLAMA_MODEL,
        messages=messages,
        options={"temperature": 0.7}
    )
    raw = response["message"]["content"].strip()
    raw = re.sub(r"^```[a-z]*\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)
    return raw.strip()


def read_until_prompt(shell, timeout: float = OUTPUT_WAIT_SECONDS) -> str:
    buf = ""
    deadline   = time.time() + timeout
    last_recv  = time.time()

    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(4096).decode("utf-8", errors="replace")
            buf += chunk
            last_recv = time.time()
            if buf.rstrip().endswith("$ ") or buf.rstrip().endswith("$"):
                break
        else:
            if buf and (time.time() - last_recv) > 3.0:
                break
            time.sleep(0.1)

    lines   = buf.split("\n")
    cleaned = [l for l in lines if not l.strip().endswith("$ ") and not l.strip() == "$"]
    return "\n".join(cleaned).strip()


def strip_welcome_banner(shell) -> str:
    return read_until_prompt(shell, timeout=15)


def run_attack(scenario: str):
    print("\n" + "═" * 60)
    print("  ATTACKER LLM — Cybersecurity Simulation")
    print("═" * 60)
    print(f"  Target  : {TARGET_HOST}:{TARGET_PORT}")
    print(f"  Model   : {OLLAMA_MODEL}")
    print(f"  Scenario: {scenario[:80]}")
    print("═" * 60 + "\n")

    # ── Ollama check ──────────────────────────────────────────
    ollama_client = ollama.Client(host="http://127.0.0.1:11434")
    try:
        ollama_client.list()
        print("[✓] Ollama reachable")
    except Exception as e:
        print(f"[✗] Ollama not reachable: {e}")
        sys.exit(1)

    # ── SSH connect ───────────────────────────────────────────
    print(f"[*] Connecting to {TARGET_HOST}:{TARGET_PORT} via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            hostname=TARGET_HOST, port=TARGET_PORT,
            username=SSH_USERNAME, password=SSH_PASSWORD,
            timeout=15, allow_agent=False, look_for_keys=False
        )
        print("[✓] SSH connected")
    except Exception as e:
        print(f"[✗] SSH failed: {e}")
        sys.exit(1)

    # ── Open interactive shell ────────────────────────────────
    shell = ssh.invoke_shell(term="xterm", width=220, height=50)
    shell.settimeout(OUTPUT_WAIT_SECONDS)
    print("[*] Waiting for welcome banner...")
    banner = strip_welcome_banner(shell)
    print(f"[✓] Shell ready.\n")

    # ── LLM conversation init ─────────────────────────────────
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Penetration test scenario: {scenario}\n\n"
                f"You are now in an SSH session on the target at {TARGET_HOST}. "
                f"The welcome banner was:\n{banner}\n\n"
                f"Begin the attack. Output your first command only."
            )
        }
    ]

    log({"event": "session_start", "scenario": scenario, "target": TARGET_HOST,
         "model": OLLAMA_MODEL})

    turn = 0
    try:
        while turn < MAX_TURNS:
            turn += 1
            print(f"[Turn {turn}/{MAX_TURNS}] Asking LLM for next command...")

            # Emit "thinking" status so GUI shows spinner
            event_store.push({"event": "thinking", "turn": turn})

            command = get_llm_command(ollama_client, messages)

            if not command or command.upper() == "DONE":
                print("\n[✓] Attacker LLM signalled mission complete.")
                log({"event": "mission_complete", "turns": turn})
                break

            print(f"\n  $ {command}")
            log({"event": "command_sent", "turn": turn, "command": command})

            shell.send(command + "\n")

            print(f"  [*] Waiting for output...")
            output = read_until_prompt(shell, timeout=OUTPUT_WAIT_SECONDS)

            if output.startswith(command):
                output = output[len(command):].lstrip("\r\n")

            print(f"  OUTPUT: {output[:120].replace(chr(10),' ')}{'...' if len(output)>120 else ''}\n")
            log({"event": "output_received", "turn": turn, "output": output[:3000]})

            messages.append({"role": "assistant", "content": command})
            messages.append({
                "role": "user",
                "content": f"Command output:\n{output}\n\nAnalyze this and provide your next attack command."
            })

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        event_store.push({"event": "error", "message": str(e)})
    finally:
        try:
            shell.close()
        except Exception:
            pass
        ssh.close()
        print(f"\n[*] Disconnected. Log → {LOG_FILE}")

    print("\n" + "═" * 60)
    print("  Attack session finished.")
    print("═" * 60)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        scenario = " ".join(sys.argv[1:])
    else:
        print("Enter attack scenario:")
        scenario = input("> ").strip()
        if not scenario:
            scenario = "Perform full reconnaissance and steal database credentials"

    run_attack(scenario)
