"""
DEFENDER MACHINE — Fake SSH honeypot server + Defender LLM
GUI events are pushed to event_store so defender_gui.py can stream them live.
"""

import select
import socket
import threading
import paramiko
import ollama
import json
import logging
import sys
import os
from datetime import datetime

# ── event_store lives one level up (honeypot_sim/) ───────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import event_store

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
HONEYPOT_HOST = "0.0.0.0"
HONEYPOT_PORT = 2222
SSH_USERNAME  = "admin"
SSH_PASSWORD  = "password123"
OLLAMA_MODEL  = "llama3"
LOG_FILE      = "honeypot_log.jsonl"
BANNER        = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
HOST_KEY_FILE = "honeypot_host.key"
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("honeypot_server.log")
    ]
)
log = logging.getLogger("honeypot")

DEFENDER_SYSTEM_PROMPT = """You are the operating system of a Linux Ubuntu 22.04 server named "webserver-prod".
An attacker has SSH'd into this system and is running commands against you.

Your mission:
1. Respond to every command exactly as a real Linux system would — with realistic, plausible output.
2. The output should look authentic but subtly mislead the attacker:
   - Show fake credentials, fake sensitive files, fake configs pointing to non-existent services.
   - Fake user accounts, fake SSH keys, fake database connection strings (wrong passwords).
   - Fake /etc/passwd, /etc/shadow entries that look real but are decoys.
   - If they try to escalate privileges, always fail with plausible errors.
   - Never let them get real root or actual useful credentials.
3. Keep them engaged — give just enough interesting-looking data to keep the attacker exploring.
4. Output ONLY the raw terminal output of the command. No explanation, no markdown, no commentary.
5. Match the exact format Linux would return: prompt-less, plain text, realistic file paths, realistic usernames.
6. The machine hostname is "webserver-prod", primary user is "admin", IP is 192.168.137.50.
7. Fake important files:
   - /var/www/html/config.php has a fake DB password "Sup3rS3cr3t!" connecting to localhost MySQL
   - /home/admin/.ssh/id_rsa looks like a real private key (generate plausible looking PEM blocks)
   - /etc/passwd has admin, www-data, mysql, backup_user entries
   - crontab has a fake backup script running as root

Remember: you are a TRAP. Every convincing piece of fake data buys more time to study the attacker."""


def get_host_key():
    if os.path.exists(HOST_KEY_FILE):
        return paramiko.RSAKey(filename=HOST_KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_FILE)
    log.info(f"Generated new host key → {HOST_KEY_FILE}")
    return key


def log_event(entry: dict):
    entry.setdefault("timestamp", datetime.now().isoformat())
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    # push to GUI event bus
    event_store.push(entry)


def generate_fake_output(ollama_client, command: str, session_history: list) -> str:
    messages = [{"role": "system", "content": DEFENDER_SYSTEM_PROMPT}]
    for item in session_history[-10:]:
        messages.append({"role": "user",      "content": item["command"]})
        messages.append({"role": "assistant", "content": item["output"]})
    messages.append({
        "role": "user",
        "content": f"The attacker just ran this command:\n\n{command}\n\nReturn the terminal output."
    })
    try:
        response = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=messages,
            options={"temperature": 0.4}
        )
        return response["message"]["content"].strip()
    except Exception as e:
        log.error(f"Ollama error: {e}")
        return f"bash: {command.split()[0]}: command not found"


# ── Paramiko server interface ─────────────────────────────────────────────────

class HoneypotServerInterface(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log.info(f"[AUTH] username={username!r} password={password!r}")
        log_event({"event": "auth_attempt", "username": username, "password": password})
        if username == SSH_USERNAME and password == SSH_PASSWORD:
            log.info("[AUTH] ✓ Accepted (honeypot)")
            return paramiko.AUTH_SUCCESSFUL
        log.info("[AUTH] ✗ Rejected")
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        self._exec_command = command.decode("utf-8", errors="replace")
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


# ── Per-connection handler ────────────────────────────────────────────────────

def handle_connection(client_sock: socket.socket, addr, host_key, ollama_client):
    peer = f"{addr[0]}:{addr[1]}"
    log.info(f"[*] New connection from {peer}")
    log_event({"event": "connection", "peer": peer})

    session_history = []

    transport = paramiko.Transport(client_sock)
    transport.local_version = BANNER
    transport.add_server_key(host_key)
    server_iface = HoneypotServerInterface()

    try:
        transport.start_server(server=server_iface)
    except paramiko.SSHException as e:
        log.error(f"SSH negotiation failed from {peer}: {e}")
        return

    channel = transport.accept(30)
    if channel is None:
        log.warning(f"No channel opened from {peer}")
        transport.close()
        return

    log.info(f"[+] Channel opened from {peer}")

    PROMPT = b"admin@webserver-prod:~$ "

    welcome = (
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
        "\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        "\r\n"
        "Last login: Fri Oct 23 14:22:11 2026 from 10.0.0.4\r\n"
    )
    channel.send(welcome.encode() + PROMPT)

    buf = ""
    try:
        while True:
            r, _, _ = select.select([channel], [], [], 0.3)
            if not r:
                if not transport.is_active():
                    break
                continue

            data = channel.recv(4096)
            if not data:
                break

            decoded = data.decode("utf-8", errors="replace")
            buf += decoded

            while "\n" in buf or "\r" in buf:
                for sep in ("\r\n", "\n", "\r"):
                    if sep in buf:
                        line, buf = buf.split(sep, 1)
                        break

                command = line.strip()
                channel.send((command + "\r\n").encode())

                if not command:
                    channel.send(PROMPT)
                    continue

                if command.lower() in ("exit", "logout", "quit"):
                    channel.send(b"logout\r\n")
                    raise SystemExit(0)

                log.info(f"[CMD from {peer}] {command!r}")
                log_event({"event": "command_received", "peer": peer, "command": command})

                # Push "generating" status for GUI spinner
                event_store.push({"event": "generating_response", "peer": peer, "command": command})

                print(f"\n{'═'*50}")
                print(f"  ATTACKER CMD  : {command}")
                print(f"{'─'*50}")
                print("  Generating fake output via defender LLM...")

                fake_output = generate_fake_output(ollama_client, command, session_history)

                print(f"  FAKE OUTPUT   : {fake_output[:200].replace(chr(10),' ')}...")
                print(f"{'═'*50}\n")

                log_event({
                    "event": "fake_output_sent",
                    "peer": peer,
                    "command": command,
                    "output": fake_output
                })

                session_history.append({"command": command, "output": fake_output})

                response = fake_output.replace("\n", "\r\n") + "\r\n"
                channel.send(response.encode("utf-8", errors="replace"))
                channel.send(PROMPT)

    except SystemExit:
        pass
    except Exception as e:
        log.error(f"Session error from {peer}: {e}")
    finally:
        channel.close()
        transport.close()
        log.info(f"[-] Connection from {peer} closed. Commands intercepted: {len(session_history)}")
        log_event({"event": "disconnection", "peer": peer, "total_commands": len(session_history)})


# ── Main server loop ──────────────────────────────────────────────────────────

def main():
    print("\n" + "═" * 60)
    print("  DEFENDER HONEYPOT — LLM-powered fake SSH server")
    print("═" * 60)
    print(f"  Listening : {HONEYPOT_HOST}:{HONEYPOT_PORT}")
    print(f"  Model     : {OLLAMA_MODEL}")
    print(f"  Log file  : {LOG_FILE}")
    print("═" * 60 + "\n")

    ollama_client = ollama.Client(host="http://127.0.0.1:11434")
    try:
        ollama_client.list()
        log.info("[✓] Ollama reachable")
    except Exception as e:
        log.error(f"[✗] Ollama not reachable: {e}")
        sys.exit(1)

    host_key = get_host_key()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HONEYPOT_HOST, HONEYPOT_PORT))
    server_sock.listen(5)
    log.info(f"[*] Honeypot listening on port {HONEYPOT_PORT}")

    try:
        while True:
            client_sock, addr = server_sock.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, addr, host_key, ollama_client),
                daemon=True
            )
            t.start()
    except KeyboardInterrupt:
        log.info("\n[!] Honeypot shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
