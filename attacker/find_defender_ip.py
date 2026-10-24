"""
find_defender_ip.py  —  run on ATTACKER machine
Scans the hotspot subnet to find the defender laptop's IP address.
The hotspot subnet is typically 192.168.137.0/24 on Windows.
"""

import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

SUBNET = "192.168.137"
PORT   = 2222        # honeypot port
TIMEOUT = 0.5


def probe(ip: str) -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((ip, PORT))
        s.close()
        if result == 0:
            return ip
    except Exception:
        pass
    return None


def get_own_hotspot_ip() -> str:
    """Try to detect the hotspot adapter IP (usually 192.168.137.1 on Windows)."""
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True
        )
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if "192.168.137" in line and "IPv4" in line:
                ip = line.split(":")[-1].strip()
                return ip
    except Exception:
        pass
    return "192.168.137.1"


def main():
    own_ip = get_own_hotspot_ip()
    print(f"[*] Your hotspot IP detected as: {own_ip}")
    print(f"[*] Scanning {SUBNET}.1-254 for open port {PORT}...")

    found = []
    ips = [f"{SUBNET}.{i}" for i in range(1, 255) if f"{SUBNET}.{i}" != own_ip]

    with ThreadPoolExecutor(max_workers=80) as ex:
        futures = {ex.submit(probe, ip): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                print(f"\n  [✓] FOUND honeypot at: {result}")

    if not found:
        print("\n[✗] No honeypot found. Make sure:")
        print("    1. Defender laptop is connected to this hotspot")
        print("    2. honeypot_server.py is running on the defender")
        print("    3. Windows Firewall on defender allows port 2222")
    else:
        print(f"\n[→] Update TARGET_HOST in attacker.py to: {found[0]}")


if __name__ == "__main__":
    main()
