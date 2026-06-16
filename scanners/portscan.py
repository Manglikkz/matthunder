"""
portscan - Port scanner (naabu/nmap wrapper).

Scans for open ports on the target domain.
Wraps naabu (Go) or falls back to nmap or Python socket scan.

Usage:
  python matthunder_cli.py portscan example.com
"""

import os
import shutil
import socket
import subprocess
from typing import Optional

from . import SCANNER_REGISTRY
from .common import (
    resolve_tool,
    finish_scan, log, normalize_domain, open_db, utc_now_iso,
)


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888,
    9090, 9200, 9300, 27017,
]

PORT_SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9090: "HTTP-Mgmt", 9200: "Elasticsearch",
    9300: "ES-Transport", 27017: "MongoDB",
}


def _resolve(name: str) -> Optional[str]:
    return resolve_tool(name)



def _socket_scan(domain: str, ports: list[int], timeout: float = 1.5) -> list[dict]:
    """Lightweight Python socket-based port scan as fallback."""
    results = []
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return results

    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                service = PORT_SERVICE.get(port, "unknown")
                results.append({"port": port, "state": "open", "service": service, "ip": ip})
        except Exception:
            continue
    return results


def run(domain: str, ports: str = "top30") -> dict:
    domain = normalize_domain(domain)

    con = open_db()
    scan_id = con.execute(
        "INSERT INTO scans (id, scanner, domain, params, status, created_at) "
        "VALUES (lower(hex(randomblob(16))), 'portscan', ?, ?, 'running', ?)",
        (domain, ports, utc_now_iso()),
    ).lastrowid
    con.commit()
    scan_id = con.execute("SELECT id FROM scans WHERE rowid=?", (scan_id,)).fetchone()["id"]
    log(con, scan_id, f"Port scan started - domain: {domain}")

    findings: list[dict] = []

    # Try naabu first
    naabu = _resolve("naabu")
    if naabu:
        log(con, scan_id, "Running naabu...")
        port_flag = "-top-ports 100" if ports == "top30" else f"-p {ports}"
        cmd = [naabu, "-host", domain, "-silent", "-o", f"_matthunder_ports_{scan_id}.txt"]
        if ports == "top30":
            cmd.extend(["-top-ports", "100"])
        else:
            cmd.extend(["-p", ports])
        try:
            proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=120)
            out_path = f"_matthunder_ports_{scan_id}.txt"
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if ":" in line:
                            parts = line.split(":")
                            port = int(parts[-1]) if parts[-1].isdigit() else 0
                            if port:
                                service = PORT_SERVICE.get(port, "unknown")
                                findings.append({"port": port, "state": "open", "service": service, "ip": parts[0] if len(parts) > 1 else domain})
                os.remove(out_path)
            log(con, scan_id, f"naabu found {len(findings)} open ports")
        except subprocess.TimeoutExpired:
            log(con, scan_id, "naabu timed out")
        except FileNotFoundError:
            log(con, scan_id, "naabu not found, falling back to socket scan")
            findings = _socket_scan(domain, COMMON_PORTS)
        except Exception as e:
            log(con, scan_id, f"naabu error: {e}")
    else:
        # Try nmap
        nmap = _resolve("nmap")
        if nmap:
            log(con, scan_id, "Running nmap...")
            cmd = [nmap, "-sT", "-T4", "--top-ports", "30", "-oG", f"_matthunder_ports_{scan_id}.txt", domain]
            try:
                proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=120)
                for line in (proc.stdout + proc.stderr).splitlines():
                    if "/open/" in line:
                        parts = line.split()
                        for p in parts:
                            if "/open/" in p:
                                port_num = int(p.split("/")[0])
                                service = PORT_SERVICE.get(port_num, "unknown")
                                findings.append({"port": port_num, "state": "open", "service": service})
                log(con, scan_id, f"nmap found {len(findings)} open ports")
            except Exception as e:
                log(con, scan_id, f"nmap error: {e}")
        else:
            # Fallback to socket scan
            log(con, scan_id, "No port scanner found, using Python socket scan...")
            findings = _socket_scan(domain, COMMON_PORTS)
            log(con, scan_id, f"Socket scan found {len(findings)} open ports")

    for f in findings:
        con.execute(
            "INSERT INTO results (scan_id, category, target_url, status, detail, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, f"port_{f['port']}", domain, f["state"],
             f"port={f['port']} service={f['service']} ip={f.get('ip', domain)}", utc_now_iso()),
        )
    con.commit()
    finish_scan(con, scan_id, status="completed", total_sources=1, total_links=len(findings))

    # Cleanup
    for p in [f"_matthunder_ports_{scan_id}.txt"]:
        try:
            os.remove(p)
        except OSError:
            pass
    con.close()
    return {"scan_id": scan_id, "scanner": "portscan", "domain": domain, "findings": len(findings)}


SCANNER_REGISTRY["portscan"] = run
SCANNER_REGISTRY["ports"] = run
