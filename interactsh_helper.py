"""
interactsh - OOB interaction client for blind vulnerability verification.

Wraps interactsh-client (projectdiscovery/interactsh) to provide a
persistent OOB callback URL for blind SSRF/XXE/XSS/RCE verification.

Usage:
  python -c "from interactsh_helper import InteractshClient; c = InteractshClient(); print(c.register())"
  # or
  python interactsh_helper.py register
"""

import json
import os
import shutil
import subprocess
import time
import uuid
from typing import Optional


def _resolve(name: str = "interactsh-client") -> Optional[str]:
    gopath_bin = os.path.join(os.path.expanduser("~"), "go", "bin")
    cand = os.path.join(gopath_bin, name + (".exe" if os.name == "nt" else ""))
    if os.path.exists(cand):
        return cand
    return shutil.which(name)


class InteractshClient:
    """Lightweight wrapper around interactsh-client Go binary."""

    def __init__(self, token: Optional[str] = None, server: str = "oast.live"):
        self.token = token
        self.server = server
        self._session_id = uuid.uuid4().hex[:8]
        self._proc: Optional[subprocess.Popen] = None
        self._log_path: Optional[str] = None

    def register(self, timeout: int = 30) -> Optional[str]:
        """Spawn interactsh-client and return the unique subdomain."""
        bin_ = _resolve()
        if not bin_:
            print("[!] interactsh-client not installed. Run setup.sh / setup.bat.", flush=True)
            return None
        self._log_path = f"_interactsh_{self._session_id}.log"
        cmd = [bin_, "-v", "-o", self._log_path, "-n", self._session_id]
        if self.token:
            cmd += ["-t", self.token]
        if self.server and self.server != "oast.live":
            cmd += ["-s", self.server]
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Failed to start interactsh-client: {e}", flush=True)
            return None
        deadline = time.time() + timeout
        domain_prefix = f"{self._session_id}."
        while time.time() < deadline:
            if not self._proc.poll() is None and self._proc.returncode not in (None, 0):
                break
            try:
                with open(self._log_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = f.read()
                m_start = data.find("[*]")
                if "interactsh" in data and domain_prefix in data:
                    for line in data.splitlines():
                        if domain_prefix in line:
                            idx = line.find(domain_prefix)
                            if idx > 0:
                                end = idx
                                while end < len(line) and line[end] not in " \n\r\t,":
                                    end += 1
                                return line[idx:end]
            except (FileNotFoundError, IOError):
                pass
            time.sleep(0.5)
        return None

    def poll(self, since_seconds: int = 60) -> list[dict]:
        """Poll interactsh log for new interactions."""
        if not self._log_path or not os.path.exists(self._log_path):
            return []
        out = []
        try:
            with open(self._log_path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
        except IOError:
            return out
        for line in data.splitlines():
            if "Request" in line or "DNS" in line or "SMTP" in line:
                try:
                    out.append({"raw": line.strip()})
                except Exception:
                    pass
        return out

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if self._log_path:
            try:
                os.remove(self._log_path)
            except OSError:
                pass


def main():
    import argparse
    p = argparse.ArgumentParser(description="matthunder interactsh helper")
    p.add_argument("action", choices=["register", "poll", "stop"], help="Action to perform")
    p.add_argument("-s", "--server", default="oast.live", help="interactsh server")
    p.add_argument("-t", "--token", help="interactsh auth token")
    p.add_argument("--timeout", type=int, default=30, help="register timeout (s)")
    args = p.parse_args()

    c = InteractshClient(token=args.token, server=args.server)
    if args.action == "register":
        domain = c.register(timeout=args.timeout)
        if domain:
            print(f"OK  {domain}")
        else:
            print("FAIL")
            sys.exit(1)
    elif args.action == "poll":
        for item in c.poll():
            print(item)
    elif args.action == "stop":
        c.stop()


if __name__ == "__main__":
    main()
