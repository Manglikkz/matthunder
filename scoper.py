"""
scoper - target scope filter.

Parses scope rules (wildcard domains, URLs, CIDR, IP ranges) and decides
whether a given host/URL is in-scope. Inspired by Hacker-Scoper (its-leon).

Supported rule formats (one per line):
  *.example.com
  example.com
  https://*.example.com
  192.0.2.0/24
  192.0.2.0-192.0.2.255
  regex:^.*\.example\.com$

Usage:
  python scoper.py load public-bug-bounty-program/hackerone_bounty.txt
  python scoper.py check api.example.com
  python scoper.py filter targets.txt
"""

import ipaddress
import re
import sys
from typing import Iterable, Optional
from urllib.parse import urlparse


class Scoper:
    def __init__(self, rules: Iterable[str] = None):
        self.wildcard_hosts: list[str] = []
        self.exact_hosts: set[str] = set()
        self.cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.ranges: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
        self.regexes: list[re.Pattern] = []
        if rules:
            for r in rules:
                self.add_rule(r)

    def add_rule(self, rule: str) -> None:
        rule = (rule or "").strip()
        if not rule or rule.startswith("#"):
            return
        if rule.startswith("regex:"):
            try:
                self.regexes.append(re.compile(rule[6:]))
            except re.error:
                pass
            return
        if rule.startswith("http://") or rule.startswith("https://"):
            try:
                rule = urlparse(rule).netloc
            except Exception:
                return
        if "/" in rule and not rule.startswith("regex:"):
            try:
                self.cidrs.append(ipaddress.ip_network(rule, strict=False))
                return
            except ValueError:
                pass
        if "-" in rule and self._looks_like_ip_range(rule):
            try:
                a, b = rule.split("-", 1)
                self.ranges.append((ipaddress.IPv4Address(a.strip()), ipaddress.IPv4Address(b.strip())))
                return
            except Exception:
                pass
        host = rule.lower().lstrip("*.")
        if "*" in host:
            base = host.lstrip("*.")
            if base and base not in self.wildcard_hosts:
                self.wildcard_hosts.append(base)
        else:
            self.exact_hosts.add(host)

    def _looks_like_ip_range(self, rule: str) -> bool:
        try:
            a, b = rule.split("-", 1)
            ipaddress.IPv4Address(a.strip())
            ipaddress.IPv4Address(b.strip())
            return True
        except Exception:
            return False

    def in_scope(self, target: str) -> bool:
        if not target:
            return False
        t = target.strip().lower()
        if t.startswith("http://") or t.startswith("https://"):
            try:
                t = urlparse(t).netloc
            except Exception:
                return False
        try:
            ip = ipaddress.ip_address(t)
            for net in self.cidrs:
                if ip in net:
                    return True
            for lo, hi in self.ranges:
                if lo <= ip <= hi:
                    return True
        except ValueError:
            pass
        for pat in self.regexes:
            if pat.search(target):
                return True
        if t in self.exact_hosts:
            return True
        for base in self.wildcard_hosts:
            if t == base or t.endswith("." + base):
                return True
        return False


def _iter_lines(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line


def main():
    if len(sys.argv) < 2:
        print("usage: python scoper.py <load|check|filter> ...")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "load":
        if len(sys.argv) < 3:
            print("usage: scoper load <rules-file>")
            sys.exit(1)
        sc = Scoper(_iter_lines(sys.argv[2]))
        print(f"loaded {len(sc.exact_hosts)} exact + {len(sc.wildcard_hosts)} wildcard + "
              f"{len(sc.cidrs)} CIDR + {len(sc.ranges)} IP range + {len(sc.regexes)} regex rules")
    elif cmd == "check":
        if len(sys.argv) < 4:
            print("usage: scoper check <rules-file> <target>")
            sys.exit(1)
        sc = Scoper(_iter_lines(sys.argv[2]))
        result = sc.in_scope(sys.argv[3])
        print("IN_SCOPE" if result else "OUT_OF_SCOPE")
    elif cmd == "filter":
        if len(sys.argv) < 4:
            print("usage: scoper filter <rules-file> <targets-file>")
            sys.exit(1)
        sc = Scoper(_iter_lines(sys.argv[2]))
        with open(sys.argv[3], "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                t = line.strip()
                if not t:
                    continue
                print("IN" if sc.in_scope(t) else "OUT", t)
    else:
        print(f"unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
