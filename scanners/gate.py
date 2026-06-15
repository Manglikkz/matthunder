"""
gate - 7-Question Gate for finding validation before reporting.

Inspired by:
  - Claude-BugHunter triage-validation (7-Question Gate)
  - shuvonsec/claude-bug-bounty /validate
  - All 5 AI providers: "validate before report"

The 7 Questions:
  Q1: Can an attacker do this RIGHT NOW? (not theoretical)
  Q2: Is it in the program's accepted impact list?
  Q3: Is the target in scope?
  Q4: Is it a duplicate of a known finding?
  Q5: Can you reproduce it reliably?
  Q6: Is the impact clear and demonstrable?
  Q7: Is it NOT on the always-rejected list?

Usage:
  python matthunder_cli.py gate
  (interactive mode — asks questions about your finding)
"""

from . import SCANNER_REGISTRY


ALWAYS_REJECTED = [
    "Missing HTTPOnly flag on non-session cookie",
    "Missing Secure flag on non-sensitive cookie",
    "Self-XSS that requires user to paste in console",
    "Clickjacking on pages with no sensitive actions",
    "Missing email verification on registration",
    "Open redirect via user interaction (link click)",
    "Information disclosure via Server header only",
    "Version disclosure without known vulnerability",
    "SSL/TLS version warnings without exploit",
    "DNS zone transfer on non-sensitive domain",
    "OPTIONS method enabled (CORS preflight)",
    "TRACE/TRACK method enabled (no impact shown)",
    "403 bypass on non-sensitive resource",
    "Rate limiting not implemented on non-auth endpoint",
    "Password complexity policy too weak (without brute force proof)",
    "Username enumeration via registration (not login)",
    "Email enumeration via forgot password (without impact)",
    "Clickjacking on static pages",
    "Host header injection without password reset poison",
    "Subdomain takeover without demonstrating claim",
]

PROGRAM_IMPACT_COMMON = [
    "Account takeover",
    "Unauthorized access to data",
    "Remote code execution",
    "SQL injection with data exfiltration",
    "Stored XSS affecting other users",
    "SSRF with cloud metadata access",
    "IDOR accessing other users' PII",
    "Authentication bypass",
    "Authorization bypass (privilege escalation)",
    "Payment manipulation",
    "Race condition with financial impact",
    "Full account takeover via CSRF",
    "GraphQL introspection exposing sensitive data",
    "File upload leading to RCE",
    "Server-side template injection",
]


def run_interactive() -> dict:
    """Run the 7-Question Gate interactively."""
    print(f"\n  \033[1m\033[93m  7-QUESTION GATE — Finding Validation\033[0m")
    print(f"  {'─'*55}")
    print(f"  Answer each question honestly. One 'No' = kill the finding.\n")

    questions = [
        ("Q1", "Can an attacker do this RIGHT NOW?",
         "Not theoretical. Not 'if they also do X'. Real, reproducible impact."),
        ("Q2", "Is it in the program's accepted impact list?",
         "Check the program's policy. Some programs don't accept certain bug types."),
        ("Q3", "Is the target in scope?",
         "Verify against the program's scope. Wildcard ≠ everything."),
        ("Q4", "Is it a duplicate?",
         "Check if someone already reported this. Search disclosed reports."),
        ("Q5", "Can you reproduce it reliably?",
         "Steps to reproduce must work every time, not just once."),
        ("Q6", "Is the impact clear and demonstrable?",
         "Can you show data leak? Account takeover? RCE? Not just 'potential'."),
        ("Q7", "Is it NOT on the always-rejected list?",
         "See common always-rejected findings below."),
    ]

    print(f"  \033[91m  Always-Rejected (common):\033[0m")
    for r in ALWAYS_REJECTED[:5]:
        print(f"    • {r}")
    print(f"    ... and {len(ALWAYS_REJECTED)-5} more\n")

    passed = 0
    failed_at = None
    answers = []

    for qid, question, context in questions:
        print(f"  \033[96m{qid}\033[0m: {question}")
        print(f"      \033[90m{context}\033[0m")
        ans = input(f"      (y/n): ").strip().lower()
        answers.append({"q": qid, "question": question, "answer": ans})

        if ans == "y":
            passed += 1
        else:
            if failed_at is None:
                failed_at = qid
            print(f"      \033[91m✗ Failed at {qid} — finding should NOT be submitted\033[0m")
            break
        print()

    # Result
    print(f"\n  {'─'*55}")
    if passed == 7:
        print(f"  \033[92m✓ ALL 7 QUESTIONS PASSED\033[0m")
        print(f"  Finding is ready for submission. Write the report!")
        result = "PASS"
    else:
        print(f"  \033[91m✗ GATE FAILED at {failed_at}\033[0m")
        print(f"  Finding should NOT be submitted. Fix or kill it.")
        result = "FAIL"

    print(f"  Score: {passed}/7")
    print()

    return {
        "result": result,
        "score": f"{passed}/7",
        "failed_at": failed_at,
        "answers": answers,
    }


def run(domain: str = None) -> dict:
    """Entry point for scanner registry."""
    return run_interactive()


SCANNER_REGISTRY["gate"] = run
SCANNER_REGISTRY["validate"] = run
