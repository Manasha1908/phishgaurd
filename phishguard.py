#!/usr/bin/env python3
"""
PhishGuard: a beginner-friendly phishing URL risk checker.
This tool checks URL text only. It does not visit the website and cannot prove
that a URL is safe or malicious.
"""
from urllib.parse import urlparse
import ipaddress
import re
import sys

SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure", "account", "password",
    "banking", "wallet", "confirm", "signin", "free", "gift"
}

def check_url(raw_url):
    url = raw_url.strip()
    if not url:
        return {"score": 0, "level": "Invalid input", "reasons": ["No URL was entered."]}

    # Add a scheme for parsing when the user enters example.com
    candidate = url if "://" in url else "http://" + url
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    reasons = []
    score = 0

    if not host or "." not in host:
        reasons.append("The URL does not look like a complete domain.")
        score += 2

    if parsed.scheme.lower() != "https":
        reasons.append("The link does not use HTTPS.")
        score += 1

    if "@" in parsed.netloc:
        reasons.append("The URL contains '@', which can hide the actual destination.")
        score += 2

    try:
        ipaddress.ip_address(host)
        reasons.append("The hostname is an IP address rather than a regular domain.")
        score += 2
    except ValueError:
        pass

    if len(url) > 75:
        reasons.append("The URL is unusually long.")
        score += 1

    if host.count("-") >= 2:
        reasons.append("The domain contains several hyphens.")
        score += 1

    if host.count(".") >= 4:
        reasons.append("The domain has many subdomain levels.")
        score += 1

    if re.search(r"%[0-9a-fA-F]{2}", url):
        reasons.append("The URL contains encoded characters.")
        score += 1

    found_words = sorted(word for word in SUSPICIOUS_WORDS if word in url.lower())
    if found_words:
        reasons.append("Contains words often seen in deceptive links: " + ", ".join(found_words) + ".")
        score += min(2, len(found_words))

    if score >= 5:
        level = "HIGH RISK"
    elif score >= 2:
        level = "CAUTION"
    else:
        level = "LOWER RISK SIGNALS"

    if not reasons:
        reasons.append("No listed warning signs were detected by these simple checks.")

    return {"score": score, "level": level, "reasons": reasons}

def main():
    print("=" * 46)
    print(" PhishGuard - Phishing URL Risk Checker")
    print("=" * 46)
    print("Enter a URL to inspect, or type 'quit' to exit.")
    print("Example: http://example.com/login/verify")
    while True:
        try:
            raw_url = input("\\nURL> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\\nExiting PhishGuard.")
            break
        if raw_url.lower() in {"quit", "exit", "q"}:
            print("Exiting PhishGuard.")
            break
        result = check_url(raw_url)
        print(f"\\nRisk result: {result['level']} (score: {result['score']})")
        for reason in result["reasons"]:
            print(f" - {reason}")
        print("Reminder: this is a heuristic demo, not a security guarantee.")

if __name__ == "__main__":
    main()
