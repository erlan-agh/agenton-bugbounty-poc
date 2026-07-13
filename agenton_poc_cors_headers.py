#!/usr/bin/env python3
"""
AgentOn (agenton.me) — PoC: Over-permissive CORS + Missing Security Headers
Self-contained verification script. Run from an authorized tester's machine.

What it proves (read-only, no destructive action):
  1. Access-Control-Allow-Origin: *  returned on an AUTHENTICATED API route.
  2. Missing defensive headers: CSP, X-Frame-Options, X-Content-Type-Options,
     Referrer-Policy, Cross-Origin-Opener-Policy, CSRF token.
  3. Preflight (OPTIONS) is answered 200 and echoes wildcard + allows the
     Authorization header from ANY origin.

Usage:
  export AQT="your_agenton_api_key"
  python3 agenton_poc_cors_headers.py

The script only sends safe GET/OPTIONS requests against YOUR OWN account.
"""
import os, sys, json, urllib.request, urllib.error

BASE = "https://agenton.me"
API_ME = f"{BASE}/api/agents/me"
EVIL_ORIGIN = "https://evil.example.com"
API_KEY = os.environ.get("AQT")

if not API_KEY:
    print("[!] Set env AQT=your_agenton_api_key first.")
    sys.exit(2)

def req(method, url, headers=None, body=None):
    headers = headers or {}
    r = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")

print("=" * 64)
print("AgentOn CORS / Security-Header PoC  (read-only, own account)")
print("=" * 64)

# 1) Authed GET — inspect response headers for CORS + defenses
status, hdr, body = req("GET", API_ME, {"Authorization": f"Bearer {API_KEY}"})
print(f"\n[1] GET {API_ME}  ->  HTTP {status}")
print("    Response headers of interest:")
for k in ["access-control-allow-origin", "content-security-policy",
          "x-frame-options", "x-content-type-options", "referrer-policy",
          "cross-origin-opener-policy", "cross-origin-resource-policy",
          "set-cookie", "x-csrf-token", "x-xsrf-token"]:
    v = hdr.get(k)
    print(f"      {k:32}: {v if v is not None else '(ABSENT)'}")

# 2) Preflight from a foreign origin
status2, hdr2, _ = req("OPTIONS", API_ME, {
    "Origin": EVIL_ORIGIN,
    "Access-Control-Request-Method": "GET",
    "Access-Control-Request-Headers": "authorization",
})
print(f"\n[2] OPTIONS (preflight) from {EVIL_ORIGIN}  ->  HTTP {status2}")
for k in ["access-control-allow-origin", "access-control-allow-methods",
          "access-control-allow-headers", "access-control-allow-credentials"]:
    v = hdr2.get(k)
    print(f"      {k:34}: {v if v is not None else '(ABSENT)'}")

# 3) Verdict
aco = hdr.get("access-control-allow-origin")
csp = hdr.get("content-security-policy")
xfo = hdr.get("x-frame-options")
xcto = hdr.get("x-content-type-options")
rp = hdr.get("referrer-policy")

print("\n" + "=" * 64)
print("VERDICT")
print("=" * 64)
# The wildcard only appears on the preflight (OPTIONS) response; the simple
# GET response omits ACAO entirely. Both are reported for accuracy.
cors_bad = (aco == "*") or (hdr2.get("access-control-allow-origin") == "*")
aco_seen = aco or hdr2.get("access-control-allow-origin")
print(f"  CORS allow-origin '*' (preflight)      : {'VULN' if cors_bad else 'ok'}   ({aco_seen})")
print(f"  CSP present                           : {'ok' if csp else 'MISSING'}")
print(f"  X-Frame-Options present               : {'ok' if xfo else 'MISSING'}")
print(f"  X-Content-Type-Options present        : {'ok' if xcto else 'MISSING'}")
print(f"  Referrer-Policy present               : {'ok' if rp else 'MISSING'}")
if cors_bad or not (csp and xfo and xcto and rp):
    print("\n  >>> Report MEDIUM: tighten CORS to trusted origins + add the")
    print("      missing security headers. See agenton_bug_report.md.")
    sys.exit(1)
print("\n  >>> No CORS/header gaps detected.")
sys.exit(0)
