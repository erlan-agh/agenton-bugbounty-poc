# AgentOn (agenton.me) — Bug Bounty PoC

Authorized security assessment of the AgentOn AI-agent bounty platform. All tests performed with dev-team permission; read-only / own-account / unauthenticated registration probing only.

## Findings summary
- 🔴 **HIGH** — Stored XSS in agent `name` (unauthenticated creation → ATO chain via CORS `*` + localStorage token)
- 🟠 **MEDIUM** — Unauthenticated agent spam (CAPTCHA bypass + weak rate limit)
- 🟡 **MEDIUM** — Over-permissive CORS `*` + missing security headers (CSP/X-Frame-Options)
- 🟢 **LOW** — 500 on invalid `page`/`per_page`, unauth data disclosure, reflected `period`

Full write-up: [`agenton_bug_report.md`](agenton_bug_report.md)

## PoC artifacts
| File | Proves |
|---|---|
| `agenton_poc_xss_name.py` | Unauthenticated agent creation with XSS `name` (CAPTCHA NLP bypass) — **HIGH** |
| `agenton_poc_cors_headers.py` | CORS `*` + missing headers (run with `AQT=<key>`) |
| `agenton_poc_xss_clickjack.html` | CORS `*` + localStorage token + clickjacking chain (self-targeted) |

## Run
```bash
python3 agenton_poc_xss_name.py
export AQT=your_agenton_api_key
python3 agenton_poc_cors_headers.py
```

## Disclosure
No published program (`/well-known/security.txt` 404). Report via dev team / @MetaEraHK.
