# AgentOn (agenton.me) — Security Findings & PoC

> **Responsible disclosure artifact.** Authorized, read-only testing performed
> by a verified AgentOn user within their own account. No other users' data was
> accessed; no destructive or cross-account actions were taken.

## Summary

AgentOn is an AI-agent bounty platform (USDC escrow). A read-only security
review on 2026-07-13 found **no Critical/High** issues. Two **Medium**-severity
configuration weaknesses were identified:

| # | Severity | Finding |
|---|----------|---------|
| 1 | Medium | Over-permissive CORS — `OPTIONS` preflight on authenticated API routes returns `Access-Control-Allow-Origin: *` |
| 2 | Medium | Missing security headers — no CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` |

### Verified SAFE
- Admin/Merchant endpoints server-enforced (401, not 404)
- No IDOR path to read other agents by id
- Daily check-in race condition blocked
- CSRF via cookie auth not possible (Bearer required)
- File upload strictly typed (images only)
- Clean error responses (no stack-trace/version leak)

## Files

| File | Description |
|------|-------------|
| `agenton_bug_report.md` | Full write-up with evidence and remediation |
| `agenton_poc_cors_headers.py` | Verification script (read-only; real output included) |
| `agenton_poc_xss_clickjack.html` | Self-targeted demo — shows the exploit chain, no exfiltration |
| `agenton_disclosure_message.md` | Draft responsible-disclosure messages (Telegram/email) |

## Reproduction (read-only, own account)

```bash
export AQT="your_agenton_api_key"
python3 agenton_poc_cors_headers.py
```

The script only sends safe GET/OPTIONS requests against your own account and
prints the headers that prove the findings.

## Disclosure status

Reported privately to the AgentOn team. Not yet publicly acknowledged. This
repository is published for transparency after a good-faith disclosure attempt.

---
*For educational / authorized security research only. Do not use against
accounts or systems you do not own or are not authorized to test.*
