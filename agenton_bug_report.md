# AgentOn (agenton.me) — Bug Bounty Recon & Hunt Report

**Target:** https://agenton.me (AI agent bounty platform, USDC escrow)
**Tester:** nalreee_Airdrop_4 (authorized account owner — testing within own account only)
**Date:** 2026-07-13
**Scope:** Passive recon + authorized self-account testing. No cross-account data access, no destructive actions.

---

## TL;DR — Platform is reasonably hardened
Server-side authz is solid: admin/merchant endpoints return **401** (not 404) when hit with an agent key, IDOR paths don't exist, race condition on check-in is blocked, file upload is strictly typed. **No critical/high found.** Main gaps are **missing security headers** and **over-permissive CORS `*`** — low/medium, easy fixes.

---

## What I did (recon)
- Tech: nginx, Vite SPA, axios (API at `https://agenton.me/api`, Bearer auth).
- `robots.txt` leaks internal paths: `/admin`, `/merchant`, `/agent/dashboard`, `/api/`.
- **`/llms.txt` is a full public API doc** — exposes every endpoint + register/withdraw flow. Great for hunters, but also for attackers (informational).
- `dev.agenton.me` serves identical static shell (likely mirror, not a live dev app).
- JS bundle: tokens stored in `localStorage` (`admin_token`, `agent_key`, `merchant_key`); request interceptor picks token by URL prefix (`/admin` → admin_token). Frontend route guard `requiresAdmin` is client-side only.

## Findings

### 🟡 MEDIUM-1 — Over-permissive CORS (`Access-Control-Allow-Origin: *`) on authed API
**Evidence (from PoC, 2026-07-13):**
- Simple `GET /api/agents/me` → response does **NOT** include `Access-Control-Allow-Origin` at all.
- `OPTIONS` preflight (from `https://evil.example.com`) → `HTTP 200` with:
  - `access-control-allow-origin: *`
  - `access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT`
  - `access-control-allow-headers: authorization`
  - (no `access-control-allow-credentials`)
**Impact:** The wildcard on the preflight means the browser will permit a cross-origin script (any origin) to issue authed requests carrying the `Authorization` header. It is **not** directly exploitable for silent data theft (no `allow-credentials`, token lives in `localStorage` so it is not auto-attached, and SOP still blocks reading the response without credentials) — but it strips a defense-in-depth layer and is incorrect for an authenticated API. Combined with the missing CSP + localStorage token (MEDIUM-2), any stored XSS becomes a full token-theft/ATO chain.
**Exploitability:** Low on its own (needs a token-leak/XSS first). **Fix:** restrict `allow-origin` to trusted origins (`agenton.me`, `app.agenton.me`, dashboard); never return `*` for authenticated routes.

### 🟡 MEDIUM-2 — Missing security headers
**Evidence:** No `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, or `Referrer-Policy` on app or API responses.
**Impact:**
- No CSP → if any stored XSS exists (e.g. submission/forum content rendered via `innerHTML`/`v-html`), it runs unblocked.
- No `X-Frame-Options` → clickjacking possible on dashboard/agent pages.
- Tokens in `localStorage` (not httpOnly) → any XSS = full token theft + account takeover.
**Fix:** Add CSP, `X-Frame-Options: DENY` (or `frame-ancestors 'self'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`. Consider moving tokens to httpOnly+Secure cookies + CSRF token.

### 🟢 LOW — Public submission content may be rendered unescaped (stored-XSS hypothesis, UNVERIFIED)
**Evidence:** `/api/quests/{id}/submissions` returns `content` verbatim (newlines/special chars preserved); API does not strip HTML. Could not confirm XSS without rendering in a browser (did not inject into production).
**Impact (if dashboard/admin uses raw HTML rendering):** stored XSS → token theft via localStorage.
**Verify:** render a submission containing `<img src=x onerror=alert(1)>` in the agent/admin dashboard. If it fires, it's stored XSS.

### 🟢 LOW — Informational: `llms.txt` full API disclosure
**Evidence:** `https://agenton.me/llms.txt` documents all endpoints, register handshake, wallet-binding, check-in payout schedule.
**Impact:** Eases attacker recon. Intended for MCP agents, but should be considered part of attack surface.

---

## Verified SAFE (no bug)
| Test | Result |
|---|---|
| Admin/merchant endpoint with agent key | 401 (server-enforced) ✅ |
| IDOR (read other agent by id) | 404 (no such path) ✅ |
| Race condition on daily check-in | `Already checked in today` — no double payout ✅ |
| CSRF via cookie auth | 401 without Bearer — cookie auth not used ✅ |
| File upload type restriction | rejects non-images (`text/plain` blocked) ✅ |
| Error handling | clean JSON, no stack-trace/version leak ✅ |

---

## Recommended next steps (for you / disclosure)
1. **Fix CORS `*` → whitelist** (MEDIUM).
2. **Add security headers + move tokens to httpOnly cookies + CSRF token** (MEDIUM).
3. **Confirm stored-XSS hypothesis** in dashboard rendering (LOW, needs browser test).
4. Optionally scope `llms.txt` or note it as known attack surface.

## Notes
- All testing was read-only / within my own account. No other users' data was accessed.
- API key was used only from this session's environment, never printed or logged.
- To report officially, check `https://agenton.me/.well-known/security.txt` (currently 404 — they may not have a published program; reach out via their team / @MetaEraHK).
