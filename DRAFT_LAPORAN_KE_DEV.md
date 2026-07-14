# Draft Laporan Bug — AgentOn (agenton.me)

**Kepada:** Tim Dev AgentOn
**Dari:** RajinGarap (ethical hacker, disuruh tim dev untuk security test)
**Tanggal:** 14 Juli 2026
**Status:** Authorized black-box security assessment

---

Halo tim Dev AgentOn,

Sesuai permintaan, saya sudah melakukan security testing pada platform AgentOn (agenton.me). Berikut adalah ringkasan temuan bug yang saya temukan. Semua test dilakukan secara authorized dan tidak ada data pengguna yang dimodifikasi atau dieksfiltrasi.

## Ringkasan

| Severity | Jumlah | Item |
|---|---|---|
| 🔴 High | 1 | Stored XSS pada field `name` agent → berpotensi account takeover |
| 🟠 Medium | 1 | Agent spam tanpa login (CAPTCHA lemah + rate limit longgar) |
| 🟡 Low/Med | 3 | 500 error pada param invalid, CORS terlalu permisif, Reflected XSS potensial |
| ⚪ Low | 2 | Data disclosure tanpa auth, validasi `per_page` |
| ⚪ Info | 1 | robots.txt membocorkan struktur admin |

**Total: 8 temuan.** Tidak ditemukan Critical. Authz (IDOR/BAC), validasi withdrawal, dan SQL injection sudah aman.

---

## 🔴 HIGH — Stored XSS di field `name` agent (account takeover chain)

**Endpoint:** `POST /api/agents/register` → field `name`
**Auth:** Tidak perlu login

**Masalah:** Field `name` agent **disimpan tanpa sanitasi** dan direfleksikan utuh di response API. Dikombinasikan dengan:
- Token disimpan di `localStorage` (bukan httpOnly cookie), dan
- CAPTCHA bisa di-bypass + rate limit lemah,

...seorang attacker bisa **membuat agent tanpa login** dengan `name` berisi payload XSS, yang akan **mencuri token korban** saat halaman agent dibuka.

**Bukti (PoC yang saya jalankan):**
```
POST /api/agents/register
  {"name":"<script>alert(document.cookie)</script>","description":"xss_poc"}
# solve CAPTCHA (NLP) → verify → 200
# GET /api/agents/me dengan api_key agent baru:
# {"name":"<script>alert(document.cookie)</script>", ...}  ← payload tersimpan utuh
```

**Dampak:** Token theft → account takeover (withdraw ilegal, impersonasi, akses admin).

**Rekomendasi Fix:**
1. Sanitasi input `name`/`description` di server (tolak `< > " '`).
2. Jangan render `name` via `innerHTML`/`dangerouslySetInnerHTML` di client.
3. Gabung dengan fix CORS (pakai httpOnly cookie atau `Allow-Origin` spesifik) untuk memutus chain.

---

## 🟠 MEDIUM — Agent Spam tanpa Login

**Endpoint:** `POST /api/agents/register` → `/verify`
**Masalah:** CAPTCHA berupa soal matematika natural-language mudah di-solve script. Rate limit hanya 2/menit (naik 5/jam setelah 1 sukses) — cuma memperlambat, tidak mencegah.

**Bukti:** Saya berhasil membuat agent terverifikasi tanpa login menggunakan solver NLP.

**Rekomendasi:** Ganti CAPTCHA dengan hCaptcha/reCAPTCHA + rate limit per-IP & per-device + verifikasi email/Discord wajib.

---

## 🟡 LOW/MEDIUM — Lainnya

1. **500 error pada `page`/`per_page` negatif** (`?page=0`, `?per_page=-5`) → seharusnya 422.
2. **CORS `Allow-Origin: *`** + `allow-headers: authorization` → bahaya jika ada XSS (token di localStorage).
3. **Reflected param `period`** di `/api/agents/leaderboard` → XSS jika dirender polos di client.

## ⚪ LOW — Lainnya

4. **Data disclosure tanpa auth:** `/api/platform/overview`, `/api/tokens`, `/api/quests` membuang data publik (low risk).
5. **`per_page` gak divalidasi:** terima nilai gila (99999999).

## ⚪ INFO

6. **robots.txt** membocorkan `/admin`, `/merchant`, `/agent/dashboard`, `/api/`.

---

## Prioritas Fix

1. **URGENT:** Fix #1 (Stored XSS) + CORS bersamaan — ini chain account takeover.
2. Fix #2 (validasi page/per_page).
3. Perketat #3 (rate limit + CAPTCHA nyata).
4. Sanitasi #4 (allowlist `period`) + rate-limit data publik.

---

Laporan lengkap dengan PoC teknis ada di file terlampir (AgentOn_bug_report.md). Saya siap bantu verifikasi fix jika diperlukan.

Terima kasih,
RajinGarap
