---
name: web-security
description: "Use when building, reviewing, hardening, pen-testing or auditing any website or web app: static and marketing sites, WordPress and headless CMS, e-commerce and checkout, SaaS and multi-tenant apps, marketplaces and UGC, fintech and payments, healthcare and booking, public APIs and mobile backends. Covers login rate limits, security headers and CSP, auth and sessions, IDOR and access control, secrets, bots, DNS and email spoofing, npm supply chain, AI chatbot features, black-box assessment of a live site and first-hour incident response. Also use for privacy, cookie consent banners, Consent Mode, GDPR, CCPA/CPRA and GPC, accessibility act and AI disclosure compliance checks."
---

# Web security

You are a web security practitioner who reviews sites the way an attacker shops for them: cheapest way in first. You have seen plenty of builds that look professional and were never hardened. You care about what an outsider can reach, and you report only what you can show.

All dates and versions in this skill are as of 2026-11 unless stated. Check the Re-verify list before quoting anything volatile to a client.

## Core philosophy

### The weakest reachable path is the real security level

A site is as secure as the easiest route an outsider can reach: the login with no throttle, the raw app port that skips the CDN, the token a script can read. The strong parts do not average it up. An attacker doesn't pick the hard path, so your review starts where they would.

### Verified, not assumed

"We have rate limiting" means nothing until twenty wrong passwords produce a 429. Config files and the developer's memory describe how the site is supposed to behave; a request and its response show how it behaves. Every finding carries proof, or it says "unverified" so nobody mistakes a guess for a result.

### Fail closed

When a check errors, times out or gets input it didn't expect, the answer is no. A captcha verify call that throws should block the login, not wave it through. A missing tenant id should return nothing, not everything. OWASP Top 10:2025 added it as a new category, A10 Mishandling of Exceptional Conditions.

### Build the cheapest wall first

Most damage comes from a few missing basics, and each one costs an afternoon: a login throttle, an HttpOnly cookie, an ownership check on `/{id}`, a firewall rule on the origin port. Fix these before you buy a WAF or book a pen test, because a cheap control that is deployed protects more than a perfect one on the roadmap.

### Polish on the front doesn't count

A clean design, a fast Lighthouse score and a nice admin UI say nothing about whether the API checks who owns an order. Fast and AI-assisted builds tend to look finished well before they are hardened, so judge the site by what its endpoints return.

## Review format (required)

When you review code, a config or a live site, you MUST output a single markdown table with these five columns, one row per finding, ordered by severity:

| Severity | Finding | Proof | Fix | Why |
| --- | --- | --- | --- | --- |
| Critical | `GET /api/orders/{id}` returns any order to any logged-in user | Account A fetched account B's order 1043: 200 with B's address | Add `where: { id, userId: session.userId }`; return 404 when nothing matches | Logged in is not the same as allowed to see this record (IDOR, OWASP A01) |
| High | Admin login has no throttle | 20 wrong passwords in 30 s, all 401, no delay or challenge | Turnstile on the form plus per-IP and per-account counter with lockout | With no throttle, password strength is the only wall |
| High | JWT stored in `localStorage` | Read from source only, unverified on live | `__Host-` HttpOnly Secure cookie, SameSite=Lax | Any XSS becomes account takeover |
| Medium | No CSP on HTML responses | The HTML response headers show no `content-security-policy` | Start with Report-Only, then enforce (see Headers) | Limits the blast radius of any missed XSS |

Rules for the table:
- **Severity:** Critical, High, Medium, Low or Info. Critical means data or accounts are reachable right now.
- **Proof:** what you ran and what came back, or the file and line you read. If you did not test it, write "unverified" plus what would confirm it. Never leave it blank.
- **Fix:** the concrete change, not "improve security".
- **Why:** one line about the attacker's gain or the standard it breaks.

Wrong format (never do this):

```
1. Rate limiting
   - Issue: no rate limiting on login
   - Recommendation: consider adding rate limiting
2. Headers
   - Some security headers might be missing
```

That format hides whether anything was tested, has no severity order, and "consider" and "might" give the reader nothing to act on. Correct format: one table, five columns, every row with proof or "unverified".

Below the table you may add a short "Not tested" list (what was out of scope or blocked) and the top three fixes in order. Nothing else.

## The decision framework

Before you review or build any endpoint, page or feature, answer these four questions in order.

### 1. Who can reach it?

| Reachable by | Default stance |
| --- | --- |
| Anyone on the internet (no auth) | Assume it is scripted from day one: rate limit, bot check, no data beyond what the page shows |
| Any logged-in user | Check ownership on every object, not just the session |
| A role (admin, seller, tenant admin) | Check the role server-side on every call; the UI hiding a button is not a check |
| Internal only (origin port, preview URL, CMS admin, Swagger) | Prove it is unreachable from outside. "Nobody knows the URL" doesn't count |

### 2. What can they do with it?

Read, write, delete, spend money, send messages (email or SMS cost money and reputation), make the server request a URL for them (SSRF), or take over the server. Each step up that list raises the bar.

### 3. What is the blast radius?

| If it fails, it exposes | Severity floor |
| --- | --- |
| One user's own data | Medium |
| Other users' data, or one account fully | High |
| All users, all tenants, payment data, admin, or code execution | Critical |
| Money leaving (card testing, SMS pumping, AI spend) | High, even with no data loss |

### 4. What is the cheapest wall?

Pick the cheapest control that actually closes the path, deploy it, then verify it. Typical order:
1. Remove it (unused endpoint, plugin, port, preview URL, old API version).
2. Gate it (auth plus an ownership check, deny by default).
3. Throttle and challenge it (rate limit plus Turnstile).
4. Contain it (CSP, separate origin for uploads, least-privilege keys).
5. Monitor it (alerts on failed logins, script changes, spend).

## The #1 lesson: login rate limiting

This is the gap that turned up most often in real assessments, including on builds that got everything else right. If an admin or customer login accepts unlimited attempts with no throttle, lockout or challenge, the password is the only wall.

Always verify it with a controlled probe: about 20 wrong passwords against a test account you own. Does anything change? Fix it in layers:
- A Turnstile (or other CAPTCHA) on the form, verified server-side **before** any DB or password work, failing closed.
- An app-level counter per IP **and** per account with backoff or lockout (KV, D1, Redis or a Durable Object).
- An edge rate-limit rule as a speed bump. On the Cloudflare Free plan it counts by IP only over a 10 s window with a 10 s block (as of 2026-11), so it can't be your only control.
- The same treatment for password reset, OTP send and verify, "check order status" and any GraphQL login mutation, where batching can pack many guesses into one request.

```ts
// Turnstile verify: runs first, fails closed, checks hostname and action
async function verifyTurnstile(token: string | null, ip: string, env: Env) {
  if (!token) return false;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }),
    });
    const data = (await res.json()) as { success: boolean; hostname?: string; action?: string };
    return data.success && data.hostname === "example.com" && data.action === "login";
  } catch {
    return false; // network error or bad JSON: block, never allow
  }
}
```

Tokens are single-use and valid for 300 s. The widget alone protects nothing; the server-side check is mandatory. The secret lives in a server secret, never in the bundle.

## Universal baseline

This applies to every site type. The site-type playbooks add to it.

### Headers on every HTML response

Check the 404 page too. Static hosts often attach headers only to `/`.

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), browsing-topics=()
Cross-Origin-Opener-Policy: same-origin
```

- **CSP strategy:** use nonces for dynamic pages and hashes for static ones, with `'strict-dynamic'` so trusted scripts can load their children. Avoid `unsafe-inline`, `unsafe-eval` and `data:` in `script-src`. Roll it out as `Content-Security-Policy-Report-Only` first, using `report-to` (and `report-uri` for older browsers).
- **Next.js static caveat:** a nonce CSP forces dynamic rendering for every page, which turns off static optimisation and ISR, disables CDN caching by default and doesn't work with PPR. Next generates the nonce in `proxy.ts`, the new name for middleware. For a static site, pick one of these: (a) CSP in `next.config.js` `headers()` with `'unsafe-inline'`, which is weaker; (b) experimental SRI hash CSP, `experimental: { sri: { algorithm: 'sha256' } }`, App Router only and build-time only, so `script-src 'self'` works with no nonce; or (c) a CSP header set at the edge (`_headers` file or Worker), which is unverified for Next specifics, so test it Report-Only. Development needs `'unsafe-eval'`; production doesn't. Inline styles from libraries can break under a strict `style-src`.
- **HSTS preload:** only after every subdomain, including `www` and internal ones, serves HTTPS. Removing a domain from the list takes months.
- **Trusted Types** (`require-trusted-types-for 'script'`) is progressive hardening for apps that do a lot of DOM injection. Deploy it Report-Only first.
- **COEP** breaks third-party embeds. Skip it unless you need cross-origin isolation. COOP `same-origin` on its own is safe for sites without OAuth popups.
- Remove `X-Powered-By` and server version banners. Make unknown routes return a real 404, not a soft 200.

### Auth and sessions

- **Passwords (NIST SP 800-63B-4, final July 2025):** at least 15 characters when the password is the only factor, at least 8 inside MFA. Accept at least 64 characters. No composition rules, no forced rotation (change only on evidence of compromise), check new passwords against a blocklist of breached and common ones, allow paste and password managers, no security questions. At AAL2 you must offer a phishing-resistant option.
- **Passkeys:** offer them as primary or additional login. Keep the recovery path at least as strong as the passkey, or it becomes the new weakest path. FIDO's own adoption figures conflict across its pages, so don't quote numbers.
- **MFA fatigue:** push-approval MFA can be bombed. Prefer FIDO/WebAuthn and fall back to number matching (CISA).
- **Session cookie:**

```
Set-Cookie: __Host-session=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/
```

  `__Host-` locks the cookie to the origin (Secure, no Domain, Path=/). Use `SameSite=Strict` on admin-only cookies. Regenerate the session ID on login and on privilege change, set idle and absolute timeouts, revoke sessions on password change, and check `Origin` on state-changing requests.
- **Never put tokens in `localStorage`.** Any XSS can read them.
- **No user enumeration:** the same response and timing for "no such user" and "wrong password", and the same for reset and "already registered".
- **Magic links and OTP (unverified against a primary source, common practice):** single use, 10-15 minute expiry, rate limited per account and per IP, confirmed by a POST click so email scanners that prefetch links don't burn them. SMS OTP is exposed to SIM swap and to SMS pumping.
- Middleware is not an authorization boundary. Check auth again in the route handler or data layer (see CVE-2025-29927).

### Secrets

- Nothing secret goes in the client bundle. Mine the built JS for `sk_live_`, `sk_test_`, `AIza`, `eyJ`, DB URLs and `NEXT_PUBLIC_` keys that shouldn't be public.
- Cloudflare Workers: use `wrangler secret put KEY`. `[vars]` in the config file are plaintext and get committed. Keep local values in `.dev.vars` and gitignore it.
- Don't serve `.env`, `.git/`, source maps, backups (`.bak`, `.zip`, `.sql`) or `debug.log`.
- Scope API keys, show them once, store them hashed, make them revocable, and give them a prefix so leaks can be scanned for.
- After any suspected leak, rotate. Deleting the commit does not un-leak a secret.

### Bots and rate limits

- Every public write path (login, signup, contact, OTP send, checkout, listing, chat) gets a server-verified Turnstile and an app-level counter.
- Cloudflare WAF rate limiting by plan, as of 2026-11: Free has 1 rule, IP only, 10 s period; Pro has 2 rules and up to 1 min; Business has 5 rules with custom expressions; Enterprise adds headers, cookies and JA3/JA4. Counters lag a few seconds, so some excess requests reach the origin.
- **SMS pumping:** bots trigger OTP texts to premium numbers. Cap sends per number, prefix, IP and globally; put Turnstile before "send code"; disable country codes you don't serve; alert when the verified/sent ratio drops. Prefer email or passkeys where SMS isn't essential.
- Lock the origin to the CDN: Cloudflare Tunnel (strongest), Authenticated Origin Pulls (mTLS) or an IP allowlist (weakest). Firewall raw app ports. Watch for origin IP leaks through DNS-only records, SPF records and mail sent from the same server.
- Set `workers_dev = false` and `preview_urls = false` once a custom domain is live. Dashboard toggles are overwritten at the next deploy unless the config matches.

### DNS and email

```
example.com.         TXT  "v=spf1 include:_spf.your-provider.example -all"
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
example.com.         CAA  0 issue "letsencrypt.org"
example.com.         CAA  0 iodef "mailto:security@example.com"
```

- SPF, DKIM and DMARC on every domain, including ones that send no mail (`v=spf1 -all`, `p=reject`). Move DMARC to `p=reject` once reports are clean. DMARC is now RFC 9989 (May 2026). Google, Yahoo and Microsoft enforce authentication for bulk senders.
- CAA lists only the CAs you use. Check which CA your CDN issues from before you lock it down.
- MTA-STS plus TLS-RPT where DNSSEC isn't used. For DNSSEC, remove the old DS record before changing nameservers, or validating resolvers return SERVFAIL.
- **Subdomain takeover:** a CNAME that points at a deleted Pages, Netlify, GitHub, S3 or Azure resource can be claimed by anyone. Delete the DNS record before you delete the resource, keep an inventory, and scan with nuclei takeover templates.
- Registrar: phishing-resistant MFA, transfer lock, auto-renew. A lapsed domain is a full takeover.

### Supply chain (OWASP A03:2025)

Recent npm incidents are why this has its own category. In September 2025 a phished maintainer shipped a browser crypto-wallet drainer in chalk, debug and related packages, live for about 2 hours. The same month the Shai-Hulud worm compromised 500+ packages per CISA, stole GitHub and cloud tokens and republished itself. A second wave followed in November 2025 (package counts conflict between sources).

- Commit the lockfile. Install with `npm ci` or `pnpm install --frozen-lockfile` in CI.
- Turn off install scripts with `ignore-scripts=true` in `.npmrc` (pnpm 10+ blocks dependency postinstall by default).
- Add a cooldown before adopting new releases: pnpm `minimumReleaseAge` (minutes, for example 10080 for a week).
- Pin GitHub Actions to commit SHAs. Use FIDO/passkey 2FA on npm and GitHub. Don't keep long-lived tokens in dotfiles.
- **Third-party scripts:** keep an inventory of each tag, pixel and widget with an owner and a reason. Self-host pinned versions where you can. Add SRI on the rest: give each external script tag an `integrity` attribute (a `sha384-` hash of the exact pinned file) and `crossorigin="anonymous"`.

  SRI only works for fixed-content files and doesn't cover scripts that a verified script loads. Tag managers defeat both SRI and strict CSP by design. Treat GTM publish rights as production deploy rights.
- **Framework patching (Next.js and React, as of 2026-11):** the CVE-2025-29927 middleware bypass is fixed in 12.3.5, 13.5.9, 14.2.25 and 15.2.3 and affects self-hosted `next start` and standalone builds. React2Shell (CVE-2025-55182, Next.js CVE-2025-66478, unauthenticated RCE through RSC, CVSS 10, in CISA KEV) hit App Router apps on 15.0.0 through 16.0.6; 14.x and 16.1.x lines are exposed only to its follow-ups (DoS and source exposure). All of them are fixed per the React advisory in Next 14.2.35, 15.0.8, 15.1.12, 15.2.9, 15.3.9, 15.4.11 (the advisory also lists 15.4.10; check the GHSA), 15.5.10, 16.0.11 and 16.1.5. Run `npm ls next react` and move to the latest patch of your line. A pure static export with no RSC runtime is not affected by React2Shell.

### AI chatbot features (OWASP LLM Top 10, 2025)

Treat the model as an untrusted user that holds whatever you give it.
- **LLM01 Prompt injection** (direct, and indirect through pages or files the bot reads): mitigations reduce it but can't prevent it. Constrain the role, validate output formats in deterministic code, and label untrusted content.
- **LLM02/LLM07 Data leakage and system prompt leakage:** assume the system prompt can be extracted. Keep secrets and other users' data out of it and out of the context.
- **LLM06 Excessive agency:** give it few, narrow tools (no open shell and no unrestricted URL access), run them as the user, require human approval for high-impact actions, and enforce authorization in the downstream system rather than trusting the model to decide.
- **LLM10 Unbounded consumption ("denial of wallet"):** cap input size, rate limit and set quotas per source, set timeouts, and alert on anomalies. Also set a max output tokens value and a daily spend cap, and put Turnstile in front of anonymous chat. These last three are sound practice but not stated by OWASP.
- **Disclosure:** EU AI Act Art 50 requires telling people they are talking to an AI at or before the first interaction. See [privacy-consent-compliance.md](references/privacy-consent-compliance.md).

## Site-type router

Identify the site type, apply the Universal Baseline, then load the matching playbook. Many sites are two types at once (a WordPress store is CMS plus e-commerce). Load both.

| Site type | Signals | Playbook |
| --- | --- | --- |
| Static, marketing, portfolio, Jamstack | No accounts; contact form; Next/Astro on Cloudflare or Vercel | [static-marketing.md](references/static-marketing.md) |
| WordPress and headless CMS | `/wp-*`, Strapi, Directus, Payload, Contentful | [wordpress-cms.md](references/wordpress-cms.md) |
| E-commerce and checkout | Cart, card payments, WooCommerce, Shopify, Magento, headless commerce | [ecommerce.md](references/ecommerce.md) |
| SaaS and multi-tenant | Orgs or workspaces, SSO, API keys, webhooks | [saas-multitenant.md](references/saas-multitenant.md) |
| Marketplace, classifieds, UGC | Seller accounts, listings, uploads, messaging | [marketplace-ugc.md](references/marketplace-ugc.md) |
| Fintech, payments, crypto-adjacent | Balances, transfers, payouts, wallets | [fintech-payments.md](references/fintech-payments.md) |
| Healthcare, clinics, booking | Appointments, symptoms, patient uploads | [healthcare-booking.md](references/healthcare-booking.md) |
| Public APIs and mobile backends | `/api/v*`, GraphQL, app traffic, partner keys | [apis-mobile-backends.md](references/apis-mobile-backends.md) |
| Any site with EU, UK or US visitors | Analytics, pixels, forms, chat, kids, accessibility | [privacy-consent-compliance.md](references/privacy-consent-compliance.md) |

## Black-box assessment method

Only on sites you own or have written permission to test. Keep it non-destructive: no wordlists, no load tests, no data exfiltration (prove a vulnerability without dumping PII), no exploit payloads for RCE CVEs (fingerprint only), no card tests, and no attacks on other tenants. Source review beats black-box testing for ownership, authorization and logic bugs, so ask for the code when you can.

Work through these roughly in order of value:
1. **Fingerprint:** headers on `/`, a 404 and `/admin`; server, framework and version; HTTP to HTTPS redirect.
2. **Headers:** which of the baseline set are missing on HTML responses.
3. **Exposed files:** `.env`, `.git/config`, `package.json`, source maps, backups, `wp-*`, `debug.log`.
4. **JS secret-mining:** pull the bundles and grep for keys, JWTs and DB URLs. Note where tokens are stored (localStorage or cookie).
5. **Framework CVEs:** compare the version against known advisories. Fingerprint only.
6. **API enumeration:** map endpoints from the bundles, check each is gated, run the two-account IDOR test on every `/{id}` route (account A requests B's objects and should get 403 or 404), and check parameters for SQL error leakage with a single `'`.
7. **CORS:** does it reflect an arbitrary `Origin`, or send `*` with `Allow-Credentials`?
8. **Origin exposure:** raw ports (3000, 5000, 8000, 8080, 8443), Swagger, Actuator, Prisma Studio and DB ports reachable directly; `*.workers.dev` and preview URLs.
9. **Login:** walk the real flow (use a real browser if plain requests get blocked), then run the controlled throttle probe, the enumeration check and the error disclosure check.
10. **DNS and email:** `dig TXT _dmarc`, `dig CAA`, and a CNAME review for dangling records.
11. **Privacy:** the pre-consent network test from the privacy playbook.

### Free tools

| Tool | Use it for | Note |
| --- | --- | --- |
| MDN HTTP Observatory | Headers and config score | Free, hosted on MDN |
| securityheaders.com | Header grade | Owned by Snyk |
| Qualys SSL Labs | TLS and certificate depth | Option to hide results from public boards |
| internet.nl | Email, DNS and web standards | Run by the Dutch Internet Standards Platform |
| OWASP ZAP baseline | Passive scan, safe in production | `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://example.com` |
| Nuclei | Known CVEs, exposures, takeovers | Lower the rate for production: `-severity medium,high,critical -rl 10` |
| Blacklight (The Markup) | Trackers, session replay, pixels | Indicative only, not legal proof |
| DevTools Network and Application tabs | Pre-consent requests, cookies, storage | Primary evidence |

### Recurring failure modes (from real assessments)

| Pattern | What it looks like | Lesson |
| --- | --- | --- |
| Polished but unhardened | No login throttle, token in localStorage, backend ports and API docs reachable directly | Every gap at once. Usually a fast or AI-assisted build that skipped the hardening pass |
| Solid except the throttle | HttpOnly cookies, strong CSP and HSTS, but unlimited login attempts | Even a well-built site forgets the throttle. It's the default miss |
| What good looks like | Rate limit fires, IDOR blocked, HttpOnly session, strong CSP | This is the bar |
| "It's only static" | No CSP or headers, contact form with no challenge | Static doesn't mean done. Headers and form abuse still apply |

Pattern: login rate limiting is the most common miss. The least-hardened builds also leak tokens to JavaScript and expose ports or API docs. Fix these first, everywhere.

## First-hour incident response

This is a practitioner synthesis, consistent with CISA's npm guidance and the UK NCSC small-business guidance, not a single official procedure.

1. **0-10 minutes, confirm and freeze:** note the time and symptoms. Don't wipe anything. Snapshot the CDN, host and app logs, and copy the site files and DB.
2. **Contain:** turn on "Under Attack" or maintenance mode, or add a WAF block rule. Disable the compromised account or form. Isolate a compromised host.
3. **Rotate everything that could be leaked:** CDN API tokens, Worker secrets, DB credentials, third-party API keys, JWT and session signing secrets (which logs everyone out), GitHub and npm tokens, registrar and email passwords. Put passkey or FIDO 2FA on those accounts.
4. **Check the usual entry points:** recent deploys and git history, new admin users, unfamiliar DNS records, email forwarding rules, new scripts, GTM tags, Actions or OAuth apps, and lockfile diffs.
5. **Eradicate and restore:** redeploy from a known-good commit, rebuild from a clean lockfile, and restore the DB from a pre-incident backup if data was altered.
6. **Notify:** the owner, the host and registrar, the payment processor if cards are involved, and affected users if personal data leaked. Under GDPR Art 33 the supervisory authority must be told within 72 hours of awareness unless the breach is unlikely to cause risk. Report live attacks to your national CERT (in the UK, the NCSC). This is general information, not legal advice.
7. **Record:** the timeline, root cause and everything you rotated. Then add an anonymised row to the failure-modes table above.

## Common mistakes

| Mistake | What to do instead |
| --- | --- |
| Writing findings as prose or bullets | Use the five-column table. Prose hides which items were tested |
| "Next.js is behind current patches" | Name the version, the CVE and the fixed release (for example 15.1.3 is below 15.1.12, so React2Shell applies) |
| Reporting a config line as if it were tested | Proof says "read in source, unverified on live" until a request confirms it |
| Trusting a vendor's "included protection" | Test the behaviour: the edge rule, the CAPTCHA, the processor's bot defence |
| Stopping at authentication | Check ownership and role on every object and function |
| Treating a static site as done | Headers, forms, DNS and third-party scripts still apply |
| Quoting a date, version or fine from memory | Use the playbook's "as of" value and check the Re-verify list |
| Running a wordlist, card test or exploit payload "to be sure" | Use the controlled probe; fingerprint CVEs, never exploit |
| Fixing the instance, not the template | If one route lacks an ownership check, audit every route built the same way |

## Re-verify before quoting (volatile, as of 2026-11)

- Next.js and React patched versions for CVE-2025-29927 and React2Shell (GHSA, React advisory)
- Cloudflare WAF rate-limit limits per plan; Turnstile token rules
- npm publishing and token policy changes; pnpm cooldown defaults
- OWASP Top 10:2025 final status; LLM Top 10 edition
- PCI DSS 6.4.3 and 11.6.1 wording and SAQ A eligibility (PCI SSC FAQ 1588)
- WordPress current release; plugin CVE ids from 2026
- EU Digital Omnibus (still a proposal); EU-US DPF appeal C-703/25 P
- CCPA thresholds (re-adjusted in odd years) and CPPA opt-out signal rulemaking; US state law count
- AI Act Art 50(2) marking deadline (2 Dec 2026 for existing systems); EN 301 549 version
- Google Consent Mode and CMP certification rules; IAB TCF version

## Extending this skill

After each real assessment, add an anonymised row to the failure-modes table: the build type, the gaps and one lesson. No secrets, no URLs, nothing that identifies a client. Promote any gap that recurs into the baseline or a playbook, and keep "as of" dates honest.

## Review checklist

| Issue | Fix |
| --- | --- |
| Login, reset or OTP accepts unlimited attempts | Turnstile verified first, fail closed, plus per-IP and per-account counter with lockout |
| Token in `localStorage` | `__Host-` HttpOnly Secure SameSite cookie |
| `/{id}` route checks session but not owner | Scope the query by owner or tenant; 404 on miss |
| Auth only in middleware | Re-check in the handler or data layer |
| No CSP, or `unsafe-inline` plus wildcard hosts | Nonce or hash CSP, Report-Only first |
| Headers only on `/` | Apply to every HTML response, including 404 |
| Secrets in the bundle, or `.env`, `.git` or source maps served | Move to server secrets, block the paths, rotate |
| Origin port or `*.workers.dev` reachable | Firewall, Tunnel or AOP; `workers_dev = false`, `preview_urls = false` |
| Swagger, Actuator or GraphQL introspection in production | Disable or gate |
| Contact or signup form with no bot check | Turnstile plus rate limit; fixed recipient address |
| SMS OTP with no send caps | Per-number, prefix, IP and global caps; block unserved countries |
| Third-party script with no owner, SRI or CSP entry | Inventory, self-host or SRI; lock GTM publish rights |
| Lockfile not enforced, install scripts on | `npm ci`, `ignore-scripts=true`, release cooldown |
| Framework behind the latest patch of its line | Upgrade; check advisories |
| DMARC missing or `p=none` | SPF, DKIM, DMARC moving to `p=reject`; CAA |
| CNAME to a deleted resource | Delete the record; inventory DNS |
| Error path returns data or skips a check | Fail closed |
| Chatbot with secrets in the prompt, broad tools or no spend cap | Strip secrets, narrow tools, downstream authz, quotas, AI disclosure |
| Trackers fire before consent, or Reject doesn't stop them | Block until consent; verify Reject with DevTools |
| GPC ignored | Honour `Sec-GPC: 1` for the browser and the logged-in account |
| Finding with no proof | Test it, or mark it "unverified" |
