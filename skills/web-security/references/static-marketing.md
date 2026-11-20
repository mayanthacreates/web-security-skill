# Static, marketing and portfolio sites

Jamstack and mostly-static sites: Next.js, Astro or plain HTML on Cloudflare Workers/Pages, Vercel or Netlify. Apply the Universal Baseline in SKILL.md first. Facts are as of 2026-11; tags: (unverified) means no primary source confirmed it.

## Threat model

There is little server-side state, so the attacker goes for:
- What runs in the visitor's browser: third-party scripts, tag managers, npm dependencies.
- The build and deploy pipeline, and DNS.
- The few dynamic endpoints: contact form, newsletter, API routes, server actions, middleware.
- The framework runtime, when Next.js SSR or RSC is in use. A "static-looking" Next app with RSC is a server.
- Reputation abuse: form spam, mail relay, subdomain takeover, phishing from your domain.

## Recent incidents

| Attack | Incident | Confidence |
| --- | --- | --- |
| Third-party CDN changes owner | polyfill.io (2024): domain bought, script modified to inject malicious code; Sansec reported 100,000+ sites; later tied to a wider multi-CDN operator (bootcdn, bootcss, staticfile). Cloudflare rewrote polyfill.io links to its mirror | Secondary, multiple outlets |
| npm build dependencies | Sept 2025: phished maintainer shipped malicious chalk, debug and related packages (about 2 hours live); same month the Shai-Hulud worm compromised 500+ packages per CISA. Package counts conflict by counting date | CISA plus secondary |
| Framework RCE on SSR Next.js | React2Shell CVE-2025-55182 (disclosed 3 Dec 2025, CVSS 10, unauthenticated RCE via RSC Flight deserialisation, added to CISA KEV). Follow-ups: CVE-2025-55184 and CVE-2025-67779 (DoS), CVE-2025-55183 (source exposure), CVE-2026-23864 (DoS, Jan 2026) | React advisory (primary); KEV secondary |
| Middleware auth bypass | Next.js CVE-2025-29927 (Mar 2025): a crafted request header makes middleware skip its checks. Header commonly cited as `x-middleware-subrequest` (unverified, check GHSA-f82v-jwr5-mffw) | Secondary, two summaries agree |
| Contact form abuse | Spam relay, header injection, bot floods, mailbox bombing. A real assessment found a portfolio contact form with no CAPTCHA | Internal plus Cloudflare docs |
| Subdomain takeover | CNAME to a deprovisioned GitHub Pages, Netlify, S3 or Azure resource | MDN (secondary) |

## Checklist

### MUST

1. **Security headers on every HTML response**: HSTS, CSP with `frame-ancestors` and `object-src 'none'`, nosniff, Referrer-Policy, Permissions-Policy.
   Verify: send a HEAD request to the home page and to a missing page and compare the two header sets. Read the CSP or paste it into https://csp-evaluator.withgoogle.com.
2. **Every third-party script inventoried, justified, and pinned or self-hosted.** No script from a domain you don't control without SRI or a strict CSP entry. Remove dead embeds (old analytics, chat, polyfill-type CDNs).
   Verify: list every external script tag and dynamic loader host in the HTML and bundles; check external scripts carry `integrity=` and `crossorigin`; grep for `polyfill.io`, `bootcdn`, `bootcss`, `staticfile`.
3. **Contact and newsletter forms have server-side bot control and a rate limit.** Turnstile verified via siteverify; tokens are single-use and expire after 300 s; replays return `timeout-or-duplicate`; the widget alone does not protect.
   Verify: POST the form endpoint with no token and with a garbage token; expect 4xx and no email. 3-5 requests are enough. Send `\r\n` once in the name field to a test inbox you own and confirm no header injection.
4. **No secrets in the client bundle; no `.env`, `.git` or source maps served.**
   Verify: grep pulled JS for `sk_`, `AIza`, `eyJ`, DB URLs; request `/.env`, `/.git/config`, `/*.js.map`.
5. **Framework patched past the 2025 criticals.** React advisory fixed versions: react-server-dom-* 19.0.1, 19.1.2, 19.2.1; Next.js 14.2.35, 15.0.8, 15.1.12, 15.2.9, 15.3.9, 15.4.11 (the advisory also lists 15.4.10; check the Next.js GHSA), 15.5.10, 16.0.11, 16.1.5. Middleware bypass fixed in 12.3.5, 13.5.9, 14.2.25, 15.2.3. A pure static export with no server and no RSC runtime is not affected by React2Shell.
   Verify: read the lockfile if you have repo access. Black-box: fingerprint only (`x-powered-by`, `/_next/static` build manifest). Never send exploit payloads.
6. **Never rely on middleware alone for authorization.** Re-check auth in the route handler or data layer.
   Verify: request each protected route with no session; expect 401, 403 or a redirect from the handler, not just from middleware.
7. **DNS hygiene**: no CNAME to deprovisioned Pages, Netlify, GitHub, Azure or S3 resources; remove DNS before deleting the hosted project.
   Verify: list subdomains (zone export or Certificate Transparency logs), `dig CNAME` each, look for provider "not found" pages.
8. **Registrar and DNS account protected**: phishing-resistant MFA, registrar lock, auto-renew on. A lapsed domain is a site takeover.
   Verify: `whois` shows `clientTransferProhibited`; ask the owner which MFA type is set.

### SHOULD

9. CSP in enforce mode with nonces or hashes (no `unsafe-inline` or `unsafe-eval`) plus `report-to`. See the Next.js static caveat in SKILL.md. Verify: read the header; load the page with DevTools and confirm no violations from first-party code.
10. SRI on external scripts and styles that can't be self-hosted. Verify: `integrity=` present.
11. Lock npm: lockfile committed, lockfile-only installs in CI, a cooldown before new releases, 2FA on npm and GitHub, no long-lived publish tokens. Verify: repo review.
12. Disable `*.workers.dev` and preview URLs for production Workers; protect preview deployments on other hosts (vendor specifics unverified, check current docs). Verify: request `https://<worker>.<account>.workers.dev` and any `*-git-*.vercel.app` pattern; expect disabled or gated.
13. Edge rate limit on any API route, form or server action. Verify: about 20 controlled requests; expect 429 or a challenge.
14. CAA, SPF, DKIM and DMARC (`p=reject` as the goal; `p=quarantine` only as a staging step) so the domain can't be spoofed. Verify: `dig CAA`, `dig TXT _dmarc`.
15. Form mail goes through a transactional provider with a fixed recipient; the recipient is never taken from the request. Verify: inspect form field names for `to` or `recipient`.

### NICE

16. CSP reporting collected (Report URI, Cloudflare) before switching to enforce.
17. `/.well-known/security.txt`.
18. Self-host fonts and analytics (also removes third-party script risk and a consent question).
19. COOP and CORP where embeds allow.
20. Watch Certificate Transparency logs for unexpected certificates on your subdomains.

## Gotchas

- **Cloudflare Workers/Pages:** `*.workers.dev` and `*.pages.dev` serve the same app without your zone's WAF rules. Image resizing via `/cdn-cgi/image` needs a zone, so preview URLs can look broken. Headers must be set per path (`_headers`) or in Worker code; HTML routes and static assets are configured separately.
- **Next.js on any host:** RSC turns static-looking apps into servers. If you believe the site is static, confirm no Server Function endpoint is reachable.
- **Tag managers:** a compromised GTM container bypasses code review and can load scripts from allowlisted domains (see the Stripe/GTM skimmer in ecommerce.md). Audit GTM tags, not just `<script>` tags.
- **Edge form handlers:** the Turnstile secret lives in a Worker secret, never in the bundle. Check `hostname` and `action` in the siteverify response.

## Sources

- OWASP Top 10:2025: https://top10.owasp.org/2025/0x00_2025-Introduction (accessed 2026-11-20)
- React advisory, CVE-2025-55182: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components (accessed 2026-11-20)
- Vercel React2Shell bulletin: https://vercel.com/kb/bulletin/react2shell (accessed 2026-11-20)
- Next.js CVE-2025-29927: https://nextjs.org/blog/cve-2025-29927 (accessed 2026-11-20)
- React2Shell KEV coverage (secondary): https://thehackernews.com/2025/12/critical-react2shell-flaw-added-to-cisa.html (accessed 2026-11-20)
- Next.js CSP guide: https://nextjs.org/docs/app/guides/content-security-policy (accessed 2026-11-20)
- Cloudflare Turnstile server-side validation: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/ (accessed 2026-11-20)
- Cloudflare Workers previews: https://developers.cloudflare.com/workers/previews/configuration/ (accessed 2026-11-20)
- CISA npm alert: https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem (accessed 2026-11-20)
- Sansec, polyfill.io: https://sansec.io/research/polyfill-supply-chain-attack (accessed 2026-11-20)
- BleepingComputer, polyfill.io: https://www.bleepingcomputer.com/news/security/polyfillio-javascript-supply-chain-attack-impacts-over-100K-sites/ (accessed 2026-11-20)
- MDN, subdomain takeovers: https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers (accessed 2026-11-20)
- MDN, Subresource Integrity: https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity (accessed 2026-11-20)
