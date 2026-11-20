# WordPress and headless CMS

Apply the Universal Baseline in SKILL.md first. Facts are as of 2026-11. Vendor figures (Patchstack, Wordfence) are self-reported; plugin CVE ids from 2026 come from search summaries and should be opened on the Wordfence or Patchstack page before you put them in a report.

## Threat model

WordPress core is comparatively well maintained. The risk sits in the plugin and theme ecosystem, update lag, weak admin credentials and hosting hygiene. Attackers mass-scan for known-vulnerable plugin versions and exploit within hours of disclosure. Headless CMS moves the risk to the CMS admin and API, often exposed to the internet, and to the preview and webhook pipeline feeding the front end.

## Ecosystem facts

- Patchstack, covering 2025 (vendor): about 11,334 new ecosystem vulnerabilities, up 42% on 2024; 91% in plugins, 9% in themes; 46% had no patch at disclosure; weighted median time to first mass exploitation about 5 hours. Core vulnerability counts conflict between sources.
- Current release per wordpress.org/download/releases (as of 2026-11): 7.1.5 (18 Nov 2026). The page's own "last modified" date contradicts it, so confirm on wordpress.org/news. Only the latest branch is actively maintained.
- WordPress hardening handbook (primary): files 644, directories 755, `wp-config.php` 400 or 440 and denied from the web, `DISALLOW_FILE_EDIT`, a least-privilege DB user per site, SFTP not FTP, remove unused plugins, test restores, monitor file changes.
- Brute-force handbook (primary): `xmlrpc.php` and `system.multicall` are frequent targets, so disable XML-RPC if unused. Put Turnstile or a CAPTCHA on `wp-login.php`. Rate limit at the edge, not in PHP plugins. Core has no 2FA, so add it for admins. Passkeys are recommended, with at least two authenticators per admin.

## Recent incidents

| Attack | Incident | Confidence |
| --- | --- | --- |
| Plugin portfolio bought, then backdoored | Essential Plugin (Apr 2026): portfolio sold, buyer planted a dormant backdoor via a fake update; WordPress.org closed 31 plugins. Reported scale conflicts, treat as unknown | Secondary |
| Vendor update channel compromised | ShapedPlugin Pro plugins backdoored through the official licensed update endpoint (Wordfence notice Jun 2026, CVE-2026-10735, CVSS 9.8) | Secondary |
| Unauthenticated critical plugin flaws exploited on disclosure | Burst Statistics auth bypass (CVSS 9.8, fixed 3.4.2, mass exploitation May 2026); Ninja Forms File Upload arbitrary upload (Apr 2026). Block counts are attempts, not compromises | Secondary |
| Credential attacks on wp-login and xmlrpc | `system.multicall` amplification, long documented | WordPress handbook (primary) |
| REST user enumeration, then targeted brute force | `/wp-json/wp/v2/users`, `?rest_route=/wp/v2/users`, `/?author=1` | Secondary |
| Headless CMS flaws | Strapi CVE-2026-27886 (unauthenticated, 4.0.0 to 5.36.1, fixed 5.37.0, admin secret exposure); Payload CVE-2026-25544 (blind SQLi, CVSS 9.8, fixed 3.73.0); Directus CVE-2025-55746 (unauthenticated file upload, fixed 11.9.3). In-the-wild exploitation of the Strapi flaw is unverified | Secondary, check CISA KEV |

## WordPress checklist

### MUST

1. **Core, plugins and themes current; auto-updates on for core minor releases and exposed plugins; unused plugins and themes deleted.**
   Verify: `/readme.html` should not exist; read `<meta name="generator">` and `?ver=` strings on core and plugin assets; read `/wp-content/plugins/<slug>/readme.txt` stable tags and cross-check against Wordfence Intelligence, Patchstack and CISA KEV. Never exploit.
2. **Admins have 2FA or passkeys; no user named `admin`; unique strong passwords; no shared accounts.**
   Verify: owner-assisted login shows a second factor; `/wp-login.php?action=lostpassword` gives a generic response.
3. **Edge rate limit plus challenge on `/wp-login.php` and `/xmlrpc.php`.**
   Verify: about 20 wrong logins against a throwaway test user; expect 429 or a challenge. Then:
   ```
   curl -s -X POST https://site/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
   ```
   Pass: 403 or 404, or a method list without `system.multicall` if XML-RPC is genuinely needed. A 200 with `system.multicall` fails.
4. **XML-RPC disabled unless Jetpack or the mobile app needs it.** Verify: as above.
5. **No username enumeration.**
   Verify: `curl -s https://site/wp-json/wp/v2/users` (read the start of the output) and `curl -sI 'https://site/?author=1'`. Pass: 401, 403, 404 or empty. Fail: JSON with a `slug` equal to a login name. Block the users route for unauthenticated users only; blocking the whole REST API breaks the block editor. Make sure display names and author slugs aren't login names.
6. **Sensitive files not reachable**: `wp-config.php` and its backups (`.bak`, `.old`, `~`, `.zip`), `.git`, `.env`, `debug.log`, PHP files in uploads, DB dumps, `wp-content/ai1wm-backups`, `backup*.zip`.
   Verify: request each; expect 403 or 404, never 200 with content. `/wp-content/debug.log` and an open `/wp-content/uploads/` listing are the common hits.
7. **PHP execution off in `/wp-content/uploads/`; permissions 644/755; `wp-config.php` 400/440; `DISALLOW_FILE_EDIT` true.**
   Verify: directory listing is off; permissions need owner shell access.
8. **Off-site backups with a tested restore.** Verify: owner shows the last restore test date.
9. **Admin over HTTPS with HSTS; optionally IP-restrict `wp-admin` or put it behind Access.** BasicAuth on `wp-admin` can break `admin-ajax.php`, so test it.
   Verify: `curl -sI http://site/wp-admin` redirects to HTTPS with headers present.

### SHOULD

10. WAF with virtual patching (Wordfence, Patchstack, Cloudflare managed rules) as an addition to patching, not a substitute.
11. Plugin vetting: active installs, last update, author and ownership change history, vendor reputation. Subscribe to alerts for the exact plugin list. Verify: owner provides the inventory.
12. File integrity monitoring: `wp core verify-checksums`; alert on new PHP in uploads.
13. A DB user per site with only SELECT, INSERT, UPDATE and DELETE, after testing upgrades (revoking DROP or ALTER can break schema upgrades).
14. Least-privilege roles: editors aren't administrators; review the admin list quarterly (`wp user list --role=administrator`).
15. Security headers and CSP on the front end. Many plugins inject inline script, so start Report-Only.
16. Turnstile and nonces on contact and comment forms; disable comments and pingbacks if unused.
17. Shorter auth cookie lifetime for admins; "remember me" off for admins.

### NICE

18. Passkeys for every admin, two authenticators each.
19. Move `wp-config.php` above the web root (the handbook says the benefit is debated).
20. Renaming the login URL is noise reduction only and should never be the only defence.
21. A staging site with identical plugins and a 24-hour canary before production updates.
22. Run `wp-cli` as a deploy user separate from the PHP-FPM user.

## Headless CMS checklist (Strapi, Directus, Payload, Contentful, Sanity)

### MUST

1. **CMS admin and API not public, or behind an IP allowlist, Access or SSO.** The public front end calls a read-only, scoped content API.
   Verify: `curl -sI https://cms.example.com/admin` (Strapi, Payload), `/admin` and `/server/info` (Directus); expect gated, no version banner.
2. **Patched**: Strapi 5.37.0 or later, Payload 3.73.0 or later, Directus 11.9.3 or later. Re-check each project's advisories at audit time.
3. **Public role denies by default**: no `find` or `findOne` on sensitive collections for unauthenticated users; drafts not public.
   Verify: unauthenticated GET on `/api/<collection>` and `/api/users` returns only intended fields (Strapi `/api/users` and `/api/upload/files` are classic leaks); `?populate=*` must not expose relations such as `createdBy`.
4. **Separate read-only delivery tokens from management tokens.** Tokens appear in client bundles only if they are intentionally public-read.
   Verify: grep the bundle for CMS tokens, then test what the token can do (GET only).
5. **Webhooks from the CMS to build or revalidate endpoints need a secret or signature; preview mode uses signed, expiring tokens.**
   Verify: POST `/api/revalidate` without the secret; expect 401 or 403.
6. **Upload restrictions**: type, size, object storage, no execution. Verify with an owner-account test upload only.

SHOULD: admin 2FA or SSO; rate limits on admin login and GraphQL; GraphQL introspection off and depth capped in production; an audit log of publish events; preview URLs not indexable (`X-Robots-Tag: noindex`).

NICE: a separate domain for the CMS admin; WAF rules for the CMS path; periodic content exports to the repo.

## Gotchas

- Plugins often add their own `admin-ajax` or REST routes with weak capability checks. Broken access control was reported as the most exploited type in 2025. Call plugin routes (`/wp-json/<namespace>/v1/...`) unauthenticated and confirm anything that mutates data returns 401 or 403.
- Plugin `readme.txt` stable tags are public, so attackers fingerprint exact versions in seconds. Patch speed matters more than hiding versions.
- With a median of about 5 hours to mass exploitation, "monthly update day" is too slow. Turn on auto-updates for exposed plugins.
- Premium plugins update outside wordpress.org, and the ShapedPlugin compromise came through the licensed update channel, so wordpress.org monitoring alone misses it.
- Shared hosting often runs every site in an account as one OS user, so one compromised site infects its neighbours (unverified, general hosting knowledge). Isolate sites per user or container.
- Multisite: the `wp-includes` .htaccess hardening rule breaks `ms-files.php`.
- Headless: GraphQL introspection and REST `populate` enlarge the readable surface. A leaked management token can rewrite content site-wide (stored XSS or a skimmer on every page). Preview deploys are public unless protected.

## Sources

- WordPress hardening: https://developer.wordpress.org/advanced-administration/security/hardening/ (accessed 2026-11-20)
- WordPress brute force: https://developer.wordpress.org/advanced-administration/security/brute-force/ (accessed 2026-11-20)
- WordPress releases: https://wordpress.org/download/releases/ (accessed 2026-11-20)
- Patchstack 2025 analysis (vendor): https://patchstack.com/?p=25568 (accessed 2026-11-20)
- Patchstack, State of WordPress Security 2026: https://patchstack.com/whitepaper/state-of-wordpress-security-in-2026/ (accessed 2026-11-20)
- Patchstack, Essential Plugin: https://www.patchstack.com/articles/critical-supply-chain-compromise-on-20-plugins-by-essentialplugin/ (accessed 2026-11-20)
- Wordfence, ShapedPlugin PSA: https://www.wordfence.com/blog/2026/06/psa-supply-chain-compromise-targets-shapedplugin-backdoored-pro-plugins-distributed-via-official-channels/ (accessed 2026-11-20)
- Wordfence, Burst Statistics: https://www.wordfence.com/blog/2026/06/attackers-actively-exploiting-critical-vulnerability-in-burst-statistics-plugin/ (accessed 2026-11-20)
- Wordfence, Ninja Forms File Upload: https://www.wordfence.com/blog/2026/04/attackers-actively-exploiting-critical-vulnerability-in-ninja-forms-file-upload-plugin/ (accessed 2026-11-20)
- Bishop Fox, Strapi CVE-2026-27886: https://bishopfox.com/blog/cve-2026-27886-unauthenticated-boolean-oracle-exfiltration-of-administrator-secrets-in-strapi (accessed 2026-11-20)
- NVD CVE-2026-25544 (Payload): https://nvd.nist.gov/vuln/detail/CVE-2026-25544 (accessed 2026-11-20)
- OSV CVE-2025-55746 (Directus): https://osv.dev/vulnerability/CVE-2025-55746 (accessed 2026-11-20)
