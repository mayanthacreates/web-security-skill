# Marketplaces, classifieds and UGC sites

Seller and buyer accounts, listings, uploads, messaging, reviews. Apply the Universal Baseline in SKILL.md first. Facts are as of 2026-11. Confidence tags: HIGH (primary read), MED (reputable secondary), LOW (vendor only or conflicting).

## Threat model

Every user is a content author, so every field is an input that other users render. Attackers want:
- Stored XSS through listing fields, messages and uploads (SVG especially).
- Other users' private data through IDOR on listings, leads, messages and invoices.
- Uploaded ID documents in public buckets.
- Money: fake listings, fake payments, SMS pumping on OTP signup.
- Your server as a proxy: SSRF through link previews, avatar-by-URL and image import.
- The whole catalogue and every phone number, by scraping.

## Recent incidents

| Attack | Evidence | Confidence |
| --- | --- | --- |
| Stored XSS via uploaded SVG and deny-list sanitisers | 2025 CVE cluster: DNN CVE-2025-64094 (a deny-list fix for CVE-2025-48378 missed other SVG constructs), MetInfo CVE-2025-60450, eLabFTW CVE-2025-62793, FileRise CVE-2025-66403 | MED (aggregators) |
| Public storage bucket of user uploads | Tea app, Jul 2025: about 72,000 images (about 13,000 selfies and ID photos) in an open Firebase bucket whose URL was in the Android app; a second exposure of 1M+ DMs reported | MED |
| IDOR on object IDs plus default credentials | McHire 2025: test account `123456/123456` and an incrementing `lead_id` returned other applicants' chats | MED-HIGH |
| Fake listings and fake-payment fraud against sellers | Forged cheques, too-cheap fake listings and fake bank-transfer screenshots used against private sellers. Generic threat-model pattern; no source cited here (unverified) | LOW |
| SMS pumping on phone-OTP signup | Bots submit numbers so attacker-linked carriers earn termination fees. Twilio: geo permissions, per-number and prefix limits, conversion monitoring; its own docs say no control is 100% | MED (vendor) |
| SSRF via URL preview, image fetch, webhooks | OWASP SSRF cheat sheet; Next.js CVE-2024-34351 (Server Actions plus Host header, 14.1.1 and below) and CVE-2025-57822 (middleware redirect handling, fixed 14.2.32 and 15.4.7) | MED-HIGH |
| Scraping of listings and contacts | Trello 2024: an API returned profiles by email, about 15M records | LOW |
| Insider and support-desk data theft | Coinbase, May 2025: bribed support agents copied customer data including ID images | MED |
| Messaging abuse (scam links, off-platform payment) | No primary incident source found; standard threat model (unverified) | LOW |

## Checklist

### MUST

1. **Output-encode all user text; never render raw HTML from listing fields.**
   Verify: on your own test listing, put an inert canary such as `"><u>canary123</u>` in the title, description, seller name and a message. View it on the list page, detail page, share/OG tags, email notifications and admin view. It must show as literal text everywhere, never underlined.
2. **Uploads:** allowlist by decoded content, not Content-Type or extension; re-encode raster images; random server-generated filenames; size and dimension limits; serve files from a separate cookieless origin with `X-Content-Type-Options: nosniff` (OWASP File Upload cheat sheet).
   Verify: upload a renamed `.txt` as `.jpg` and a `.jpg` with trailing bytes; confirm rejection or re-encoding (download and compare the hash and EXIF). The file URL host differs from the app origin and returns `nosniff`.
3. **Block SVG uploads unless essential.** If allowed, serve them with `Content-Disposition: attachment` or from a sandbox origin with `Content-Security-Policy: sandbox`, and use an allowlist sanitiser, not a deny-list. (The OWASP cheat sheet doesn't cover SVG; this is a synthesis.)
   Verify, in staging: upload a benign SVG whose `<script>` only sets `document.title`; navigating to the file URL must not run it. Delete it afterwards.
4. **Object-level authorization on every `/{id}` read and write**: listings, leads, messages, seller inventory, invoices (OWASP API1).
   Verify: with seller A and seller B test accounts, request B's IDs from A's session, including PATCH and DELETE; expect 403 or 404.
5. **Random IDs (UUID or ULID) for private objects, plus the check above.** IDs are not a control on their own.
   Verify: IDs aren't sequential; try 3-5 adjacent IDs of your own objects only.
6. **Storage buckets private by default; signed, expiring URLs for sensitive uploads** (government ID, business licence, KYC selfies). Tea is the template.
   Verify: open an uploaded-ID URL in a logged-out browser; pull bucket names from the JS bundle or mobile app and confirm anonymous list and read are denied.
7. **OTP and SMS abuse controls:** caps per IP, number, prefix and globally; Turnstile before send; unserved country codes disabled; cooldown and max resends; alerts on conversion-rate drops and spend.
   Verify: one OTP request, then 4-5 rapid resends from one IP; expect throttling. Unsupported prefixes rejected. Never mass-send.
8. **No user-supplied URL goes straight into a server-side fetch** (link previews, avatar-by-URL, webhooks, image import). Allowlist scheme, host and port; resolve DNS and block private, loopback, link-local and metadata ranges; pin the validated IP; disable redirects; require IMDSv2 on AWS.
   Verify: submit an out-of-band callback host you control and see whether the server fetches it (that alone proves reachability); then confirm `http://127.0.0.1/` and a redirecting URL are refused. Never target metadata endpoints or hosts you don't own.
9. **Framework patched past known SSRF and auth-bypass CVEs** (Next.js CVE-2024-34351, CVE-2025-57822, plus those in SKILL.md).
   Verify: fingerprint the version and compare with advisories.
10. **Rate limit and Turnstile on every public write path**: post listing, message, report, signup, contact.
    Verify: 15-20 rapid submissions of a harmless form; something must change (429 or a challenge).

### SHOULD

11. Listing-fraud controls: seller verification, price-anomaly flags, duplicate image and identifier detection, gated phone-number reveal, posting caps on new accounts. Verify: list the same test photos from two fresh accounts; expect a flag or hold.
12. Seller-protection UX: warn against off-platform payment, cheques and screenshot "transfers".
13. Moderation: report button, queue SLA, audit log of moderator actions, takedown and appeal. Verify: report a test listing and confirm a record and notification.
14. Messaging: strip or hold links in first messages from new accounts, block executable attachments, per-user message caps, block and report. Verify: send a link from a fresh account to your own second account.
15. Scraping defences: per-IP and per-token limits on list, search and detail APIs; CDN bot management; no unauthenticated bulk endpoints; no full phone numbers in list JSON. Verify: compare list-endpoint JSON with the visible UI for hidden fields.
16. Strip EXIF GPS by re-encoding. Verify: upload a photo with GPS EXIF, download the served version, check with `exiftool`.
17. Headers including `frame-ancestors 'none'` and a tight CSP, so a missed XSS has limited impact.
18. If minors can post, check the children's-data rules in privacy-consent-compliance.md.

### NICE

19. Perceptual hashing or reverse-image checks for stolen listing photos.
20. Seller reputation scores and escrow or verified-deposit flows.
21. Honeypot form fields.
22. The URL-preview and webhook fetcher runs in an isolated, egress-restricted service.

## Gotchas

- A new framework image or preview endpoint is an SSRF surface even if you wrote no fetch code.
- Re-encoding fixes most polyglot and EXIF issues for raster images, but not SVG, PDF or DOCX. They need their own handling.
- A domain allowlist doesn't stop DNS rebinding. Validate the resolved IP and connect to it.
- Mobile apps leak bucket and API names. The Tea bucket URL was in the Android app.
- SMS vendors market "guaranteed" fraud protection while their own docs say it isn't guaranteed.
- Support and admin tooling is a data path too (Coinbase). Limit what support staff can see and export.

## Sources

- OWASP API Security Top 10 2023: https://api-security.owasp.org/editions/2023/en/0x11-t10 (accessed 2026-11-20)
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html (accessed 2026-11-20)
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html (accessed 2026-11-20)
- SVG XSS CVEs: https://www.sentinelone.com/vulnerability-database/cve-2025-64094/ ; https://feedly.com/cve/CVE-2025-60450 ; https://www.sentinelone.com/vulnerability-database/cve-2025-62793/ ; https://www.sentinelone.com/vulnerability-database/cve-2025-66403/ (accessed 2026-11-20)
- Tea app breach: https://fortune.com/2025/07/26/tea-app-hack-images-online-leaks-users-selfies/ ; https://www.engadget.com/cybersecurity/tea-app-suffers-breach-exposing-thousands-of-user-images-190731414.html (accessed 2026-11-20)
- McHire: https://www.bleepingcomputer.com/news/security/123456-password-exposed-chats-for-64-million-mcdonalds-job-applications/ (accessed 2026-11-20)
- Twilio toll fraud prevention (vendor): https://www.twilio.com/docs/verify/preventing-toll-fraud (accessed 2026-11-20)
- NVD CVE-2024-34351: https://nvd.nist.gov/vuln/detail/CVE-2024-34351 (accessed 2026-11-20)
- NVD CVE-2025-57822: https://nvd.nist.gov/vuln/detail/CVE-2025-57822 ; Vercel: https://vercel.com/changelog/cve-2025-57822 (accessed 2026-11-20)
- Coinbase breach: https://fortune.com/2025/05/16/coinbase-data-breach-ransom-sec-investigation/ (accessed 2026-11-20)
- API breach roundup incl. Trello (secondary): https://blog.treblle.com/takeaways-from-5-terrible-api-breaches (accessed 2026-11-20)
