# SaaS and multi-tenant web apps

Apply the Universal Baseline in SKILL.md first. This file is also the home of webhook receiver verification, which the e-commerce and fintech playbooks reuse. Facts are as of 2026-11.

## Threat model

One bug, many customers. The worst failures are:
- Cross-tenant data access: BOLA/IDOR, a missing tenant filter, a shared cache, storage bucket or job queue.
- Privilege escalation inside a tenant: BFLA, mass assignment.
- Identity-layer failures: SAML or OIDC validation errors, unsafe account linking, weak MFA.
- Integration credentials: API keys, OAuth tokens, webhooks.

OWASP Top 10:2025 keeps A01 Broken Access Control at number one. On the API list, BOLA is API1 and BFLA is API5: both are authorisation failures.

## Recent incidents

| Attack | Incident | Confidence |
| --- | --- | --- |
| Customer credentials without MFA | Snowflake customer data theft (Mandiant, Jun 2024): every incident traced to stolen customer credentials, mostly from infostealers, some unrotated for years; no MFA, no network allowlists. Not a platform breach | Secondary |
| Integration OAuth token theft | Salesloft Drift (Aug 2025): stolen Drift OAuth and refresh tokens used to read customers' Salesforce data and hunt for AWS keys and other secrets; tokens revoked about 20 Aug. Reported org counts are unverified | Secondary |
| IDOR plus default credentials | McHire (Jun-Jul 2025): a dormant admin test account with `123456` as username and password, plus an IDOR exposing applicant chats. "64 million" is an upper bound of reachable records | Secondary |
| SAML signature bypass | ruby-saml CVE-2025-25291 and CVE-2025-25292 (Mar 2025): a parser differential enables signature wrapping and auth bypass; fixed in 1.12.4 and 1.18.0. CVSS differs by source | Secondary |
| Framework flaws in SaaS front ends | CVE-2025-29927 middleware bypass and React2Shell (see SKILL.md). Apps with tenant checks only in middleware are directly exposed | Primary and secondary |
| Forged webhooks | Stripe: without verification, an attacker can send fake events to fulfil orders, grant access or modify records | Primary |

## Checklist

### MUST

1. **Tenant context derived on the server for every request.** Take the tenant from the verified session or token and re-check membership. A client-supplied tenant id is only a selector. Objects outside the caller's tenant return 404, the same as not found.
   Verify: create two tenants (T1, T2), each with a user and data. As the T1 user, request T2 ids on every `/{id}` route, `?tenant_id=`, `X-Tenant-ID` and subdomain swaps; expect 404 or 403 with no body difference that reveals existence. Repeat for list, export, search, file download, signed URLs, GraphQL by-id queries and nested relations.
2. **Object-level (BOLA) and function-level (BFLA) authorization on every endpoint**, central and deny-by-default.
   Verify: as a low-role user, call every admin or owner endpoint found in the JS and API docs (DELETE, PATCH, invite, role change, billing, export, impersonation); expect 403. Try method swaps and `/api/v1` versus `/api/v2`.
3. **Property-level control (API3):** response filtering and mass-assignment protection.
   Verify: PATCH your own object with `role`, `is_admin`, `tenant_id`, `plan`, `owner_id`, `price`; they must be ignored or rejected. Responses must not include password hashes, internal ids or other users' emails.
4. **Database isolation as defence in depth:** PostgreSQL RLS enabled and forced on tenant tables; the request role is not superuser and lacks BYPASSRLS; tenant set as a transaction-local setting; fail closed when it's missing; explicit tenant predicates in raw SQL and bulk statements.
   Verify: source and DB review. Black-box proxy: the IDOR tests above, plus two parallel sessions alternating tenants to check for pooled-connection bleed.
5. **Cache, queue, storage and search keys include the tenant id.** Background jobs re-establish and re-authorise tenant context. Storage is partitioned with exact-prefix boundaries. Signed URLs are issued only after authorization.
   Verify: compare tenant-specific resources from two accounts within a minute; change the object key in a signed URL and expect 403.
6. **Strong auth for every user:** MFA available, and enforced for admins and tenants that ask; breached-password blocklist; rate limits; no enumeration.
   Verify: about 20 wrong logins, generic errors, uniform reset responses, MFA enrolment offered.
7. **API keys:** shown once, stored hashed, scoped per tenant and permission, revocable, rotated, prefixed for leak scanning (for example `acme_live_...`), with created and last-used metadata; never in URLs or logs.
   Verify: in a test tenant, use a key against another tenant (403), a read-only key for a write (403), then revoke it and retry (401 immediately).
8. **Inbound webhook signatures verified** (see Webhooks below).
9. **SAML:** verify with the stored IdP key and ignore `KeyInfo` in the document; RSA-SHA-256 or better, reject SHA-1; the signature must cover the assertion you use; schema validation and absolute XPath (no `getElementsByTagName`); check `Destination`, `Audience`, `Recipient` and `SubjectConfirmationData`; match `InResponseTo` for SP-initiated flows; short `NotBefore`/`NotOnOrAfter` windows; replay detection on assertion ids; IdP-initiated SSO off unless needed, otherwise allowlist RelayState. Keep SAML libraries patched.
   Verify, only in your own test tenant with your own IdP: replay a captured SAMLResponse, send it to another tenant's ACS URL, change the NameID without re-signing, and remove the signature. All must be rejected.
10. **OIDC and OAuth (RFC 9700):** exact redirect URI matching (no wildcards or prefixes); authorization code flow with PKCE S256; no implicit or password grant; `state` or PKCE/nonce against CSRF; validate `iss`, `aud`, `exp`, `nonce` and an algorithm allowlist; `iss` parameter with multiple authorization servers; refresh token rotation or sender-constraint; no open redirectors; audience-restricted tokens.
    Verify: in your own client registration, try `redirect_uri=https://attacker.example`, `.../callback/../x` and subdomain variants; all rejected. `response_type=token` refused.
11. **Tenant-aware SSO account linking:** never auto-link an SSO login to an existing local account by email alone; bind an IdP to a verified tenant domain (unverified, common practice).
    Verify: sign up locally as victim@domain in a test tenant, then log in through an IdP asserting the same unverified email; no silent merge.
12. **Audit logs** for login, MFA change, role change, API key create and revoke, SSO config, export, impersonation and support access, with verified tenant and actor; append-only; tenant admins see only their own; no secrets in logs (OWASP multi-tenant cheat sheet; ASVS 5.0 V16).
    Verify: perform an action in a test tenant and confirm the event; confirm one tenant admin can't read another tenant's log.
13. **Per-tenant rate limits and quotas**, with 429 and `Retry-After`; tenant id is a limit dimension.
    Verify: a controlled burst of about 30 requests to a heavy endpoint.

### SHOULD

14. SCIM or admin-controlled deprovisioning; revoke sessions on role change or removal; short access-token lifetimes.
15. IP allowlists or private connectivity for sensitive tenants (Snowflake lacked them).
16. OAuth app governance per tenant: least scopes, admin approval, token expiry, revocation, alerts on bulk API reads (Salesloft Drift).
17. SSRF controls on webhook and URL-fetch features: block private ranges, internal redirects and metadata addresses; sign outbound webhooks and use a distinct egress.
    Verify, on your own environment only: set an outbound webhook to `http://127.0.0.1` and `http://169.254.169.254/`; expect a block.
18. API inventory: no undocumented or old versions; `/api/v0`, `/internal`, `/debug` blocked; OpenAPI and Swagger not public in production.
19. Support impersonation needs tenant consent, is time-boxed and audited.
20. Import and export checked for CSV injection and file type; uploads scanned.

### NICE

21. Passkeys and phishing-resistant MFA; device-bound sessions.
22. Per-tenant encryption keys (BYOK) and per-tenant backups.
23. Dedicated infrastructure for high-risk tenants; a nightly cross-tenant IDOR test in CI with two seeded tenants.
24. Canary records per tenant to detect cross-tenant reads.
25. Public security page, `security.txt`, and a bug bounty or disclosure policy.

## Webhooks: receiver verification

Shared by ecommerce.md and fintech-payments.md.

- **Stripe:** header `Stripe-Signature` carries `t=` (timestamp) and `v1=` signatures. The signed payload is `timestamp + "." + raw body`, HMAC-SHA256 with the endpoint's `whsec_` secret. Use only `t` and `v1`. Compare in constant time against every `v1` (there can be several during rotation; the old secret can stay valid up to 7 days). Official libraries default to a 5-minute tolerance; a tolerance of 0 disables the recency check. The framework must not modify the raw body. Dedupe on event id, since events repeat and arrive out of order. Exempt the route from CSRF, return 2xx fast and process asynchronously. Stripe retries live events for up to three days.
- **Shopify:** `X-Shopify-Hmac-SHA256` is a base64 HMAC-SHA256 of the raw body with the app client secret. Capture the raw body before JSON parsing and compare in constant time. Dedupe on `X-Shopify-Webhook-Id`, not `X-Shopify-Event-Id`. Respond within about 5 s; Shopify retries 8 times over 4 hours. HMAC applies to HTTPS deliveries only. Secret rotation can take up to an hour.
- **Other providers (GitHub, Slack, Twilio):** not verified for this skill. The pattern is the same, but read each provider's current docs before writing provider-specific tests.

```ts
// Generic HMAC receiver: raw body, constant-time compare, timestamp window, dedupe
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifySignature(rawBody: string, ts: string, sig: string, secret: string) {
  const age = Math.abs(Date.now() / 1000 - Number(ts));
  if (!Number.isFinite(age) || age > 300) return false; // stale or missing timestamp: reject
  const expected = createHmac("sha256", secret).update(`${ts}.${rawBody}`).digest("hex");
  const a = Buffer.from(expected), b = Buffer.from(sig);
  return a.length === b.length && timingSafeEqual(a, b);
}
// Then: if (await seen(eventId)) return 200 without reprocessing.
```

Black-box test on your own receiver: unsigned POST gives 4xx; a valid signature with one byte of the body changed gives 4xx; a stale timestamp gives 4xx; the same event id twice is processed once; another tenant's secret gives 4xx.

## Gotchas

- **Subdomain tenancy:** check that the `Host` or subdomain tenant matches the session tenant. Wildcard cookies on `.example.com` let one tenant's hosted page steal another's session. Use host-only cookies and a separate domain for user content (unverified, general practice).
- **ORMs are defence in depth only.** Raw SQL, bulk updates and some hooks skip ORM-level tenant filters.
- **Connection pooling:** an RLS context set per session can leak across pooled connections. Use transaction-local settings and test through the pooled path.
- **Search, analytics, vector stores and caches** are where tenant filtering is most often forgotten.
- **GraphQL:** by-id queries and nested relations bypass REST-level checks. Turn introspection off in production and limit depth and complexity.
- **Next.js and React front ends:** authorization in middleware or client components alone is exploitable. Enforce it in server handlers and the data layer.
- **Default and test accounts (McHire):** scan every environment, including legacy tenants, for default credentials and delete dormant test admins.
- **Long-lived integration tokens (Drift, Snowflake):** expire, scope and monitor them. Treat a vendor compromise as your incident.

## Sources

- OWASP Top 10:2025: https://top10.owasp.org/2025/0x00_2025-Introduction (accessed 2026-11-20)
- OWASP ASVS 5.0.0: https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en (accessed 2026-11-20)
- OWASP API Security Top 10 2023: https://api-security.owasp.org/editions/2023/en/0x11-t10 (accessed 2026-11-20)
- OWASP Multi-Tenant Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html (accessed 2026-11-20)
- OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html (accessed 2026-11-20)
- OWASP Credential Stuffing Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html (accessed 2026-11-20)
- RFC 9700, OAuth 2.0 Security BCP: https://www.rfc-editor.org/rfc/rfc9700 (accessed 2026-11-20)
- NIST SP 800-63B-4 passwords: https://pages.nist.gov/800-63-4/sp800-63b/passwords (accessed 2026-11-20)
- Stripe webhooks: https://docs.stripe.com/webhooks (accessed 2026-11-20)
- Shopify HTTPS webhooks: https://shopify.dev/docs/apps/build/webhooks/subscribe/https (accessed 2026-11-20)
- Mandiant, UNC5537 Snowflake: https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion (accessed 2026-11-20)
- BleepingComputer, Salesloft Drift: https://www.bleepingcomputer.com/news/security/salesloft-breached-to-steal-oauth-tokens-for-salesforce-data-theft-attacks (accessed 2026-11-20)
- TechCrunch, Salesloft GitHub link: https://techcrunch.com/2025/09/08/salesloft-says-drift-customer-data-thefts-linked-to-march-github-account-hack/ (accessed 2026-11-20)
- Ian Carroll, McHire write-up: https://ian.sh/mcdonalds (accessed 2026-11-20)
- BleepingComputer, McHire: https://www.bleepingcomputer.com/news/security/123456-password-exposed-chats-for-64-million-mcdonalds-job-applications/ (accessed 2026-11-20)
- OSV, ruby-saml CVE-2025-25291: https://osv.dev/vulnerability/CVE-2025-25291 (accessed 2026-11-20)
