# Public APIs and mobile backends

REST and GraphQL APIs, mobile app backends, partner APIs. Apply the Universal Baseline in SKILL.md first. Webhook receivers and OAuth/SAML details live in [saas-multitenant.md](saas-multitenant.md). Facts are as of 2026-11.

## Threat model

"The mobile API is hidden" is not a control: app traffic is trivial to inspect, and bundles and binaries leak endpoint and bucket names. Attackers enumerate every route, then try each one with no token, with another user's token and with extra fields. OWASP API Security Top 10 (2023, still the current edition as of 2026-11):

1. API1 Broken Object Level Authorization (BOLA)
2. API2 Broken Authentication
3. API3 Broken Object Property Level Authorization
4. API4 Unrestricted Resource Consumption
5. API5 Broken Function Level Authorization
6. API6 Unrestricted Access to Sensitive Business Flows
7. API7 Server Side Request Forgery
8. API8 Security Misconfiguration
9. API9 Improper Inventory Management
10. API10 Unsafe Consumption of APIs

## Recent incidents

| Attack | Evidence | Confidence |
| --- | --- | --- |
| Unauthenticated or over-exposed API returning customer data | Optus 2022 (unauthenticated API the likely cause, about 10-11M records), T-Mobile 2023 (37M customers via an API; BOLA detail unverified), Trello 2024 (API returned profiles by email, about 15M) | MED |
| IDOR plus default credentials | McHire 2025 | MED-HIGH |
| Stolen long-lived OAuth and refresh tokens | Salesloft Drift 2025 | MED-HIGH |
| GraphQL batching and alias rate-limit bypass on OTP and login | Technique documented by OWASP and vendors; no named 2025 breach found | MED (technique) |
| Mobile app leaks bucket and API endpoints | Tea 2025 | MED |
| Framework SSRF | Next.js CVE-2024-34351 and CVE-2025-57822 | MED-HIGH |

## Checklist

### MUST

1. **Authenticate every non-public endpoint; deny by default** (API2, API5).
   Verify: crawl API paths from JS bundles and mobile traffic, including mobile-only `/api/v1/...` routes; call each with no credentials; expect 401 or 403.
2. **BOLA and BFLA checks on every ID-bearing and role-sensitive route** (API1, API5).
   Verify: the two-account test across read, update and delete; call admin-prefixed routes with a normal user token.
3. **Property-level authorization: no mass assignment, no excessive data exposure** (API3).
   Verify: compare response fields with what the UI needs; send `role`, `isAdmin`, `price`, `ownerId` on an update to your own object and confirm they are ignored.
4. **Rate limits that count operations, per user, per IP and per sensitive business flow** (API4, API6): login, OTP, password reset, search, checkout, listing creation.
   Verify: 15-20 requests on login, OTP and a list endpoint; expect 429 or backoff with `Retry-After`.
5. **Token hygiene:** short-lived access tokens; refresh-token rotation and revocation; tokens in Keychain or Keystore on mobile and in HttpOnly cookies on the web; follow RFC 9700.
   Verify: decode a JWT (header and claims only) and check `alg`, `exp`, audience and scope; confirm `alg: none` and unsigned tokens are rejected; confirm logout or revoke kills the refresh token on a test account.
6. **API inventory and environment hygiene:** no old versions with weaker auth, no staging, debug or Swagger in production (API9, API8).
   Verify: probe `/v0`, `/v1`, `/v2`, `/swagger`, `/openapi.json`, `/graphql`, `/actuator` on the production host; compare auth behaviour across versions.
7. **Input validation and parameterised queries; JSON schema validation; size limits; strict content types.**
   Verify: an oversized body, a wrong content type and an array where a string belongs; expect 4xx without stack traces.
8. **GraphQL:** introspection and field suggestions off in production; depth, amount and cost limits; capped batch size; no batching or aliasing on login, OTP or reset; authorization at the resolver or field level; remove `node`/`nodes` if unused; timeouts.
   Verify: send `{__schema{types{name}}}`; send a query with 2 aliased copies of a harmless field to see whether counts are limited; check whether an array of 2 queries is accepted on a sensitive mutation (never send hundreds of guesses); look for "Did you mean" suggestions.
9. **Upstream API responses treated as untrusted** (API10): schema validation, timeouts, no blind redirect-following.
   Verify: review only.
10. **SSRF protections on any server-side fetch** (API7). See marketplace-ugc.md item 8.
11. **No secrets in the app binary or JS bundle.** Use short-lived tokens issued after auth.
    Verify: run `strings` or jadx on your own build; grep the bundle as in SKILL.md.

### SHOULD

12. A versioning policy with deprecation and sunset dates; only supported versions live (API9).
13. Per-client API keys with scopes and quotas; separate keys per environment; rotate on staff change.
14. Gateway logging and alerts on abnormal volume and enumeration; unique request IDs.
15. Certificate pinning on mobile (unverified; it carries operational risk).
16. App attestation (Play Integrity, App Attest) on abuse-prone flows.
17. A CORS allowlist; never `*` with credentials.
18. Generic errors, and the same 404 for forbidden and missing objects.

### NICE

19. Per-endpoint cost budgets and adaptive throttling.
20. Contract tests in CI that assert the authorization matrix.
21. HMAC-signed requests for partner APIs.
22. mTLS for partner links.
23. Canary tokens in schemas and test data.

## Gotchas

- CDN rate limiting counts HTTP requests. GraphQL batching and aliasing pack many operations into one request, so count operations in the app.
- Old API versions often miss newer authorization fixes (API9 version drift).
- Refresh tokens held by integration vendors are as dangerous as passwords (Salesloft Drift).
- Mobile apps leak bucket names and internal hostnames. Assume an attacker has read your binary.

## Sources

- OWASP API Security Top 10 2023: https://api-security.owasp.org/editions/2023/en/0x11-t10 ; https://owasp.org/www-project-api-security/ (accessed 2026-11-20)
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html (accessed 2026-11-20)
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html (accessed 2026-11-20)
- RFC 9700: https://www.rfc-editor.org/info/rfc9700 (accessed 2026-11-20)
- API breach roundups (secondary): https://blog.treblle.com/takeaways-from-5-terrible-api-breaches ; https://salt.security/blog/t-mobile-api-breach-what-went-wrong ; https://www.f5.com/company/blog/lessons-learned-so-far-breach-t-mobile (accessed 2026-11-20)
- McHire: https://www.bleepingcomputer.com/news/security/123456-password-exposed-chats-for-64-million-mcdonalds-job-applications/ (accessed 2026-11-20)
- Salesloft Drift, GTIG: https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift (accessed 2026-11-20)
- Tea app breach: https://www.engadget.com/cybersecurity/tea-app-suffers-breach-exposing-thousands-of-user-images-190731414.html (accessed 2026-11-20)
- GraphQL batching (vendor): https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/ ; https://lab.wallarm.com/graphql-batching-attack/ (accessed 2026-11-20)
- NVD CVE-2024-34351: https://nvd.nist.gov/vuln/detail/CVE-2024-34351 ; CVE-2025-57822: https://nvd.nist.gov/vuln/detail/CVE-2025-57822 (accessed 2026-11-20)
