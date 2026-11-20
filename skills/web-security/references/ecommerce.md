# E-commerce and checkout

WooCommerce, Shopify, Magento/Adobe Commerce and headless commerce. Apply the Universal Baseline in SKILL.md first. A WordPress store also needs [wordpress-cms.md](wordpress-cms.md). Webhook verification details live in [saas-multitenant.md](saas-multitenant.md). Facts are as of 2026-11.

PCI DSS content below is general information, not legal or compliance advice. Read the official PCI DSS v4.0.1 text and confirm your SAQ with your acquirer.

## Threat model

Money and cards. Attackers want:
- Card data in the browser (Magecart, web skimming).
- Accounts: credential stuffing, account takeover, loyalty and stored-value theft.
- Payment logic bypass: mark an order paid, tamper the price, forge a payment webhook.
- Bot abuse of business flows: card testing, coupon and gift-card cracking, inventory hoarding, scalping.
- Platform RCE in the shop software or its plugins.

## PCI DSS v4.0.1: 6.4.3 and 11.6.1

The standard's PDF was not read; this is paraphrased from PCI SSC FAQ 1588 (primary) and processor and vendor docs (secondary).

- **6.4.3, payment page scripts:** a method to confirm each script is authorised, a method to assure each script's integrity, and an inventory of all scripts with a written business or technical justification. 3-D Secure scripts are exempt per Adyen's documentation.
- **11.6.1, change and tamper detection:** a mechanism that alerts staff to unauthorised changes to security-impacting HTTP headers and to script contents of payment pages as received by the browser. Investigate and resolve unauthorised changes promptly.
- **Frequency:** at least every 7 days, or per a targeted risk analysis under 12.3.1 (multiple vendors agree; not primary-verified).
- **In force:** 31 March 2025, as a formerly future-dated requirement (secondary).
- **v4.0.1 scope:** applies to scripts on the merchant's own payment page, not scripts inside the processor's iframe (secondary).
- **SAQ A (FAQ 1588, Feb 2025, primary):** 6.4.3 and 11.6.1 are not line items. Instead there is an eligibility criterion: the merchant site is "not susceptible to attacks from scripts that could affect the merchant's e-commerce system(s)". It applies only where the page embeds a processor's payment page or form (for example an iframe), not to full redirects or emailed payment links. You can meet it by applying 6.4.3/11.6.1 techniques yourself or through a third party, or by getting confirmation from a PCI DSS compliant processor that its implementation protects the page. A non-payment script vendor doesn't count as that processor.
- **SAQ A-EP and SAQ D:** implement both requirements fully (secondary).
- **Hosted checkout is not automatically exempt.** Shopify's PCI Level 1 status covers Shopify's systems; scripts you control on payment pages remain your duty per a vendor reading (secondary). Shopify says checkout extensions run in a sandbox (secondary).

## Recent incidents

| Attack | Incident | Confidence |
| --- | --- | --- |
| Tag manager and trusted-domain skimmer | Sansec, 4 Jun 2026: a rogue GTM container pulls skimmer code from a Stripe customer record's metadata, hooks the Magento checkout button, XOR-encodes card data into localStorage and exfiltrates it to `api.stripe.com/v1/customers` as fake customers every 60 s; a variant uses Firestore. Trusted domains defeat CSP allowlists. IOCs include localStorage keys `cus_customer_id` and `_d_data_customer_` | Primary (Sansec) |
| Plugin flaw leads to checkout JS injection | Funnel Builder (FunnelKit), May 2026: an unauthenticated checkout endpoint let attackers write to the "External Scripts" setting so a loader printed on every checkout; fixed in 3.15.0.3; 40,000+ stores. CVE id conflicts across sources | Secondary |
| Platform RCE then skimmer | SessionReaper CVE-2025-54236 (Adobe Commerce/Magento, CVSS 9.1), patched Sep 2025, exploited, in CISA KEV; Sansec reported 62% of stores still unpatched six weeks later | Secondary |
| SVG `onload` fake checkout overlay | Sansec, Apr 2026: invisible SVG elements inject a fake checkout overlay on 99 Magento stores | Secondary |
| Payment logic bypass in gateway plugins | 2026 WooCommerce gateway entries: unauthenticated order-status changes, bad signature verification, missing authorization; one Stripe plugin allowed order changes when the webhook secret was empty | Secondary |
| Card testing | Stripe reports Radar blocked 20M+ card-testing attempts per day at the peak of a 2025 wave | Secondary, vendor figure |
| Credential stuffing | OWASP cheat sheet: MFA, device fingerprinting, graduated rate limits, breached-password checks, bot detection, user notification | Primary |

## Checklist

### MUST

1. **Payment page script control (6.4.3):** a written inventory of every script on checkout and payment pages with owner and justification; an enforced CSP `script-src` allowlist or nonce on checkout; no tag manager on checkout, or a locked-down GTM with 2FA and change approval.
   Verify: load `/checkout` and the payment step, collect every script request, compare with the owner's inventory, read the CSP on that response. Fail if `unsafe-inline` plus wildcard hosts, or if GTM, analytics, chat or A/B tools load there without justification.
2. **Tamper detection (11.6.1):** a scheduled (at least weekly, or per risk analysis) hash or monitor of checkout scripts and security headers that alerts a person. Tools include Cloudflare Client-Side Security Advanced (needed for its PCI features), Report URI, Jscrambler and Feroot.
   Verify: ask for the alert config and the last test alert. Black-box: record header and script hashes yourself on two dates and diff them.
3. **Hosted or iframe card fields** (Stripe Elements or Checkout, Shopify checkout, Adyen) so card data never touches your server.
   Verify: in the checkout DOM, card number and CVC fields sit in a cross-origin iframe from the processor's domain.
4. **Webhook and payment callback signatures verified.** Reject unsigned and stale events. Derive order state from the processor API, never from the browser redirect.
   Verify: POST an unsigned body to the webhook URL; expect 400, 401 or 403 and no state change. Never send a forged "paid" event for a real order; use a sandbox test order.
5. **Price, quantity, shipping, currency and discount computed server-side.**
   Verify: in your own sandbox session, change price to 0.01 or quantity to -1 in the add-to-cart or checkout request; the server must recompute or reject.
6. **Orders and customer records ownership-checked (IDOR).** Guest order pages need an unguessable token.
   Verify: two test accounts; request B's order, address and invoice endpoints with A's session; expect 403 or 404.
7. **Login and account endpoints throttled, MFA offered, no enumeration, breached-password check** on login, password reset, "check order status" and OTP.
   Verify: about 20 wrong logins on a test account; identical reset responses for known and unknown emails.
8. **Card-testing controls:** Turnstile or processor-native bot defence on checkout and "add card"; caps per session, IP and card; AVS and CVC checks; guest checkout limits.
   Verify: confirm the control exists (challenge on checkout, processor rules). Never run card tests, not even with test numbers in live mode.
9. **Platform and plugins patched:** Magento past CVE-2025-54236; WooCommerce core and every payment and checkout plugin current; Shopify apps reviewed.
   Verify: version fingerprints (`/magento_version` returns a version on some installs, which is itself a leak; WooCommerce `readme.txt`).
10. **Admin access:** 2FA or SSO on every store admin and staff account; ex-staff and ex-agency users removed; API keys restricted.
    Verify: owner provides the user list and MFA status.
11. **No payment secret keys in client JS** (`sk_live_`, `sk_test_`). Any Stripe secret key or direct calls to `api.stripe.com` or `firestore.googleapis.com` in browser JS are a compromise indicator per Sansec.
    Verify: grep bundles and checkout HTML.

### SHOULD

12. CSP enforced on checkout with `report-to`; SRI on unavoidable external scripts; `frame-ancestors` and `form-action` pinned.
13. "Custom script" admin fields in funnel or checkout plugins locked to 2FA admins with change alerts. Verify: the owner shows the setting.
14. Coupons: single-use or per-customer limits, minimum cart, non-stacking by default, code entropy, expiry, rate limit on the apply endpoint. Verify: about 10 invalid codes should hit a limit. Never use a wordlist.
15. Gift cards and store credit: unguessable codes, throttled and challenged balance checks, login to redeem, uniform responses. Verify: a handful of invalid lookups should be throttled by 10-20. Never enumerate real codes.
16. Inventory and scalping bots: per-customer caps, waiting room, cart hold times, bot management on drop pages (OWASP API6).
17. Processor fraud rules (Radar, 3-D Secure) and manual review for mismatched billing and shipping.
18. Logging and alerts on admin logins, price, coupon and script setting changes, new admins, outbound connections from the web tier.
19. DMARC, SPF and DKIM for transactional mail.
20. ATO defences: new-device notification, session list with revoke, re-auth for address, payment or email changes.

### NICE

21. Passkeys for customers and staff.
22. Server-side GTM or a first-party tag proxy so third-party code never runs on checkout.
23. Periodic external skimmer scans and lookalike-domain monitoring.
24. Honeypot fields and time-to-submit checks on checkout.
25. A separate admin hostname behind Access.

## Platform gotchas

- **Shopify:** legacy custom apps (admin-created `shpat_` tokens) can't be created after 1 Jan 2026; existing ones still work. Audit and rotate old tokens and unused apps. Webhooks are signed with HMAC-SHA256 in `X-Shopify-Hmac-SHA256` (details in saas-multitenant.md). Storefront API tokens are public by design, so check they are scoped to read products and cart only. Theme Liquid and apps inject storefront scripts.
- **WooCommerce:** everything in wordpress-cms.md applies. Payment gateway plugins are high-value targets; set the webhook secret (an empty one allowed unauthenticated order changes in one plugin). Use gateway-hosted card fields to stay in SAQ A or A-EP territory. Order-received URLs carry `key=wc_order_...`; confirm guests can't view others' orders by changing the id. REST consumer keys (`ck_`, `cs_`) should be read-only where possible.
- **Magento/Adobe Commerce:** patch within days; virtual patching via a WAF. Both the Stripe/GTM skimmer and SessionReaper target it.
- **Headless commerce:** you own the checkout page, so you own 6.4.3 and 11.6.1. Keep payment in the processor's hosted fields, patch Next.js and React, keep admin keys off the client, validate cart and price in your backend-for-frontend, and enforce per-customer authorization there (middleware alone is not enough, see CVE-2025-29927).

## Sources

- PCI SSC FAQ 1588: https://www.pcisecuritystandards.org/faqs/1588/ (accessed 2026-11-20)
- Adyen script security guide: https://docs.adyen.com/development-resources/pci-dss-compliance-guide/script-security (accessed 2026-11-20)
- Cloudflare Client-Side Security, PCI DSS: https://developers.cloudflare.com/page-shield/reference/pci-dss/ (accessed 2026-11-20)
- Report URI, 6.4.3 and 11.6.1 (secondary): https://blog.report-uri.com/pci-dss-4-0-1-and-requirements-6-4-3-and-11-6-1-what-changed-for-payment-page-scripts/ (accessed 2026-11-20)
- Cloud Security Alliance, PCI 6.4.3 and 11.6.1 (secondary): https://cloudsecurityalliance.org/blog/2026/07/23/pci-dss-6-4-3-and-11-6-1-a-deep-dive-into-payment-page-security-and-integrity-requirements (accessed 2026-11-20)
- Akamai, PCI DSS v4.0.1 client-side (secondary): https://www.akamai.com/blog/security/pci-dss-v401-meeting-new-client-side-security-requirements (accessed 2026-11-20)
- cside, Shopify and PCI (vendor): https://cside.com/blog/does-shopify-make-you-pci-compliant-6-4-3-11-6-1 (accessed 2026-11-20)
- Sansec, Stripe API skimmer: https://sansec.io/research/stripe-api-skimmer-infrastructure (accessed 2026-11-20)
- Sansec, Funnel Builder: https://sansec.io/research/funnelkit-woocommerce-vulnerability-exploited (accessed 2026-11-20)
- Sansec, SessionReaper: https://sansec.io/research/sessionreaper (accessed 2026-11-20)
- Help Net Security, CVE-2025-54236: https://www.helpnetsecurity.com/2025/10/23/adobe-magento-cve-2025-54236-attack/ (accessed 2026-11-20)
- Sansec, SVG onload skimmer: https://sansec.io/research/svg-onload-magecart-skimmer (accessed 2026-11-20)
- Wordfence, WooCommerce Stripe gateway entry: https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/woocommerce-gateway-stripe/woocommerce-stripe-payment-gateway-1070-missing-authorization-to-unauthenticated-order-status-manipulation-via-order-parameter (accessed 2026-11-20)
- Stripe card testing: https://docs.stripe.com/card-testing and https://stripe.com/newsroom/news/card-testing-surge (accessed 2026-11-20)
- OWASP Credential Stuffing Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html (accessed 2026-11-20)
- Shopify HTTPS webhooks: https://shopify.dev/docs/apps/build/webhooks/subscribe/https (accessed 2026-11-20)
- Shopify legacy custom apps changelog: https://shopify.dev/changelog/posts/legacy-custom-apps-can-t-be-created-after-january-1-2026.md (accessed 2026-11-20)
