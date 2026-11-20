# Fintech, payments and crypto-adjacent sites

Balances, transfers, payouts, wallets, signing flows. Apply the Universal Baseline in SKILL.md first. For card checkout see [ecommerce.md](ecommerce.md); for webhook verification see [saas-multitenant.md](saas-multitenant.md). Facts are as of 2026-11. Confidence tags: HIGH, MED, LOW as in the other playbooks.

Regulatory notes here (PSD2, PSD3, NIST) are general information, not legal advice.

## Threat model

The attacker wants money to move: their way, twice, or without authorization. Routes in:
- Logic flaws: race conditions (withdraw twice, reuse a voucher, beat a daily limit), client-supplied amounts, forged callbacks.
- Account takeover through weak step-up or SMS OTP.
- The front end itself: a tampered signing UI or a skimmer on the dashboard.
- People: bribed support staff, impersonation scams against customers.
- Integration tokens that bypass your MFA entirely.

## Recent incidents

| Attack | Evidence | Confidence |
| --- | --- | --- |
| Front-end tampering of a signing UI | Bybit, 21 Feb 2025, about USD 1.5B: malicious JS served from Safe{Wallet}'s S3 bucket; signers saw a normal address but approved a different transaction. Traced to a compromised developer machine; FBI attributed it to Lazarus. Injection dates differ by source | HIGH-MED |
| Insider bribery and support-desk social engineering | Coinbase, May 2025: bribed support agents leaked customer data; attackers then impersonated Coinbase; USD 180-400M cost estimate | MED |
| Impersonation scams at scale | Chainalysis: at least about USD 14B in scam receipts for 2025, impersonation the main driver | MED |
| Wallet drainers and signature phishing | Scam Sniffer: drainer losses USD 83.85M in 2025, down 83% from 2024. Different method from Chainalysis, so don't compare | MED |
| Race conditions (limit overrun) | PortSwigger "Smashing the state machine": a single-packet attack sends 20-30 requests in one TCP packet over HTTP/2; the bug pattern is check-then-act without atomicity. No named 2024-26 payment incident found | MED |
| OAuth integration token theft | Salesloft Drift 2025: stolen OAuth and refresh tokens used for mass Salesforce data theft | MED-HIGH |

## Checklist

### MUST

1. **Every money or state change is server-authoritative and atomic**: a DB transaction with a row lock or a conditional update (`UPDATE ... WHERE balance >= x`), plus a unique idempotency key per payment or withdrawal.
   Verify, sandbox only or with owner consent and a refundable amount: fire 2-3 identical "redeem", "apply coupon" or "transfer small amount" requests in parallel (for example Burp Repeater "send group in parallel" over HTTP/2) with a trivial amount or a single-use test voucher. The benefit must apply exactly once.
2. **Never trust a client-supplied amount, currency, price, fee or recipient.** Recompute from IDs on the server.
   Verify: tamper amount, currency and quantity in a sandbox checkout (negative, zero, decimal overflow, currency swap); the server rejects or reprices.
3. **Payment-provider webhooks verified (signature, timestamp, replay protection) and order state transitions enforced.** A forged callback or a replayed "success" URL can't mark anything paid.
   Verify: replay a captured sandbox webhook and send one with a bad signature; both rejected or no-op.
4. **Step-up authentication for sensitive actions** (add payee or withdrawal address, change email, phone or password, raise limits), using phishing-resistant factors where possible. NIST SP 800-63B-4 (final July 2025): a phishing-resistant option must be offered at AAL2 and is required at AAL3; passwords are not phishing-resistant.
   Verify: try to add a withdrawal destination with only a session cookie; expect a step-up prompt and a notification.
5. **Payee and withdrawal-address changes carry a cooling-off period and an out-of-band notification** (unverified, standard practice).
   Verify: walk the flow on a test account.
6. **No secrets or signing logic in the front end; front-end assets integrity-controlled**: pinned CDN scripts with SRI, strict CSP `script-src`, locked-down build and deploy credentials and storage buckets. The Bybit root cause was a modified JS bundle in a storage bucket.
   Verify: list every third-party script origin on payment and dashboard pages; confirm SRI or first-party hosting; with owner permission, inspect the asset bucket ACL read-only to confirm it isn't publicly writable.
7. **Login throttle, MFA and credential-stuffing defence** (the SKILL.md #1 lesson).
8. **Support and back-office access hardened**: least privilege, access logging, alerts on bulk customer-data export, no raw ID images in support tooling by default (Coinbase).
   Verify: review only; ask the owner for the access matrix.
9. **Immutable audit trail of every financial event** with actor, IP and device (unverified, standard practice).

### SHOULD

10. Transaction monitoring and velocity limits per account, device and payee; alerts to the user on a new device, new payee or large transfer.
11. Out-of-band confirmation showing amount and payee ("what you see is what you sign"), especially for crypto and multisig flows (Bybit).
12. Webhook and API keys scoped, rotated, never in client bundles; OAuth refresh-token rotation and expiry per RFC 9700, with revocation (Drift tokens were the pivot).
13. Anti-phishing: DMARC at `p=reject`, lookalike-domain monitoring, an impersonation takedown process, clear "we will never ask for..." messaging.
14. Daily reconciliation of your ledger against the provider, with alerts on drift.

### NICE

15. Passkeys as the default second factor.
16. Device binding and risk-based auth.
17. Bug bounty or disclosure page plus `security.txt`.
18. For wallet integrations: an allowlist of signing contexts, and transaction simulation before signing (anti-drainer).

## Regulatory context (EU)

- **PSD2 and SCA:** strong customer authentication applies to in-scope EU payment services. Sites selling to EU customers through an acquirer typically inherit it through 3-D Secure 2 (unverified, standard knowledge).
- **PSD3 and the Payment Services Regulation:** provisional political agreement 27 Nov 2025; committee approval May 2026; not yet in force; most obligations expected around 2028 (sources differ, H2 2027 to Q2-Q3 2028). Fraud liability for PSPs with inadequate controls is a headline change. MED.
- **SMS OTP** is weak for money movement: NIST doesn't treat it as phishing-resistant, and it is exposed to SIM swap and SMS pumping.

## Gotchas

- Race-condition tests need HTTP/2 for the single-packet technique. Against HTTP/1 sites results are flaky, so "no finding" is not a clean bill of health.
- In the Bybit case the backend was fine and the attack lived in the vendor's front end. Your payment page is only as safe as your third parties.
- Drainer losses fell in 2025 while impersonation scams rose. Don't over-invest in drainer defences at the expense of anti-phishing.
- OAuth tokens held by integrations bypass your MFA entirely (Salesloft Drift).

## Sources

- Bybit, NCC Group analysis: https://www.nccgroup.com/research/in-depth-technical-analysis-of-the-bybit-hack/ (accessed 2026-11-20)
- Bybit, BleepingComputer: https://www.bleepingcomputer.com/news/security/lazarus-hacked-bybit-via-breached-safe-wallet-developer-machine/amp/ (accessed 2026-11-20)
- Bybit, SlowMist: https://slowmist.medium.com/bybits-1-5-billion-theft-unveiled-safe-wallet-front-end-code-tampered-84b78f0fa9c2 (accessed 2026-11-20)
- Coinbase breach: https://fortune.com/2025/05/16/coinbase-data-breach-ransom-sec-investigation/ ; https://www.insurancejournal.com/news/national/2025/05/15/823862.htm (accessed 2026-11-20)
- Chainalysis coverage: https://www.infosecurity-magazine.com/news/impersonation-fraud-record-17bn/ (accessed 2026-11-20)
- Scam Sniffer via Cointelegraph: https://cointelegraph.com/news/crypto-phishing-losses-fell-83-percent-2025-wallet-drainers (accessed 2026-11-20)
- PortSwigger race conditions: https://portswigger.net/web-security/race-conditions ; https://portswigger.net/research/smashing-the-state-machine (accessed 2026-11-20)
- NIST SP 800-63B-4: https://csrc.nist.gov/pubs/sp/800/63/B/4/final ; https://pages.nist.gov/800-63-4/sp800-63b.html (accessed 2026-11-20)
- Salesloft Drift, GTIG: https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift (accessed 2026-11-20)
- RFC 9700: https://www.rfc-editor.org/info/rfc9700 (accessed 2026-11-20)
- PSD3 and PSR: https://www.hoganlovells.com/en/publications/final-texts-for-psd3-and-psr-awaited-as-european-parliament-and-council-of-eu-announce-provisional ; https://www.dlapiper.com/insights/publications/2026/03/psd3-and-psr (accessed 2026-11-20)
