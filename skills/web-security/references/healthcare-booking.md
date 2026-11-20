# Healthcare, clinics and booking sites

Clinic sites with online booking, patient portals, symptom or treatment pages, patient uploads. Apply the Universal Baseline in SKILL.md and the consent rules in [privacy-consent-compliance.md](privacy-consent-compliance.md). Facts are as of 2026-11. This playbook covers generic health-data handling; it doesn't cover any one country's health regulator. Check which health-data rules apply where the clinic is licensed.

Privacy and health-data content here is general information, not legal advice.

## Threat model

A "simple" booking form becomes health data the moment it records a treatment or symptom, even if nobody types a diagnosis. Under GDPR, health data is a special category (Art 9). The main leaks are rarely hacks:
- Third-party trackers (Meta Pixel, Google Analytics, chat widgets) sending appointment and condition data to ad platforms.
- Open storage and IDOR holding ID, insurance and medical uploads.
- Booking abuse: slot hoarding, fake bookings, SMS pumping through confirmation texts, patient enumeration through "already registered" messages.

## Recent incidents

| Issue | Evidence | Confidence |
| --- | --- | --- |
| Trackers leaking appointment and condition data | US hospital settlements in 2025 over Meta Pixel and similar trackers: Jefferson Healthcare, Pomona Valley (USD 600K fund), Eisenhower (USD 875K fund), LCMC Health, TrueCare and others. US-law context, but the technical mechanism is identical on any clinic site | MED |
| Open storage and IDOR on sensitive uploads | Tea (ID photos and selfies in an open bucket), McHire (IDOR on applicant chats). The same pattern applies to insurance cards, X-rays and referral letters | MED |
| Booking abuse | No primary incident found. Threat model only (unverified): slot-hoarding bots, fake bookings to block competitors, SMS pumping via confirmation texts, enumeration of patients | LOW |

## Checklist

### MUST

1. **Data minimisation on public forms**: collect only what booking needs (name, contact, preferred slot, service). No clinical history, medications, government ID or insurance numbers on the public form; collect those in clinic or in an authenticated portal.
   Verify: walk the form and list every field; flag any health or ID field.
2. **No third-party marketing trackers on pages or forms where a user reveals health information** (booking confirmation, treatment pages that carry identifiers, the portal). Load analytics only after consent, and strip URL parameters and form values from events.
   Verify: open the booking flow in a clean browser profile with the DevTools Network tab; list third-party requests at each step; inspect payloads for name, phone and treatment values and for `fbq`, `gtag` or chat-widget calls before consent.
3. **TLS everywhere with HSTS. Booking confirmation emails and SMS carry no clinical detail**, only date, time and clinic name.
   Verify: read a test confirmation email and SMS.
4. **Object-level authorization on appointment and patient records; random, unguessable booking references; no PII in URLs** (OWASP API1).
   Verify: with two test patients, request each other's booking ID; "manage my booking" links need a signed token or OTP, not just an ID.
5. **No user enumeration** in "already registered", "find my booking" and password reset.
   Verify: submit a known and an unknown phone or email; messages and timing are identical.
6. **Rate limit and Turnstile on booking, OTP and contact forms**; cap pending bookings per phone and IP; OTP send caps against SMS pumping.
   Verify: as marketplace-ugc.md items 7 and 10.
7. **Private storage for uploads** (insurance card, X-ray, ID) with signed, expiring URLs; admin access logged.
   Verify: open an upload URL in a logged-out browser; expect denial.
8. **Know where health data goes.** List every processor that receives form data: form backend, email provider, CRM, messaging API, analytics, chat widget. Check each has a processor agreement (GDPR Art 28) and a lawful transfer basis, and check the clinic's local health-data rules on hosting location.
   Verify: map the front-end endpoints with DevTools and DNS or ASN lookups; the rest needs a vendor questionnaire.
9. **A privacy notice at the point of collection** covering what, why, who receives it and how to exercise rights (GDPR Art 13 where it applies).
   Verify: a notice link sits next to the form and names processors and transfers.
10. **A tested path to answer access requests within one month** (GDPR Art 12(3), extendable by two months for complex requests).
    Verify: ask the owner to show the procedure.
11. **A breach response plan with named contacts.** Under GDPR, notify the supervisory authority within 72 hours of awareness (Art 33). See the incident steps in SKILL.md.
    Verify: ask for the plan.

### SHOULD

12. Marketing consent kept separate from booking consent.
13. Back-office access control: roles, MFA, access logging for booking and CRM tools. Treat inappropriate staff access to patient data as a breach.
14. A retention schedule; delete stale booking data.
15. Restrict chat and email transcripts of health questions; avoid medical images over consumer chat apps unless policy allows.
16. Check advertising claims and before/after images against the clinic's local advertising rules before publishing.
17. Pen-test the booking back office, not just the public site.

### NICE

18. Self-hosted or privacy-first analytics with no cross-site identifiers.
19. Passkey or OTP login for the patient portal.
20. Appointment reminders through app push instead of SMS.

## Gotchas

- Tag managers let marketing add pixels later without a code review. Control GTM access and publish rights.
- A third-party "online booking widget" makes the vendor your processor and possibly a cross-border transfer of health data.
- Session replay and heatmap tools record form fields by default. Check their masking settings on every health form.
- A confirmation SMS that names the treatment leaks health data to anyone who sees the phone's lock screen.

## Sources

- GDPR (EU) 2016/679, Arts 9, 12, 13, 28, 33: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679 (accessed 2026-11-20)
- OWASP API Security Top 10 2023: https://api-security.owasp.org/editions/2023/en/0x11-t10 (accessed 2026-11-20)
- HIPAA Journal, Jefferson Healthcare Meta Pixel settlement: https://www.hipaajournal.com/jefferson-healthcare-meta-pixel-class-action-settlement/ (accessed 2026-11-20)
- HIPAA Journal, LCMC Health Meta Pixel settlement: https://www.hipaajournal.com/lcmc-health-meta-pixel-settlement/ (accessed 2026-11-20)
- Bloomberg Law, TrueCare: https://news.bloomberglaw.com/litigation/truecare-reaches-agreement-to-drop-patients-meta-pixel-suit (accessed 2026-11-20)
- Tea app breach: https://fortune.com/2025/07/26/tea-app-hack-images-online-leaks-users-selfies/ (accessed 2026-11-20)
- McHire: https://www.bleepingcomputer.com/news/security/123456-password-exposed-chats-for-64-million-mcdonalds-job-applications/ (accessed 2026-11-20)
- Twilio toll fraud prevention (vendor): https://www.twilio.com/docs/verify/preventing-toll-fraud (accessed 2026-11-20)
