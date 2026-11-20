# Privacy, cookie consent and compliance

For any site with visitors from the EU, UK or US: cookie consent, Google Consent Mode v2, GDPR essentials, CCPA/CPRA and GPC, the European Accessibility Act, EU AI Act Art 50 for chatbots, and children's data (COPPA). Facts are as of 2026-11. Confidence: HIGH (primary text read), MED (secondary or primary via snippet), LOW (vendor or conflicting).

**General information, not legal advice.** Laws, regulator guidance and enforcement change. Confirm with a lawyer qualified in the relevant jurisdiction before relying on this for a client.

## Threat model

Here the "attacker" is a regulator, a plaintiff or a platform policy, and they test the same way you should: load the page in a clean browser and watch the network. The common failures:
- Trackers fire before consent.
- "Reject all" doesn't actually stop them.
- GPC is ignored.
- The chatbot never says it is an AI.
- The checkout can't be used with a keyboard.

## Recent enforcement

| Case | What went wrong | Confidence |
| --- | --- | --- |
| CNIL vs Google, EUR 325M (Sept 2025) | Ads in Gmail without consent; cookies on account creation. Google had added an equal reject option in 2023, but consent was still not informed | MED-HIGH |
| CNIL vs Shein, EUR 150M (Sept 2025) | Cookies set before any choice; "Reject all" still produced cookies | MED-HIGH |
| California AG vs Healthline, USD 1.55M (Jul 2025) | Opt-outs, including GPC, not honoured | MED |
| California AG vs Disney, USD 2.75M (Feb 2026) | GPC applied only to the device even when the user was logged in | MED |
| CPPA vs PlayOn Sports, USD 1.1M (Mar 2026) | Failed to honour GPC | MED |
| CPPA plus CA, CO and CT AGs joint sweep (Sept 2025) | Targeted GPC non-compliance | MED |
| FTC COPPA: Cognosphere USD 20M (Jan 2025), Apitor (Sep 2025, via an SDK), Disney USD 10M (Sep 2025) | Children's data | MED |

## 1. Cookie consent (EU ePrivacy plus GDPR, UK PECR)

### When consent is needed

- ePrivacy Directive Art 5(3): storing or reading information on a device needs clear information and consent, unless it is solely for transmission or strictly necessary for a service the user explicitly asked for. HIGH.
- The consent standard is GDPR's (Art 4(11), Art 7). HIGH.
- EDPB Guidelines 2/2023: Art 5(3) covers more than cookies, including pixels, URL tracking, local storage, unique identifiers and IP-based tracking. HIGH.
- Preference cookies the user chose (language, UI state) count as essential. HIGH.
- **Analytics is not "strictly necessary"** under the Directive. National exceptions:
  - France (CNIL): anonymous first-party audience measurement can be exempt within strict limits (13-month lifetime and 25-month retention cited). MED.
  - UK: a statistical-purposes exception since Feb 2026 (see below). MED.
  - Elsewhere: treat analytics as consent-required unless the national regulator says otherwise (unverified per country).
- **Safe default:** ask consent before analytics, ads, social pixels, session replay, A/B tools and embedded media that sets identifiers. Without consent, allow only session and auth, CSRF, cart, load balancing, security and the consent record itself.

### Banner design (regulator positions)

| Rule | Position | Confidence |
| --- | --- | --- |
| Reject as easy as accept | Most EU regulators treat a banner with no reject option on the layer that has "Accept" as an infringement (EDPB taskforce). A few accept reject on a second layer | HIGH |
| CNIL standard | "Accept all" and "Reject all" at the same level and in the same format; one-click accept with multi-step refuse biases the choice | HIGH |
| No pre-ticked boxes | Not valid consent (GDPR recital 32; EDPB 05/2020) | HIGH |
| No cookie walls | Access can't depend on consenting (EDPB 05/2020) | HIGH |
| Scrolling is not consent | EDPB 05/2020 | HIGH |
| Links instead of reject buttons | Flagged as problematic | MED |
| "Legitimate interest" toggles for ad cookies | Not valid for ePrivacy-covered access | MED |
| Consent or pay | EDPB Opinion 08/2024, aimed at large platforms: a real alternative is needed | MED |

Ship "Reject all" on the first layer with the same size and prominence as "Accept all". That satisfies the CNIL and the EDPB majority view, and it's the safe UK default (ICO primary text couldn't be read; unverified).

### Granularity, withdrawal, records, re-consent

- **Granularity:** per-purpose choice, with accept all and reject all on the first layer and per-purpose controls one click away (a "Customise" button at the same level is fine). HIGH (CNIL).
- **Withdrawal:** as easy as giving consent (GDPR Art 7(3)). Keep a permanent "Manage cookies" link or icon, and make withdrawal actually stop reading and writing. HIGH.
- **Records:** you must be able to prove consent (Art 7(1)); Google's EU User Consent Policy also requires records. Store a timestamp, banner and policy version, per-purpose choices and a random consent ID. HIGH.
- **Re-consent:** EU law sets no fixed period. The CNIL calls keeping both consent and refusal for 6 months good practice. Don't present 12 months as a legal rule. Ask again when purposes or vendors change materially, and don't re-ask on every page after a refusal. HIGH.

### UK: Data (Use and Access) Act 2025 and PECR

- PECR fines raised to up to GBP 17.5M or 4% of global turnover, in force 5 Feb 2026 per law-firm summaries. MED.
- Three new consent exceptions since Feb 2026, each valid only when used **solely** for that purpose. MED:
  - Statistics to improve the site, with information and a simple, free opt-out. A third-party tool qualifies only as a processor.
  - Appearance and functionality preferences (language, screen size, dark mode). Not interest-based tailoring.
  - Emergency location.
  - Advertising-related analytics stays outside these exceptions.
- ICO final guidance on storage and access technologies was published 29 Apr 2026. MED.
- EU adequacy for the UK was renewed to 27 Dec 2031. MED.

### EU Digital Omnibus: still a proposal

The Commission proposed it in Nov 2025 (moving cookie rules into GDPR, a browser-signal duty, a 96-hour breach window). The Council agreed its mandate on 21 Oct 2026 (secondary reports say it keeps cookie rules in ePrivacy, sets a 4-month wait after a refusal, and drops the browser-signal duty, but a June 2026 Council document still had it). Parliament has no position yet. **Nothing in it changes today's rules.** GDPR breach notice stays at 72 hours. MED.

## 2. Google Consent Mode v2

- Four consent types: `ad_storage`, `analytics_storage`, plus `ad_user_data` and `ad_personalization` (added Nov 2023). HIGH.
- Google's EU User Consent Policy (EEA, UK, Switzerland) requires consent where the law requires it and for personal data used to personalise ads, keeping records, and withdrawal instructions. It is a contract requirement, not a statute. HIGH.
- **Basic mode:** tags are blocked until the user interacts with the banner; refusal sends nothing. **Advanced mode:** tags load with consent denied and send cookieless pings (consent state, timestamp, user agent, referrer, a random number). Whether those pre-consent pings are lawful under Art 5(3) isn't settled by any ruling found (unverified). For minimum regulatory risk in the EU and UK, use basic mode and flag the choice to the client as a risk decision.
- Set defaults **before** any `config` or `event` command, scoped by region; use `wait_for_update` for async banners. HIGH.

```html
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('consent', 'default', {
    ad_storage: 'denied', analytics_storage: 'denied',
    ad_user_data: 'denied', ad_personalization: 'denied',
    region: ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IS','IT','LV','LI','LT','LU','MT','NL','NO','PL','PT','RO','SK','SI','ES','SE','GB','CH'],
    wait_for_update: 500 // region = EEA + UK + CH; check the list before shipping
  });
  // The CMP calls gtag('consent', 'update', {...}) after the user's choice.
</script>
```

- Personalised ads need both `ad_user_data` and `ad_personalization` granted. MED.
- To serve personalised ads through AdSense, Ad Manager or AdMob in the EEA, UK and Switzerland, Google requires a Google-certified CMP integrated with IAB TCF. MED.
- **IAB TCF** matters only if you run programmatic ads. v2.3 strings without `disclosedVendors` are invalid since the 28 Feb 2026 cut-off (HIGH). v2.4 web deadline 23 Oct 2026, apps and CTV 23 Feb 2027 (MED). Your CMP vendor handles it.

## 3. GDPR essentials for a website

- **Scope:** applies to non-EU sites that offer goods or services to, or monitor, people in the EU (Art 3(2)). Being reachable from the EU isn't enough on its own. HIGH.
- **Lawful basis** per purpose (Art 6(1)): consent, contract, legal obligation, vital interests, public task or legitimate interests. For ePrivacy-covered cookies, consent is the route.
- **Privacy notice at collection (Art 13):** controller identity and contact, DPO if any, purposes and legal basis, legitimate interests relied on, recipients, third-country transfers and safeguards, retention, rights, the right to withdraw consent and to complain, and automated decision-making. HIGH, with the last items unverified in the extract read.
- **Rights requests:** answer within one month, extendable by two months for complex requests with notice (Art 12(3)). HIGH.
- **Breach:** notify the supervisory authority without undue delay and where feasible within 72 hours of awareness, unless it is unlikely to cause risk (Art 33). HIGH.
- **Processors (Art 28):** sign DPAs with the host, email provider, analytics, CRM, chat widget and payment processor. HIGH.
- **Records of processing (Art 30):** the under-250-staff exemption doesn't apply if processing is regular, risky or involves special-category data, so most sites still need records. HIGH.
- **EU representative (Art 27):** required when Art 3(2) applies, unless processing is occasional and low-risk. Most regular e-commerce or lead-gen sites aimed at the EU won't count as occasional. HIGH.
- **Special categories (Art 9)** include health data. **Children:** consent age 16 for online services, which member states may lower to 13 (Art 8). HIGH.
- **Fines:** up to EUR 10M or 2%, and EUR 20M or 4% of global turnover, whichever is higher (Art 83). HIGH.
- **EU-US transfers:** the Data Privacy Framework stands. The General Court dismissed the Latombe challenge on 3 Sep 2025, and an appeal is pending as C-703/25 P with no ruling found. Use DPF-certified recipients and keep SCCs as a fallback for key vendors (standard practice). MED.

## 4. US privacy

### California (CCPA/CPRA)

- **Thresholds, any one of:** annual gross revenue over USD 26,625,000 (CPI-adjusted from 1 Jan 2025); buying, selling or sharing PI of 100,000+ California consumers or households; 50%+ of revenue from selling or sharing PI. The AG's FAQ still shows USD 25M. Thresholds re-adjust every odd-numbered year. HIGH.
- **Penalties:** up to USD 2,663 per violation, USD 7,988 per intentional violation or one involving known minors under 16; breach statutory damages USD 107-799 per consumer. HIGH.
- **"Do Not Sell or Share My Personal Information"** link if you sell or share. No account needed to opt out. Honour the request within 15 business days and wait 12 months before asking again. HIGH.
- **GPC must be honoured** as a valid opt-out request. HIGH.
- New regulations effective 1 Jan 2026; ADMT provisions from 1 Jan 2027 (MED). Opt-out preference signal rulemaking status conflicts between sources; check the CPPA. AB 566 requires browsers to offer an opt-out signal from 1 Jan 2027 (MED).

### GPC mechanics

- Request header `Sec-GPC: 1` (exactly "1"); `navigator.globalPrivacyControl` in JS; optional `/.well-known/gpc.json`. GPC means do-not-sell-or-share, not deletion. HIGH.
- Brave and DuckDuckGo send it natively, Firefox has a setting, and Privacy Badger, Disconnect and OptMeowt extensions add it.

```ts
// Honour GPC server-side for the browser AND the logged-in account (the Disney lesson)
const gpc = req.headers.get("sec-gpc") === "1";
if (gpc) {
  disableSaleAndSharing(res);                        // suppress ad pixels and data-sharing tags
  if (session?.userId) await setOptOut(session.userId); // persist across devices
}
```

### Other US states

- New laws in force 1 Jan 2026 in Indiana, Kentucky and Rhode Island. Counts of states with laws vary (20 to 24 depending on what is counted). Colorado and Connecticut consistently require universal opt-out signals; other lists name more states. MED to LOW, so check state AG pages.
- **Engineering default:** honour GPC for all US visitors, and persist it to logged-in accounts.

## 5. European Accessibility Act (Directive (EU) 2019/882)

- Applies to **e-commerce services** from 28 Jun 2025: services at a distance through websites and apps aimed at concluding a consumer contract. HIGH.
- **Microenterprise exemption** for services: fewer than 10 people and turnover or balance sheet of EUR 2M or less. HIGH.
- Disproportionate burden can be claimed with an assessment renewed at least every five years. HIGH.
- Existing websites are **not** grandfathered. Only products in use before 28 Jun 2025 and contracts concluded before then get a transition (to 2030 and up to five years). HIGH.
- Harmonised standard: EN 301 549 (v3.2.1, aligned with WCAG 2.1 AA). A v4.1.1 publication is reported but unverified. Enforcement is national and uneven. LOW-MED.
- **Practical:** target WCAG 2.1 AA (2.2 AA is a safe superset) across the whole purchase journey, including the consent banner itself.

## 6. EU AI Act Art 50 (chatbots)

- **Art 50(1):** AI systems that interact with people must tell them they're interacting with an AI, unless it's obvious. **Art 50(5):** the information must be given clearly at the latest at first interaction, and be accessible. HIGH.
- The AI Act applies from 2 Aug 2026 generally. The AI Omnibus (Regulation (EU) 2026/1744) did **not** postpone Art 50(1), (3), (4) or (5). Generative systems placed on the market before 2 Aug 2026 must meet Art 50(2) output marking by **2 Dec 2026**. HIGH.
- **Practical:** show "You're chatting with an AI assistant" before or at the first message, not only in the footer, and don't give the bot a persona that implies a human. Art 50(2) marking falls on the provider (the model vendor, or you if you build it). A site embedding a vendor's bot is normally a deployer, but that split needs a lawyer (unverified).

## 7. Children's data

- **COPPA (US):** amended rule effective 23 Jun 2025, compliance due 22 Apr 2026. It requires separate verifiable parental consent before disclosing children's data to third parties (advertising and AI training are unlikely to qualify as "integral"), a written information security program, a posted data retention policy with no indefinite retention, and it adds biometric identifiers to personal information. HIGH to MED-HIGH.
- If a site is child-directed or knows it has users under 13, audit third-party SDKs and pixels first (the Apitor case came through an SDK). An age gate alone doesn't remove COPPA duties for a child-directed site.
- GDPR Art 8: consent age 16, which member states may lower to 13.
- State kids' codes and age-verification laws were not researched.

## Checklist

### MUST

1. **No non-essential trackers before consent** for EU and UK visitors. Verify: test A below.
2. **"Reject all" on the first layer, equal prominence; no pre-ticked boxes, no cookie wall, no scroll-to-consent.** Verify: test A step 9.
3. **Reject and withdraw actually stop the trackers and clear the cookies** (the Shein lesson). Verify: test A steps 5-6.
4. **Consent records stored** (timestamp, version, choices, random ID). Verify: ask for an export.
5. **Consent Mode defaults set to denied before any tag fires** in EEA, UK and CH. Verify: test A step 10.
6. **GPC honoured for the browser and the logged-in account; a "Do Not Sell or Share" link if you sell or share.** Verify: test B.
7. **A privacy notice at each collection point** with the Art 13 items. Verify: inspect forms, checkout and newsletter.
8. **DPAs with every processor; a rights-request process on a one-month clock; a breach runbook on a 72-hour clock.** Verify: ask the owner.
9. **AI disclosure at the first chatbot message.** Verify: open the chat.
10. **Store purchase journey at WCAG 2.1 AA** if selling to EU consumers and not a microenterprise. Verify: axe or Lighthouse plus a keyboard-only run through checkout and the banner.

### SHOULD

11. Records of processing (Art 30) and an EU representative where Art 27 applies.
12. Basic Consent Mode in the EU and UK unless the client accepts the advanced-mode risk in writing.
13. Self-hosted fonts and analytics to reduce the consent surface. Fonts loaded from Google disclose the visitor's IP.
14. An accessibility statement.
15. SDK and pixel audit on any site that may have children as users.

### NICE

16. A Playwright check in CI that loads the site with and without consent and with `Sec-GPC: 1` and fails on unexpected third-party requests.
17. Blacklight scans after every tag change.

## Black-box tests (own or owner-authorised sites only)

These are standard practice, not regulator-published procedures.

**A. Pre-consent test (EU/UK)**
1. Fresh browser profile or private window; clear site data; use an EU location if the site geo-gates.
2. DevTools Network tab: "Preserve log" on, cache disabled. Load the homepage **without touching the banner**.
3. Filter third-party domains. Expect none to analytics, ads or social pixels (google-analytics.com, googletagmanager.com collect calls, doubleclick.net, facebook.com/tr, TikTok, Hotjar, Clarity) before consent.
4. Application tab: cookies, Local Storage, Session Storage and IndexedDB hold only essential items. Check `Set-Cookie` on the first HTML response too.
5. Click **Reject all**, reload, repeat steps 3-4, and confirm previously set non-essential cookies are gone.
6. Click **Accept all** and confirm trackers fire; then withdraw via "Manage cookies" and confirm requests stop and cookies clear.
7. Enable one category only (for example analytics) and confirm ad requests stay silent.
8. Reload and revisit: the banner doesn't reappear on every page, and the stored choice has a stated lifetime.
9. Banner design: reject on layer one, same size and format as accept, no pre-ticked toggles, no cookie wall, keyboard and screen-reader operable.
10. Consent Mode: in the console, `dataLayer` shows `['consent','default',{...}]` before any `config`, all four types denied in the EEA, UK and Switzerland, then an `update` after the choice. Basic mode sends no Google requests before interaction; advanced mode sends cookieless pings with consent denied. (The meaning of the `gcs=` and `gcd=` parameters is unverified.)

**B. GPC test (US)**
1. Turn on GPC (Brave by default, Firefox setting, or Privacy Badger or OptMeowt). Confirm `navigator.globalPrivacyControl === true`.
2. `curl -sI -H 'Sec-GPC: 1' https://example.com/` confirms the server receives it, but a HEAD can't prove it is honoured, so:
3. In a clean profile (US IP if geo-gated), compare third-party ad and data-sharing requests with and without GPC. Sale and sharing requests should stop. Regulators ran exactly this test in the Healthline, Disney and PlayOn cases.
4. Logged in: the opt-out persists to the account and other devices.
5. Check `/.well-known/gpc.json` (`gpc: true` only if you honour it).
6. A "Do Not Sell or Share" link is on the home page if you sell or share, and works without an account.

**Tools:** DevTools and Google Tag Assistant are primary evidence. Blacklight (The Markup) scans trackers, session recording and pixels, but its results are indicative, not proof of a violation. Vendor cookie scanners are fine for inventory but weren't verified for this skill.

## Sources

- ePrivacy Directive 2002/58/EC: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32002L0058 (accessed 2026-11-20)
- GDPR (EU) 2016/679: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679 (accessed 2026-11-20)
- EDPB Guidelines 2/2023: https://edpb.europa.eu/system/files/2024-10/edpb_guidelines_202302_technical_scope_art_53_eprivacydirective_v2_en_0.pdf (accessed 2026-11-20)
- EDPB Cookie Banner Taskforce report: https://www.edpb.europa.eu/system/files/2023-01/edpb_20230118_report_cookie_banner_taskforce_en.pdf (accessed 2026-11-20)
- CNIL consolidated cookie recommendation (16 Jan 2026): https://cnil.fr/sites/default/files/2026-01/recommandation_cookies_consolidee.pdf (accessed 2026-11-20)
- CNIL audience measurement (via search): https://cnil.fr/fr/cookies-solutions-pour-les-outils-de-mesure-daudience (accessed 2026-11-20)
- EDPB Guidelines 05/2020 on consent: https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en (accessed 2026-11-20)
- EDPB Opinion 08/2024: https://www.edpb.europa.eu/our-work-tools/our-documents/opinion-board-art-64/opinion-082024-valid-consent-context-consent-or_en (accessed 2026-11-20)
- CNIL Google and Shein fines: https://cnil.fr/en/cookie-regulation-cnil-continuing-action-plan-initiated-2019-and-has-imposed-two-fines-shein-and ; https://www.theregister.com/2025/09/04/france_google_shein_cookie_fines/ (accessed 2026-11-20)
- ICO final storage and access guidance (403 on fetch, via secondaries): https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2026/04/final-storage-and-access-technologies-guidance-published/ (accessed 2026-11-20)
- Osborne Clarke, UK data law outlook: https://www.osborneclarke.com/insights/regulatory-outlook-may-2026-data-law (accessed 2026-11-20)
- Osborne Clarke, PECR exceptions: https://marketinglaw.osborneclarke.com/advertising-regulation/new-exceptions-explained-in-ico-final-guidance-on-storage-and-access-technologies-could-online-advertising-be-next/ (accessed 2026-11-20)
- UK adequacy renewal: https://www.freeths.co.uk/insights-events/legal-articles/2026/european-commission-renews-uk-adequacy-decisions-until-27-december-2031/ (accessed 2026-11-20)
- Digital Omnibus: https://www.cuatrecasas.com/en/global/intellectual-property/art/digital-omnibus-eu-council-establishes-position ; https://ppc.land/eu-council-agrees-4-month-cookie-re-ask-wait-for-digital-omnibus-talks/ ; https://data.consilium.europa.eu/doc/document/ST-9773-2026-REV-1/en/pdf (accessed 2026-11-20)
- Google EU User Consent Policy: https://www.google.com/about/company/user-consent-policy/ (accessed 2026-11-20)
- Google consent guide: https://developers.google.com/tag-platform/security/guides/consent (accessed 2026-11-20)
- Google consent mode concepts: https://developers.google.com/tag-platform/security/concepts/consent-mode (accessed 2026-11-20)
- Google Ads EEA consent mode: https://support.google.com/google-ads/answer/13695607 (accessed 2026-11-20)
- Google CMP requirements: https://support.google.com/adsense/answer/13554116 (accessed 2026-11-20)
- IAB Europe TCF v2.3: https://iabeurope.eu/all-you-need-to-know-about-the-transition-to-tcf-v2-3/ (accessed 2026-11-20)
- IAB Europe TCF v2.4 timeline: https://iabeurope.eu/wp-content/uploads/TCF_V-CMP_comms_TCFpoliciesV5.0.bAndSpecificationsV2.4ConfirmationOf-theTimeline_160726_IABEurope.pdf (accessed 2026-11-20)
- DPF appeal C-703/25 P: https://eur-lex.europa.eu/eli/C/2025/6610/oj (accessed 2026-11-20)
- General Court T-553/23: https://iapp.org/news/a/european-general-court-dismisses-latombe-challenge-upholds-eu-us-data-privacy-framework (accessed 2026-11-20)
- California AG CCPA: https://oag.ca.gov/privacy/ccpa (accessed 2026-11-20)
- CPPA thresholds: https://www.cppa.ca.gov/regulations/cpi_adjustment.html (accessed 2026-11-20)
- CPPA regulations: https://cppa.ca.gov/regulations/ (accessed 2026-11-20)
- CPPA Aug 2026 materials: https://cppa.ca.gov/meetings/materials/20260806_07_02.pdf (accessed 2026-11-20)
- W3C GPC spec: https://w3c.github.io/gpc/ (accessed 2026-11-20)
- Global Privacy Control: https://globalprivacycontrol.org/ (accessed 2026-11-20)
- Healthline settlement: https://www.insideprivacy.com/ccpa/california-attorney-general-announces-1-55m-ccpa-settlement-with-healthline-com/ (accessed 2026-11-20)
- Disney settlement: https://www.cooley.com/news/insight/2026/2026-03-25-a-tale-as-old-as-2020-landmark-2-75-million-ccpa-enforcement (accessed 2026-11-20)
- PlayOn fine: https://www.hklaw.com/en/insights/publications/2026/03/calprivacy-fines-playon-sports-1-1m-for-ccpa-opt-out-and-notice (accessed 2026-11-20)
- CPPA sweep: https://cppa.ca.gov/announcements/2025/20250909.html (accessed 2026-11-20)
- Multistate, 2026 state laws: https://multistate.us/insider/2026/2/4/all-of-the-comprehensive-privacy-laws-that-take-effect-in-2026 (accessed 2026-11-20)
- IAPP, Indiana, Kentucky, Rhode Island: https://iapp.org/news/a/new-year-new-rules-us-state-privacy-requirements-coming-online-as-2026-begins (accessed 2026-11-20)
- Benesch, 2026 enactments: https://www.beneschlaw.com/insight/the-privacy-patchwork-grows-alabama-louisiana-oklahoma-and-vermont-join-the-compliance-landscape/ (accessed 2026-11-20)
- European Accessibility Act 2019/882: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32019L0882 (accessed 2026-11-20)
- EAA enforcement (secondary): https://www.taylorwessing.com/en/insights-and-events/insights/2026/06/the-eaa-and-bfsg-recap-and-update (accessed 2026-11-20)
- AI Act 2024/1689: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32024R1689 (accessed 2026-11-20)
- AI Omnibus 2026/1744: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32026R1744 (accessed 2026-11-20)
- FTC COPPA final rule: https://www.govinfo.gov/content/pkg/FR-2025-04-22/html/2025-05904.htm (accessed 2026-11-20)
- Davis Polk COPPA update: https://www.davispolk.com/insights/client-update/ftc-prioritizes-coppa-enforcement-new-compliance-obligations-take-effect (accessed 2026-11-20)
- Blacklight: https://themarkup.org/Blacklight (accessed 2026-11-20)
