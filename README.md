# Web Security Skill for Claude Code, Codex and Gemini CLI

**An open-source AI agent skill for web security.** It teaches your AI assistant to review, harden and black-box test websites the way a practitioner does: find the weakest reachable path, prove every finding, fail closed and build the cheapest wall first. It also covers privacy and cookie consent compliance for EU, UK and US visitors.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/format-SKILL.md-orange.svg)](https://agentskills.io)
![Claude Code](https://img.shields.io/badge/Claude%20Code-supported-8A63D2)
![Codex](https://img.shields.io/badge/OpenAI%20Codex-supported-10A37F)
![Gemini CLI](https://img.shields.io/badge/Gemini%20CLI-supported-4285F4)

**Install in one line (Claude Code):**

```
/plugin install web-security --marketplace mayanthacreates/web-security-skill
```

## What you get

- **Findings with proof.** Every review comes back as one table: severity, finding, proof (how it was verified, or "unverified"), fix and why. No vague "consider adding security headers".
- **A playbook per site type.** Static and marketing sites, WordPress and headless CMS, e-commerce (including PCI DSS 4.0.1 6.4.3 and 11.6.1), SaaS and multi-tenant apps, marketplaces and user content, fintech and payments, healthcare and booking, public APIs and mobile backends.
- **A 2026 baseline for every site.** Headers and CSP (including the Next.js static rendering trade-off), auth per NIST SP 800-63B-4 and passkeys, sessions and cookies, secrets, bots and rate limits, DNS and email spoofing, npm supply chain (OWASP A03:2025) and AI chatbot risks (OWASP LLM Top 10).
- **Privacy and consent checks.** Cookie consent rules, Google Consent Mode v2, GDPR basics, CCPA/CPRA and Global Privacy Control, the European Accessibility Act and EU AI Act chatbot disclosure. General information, not legal advice.
- **A non-destructive black-box method,** free tools for each check, and a first-hour incident response plan.
- **Honest about dates.** Every time-sensitive fact is marked "as of 2026-11", and the skill lists what to re-verify before quoting it.

## Structure

```
skills/web-security/
├── SKILL.md                         philosophy, review table, decision framework,
│                                    universal baseline, router, black-box method,
│                                    incident response, review checklist
└── references/
    ├── static-marketing.md
    ├── wordpress-cms.md
    ├── ecommerce.md
    ├── saas-multitenant.md
    ├── marketplace-ugc.md
    ├── fintech-payments.md
    ├── healthcare-booking.md
    ├── apis-mobile-backends.md
    └── privacy-consent-compliance.md
```

The core stays small. Your agent loads a playbook only when the site type matches, so a WordPress audit never loads the fintech rules.

## Install

**Claude Code** (plugin, recommended - gets updates):

```
/plugin install web-security --marketplace mayanthacreates/web-security-skill
```

or in two steps: `/plugin marketplace add mayanthacreates/web-security-skill`, then `/plugin install web-security@mayanthacreates-security`.

**OpenAI Codex** (plugin):

```bash
codex plugin marketplace add mayanthacreates/web-security-skill
codex plugin add web-security@mayanthacreates-security
```

**Any agent** with the open-source [skills CLI](https://github.com/vercel-labs/skills):

```bash
npx skills add mayanthacreates/web-security-skill
```

**Manual install:**

```bash
git clone https://github.com/mayanthacreates/web-security-skill.git
cp -r web-security-skill/skills/web-security ~/.claude/skills/
```

For Codex use `~/.agents/skills/`, for Gemini CLI use `~/.gemini/skills/`. Restart the tool. The skill triggers on its own when a task matches, or you can ask for it by name.

## Use it responsibly

Only test sites you own or have written permission to test. The black-box method is non-destructive by design: no exploitation, no load testing, no brute force beyond a small, controlled rate-limit check.

## Contributing

Issues and pull requests are welcome. Add facts only with a source and an "as of" date, and mark anything you couldn't confirm as unverified. Never include secrets or anything that identifies a real site you assessed.

## License

MIT. See [LICENSE](LICENSE). Also by the same author: [marketing-frameworks-skill](https://github.com/mayanthacreates/marketing-frameworks-skill).
