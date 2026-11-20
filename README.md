# PhishWatch

PhishWatch is a controlled security-research lab for understanding link activity and building defensive phishing detection.

## Safety and scope

- Use only test links and email accounts you own or have explicit permission to test.
- The tracker records a timestamp, a coarse request classification, and browser user-agent for controlled testing.
- It does **not** collect passwords, OTPs, cookies, authorization headers, message contents, or precise IP addresses.
- It does not attempt to bypass Gmail, Safe Browsing, spam filters, or security scanners.
- Automated link scanners may visit links before a person does. PhishWatch labels likely automation as a heuristic, not proof.

## Requirements

- Node.js 18 or newer
- npm

## Run locally

```bash
npm install
npm start
```

Open <http://localhost:3000>.

## Included features

- Dashboard with recent controlled test-link events
- Generate a unique test URL
- Record GET/HEAD visits and classify likely automated requests
- Analyze a URL for common phishing indicators without visiting it

## Next steps

1. Add persistent database storage (SQLite).
2. Add configurable alert rules.
3. Add safe email-header analysis using sample `.eml` files.
4. Add tests and deployment guidance for a private, authorized test environment.

## Important interpretation note

A click event does not prove a human clicked. Email security gateways and preview systems may fetch links automatically. Treat user-agent and request-method signals as clues only.
