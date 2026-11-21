# PhishWatch

PhishWatch is a controlled security-research lab for understanding link activity and building defensive phishing detection.

## Safety and scope

- Use only test links and email accounts you own or have explicit permission to test.
- The tracker records a timestamp, HTTP method, limited user-agent string, test ID, and a transparent classification explanation.
- It does **not** collect passwords, OTPs, cookies, authorization headers, message contents, or IP addresses.
- It does not attempt to bypass Gmail, Safe Browsing, spam filters, or security scanners.
- A normal GET request is recorded as **Unclassified visit**, never as a confirmed human click.
- Known automation markers and HEAD requests are labelled **Likely automated / preview** with Medium confidence. These are heuristics, not proof; user-agent strings can be spoofed.
- Keep the application on localhost or another private, access-controlled test environment. Do not expose the dashboard publicly without adding authentication and appropriate operational safeguards.

## Requirements

- Node.js 18 or newer
- npm

## Run locally

```bash
npm install
npm start
```

Open <http://localhost:3000>.

For development with automatic restart:

```bash
npm run dev
```

Run the automated tests:

```bash
npm test
```

## Included features

- Dashboard with recent controlled test-link events
- Generate a unique test URL
- Record GET/HEAD visits with classification confidence and a plain-language reason
- Analyze a URL for common phishing indicators without visiting it
- Store local activity in `data/activity.json`

## Project structure

- `server.js` — Express application and API routes
- `tracker.js` — local campaign and event storage
- `classifier.js` — transparent request classification
- `detector.js` — defensive URL heuristics
- `index.html`, `style.css`, `script.js` — dashboard
- `test/` — automated tests
- `data/` — runtime activity storage

## Important interpretation note

A click event does not prove a human clicked. Email security gateways and preview systems may fetch links automatically. Treat user-agent and request-method signals as clues only. The URL checker is heuristic and cannot guarantee that a URL is safe or malicious.
