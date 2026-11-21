# PhishWatch

PhishWatch is a local, controlled security-research lab for understanding link activity and inspecting suspicious URLs. Version **0.3.0**.

## Safety, privacy and scope

- Use only test links and accounts you own or have explicit permission to test.
- The tracker records a timestamp, HTTP method, test ID, test label, and a transparent classification explanation. A user-agent string is examined transiently (up to 300 characters) for classification but is not persisted.
- It does **not** collect passwords, OTPs, cookies, authorization headers, message contents, or IP addresses.
- It does not attempt to bypass Gmail, Safe Browsing, spam filters, or security scanners.
- A normal browser-like GET request is recorded as **Unclassified visit**, never as a confirmed human click.
- HEAD requests and recognizable automation/preview user-agent markers are labelled **Likely automated / preview** with Medium confidence. These are heuristics, not proof; user-agent strings can be missing or spoofed.
- The URL checker uses local heuristics. It does not visit submitted URLs, consult a threat-intelligence service, or guarantee that a URL is safe or malicious.
- The server binds to `127.0.0.1` by default. Keep it local. Do not set a public/network-facing host or expose the dashboard without first adding authentication, authorization, rate limits and an appropriate deployment review.

## Requirements

- Node.js 20 or newer
- npm (included with Node.js)
- Git (recommended for development)

## Run locally

```bash
npm install
npm start
```

Open <http://localhost:3000>.

For automatic restart during development:

```bash
npm run dev
```

Run the automated unit and integration tests:

```bash
npm test
```

On Windows PowerShell, if script execution policy blocks the npm PowerShell shim, use `npm.cmd` instead:

```powershell
npm.cmd install
npm.cmd test
npm.cmd start
```

## Features

- Dashboard for controlled test-link activity
- Unique random token per generated test link
- GET and HEAD request recording
- Transparent classification, confidence and plain-language evidence
- URL risk analysis without opening the submitted URL
- Local JSON storage with a bounded activity history
- Security headers, strict JSON request-size limit and API input validation
- Automated tests for classification, URL analysis, API behavior and tracking flows
- GitHub Actions test workflow

## API overview

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/health` | Health and version check |
| GET | `/api/events` | Read the latest 100 activity events |
| GET | `/api/campaigns` | List local test campaigns |
| POST | `/api/campaigns` | Create a controlled test link |
| POST | `/api/analyze-url` | Analyze a URL using local heuristics |
| GET / HEAD | `/t/:token` | Record an authorized test-link request |

The tracking endpoint rejects other HTTP methods. The dashboard and API are intended for local use, not as a public multi-user service.

## Local data

Runtime data is stored in `data/activity.json`. The data directory is ignored by Git so local test activity is not committed.

Optional environment settings:

- `PORT` — local server port (default: `3000`)
- `HOST` — bind address (default: `127.0.0.1`; changing this can expose the service to your network)
- `PHISHWATCH_BASE_URL` — base URL placed in generated test links (default: `http://localhost:<PORT>`)
- `PHISHWATCH_DATA_DIR` — alternate data directory, primarily useful for isolated tests

## Project structure

- `server.js` — Express application, HTTP routes and security headers
- `tracker.js` — local campaign and event storage
- `classifier.js` — transparent request classification
- `detector.js` — defensive URL heuristics
- `index.html`, `style.css`, `script.js` — dashboard
- `test/` — unit and API integration tests
- `data/` — runtime activity storage

## Interpreting results

A request to a tracking link does not prove a human clicked. Email security gateways, link-preview services, browser prefetching and other automated systems may request links. Conversely, automation can imitate a normal browser. Treat classification as an investigative clue, not a verdict.
