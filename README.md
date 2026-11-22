# PhishWatch

PhishWatch is a local, controlled security-research lab for understanding link activity and inspecting suspicious URLs. Version **0.3.0**.

## Safety, privacy and scope

- Use only test links and accounts you own or have explicit permission to test.
- The tracker records a timestamp, HTTP method, test ID, test label, and a transparent classification explanation. A user-agent string is examined transiently (up to 300 characters) for classification but is not persisted.
- It does **not** collect passwords, OTPs, cookies, authorization headers, message contents, or IP addresses.
- It does not attempt to bypass Gmail, Safe Browsing, spam filters, or security scanners.
- A normal browser-like GET request is recorded as **Unclassified visit**, never as a confirmed human click.
- HEAD requests and recognizable automation/preview user-agent markers are labelled **Likely automated / preview** with Medium confidence. These heuristics are not proof; user-agent strings can be missing or spoofed.
- The URL checker uses local heuristics. It does not visit submitted URLs (including redirect hops supplied to it), consult a threat-intelligence service, or guarantee that a URL is safe or malicious.
- The dashboard requires authentication, and the API and tracking endpoint are rate limited (see below). The server still binds to `127.0.0.1` by default: keep it local. Publishing this lab on a public or network-facing host needs an additional review — TLS, durable session storage, real accounts and a WAF are all out of scope for a single-user local tool.

## Requirements

- Node.js 20 or newer
- npm (included with Node.js)
- Git (recommended for development)

## Run locally

```bash
npm install
npm start
```

Open <http://localhost:3000>. You are redirected to `/login` until you sign in.

**Choose a password before you start** (or let PhishWatch generate one):

```bash
# macOS / Linux
PHISHWATCH_PASSWORD='a-long-passphrase-you-pick' npm start
```

```powershell
# Windows PowerShell
$env:PHISHWATCH_PASSWORD='a-long-passphrase-you-pick'; npm start
```

If `PHISHWATCH_PASSWORD` is not set, PhishWatch generates a random password for that process and prints it once in the console, like this:

```
No PHISHWATCH_PASSWORD was set, so a one-time dashboard password was generated.
Dashboard password for this run: 5rG...qQ
It is not stored anywhere and changes on the next start.
```

There is no configuration in which the dashboard is served without authentication. Copying the generated password into the login form is the fastest way to get in for a one-off demo; setting `PHISHWATCH_PASSWORD` is what you want for repeatable use.

**Important:** generated tracking links use `localhost` and work only on the same computer running PhishWatch. They are useful for local browser testing, but they cannot be reached by an external email scanner or another device. Do not send these local-only links expecting remote recipients or mail gateways to reach your server.

### Seed a demo

```bash
npm run seed:demo
```

Writes one campaign plus seven representative visits (gateway HEAD probe, Safe Links fetch, Slack and Googlebot previews, a missing-user-agent request and a browser-like GET) so a walkthrough has real classification output without waiting for traffic. The server does not need to be running — the script writes through the same tracker the server reads.

Every seeded row is labelled **`[DEMO][MOCK] Interview walkthrough - synthetic visits`** in the Test column, so mock data cannot be mistaken for a real observation in the dashboard or in an exported CSV. Only the visits are fabricated; the classification and evidence text come from the real classifier. Re-running adds another demo campaign and prints a reminder. To remove the seeded data, delete `data/activity.json` and restart the server.

`demo-script.html` is a self-contained, printable one-page walkthrough of the whole demo (open it directly in a browser and print to PDF; it is deliberately not served by the app so print styles are not blocked by the app's CSP).

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

## Dashboard authentication

| Concern | Implementation |
|---|---|
| Password storage | Never stored. A scrypt-derived key (`N=16384`, per-process random salt) is held in memory and compared with `crypto.timingSafeEqual`. |
| Session | 32 random bytes, base64url, kept in an in-memory `Map` with an 8-hour expiry. Opaque to the client and revocable server-side on sign-out. |
| Cookie | `pw_session`, `HttpOnly`, `SameSite=Strict`, `Path=/`, `Max-Age=28800`, plus `Secure` automatically when the request arrived over HTTPS. |
| Sign-in route | `POST /api/login` accepts JSON, is rate limited, and rejects cross-origin requests. |
| Sign-out route | `POST /api/logout` destroys the session on the server *and* clears the cookie. |
| CSRF | `SameSite=Strict` plus an explicit `Origin`/`Host` match on every state-changing dashboard route (`POST /api/login`, `/api/logout`, `/api/campaigns`, `/api/analyze-url`). A cross-site form post gets `403`. |
| Unauthenticated dashboard request | HTML routes redirect `302` to `/login`; `/api/*` routes return `401` JSON instead of leaking whether data exists. |
| Unauthenticated tracking request | Allowed by design — see below. |

### What is deliberately *not* behind authentication

`GET`/`HEAD /t/:token` stays public. The whole point of the lab is that a browser following a test link is recorded; a link recipient cannot present a dashboard session, and requiring one would make the tracker measure nothing. It is still bounded:

- only `GET` and `HEAD` (anything else is `405` with `Allow: GET, HEAD`),
- unknown tokens are `404`,
- it is the most aggressively rate-limited route (60 requests/minute per source),
- it records the same non-identifying fields it always did, with no credentials, cookies, headers, referrer or address.

### Why these choices

- **scrypt + constant-time compare** makes an offline guess at the stored secret expensive if the process memory leaks, and hides which character of a wrong password was the mistake.
- **Opaque server-side sessions** beat signed stateless tokens here because sign-out must actually revoke access and a local lab has exactly one process. There is no key to leak into a cookie.
- **`SameSite=Strict` is the primary CSRF defence**; the `Origin` check is defence in depth for browser versions or clients that ignore the attribute.
- **`401` for API and `302` for pages** keeps a JSON client honest without rendering a dashboard shell to an unauthenticated visitor.

## Rate limiting

Limits are fixed-window, held in memory, and reset on restart. Every response carries `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`; a blocked request also gets `Retry-After`.

| Route | Limit | Window |
|---|---|---|
| `POST /api/login` | 5 attempts (configurable) | 15 minutes |
| Authenticated dashboard API (`/api/events`, `/api/campaigns`, `/api/analyze-url`) | 120 requests | 1 minute |
| `GET`/`HEAD /t/:token` | 60 requests | 1 minute |

- A **successful** sign-in clears the attempt counter for that source, so a legitimate operator is not locked out by their own earlier typos. Repeated failures are counted and the response is `429` with `Retry-After`.
- Buckets are keyed by `HMAC-SHA256(client address)` with a per-process random salt, truncated to 22 characters. The limiter can distinguish sources without ever holding or persisting a raw IP; nothing is written to `data/activity.json`.
- Proxy headers are not trusted (`app.set("trust proxy", false)`), so the bucket key is the real socket address. If you put a reverse proxy in front of PhishWatch, that setting must be reviewed, or every request will share the proxy's address.
- State is per process: a restart resets the counters, and a multi-instance deployment would need a shared store instead.

## Features

- Dashboard for controlled test-link activity
- One-command demo seed with clearly-labelled mock visits
- Password-protected dashboard with session cookies and server-side sign-out
- Rate limiting on sign-in, dashboard APIs and the tracking endpoint
- One-click copy for generated test links
- CSV export of the latest 100 activity records
- Unique random token per generated test link
- GET and HEAD request recording
- Transparent classification, confidence and plain-language evidence
- URL risk analysis without opening the submitted URL: brand-distance typosquatting, punycode decoding to a readable form, and redirect awareness
- Redirect chains can be analysed from hops you already observed, without the server following them
- Local JSON storage with a bounded activity history
- Security headers, strict JSON request-size limit and API input validation
- Automated tests for classification, URL analysis, authentication, rate limiting, API behavior and tracking flows
- GitHub Actions test workflow

## API overview

`Session` means the request must carry the `pw_session` cookie from `POST /api/login`.

| Method | Route | Session | Purpose |
|---|---|---|---|
| GET | `/api/health` | no | Health and version check |
| POST | `/api/login` | no | Exchange the dashboard password for a session cookie |
| POST | `/api/logout` | yes | Revoke the session and clear the cookie |
| GET | `/api/events` | yes | Read the latest 100 activity events |
| GET | `/api/campaigns` | yes | List local test campaigns (tokens are not returned) |
| POST | `/api/campaigns` | yes | Create a controlled test link |
| POST | `/api/analyze-url` | yes | Analyze a URL using local heuristics; optional `chain` array of observed hops |
| GET / HEAD | `/t/:token` | no | Record an authorized test-link request |

Signing in from a shell:

```bash
curl -c cookies.txt -X POST http://127.0.0.1:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"password":"your-dashboard-password"}'

curl -b cookies.txt http://127.0.0.1:3000/api/events
```

The tracking endpoint rejects other HTTP methods. The dashboard and API are intended for local use, not as a public multi-user service.

## URL checker: what it now detects

`POST /api/analyze-url` accepts `{ "url": "…" }` and, optionally, `{ "chain": ["https://hop1", "https://hop2"] }` for hops you already observed in mail headers or a proxy log. Nothing is fetched, resolved or clicked — not even a supplied hop.

| Check | Signal | Weight |
|---|---|---|
| Brand distance | A host segment within 2 edits (Damerau-Levenshtein, transpositions count once) of a brand name such as `paypal` or `microsoft` | 35 |
| Lookalike characters | Segment normalises to a brand after mapping `1→l`, `0→o`, Cyrillic/Greek homoglyphs and `rn→m` | 35 |
| Brand in registered domain | Exact brand text in the registrable label, outside the brand's own allowlist | 30 |
| Brand in subdomain | Brand text only in a subdomain, with the real registered domain named in the evidence | 20 |
| Punycode | Any `xn--` label, decoded per RFC 3492 and shown in readable form with its ASCII skeleton | 25 |
| Mixed scripts | Decoded hostname combines Latin with Cyrillic, Greek or another script | 20 |
| Embedded destination | A redirect parameter (`url`, `next`, `continue`, `return`, `redirect_uri`, …) carrying a different host | 20 each |
| Protocol-relative path | `//` inside the path, which some clients re-read as a new host | 10 |
| Double encoding | `%25xx` sequences hiding a second destination from scanners | 10 |
| Link shortener | Host on a known shortener list; the final destination is reported as unknown, never resolved | 10 |
| Supplied chain | Plain-HTTP hops, host changes, more than 3 hops, or a final hop impersonating a brand | 10–30 |

Redirect contributions are capped at 50 so a chain cannot single-handedly produce a High verdict. Brand comparison only runs against the hostname: a brand word in the path or query (`/search?q=paypal`) is not treated as a typosquat, which keeps false positives down.

Example: `http://paypa1-secure-login.verify-account.example.tld/login?update=1` scores 65 (HTTPS 20, account-themed path 10, `paypa1` one edit from `paypal` 35) and is reported as **High**, with `brandMatch.kind: "lookalike"`. Before brand distance existed it scored 30 and was only Medium.

## Local data

Runtime data is stored in `data/activity.json`. The data directory is ignored by Git so local test activity is not committed. Sessions and rate-limit buckets live only in memory and are never written to disk.

Environment settings:

- `PHISHWATCH_PASSWORD` — dashboard password. If unset, a random one is generated per process and printed at startup.
- `PHISHWATCH_LOGIN_MAX_ATTEMPTS` — sign-in attempts allowed per source per 15 minutes (default: `5`).
- `PORT` — local server port (default: `3000`).
- `HOST` — bind address (default: `127.0.0.1`; changing this exposes the service to your network, even though the dashboard now requires a password).
- `PHISHWATCH_BASE_URL` — base URL placed in generated test links (default: `http://localhost:<PORT>`).
- `PHISHWATCH_DATA_DIR` — alternate data directory, primarily useful for isolated tests.

## Project structure

- `server.js` — Express application, HTTP routes, security headers, authentication and rate-limit wiring
- `auth.js` — password verification, session store and cookie helpers
- `ratelimit.js` — in-memory fixed-window limiter keyed by hashed client address
- `tracker.js` — local campaign and event storage
- `classifier.js` — transparent request classification
- `detector.js` — defensive URL heuristics: brand distance, punycode decoding and offline redirect analysis
- `index.html`, `style.css`, `script.js` — dashboard
- `login.html`, `login.js` — sign-in screen
- `scripts/seed-demo.js` — `npm run seed:demo`, writes the labelled mock campaign and visits
- `demo-script.html` — printable one-page interview walkthrough
- `test/` — unit and API integration tests
- `data/` — runtime activity storage

## Interpreting results

A request to a tracking link does not prove a human clicked. Email security gateways, link-preview services, browser prefetching and other automated systems may request links. Conversely, automation can imitate a normal browser. Treat classification as an investigative clue, not a verdict.

## Known gaps

Worth stating before someone else finds them:

- Sessions are in memory: a restart signs everyone out, and there is only one operator account (no roles, no per-user audit trail).
- No TLS: the password crosses the loopback interface in clear text. That is acceptable on `localhost` and unacceptable anywhere else.
- No account lockout beyond the rate-limit window, no CAPTCHA, no MFA and no notification of failed sign-ins beyond a console line.
- No persistent audit log of authentication events.
- Rate-limit state is per process, so multiple instances would each allow their own quota.
