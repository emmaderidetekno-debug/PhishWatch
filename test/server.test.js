const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "phishwatch-test-"));
process.env.PHISHWATCH_DATA_DIR = dataDir;
const PASSWORD = "correct-horse-battery-staple";
process.env.PHISHWATCH_PASSWORD = PASSWORD;
process.env.PHISHWATCH_LOGIN_MAX_ATTEMPTS = "5";

const app = require("../server");
let server;
let baseUrl;
let sessionCookieHeader;

test.before(async () => {
  server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;

  const response = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password: PASSWORD })
  });
  assert.equal(response.status, 200);
  sessionCookieHeader = response.headers.getSetCookie()[0].split(";")[0];
});

test.after(async () => {
  if (server) await new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
  fs.rmSync(dataDir, { recursive: true, force: true });
});

function authed(route, options = {}) {
  return fetch(`${baseUrl}${route}`, {
    ...options,
    headers: { cookie: sessionCookieHeader, ...(options.headers || {}) }
  });
}

async function jsonRequest(route, body) {
  return authed(route, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
}

test("health endpoint reports the application version and security headers", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  const data = await response.json();
  assert.equal(response.status, 200);
  assert.equal(data.ok, true);
  assert.equal(data.version, "0.3.0");
  assert.equal(data.dashboardAuth, "required");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
  assert.equal(response.headers.get("x-powered-by"), null);
});

test("dashboard pages and data routes are closed without a session", async () => {
  const dashboard = await fetch(`${baseUrl}/`, { redirect: "manual" });
  assert.equal(dashboard.status, 302);
  assert.equal(dashboard.headers.get("location"), "/login");

  const script = await fetch(`${baseUrl}/script.js`, { redirect: "manual" });
  assert.equal(script.status, 302);

  for (const route of ["/api/events", "/api/campaigns"]) {
    const response = await fetch(`${baseUrl}${route}`);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: "Sign in to the PhishWatch dashboard first." });
  }

  const create = await fetch(`${baseUrl}/api/campaigns`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ label: "Unauthenticated" })
  });
  assert.equal(create.status, 401);

  const analyze = await fetch(`${baseUrl}/api/analyze-url`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.com" })
  });
  assert.equal(analyze.status, 401);
});

test("the login screen is public and sign-in issues an HttpOnly strict cookie", async () => {
  const page = await fetch(`${baseUrl}/login`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Dashboard sign-in/);

  const wrong = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password: "not-the-password" })
  });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.headers.get("set-cookie"), null);

  const missing = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({})
  });
  assert.equal(missing.status, 400);

  const good = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password: PASSWORD })
  });
  assert.equal(good.status, 200);
  const cookie = good.headers.getSetCookie()[0];
  assert.match(cookie, /^pw_session=[A-Za-z0-9_-]{43};/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Max-Age=28800/);
  assert.equal(cookie.includes("Secure"), false);
});

test("cross-origin state changes are rejected", async () => {
  const response = await authed("/api/campaigns", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://attacker.example" },
    body: JSON.stringify({ label: "CSRF attempt" })
  });
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: "Cross-origin requests are not allowed." });
});

test("campaign creation validates labels and returns a local test URL", async () => {
  const response = await jsonRequest("/api/campaigns", { label: "API integration test" });
  const data = await response.json();
  assert.equal(response.status, 201);
  assert.equal(data.campaign.label, "API integration test");
  assert.match(data.trackingUrl, /^http:\/\/localhost:3000\/t\/[a-f0-9]{36}$/);
  assert.equal(response.headers.get("ratelimit-limit"), "120");

  const listResponse = await authed("/api/campaigns");
  const listData = await listResponse.json();
  assert.equal(listData.campaigns[0].label, "API integration test");
  assert.equal(Object.hasOwn(listData.campaigns[0], "token"), false);

  const invalid = await jsonRequest("/api/campaigns", { label: 123 });
  assert.equal(invalid.status, 400);
});

test("tracking endpoint records GET as unclassified and HEAD as likely automated without a session", async () => {
  const created = await jsonRequest("/api/campaigns", { label: "Tracking integration test" });
  const campaign = await created.json();
  const route = new URL(campaign.trackingUrl).pathname;

  const getResponse = await fetch(`${baseUrl}${route}`, {
    headers: { "user-agent": "Mozilla/5.0 Chrome/120.0" }
  });
  assert.equal(getResponse.status, 200);
  assert.match(await getResponse.text(), /No password or personal credentials/);

  const headResponse = await fetch(`${baseUrl}${route}`, {
    method: "HEAD",
    headers: { "user-agent": "Controlled test client" }
  });
  assert.equal(headResponse.status, 204);

  const eventsResponse = await authed("/api/events");
  const { events } = await eventsResponse.json();
  assert.equal(events.length, 2);
  assert.equal(events[0].method, "HEAD");
  assert.equal(events[0].classification, "Likely automated / preview");
  assert.equal(events[0].confidence, "Medium");
  assert.equal(events[0].campaignLabel, "Tracking integration test");
  assert.equal(events[1].method, "GET");
  assert.equal(events[1].classification, "Unclassified visit");
  assert.equal(events[1].confidence, "Low");
  for (const event of events) {
    assert.equal(Object.hasOwn(event, "ip"), false);
    assert.equal(Object.hasOwn(event, "ipAddress"), false);
    assert.equal(Object.hasOwn(event, "userAgent"), false);
  }
});

test("tracking endpoint rejects unsupported methods and unknown tokens", async () => {
  const unsupported = await fetch(`${baseUrl}/t/not-a-token`, { method: "PUT" });
  assert.equal(unsupported.status, 405);
  assert.equal(unsupported.headers.get("allow"), "GET, HEAD");

  const missing = await fetch(`${baseUrl}/t/not-a-token`);
  assert.equal(missing.status, 404);
});

test("URL analysis validates input types and limits", async () => {
  const wrongType = await jsonRequest("/api/analyze-url", { url: 42 });
  assert.equal(wrongType.status, 400);

  const tooLong = await jsonRequest("/api/analyze-url", { url: "a".repeat(2049) });
  assert.equal(tooLong.status, 400);

  const unsafeScheme = await jsonRequest("/api/analyze-url", { url: "javascript:alert(1)" });
  const result = await unsafeScheme.json();
  assert.equal(unsafeScheme.status, 200);
  assert.equal(result.valid, false);
  assert.equal(result.risk, "High");
});

test("URL analysis accepts an observed redirect chain and validates it", async () => {
  const withChain = await jsonRequest("/api/analyze-url", {
    url: "https://news.example/a",
    chain: ["https://news.example/a", "https://paypa1.com/signin"]
  });
  const data = await withChain.json();
  assert.equal(withChain.status, 200);
  assert.equal(data.redirectAnalysis.chainHops, 2);
  assert.equal(data.redirectAnalysis.finalHost, "paypa1.com");

  const notArray = await jsonRequest("/api/analyze-url", { url: "https://example.com", chain: "https://x.example" });
  assert.equal(notArray.status, 400);

  const tooMany = await jsonRequest("/api/analyze-url", {
    url: "https://example.com",
    chain: Array.from({ length: 11 }, () => "https://x.example")
  });
  assert.equal(tooMany.status, 400);

  const badHop = await jsonRequest("/api/analyze-url", { url: "https://example.com", chain: [42] });
  assert.equal(badHop.status, 400);
});

test("CSV export neutralises spreadsheet formula triggers in a label", async () => {
  const label = '=HYPERLINK("http://example.invalid","click")';
  const created = await jsonRequest("/api/campaigns", { label });
  const body = await created.json();
  assert.equal(body.campaign.label, label);

  // The label only reaches the export once a visit is recorded against it.
  await fetch(`${baseUrl}${new URL(body.trackingUrl).pathname}`);

  const unauthenticated = await fetch(`${baseUrl}/api/events.csv`);
  assert.equal(unauthenticated.status, 401);

  const response = await authed("/api/events.csv");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/csv/);
  assert.match(response.headers.get("content-disposition"), /attachment; filename="phishwatch-activity\.csv"/);

  // Read raw bytes: fetch's text() decoder strips a UTF-8 BOM, which would hide
  // whether the attachment Excel needs is actually present.
  const raw = Buffer.from(await response.arrayBuffer());
  assert.deepEqual([raw[0], raw[1], raw[2]], [0xef, 0xbb, 0xbf], "export must start with a UTF-8 BOM");
  const csv = raw.toString("utf8");
  assert.equal(csv.startsWith("\ufeff"), true);

  const row = csv.split("\r\n").find(line => line.includes("HYPERLINK"));
  assert.ok(row, "expected the malicious label to appear in the export");
  assert.match(row, /"'=HYPERLINK\(""http:\/\/example\.invalid""/);
  assert.equal(/,?"=HYPERLINK/.test(row), false, "a raw formula must never be exported");
});

test("malformed JSON receives a controlled client error", async () => {
  const response = await authed("/api/campaigns", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{"
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "Request body must contain valid JSON." });
});

test("unknown routes return JSON 404 responses", async () => {
  const response = await fetch(`${baseUrl}/route-that-does-not-exist`);
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: "The requested resource was not found." });
});

test("generated links do not trust an untrusted Host header", async () => {
  const response = await authed("/api/campaigns", {
    method: "POST",
    headers: { "content-type": "application/json", host: "attacker.example" },
    body: JSON.stringify({ label: "Host header test" })
  });
  const data = await response.json();
  assert.equal(response.status, 201);
  assert.match(data.trackingUrl, /^http:\/\/localhost:3000\/t\//);
  assert.equal(data.trackingUrl.includes("attacker.example"), false);
});

test("sign-out revokes the session server-side", async () => {
  const login = await fetch(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password: PASSWORD })
  });
  const cookie = login.headers.getSetCookie()[0].split(";")[0];

  const logout = await fetch(`${baseUrl}/api/logout`, {
    method: "POST",
    headers: { cookie, "content-type": "application/json" }
  });
  assert.equal(logout.status, 204);
  assert.match(logout.headers.get("set-cookie"), /Max-Age=0/);

  const after = await fetch(`${baseUrl}/api/events`, { headers: { cookie } });
  assert.equal(after.status, 401);
});

test("repeated failed sign-ins are rate limited with Retry-After", async () => {
  let rateLimited = null;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const response = await fetch(`${baseUrl}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: `wrong-${attempt}` })
    });
    if (response.status === 429) {
      rateLimited = response;
      break;
    }
    assert.equal(response.status, 401);
  }

  assert.ok(rateLimited, "expected a 429 after repeated failed sign-ins");
  assert.match(rateLimited.headers.get("retry-after"), /^\d+$/);
  assert.equal(rateLimited.headers.get("ratelimit-remaining"), "0");
  assert.match((await rateLimited.json()).error, /Too many sign-in attempts/);
});
