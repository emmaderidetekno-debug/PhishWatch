const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "phishwatch-test-"));
process.env.PHISHWATCH_DATA_DIR = dataDir;

const app = require("../server");
let server;
let baseUrl;

test.before(async () => {
  server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

test.after(async () => {
  if (server) await new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function jsonRequest(route, body) {
  return fetch(`${baseUrl}${route}`, {
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
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
  assert.equal(response.headers.get("x-powered-by"), null);
});

test("campaign creation validates labels and returns a local test URL", async () => {
  const response = await jsonRequest("/api/campaigns", { label: "API integration test" });
  const data = await response.json();
  assert.equal(response.status, 201);
  assert.equal(data.campaign.label, "API integration test");
  assert.match(data.trackingUrl, /^http:\/\/localhost:3000\/t\/[a-f0-9]{36}$/);

  const listResponse = await fetch(`${baseUrl}/api/campaigns`);
  const listData = await listResponse.json();
  assert.equal(listData.campaigns[0].label, "API integration test");
  assert.equal(Object.hasOwn(listData.campaigns[0], "token"), false);

  const invalid = await jsonRequest("/api/campaigns", { label: 123 });
  assert.equal(invalid.status, 400);
});

test("tracking endpoint records GET as unclassified and HEAD as likely automated", async () => {
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

  const eventsResponse = await fetch(`${baseUrl}/api/events`);
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

test("malformed JSON receives a controlled client error", async () => {
  const response = await fetch(`${baseUrl}/api/campaigns`, {
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
