const test = require("node:test");
const assert = require("node:assert/strict");

const { createAuth, parseCookies, sessionCookie, clearSessionCookie, SESSION_COOKIE } = require("../auth");
const { createRateLimiter } = require("../ratelimit");

function fakeRequest(address) {
  return { socket: { remoteAddress: address }, ip: address, headers: {} };
}

function fakeResponse() {
  const headers = new Map();
  return {
    statusCode: 200,
    body: undefined,
    headers,
    status(code) { this.statusCode = code; return this; },
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    type(value) { this.contentType = value; return this; },
    json(value) { this.body = value; return this; },
    send(value) { this.body = value; return this; }
  };
}

test("verifyPassword accepts only the configured password", () => {
  const auth = createAuth({ password: "lab-password" });
  assert.equal(auth.verifyPassword("lab-password"), true);
  assert.equal(auth.verifyPassword("lab-password "), false);
  assert.equal(auth.verifyPassword("LAB-PASSWORD"), false);
  assert.equal(auth.verifyPassword(""), false);
  assert.equal(auth.verifyPassword(undefined), false);
  assert.equal(auth.verifyPassword({ toString: () => "lab-password" }), false);
});

test("sessions are random, expiring and revocable", () => {
  let clock = 1_000;
  const auth = createAuth({ password: "lab-password", ttlMs: 5_000, now: () => clock });

  const first = auth.createSession();
  const second = auth.createSession();
  assert.notEqual(first.id, second.id);
  assert.match(first.id, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(auth.readSession(first.id).id, first.id);

  clock += 5_001;
  assert.equal(auth.readSession(first.id), null);
  assert.equal(auth.sessionCount(), 1, "an expired session stays until it is read or pruned");
  auth.pruneExpired();
  assert.equal(auth.sessionCount(), 0);

  const third = auth.createSession();
  auth.destroySession(third.id);
  assert.equal(auth.readSession(third.id), null);
});

test("session ids must look like session ids", () => {
  const auth = createAuth({ password: "lab-password" });
  const session = auth.createSession();
  assert.equal(auth.readSession("../../etc/passwd"), null);
  assert.equal(auth.readSession("short"), null);
  assert.equal(auth.readSession(session.id.slice(0, 10)), null);
  assert.equal(auth.readSession(undefined), null);
});

test("session cookies are HttpOnly, SameSite=Strict and opt into Secure", () => {
  const cookie = sessionCookie("abc", 60_000, { secure: false });
  assert.match(cookie, new RegExp(`^${SESSION_COOKIE}=abc;`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Max-Age=60/);
  assert.equal(cookie.includes("Secure"), false);
  assert.match(sessionCookie("abc", 60_000, { secure: true }), /Secure/);
  assert.match(clearSessionCookie(), /Max-Age=0/);
});

test("cookie parsing handles padding, quoting and junk", () => {
  const cookies = parseCookies(`pw_session=abc123; theme=dark; quoted="value"; broken; =nope`);
  assert.equal(cookies.pw_session, "abc123");
  assert.equal(cookies.theme, "dark");
  assert.equal(cookies.quoted, "value");
  assert.equal(Object.keys(cookies).includes("broken"), false);
  assert.deepEqual(parseCookies(undefined), Object.create(null));
});

test("rate limiter blocks above the maximum and recovers after the window", () => {
  let clock = 0;
  const limiter = createRateLimiter({ windowMs: 1_000, max: 2, now: () => clock });
  const request = fakeRequest("127.0.0.1");

  const first = fakeResponse();
  let nextCalled = 0;
  limiter.middleware(request, first, () => { nextCalled += 1; });
  assert.equal(nextCalled, 1);
  assert.equal(first.headers.get("ratelimit-limit"), "2");
  assert.equal(first.headers.get("ratelimit-remaining"), "1");

  limiter.middleware(request, fakeResponse(), () => { nextCalled += 1; });
  assert.equal(nextCalled, 2);

  const blocked = fakeResponse();
  limiter.middleware(request, blocked, () => { nextCalled += 1; });
  assert.equal(nextCalled, 2, "limiter must not call next when blocked");
  assert.equal(blocked.statusCode, 429);
  assert.equal(blocked.headers.get("retry-after"), "1");
  assert.match(blocked.body.error, /Too many requests/);

  clock = 1_001;
  const afterWindow = fakeResponse();
  limiter.middleware(request, afterWindow, () => { nextCalled += 1; });
  assert.equal(nextCalled, 3);
});

test("rate limiter keeps sources in separate buckets and can be reset", () => {
  const limiter = createRateLimiter({ windowMs: 60_000, max: 1, now: () => 0 });
  const first = fakeRequest("10.0.0.1");
  const second = fakeRequest("10.0.0.2");

  limiter.middleware(first, fakeResponse(), () => {});
  const sameSource = fakeResponse();
  limiter.middleware(first, sameSource, () => {});
  assert.equal(sameSource.statusCode, 429);

  const otherSource = fakeResponse();
  limiter.middleware(second, otherSource, () => {});
  assert.equal(otherSource.statusCode, 200);

  limiter.reset(first);
  const afterReset = fakeResponse();
  limiter.middleware(first, afterReset, () => {});
  assert.equal(afterReset.statusCode, 200);
});

test("rate limiter buckets are keyed by a hash, never by the raw address", () => {
  const limiter = createRateLimiter({ windowMs: 60_000, max: 5, now: () => 0 });
  const result = limiter.consume(fakeRequest("203.0.113.9"));
  assert.equal(result.key.includes("203.0.113.9"), false);
  assert.match(result.key, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(result.remaining, 4);
});
