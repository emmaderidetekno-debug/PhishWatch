const crypto = require("crypto");

const SESSION_COOKIE = "pw_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{20,64}$/;
const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1 };
const KEY_LENGTH = 32;

function derive(password, salt) {
  return crypto.scryptSync(Buffer.from(String(password), "utf8"), salt, KEY_LENGTH, SCRYPT_OPTIONS);
}

/**
 * Single-operator dashboard authentication.
 *
 * The password is never kept in plaintext: only a scrypt-derived key with a
 * per-process random salt is held in memory. Sessions are opaque random ids
 * validated against an in-memory store, so they are revocable and nothing
 * about the operator is stored on the client beyond an unguessable token.
 */
function createAuth({ password, ttlMs = SESSION_TTL_MS, now = () => Date.now() } = {}) {
  if (typeof password !== "string" || password.length === 0) {
    throw new TypeError("createAuth requires a non-empty dashboard password.");
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new TypeError("createAuth requires a positive session lifetime.");
  }

  const salt = crypto.randomBytes(16);
  const expectedKey = derive(password, salt);
  const sessions = new Map();

  function verifyPassword(candidate) {
    if (typeof candidate !== "string" || candidate.length === 0 || candidate.length > 1024) return false;
    const candidateKey = derive(candidate, salt);
    // Constant-time comparison: the response time must not reveal how many
    // leading characters of the password were correct.
    return crypto.timingSafeEqual(candidateKey, expectedKey);
  }

  function createSession() {
    const id = crypto.randomBytes(32).toString("base64url");
    const expiresAt = now() + ttlMs;
    sessions.set(id, { expiresAt });
    return { id, expiresAt, ttlMs };
  }

  function readSession(id) {
    if (typeof id !== "string" || !SESSION_ID_PATTERN.test(id)) return null;
    const session = sessions.get(id);
    if (!session) return null;
    if (session.expiresAt <= now()) {
      sessions.delete(id);
      return null;
    }
    return { id, expiresAt: session.expiresAt };
  }

  function destroySession(id) {
    if (typeof id === "string" && SESSION_ID_PATTERN.test(id)) sessions.delete(id);
  }

  function pruneExpired() {
    const current = now();
    for (const [id, session] of sessions) {
      if (session.expiresAt <= current) sessions.delete(id);
    }
  }

  return {
    verifyPassword,
    createSession,
    readSession,
    destroySession,
    pruneExpired,
    sessionCount: () => sessions.size
  };
}

function parseCookies(header) {
  const cookies = Object.create(null);
  if (typeof header !== "string") return cookies;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    if (!name) continue;
    let value = part.slice(index + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    cookies[name] = value;
  }
  return cookies;
}

function sessionCookie(id, ttlMs, { secure = false } = {}) {
  const attributes = [
    `${SESSION_COOKIE}=${id}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.floor(ttlMs / 1000)}`
  ];
  if (secure) attributes.push("Secure");
  return attributes.join("; ");
}

function clearSessionCookie({ secure = false } = {}) {
  const attributes = [`${SESSION_COOKIE}=`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (secure) attributes.push("Secure");
  return attributes.join("; ");
}

module.exports = {
  SESSION_COOKIE,
  SESSION_TTL_MS,
  createAuth,
  parseCookies,
  sessionCookie,
  clearSessionCookie
};
