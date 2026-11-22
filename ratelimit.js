const crypto = require("crypto");

/**
 * Fixed-window rate limiter.
 *
 * Buckets are keyed by an HMAC of the client address rather than the address
 * itself: the limiter can tell two sources apart and it still never holds a
 * raw IP in memory or on disk, and nothing is written to data/activity.json.
 * State is per-process and discarded on restart, which is the right scope for
 * a local lab but means limits are per instance, not global.
 */
function createRateLimiter({
  windowMs,
  max,
  message = "Too many requests. Try again shortly.",
  plain = false,
  now = () => Date.now(),
  keySalt = crypto.randomBytes(16)
} = {}) {
  if (!Number.isFinite(windowMs) || windowMs <= 0) throw new TypeError("windowMs must be a positive number.");
  if (!Number.isInteger(max) || max <= 0) throw new TypeError("max must be a positive integer.");

  const buckets = new Map();
  const PRUNE_THRESHOLD = 2000;

  function keyFor(req) {
    const address = String((req.socket && req.socket.remoteAddress) || req.ip || "unknown");
    return crypto.createHmac("sha256", keySalt).update(address).digest("base64url").slice(0, 22);
  }

  function prune() {
    const current = now();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= current) buckets.delete(key);
    }
  }

  function consume(req) {
    const key = keyFor(req);
    const current = now();
    let bucket = buckets.get(key);

    if (!bucket || current >= bucket.resetAt) {
      bucket = { count: 0, resetAt: current + windowMs };
      buckets.set(key, bucket);
    }

    bucket.count += 1;
    if (buckets.size > PRUNE_THRESHOLD) prune();

    return {
      key,
      limited: bucket.count > max,
      remaining: Math.max(0, max - bucket.count),
      retryAfter: Math.max(1, Math.ceil((bucket.resetAt - current) / 1000))
    };
  }

  function reset(req) {
    buckets.delete(keyFor(req));
  }

  function middleware(req, res, next) {
    const result = consume(req);

    res.setHeader("RateLimit-Limit", String(max));
    res.setHeader("RateLimit-Remaining", String(result.remaining));
    res.setHeader("RateLimit-Reset", String(result.retryAfter));

    if (!result.limited) return next();

    res.setHeader("Retry-After", String(result.retryAfter));
    if (plain) {
      return res.status(429).type("text/plain").send(message);
    }
    return res.status(429).json({ error: message, retryAfterSeconds: result.retryAfter });
  }

  return { middleware, reset, consume, prune, size: () => buckets.size };
}

module.exports = { createRateLimiter };
