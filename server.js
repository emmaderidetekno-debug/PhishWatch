const crypto = require("crypto");
const express = require("express");
const path = require("path");
const { analyzeUrl } = require("./detector");
const { classifyVisit } = require("./classifier");
const { recordEvent, getEvents, getCampaigns, createCampaign } = require("./tracker");
const { eventsToCsv } = require("./csv");
const { SESSION_COOKIE, createAuth, parseCookies, sessionCookie, clearSessionCookie } = require("./auth");
const { createRateLimiter } = require("./ratelimit");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
// PhishWatch is a private local lab by default. Set HOST explicitly only when
// you understand the exposure and have added suitable access controls.
const HOST = process.env.HOST || "127.0.0.1";
const LOCAL_BASE_URL = process.env.PHISHWATCH_BASE_URL || `http://localhost:${PORT}`;

// There is no "no password" configuration. If the operator supplies
// PHISHWATCH_PASSWORD it is used; otherwise a random password is generated for
// this process and printed once at startup. A lab that is reachable is never
// an unauthenticated lab.
const GENERATED_PASSWORD = process.env.PHISHWATCH_PASSWORD ? null : crypto.randomBytes(18).toString("base64url");
const auth = createAuth({ password: process.env.PHISHWATCH_PASSWORD || GENERATED_PASSWORD });

const LOGIN_MAX_ATTEMPTS = Number.parseInt(process.env.PHISHWATCH_LOGIN_MAX_ATTEMPTS || "5", 10);
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 120,
  message: "Too many dashboard requests. Wait a minute and try again."
});

const loginLimiter = createRateLimiter({
  windowMs: LOGIN_WINDOW_MS,
  max: Number.isInteger(LOGIN_MAX_ATTEMPTS) && LOGIN_MAX_ATTEMPTS > 0 ? LOGIN_MAX_ATTEMPTS : 5,
  message: "Too many sign-in attempts. Wait 15 minutes and try again."
});

const trackingLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 60,
  message: "Too many requests for this PhishWatch test link. Try again shortly.",
  plain: true
});

app.disable("x-powered-by");
// Proxy headers are not trusted: req.ip must be the real socket address unless
// an operator deliberately configures a trusted proxy in front of the app.
app.set("trust proxy", false);
app.use(express.json({ limit: "10kb", strict: true }));

app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
  next();
});

function isSecureRequest(req) {
  return Boolean(req.secure) || req.get("x-forwarded-proto") === "https";
}

function currentSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  return auth.readSession(cookies[SESSION_COOKIE]);
}

// Cookies are SameSite=Strict, so a cross-site form post normally arrives
// without them. The Origin check is a second, explicit gate on every
// state-changing dashboard route.
function requireSameOrigin(req, res, next) {
  const origin = req.get("origin");
  if (!origin) return next();
  let originHost;
  try {
    originHost = new URL(origin).host;
  } catch {
    return res.status(403).json({ error: "Cross-origin requests are not allowed." });
  }
  if (originHost !== req.get("host")) {
    return res.status(403).json({ error: "Cross-origin requests are not allowed." });
  }
  return next();
}

function requireDashboard(req, res, next) {
  const session = currentSession(req);
  if (session) {
    req.dashboardSession = session;
    return next();
  }

  if (req.path.startsWith("/api/")) {
    return res.status(401).json({ error: "Sign in to the PhishWatch dashboard first." });
  }
  return res.redirect(302, "/login");
}

app.get("/", requireDashboard, (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/script.js", requireDashboard, (_req, res) => res.sendFile(path.join(__dirname, "script.js")));

// The login screen and its stylesheet are the only dashboard assets served
// without a session. They contain no site data.
app.get("/login", (req, res) => {
  if (currentSession(req)) return res.redirect(302, "/");
  return res.sendFile(path.join(__dirname, "login.html"));
});
app.get("/login.js", (_req, res) => res.sendFile(path.join(__dirname, "login.js")));
app.get("/style.css", (_req, res) => res.sendFile(path.join(__dirname, "style.css")));

app.post("/api/login", loginLimiter.middleware, requireSameOrigin, (req, res) => {
  const password = req.body && req.body.password;
  if (typeof password !== "string" || password.length === 0) {
    return res.status(400).json({ error: "Enter the dashboard password." });
  }

  if (!auth.verifyPassword(password)) {
    // No password material and no client address is logged; only the failure
    // itself, so the operator can see attempts without retaining identifiers.
    console.warn("PhishWatch: rejected dashboard sign-in attempt.");
    return res.status(401).json({ error: "Incorrect password." });
  }

  loginLimiter.reset(req);
  auth.pruneExpired();
  const session = auth.createSession();
  res.setHeader("Set-Cookie", sessionCookie(session.id, session.ttlMs, { secure: isSecureRequest(req) }));
  return res.json({ ok: true, expiresAt: new Date(session.expiresAt).toISOString() });
});

app.post("/api/logout", requireDashboard, requireSameOrigin, (req, res) => {
  auth.destroySession(req.dashboardSession.id);
  res.setHeader("Set-Cookie", clearSessionCookie({ secure: isSecureRequest(req) }));
  return res.status(204).end();
});

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, name: "PhishWatch", version: "0.3.0", dashboardAuth: "required" });
});

app.get("/api/events", requireDashboard, apiLimiter.middleware, (_req, res) => {
  res.json({ events: getEvents().slice(0, 100) });
});

// The export is generated on the server so there is one authoritative escaper,
// and so label text is neutralised where it can be tested rather than trusted.
app.get("/api/events.csv", requireDashboard, apiLimiter.middleware, (_req, res) => {
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", 'attachment; filename="phishwatch-activity.csv"');
  res.send(eventsToCsv(getEvents().slice(0, 100)));
});

app.get("/api/campaigns", requireDashboard, apiLimiter.middleware, (_req, res) => {
  const campaigns = getCampaigns().map(({ id, label, createdAt }) => ({ id, label, createdAt }));
  res.json({ campaigns });
});

app.post("/api/campaigns", requireDashboard, apiLimiter.middleware, requireSameOrigin, (req, res) => {
  const rawLabel = req.body?.label;
  if (rawLabel !== undefined && typeof rawLabel !== "string") {
    return res.status(400).json({ error: "Test label must be text." });
  }

  const label = (rawLabel || "My controlled test").trim().slice(0, 80);
  const campaign = createCampaign(label || "My controlled test");

  return res.status(201).json({
    campaign: { id: campaign.id, label: campaign.label, createdAt: campaign.createdAt },
    trackingUrl: `${LOCAL_BASE_URL}/t/${campaign.token}`
  });
});

app.post("/api/analyze-url", requireDashboard, apiLimiter.middleware, requireSameOrigin, (req, res) => {
  if (typeof req.body?.url !== "string") {
    return res.status(400).json({ error: "URL must be supplied as text." });
  }

  const input = req.body.url.trim();
  if (!input || input.length > 2048) {
    return res.status(400).json({ error: "Enter a URL up to 2048 characters." });
  }

  // An optional chain lets an operator paste the hops they already observed in
  // email headers or a proxy log. No hop is ever requested by the server.
  const rawChain = req.body.chain;
  if (rawChain !== undefined) {
    if (!Array.isArray(rawChain)) {
      return res.status(400).json({ error: "Redirect chain must be an array of URLs." });
    }
    if (rawChain.length > 10) {
      return res.status(400).json({ error: "Redirect chain accepts at most 10 hops." });
    }
    if (rawChain.some(hop => typeof hop !== "string" || hop.length > 2048)) {
      return res.status(400).json({ error: "Each redirect hop must be a URL of at most 2048 characters." });
    }
  }

  return res.json(analyzeUrl(input, { redirectChain: rawChain }));
});

// Authorized local test endpoint. It deliberately stores no IP, credentials,
// cookies, authorization headers, or message content. It is intentionally the
// only dashboard-owned route that is reachable without a session: the browser
// following a test link cannot authenticate, and requiring a session here would
// break the one thing the lab measures.
app.all("/t/:token", trackingLimiter.middleware, (req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return res.status(405).set("Allow", "GET, HEAD").send("Method not allowed.");
  }

  const campaign = getCampaigns().find(item => item.token === req.params.token);
  if (!campaign) return res.status(404).send("This PhishWatch test link is not valid.");

  const userAgent = String(req.get("user-agent") || "").slice(0, 300);
  const method = req.method;
  const assessment = classifyVisit(method, userAgent);

  recordEvent({
    id: crypto.randomUUID(),
    campaignId: campaign.id,
    campaignLabel: campaign.label,
    timestamp: new Date().toISOString(),
    method,
    classification: assessment.classification,
    confidence: assessment.confidence,
    reason: assessment.reason
  });

  if (method === "HEAD") return res.status(204).end();

  return res.type("html").send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishWatch controlled test</title>
</head>
<body>
<main>
<p><strong>Controlled security test</strong></p>
<h1>PhishWatch test link</h1>
<p>This page is part of an authorized security experiment. Your visit was recorded for the test dashboard.</p>
<p><strong>No password or personal credentials were requested or collected.</strong></p>
<p>You can close this page.</p>
</main>
</body>
</html>`);
});

app.use((_req, res) => {
  res.status(404).json({ error: "The requested resource was not found." });
});

app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({ error: "Request body must contain valid JSON." });
  }
  return res.status(500).json({ error: "An unexpected server error occurred." });
});

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`PhishWatch running at http://localhost:${PORT}`);
    console.log(`Listening on ${HOST}; local-only by default.`);
    if (GENERATED_PASSWORD) {
      console.log("");
      console.log("No PHISHWATCH_PASSWORD was set, so a one-time dashboard password was generated.");
      console.log(`Dashboard password for this run: ${GENERATED_PASSWORD}`);
      console.log("It is not stored anywhere and changes on the next start. Set PHISHWATCH_PASSWORD to choose your own.");
      console.log("");
    }
  });
}

module.exports = app;
