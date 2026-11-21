const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { analyzeUrl } = require("./detector");
const { classifyVisit } = require("./classifier");
const { recordEvent, getEvents, getCampaigns, createCampaign } = require("./tracker");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
// PhishWatch is a private local lab by default. Set HOST explicitly only when
// you understand the exposure and have added suitable access controls.
const HOST = process.env.HOST || "127.0.0.1";
const LOCAL_BASE_URL = process.env.PHISHWATCH_BASE_URL || `http://localhost:${PORT}`;

app.disable("x-powered-by");
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

// Serve only intended dashboard assets; never expose the local data directory.
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/style.css", (_req, res) => res.sendFile(path.join(__dirname, "style.css")));
app.get("/script.js", (_req, res) => res.sendFile(path.join(__dirname, "script.js")));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, name: "PhishWatch", version: "0.3.0" });
});

app.get("/api/events", (_req, res) => {
  res.json({ events: getEvents().slice(0, 100) });
});

app.get("/api/campaigns", (_req, res) => {
  res.json({ campaigns: getCampaigns() });
});

app.post("/api/campaigns", (req, res) => {
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

app.post("/api/analyze-url", (req, res) => {
  if (typeof req.body?.url !== "string") {
    return res.status(400).json({ error: "URL must be supplied as text." });
  }

  const input = req.body.url.trim();
  if (!input || input.length > 2048) {
    return res.status(400).json({ error: "Enter a URL up to 2048 characters." });
  }

  return res.json(analyzeUrl(input));
});

// Authorized local test endpoint. It deliberately stores no IP, credentials,
// cookies, authorization headers, or message content.
app.all("/t/:token", (req, res) => {
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
  });
}

module.exports = app;
