const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { analyzeUrl } = require("./detector");
const { classifyVisit } = require("./classifier");
const { recordEvent, getEvents, getCampaigns, createCampaign } = require("./tracker");

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

// Serve only the intended dashboard assets; do not expose the data store.
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/style.css", (_req, res) => res.sendFile(path.join(__dirname, "style.css")));
app.get("/script.js", (_req, res) => res.sendFile(path.join(__dirname, "script.js")));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, name: "PhishWatch", version: "0.2.0" });
});

app.get("/api/events", (_req, res) => {
  res.json({ events: getEvents().slice(0, 100) });
});

app.get("/api/campaigns", (_req, res) => {
  res.json({ campaigns: getCampaigns() });
});

app.post("/api/campaigns", (req, res) => {
  const rawLabel = req.body?.label;
  const label = String(rawLabel || "My controlled test").trim().slice(0, 80);
  const campaign = createCampaign(label || "My controlled test");

  res.status(201).json({
    campaign,
    trackingUrl: `${req.protocol}://${req.get("host")}/t/${campaign.token}`
  });
});

app.post("/api/analyze-url", (req, res) => {
  const input = String(req.body?.url || "").trim();

  if (!input || input.length > 2048) {
    return res.status(400).json({ error: "Enter a URL up to 2048 characters." });
  }

  return res.json(analyzeUrl(input));
});

// Authorized test endpoint: no IP, credentials, cookies or message content are stored.
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
    timestamp: new Date().toISOString(),
    method,
    userAgent: userAgent || "Not provided",
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
<style>
body{font:16px system-ui,sans-serif;background:#f4f7fb;color:#172033;display:grid;place-items:center;min-height:100vh;margin:0}
main{max-width:560px;margin:24px;padding:32px;background:white;border:1px solid #dce3ee;border-radius:16px}
h1{margin-top:0}.tag{display:inline-block;background:#e8f2ff;color:#1558a6;padding:6px 10px;border-radius:99px;font-size:13px}
</style>
</head>
<body><main>
<span class="tag">Controlled security test</span>
<h1>PhishWatch test link</h1>
<p>This page is part of an authorized security experiment. Your visit was recorded for the test dashboard.</p>
<p><strong>No password or personal credentials were requested or collected.</strong></p>
<p>You can close this page.</p>
</main></body></html>`);
});

app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({ error: "Request body must contain valid JSON." });
  }
  return res.status(500).json({ error: "An unexpected server error occurred." });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`PhishWatch running at http://localhost:${PORT}`);
  });
}

module.exports = app;
