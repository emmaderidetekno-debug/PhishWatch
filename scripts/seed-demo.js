#!/usr/bin/env node
"use strict";

/**
 * Seeds one clearly-labelled demo campaign and a representative set of visits.
 *
 * Everything it writes is synthetic and every event carries a campaign label
 * that starts with [DEMO][MOCK], so mock rows are impossible to mistake for a
 * real observation in the dashboard or in an exported CSV. It uses the same
 * classifier the live tracker uses, so the evidence text is genuine output
 * rather than invented prose — only the visits themselves are fabricated.
 *
 * The server does not need to be running: this writes through tracker.js to the
 * same data/activity.json the server reads.
 */

const crypto = require("crypto");
const { createCampaign, recordEvent } = require("../tracker");
const { classifyVisit } = require("../classifier");

const DEMO_LABEL = "[DEMO][MOCK] Interview walkthrough - synthetic visits";

const USER_AGENTS = {
  chrome:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  slack: "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
  googlebot: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  safeLinks:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36; MS-Office-Safelinks/1.0",
  gateway: "Barracuda-Link-Protection/1.0 (gateway probe)",
  none: ""
};

// Chronological order. recordEvent() unshifts, so the stored file ends up
// newest-first exactly as a live capture would.
const VISITS = [
  { minutesAgo: 96, method: "HEAD", userAgent: USER_AGENTS.safeLinks },
  { minutesAgo: 95, method: "GET", userAgent: USER_AGENTS.safeLinks },
  { minutesAgo: 88, method: "GET", userAgent: USER_AGENTS.slack },
  { minutesAgo: 74, method: "GET", userAgent: USER_AGENTS.googlebot },
  { minutesAgo: 61, method: "HEAD", userAgent: USER_AGENTS.gateway },
  { minutesAgo: 28, method: "GET", userAgent: USER_AGENTS.none },
  { minutesAgo: 9, method: "GET", userAgent: USER_AGENTS.chrome }
];

function seedDemo({ now = Date.now() } = {}) {
  const campaign = createCampaign(DEMO_LABEL);
  const events = VISITS.map(visit => {
    const timestamp = new Date(now - visit.minutesAgo * 60 * 1000).toISOString();
    const assessment = classifyVisit(visit.method, visit.userAgent);
    const event = {
      id: crypto.randomUUID(),
      campaignId: campaign.id,
      campaignLabel: campaign.label,
      timestamp,
      method: visit.method,
      classification: assessment.classification,
      confidence: assessment.confidence,
      reason: assessment.reason
    };
    recordEvent(event);
    return event;
  });

  return { campaign, events };
}

function main() {
  const { campaign, events } = seedDemo();
  const port = Number(process.env.PORT) || 3000;
  const baseUrl = process.env.PHISHWATCH_BASE_URL || `http://localhost:${port}`;

  console.log("PhishWatch demo seed - MOCK DATA ONLY");
  console.log("");
  console.log(`Campaign : ${campaign.label}`);
  console.log(`Campaign : ${campaign.id}`);
  console.log(`Test URL : ${baseUrl}/t/${campaign.token}`);
  console.log("");
  console.log(`${events.length} synthetic visits written (newest first in the dashboard):`);
  for (const event of [...events].reverse()) {
    console.log(`  ${event.timestamp}  ${event.method.padEnd(4)}  ${event.classification} / ${event.confidence}`);
  }
  console.log("");
  console.log("Every seeded row is labelled [DEMO][MOCK]. To remove this campaign and its");
  console.log("visits, delete data/activity.json (or the [DEMO][MOCK] entries in it).");
  console.log("Re-running this command adds another demo campaign rather than replacing it.");
  console.log("");
  console.log("Note: the test URL is local-only and useless outside this machine. Do not");
  console.log("send it to anyone.");
}

if (require.main === module) {
  main();
}

module.exports = { seedDemo, DEMO_LABEL };
