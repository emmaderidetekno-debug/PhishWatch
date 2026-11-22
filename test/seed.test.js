const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "phishwatch-seed-"));
process.env.PHISHWATCH_DATA_DIR = dataDir;

const { seedDemo, DEMO_LABEL } = require("../scripts/seed-demo");
const { getCampaigns, getEvents } = require("../tracker");

const FIXED_NOW = Date.parse("2026-11-22T12:00:00.000Z");

test.after(() => {
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test("the seeded campaign is obvious mock data", () => {
  const { campaign } = seedDemo({ now: FIXED_NOW });
  assert.match(campaign.label, /\[DEMO\]\[MOCK\]/);
  assert.equal(campaign.label, DEMO_LABEL);
  assert.match(campaign.token, /^[a-f0-9]{36}$/);
  assert.match(campaign.id, /^[0-9a-f-]{36}$/);
  assert.equal(getCampaigns()[0].id, campaign.id);
});

test("it writes one representative visit per classification the lab can produce", () => {
  const { campaign, events } = seedDemo({ now: FIXED_NOW });
  assert.equal(events.length, 7);

  const automated = events.filter(event => event.classification === "Likely automated / preview");
  const unclassified = events.filter(event => event.classification === "Unclassified visit");
  assert.ok(automated.length >= 4, "expect several automation-flavoured visits");
  assert.ok(unclassified.length >= 2, "expect browser-like and missing-UA visits");
  assert.equal(automated.every(event => event.confidence === "Medium"), true);
  assert.equal(unclassified.every(event => event.confidence === "Low"), true);

  assert.ok(events.some(event => event.method === "HEAD"));
  assert.ok(events.some(event => /no user-agent/i.test(event.reason)));
  assert.ok(events.some(event => /link-preview|bot, crawler/i.test(event.reason)));

  assert.equal(events.every(event => event.campaignId === campaign.id), true);
  assert.equal(events.every(event => event.campaignLabel === DEMO_LABEL), true);
});

test("seeded events keep the non-identifying schema and a plausible timeline", () => {
  const { campaign } = seedDemo({ now: FIXED_NOW });
  // Scope to this run: repeated seeds reuse fixed timestamps, so ordering is
  // only meaningful within one campaign.
  const stored = getEvents().filter(event => event.campaignId === campaign.id);
  assert.equal(stored.length, 7);

  for (const event of stored) {
    assert.deepEqual(
      Object.keys(event).sort(),
      ["campaignId", "campaignLabel", "classification", "confidence", "id", "method", "reason", "timestamp"]
    );
    assert.ok(Date.parse(event.timestamp) <= FIXED_NOW);
  }

  // Newest first, as the dashboard reads them.
  for (let index = 1; index < stored.length; index += 1) {
    assert.ok(Date.parse(stored[index - 1].timestamp) >= Date.parse(stored[index].timestamp));
  }
});

test("re-running the command adds a new campaign instead of corrupting the old one", () => {
  const before = getCampaigns().length;
  const first = seedDemo({ now: FIXED_NOW });
  const second = seedDemo({ now: FIXED_NOW });
  assert.equal(getCampaigns().length, before + 2);
  assert.notEqual(first.campaign.id, second.campaign.id);
  assert.equal(first.campaign.label, second.campaign.label);
});
