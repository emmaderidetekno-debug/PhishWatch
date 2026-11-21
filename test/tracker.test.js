const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "phishwatch-tracker-"));
process.env.PHISHWATCH_DATA_DIR = dataDir;
const { createCampaign, getCampaigns, recordEvent, getEvents } = require("../tracker");

test.after(() => {
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test("creates unique campaigns with bounded labels and random tokens", () => {
  const first = createCampaign("A".repeat(100));
  const second = createCampaign("Second campaign");

  assert.equal(first.label.length, 80);
  assert.match(first.token, /^[a-f0-9]{36}$/);
  assert.notEqual(first.token, second.token);
  assert.equal(getCampaigns().length, 2);
  assert.equal(getCampaigns()[0].id, second.id);
});

test("keeps only the latest 1000 events in newest-first order", () => {
  for (let index = 0; index < 1005; index += 1) {
    recordEvent({ id: String(index), timestamp: new Date(index).toISOString() });
  }

  const events = getEvents();
  assert.equal(events.length, 1000);
  assert.equal(events[0].id, "1004");
  assert.equal(events[999].id, "5");
});

test("creates its configured data directory when writing", () => {
  assert.equal(fs.existsSync(path.join(dataDir, "activity.json")), true);
  const stored = JSON.parse(fs.readFileSync(path.join(dataDir, "activity.json"), "utf8"));
  assert.equal(Array.isArray(stored.events), true);
  assert.equal(Array.isArray(stored.campaigns), true);
});
