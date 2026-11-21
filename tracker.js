const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const dataDir = path.join(__dirname, "data");
const file = path.join(dataDir, "activity.json");

function readStore() {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return {
      campaigns: Array.isArray(parsed.campaigns) ? parsed.campaigns : [],
      events: Array.isArray(parsed.events) ? parsed.events : []
    };
  } catch (error) {
    if (error.code !== "ENOENT" && !(error instanceof SyntaxError)) {
      throw error;
    }
    return { campaigns: [], events: [] };
  }
}

function writeStore(store) {
  fs.mkdirSync(dataDir, { recursive: true });
  const temporaryFile = `${file}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(store, null, 2), { mode: 0o600 });
  fs.renameSync(temporaryFile, file);
}

function getCampaigns() {
  return readStore().campaigns;
}

function getEvents() {
  return readStore().events;
}

function createCampaign(label) {
  const store = readStore();
  const campaign = {
    id: crypto.randomUUID(),
    token: crypto.randomBytes(18).toString("hex"),
    label: String(label).slice(0, 80),
    createdAt: new Date().toISOString()
  };

  store.campaigns.unshift(campaign);
  writeStore(store);
  return campaign;
}

function recordEvent(event) {
  const store = readStore();
  store.events.unshift(event);
  store.events = store.events.slice(0, 1000);
  writeStore(store);
  return event;
}

module.exports = { getCampaigns, getEvents, createCampaign, recordEvent };
