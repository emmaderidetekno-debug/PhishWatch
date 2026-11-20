const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const dataDir = path.join(__dirname, "..", "data");
const file = path.join(dataDir, "activity.json");

function readStore() {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return { campaigns: [], events: [] };
  }
}

function writeStore(store) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(store, null, 2));
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
    label,
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
