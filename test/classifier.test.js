const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyVisit } = require("../classifier");

test("classifies HEAD requests as likely automated with medium confidence", () => {
  const result = classifyVisit("HEAD", "Mozilla/5.0");
  assert.equal(result.classification, "Likely automated / preview");
  assert.equal(result.confidence, "Medium");
  assert.match(result.reason, /clue, not proof/i);
});

test("recognizes an explicit security-scanner marker", () => {
  const result = classifyVisit("GET", "Example SafeLinks Scanner");
  assert.equal(result.classification, "Likely automated / preview");
  assert.equal(result.confidence, "Medium");
  assert.match(result.reason, /security-scanning/i);
});

test("does not call a normal browser-like GET a human click", () => {
  const result = classifyVisit("GET", "Mozilla/5.0 Chrome/120.0 Safari/537.36");
  assert.equal(result.classification, "Unclassified visit");
  assert.equal(result.confidence, "Low");
  assert.match(result.reason, /does not prove a person/i);
});

test("keeps missing user-agent requests unclassified", () => {
  const result = classifyVisit("GET", "");
  assert.equal(result.classification, "Unclassified visit");
  assert.match(result.reason, /No user-agent/i);
});

test("recognizes a spaced Safe Links marker", () => {
  const result = classifyVisit("GET", "Example Safe Links preview");
  assert.equal(result.classification, "Likely automated / preview");
  assert.equal(result.confidence, "Medium");
});

test("normalizes the HTTP method before classifying HEAD", () => {
  const result = classifyVisit("head", "Mozilla/5.0");
  assert.equal(result.classification, "Likely automated / preview");
  assert.equal(result.confidence, "Medium");
});
