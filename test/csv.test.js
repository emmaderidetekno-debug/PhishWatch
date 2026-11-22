const test = require("node:test");
const assert = require("node:assert/strict");

const { eventsToCsv, neutraliseCell, quoteCell, COLUMNS } = require("../csv");

function event(overrides = {}) {
  return {
    timestamp: "2026-11-22T10:00:00.000Z",
    campaignLabel: "Ordinary campaign",
    method: "GET",
    classification: "Unclassified visit",
    confidence: "Low",
    reason: "No clear automation marker was found.",
    ...overrides
  };
}

function cellFor(csv, column, row = 0) {
  const lines = csv.replace(/^\ufeff/, "").split("\r\n").filter(Boolean);
  const index = COLUMNS.indexOf(column);
  // Split on commas that are not inside quotes.
  const cells = lines[row + 1].match(/("(?:[^"]|"")*"|[^,]*)(,|$)/g).map(part => part.replace(/,$/, ""));
  return cells[index];
}

test("labels starting with = + - or @ are neutralised, not evaluated", () => {
  const payloads = [
    '=HYPERLINK("http://example.invalid","click")',
    "=1+1",
    "+1+1",
    "-2+3",
    "@SUM(A1:A2)",
    '=cmd|\' /C calc\'!A0'
  ];

  for (const payload of payloads) {
    const neutralised = neutraliseCell(payload);
    assert.equal(neutralised, `'${payload}`, `${payload} should be prefixed with a quote`);
    assert.equal(/^[=+\-@]/.test(neutralised), false);
  }
});

test("a formula hidden behind whitespace or tab is still neutralised", () => {
  for (const payload of [" =1+1", "\t=1+1", "\r=1+1", "\u00a0=1+1", "\ufeff=1+1"]) {
    assert.equal(neutraliseCell(payload), `'${payload}`);
  }
});

test("ordinary text is left exactly as it was", () => {
  const samples = [
    "Interview demo - Gmail link test",
    "[DEMO][MOCK] Interview walkthrough - synthetic visits",
    "test-2026-Q1",
    "support@example.com",
    "<script>alert(1)</script>",
    "50% of clicks"
  ];
  for (const sample of samples) {
    assert.equal(neutraliseCell(sample), sample);
  }
});

test("empty and missing values become empty cells", () => {
  assert.equal(neutraliseCell(undefined), "");
  assert.equal(neutraliseCell(null), "");
  assert.equal(neutraliseCell(""), "");
});

test("quotes are doubled and commas stay inside the cell", () => {
  assert.equal(quoteCell('a"b'), '"a""b"');
  assert.equal(quoteCell("a,b"), '"a,b"');

  const csv = eventsToCsv([event({ campaignLabel: 'click, then "run"' })]);
  const cell = cellFor(csv, "campaignLabel");
  assert.equal(cell, '"click, then ""run"""');
});

test("the whole export is neutralised, not just the label column", () => {
  const csv = eventsToCsv([event({
    campaignLabel: "=1+1",
    reason: "=2+2",
    classification: "+SUM(A1)",
    method: "-1",
    confidence: "@cmd"
  })]);

  for (const column of ["campaignLabel", "reason", "classification", "method", "confidence"]) {
    const cell = cellFor(csv, column);
    assert.match(cell, /^"'/, `${column} must be neutralised`);
  }
});

test("the export keeps its BOM, header and CRLF line endings", () => {
  const csv = eventsToCsv([event(), event()]);
  assert.equal(csv.startsWith("\ufeff"), true);
  const lines = csv.replace(/^\ufeff/, "").split("\r\n");
  assert.equal(lines[0], "timestamp,campaignLabel,method,classification,confidence,reason");
  assert.equal(lines[1].includes("Ordinary campaign"), true);
  assert.equal(lines[lines.length - 1], "");
});

test("the export of no events is a valid header-only document", () => {
  const csv = eventsToCsv([]);
  assert.equal(csv, "\ufefftimestamp,campaignLabel,method,classification,confidence,reason\r\n");
});
