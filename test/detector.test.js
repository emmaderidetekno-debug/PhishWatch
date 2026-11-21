const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrl } = require("../detector");

test("accepts a normal HTTPS URL without declaring it guaranteed safe", () => {
  const result = analyzeUrl("https://example.com/about");
  assert.equal(result.valid, true);
  assert.equal(result.risk, "Low");
  assert.match(result.indicators[0], /does not prove/i);
});

test("flags an IPv4 address as a URL indicator", () => {
  const result = analyzeUrl("http://192.0.2.10/login");
  assert.equal(result.valid, true);
  assert.ok(result.indicators.some(item => /IP address/i.test(item)));
});

test("rejects non-HTTP protocols", () => {
  const result = analyzeUrl("javascript:alert(1)");
  assert.equal(result.valid, false);
  assert.equal(result.risk, "High");
  assert.ok(result.score >= 60);
});

test("rejects malformed input", () => {
  const result = analyzeUrl("not a URL");
  assert.equal(result.valid, false);
  assert.equal(result.score, 100);
});

test("raises risk for insecure URLs with account-themed paths", () => {
  const result = analyzeUrl("http://example.com/verify-account");
  assert.equal(result.valid, true);
  assert.equal(result.risk, "Medium");
  assert.ok(result.score >= 30);
});

test("detects embedded credentials", () => {
  const result = analyzeUrl("https://user:pass@example.com/");
  assert.ok(result.indicators.some(item => /embedded username\/password/i.test(item)));
});
