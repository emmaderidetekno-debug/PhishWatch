const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeUrl, decodeHost } = require("../detector");

test("accepts a normal HTTPS URL without declaring it guaranteed safe", () => {
  const result = analyzeUrl("https://example.com/about");
  assert.equal(result.valid, true);
  assert.equal(result.risk, "Low");
  assert.equal(result.score, 0);
  assert.match(result.indicators[0], /does not prove/i);
  assert.equal(result.brandMatch, null);
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

test("flags an IPv6 address as a URL indicator", () => {
  const result = analyzeUrl("http://[2001:db8::1]/");
  assert.equal(result.valid, true);
  assert.ok(result.indicators.some(item => /IP address/i.test(item)));
});

test("detects punycode hostnames as a lookalike-domain indicator", () => {
  const result = analyzeUrl("https://xn--pple-43d.com/");
  assert.ok(result.indicators.some(item => /punycode/i.test(item)));
});

test("scores long URLs without treating the score as a verdict", () => {
  const result = analyzeUrl(`https://example.com/${"a".repeat(190)}`);
  assert.ok(result.score >= 10);
  assert.ok(result.indicators.some(item => /unusually long/i.test(item)));
});

// --- typosquat / brand distance --------------------------------------------

test("a one-character-off PayPal domain is High risk, not Medium", () => {
  const result = analyzeUrl("http://paypa1-secure-login.verify-account.example.tld/login?update=1");
  assert.equal(result.risk, "High");
  assert.ok(result.score >= 60, `expected a High score, got ${result.score}`);
  assert.equal(result.brandMatch.name, "paypal");
  assert.equal(result.brandMatch.official, false);
  assert.equal(result.brandMatch.kind, "lookalike");
  assert.ok(result.indicators.some(item => /typosquat/i.test(item)));
});

test("digit-for-letter substitution is caught as a lookalike", () => {
  const result = analyzeUrl("https://paypa1.com/signin");
  assert.equal(result.brandMatch.name, "paypal");
  assert.equal(result.brandMatch.distance, 0, "the skeleton collapses 1 to l before distance is measured");
  assert.ok(result.indicators.some(item => /lookalike characters/i.test(item)));
});

test("transposed characters are measured as one edit, not two", () => {
  const result = analyzeUrl("https://payapl.com/login");
  assert.equal(result.brandMatch.name, "paypal");
  assert.equal(result.brandMatch.kind, "lookalike");
});

test("a brand in the registered domain but not its official domain is flagged", () => {
  const result = analyzeUrl("https://paypal-secure-account.com/login");
  assert.equal(result.brandMatch.name, "paypal");
  assert.equal(result.brandMatch.kind, "brand-in-registered-domain");
  assert.equal(result.brandMatch.registeredDomain, "paypal-secure-account.com");
});

test("a brand parked in a subdomain is reported with the real registered domain", () => {
  const result = analyzeUrl("https://paypal.com.login.evil.tld/");
  assert.equal(result.brandMatch.kind, "brand-in-subdomain");
  assert.equal(result.brandMatch.registeredDomain, "evil.tld");
  assert.ok(result.indicators.some(item => /registered domain is "evil\.tld"/i.test(item)));
});

test("official brand domains and their subdomains are not accused of typosquatting", () => {
  for (const url of [
    "https://www.paypal.com/signin",
    "https://paypal.co.uk/",
    "https://mail.google.com/mail/u/0",
    "https://github.com/emmaderidetekno-debug/PhishWatch"
  ]) {
    const result = analyzeUrl(url);
    assert.equal(result.brandMatch.official, true, `${url} should be recognised as official`);
    assert.equal(result.risk, "Low", `${url} should stay Low risk`);
    assert.equal(result.indicators.some(item => /typosquat/i.test(item)), false);
  }
});

test("a brand word in the path or query is not treated as a typosquat", () => {
  const result = analyzeUrl("https://example.com/search?q=paypal+login");
  assert.equal(result.brandMatch, null);
  assert.equal(result.risk, "Low");
});

test("an unrelated domain that merely shares a prefix is not flagged", () => {
  const result = analyzeUrl("https://applepie-recipes.example/");
  assert.equal(result.brandMatch, null);
});

// --- punycode decoding ------------------------------------------------------

test("punycode is decoded to a readable form and mapped to the brand it imitates", () => {
  const result = analyzeUrl("https://xn--pple-43d.com/");
  assert.equal(result.hostname, "xn--pple-43d.com");
  assert.notEqual(result.decodedHostname, result.hostname);
  assert.match(result.decodedHostname, /\u0430pple\.com/);
  assert.equal(result.brandMatch.name, "apple");
  assert.equal(result.brandMatch.kind, "lookalike");
  assert.equal(result.risk, "High");
  assert.ok(result.indicators.some(item => /decodes to/i.test(item)));
});

test("mixed-script lookalikes are called out separately from plain punycode", () => {
  const result = analyzeUrl("https://xn--80ak6aa92e.com/");
  assert.notEqual(result.decodedHostname, result.hostname);
  assert.ok(result.indicators.some(item => /mixes scripts/i.test(item)));
  assert.equal(result.risk, "High");
});

test("decodeHost leaves ASCII labels untouched and survives invalid punycode", () => {
  assert.equal(decodeHost("example.com"), "example.com");
  assert.equal(decodeHost("www.example.co.uk"), "www.example.co.uk");
  // "xn--!!" carries characters that cannot appear in punycode, so the label
  // must be returned unchanged rather than throwing out of the checker.
  assert.equal(decodeHost("xn--!!.com"), "xn--!!.com");
});

// --- redirect awareness -----------------------------------------------------

test("an embedded destination in a redirect parameter is reported with its host", () => {
  const result = analyzeUrl("https://accounts.example.com/login?continue=https://evil.example/steal");
  assert.equal(result.redirectAnalysis.embeddedDestinations.length, 1);
  assert.equal(result.redirectAnalysis.embeddedDestinations[0].parameter, "continue");
  assert.equal(result.redirectAnalysis.embeddedDestinations[0].hostname, "evil.example");
  assert.ok(result.indicators.some(item => /open redirect/i.test(item)));
});

test("a redirect parameter pointing back at the same host is not flagged", () => {
  const result = analyzeUrl("https://example.com/login?next=/dashboard");
  assert.equal(result.redirectAnalysis.embeddedDestinations.length, 0);
});

test("a brand-lookalike redirect destination adds its own warning", () => {
  const result = analyzeUrl("https://trusted.example/go?url=https://paypa1.com/signin");
  assert.equal(result.redirectAnalysis.embeddedDestinations[0].hostname, "paypa1.com");
  assert.ok(result.indicators.some(item => /also looks like "paypal"/i.test(item)));
});

test("a protocol-relative path segment is flagged", () => {
  const result = analyzeUrl("https://example.com//evil.example/login");
  assert.ok(result.indicators.some(item => /protocol-relative/i.test(item)));
});

test("double-encoded URLs are flagged", () => {
  const result = analyzeUrl("https://example.com/r?x=%2568%2574%2574%2570");
  assert.ok(result.indicators.some(item => /double-encoded/i.test(item)));
});

test("a link shortener is named, not resolved", () => {
  const result = analyzeUrl("https://bit.ly/3xYzAbc");
  assert.equal(result.redirectAnalysis.shortener, "bit.ly");
  assert.ok(result.indicators.some(item => /shortening service/i.test(item)));
});

test("a supplied redirect chain reports hops, HTTP downgrades and an impersonated final host", () => {
  const result = analyzeUrl("https://news.example/article", {
    redirectChain: [
      "https://news.example/article",
      "http://tracker.example/c?u=1",
      "https://paypa1.com/signin"
    ]
  });
  assert.equal(result.redirectAnalysis.chainHops, 3);
  assert.equal(result.redirectAnalysis.finalHost, "paypa1.com");
  assert.deepEqual(result.redirectAnalysis.chainHosts, ["news.example", "tracker.example", "paypa1.com"]);
  const chainIndicator = result.indicators.find(item => /supplied redirect chain/i.test(item));
  assert.ok(chainIndicator, "expected a chain indicator");
  assert.match(chainIndicator, /plain HTTP/);
  assert.match(chainIndicator, /impersonates "paypal"/);
  assert.ok(result.score >= 30);
});

test("a short, clean redirect chain adds nothing", () => {
  const result = analyzeUrl("https://example.com/a", {
    redirectChain: ["https://example.com/a", "https://example.com/b"]
  });
  assert.equal(result.redirectAnalysis.chainHops, 2);
  assert.equal(result.indicators.some(item => /supplied redirect chain/i.test(item)), false);
  assert.equal(result.risk, "Low");
});

test("invalid chain entries are ignored rather than throwing", () => {
  const result = analyzeUrl("https://example.com/", { redirectChain: ["not a url", "", null] });
  assert.equal(result.valid, true);
  assert.equal(result.redirectAnalysis.chainHops, 0);
});

test("redirect signals are capped so they cannot dominate the score alone", () => {
  const query = new URLSearchParams({
    url: "https://a.example/",
    next: "https://b.example/",
    continue: "https://c.example/",
    redirect: "https://d.example/"
  });
  const result = analyzeUrl(`https://example.com/go?${query}`);
  assert.ok(result.redirectAnalysis.embeddedDestinations.length >= 4);
  assert.ok(result.score - result.redirectAnalysis.embeddedDestinations.length * 20 <= 10);
  assert.equal(result.risk, "Medium");
});
