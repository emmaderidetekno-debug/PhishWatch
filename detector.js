const net = require("node:net");

function analyzeUrl(input) {
  const indicators = [];
  let parsed;

  try {
    parsed = new URL(String(input));
  } catch {
    return {
      valid: false,
      risk: "High",
      score: 100,
      indicators: ["The supplied text is not a valid absolute URL."]
    };
  }

  const host = parsed.hostname.toLowerCase();

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return {
      valid: false,
      hostname: host,
      protocol: parsed.protocol,
      risk: "High",
      score: 100,
      indicators: ["Only HTTP and HTTPS URLs can be assessed by this checker."]
    };
  }

  if (!host) {
    return {
      valid: false,
      risk: "High",
      score: 100,
      indicators: ["The URL does not contain a hostname."]
    };
  }

  let score = 0;

  if (parsed.protocol !== "https:") {
    score += 20;
    indicators.push("The URL does not use HTTPS.");
  }

  if (parsed.username || parsed.password) {
    score += 30;
    indicators.push("The URL contains embedded username/password information.");
  }

  if (host.startsWith("xn--") || host.includes(".xn--")) {
    score += 25;
    indicators.push("The hostname contains punycode, which can be used for lookalike domains.");
  }

  const ipHost = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

  if (net.isIP(ipHost)) {
    score += 20;
    indicators.push("The hostname is an IP address rather than a conventional domain.");
  }

  if (host.split(".").length >= 5) {
    score += 10;
    indicators.push("The hostname has an unusually large number of subdomains.");
  }

  if (parsed.href.length > 180) {
    score += 10;
    indicators.push("The URL is unusually long.");
  }

  if (/(login|verify|account|secure|password|update|wallet|support)/i.test(parsed.pathname + parsed.search)) {
    score += 10;
    indicators.push("The URL contains words commonly used in account-themed lures.");
  }

  score = Math.min(score, 100);
  const risk = score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";

  return {
    valid: true,
    hostname: host,
    protocol: parsed.protocol,
    risk,
    score,
    indicators: indicators.length
      ? indicators
      : ["No obvious heuristic indicators found. This does not prove the URL is safe."]
  };
}

module.exports = { analyzeUrl };
