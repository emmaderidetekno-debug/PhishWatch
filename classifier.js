const AUTOMATION_PATTERNS = [
  { pattern: /bot|crawler|spider/i, reason: "User-agent identifies itself as a bot, crawler or spider." },
  { pattern: /scanner|safe[\s_-]?links|urlscan|proofpoint|mimecast/i, reason: "User-agent contains a known security-scanning or link-protection marker." },
  { pattern: /preview|googleimageproxy|slackbot|facebookexternalhit|twitterbot/i, reason: "User-agent contains a link-preview or content-fetching marker." }
];

function classifyVisit(method, userAgent) {
  const normalizedMethod = String(method || "").toUpperCase();
  const normalizedAgent = String(userAgent || "").slice(0, 300);

  if (normalizedMethod === "HEAD") {
    return {
      classification: "Likely automated / preview",
      confidence: "Medium",
      reason: "HEAD requests commonly check a resource without loading its page; this is a clue, not proof."
    };
  }

  const match = AUTOMATION_PATTERNS.find(item => item.pattern.test(normalizedAgent));
  if (match) {
    return {
      classification: "Likely automated / preview",
      confidence: "Medium",
      reason: match.reason
    };
  }

  return {
    classification: "Unclassified visit",
    confidence: "Low",
    reason: normalizedAgent
      ? "No clear automation marker was found. A browser-like request does not prove a person clicked."
      : "No user-agent was supplied, so the request cannot be classified reliably."
  };
}

module.exports = { classifyVisit };
