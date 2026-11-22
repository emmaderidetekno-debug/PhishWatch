const net = require("node:net");

/**
 * Defensive URL heuristics. Everything here is offline: no URL is ever
 * requested, resolved or opened, so the checker cannot be used to probe a third
 * party and cannot tip off whoever built the link.
 */

// Brands whose domains are impersonated most often. `domains` is the allowlist
// of registrable domains that legitimately carry the brand; anything else that
// looks like the name is a candidate typosquat.
const BRANDS = [
  { name: "paypal", domains: ["paypal.com", "paypal.me", "paypal.co.uk"] },
  { name: "microsoft", domains: ["microsoft.com", "microsoftonline.com", "live.com", "office.com"] },
  { name: "outlook", domains: ["outlook.com", "live.com"] },
  { name: "office365", domains: ["office.com", "office365.com"] },
  { name: "google", domains: ["google.com", "google.co.uk", "g.co", "googleusercontent.com", "youtube.com"] },
  { name: "gmail", domains: ["gmail.com", "google.com"] },
  { name: "apple", domains: ["apple.com", "apple.co", "icloud.com", "me.com"] },
  { name: "amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"] },
  { name: "netflix", domains: ["netflix.com"] },
  { name: "facebook", domains: ["facebook.com", "fb.com", "messenger.com"] },
  { name: "instagram", domains: ["instagram.com"] },
  { name: "whatsapp", domains: ["whatsapp.com", "wa.me"] },
  { name: "linkedin", domains: ["linkedin.com", "lnkd.in"] },
  { name: "github", domains: ["github.com", "githubusercontent.com"] },
  { name: "dropbox", domains: ["dropbox.com"] },
  { name: "docusign", domains: ["docusign.com", "docusign.net"] },
  { name: "adobe", domains: ["adobe.com"] },
  { name: "chase", domains: ["chase.com"] },
  { name: "wellsfargo", domains: ["wellsfargo.com"] },
  { name: "bankofamerica", domains: ["bankofamerica.com", "bofa.com"] },
  { name: "hsbc", domains: ["hsbc.com", "hsbc.co.uk"] },
  { name: "coinbase", domains: ["coinbase.com"] },
  { name: "binance", domains: ["binance.com"] },
  { name: "steam", domains: ["steampowered.com", "steamcommunity.com"] },
  { name: "spotify", domains: ["spotify.com"] },
  { name: "dhl", domains: ["dhl.com", "dhl.de"] },
  { name: "fedex", domains: ["fedex.com"] },
  { name: "ups", domains: ["ups.com"] },
  { name: "zoom", domains: ["zoom.us", "zoom.com"] },
  { name: "slack", domains: ["slack.com"] },
  { name: "salesforce", domains: ["salesforce.com"] },
  { name: "okta", domains: ["okta.com"] },
  { name: "tiktok", domains: ["tiktok.com"] },
  { name: "twitter", domains: ["twitter.com", "x.com"] }
];

const TWO_LEVEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk",
  "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in",
  "com.au", "net.au", "org.au", "co.nz", "co.za", "com.br",
  "com.mx", "com.sg", "com.hk", "com.tr", "com.cn", "com.tw"
]);

// Parameters that carry a second destination. Attackers chain them onto
// legitimate redirectors so the visible link points at a trusted host.
const REDIRECT_PARAMS = new Set([
  "url", "u", "uri", "link", "redirect", "redirect_uri", "redirect_url",
  "redirecturl", "return", "return_to", "returnto", "returnurl", "continue",
  "next", "dest", "destination", "target", "goto", "out", "r", "ref",
  "callback", "forward", "view"
]);

const SHORTENER_HOSTS = new Set([
  "bit.ly", "t.co", "tinyurl.com", "rb.gy", "cutt.ly", "is.gd", "ow.ly",
  "buff.ly", "goo.gl", "lnkd.in", "s.id", "diln.co", "rebrand.ly",
  "shorturl.at", "t.ly", "v.gd", "tiny.cc", "bl.ink", "shorte.st"
]);

// Characters that read as Latin letters in another script or as digits.
const CONFUSABLES = {
  // Cyrillic
  "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u0451": "e", "\u043a": "k",
  "\u043c": "m", "\u043d": "h", "\u043e": "o", "\u0440": "p", "\u0441": "c",
  "\u0442": "t", "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0457": "i",
  "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u0261": "g", "\u04cf": "l",
  "\u051b": "q", "\u051d": "w",
  // Greek
  "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b7": "n", "\u03b9": "i",
  "\u03ba": "k", "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t",
  "\u03c5": "u", "\u03c7": "x", "\u03c9": "w", "\u03b3": "y", "\u03bc": "u",
  "\u03c0": "n",
  // Latin diacritics that collapse to plain letters
  "\u00e4": "a", "\u00f6": "o", "\u00fc": "u", "\u00e9": "e", "\u00e8": "e",
  "\u00ea": "e", "\u00f1": "n", "\u00e7": "c", "\u011f": "g", "\u015f": "s",
  "\u0131": "i", "\u0130": "i",
  // Digits and symbols used in place of letters
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
  "8": "b", "9": "g", "$": "s", "@": "a"
};

// --- punycode ---------------------------------------------------------------
// RFC 3492 decoder, so a lookalike domain can be shown in the browser's own
// readable form instead of the xn-- string that hides the trick.

function adaptBias(delta, numPoints, firstTime) {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  let value = firstTime ? Math.floor(delta / 700) : delta >> 1;
  value += Math.floor(value / numPoints);
  let k = 0;
  while (value > ((base - tMin) * tMax) >> 1) {
    value = Math.floor(value / (base - tMin));
    k += base;
  }
  return Math.floor(k + ((base - tMin + 1) * value) / (value + skew));
}

function decodePunycode(input) {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const initialBias = 72;
  const initialN = 128;
  const output = [];
  let n = initialN;
  let i = 0;
  let bias = initialBias;
  let index = 0;

  const basicLength = input.lastIndexOf("-");
  if (basicLength > 0) {
    for (let position = 0; position < basicLength; position += 1) {
      const code = input.charCodeAt(position);
      if (code >= 0x80) throw new Error("invalid basic segment");
      output.push(input[position]);
    }
  }
  index = basicLength > 0 ? basicLength + 1 : 0;

  while (index < input.length) {
    const oldIndex = i;
    let weight = 1;
    for (let k = base; ; k += base) {
      if (index >= input.length) throw new Error("truncated input");
      const code = input.charCodeAt(index);
      index += 1;
      let digit;
      if (code >= 0x30 && code <= 0x39) digit = code - 22;
      else if (code >= 0x41 && code <= 0x5a) digit = code - 0x41;
      else if (code >= 0x61 && code <= 0x7a) digit = code - 0x61;
      else throw new Error("invalid digit");
      i += digit * weight;
      const threshold = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < threshold) break;
      weight *= base - threshold;
    }
    const pointCount = output.length + 1;
    bias = adaptBias(i - oldIndex, pointCount, oldIndex === 0);
    n += Math.floor(i / pointCount);
    i %= pointCount;
    output.splice(i, 0, String.fromCodePoint(n));
    i += 1;
  }

  return output.join("");
}

function decodeHost(hostname) {
  return hostname
    .split(".")
    .map(label => {
      if (!label.toLowerCase().startsWith("xn--")) return label;
      try {
        return decodePunycode(label.slice(4));
      } catch {
        return label;
      }
    })
    .join(".");
}

function hasMixedScripts(value) {
  const scripts = new Set();
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code < 0x80) {
      if (/[a-z]/i.test(character)) scripts.add("latin");
    } else if (code >= 0x0400 && code <= 0x04ff) {
      scripts.add("cyrillic");
    } else if (code >= 0x0370 && code <= 0x03ff) {
      scripts.add("greek");
    } else if (code >= 0x1e00 && code <= 0x1eff) {
      scripts.add("latin");
    } else if (code > 0x2e80) {
      scripts.add("other");
    }
  }
  return scripts.size > 1;
}

// --- string distance --------------------------------------------------------

function toSkeleton(value) {
  return Array.from(String(value).toLowerCase())
    .map(character => CONFUSABLES[character] || character)
    .join("")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/cl/g, "d")
    .replace(/[^a-z0-9]/g, "");
}

function damerauLevenshtein(a, b) {
  const rows = a.length + 1;
  const columns = b.length + 1;
  const matrix = Array.from({ length: rows }, (_, row) => {
    const line = new Array(columns).fill(0);
    line[0] = row;
    return line;
  });
  for (let column = 1; column < columns; column += 1) matrix[0][column] = column;

  for (let row = 1; row < rows; row += 1) {
    for (let column = 1; column < columns; column += 1) {
      const cost = a[row - 1] === b[column - 1] ? 0 : 1;
      matrix[row][column] = Math.min(
        matrix[row - 1][column] + 1,
        matrix[row][column - 1] + 1,
        matrix[row - 1][column - 1] + cost
      );
      if (
        row > 1 && column > 1 &&
        a[row - 1] === b[column - 2] &&
        a[row - 2] === b[column - 1]
      ) {
        matrix[row][column] = Math.min(matrix[row][column], matrix[row - 2][column - 2] + 1);
      }
    }
  }

  return matrix[a.length][b.length];
}

function registrableDomain(labels) {
  if (labels.length <= 2) return labels.join(".");
  const suffix = labels.slice(-2).join(".");
  if (TWO_LEVEL_SUFFIXES.has(suffix)) return labels.slice(-3).join(".");
  return labels.slice(-2).join(".");
}

// --- brand distance ---------------------------------------------------------

function assessBrand(hostname) {
  const asciiLabels = hostname.split(".").filter(Boolean);
  const readableHost = decodeHost(hostname);
  const labels = readableHost.split(".").filter(Boolean);
  const registered = registrableDomain(labels);
  const registeredLabel = registered.split(".")[0] || "";

  const official = BRANDS.find(brand =>
    brand.domains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))
  );
  if (official) return { name: official.name, official: true, kind: "official", token: null, distance: 0 };

  const tokens = new Set();
  for (const label of [...labels, ...asciiLabels]) {
    tokens.add(label);
    for (const part of label.split(/[-_]+/)) if (part) tokens.add(part);
  }

  let best = null;
  for (const brand of BRANDS) {
    const brandSkeleton = toSkeleton(brand.name);
    for (const token of tokens) {
      const tokenLower = token.toLowerCase();
      const tokenSkeleton = toSkeleton(token);
      if (tokenSkeleton.length < 4) continue;
      if (Math.abs(tokenSkeleton.length - brandSkeleton.length) > 2) continue;

      const exact = tokenLower === brand.name;
      const homoglyph = !exact && tokenSkeleton === brandSkeleton;
      const distance = damerauLevenshtein(tokenSkeleton, brandSkeleton);
      const typosquat = !exact && !homoglyph && distance <= 2 && brandSkeleton.length >= 5;
      if (!exact && !homoglyph && !typosquat) continue;

      const inRegistered = token === registeredLabel || registeredLabel.split(/[-_]+/).includes(token);
      let kind;
      let weight;
      if (homoglyph || typosquat) {
        kind = "lookalike";
        weight = 35;
      } else if (inRegistered) {
        kind = "brand-in-registered-domain";
        weight = 30;
      } else {
        kind = "brand-in-subdomain";
        weight = 20;
      }

      const candidate = {
        name: brand.name,
        official: false,
        kind,
        token,
        distance,
        inRegistered,
        registeredDomain: registered,
        weight
      };
      if (!best || candidate.weight > best.weight) best = candidate;
      if (best.weight === 35) return best;
    }
  }

  return best;
}

function describeBrand(match) {
  if (!match || match.official) return null;
  if (match.kind === "lookalike") {
    const wording = match.distance === 0
      ? `uses lookalike characters that read as "${match.name}"`
      : `is ${match.distance} character${match.distance === 1 ? "" : "s"} away from "${match.name}"`;
    return `The host segment "${match.token}" ${wording} without being part of the official ${match.name} domain. Treat this as typosquatting until proven otherwise.`;
  }
  if (match.kind === "brand-in-registered-domain") {
    return `The ${match.name} brand appears in the registered domain "${match.registeredDomain}", which is not an official ${match.name} domain.`;
  }
  return `The ${match.name} brand appears in a subdomain, but the registered domain is "${match.registeredDomain}".`;
}

// --- redirect analysis ------------------------------------------------------
// A "redirect chain" here means the URL's own redirect parameters plus any hops
// the operator already knows about (from an email, proxy log or headers). The
// checker never follows a hop, so nothing is requested on an attacker's behalf.

function looksLikeUrl(value) {
  return /^(?:https?:)?\/\//i.test(value) || /^[a-z0-9-]+(\.[a-z0-9-]+)+\//i.test(value);
}

function safeParseUrl(value, base) {
  try {
    return base ? new URL(value, base) : new URL(value);
  } catch {
    return null;
  }
}

function analyzeRedirects(parsed, chain) {
  const indicators = [];
  const embeddedDestinations = [];
  let score = 0;

  for (const [name, value] of parsed.searchParams) {
    if (!REDIRECT_PARAMS.has(name.toLowerCase())) continue;
    if (!looksLikeUrl(value)) continue;

    const target = safeParseUrl(value.startsWith("//") ? `https:${value}` : value, parsed);
    if (!target) continue;
    if (target.hostname === parsed.hostname) continue;

    embeddedDestinations.push({ parameter: name, hostname: target.hostname });
    score += 20;
    const targetBrand = assessBrand(target.hostname);
    const brandNote = targetBrand && !targetBrand.official
      ? ` That destination also looks like "${targetBrand.name}".`
      : "";
    indicators.push(
      `The "${name}" parameter carries a different destination host ("${target.hostname}"), which is how an open redirect on a trusted site launders a link.${brandNote}`
    );
  }

  if (/\/\//.test(parsed.pathname)) {
    score += 10;
    indicators.push("The path contains a protocol-relative \"//\" segment, which can be interpreted as a new host by some clients.");
  }

  if (/%25[0-9a-f]{2}/i.test(parsed.href)) {
    score += 10;
    indicators.push("The URL is double-encoded (%25 sequences), a common way to hide a second destination from scanners.");
  }

  let shortener = null;
  if (SHORTENER_HOSTS.has(parsed.hostname)) {
    shortener = parsed.hostname;
    score += 10;
    indicators.push(`"${parsed.hostname}" is a link-shortening service, so the final destination is not visible in this URL. Resolve it from logs or headers rather than by clicking.`);
  }

  const hops = [];
  const chainHosts = [];
  const chainIssues = [];

  if (Array.isArray(chain)) {
    for (const entry of chain) {
      const hop = safeParseUrl(String(entry));
      if (!hop) continue;
      hops.push(hop.href);
      chainHosts.push(hop.hostname);
    }

    if (hops.length > 0) {
      const insecure = hops.filter(hop => hop.startsWith("http://")).length;
      if (insecure > 0) {
        score += 10;
        chainIssues.push(`${insecure} hop${insecure === 1 ? " travels" : "s travel"} over plain HTTP`);
      }

      const hostChanges = chainHosts.filter((host, index) => index > 0 && host !== chainHosts[index - 1]).length;
      if (hostChanges > 0) {
        chainIssues.push(`the destination host changes ${hostChanges} time${hostChanges === 1 ? "" : "s"}`);
      }

      if (hops.length > 3) {
        score += 10;
        chainIssues.push(`${hops.length} hops is longer than a normal link`);
      }

      const finalHost = chainHosts[chainHosts.length - 1];
      const finalBrand = finalHost ? assessBrand(finalHost) : null;
      if (finalBrand && !finalBrand.official) {
        // A chain that ends on a brand lookalike is the whole attack, so it is
        // weighted like a lookalike domain rather than like a suspicious hop.
        score += 30;
        chainIssues.push(`the final hop "${finalHost}" impersonates "${finalBrand.name}"`);
      }

      if (chainIssues.length > 0) {
        indicators.push(`The supplied redirect chain (${chainHosts.join(" -> ")}): ${chainIssues.join("; ")}.`);
      }
    }
  }

  return {
    score: Math.min(score, 50),
    indicators,
    summary: {
      embeddedDestinations,
      shortener,
      chainHops: hops.length,
      chainHosts,
      finalHost: chainHosts.length ? chainHosts[chainHosts.length - 1] : null
    }
  };
}

// --- main entry point -------------------------------------------------------

function analyzeUrl(input, options = {}) {
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

  const decodedHostname = decodeHost(host);
  const readableHost = decodedHostname !== host ? decodedHostname : null;

  if (host.startsWith("xn--") || host.includes(".xn--")) {
    score += 25;
    // Skeletonise label by label so the readable form keeps its dots.
    const readableSkeleton = decodedHostname
      .split(".")
      .map(label => toSkeleton(label))
      .join(".");
    indicators.push(
      readableHost
        ? `The hostname contains punycode, which hides non-Latin characters. It decodes to "${readableHost}" and reads as "${readableSkeleton}".`
        : "The hostname contains punycode, which can be used for lookalike domains."
    );
  }

  if (readableHost && hasMixedScripts(readableHost)) {
    score += 20;
    indicators.push("The decoded hostname mixes scripts (for example Latin with Cyrillic or Greek), which a legitimate brand domain does not do.");
  }

  const ipHost = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;

  if (net.isIP(ipHost)) {
    score += 20;
    indicators.push("The hostname is an IP address rather than a conventional domain.");
  }

  const labels = host.split(".");
  if (labels.length >= 5) {
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

  const brandMatch = assessBrand(host);
  if (brandMatch && !brandMatch.official) {
    score += brandMatch.weight;
    indicators.push(describeBrand(brandMatch));
  }

  const redirects = analyzeRedirects(parsed, options.redirectChain);
  score += redirects.score;
  indicators.push(...redirects.indicators);

  score = Math.min(score, 100);
  const risk = score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";

  return {
    valid: true,
    hostname: host,
    decodedHostname,
    protocol: parsed.protocol,
    risk,
    score,
    indicators: indicators.length
      ? indicators
      : ["No obvious heuristic indicators found. This does not prove the URL is safe."],
    brandMatch: brandMatch
      ? {
          name: brandMatch.name,
          official: brandMatch.official,
          kind: brandMatch.kind,
          token: brandMatch.token,
          distance: brandMatch.distance,
          registeredDomain: brandMatch.registeredDomain || null
        }
      : null,
    redirectAnalysis: redirects.summary
  };
}

module.exports = { analyzeUrl, decodeHost, assessBrand };
