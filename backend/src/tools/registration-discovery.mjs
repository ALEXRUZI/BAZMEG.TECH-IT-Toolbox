import net from "node:net";
import { ipNumber, fail, RegistrationError } from "./registration-input.mjs";
import { REGISTRATION_LIMITS as L } from "./registration-resources.mjs";
import { registrationExchange, validateRegistrationDestination } from "./registration-network.mjs";
import { boundedJson } from "./registration-parse.mjs";

const bootstraps = new Map(), failures = new Map();
export const BOOTSTRAP_TTL_MS = 24 * 3600000;
export const BOOTSTRAP_RETRY_MS = 30000;
const sources = { domain: "dns", ipv4: "ipv4", ipv6: "ipv6", asn: "asn" };

export function validateBootstrap(data, kind) {
  if (!data || data.version !== "1.0" || typeof data.publication !== "string" || !Number.isFinite(Date.parse(data.publication))
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(data.publication)
    || !Array.isArray(data.services) || data.services.length > 4000) fail("MALFORMED_REPLY", "Invalid IANA RDAP bootstrap data.");
  for (const service of data.services) {
    if (!Array.isArray(service) || service.length !== 2 || !service.every(Array.isArray) || !service[0].length || service[0].length > 4000 || !service[1].length || service[1].length > 16) fail("MALFORMED_REPLY", "Invalid IANA bootstrap service.");
    for (const key of service[0]) {
      if (typeof key !== "string" || key.length > 253) fail("MALFORMED_REPLY", "Invalid IANA bootstrap entry.");
      if (kind === "domain" && key !== "" && !key.split(".").every((v) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v))) fail("MALFORMED_REPLY", "Invalid IANA domain entry.");
      if (kind === "asn") {
        const m = key.match(/^(\d+)-(\d+)$/);
        if (!m || Number(m[1]) > Number(m[2]) || Number(m[2]) > 4294967295) fail("MALFORMED_REPLY", "Invalid IANA ASN range.");
      }
      if (["ipv4", "ipv6"].includes(kind)) {
        const [ip, prefix] = key.split("/");
        if (key.split("/").length !== 2 || net.isIP(ip) !== (kind === "ipv4" ? 4 : 6) || !/^\d+$/.test(prefix ?? "") || Number(prefix) > (kind === "ipv4" ? 32 : 128)) fail("MALFORMED_REPLY", "Invalid IANA IP prefix.");
      }
    }
    for (const base of service[1]) {
      if (typeof base !== "string" || base.length > 2048) fail("MALFORMED_REPLY", "Invalid IANA RDAP URL.");
      if (/[\p{Cc}\p{Cf}\s\\]/u.test(base)) fail("SECURITY_REJECTION", "Unsafe IANA RDAP base URL.");
      // HTTP-only discovery is unsupported; HTTPS candidates must pass policy.
      let url; try { url = new URL(base); } catch { fail("MALFORMED_REPLY", "Invalid IANA RDAP URL."); }
      if (!["http:", "https:"].includes(url.protocol) || !url.pathname.endsWith("/") || url.search || url.hash || url.username || url.password) fail("SECURITY_REJECTION", "Unsafe IANA RDAP base URL.");
      // Even an unused HTTP candidate must not turn a known unsafe endpoint
      // into an unsupported-discovery WHOIS fallback. No HTTP connection occurs.
      if (url.protocol === "http:") url.protocol = "https:";
      validateRegistrationDestination(url.href, "rdap");
    }
  }
  return data;
}

export function matchBootstrap(data, input, evidence = null) {
  let best = -1, urls = [];
  for (const [entries, endpoints] of data.services) for (const entry of entries) {
    let score = -1;
    if (input.kind === "domain" && (entry === "" || input.canonical === entry || input.canonical.endsWith(`.${entry}`))) score = entry === "" ? 0 : entry.split(".").length;
    if (input.kind === "asn") { const [a, b] = entry.split("-").map(Number); const n = Number(input.canonical.slice(2)); if (n >= a && n <= b) score = 0; }
    if (["ipv4", "ipv6"].includes(input.kind)) {
      const [ip, prefix] = entry.split("/"), shift = BigInt((input.kind === "ipv4" ? 32 : 128) - Number(prefix));
      if (ipNumber(input.canonical) >> shift === ipNumber(ip) >> shift) score = Number(prefix);
    }
    if (score > best) { best = score; urls = [...endpoints]; }
    else if (score >= 0 && score === best) urls.push(...endpoints);
  }
  if (best < 0) fail("UNSUPPORTED_DISCOVERY", "IANA has no RDAP service for this identifier.");
  const secure = [...new Set(urls)].filter((v) => new URL(v).protocol === "https:");
  if (!secure.length) fail("UNSUPPORTED_DISCOVERY", "IANA has no HTTPS RDAP service for this identifier.");
  if (evidence) evidence.services = secure.map((base) => new URL(base).href);
  return new URL(secure[0]).href;
}

export async function discoverRdap(input, operation, options, record) {
  const now = options.now || Date.now, kind = input.kind;
  const source = `https://data.iana.org/rdap/${sources[kind]}.json`;
  let entry = bootstraps.get(kind);
  if (!entry || now() >= entry.expiresAt) {
    const previous = failures.get(kind);
    if (previous && now() - previous.time < BOOTSTRAP_RETRY_MS) throw new RegistrationError(previous.code, previous.message);
    try {
      const response = await record("rdap", "bootstrap", source, () => registrationExchange(source, "rdap", "", operation, options, L.bootstrapBytes));
      if (response.status === 429) fail("UPSTREAM_RATE_LIMITED", "IANA bootstrap service is rate-limited.");
      if (response.status !== 200) fail("DISCOVERY_UNAVAILABLE", "IANA bootstrap service is unavailable.");
      const data = validateBootstrap(boundedJson(response.text), kind);
      const fetchedAt = now();
      const maxAge = response.headers?.["cache-control"]?.match(/(?:^|,)\s*max-age=(\d+)/i);
      const expires = Date.parse(response.headers?.expires ?? "");
      const ttl = maxAge ? Number(maxAge[1]) * 1000 : Number.isFinite(expires) ? expires - fetchedAt : BOOTSTRAP_TTL_MS;
      entry = { data, fetchedAt, expiresAt: fetchedAt + Math.max(60000, Math.min(ttl, BOOTSTRAP_TTL_MS)) };
      operation.assertLive(); bootstraps.set(kind, entry); failures.delete(kind);
    } catch (error) {
      if (error instanceof RegistrationError && !["CANCELLED", "DEADLINE_EXHAUSTED", "CAPACITY_EXHAUSTED"].includes(error.code)) failures.set(kind, { time: now(), code: error.code, message: error.safeMessage });
      throw error;
    }
  }
  const discovery = { source, fetchedAt: new Date(entry.fetchedAt).toISOString(), ageSeconds: Math.max(0, (now() - entry.fetchedAt) / 1000), fresh: now() < entry.expiresAt, expiresAt: new Date(entry.expiresAt).toISOString(), publication: entry.data.publication };
  const evidence = {};
  const base = matchBootstrap(entry.data, input, evidence);
  return { base, discovery, services: evidence.services };
}

// Exact service URLs published in https://data.iana.org/rdap/ipv4.json;
// organization names: https://www.iana.org/numbers (checked 2026-10-14).
// These are identity labels only, never routing/discovery overrides.
const RIRS = new Map([
  ["https://rdap.afrinic.net/rdap/", "AFRINIC"],
  ["https://rdap.apnic.net/", "APNIC"],
  ["https://rdap.arin.net/registry/", "ARIN"],
  ["https://rdap.lacnic.net/rdap/", "LACNIC"],
  ["https://rdap.db.ripe.net/", "RIPE NCC"],
]);
export function registryEvidence(kind, services, source, discovery) {
  const candidates = [...new Set(services.map((base) => RIRS.get(base) ?? null))];
  const service = services.find((base) => source.startsWith(base) && RIRS.has(base)) ?? null;
  // A final validated response must remain within an IANA-selected exact
  // service. Transfers/redirects to other services are not an identity proof.
  const name = kind !== "domain" && service && candidates.length === 1 && candidates[0] ? candidates[0] : null;
  return { name, service: name ? service : null, candidates, services, source: discovery.source,
    publication: discovery.publication, reason: name ? "IANA bootstrap selection and verified HTTPS response from the selected service" : "Registry / RIR identity is unavailable; discovery and response evidence are insufficient" };
}
export function resetBootstrapState() { bootstraps.clear(); failures.clear(); }
