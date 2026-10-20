import { normalizeRegistration, RegistrationError, fail } from "./registration-input.mjs";
import { admitRegistration, createRegistrationOperation, resultCache, REGISTRATION_LIMITS as L } from "./registration-resources.mjs";
import { discoverRdap, registryEvidence } from "./registration-discovery.mjs";
import { registrationExchange, validateRegistrationDestination } from "./registration-network.mjs";
import { parseRdap, parseWhois, whoisReferral } from "./registration-parse.mjs";
export { RegistrationError } from "./registration-input.mjs";

export const AUTO_FALLBACK_CODES = Object.freeze(["UNSUPPORTED_DISCOVERY", "PROTOCOL_UNAVAILABLE"]);

export async function lookupRegistration(payload, options = {}) {
  const input = normalizeRegistration(payload), now = options.now || Date.now;
  if (options.signal?.aborted) fail("CANCELLED", "Registration lookup was cancelled.");
  // Every request, including cache hits, consumes a client/global rate unit.
  const release = admitRegistration(options.clientIp || "unknown", now());
  const operation = createRegistrationOperation(options), attempts = [], rawResponses = [];
  const key = `${input.kind}:${input.canonical}:${input.protocolMode}`;
  const record = async (protocol, phase, source, work) => {
    const attempt = { protocol, phase, source, timestamp: new Date(now()).toISOString(), outcome: "pending", status: null };
    attempts.push(attempt);
    try {
      operation.assertLive();
      const response = await work(attempt);
      operation.assertLive();
      if (Number.isInteger(response?.status)) attempt.status = response.status;
      if (attempt.outcome === "pending") attempt.outcome = "completed";
      return response;
    } catch (error) {
      const safe = error instanceof RegistrationError ? error : new RegistrationError("TEMPORARY_FAILURE", "Registration service request failed.");
      attempt.outcome = safe.code; throw safe;
    }
  };
  const exchange = async (source, protocol, query, phase, attempt) => {
    const response = await registrationExchange(source, protocol, query, operation, options);
    attempt.status = response.status;
    rawResponses.push({ protocol, phase, source: response.source, timestamp: new Date(now()).toISOString(), text: response.text });
    return response;
  };
  let discovery = null, fallbackReason = null;
  try {
    const cached = resultCache.get(key, now());
    if (cached) {
      operation.assertLive();
      const response = structuredClone(cached.response);
      response.discovery.ageSeconds = Math.max(0, (now() - Date.parse(response.discovery.fetchedAt)) / 1000);
      response.discovery.fresh = response.discovery.expiresAt === null || now() < Date.parse(response.discovery.expiresAt);
      return { ...response, input, cache: { cached: true, ageSeconds: Math.max(0, (now() - cached.storedAt) / 1000), ttlSeconds: L.cacheMs / 1000 } };
    }
    const rdap = async () => {
      const found = await record("rdap", "discovery", `https://data.iana.org/rdap/${({ domain: "dns", asn: "asn", ipv4: "ipv4", ipv6: "ipv6" })[input.kind]}.json`, () => discoverRdap(input, operation, options, record));
      discovery = found.discovery;
      const resource = input.kind === "domain" ? `domain/${input.canonical}` : input.kind === "asn" ? `autnum/${input.canonical.slice(2)}` : `ip/${input.canonical}`;
      let url = found.base + resource;
      const seen = new Set();
      for (let depth = 0; depth <= L.redirects; depth++) {
        const validated = validateRegistrationDestination(url, "rdap").href;
        if (seen.has(validated)) fail("LIMIT_EXCEEDED", "RDAP redirect loop detected.");
        seen.add(validated);
        const value = await record("rdap", depth ? "redirect" : "query", validated, async (attempt) => {
          const response = await exchange(validated, "rdap", "", attempt.phase, attempt);
          if ([301, 302, 303, 307, 308].includes(response.status)) {
            if (depth >= L.redirects) fail("LIMIT_EXCEEDED", "RDAP redirect limit exceeded.");
            if (typeof response.headers?.location !== "string") fail("MALFORMED_REPLY", "RDAP redirect has no valid location.");
            if (/[\p{Cc}\p{Cf}\s\\]/u.test(response.headers.location)) fail("SECURITY_REJECTION", "Unsafe RDAP redirect location rejected.");
            let target; try { target = new URL(response.headers.location, validated).href; } catch { fail("SECURITY_REJECTION", "Invalid RDAP redirect destination."); }
            validateRegistrationDestination(target, "rdap"); attempt.outcome = "redirect";
            return { redirect: target };
          }
          if (response.status === 429) fail("UPSTREAM_RATE_LIMITED", "RDAP service is rate-limited. Try again later.");
          if ([405, 501].includes(response.status)) fail("PROTOCOL_UNAVAILABLE", "RDAP service does not support this operation.");
          if ([401, 403].includes(response.status)) fail("SECURITY_REJECTION", "RDAP service denied access; fallback is not permitted.");
          if (response.status >= 500) fail("TEMPORARY_FAILURE", "RDAP service is temporarily unavailable.");
          if (![200, 404].includes(response.status)) fail("UPSTREAM_FAILURE", "RDAP service returned an unsuccessful status.");
          if (!/^(?:application\/rdap\+json|application\/json)(?:\s*;|$)/i.test(response.headers?.["content-type"] ?? "")) fail("MALFORMED_REPLY", "RDAP response did not declare JSON content.");
          const normalized = parseRdap(response.text, input.kind, response.status, input.canonical);
          normalized.details.registryEvidence = registryEvidence(input.kind, found.services, validated, discovery);
          if (normalized.details.registryEvidence.name) normalized.fields["Registry / RIR"] = [normalized.details.registryEvidence.name];
          attempt.outcome = normalized.outcome;
          return { normalized, source: validated, protocol: "rdap" };
        });
        if (value.redirect) url = value.redirect;
        else return value;
      }
    };
    const whois = async () => {
      const iana = "whois://whois.iana.org:43";
      const discoveryQuery = input.kind === "domain" ? input.canonical.split(".").at(-1) : input.canonical;
      let source = await record("whois", "discovery", iana, async (attempt) => {
        const response = await exchange(iana, "whois", discoveryQuery, "discovery", attempt);
        parseWhois(response.text); // Includes denial, temporary error and parsing budgets.
        const referral = whoisReferral(response.text, true);
        if (!referral) {
          if (!/^(?:domain|inetnum|inet6num|as-block|aut-num):\s*\S+/im.test(response.text)
            && !/^%\s*This query returned 0 objects\./im.test(response.text)) fail("MALFORMED_REPLY", "Unrecognized IANA WHOIS discovery reply.");
          fail("UNSUPPORTED_DISCOVERY", "IANA publishes no WHOIS server for this identifier.");
        }
        const destination = validateRegistrationDestination(referral, "whois").href;
        discovery = { source: iana, fetchedAt: new Date(now()).toISOString(), ageSeconds: 0, fresh: true, expiresAt: null, publication: null };
        return destination;
      });
      const seen = new Set([`${validateRegistrationDestination(iana, "whois").href}|${discoveryQuery}`]);
      // IANA -> registry is referral 1; at most one further registry referral.
      for (let depth = 1; depth <= L.referrals; depth++) {
        source = validateRegistrationDestination(source, "whois").href;
        const identity = `${source}|${input.canonical}`;
        if (seen.has(identity)) fail("LIMIT_EXCEEDED", "WHOIS referral loop detected.");
        seen.add(identity);
        const value = await record("whois", depth === 1 ? "query" : "referral", source, async (attempt) => {
          const response = await exchange(source, "whois", input.canonical, attempt.phase, attempt);
          const normalized = parseWhois(response.text, input, response.source), referral = whoisReferral(response.text);
          // Never follow a denial, rate-limit or temporary-failure response.
          if (referral) {
            const next = validateRegistrationDestination(referral, "whois").href;
            if (seen.has(`${next}|${input.canonical}`)) fail("LIMIT_EXCEEDED", "WHOIS referral loop detected.");
            if (depth === L.referrals) fail("LIMIT_EXCEEDED", "WHOIS referral limit exceeded.");
            attempt.outcome = "referral"; return { referral: next };
          }
          attempt.outcome = normalized.outcome;
          return { normalized, source, protocol: "whois" };
        });
        if (value.referral) source = value.referral;
        else return value;
      }
    };
    let found;
    if (input.protocolMode === "whois") found = await whois();
    else {
      try { found = await rdap(); }
      catch (error) {
        operation.assertLive();
        if (input.protocolMode !== "auto" || !(error instanceof RegistrationError) || !AUTO_FALLBACK_CODES.includes(error.code)) throw error;
        fallbackReason = error.code; found = await whois();
      }
    }
    operation.assertLive();
    if (!found) fail("UPSTREAM_FAILURE", "No registration result completed.");
    // Bind response-local provenance to the final queried response, not IANA's
    // discovery object or an earlier registry referral.
    for (const item of Object.values(found.normalized.details.attribution ?? {})) item.source = found.source;
    const timestamp = new Date(now()).toISOString();
    const result = { ok: true, input, protocol: found.protocol, source: found.source, timestamp,
      outcome: found.normalized.outcome, normalized: found.normalized, discovery, attempts, rawResponses, fallbackReason,
      cache: { cached: false, ageSeconds: 0, ttlSeconds: L.cacheMs / 1000 },
      warnings: ["Registration data does not establish purchase availability, physical geolocation, or live DNSSEC validation.",
        ...(found.protocol === "whois" ? ["WHOIS uses plaintext TCP/43 without transport authentication or confidentiality; parsing is conservative."] : [])] };
    // Unknown WHOIS responses are inspectable but are never retained as records.
    if (result.outcome !== "unknown") resultCache.set(key, { storedAt: now(), expiresAt: now() + L.cacheMs, response: structuredClone(result) }, now(), operation.assertLive);
    return result;
  } catch (error) {
    const safe = error instanceof RegistrationError ? error : new RegistrationError("LOOKUP_FAILED", "Registration lookup failed.");
    safe.attempts = attempts; safe.rawResponses = rawResponses; throw safe;
  } finally { operation.dispose(); release(); }
}
