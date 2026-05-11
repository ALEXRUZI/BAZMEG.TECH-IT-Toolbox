import dgram from "node:dgram";
import net from "node:net";
import { domainToASCII } from "node:url";
import { randomInt } from "node:crypto";

const SUPPORTED_RECORD_TYPES = new Set(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "PTR", "SRV"]);
const SINGLE_CACHE_TTL_SECONDS = 60;
const BURST_CACHE_TTL_SECONDS = 300;
const DNS_TIMEOUT_MS = 3000;
const CNAME_FOLLOW_LIMIT = 5;
const RATE_WINDOW_FIVE_MINUTES_MS = 5 * 60 * 1000;
const RATE_WINDOW_HOUR_MS = 60 * 60 * 1000;
const RATE_LIMIT_FIVE_MINUTES = 100;
const RATE_LIMIT_HOUR = 750;
const DNS_PORT = 53;

const CUSTOM_RESOLVER_KEYS = new Set([
  "resolver",
  "resolverIp",
  "resolverIps",
  "resolverIP",
  "resolverIPs",
  "resolverAddress",
  "resolverAddresses",
  "resolverHost",
  "resolverHostname",
  "resolverUrl",
  "resolverURL",
  "resolverEndpoint",
  "customResolver",
  "customResolvers",
  "doh",
  "dohUrl",
  "dohURL",
  "dohEndpoint",
  "dot",
  "dotHost",
  "dotHostname",
  "dnsOverHttps",
  "dnsOverHttpsUrl",
  "dnsOverTls",
  "dnsOverTlsHostname",
  "endpoint",
  "host",
  "hostname",
  "nameserver",
  "nameservers",
  "server",
  "servers",
  "url",
]);

const BULK_INPUT_KEYS = new Set([
  "bulk",
  "queries",
  "domains",
  "hosts",
  "names",
  "inputs",
]);

const TYPE_TO_CODE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  CAA: 257,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
};

const CODE_TO_TYPE = Object.fromEntries(Object.entries(TYPE_TO_CODE).map(([type, code]) => [code, type]));

const RCODE_NAMES = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
};

export const RESOLVER_REGISTRY = Object.freeze({
  cloudflare: {
    id: "cloudflare",
    name: "Cloudflare DNS",
    endpoints: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
  },
  google: {
    id: "google",
    name: "Google DNS",
    endpoints: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
  },
  opendns: {
    id: "opendns",
    name: "OpenDNS / Cisco",
    endpoints: ["208.67.222.222", "208.67.220.220", "2620:0:ccc::2", "2620:0:ccd::2"],
  },
  quad9: {
    id: "quad9",
    name: "Quad9",
    endpoints: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
  },
  fortiguard: {
    id: "fortiguard",
    name: "FortiGuard DNS",
    endpoints: ["96.45.45.45", "96.45.46.46", "208.91.112.53", "208.91.112.52"],
  },
  adguard: {
    id: "adguard",
    name: "AdGuard DNS",
    endpoints: ["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
  },
  verisign: {
    id: "verisign",
    name: "Verisign Public DNS",
    endpoints: ["64.6.64.6", "64.6.65.6", "2620:74:1b::1:1", "2620:74:1c::2:2"],
  },
  dnswatch: {
    id: "dnswatch",
    name: "DNS.WATCH",
    endpoints: ["84.200.69.80", "84.200.70.40", "2001:1608:10:25::1c04:b12f", "2001:1608:10:25::9249:d69b"],
  },
  comodo: {
    id: "comodo",
    name: "Comodo Secure DNS",
    endpoints: ["8.26.56.26", "8.20.247.20"],
  },
  level3: {
    id: "level3",
    name: "Level3 / Lumen",
    endpoints: ["4.2.2.1", "4.2.2.2"],
  },
  neustar: {
    id: "neustar",
    name: "Neustar UltraDNS",
    endpoints: ["156.154.70.1", "156.154.71.1", "2610:a1:1018::1", "2610:a1:1019::1"],
  },
});

export const BURST_RESOLVER_IDS = Object.freeze([
  "cloudflare",
  "google",
  "opendns",
  "quad9",
  "fortiguard",
  "adguard",
  "verisign",
  "dnswatch",
  "comodo",
  "level3",
]);

const cache = new Map();
const rateBuckets = new Map();

export class DnsCheckError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DnsCheckError";
    this.code = code;
    this.safeMessage = message;
  }
}

export async function checkDns(payload, options = {}) {
  const now = options.now || Date.now;
  const request = normalizeRequest(payload || {});
  const cacheKey = buildCacheKey(request);
  const cached = cache.get(cacheKey);
  const startedAt = now();

  if (cached && cached.expiresAt > startedAt) {
    return withCacheMetadata(cached.response, {
      fromCache: true,
      ttlSeconds: request.cacheTtlSeconds,
      storedAt: cached.storedAt,
      now: startedAt,
    });
  }

  if (cached) {
    cache.delete(cacheKey);
  }

  enforceRateLimit(options.clientIp || "unknown", request.tokenCost, startedAt);

  const queryDns = options.queryDns || queryDnsUdp;
  const baseResponse = request.mode === "single"
    ? await checkSingleProvider(request, queryDns)
    : await checkBurstProviders(request, queryDns);

  const response = withCacheMetadata(baseResponse, {
    fromCache: false,
    ttlSeconds: request.cacheTtlSeconds,
    storedAt: startedAt,
    now: now(),
  });

  cache.set(cacheKey, {
    storedAt: startedAt,
    expiresAt: startedAt + request.cacheTtlSeconds * 1000,
    response: withoutCacheMetadata(response),
  });

  return response;
}

export function resetDnsCheckState() {
  cache.clear();
  rateBuckets.clear();
}

export function getSingleResolverSummaries() {
  return Object.values(RESOLVER_REGISTRY).map(({ id, name }) => ({ id, name }));
}

export function getBurstResolverSummaries() {
  return BURST_RESOLVER_IDS.map((id) => {
    const { name } = RESOLVER_REGISTRY[id];
    return { id, name };
  });
}

export function normalizeDnsCheckRequest(payload) {
  return normalizeRequest(payload || {});
}

function normalizeRequest(payload) {
  rejectCustomResolverInput(payload);

  const mode = payload.mode === "burst" ? "burst" : payload.mode === "single" ? "single" : null;

  if (!mode) {
    throw new DnsCheckError("INVALID_MODE", "Choose single or burst DNS check mode.");
  }

  const recordType = typeof payload.recordType === "string" ? payload.recordType.trim().toUpperCase() : "";

  if (!SUPPORTED_RECORD_TYPES.has(recordType)) {
    throw new DnsCheckError("INVALID_RECORD_TYPE", "Choose a supported DNS record type.");
  }

  const query = normalizeQuery(payload, recordType);
  const dnssecRequested = mode === "single" ? payload.dnssec !== false : false;
  const resolverId = normalizeResolverId(payload.resolverId, mode);

  return {
    mode,
    recordType,
    resolverId,
    query,
    protocol: "udp",
    options: {
      cnameFollowLimit: CNAME_FOLLOW_LIMIT,
    },
    dnssecRequested,
    cacheTtlSeconds: mode === "single" ? SINGLE_CACHE_TTL_SECONDS : BURST_CACHE_TTL_SECONDS,
    tokenCost: mode === "single" ? 1 : 10,
  };
}

function rejectCustomResolverInput(payload) {
  for (const key of Object.keys(payload || {})) {
    if (CUSTOM_RESOLVER_KEYS.has(key)) {
      throw new DnsCheckError("CUSTOM_RESOLVER_NOT_ALLOWED", "Choose one of the predefined DNS providers.");
    }

    if (BULK_INPUT_KEYS.has(key)) {
      throw new DnsCheckError("BULK_INPUT_NOT_ALLOWED", "Enter one DNS query at a time.");
    }
  }
}

function normalizeResolverId(resolverId, mode) {
  if (mode === "burst") {
    if (resolverId !== undefined && resolverId !== null && resolverId !== "") {
      throw new DnsCheckError("INVALID_RESOLVER", "Choose a resolver available for this DNS check mode.");
    }

    return null;
  }

  if (typeof resolverId !== "string" || !RESOLVER_REGISTRY[resolverId]) {
    throw new DnsCheckError("INVALID_RESOLVER", "Choose a predefined DNS provider.");
  }

  return resolverId;
}

function normalizeQuery(payload, recordType) {
  if (recordType === "PTR") {
    const originalInput = getString(payload.query || payload.input || payload.name);
    const address = originalInput.trim();

    if (net.isIP(address) === 0 || isBlockedIp(address)) {
      throw new DnsCheckError("INVALID_QUERY", "Enter a valid public IPv4 or IPv6 address for PTR checks.");
    }

    return {
      originalInput: address,
      queryName: reverseIpName(address),
      displayName: address,
    };
  }

  if (recordType === "SRV") {
    return normalizeSrvQuery(payload);
  }

  const originalInput = getString(payload.query || payload.domain || payload.name);
  const queryName = normalizePublicDnsName(originalInput, { allowServiceLabels: false });

  return {
    originalInput: originalInput.trim(),
    queryName,
    displayName: queryName,
  };
}

function normalizeSrvQuery(payload) {
  const service = getOptionalString(payload.service);
  const protocol = getOptionalString(payload.protocol);
  const domain = getOptionalString(payload.domain);

  if (service || protocol || domain) {
    const normalizedService = normalizeSrvService(service);
    const normalizedProtocol = normalizeSrvProtocol(protocol);
    const normalizedDomain = normalizePublicDnsName(domain, { allowServiceLabels: false });
    const queryName = `${normalizedService}.${normalizedProtocol}.${normalizedDomain}`;

    validateDnsLength(queryName);

    return {
      originalInput: `${service} ${protocol} ${domain}`.trim(),
      queryName,
      displayName: queryName,
      service: normalizedService,
      protocol: normalizedProtocol,
      domain: normalizedDomain,
    };
  }

  const originalInput = getString(payload.query || payload.name);
  const queryName = normalizePublicDnsName(originalInput, { allowServiceLabels: true });
  const labels = queryName.split(".");

  if (labels.length < 4 || !labels[0].startsWith("_") || !["_tcp", "_udp"].includes(labels[1])) {
    throw new DnsCheckError("INVALID_QUERY", "Enter a valid SRV name like _service._tcp.example.com.");
  }

  return {
    originalInput: originalInput.trim(),
    queryName,
    displayName: queryName,
    service: labels[0],
    protocol: labels[1],
    domain: labels.slice(2).join("."),
  };
}

function getString(value) {
  if (typeof value !== "string") {
    throw new DnsCheckError("INVALID_QUERY", "Enter a valid DNS query.");
  }

  return value;
}

function getOptionalString(value) {
  return typeof value === "string" ? value : "";
}

function normalizeSrvService(value) {
  const trimmed = value.trim().toLowerCase();
  const service = trimmed.startsWith("_") ? trimmed : `_${trimmed}`;

  if (!/^_[a-z0-9][a-z0-9-]{0,61}$/.test(service) || service.endsWith("-")) {
    throw new DnsCheckError("INVALID_QUERY", "Enter a valid SRV service.");
  }

  return service;
}

function normalizeSrvProtocol(value) {
  const trimmed = value.trim().toLowerCase();
  const protocol = trimmed.startsWith("_") ? trimmed : `_${trimmed}`;

  if (!["_tcp", "_udp"].includes(protocol)) {
    throw new DnsCheckError("INVALID_QUERY", "Enter _tcp or _udp for SRV protocol.");
  }

  return protocol;
}

function normalizePublicDnsName(value, { allowServiceLabels }) {
  const trimmed = getString(value).trim().replace(/\.$/, "").toLowerCase();
  const ascii = domainToASCII(trimmed);

  if (!ascii || ascii !== ascii.toLowerCase()) {
    throw new DnsCheckError("INVALID_QUERY", "Enter a valid public DNS name.");
  }

  if (
    ascii === "localhost" ||
    ascii.endsWith(".localhost") ||
    ascii.endsWith(".local") ||
    ascii.endsWith(".internal") ||
    ascii.endsWith(".lan") ||
    ascii.endsWith(".home") ||
    ascii.endsWith(".home.arpa") ||
    net.isIP(ascii) !== 0 ||
    /[:/?#@[\]\\\s]/.test(ascii)
  ) {
    throw new DnsCheckError("INVALID_QUERY", "Enter a valid public DNS name.");
  }

  validateDnsLength(ascii);

  const labels = ascii.split(".");

  if (labels.length < 2) {
    throw new DnsCheckError("INVALID_QUERY", "Enter a fully qualified public DNS name.");
  }

  const labelsValid = labels.every((label, index) => {
    if (allowServiceLabels && index < 2 && label.startsWith("_")) {
      return /^_[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
    }

    return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
  });

  if (!labelsValid) {
    throw new DnsCheckError("INVALID_QUERY", "Enter a valid public DNS name.");
  }

  return ascii;
}

function validateDnsLength(name) {
  if (!name || name.length > 253 || name.split(".").some((label) => label.length > 63)) {
    throw new DnsCheckError("INVALID_QUERY", "Enter a DNS name within DNS length limits.");
  }
}

function reverseIpName(address) {
  if (net.isIP(address) === 4) {
    return `${address.split(".").reverse().join(".")}.in-addr.arpa`;
  }

  const expanded = expandIpv6(address);
  return `${expanded.replace(/:/g, "").split("").reverse().join(".")}.ip6.arpa`;
}

async function checkSingleProvider(request, queryDns) {
  const provider = RESOLVER_REGISTRY[request.resolverId];
  const result = await runProviderCheck(provider, request, queryDns);

  return {
    ...result,
    mode: "single",
    resolver: summarizeProvider(provider),
    provider: summarizeProvider(provider),
  };
}

async function checkBurstProviders(request, queryDns) {
  const providers = BURST_RESOLVER_IDS.map((id) => RESOLVER_REGISTRY[id]);
  const startedAt = Date.now();
  const providerResults = await Promise.all(providers.map((provider) => runProviderCheck(provider, request, queryDns)));
  const durationMs = Date.now() - startedAt;
  const successful = providerResults.filter((result) => result.ok);
  const fingerprints = new Set(successful.map((result) => answerFingerprint(result.records)));
  const warnings = [];
  const diagnostics = [
    {
      id: "dnssec_deep_checks_disabled",
      status: "info",
      message: "Deep DNSSEC checks are disabled in multi-provider mode to keep results fast, reduce backend load, and prevent abuse.",
    },
  ];
  const status = classifyBurstStatus(providerResults, fingerprints);

  if (fingerprints.size > 1) {
    warnings.push("Providers returned different answers.");
  }

  return {
    ok: true,
    mode: "burst",
    query: formatQuery(request),
    resolver: {
      group: "fixed-10",
      providers: providers.map(summarizeProvider),
    },
    provider: null,
    responseCode: "MULTI",
    durationMs,
    status,
    records: [],
    answer: [],
    authority: [],
    additional: [],
    diagnostics,
    warnings,
    dnssec: {
      requested: false,
      doFlagSent: false,
      adFlag: successful.some((result) => result.dnssec?.adFlag),
      deepChecksDisabled: true,
      note: "Deep DNSSEC checks are disabled in multi-provider mode to keep results fast, reduce backend load, and prevent abuse.",
    },
    providers: providerResults.map((result) => ({
      ...result,
      mode: "burst",
    })),
    raw: {
      providerCount: providerResults.length,
      providers: providerResults.map((result) => ({
        resolver: result.resolver,
        responseCode: result.responseCode,
        status: result.status,
        answer: result.answer,
        authority: result.authority,
        additional: result.additional,
      })),
    },
  };
}

async function runProviderCheck(provider, request, queryDns) {
  const startedAt = Date.now();

  try {
    const dnsResponse = await queryWithFallback(provider, request.query.queryName, request.recordType, {
      queryDns,
      dnssec: request.dnssecRequested,
    });
    const durationMs = Date.now() - startedAt;
    const base = buildProviderResponse(provider, request, dnsResponse, durationMs);

    await enrichProviderResponse(base, provider, request, queryDns);

    return base;
  } catch (error) {
    const durationMs = Date.now() - startedAt;
    const status = error?.code === "DNS_TIMEOUT" ? "timeout" : "resolver-error";

    return {
      ok: false,
      mode: request.mode,
      query: formatQuery(request),
      resolver: summarizeProvider(provider),
      provider: summarizeProvider(provider),
      responseCode: null,
      durationMs,
      status,
      records: [],
      answer: [],
      authority: [],
      additional: [],
      diagnostics: [],
      warnings: [status === "timeout" ? "The DNS query timed out." : "The resolver returned an error."],
      dnssec: {
        requested: request.dnssecRequested,
        doFlagSent: request.dnssecRequested,
        adFlag: false,
      },
      raw: {
        error: status,
      },
    };
  }
}

function buildProviderResponse(provider, request, dnsResponse, durationMs) {
  const responseCode = dnsResponse.rcodeName || "UNKNOWN";
  const flags = dnsResponse.flags || {};
  const answer = normalizeRecordArray(dnsResponse.answer);
  const authority = normalizeRecordArray(dnsResponse.authority);
  const additional = normalizeRecordArray(dnsResponse.additional);
  const records = extractRequestedRecords(answer, request.recordType);
  const warnings = [];
  const diagnostics = [];
  const status = classifyResponse(request, { ...dnsResponse, rcodeName: responseCode }, records, answer);

  if (request.dnssecRequested && responseCode === "SERVFAIL") {
    warnings.push("This SERVFAIL may be caused by DNSSEC validation failure.");
  }

  if (status === "possible-sinkhole") {
    warnings.push("The answer contains addresses commonly used for blocking or sinkholes.");
  }

  return {
    ok: true,
    mode: request.mode,
    query: formatQuery(request),
    resolver: summarizeProvider(provider),
    provider: summarizeProvider(provider),
    responseCode,
    durationMs,
    status,
    records,
    answer,
    authority,
    additional,
    diagnostics,
    warnings,
    dnssec: {
      requested: request.dnssecRequested,
      doFlagSent: request.dnssecRequested,
      adFlag: Boolean(flags.ad),
      rrsigPresent: [...answer, ...authority, ...additional].some((record) => record.type === "RRSIG"),
      nsecPresent: [...answer, ...authority].some((record) => record.type === "NSEC" || record.type === "NSEC3"),
    },
    raw: {
      id: dnsResponse.id ?? null,
      responseCode,
      flags,
      question: Array.isArray(dnsResponse.question) ? dnsResponse.question : [],
      answer,
      authority,
      additional,
    },
  };
}

function normalizeRecordArray(records) {
  return Array.isArray(records) ? records.map(normalizeRecord) : [];
}

async function enrichProviderResponse(response, provider, request, queryDns) {
  if (request.recordType === "MX") {
    await enrichMxResponse(response, provider, request, queryDns);
  }

  if (request.recordType === "TXT") {
    await enrichTxtResponse(response, provider, request, queryDns);
  }

  if (request.mode === "single" && request.dnssecRequested) {
    await enrichDnssecResponse(response, provider, request, queryDns);
  }
}

async function enrichMxResponse(response, provider, request, queryDns) {
  const mxRecords = response.records.filter((record) => record.type === "MX");
  const diagnostics = [];

  for (const record of mxRecords.slice(0, 10)) {
    const [aResponse, aaaaResponse, cnameResponse] = await Promise.all([
      safeDiagnosticQuery(provider, record.exchange, "A", request, queryDns),
      safeDiagnosticQuery(provider, record.exchange, "AAAA", request, queryDns),
      safeDiagnosticQuery(provider, record.exchange, "CNAME", request, queryDns),
    ]);
    const aRecords = extractRequestedRecords(aResponse?.answer?.map(normalizeRecord) || [], "A");
    const aaaaRecords = extractRequestedRecords(aaaaResponse?.answer?.map(normalizeRecord) || [], "AAAA");
    const cnameRecords = extractRequestedRecords(cnameResponse?.answer?.map(normalizeRecord) || [], "CNAME");

    record.resolvedA = aRecords.map((item) => item.address);
    record.resolvedAAAA = aaaaRecords.map((item) => item.address);

    diagnostics.push({
      id: "mx_host_resolution",
      status: record.resolvedA.length || record.resolvedAAAA.length ? "ok" : "warn",
      exchange: record.exchange,
      preference: record.preference,
      ttl: record.ttl,
      resolvedA: record.resolvedA,
      resolvedAAAA: record.resolvedAAAA,
    });

    if (!record.resolvedA.length && !record.resolvedAAAA.length) {
      response.warnings.push(`MX host does not resolve: ${record.exchange}.`);
    }

    if (cnameRecords.length) {
      response.warnings.push(`MX target points to CNAME: ${record.exchange}.`);
    }
  }

  if (!mxRecords.length && response.responseCode === "NOERROR") {
    const [aResponse, aaaaResponse] = await Promise.all([
      safeDiagnosticQuery(provider, request.query.queryName, "A", request, queryDns),
      safeDiagnosticQuery(provider, request.query.queryName, "AAAA", request, queryDns),
    ]);
    const aRecords = extractRequestedRecords(aResponse?.answer?.map(normalizeRecord) || [], "A");
    const aaaaRecords = extractRequestedRecords(aaaaResponse?.answer?.map(normalizeRecord) || [], "AAAA");

    if (aRecords.length || aaaaRecords.length) {
      response.warnings.push("No MX records were found, but A or AAAA records exist for this name.");
      diagnostics.push({
        id: "no_mx_address_fallback",
        status: "warn",
        a: aRecords.map((record) => record.address),
        aaaa: aaaaRecords.map((record) => record.address),
      });
    }
  }

  response.diagnostics.push(...diagnostics);
}

async function enrichTxtResponse(response, provider, request, queryDns) {
  const txtValues = response.records.filter((record) => record.type === "TXT").map((record) => record.value);
  const txtDiagnostics = analyzeTxtRecords(request.query.queryName, txtValues);
  response.diagnostics.push(...txtDiagnostics.diagnostics);
  response.warnings.push(...txtDiagnostics.warnings);

  const dmarcName = request.query.queryName.startsWith("_dmarc.")
    ? request.query.queryName
    : `_dmarc.${request.query.queryName}`;
  const dmarcResponse = await safeDiagnosticQuery(provider, dmarcName, "TXT", request, queryDns);
  const dmarcValues = extractRequestedRecords(dmarcResponse?.answer?.map(normalizeRecord) || [], "TXT").map((record) => record.value);
  const dmarcDiagnostics = analyzeDmarcRecords(dmarcName, dmarcValues);

  response.diagnostics.push(...dmarcDiagnostics.diagnostics);
  response.warnings.push(...dmarcDiagnostics.warnings);
}

async function enrichDnssecResponse(response, provider, request, queryDns) {
  const [dsResponse, dnskeyResponse] = await Promise.all([
    safeDiagnosticQuery(provider, request.query.queryName, "DS", request, queryDns),
    safeDiagnosticQuery(provider, request.query.queryName, "DNSKEY", request, queryDns),
  ]);
  const dsRecords = extractRequestedRecords(dsResponse?.answer?.map(normalizeRecord) || [], "DS");
  const dnskeyRecords = extractRequestedRecords(dnskeyResponse?.answer?.map(normalizeRecord) || [], "DNSKEY");

  response.dnssec.deepChecksDisabled = false;
  response.dnssec.dsRecords = dsRecords;
  response.dnssec.dnskeyRecords = dnskeyRecords;
  response.dnssec.dsPresent = dsRecords.length > 0;
  response.dnssec.dnskeyPresent = dnskeyRecords.length > 0;
  response.diagnostics.push({
    id: "dnssec_deep_checks",
    status: "info",
    doFlagSent: response.dnssec.doFlagSent,
    adFlag: response.dnssec.adFlag,
    dsRecords: dsRecords.length,
    dnskeyRecords: dnskeyRecords.length,
    rrsigPresent: response.dnssec.rrsigPresent,
    nsecPresent: response.dnssec.nsecPresent,
  });
}

async function safeDiagnosticQuery(provider, name, type, request, queryDns) {
  try {
    return await queryWithFallback(provider, name, type, {
      queryDns,
      dnssec: request.mode === "single" && request.dnssecRequested,
    });
  } catch {
    return null;
  }
}

async function queryWithFallback(provider, name, type, { queryDns, dnssec }) {
  let lastError;

  for (const endpoint of provider.endpoints) {
    try {
      return await queryDns(endpoint, name, type, { dnssec, timeoutMs: DNS_TIMEOUT_MS });
    } catch (error) {
      lastError = error;

      if (!isFallbackError(error)) {
        throw error;
      }
    }
  }

  throw lastError || new Error("DNS query failed.");
}

function isFallbackError(error) {
  return ["DNS_TIMEOUT", "ENOTFOUND", "ENETUNREACH", "EHOSTUNREACH", "ECONNREFUSED", "EAI_AGAIN"].includes(error?.code);
}

async function queryDnsUdp(server, name, type, { dnssec, timeoutMs }) {
  const family = net.isIP(server);
  const socket = dgram.createSocket(family === 6 ? "udp6" : "udp4");
  const packet = buildDnsQuery(name, type, dnssec);

  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      fail(Object.assign(new Error("DNS query timed out."), { code: "DNS_TIMEOUT" }));
    }, timeoutMs);

    function finish(callback, value) {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timeout);
      socket.close();
      callback(value);
    }

    function fail(error) {
      finish(reject, error);
    }

    socket.once("message", (message) => {
      try {
        finish(resolve, parseDnsResponse(message));
      } catch (error) {
        fail(error);
      }
    });
    socket.once("error", fail);
    socket.send(packet, DNS_PORT, server, (error) => {
      if (error) {
        fail(error);
      }
    });
  });
}

function buildDnsQuery(name, type, dnssec) {
  const question = encodeName(name);
  const hasOpt = Boolean(dnssec);
  const buffer = Buffer.alloc(12 + question.length + 4 + (hasOpt ? 11 : 0));
  const id = randomInt(0, 65536);
  let offset = 0;

  buffer.writeUInt16BE(id, offset);
  offset += 2;
  buffer.writeUInt16BE(0x0100, offset);
  offset += 2;
  buffer.writeUInt16BE(1, offset);
  offset += 2;
  buffer.writeUInt16BE(0, offset);
  offset += 2;
  buffer.writeUInt16BE(0, offset);
  offset += 2;
  buffer.writeUInt16BE(hasOpt ? 1 : 0, offset);
  offset += 2;
  question.copy(buffer, offset);
  offset += question.length;
  buffer.writeUInt16BE(TYPE_TO_CODE[type], offset);
  offset += 2;
  buffer.writeUInt16BE(1, offset);
  offset += 2;

  if (hasOpt) {
    buffer.writeUInt8(0, offset);
    offset += 1;
    buffer.writeUInt16BE(41, offset);
    offset += 2;
    buffer.writeUInt16BE(1232, offset);
    offset += 2;
    buffer.writeUInt32BE(0x00008000, offset);
    offset += 4;
    buffer.writeUInt16BE(0, offset);
  }

  return buffer;
}

function encodeName(name) {
  const parts = name.split(".");
  const buffers = parts.map((part) => {
    const partBuffer = Buffer.from(part, "ascii");
    return Buffer.concat([Buffer.from([partBuffer.length]), partBuffer]);
  });

  return Buffer.concat([...buffers, Buffer.from([0])]);
}

function parseDnsResponse(buffer) {
  const id = buffer.readUInt16BE(0);
  const flagsValue = buffer.readUInt16BE(2);
  const qdCount = buffer.readUInt16BE(4);
  const anCount = buffer.readUInt16BE(6);
  const nsCount = buffer.readUInt16BE(8);
  const arCount = buffer.readUInt16BE(10);
  let offset = 12;
  const question = [];

  for (let index = 0; index < qdCount; index += 1) {
    const parsedName = readName(buffer, offset);
    offset = parsedName.offset;
    const typeCode = buffer.readUInt16BE(offset);
    offset += 2;
    const classCode = buffer.readUInt16BE(offset);
    offset += 2;
    question.push({
      name: parsedName.name,
      type: CODE_TO_TYPE[typeCode] || String(typeCode),
      class: classCode,
    });
  }

  const answer = [];
  const authority = [];
  const additional = [];

  for (let index = 0; index < anCount; index += 1) {
    const parsed = readRecord(buffer, offset);
    offset = parsed.offset;
    answer.push(parsed.record);
  }

  for (let index = 0; index < nsCount; index += 1) {
    const parsed = readRecord(buffer, offset);
    offset = parsed.offset;
    authority.push(parsed.record);
  }

  for (let index = 0; index < arCount; index += 1) {
    const parsed = readRecord(buffer, offset);
    offset = parsed.offset;
    additional.push(parsed.record);
  }

  const rcode = flagsValue & 0x000f;

  return {
    id,
    flags: {
      qr: Boolean(flagsValue & 0x8000),
      aa: Boolean(flagsValue & 0x0400),
      tc: Boolean(flagsValue & 0x0200),
      rd: Boolean(flagsValue & 0x0100),
      ra: Boolean(flagsValue & 0x0080),
      ad: Boolean(flagsValue & 0x0020),
      cd: Boolean(flagsValue & 0x0010),
    },
    rcode,
    rcodeName: RCODE_NAMES[rcode] || `RCODE_${rcode}`,
    question,
    answer,
    authority,
    additional,
  };
}

function readRecord(buffer, offset) {
  const parsedName = readName(buffer, offset);
  offset = parsedName.offset;
  const typeCode = buffer.readUInt16BE(offset);
  offset += 2;
  const classCode = buffer.readUInt16BE(offset);
  offset += 2;
  const ttl = buffer.readUInt32BE(offset);
  offset += 4;
  const rdLength = buffer.readUInt16BE(offset);
  offset += 2;
  const rdataOffset = offset;
  const type = CODE_TO_TYPE[typeCode] || String(typeCode);
  const record = {
    name: parsedName.name,
    type,
    class: classCode,
    ttl,
    data: parseRdata(buffer, type, rdataOffset, rdLength),
  };

  return {
    record,
    offset: rdataOffset + rdLength,
  };
}

function parseRdata(buffer, type, offset, length) {
  if (type === "A" && length === 4) {
    return Array.from(buffer.subarray(offset, offset + length)).join(".");
  }

  if (type === "AAAA" && length === 16) {
    return compressIpv6(buffer.subarray(offset, offset + length));
  }

  if (["NS", "CNAME", "PTR"].includes(type)) {
    return readName(buffer, offset).name;
  }

  if (type === "MX") {
    return {
      preference: buffer.readUInt16BE(offset),
      exchange: readName(buffer, offset + 2).name,
    };
  }

  if (type === "TXT") {
    const values = [];
    let cursor = offset;
    const end = offset + length;

    while (cursor < end) {
      const txtLength = buffer.readUInt8(cursor);
      cursor += 1;
      values.push(buffer.subarray(cursor, cursor + txtLength).toString("utf8"));
      cursor += txtLength;
    }

    return values;
  }

  if (type === "SOA") {
    const mname = readName(buffer, offset);
    const rname = readName(buffer, mname.offset);
    let cursor = rname.offset;

    return {
      mname: mname.name,
      rname: rname.name,
      serial: buffer.readUInt32BE(cursor),
      refresh: buffer.readUInt32BE(cursor + 4),
      retry: buffer.readUInt32BE(cursor + 8),
      expire: buffer.readUInt32BE(cursor + 12),
      minimum: buffer.readUInt32BE(cursor + 16),
    };
  }

  if (type === "SRV") {
    return {
      priority: buffer.readUInt16BE(offset),
      weight: buffer.readUInt16BE(offset + 2),
      port: buffer.readUInt16BE(offset + 4),
      target: readName(buffer, offset + 6).name,
    };
  }

  if (type === "CAA") {
    return {
      flags: buffer.readUInt8(offset),
      tag: buffer.subarray(offset + 2, offset + 2 + buffer.readUInt8(offset + 1)).toString("ascii"),
      value: buffer.subarray(offset + 2 + buffer.readUInt8(offset + 1), offset + length).toString("utf8"),
    };
  }

  if (type === "DS") {
    return {
      keyTag: buffer.readUInt16BE(offset),
      algorithm: buffer.readUInt8(offset + 2),
      digestType: buffer.readUInt8(offset + 3),
      digest: buffer.subarray(offset + 4, offset + length).toString("hex"),
    };
  }

  if (type === "DNSKEY") {
    return {
      flags: buffer.readUInt16BE(offset),
      protocol: buffer.readUInt8(offset + 2),
      algorithm: buffer.readUInt8(offset + 3),
      publicKey: buffer.subarray(offset + 4, offset + length).toString("base64"),
    };
  }

  if (type === "RRSIG") {
    const signer = readName(buffer, offset + 18);
    return {
      typeCovered: CODE_TO_TYPE[buffer.readUInt16BE(offset)] || String(buffer.readUInt16BE(offset)),
      algorithm: buffer.readUInt8(offset + 2),
      labels: buffer.readUInt8(offset + 3),
      originalTtl: buffer.readUInt32BE(offset + 4),
      expiration: buffer.readUInt32BE(offset + 8),
      inception: buffer.readUInt32BE(offset + 12),
      keyTag: buffer.readUInt16BE(offset + 16),
      signerName: signer.name,
      signature: buffer.subarray(signer.offset, offset + length).toString("base64"),
    };
  }

  if (type === "NSEC") {
    const next = readName(buffer, offset);
    return {
      nextDomainName: next.name,
      typeBitMaps: buffer.subarray(next.offset, offset + length).toString("hex"),
    };
  }

  if (type === "NSEC3") {
    const saltLength = buffer.readUInt8(offset + 4);
    const hashLengthOffset = offset + 5 + saltLength;
    const hashLength = buffer.readUInt8(hashLengthOffset);

    return {
      hashAlgorithm: buffer.readUInt8(offset),
      flags: buffer.readUInt8(offset + 1),
      iterations: buffer.readUInt16BE(offset + 2),
      salt: buffer.subarray(offset + 5, offset + 5 + saltLength).toString("hex"),
      nextHashedOwnerName: buffer.subarray(hashLengthOffset + 1, hashLengthOffset + 1 + hashLength).toString("hex"),
      typeBitMaps: buffer.subarray(hashLengthOffset + 1 + hashLength, offset + length).toString("hex"),
    };
  }

  if (type === "41") {
    return {
      udpPayloadSize: buffer.readUInt16BE(offset - 8),
    };
  }

  return buffer.subarray(offset, offset + length).toString("base64");
}

function readName(buffer, offset, depth = 0) {
  if (depth > 20) {
    throw new Error("DNS compression pointer depth exceeded.");
  }

  const labels = [];
  let cursor = offset;
  let jumped = false;
  let nextOffset = offset;

  while (true) {
    const length = buffer.readUInt8(cursor);

    if ((length & 0xc0) === 0xc0) {
      const pointer = ((length & 0x3f) << 8) | buffer.readUInt8(cursor + 1);
      const pointed = readName(buffer, pointer, depth + 1);
      labels.push(pointed.name);
      cursor += 2;
      nextOffset = cursor;
      jumped = true;
      break;
    }

    if (length === 0) {
      cursor += 1;
      nextOffset = cursor;
      break;
    }

    cursor += 1;
    labels.push(buffer.subarray(cursor, cursor + length).toString("ascii"));
    cursor += length;
  }

  return {
    name: labels.filter(Boolean).join("."),
    offset: jumped ? nextOffset : cursor,
  };
}

function normalizeRecord(record) {
  const base = {
    name: record.name,
    type: record.type,
    ttl: record.ttl,
  };

  if (record.type === "A" || record.type === "AAAA") {
    return { ...base, address: record.data };
  }

  if (record.type === "CNAME") {
    return { ...base, target: record.data };
  }

  if (record.type === "NS") {
    return { ...base, host: record.data };
  }

  if (record.type === "PTR") {
    return { ...base, host: record.data };
  }

  if (record.type === "TXT") {
    return { ...base, chunks: record.data, value: record.data.join("") };
  }

  if (record.type === "MX") {
    return { ...base, preference: record.data.preference, exchange: record.data.exchange };
  }

  if (record.type === "SOA") {
    return { ...base, ...record.data };
  }

  if (record.type === "SRV") {
    return { ...base, ...record.data };
  }

  if (record.type === "CAA") {
    return { ...base, ...record.data };
  }

  return { ...base, data: record.data };
}

function extractRequestedRecords(records, recordType) {
  return records.filter((record) => record.type === recordType);
}

function classifyResponse(request, dnsResponse, records, answer) {
  if (dnsResponse.rcodeName === "NXDOMAIN") {
    return "nxdomain";
  }

  if (dnsResponse.rcodeName === "SERVFAIL") {
    return request.dnssecRequested ? "possible-dnssec-failure" : "servfail";
  }

  if (dnsResponse.rcodeName === "REFUSED") {
    return "refused";
  }

  if (hasSinkholeAddress(records)) {
    return "possible-sinkhole";
  }

  if (!records.length && dnsResponse.rcodeName === "NOERROR") {
    const cnameDepth = answer.filter((record) => record.type === "CNAME").length;

    if (cnameDepth > CNAME_FOLLOW_LIMIT) {
      return "resolver-error";
    }

    return "no-record";
  }

  return "ok";
}

function classifyBurstStatus(results, fingerprints) {
  if (results.some((result) => result.status === "possible-sinkhole")) {
    return "possible-sinkhole";
  }

  if (results.some((result) => ["refused", "servfail", "possible-dnssec-failure"].includes(result.status))) {
    return "possible-filtering";
  }

  if (fingerprints.size > 1) {
    return "different-answer";
  }

  if (results.every((result) => result.status === "nxdomain")) {
    return "nxdomain";
  }

  if (results.every((result) => result.status === "no-record")) {
    return "no-record";
  }

  return results.some((result) => result.status === "ok") ? "ok" : "resolver-error";
}

function answerFingerprint(records) {
  return JSON.stringify(records.map((record) => {
    const clone = { ...record };
    delete clone.ttl;
    return clone;
  }).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))));
}

function hasSinkholeAddress(records) {
  return records.some((record) => {
    if (!["A", "AAAA"].includes(record.type)) {
      return false;
    }

    return ["0.0.0.0", "127.0.0.1", "::", "::1"].includes(record.address);
  });
}

function analyzeTxtRecords(queryName, values) {
  const diagnostics = [];
  const warnings = [];
  const spfRecords = values.filter((value) => value.toLowerCase().startsWith("v=spf1"));

  if (spfRecords.length > 1) {
    warnings.push("Multiple SPF records were found.");
  }

  for (const spf of spfRecords) {
    const mechanisms = spf.split(/\s+/).slice(1);
    const mechanismDetails = mechanisms.map(parseSpfTerm);
    const lookupMechanisms = mechanisms.filter((part) => /^(?:[+?~-])?(?:include:|a(?::|\/|$)|mx(?::|\/|$)|ptr(?::|$)|exists:|redirect=)/i.test(part));
    const allMechanism = mechanisms.find((part) => /^(?:[+?~-])?all$/i.test(part)) || null;

    diagnostics.push({
      id: "spf",
      status: "info",
      queryName,
      value: spf,
      mechanisms,
      mechanismDetails,
      include: mechanisms.filter((part) => /^(?:[+?~-])?include:/i.test(part)),
      redirect: mechanisms.find((part) => /^redirect=/i.test(part)) || null,
      all: allMechanism,
      lookupCountEstimate: lookupMechanisms.length,
    });

    if (lookupMechanisms.length > 10) {
      warnings.push("SPF has more than 10 DNS-lookup mechanisms.");
    } else if (lookupMechanisms.length >= 8) {
      warnings.push("SPF is close to the 10 DNS-lookup mechanism limit.");
    }

    if (mechanisms.some((part) => /^(?:[+?~-])?ptr(?::|$)/i.test(part))) {
      warnings.push("SPF uses the deprecated ptr mechanism.");
    }

    if (allMechanism === "+all" || allMechanism === "all") {
      warnings.push("SPF is overly permissive with +all.");
    }

    if (!allMechanism) {
      warnings.push("SPF does not include an all mechanism.");
    }

    if (mechanismDetails.some((mechanism) => !mechanism.valid)) {
      warnings.push("SPF contains an invalid-looking or unsupported mechanism.");
    }
  }

  values.filter((value) => /(^|;)\s*v=DKIM1/i.test(value) || /(^|;)\s*(k|p)=/i.test(value)).forEach((value) => {
    const parsed = parseTagValueRecord(value);
    diagnostics.push({
      id: "dkim",
      status: parsed.p === "" ? "warn" : "info",
      selectorStyleQuery: queryName.includes("._domainkey."),
      value,
      keyType: parsed.k || null,
      hasPublicKey: typeof parsed.p === "string" && parsed.p.length > 0,
      emptyPublicKey: parsed.p === "",
    });
  });

  values.filter((value) => /^MS=/i.test(value)).forEach((value) => {
    diagnostics.push({ id: "microsoft_365_verification", status: "info", value });
  });

  values.filter((value) => /^google-site-verification=/i.test(value)).forEach((value) => {
    diagnostics.push({ id: "google_verification", status: "info", value });
  });

  if (queryName.startsWith("_acme-challenge.") || values.some((value) => /^[A-Za-z0-9_-]{20,}$/.test(value))) {
    diagnostics.push({
      id: "acme_challenge",
      status: "info",
      queryName,
      values: values.filter((value) => /^[A-Za-z0-9_-]{20,}$/.test(value)),
    });
  }

  return { diagnostics, warnings };
}

function parseSpfTerm(token) {
  const resultByQualifier = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
  };
  const normalizedToken = String(token || "").trim();
  const qualifier = /^[+?~-]/.test(normalizedToken) ? normalizedToken[0] : "+";
  const body = qualifier === normalizedToken[0] ? normalizedToken.slice(1) : normalizedToken;
  const base = {
    token: normalizedToken,
    qualifier,
    result: resultByQualifier[qualifier] || "pass",
    mechanism: "unknown",
    value: null,
    prefix: null,
    modifier: false,
    valid: false,
  };

  if (!normalizedToken || !body) {
    return base;
  }

  const modifierMatch = body.match(/^(redirect|exp)=(.+)$/i);

  if (modifierMatch) {
    return {
      ...base,
      qualifier: null,
      result: null,
      mechanism: modifierMatch[1].toLowerCase(),
      value: modifierMatch[2],
      modifier: true,
      valid: isLikelySpfDomainSpec(modifierMatch[2]),
    };
  }

  const mechanismMatch = body.match(/^([a-z0-9]+)(?::([^/]+))?(?:\/(.+))?$/i);

  if (!mechanismMatch) {
    return base;
  }

  const mechanism = mechanismMatch[1].toLowerCase();
  const value = mechanismMatch[2] || null;
  const prefix = mechanismMatch[3] || null;
  const commonMechanisms = new Set(["all", "include", "a", "mx", "ip4", "ip6", "exists", "ptr"]);
  const valid = commonMechanisms.has(mechanism) && isValidSpfMechanismShape(mechanism, value, prefix);

  return {
    ...base,
    mechanism,
    value,
    prefix,
    modifier: false,
    valid,
  };
}

function isValidSpfMechanismShape(mechanism, value, prefix) {
  if (mechanism === "all") {
    return !value && !prefix;
  }

  if (mechanism === "include" || mechanism === "exists" || mechanism === "ptr") {
    return Boolean(value) && !prefix && isLikelySpfDomainSpec(value);
  }

  if (mechanism === "a" || mechanism === "mx") {
    return (!value || isLikelySpfDomainSpec(value)) && (!prefix || isLikelySpfPrefix(prefix));
  }

  if (mechanism === "ip4") {
    return Boolean(value) && isLikelySpfIpv4(value) && (!prefix || isLikelySpfPrefix(prefix, 32));
  }

  if (mechanism === "ip6") {
    return Boolean(value) && net.isIP(value) === 6 && (!prefix || isLikelySpfPrefix(prefix, 128));
  }

  return false;
}

function isLikelySpfDomainSpec(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 253 && !/\s/.test(value);
}

function isLikelySpfPrefix(value, max = 128) {
  if (typeof value !== "string") {
    return false;
  }

  const parts = value.split("/");

  return parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= max);
}

function isLikelySpfIpv4(value) {
  return typeof value === "string" && value.split(".").length === 4 && value.split(".").every((part) => (
    /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
  ));
}

function analyzeDmarcRecords(name, values) {
  const diagnostics = [];
  const warnings = [];
  const records = values.filter((value) => value.toLowerCase().startsWith("v=dmarc1"));

  if (!records.length) {
    warnings.push(`No DMARC record was found at ${name}.`);
  }

  if (records.length > 1) {
    warnings.push(`Multiple DMARC records were found at ${name}.`);
  }

  for (const value of records) {
    const parsed = parseTagValueRecord(value);

    diagnostics.push({
      id: "dmarc",
      status: parsed.p === "none" ? "warn" : "info",
      name,
      value,
      p: parsed.p || null,
      sp: parsed.sp || null,
      rua: parsed.rua || null,
      ruf: parsed.ruf || null,
      adkim: parsed.adkim || null,
      aspf: parsed.aspf || null,
      pct: parsed.pct || null,
    });

    if (parsed.p === "none") {
      warnings.push("DMARC policy is p=none.");
    }
  }

  return { diagnostics, warnings };
}

function parseTagValueRecord(value) {
  return Object.fromEntries(value.split(";").map((part) => {
    const [rawKey, ...rawValue] = part.trim().split("=");
    return [rawKey?.trim().toLowerCase(), rawValue.join("=").trim()];
  }).filter(([key]) => key));
}

function buildCacheKey(request) {
  return JSON.stringify({
    mode: request.mode,
    queryName: request.query.queryName,
    originalInput: request.query.originalInput,
    recordType: request.recordType,
    resolver: request.mode === "single" ? request.resolverId : "fixed-10",
    protocol: request.protocol,
    options: request.options,
    dnssec: request.dnssecRequested,
  });
}

function withCacheMetadata(response, { fromCache, ttlSeconds, storedAt, now }) {
  const ageSeconds = Math.max(0, Math.floor((now - storedAt) / 1000));

  return {
    ...clone(response),
    cache: {
      fromCache,
      cacheScope: "site",
      cacheTtlSeconds: ttlSeconds,
      cacheAgeSeconds: Math.min(ageSeconds, ttlSeconds),
      cacheExpiresInSeconds: Math.max(0, ttlSeconds - ageSeconds),
    },
  };
}

function withoutCacheMetadata(response) {
  const cloneResponse = clone(response);
  delete cloneResponse.cache;
  return cloneResponse;
}

function enforceRateLimit(clientIp, cost, now) {
  const bucket = rateBuckets.get(clientIp) || [];
  const fresh = bucket.filter((entry) => now - entry.time < RATE_WINDOW_HOUR_MS);
  const hourTotal = fresh.reduce((total, entry) => total + entry.cost, 0);
  const fiveMinuteTotal = fresh
    .filter((entry) => now - entry.time < RATE_WINDOW_FIVE_MINUTES_MS)
    .reduce((total, entry) => total + entry.cost, 0);

  if (fiveMinuteTotal + cost > RATE_LIMIT_FIVE_MINUTES || hourTotal + cost > RATE_LIMIT_HOUR) {
    rateBuckets.set(clientIp, fresh);
    throw new DnsCheckError("RATE_LIMITED", "Too many live DNS checks were made recently. Please try again later.");
  }

  fresh.push({ time: now, cost });
  rateBuckets.set(clientIp, fresh);
}

function formatQuery(request) {
  return {
    input: request.query.originalInput,
    queryName: request.query.queryName,
    displayName: request.query.displayName,
    recordType: request.recordType,
    service: request.query.service || null,
    protocol: request.query.protocol || null,
    domain: request.query.domain || null,
  };
}

function summarizeProvider(provider) {
  return {
    id: provider.id,
    name: provider.name,
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function compressIpv6(bytes) {
  const groups = [];

  for (let index = 0; index < 16; index += 2) {
    groups.push(bytes.readUInt16BE(index).toString(16));
  }

  let bestStart = -1;
  let bestLength = 0;
  let currentStart = -1;
  let currentLength = 0;

  groups.forEach((group, index) => {
    if (group === "0") {
      if (currentStart === -1) {
        currentStart = index;
        currentLength = 0;
      }
      currentLength += 1;
    } else {
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
      currentStart = -1;
      currentLength = 0;
    }
  });

  if (currentLength > bestLength) {
    bestStart = currentStart;
    bestLength = currentLength;
  }

  if (bestLength < 2) {
    return groups.join(":");
  }

  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");

  if (!left && !right) {
    return "::";
  }

  if (!left) {
    return `::${right}`;
  }

  if (!right) {
    return `${left}::`;
  }

  return `${left}::${right}`;
}

function expandIpv6(address) {
  const normalizedAddress = address.toLowerCase();
  const ipv4Match = normalizedAddress.match(/(^|:)(\d+\.\d+\.\d+\.\d+)$/);
  let ipv6Address = normalizedAddress;
  let ipv4Parts = [];

  if (ipv4Match) {
    const ipv4 = ipv4Match[2];
    const ipv4Value = ipv4ToInt(ipv4);
    ipv4Parts = [
      ((ipv4Value >>> 16) & 0xffff).toString(16),
      (ipv4Value & 0xffff).toString(16),
    ];
    ipv6Address = normalizedAddress.slice(0, normalizedAddress.length - ipv4.length);
    ipv6Address = ipv6Address.endsWith(":") ? ipv6Address.slice(0, -1) : ipv6Address;
  }

  const sides = ipv6Address.split("::");
  const left = sides[0] ? sides[0].split(":").filter(Boolean) : [];
  const right = sides[1] ? sides[1].split(":").filter(Boolean) : [];
  const missingGroups = 8 - left.length - right.length - ipv4Parts.length;
  const groups = sides.length === 2
    ? [...left, ...Array(missingGroups).fill("0"), ...right, ...ipv4Parts]
    : [...left, ...right, ...ipv4Parts];

  return groups.map((group) => group.padStart(4, "0")).join(":");
}

function isBlockedIp(address) {
  if (net.isIP(address) === 4) {
    return isBlockedIpv4(address);
  }

  if (net.isIP(address) === 6) {
    const mappedIpv4 = getIpv4MappedAddress(address);
    return mappedIpv4 ? isBlockedIpv4(mappedIpv4) : isBlockedIpv6(address);
  }

  return true;
}

function isBlockedIpv4(address) {
  const value = ipv4ToInt(address);

  return [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
    ["255.255.255.255", 32],
    ["169.254.169.254", 32],
  ].some(([range, prefix]) => ipv4InCidr(value, ipv4ToInt(range), prefix));
}

function isBlockedIpv6(address) {
  const value = ipv6ToBigInt(address);

  return [
    ["::", 128],
    ["::1", 128],
    ["100::", 64],
    ["2001:db8::", 32],
    ["fc00::", 7],
    ["fe80::", 10],
    ["ff00::", 8],
  ].some(([range, prefix]) => ipv6InCidr(value, ipv6ToBigInt(range), prefix));
}

function ipv4ToInt(address) {
  return address.split(".").reduce((value, part) => {
    return (value << 8) + Number(part);
  }, 0) >>> 0;
}

function ipv4InCidr(value, range, prefix) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (range & mask);
}

function ipv6ToBigInt(address) {
  return BigInt(`0x${expandIpv6(address).replace(/:/g, "")}`);
}

function ipv6InCidr(value, range, prefix) {
  const shift = BigInt(128 - prefix);
  return (value >> shift) === (range >> shift);
}

function getIpv4MappedAddress(address) {
  const value = ipv6ToBigInt(address);
  const mappedPrefix = ipv6ToBigInt("::ffff:0:0") >> 32n;

  if ((value >> 32n) !== mappedPrefix) {
    return null;
  }

  const ipv4Value = Number(value & 0xffffffffn);

  return [
    (ipv4Value >>> 24) & 255,
    (ipv4Value >>> 16) & 255,
    (ipv4Value >>> 8) & 255,
    ipv4Value & 255,
  ].join(".");
}
