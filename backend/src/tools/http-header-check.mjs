import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { STATUS_CODES } from "node:http";
import { domainToASCII } from "node:url";

const CACHE_TTL_SECONDS = 60;
const REDIRECT_LIMIT = 2;
const REQUEST_TIMEOUT_MS = 7000;
const DNS_FAMILY_TIMEOUT_MS = 3000;
const RATE_WINDOW_FIVE_MINUTES_MS = 5 * 60 * 1000;
const RATE_WINDOW_HOUR_MS = 60 * 60 * 1000;
const RATE_LIMIT_FIVE_MINUTES = 80;
const RATE_LIMIT_HOUR = 500;
const TARGET_RATE_LIMIT_FIVE_MINUTES = 30;
const GLOBAL_RATE_LIMIT_FIVE_MINUTES = 350;
const ACTIVE_CHECK_LIMIT = 12;

export const HTTP_HEADER_CACHE_TTL_SECONDS = CACHE_TTL_SECONDS;
export const HTTP_HEADER_REDIRECT_LIMIT = REDIRECT_LIMIT;
export const HTTP_PORTS = Object.freeze([80, 8000, 8008, 8080, 8081, 8888]);
export const HTTPS_PORTS = Object.freeze([443, 4443, 8443, 8444, 9443, 10443]);

const SUPPORTED_MODES = new Set(["auto", "https", "http", "both"]);
const HTTP_PORT_SET = new Set(HTTP_PORTS);
const HTTPS_PORT_SET = new Set(HTTPS_PORTS);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const IMPORTANT_SECURITY_HEADERS = Object.freeze([
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
]);
const REQUEST_ERROR_MESSAGES = Object.freeze({
  REQUEST_TIMEOUT: "HTTP header request timed out.",
  TLS_CONNECTION_FAILED: "TLS connection failed while checking the website.",
  CONNECTION_REFUSED: "Connection refused by the website.",
  CONNECTION_RESET: "Connection reset while checking the website.",
  HTTP_CHECK_FAILED: "HTTP header check failed.",
});
const TLS_REQUEST_ERROR_CODES = new Set([
  "CERT_CHAIN_TOO_LONG",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_REVOKED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
]);
const ADDITIONAL_TLS_CA_CERTIFICATES = Object.freeze([
  // Some public sites omit this DigiCert/Thawte intermediate while browsers recover from cache/AIA.
  // Supplying it keeps normal TLS verification strict without fetching extra URLs.
  `-----BEGIN CERTIFICATE-----
MIIFOjCCBCKgAwIBAgIQB8LG0yxvDgqrrA3Q+fzVszANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0yMDA3MDIxMjQzMDJaFw0zMDA3MDIxMjQzMDJaMEIxCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxHDAaBgNVBAMTE1RoYXd0ZSBFViBSU0Eg
Q0EgRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ6jsIHs3bmIoe
7DvnuSvGX375jpWKv25Gf7uz8GZQT3DFVHeRS0NKn5WosqMVNYJKKEImR1Gb2dxl
90/GDypngguJeBVxdTtgGWPpGnuKPXfc6Qy8yKS1SRQsEs2q2EHl0tEU+/vyNro0
DDZcox947My8htb1dLx0Q/y9KjEuagQ5AXeLidtiaiAyKnThZRslD8EK/EcHRvkP
AVMSfGyCVmho3VLBP7LAlLA/RyrAX282OfK8lPZqsASNsOQhmsZPT3IuQhXz7RXc
nCpBM+GfZoFSP6+uO5j8TZMkqLTAuVAsSyGY8zNbzYupA7QmPcIfAwqG1oD9dGah
2GgKoeTnAgMBAAGjggILMIICBzAdBgNVHQ4EFgQUbC7kYbTDub3wyq2mwWh6uNTM
HaAwHwYDVR0jBBgwFoAUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDgYDVR0PAQH/BAQD
AgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAG
AQH/AgEAMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
ZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2lj
ZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMi5jcmwwN6A1oDOGMWh0dHA6Ly9j
cmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMi5jcmwwgc4GA1Ud
IASBxjCBwzCBwAYEVR0gADCBtzAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGln
aWNlcnQuY29tL0NQUzCBigYIKwYBBQUHAgIwfgx8QW55IHVzZSBvZiB0aGlzIENl
cnRpZmljYXRlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIFJlbHlpbmcg
UGFydHkgQWdyZWVtZW50IGxvY2F0ZWQgYXQgaHR0cHM6Ly93d3cuZGlnaWNlcnQu
Y29tL3JwYS11YTANBgkqhkiG9w0BAQsFAAOCAQEADf6H4Rxu128yUZjIR/vkWEv0
PnYKWUQkGXwbqaioq/zjVC/+LrIwBKwEH2aBQyBO/uvMwF+4PSThZKinw51Pfp8w
PcaBMeuQR1PEIYjQN3+NjRpMIFb2CUtbnMsHybKqKSW3rsTT2r2EIBtDrZ3EfeEg
5bfneV6PKvGqcQRZq5BBNTH11tedhcLJB+7F7GRVz8cKCTz0INpQk8gthjBND1+7
CR+ZHTWPqdXGRqiFJ09NTVmohj4dgL3VyOIArpmPbigODbp80fxzoQJepkHFef6q
mniWnIl7HApTrTIV/UN22gbCcL5dosGv69wnOVQomQsalcOkujetA5BruTiB9A==
-----END CERTIFICATE-----`,
]);
const LOCAL_SUFFIXES = [
  ".localhost",
  ".local",
  ".lan",
  ".home",
  ".internal",
  ".intranet",
  ".corp",
  ".localdomain",
];

const cache = new Map();
const rateBuckets = new Map();
const targetRateBuckets = new Map();
const globalRateBucket = [];
let activeChecks = 0;
let trustedTlsCaCertificates = null;

export class HttpHeaderCheckError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = "HttpHeaderCheckError";
    this.code = code;
    this.safeMessage = message;

    if (options.cause) {
      this.cause = options.cause;
    }
  }
}

export async function checkHttpHeader(payload, options = {}) {
  const now = options.now || Date.now;
  const request = normalizeHttpHeaderCheckRequest(payload || {});
  const checkSpecs = buildCheckSpecs(request);
  const startedAt = now();
  const checks = [];
  const freshSpecs = [];

  for (const spec of checkSpecs) {
    const cached = cache.get(spec.cacheKey);

    if (cached && cached.expiresAt > startedAt) {
      checks.push(withCheckCacheMetadata(cached.response, {
        cached: true,
        storedAt: cached.storedAt,
        now: startedAt,
      }));
    } else {
      if (cached) {
        cache.delete(spec.cacheKey);
      }

      freshSpecs.push(spec);
    }
  }

  const tokensConsumed = freshSpecs.length;

  if (tokensConsumed > 0) {
    enforceRateLimit(options.clientIp || "unknown", request.cleanHost, tokensConsumed, startedAt);
  }

  const release = acquireActiveCheck(tokensConsumed);

  try {
    for (const spec of freshSpecs) {
      const response = await runProtocolCheck(spec, {
        resolveAddresses: options.resolveAddresses || resolvePublicAddresses,
        requestUrl: options.requestUrl || requestHeaders,
        logger: options.logger,
        now,
      });

      const responseWithCacheMetadata = withCheckCacheMetadata(response, {
        cached: false,
        storedAt: startedAt,
        now: startedAt,
      });

      cache.set(spec.cacheKey, {
        storedAt: startedAt,
        expiresAt: startedAt + CACHE_TTL_SECONDS * 1000,
        response: clone(responseWithCacheMetadata),
      });
      checks.push(responseWithCacheMetadata);
    }
  } finally {
    release();
  }

  const orderedChecks = checkSpecs.map((spec) => {
    return checks.find((check) => check.cacheKey === spec.cacheKey);
  }).filter(Boolean).map(({ cacheKey, ...check }) => check);

  return {
    ok: orderedChecks.every((check) => check.ok !== false),
    input: {
      original: request.original,
      cleanHost: request.cleanHost,
      protocolMode: request.protocolMode,
    },
    budget: {
      checksRequested: checkSpecs.length,
      freshChecks: tokensConsumed,
      cachedChecks: checkSpecs.length - tokensConsumed,
      tokensConsumed,
    },
    cache: {
      ttlSeconds: CACHE_TTL_SECONDS,
    },
    redirectLimit: REDIRECT_LIMIT,
    checks: orderedChecks,
  };
}

export function normalizeHttpHeaderCheckRequest(payload) {
  const original = getTargetInput(payload).trim();
  const cleanHost = normalizeTargetHost(original);
  const protocolMode = typeof payload.protocolMode === "string" && SUPPORTED_MODES.has(payload.protocolMode)
    ? payload.protocolMode
    : "auto";
  const port = normalizeSelectedPort(payload.port, protocolMode);

  return {
    original,
    cleanHost,
    protocolMode,
    port,
  };
}

export function resetHttpHeaderCheckState() {
  cache.clear();
  rateBuckets.clear();
  targetRateBuckets.clear();
  globalRateBucket.length = 0;
  activeChecks = 0;
}

export function isBlockedPublicAddress(address) {
  return isBlockedIp(address);
}

function getTargetInput(payload) {
  const value = payload.target ?? payload.url ?? payload.host ?? payload.input;

  if (typeof value !== "string" || !value.trim()) {
    throw new HttpHeaderCheckError("INVALID_TARGET", "Enter a public website domain name.");
  }

  return value;
}

function normalizeTargetHost(value) {
  const trimmed = value.trim();
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z\d+\-.]*):\/\//);

  if (schemeMatch && !["http", "https"].includes(schemeMatch[1].toLowerCase())) {
    throw new HttpHeaderCheckError("UNSUPPORTED_PROTOCOL", "Unsupported protocol. Only HTTP and HTTPS URLs are supported.");
  }

  const bracketless = trimmed.replace(/^\[/, "").replace(/\]$/, "");

  if (net.isIP(bracketless) !== 0) {
    throw new HttpHeaderCheckError("IP_NOT_ALLOWED", "IP addresses are not allowed. Enter a public domain name instead.");
  }

  let parsed;

  try {
    parsed = new URL(schemeMatch ? trimmed : `http://${trimmed}`);
  } catch {
    throw new HttpHeaderCheckError("INVALID_TARGET", "Enter a valid public website domain name.");
  }

  if (parsed.username || parsed.password || parsed.port) {
    throw new HttpHeaderCheckError("INVALID_PORT", "Port is not supported. Use the Advanced port dropdown with a supported HTTP/HTTPS port.");
  }

  const host = parsed.hostname.replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "").toLowerCase();

  if (net.isIP(host) !== 0) {
    throw new HttpHeaderCheckError("IP_NOT_ALLOWED", "IP addresses are not allowed. Enter a public domain name instead.");
  }

  return normalizePublicHostname(host);
}

function normalizeRedirectHost(url) {
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new HttpHeaderCheckError("BLOCKED_REDIRECT", "Redirect target is blocked because it points to a private/internal/unsupported address.");
  }

  const host = url.hostname.replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "").toLowerCase();

  if (net.isIP(host) !== 0) {
    throw new HttpHeaderCheckError("BLOCKED_REDIRECT", "Redirect target is blocked because it points to a private/internal/unsupported address.");
  }

  return normalizePublicHostname(host, "BLOCKED_REDIRECT");
}

function normalizePublicHostname(host, errorCode = null) {
  const ascii = domainToASCII(host);

  if (!ascii || ascii !== ascii.toLowerCase()) {
    throw new HttpHeaderCheckError(errorCode || "INVALID_TARGET", "Enter a valid public website domain name.");
  }

  const localMessage = "Local/internal hostnames are not allowed. This tool only checks public websites.";

  if (
    ascii === "localhost" ||
    LOCAL_SUFFIXES.some((suffix) => ascii.endsWith(suffix)) ||
    ascii.includes("..") ||
    /[:/?#@[\]\\\s]/.test(ascii)
  ) {
    throw new HttpHeaderCheckError(errorCode || "LOCAL_HOSTNAME_NOT_ALLOWED", errorCode ? "Redirect target is blocked because it points to a private/internal/unsupported address." : localMessage);
  }

  const labels = ascii.split(".");

  if (labels.length < 2) {
    throw new HttpHeaderCheckError(errorCode || "LOCAL_HOSTNAME_NOT_ALLOWED", errorCode ? "Redirect target is blocked because it points to a private/internal/unsupported address." : localMessage);
  }

  if (ascii.length > 253 || labels.some((label) => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new HttpHeaderCheckError(errorCode || "INVALID_TARGET", "Enter a valid public website domain name.");
  }

  return ascii;
}

function normalizeSelectedPort(port, protocolMode) {
  if (protocolMode === "auto" || protocolMode === "both") {
    return null;
  }

  const defaultPort = protocolMode === "https" ? 443 : 80;

  if (port === undefined || port === null || port === "") {
    return defaultPort;
  }

  const portNumber = Number(port);
  const allowed = protocolMode === "https" ? HTTPS_PORT_SET : HTTP_PORT_SET;

  if (!Number.isInteger(portNumber) || !allowed.has(portNumber)) {
    throw new HttpHeaderCheckError("INVALID_PORT", "Port is not supported. Use the Advanced port dropdown with a supported HTTP/HTTPS port.");
  }

  return portNumber;
}

function buildCheckSpecs(request) {
  const specs = [];

  if (request.protocolMode === "auto") {
    specs.push(buildCheckSpec(request, "auto", "http", 80));
  } else if (request.protocolMode === "both") {
    specs.push(buildCheckSpec(request, "http", "http", 80));
    specs.push(buildCheckSpec(request, "https", "https", 443));
  } else {
    specs.push(buildCheckSpec(request, request.protocolMode, request.protocolMode, request.port));
  }

  return specs;
}

function buildCheckSpec(request, protocolLabel, scheme, port) {
  const startUrl = formatUrl(scheme, request.cleanHost, port);

  return {
    protocol: protocolLabel,
    scheme,
    host: request.cleanHost,
    port,
    startUrl,
    cacheKey: `http-header-check:v1:${request.cleanHost}:${protocolLabel === "auto" ? "auto" : `${scheme}:${port}`}`,
  };
}

async function runProtocolCheck(spec, options) {
  const startedAt = options.now();
  const chain = [spec.startUrl];
  const redirects = [];
  let currentUrl = new URL(spec.startUrl);
  let redirectsFollowed = 0;
  let lastResponse = null;
  let addresses = [];

  for (let requestIndex = 0; requestIndex < REDIRECT_LIMIT + 1; requestIndex += 1) {
    try {
      const cleanHost = requestIndex === 0 ? spec.host : normalizeRedirectHost(currentUrl);
      const resolvedAddresses = await options.resolveAddresses(cleanHost);
      const addressErrorCode = requestIndex === 0 ? "BLOCKED_TARGET" : "BLOCKED_REDIRECT";
      addresses = normalizeResolvedPublicAddresses(resolvedAddresses, addressErrorCode);
    } catch (error) {
      if (requestIndex > 0) {
        return buildBlockedRedirectCheck(spec, chain, redirects, currentUrl, error);
      }

      throw error;
    }

    lastResponse = await options.requestUrl(currentUrl, {
      timeoutMs: REQUEST_TIMEOUT_MS,
      addresses,
      logger: options.logger,
    });

    const location = getHeaderValue(lastResponse.headers, "location");

    if (REDIRECT_STATUSES.has(lastResponse.status) && location) {
      if (redirectsFollowed >= REDIRECT_LIMIT) {
        return buildTooManyRedirectsCheck(spec, chain, redirects, currentUrl, location, lastResponse, startedAt, options.now());
      }

      let nextUrl;

      try {
        nextUrl = new URL(location, currentUrl);
        normalizeRedirectHost(nextUrl);
      } catch {
        return buildBlockedRedirectCheck(spec, chain, redirects, currentUrl, null, location, lastResponse);
      }

      redirectsFollowed += 1;
      redirects.push(buildRedirectHop(currentUrl, formatDisplayUrl(nextUrl), lastResponse, location));
      currentUrl = nextUrl;
      chain.push(formatDisplayUrl(currentUrl));
      continue;
    }

    break;
  }

  const headers = normalizeHeaderList(lastResponse?.headers || []);
  const interestingHeaders = explainInterestingHeaders(headers);
  const findings = analyzeHeaders(headers, currentUrl);
  const durationMs = Math.max(0, options.now() - startedAt);

  return {
    cacheKey: spec.cacheKey,
    ok: true,
    protocol: spec.protocol,
    port: spec.port,
    cached: false,
    startUrl: spec.startUrl,
    finalUrl: formatDisplayUrl(currentUrl),
    finalCheckedUrl: formatDisplayUrl(currentUrl),
    status: lastResponse?.status ?? null,
    statusText: lastResponse?.statusText || STATUS_CODES[lastResponse?.status] || null,
    redirectsFollowed,
    chainDisplay: chain.join(" --> "),
    redirects,
    blockedRedirect: null,
    durationMs,
    headers,
    interestingHeaders,
    findings,
  };
}

function buildTooManyRedirectsCheck(spec, chain, redirects, currentUrl, location, response, startedAt, endedAt) {
  const headers = normalizeHeaderList(response.headers || []);
  const blockedRedirects = [
    ...redirects,
    buildRedirectHop(currentUrl, "X", response, location),
  ];

  return {
    cacheKey: spec.cacheKey,
    ok: false,
    protocol: spec.protocol,
    port: spec.port,
    cached: false,
    startUrl: spec.startUrl,
    finalUrl: formatDisplayUrl(currentUrl),
    finalCheckedUrl: formatDisplayUrl(currentUrl),
    status: response.status,
    statusText: response.statusText || STATUS_CODES[response.status] || null,
    redirectsFollowed: REDIRECT_LIMIT,
    chainDisplay: `${chain.join(" --> ")} --> X`,
    redirects: blockedRedirects,
    blockedRedirect: {
      from: formatDisplayUrl(currentUrl),
      status: response.status,
      location,
    },
    durationMs: Math.max(0, endedAt - startedAt),
    headers,
    interestingHeaders: explainInterestingHeaders(headers),
    findings: [{
      severity: "critical",
      code: "TOO_MANY_REDIRECTS",
      title: "Too many redirects",
      detail: "The target attempted a 3rd redirect. This tool allows only 2 redirects.",
      recommendation: "Fix the redirect chain so the final target is reached within 2 redirects.",
    }],
  };
}

function buildBlockedRedirectCheck(spec, chain, redirects, currentUrl, error, location = null, response = null) {
  const status = response?.status ?? null;
  const headers = normalizeHeaderList(response?.headers || []);
  const blockedRedirects = location && status
    ? [...redirects, buildRedirectHop(currentUrl, "X", response, location)]
    : redirects;

  return {
    cacheKey: spec.cacheKey,
    ok: false,
    protocol: spec.protocol,
    port: spec.port,
    cached: false,
    startUrl: spec.startUrl,
    finalUrl: formatDisplayUrl(currentUrl),
    finalCheckedUrl: formatDisplayUrl(currentUrl),
    status,
    statusText: status ? response?.statusText || STATUS_CODES[status] || null : null,
    redirectsFollowed: Math.max(0, chain.length - 1),
    chainDisplay: `${chain.join(" --> ")} --> X`,
    redirects: blockedRedirects,
    blockedRedirect: {
      from: formatDisplayUrl(currentUrl),
      status,
      location,
    },
    durationMs: 0,
    headers,
    interestingHeaders: explainInterestingHeaders(headers),
    findings: [{
      severity: "critical",
      code: "BLOCKED_REDIRECT",
      title: "Redirect target blocked",
      detail: error?.safeMessage || "Redirect target is blocked because it points to a private/internal/unsupported address.",
      recommendation: "Use redirects that stay on public HTTP or HTTPS website hostnames.",
    }],
  };
}

function buildRedirectHop(fromUrl, to, response, location = null) {
  return {
    from: formatDisplayUrl(fromUrl),
    to,
    status: response.status,
    statusText: response.statusText || STATUS_CODES[response.status] || null,
    location,
  };
}

async function resolvePublicAddresses(host) {
  const addresses = await resolveAddresses(host);

  return normalizeResolvedPublicAddresses(addresses, "BLOCKED_TARGET");
}

function normalizeResolvedPublicAddresses(addresses, errorCode) {
  const publicAddresses = [...new Set((Array.isArray(addresses) ? addresses : [])
    .map((address) => String(address || "").trim())
    .filter(Boolean))];

  if (publicAddresses.length === 0) {
    throw new HttpHeaderCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
  }

  if (publicAddresses.some((address) => isBlockedIp(address))) {
    throw new HttpHeaderCheckError(errorCode, errorCode === "BLOCKED_REDIRECT"
      ? "Redirect target is blocked because it points to a private/internal/unsupported address."
      : "Target resolved to a blocked/private/internal address.");
  }

  return publicAddresses;
}

async function resolveAddresses(host) {
  const lookups = await Promise.all([
    resolveDnsFamily(dns.resolve4(host)),
    resolveDnsFamily(dns.resolve6(host)),
  ]);
  const addresses = [...new Set(lookups.flat())];

  if (addresses.length > 0) {
    return addresses;
  }

  try {
    const lookupAddresses = await dns.lookup(host, { all: true });
    addresses.push(...lookupAddresses.map((record) => record.address));
  } catch {
    throw new HttpHeaderCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
  }

  if (addresses.length === 0) {
    throw new HttpHeaderCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
  }

  return [...new Set(addresses)];
}

function resolveDnsFamily(lookup) {
  return Promise.race([
    lookup.catch(() => []),
    new Promise((resolve) => {
      setTimeout(() => resolve([]), DNS_FAMILY_TIMEOUT_MS);
    }),
  ]);
}

export async function requestHeaders(url, { timeoutMs, addresses = null, logger = null } = {}) {
  const publicAddresses = addresses
    ? normalizeResolvedPublicAddresses(addresses, "BLOCKED_TARGET")
    : await resolvePublicAddresses(url.hostname);
  const errors = [];

  for (const address of publicAddresses) {
    try {
      return await requestHeadersAddress(url, address, timeoutMs);
    } catch (error) {
      errors.push(error);
      logHttpHeaderRequestFailure(logger, {
        url,
        address,
        error,
      });
    }
  }

  throw classifyRequestError(errors[errors.length - 1]);
}

function classifyRequestError(error) {
  if (error instanceof HttpHeaderCheckError) {
    return error;
  }

  const code = classifyRequestErrorCode(error);
  const message = REQUEST_ERROR_MESSAGES[code] || REQUEST_ERROR_MESSAGES.HTTP_CHECK_FAILED;

  return new HttpHeaderCheckError(code, message, { cause: error });
}

function classifyRequestErrorCode(error) {
  const code = String(error?.code || "");

  if (code === "REQUEST_TIMEOUT" || code === "ETIMEDOUT") {
    return "REQUEST_TIMEOUT";
  }

  if (code === "ECONNREFUSED") {
    return "CONNECTION_REFUSED";
  }

  if (code === "ECONNRESET") {
    return "CONNECTION_RESET";
  }

  if (isTlsRequestError(error)) {
    return "TLS_CONNECTION_FAILED";
  }

  return "HTTP_CHECK_FAILED";
}

function isTlsRequestError(error) {
  const code = String(error?.code || "");
  const message = String(error?.message || "").toLowerCase();

  return code.startsWith("ERR_TLS_") ||
    code.startsWith("ERR_SSL_") ||
    TLS_REQUEST_ERROR_CODES.has(code) ||
    /\b(tls|ssl|certificate|cert)\b/.test(message);
}

function logHttpHeaderRequestFailure(logger, { url, address, error }) {
  if (!logger || typeof logger.warn !== "function") {
    return;
  }

  logger.warn({
    tool: "http-header-check",
    hostname: safeLogValue(url.hostname),
    url: safeLogValue(formatDisplayUrl(url)),
    address: safeLogValue(address),
    errorCode: safeLogValue(error?.code || error?.name || "UNKNOWN"),
    errorMessage: safeLogValue(error?.message || "Request failed."),
  }, "HTTP Header Checker request failed.");
}

function safeLogValue(value) {
  return String(value ?? "")
    .replace(/[\r\n\t]+/g, " ")
    .slice(0, 500);
}

export function requestHeadersAddress(url, address, timeoutMs) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const transport = isHttps ? https : http;
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    const requestOptions = {
      host: address,
      port,
      path: `${url.pathname || "/"}${url.search || ""}`,
      method: "GET",
      timeout: timeoutMs,
      headers: {
        Host: formatHostHeader(url.hostname, port, url.protocol),
        "User-Agent": "BAZMEG.TECH IT Toolbox HTTP Header Checker",
        Accept: "*/*",
        Connection: "close",
      },
    };

    if (isHttps) {
      requestOptions.servername = url.hostname;
      requestOptions.ca = getTrustedTlsCaCertificates();
      requestOptions.checkServerIdentity = (_hostname, cert) => tls.checkServerIdentity(url.hostname, cert);
    }

    const request = transport.request(requestOptions, (response) => {
      const headers = rawHeadersToList(response.rawHeaders);

      response.destroy();
      resolve({
        status: response.statusCode || 0,
        statusText: response.statusMessage || STATUS_CODES[response.statusCode] || null,
        headers,
      });
    });

    request.once("timeout", () => {
      const timeoutError = new Error("HTTP header request timed out.");
      timeoutError.code = "REQUEST_TIMEOUT";
      request.destroy(timeoutError);
    });
    request.once("error", reject);
    request.end();
  });
}

function formatHostHeader(host, port, protocol) {
  const standardPort = protocol === "https:" ? 443 : 80;

  return port === standardPort ? host : `${host}:${port}`;
}

function getTrustedTlsCaCertificates() {
  if (!trustedTlsCaCertificates) {
    const defaultCertificates = typeof tls.getCACertificates === "function"
      ? tls.getCACertificates("default")
      : tls.rootCertificates;

    trustedTlsCaCertificates = [...new Set([
      ...defaultCertificates,
      ...ADDITIONAL_TLS_CA_CERTIFICATES,
    ])];
  }

  return trustedTlsCaCertificates;
}

function rawHeadersToList(rawHeaders) {
  const headers = [];

  for (let index = 0; index < rawHeaders.length; index += 2) {
    headers.push({
      name: String(rawHeaders[index] || "").toLowerCase(),
      value: String(rawHeaders[index + 1] || ""),
    });
  }

  return headers;
}

function normalizeHeaderList(headers) {
  if (Array.isArray(headers)) {
    return headers.map((header) => ({
      name: String(header.name || "").toLowerCase(),
      value: String(header.value ?? ""),
    })).filter((header) => header.name);
  }

  return Object.entries(headers || {}).flatMap(([name, value]) => {
    const values = Array.isArray(value) ? value : [value];

    return values.map((entry) => ({
      name: name.toLowerCase(),
      value: String(entry ?? ""),
    }));
  });
}

function getHeaderValue(headers, name) {
  const header = normalizeHeaderList(headers).find((entry) => entry.name.toLowerCase() === name.toLowerCase());

  return header?.value || "";
}

function getHeaderValues(headers, name) {
  return normalizeHeaderList(headers)
    .filter((entry) => entry.name.toLowerCase() === name.toLowerCase())
    .map((entry) => entry.value);
}

function explainInterestingHeaders(headers) {
  const byName = new Map();

  for (const header of headers) {
    if (!byName.has(header.name)) {
      byName.set(header.name, []);
    }

    byName.get(header.name).push(header.value);
  }

  return HEADER_DEFINITIONS
    .filter((definition) => byName.has(definition.name))
    .map((definition) => ({
      ...definition,
      values: byName.get(definition.name),
    }));
}

function analyzeHeaders(headers, finalUrl) {
  const findings = [];
  const values = (name) => getHeaderValues(headers, name);
  const first = (name) => values(name)[0] || "";
  const isHttps = finalUrl.protocol === "https:";
  const hsts = first("strict-transport-security");
  const cspValues = values("content-security-policy");
  const csp = cspValues[0] || "";
  const xContentTypeOptions = first("x-content-type-options");
  const xFrameOptions = first("x-frame-options");
  const referrerPolicy = first("referrer-policy");
  const server = first("server");
  const poweredBy = first("x-powered-by");
  const xXssProtection = first("x-xss-protection");
  const cacheControl = first("cache-control");

  findings.push(...analyzeDuplicateSecurityHeaders(headers));

  if (cspValues.length > 1) {
    findings.push(finding("warning", "DUPLICATE_CSP_HEADER", "Multiple Content-Security-Policy headers", "Multiple CSP headers were returned. Browsers may enforce all policies, but this is harder to audit and can cause unexpected behavior.", "Consolidate CSP configuration where possible and verify the effective policy."));
  }

  const cspPrivateIpReferences = getCspPrivateIpReferences(cspValues);
  const cspPrivateIps = [...new Set(cspPrivateIpReferences.flatMap((reference) => reference.privateIps))];

  if (cspPrivateIps.length > 0) {
    findings.push(finding(
      "warning",
      "CSP_EXPOSES_PRIVATE_IP",
      "CSP exposes private IP address",
      "The Content-Security-Policy references private/internal IP addresses.",
      "Avoid exposing internal infrastructure details in public response headers.",
      {
        privateIps: cspPrivateIps,
        references: cspPrivateIpReferences,
      },
    ));
  }

  if (isHttps && !hsts) {
    findings.push(finding("warning", "MISSING_HSTS", "Missing HSTS", "The HTTPS response did not include Strict-Transport-Security.", "Add HSTS after confirming the site is ready to require HTTPS."));
  } else if (isHttps && hsts) {
    const maxAge = Number(hsts.match(/max-age=(\d+)/i)?.[1] || 0);

    if (maxAge > 0 && maxAge < 15552000) {
      findings.push(finding("warning", "HSTS_MAX_AGE_LOW", "HSTS max-age is low", "Strict-Transport-Security is present, but max-age is lower than six months.", "Use a longer max-age once HTTPS is stable."));
    }

    if (!/includesubdomains/i.test(hsts)) {
      findings.push(finding("warning", "HSTS_MISSING_INCLUDE_SUBDOMAINS", "HSTS does not include subdomains", "HSTS is present without includeSubDomains.", "Consider includeSubDomains if all subdomains support HTTPS."));
    }
  }

  if (!csp) {
    findings.push(finding("warning", "MISSING_CSP", "Missing Content Security Policy", "No Content-Security-Policy header was detected.", "Add a CSP that matches the application instead of copying a generic policy."));
  } else if (cspValues.some((value) => /unsafe-inline/i.test(value))) {
    findings.push(finding("warning", "CSP_UNSAFE_INLINE", "CSP allows unsafe-inline", "The Content-Security-Policy contains unsafe-inline.", "Prefer nonces, hashes, or external scripts/styles where practical."));
  }

  if (!xContentTypeOptions) {
    findings.push(finding("warning", "MISSING_X_CONTENT_TYPE_OPTIONS", "Missing X-Content-Type-Options", "No X-Content-Type-Options header was detected.", "Set X-Content-Type-Options to nosniff."));
  } else if (xContentTypeOptions.toLowerCase() !== "nosniff") {
    findings.push(finding("warning", "X_CONTENT_TYPE_OPTIONS_NOT_NOSNIFF", "X-Content-Type-Options is not nosniff", "X-Content-Type-Options is present but not set to nosniff.", "Set X-Content-Type-Options to nosniff."));
  }

  if (!xFrameOptions && !cspValues.some((value) => /frame-ancestors/i.test(value))) {
    findings.push(finding("warning", "MISSING_FRAME_PROTECTION", "Missing frame protection", "No X-Frame-Options header or CSP frame-ancestors directive was detected.", "Add CSP frame-ancestors or X-Frame-Options where framing is not required."));
  }

  if (!referrerPolicy) {
    findings.push(finding("warning", "MISSING_REFERRER_POLICY", "Missing Referrer-Policy", "No Referrer-Policy header was detected.", "Set a Referrer-Policy appropriate for the site."));
  }

  if (poweredBy) {
    findings.push(finding("warning", "X_POWERED_BY_EXPOSED", "X-Powered-By exposed", "The response exposes an X-Powered-By header.", "Remove framework version or stack disclosure headers where possible."));
  }

  if (server) {
    findings.push(finding("info", "SERVER_EXPOSED", "Server header exposed", "The response includes a Server header. This is common, but it can reveal stack details.", "Consider reducing version detail if your server exposes it."));
  }

  if (xXssProtection) {
    findings.push(finding("info", "LEGACY_X_XSS_PROTECTION", "Legacy X-XSS-Protection present", "X-XSS-Protection is a legacy browser header and is not a strong modern security control.", "Use CSP and modern browser protections as the primary defense."));
  }

  if (!cacheControl) {
    findings.push(finding("info", "CACHE_CONTROL_MISSING", "Cache-Control missing", "No Cache-Control header was detected. This may be fine for some responses.", "Set explicit caching rules for sensitive or frequently changed content."));
  }

  findings.push(...analyzeCookies(values("set-cookie"), finalUrl.hostname));
  findings.push(...analyzeCors(headers));

  return findings;
}

function analyzeDuplicateSecurityHeaders(headers) {
  return IMPORTANT_SECURITY_HEADERS.flatMap((name) => {
    const headerValues = getHeaderValues(headers, name);

    if (headerValues.length < 2) {
      return [];
    }

    const seenValues = new Set();
    const hasIdenticalValue = headerValues.some((value) => {
      const normalizedValue = value.trim();

      if (seenValues.has(normalizedValue)) {
        return true;
      }

      seenValues.add(normalizedValue);
      return false;
    });

    if (!hasIdenticalValue) {
      return [];
    }

    return [finding("info", "DUPLICATE_SECURITY_HEADER", "Duplicate security header", "The response returns the same security header more than once.", `Remove repeated ${name} values unless multiple layers intentionally emit the same header.`)];
  });
}

function getCspPrivateIpReferences(values) {
  return values.map((value) => {
    const privateIps = [...new Set(extractCspIpLiterals(value).filter((address) => isBlockedIp(address)))];

    return {
      header: "content-security-policy",
      value,
      privateIps,
    };
  }).filter((reference) => reference.privateIps.length > 0);
}

function extractCspIpLiterals(value) {
  const text = String(value || "");
  const candidates = new Set();

  for (const match of text.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g)) {
    candidates.add(match[0]);
  }

  for (const match of text.matchAll(/\[([0-9a-fA-F:.]+)\]/g)) {
    candidates.add(match[1]);
  }

  for (const token of text.split(/[\s;]+/)) {
    const host = cspTokenToHostCandidate(token);

    if (host) {
      candidates.add(host);
    }
  }

  return [...candidates].filter((candidate) => net.isIP(candidate) !== 0);
}

function cspTokenToHostCandidate(token) {
  const normalizedToken = String(token || "")
    .trim()
    .replace(/^['"]+|['",]+$/g, "")
    .replace(/^[a-z][a-z\d+\-.]*:\/\//i, "");

  if (!normalizedToken) {
    return "";
  }

  if (normalizedToken.startsWith("[")) {
    return normalizedToken.match(/^\[([^\]]+)\]/)?.[1] || "";
  }

  return normalizedToken.split(/[/?#]/)[0];
}

function analyzeCookies(cookieHeaders, host) {
  return cookieHeaders.flatMap((value, index) => {
    const cookie = parseSetCookie(value);
    const label = cookie.name || `Cookie ${index + 1}`;
    const findings = [];

    if (!cookie.attributes.secure) {
      findings.push(finding("warning", "COOKIE_MISSING_SECURE", "Cookie missing Secure", `${label} does not include the Secure attribute.`, "Add Secure to cookies that should only be sent over HTTPS."));
    }

    if (!cookie.attributes.httponly) {
      findings.push(finding("warning", "COOKIE_MISSING_HTTPONLY", "Cookie missing HttpOnly", `${label} does not include the HttpOnly attribute.`, "Add HttpOnly to cookies that do not need JavaScript access."));
    }

    if (!cookie.attributes.samesite) {
      findings.push(finding("warning", "COOKIE_MISSING_SAMESITE", "Cookie missing SameSite", `${label} does not include the SameSite attribute.`, "Set SameSite=Lax or Strict unless cross-site use is required."));
    }

    if (String(cookie.attributes.samesite || "").toLowerCase() === "none" && !cookie.attributes.secure) {
      findings.push(finding("warning", "COOKIE_SAMESITE_NONE_WITHOUT_SECURE", "SameSite=None without Secure", `${label} uses SameSite=None without Secure.`, "Use Secure with SameSite=None cookies."));
    }

    if (cookie.attributes.domain && isBroadCookieDomain(cookie.attributes.domain, host)) {
      findings.push(finding("warning", "COOKIE_BROAD_DOMAIN", "Cookie domain is broad", `${label} uses a broad Domain attribute.`, "Scope cookies to the narrowest domain that works."));
    }

    return findings;
  });
}

function parseSetCookie(value) {
  const parts = String(value || "").split(";").map((part) => part.trim()).filter(Boolean);
  const [nameValue, ...attributes] = parts;
  const [name, ...cookieValue] = (nameValue || "").split("=");
  const parsed = {
    name: name || "",
    value: cookieValue.join("="),
    attributes: {},
  };

  for (const attribute of attributes) {
    const [rawName, ...rawValue] = attribute.split("=");
    const key = rawName.trim().toLowerCase();
    parsed.attributes[key] = rawValue.length ? rawValue.join("=").trim() : true;
  }

  return parsed;
}

function isBroadCookieDomain(domain, host) {
  const normalizedDomain = String(domain).trim().replace(/^\./, "").toLowerCase();
  const normalizedHost = String(host).toLowerCase();

  return normalizedDomain !== normalizedHost || normalizedDomain.split(".").length <= 2;
}

function analyzeCors(headers) {
  const allowOrigin = getHeaderValue(headers, "access-control-allow-origin");
  const allowCredentials = getHeaderValue(headers, "access-control-allow-credentials");

  if (allowOrigin.trim() === "*" && allowCredentials.trim().toLowerCase() === "true") {
    return [finding("critical", "CORS_WILDCARD_WITH_CREDENTIALS", "Dangerous CORS credentials policy", "Access-Control-Allow-Origin is * while Access-Control-Allow-Credentials is true.", "Do not combine wildcard origins with credentialed CORS responses.")];
  }

  return [];
}

function finding(severity, code, title, detail, recommendation, metadata = null) {
  const baseFinding = {
    severity,
    code,
    title,
    detail,
    recommendation,
  };

  if (!metadata) {
    return baseFinding;
  }

  return {
    ...baseFinding,
    metadata,
  };
}

function withCheckCacheMetadata(response, { cached, storedAt, now }) {
  const ageSeconds = Math.max(0, Math.floor((now - storedAt) / 1000));

  return {
    ...clone(response),
    cacheKey: response.cacheKey,
    cached,
    durationMs: cached ? 0 : response.durationMs,
    cacheTtlSeconds: CACHE_TTL_SECONDS,
    cacheAgeSeconds: Math.min(ageSeconds, CACHE_TTL_SECONDS),
    cacheExpiresInSeconds: Math.max(0, CACHE_TTL_SECONDS - ageSeconds),
  };
}

function enforceRateLimit(clientIp, targetHost, cost, now) {
  pruneBucket(globalRateBucket, now, RATE_WINDOW_HOUR_MS);
  const globalFiveMinuteTotal = globalRateBucket
    .filter((entry) => now - entry.time < RATE_WINDOW_FIVE_MINUTES_MS)
    .reduce((total, entry) => total + entry.cost, 0);

  if (globalFiveMinuteTotal + cost > GLOBAL_RATE_LIMIT_FIVE_MINUTES) {
    throw rateLimitedError();
  }

  enforceBucket(rateBuckets, clientIp, cost, now, RATE_LIMIT_FIVE_MINUTES, RATE_LIMIT_HOUR);
  enforceBucket(targetRateBuckets, targetHost, cost, now, TARGET_RATE_LIMIT_FIVE_MINUTES, RATE_LIMIT_HOUR);
  globalRateBucket.push({ time: now, cost });
}

function enforceBucket(buckets, key, cost, now, fiveMinuteLimit, hourLimit) {
  const bucket = buckets.get(key) || [];
  const fresh = bucket.filter((entry) => now - entry.time < RATE_WINDOW_HOUR_MS);
  const hourTotal = fresh.reduce((total, entry) => total + entry.cost, 0);
  const fiveMinuteTotal = fresh
    .filter((entry) => now - entry.time < RATE_WINDOW_FIVE_MINUTES_MS)
    .reduce((total, entry) => total + entry.cost, 0);

  if (fiveMinuteTotal + cost > fiveMinuteLimit || hourTotal + cost > hourLimit) {
    buckets.set(key, fresh);
    throw rateLimitedError();
  }

  fresh.push({ time: now, cost });
  buckets.set(key, fresh);
}

function pruneBucket(bucket, now, maxAgeMs) {
  for (let index = bucket.length - 1; index >= 0; index -= 1) {
    if (now - bucket[index].time >= maxAgeMs) {
      bucket.splice(index, 1);
    }
  }
}

function acquireActiveCheck(cost) {
  if (cost === 0) {
    return () => {};
  }

  if (activeChecks + cost > ACTIVE_CHECK_LIMIT) {
    throw rateLimitedError();
  }

  activeChecks += cost;

  return () => {
    activeChecks = Math.max(0, activeChecks - cost);
  };
}

function rateLimitedError() {
  return new HttpHeaderCheckError("RATE_LIMITED", "Too many HTTP header checks were requested recently. Try again later, or wait for the cached result to expire.");
}

function formatUrl(scheme, host, port) {
  const standardPort = scheme === "https" ? 443 : 80;

  return `${scheme}://${host}${port === standardPort ? "" : `:${port}`}`;
}

function formatDisplayUrl(url) {
  const protocol = url.protocol.replace(":", "");
  const standardPort = protocol === "https" ? "443" : "80";
  const port = url.port && url.port !== standardPort ? `:${url.port}` : "";
  const path = `${url.pathname || ""}${url.search || ""}`;

  return `${protocol}://${url.hostname}${port}${path === "/" ? "" : path}`;
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
    ["::ffff:0:0", 96],
    ["64:ff9b::", 96],
    ["100::", 64],
    ["2001::", 23],
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const HEADER_DEFINITIONS = Object.freeze([
  headerDefinition("server", "Identity / stack", "Server software reported by the origin or proxy."),
  headerDefinition("x-powered-by", "Identity / stack", "Application framework or platform hint. Often removed to reduce stack disclosure."),
  headerDefinition("x-served-by", "Identity / stack", "Proxy, cache, or platform node that served the response."),
  headerDefinition("via", "Identity / stack", "Intermediate proxy information."),
  headerDefinition("x-cache", "Identity / stack", "Cache result from a proxy or CDN."),
  headerDefinition("cf-cache-status", "Identity / stack", "Cloudflare cache status."),
  headerDefinition("content-type", "Content metadata", "Media type and character set for the response."),
  headerDefinition("content-length", "Content metadata", "Declared response body length."),
  headerDefinition("content-encoding", "Content metadata", "Compression or content coding applied to the response."),
  headerDefinition("transfer-encoding", "Content metadata", "Transfer framing used by the server."),
  headerDefinition("vary", "Content metadata", "Request headers that affect cache variants."),
  headerDefinition("etag", "Content metadata", "Entity tag used for cache validation."),
  headerDefinition("last-modified", "Content metadata", "Last modification timestamp reported by the server."),
  headerDefinition("accept-ranges", "Content metadata", "Whether the server supports range requests."),
  headerDefinition("strict-transport-security", "Security headers", "Asks browsers to use HTTPS for future requests."),
  headerDefinition("content-security-policy", "Security headers", "Controls which resources the browser may load or execute."),
  headerDefinition("x-content-type-options", "Security headers", "nosniff prevents some MIME sniffing behavior."),
  headerDefinition("x-frame-options", "Security headers", "Legacy clickjacking protection for framing."),
  headerDefinition("referrer-policy", "Security headers", "Controls how much referrer information browsers send."),
  headerDefinition("permissions-policy", "Security headers", "Controls access to browser features."),
  headerDefinition("cross-origin-opener-policy", "Security headers", "Isolates browsing contexts across origins."),
  headerDefinition("cross-origin-resource-policy", "Security headers", "Controls cross-origin resource embedding."),
  headerDefinition("cross-origin-embedder-policy", "Security headers", "Requires embeddable resources to opt in for cross-origin isolation."),
  headerDefinition("x-xss-protection", "Legacy", "Legacy/deprecated XSS filter header. CSP is the modern control."),
  headerDefinition("cache-control", "Cache", "Primary HTTP caching directive."),
  headerDefinition("pragma", "Cache", "Legacy cache directive."),
  headerDefinition("expires", "Cache", "Legacy expiration timestamp."),
  headerDefinition("age", "Cache", "Seconds a cached response has been stored by a proxy."),
  headerDefinition("set-cookie", "Cookies", "Cookie assignment from the server."),
  headerDefinition("access-control-allow-origin", "CORS", "Origins allowed to read this response through browsers."),
  headerDefinition("access-control-allow-credentials", "CORS", "Whether browsers may expose credentialed responses."),
  headerDefinition("access-control-allow-methods", "CORS", "Methods allowed for cross-origin requests."),
  headerDefinition("access-control-allow-headers", "CORS", "Request headers allowed for cross-origin requests."),
  headerDefinition("x-request-id", "Diagnostics", "Request identifier useful for logs and support."),
  headerDefinition("x-correlation-id", "Diagnostics", "Correlation identifier useful across services."),
  headerDefinition("x-amzn-trace-id", "Diagnostics", "AWS trace identifier."),
  headerDefinition("traceparent", "Diagnostics", "W3C trace context identifier."),
  headerDefinition("server-timing", "Diagnostics", "Server timing metrics exposed to the browser."),
]);

function headerDefinition(name, category, explanation) {
  return {
    name,
    category,
    explanation,
  };
}
