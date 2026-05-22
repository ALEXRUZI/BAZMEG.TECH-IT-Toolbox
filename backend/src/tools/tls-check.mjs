import dns from "node:dns/promises";
import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import net from "node:net";
import tls from "node:tls";

const CONNECT_TIMEOUT_MS = 7000;
const DNS_FAMILY_TIMEOUT_MS = 3000;
const SUPPORTED_TLS_PORTS = new Set([
  443,
  4443,
  7443,
  8443,
  9443,
  10443,
]);
const CERTIFICATE_POLICIES_EXTENSION_OID = "2.5.29.32";
const CAB_FORUM_POLICY_TYPES = Object.freeze([
  ["2.23.140.1.1", "EV", "Certificate Policies contains CA/B Forum EV policy OID 2.23.140.1.1."],
  ["2.23.140.1.2.2", "OV", "Certificate Policies contains CA/B Forum OV policy OID 2.23.140.1.2.2."],
  ["2.23.140.1.2.1", "DV", "Certificate Policies contains CA/B Forum DV policy OID 2.23.140.1.2.1."],
  ["2.23.140.1.2.3", "IV", "Certificate Policies contains CA/B Forum Individual Validated policy OID 2.23.140.1.2.3."],
]);

export class TlsCheckError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TlsCheckError";
    this.code = code;
    this.safeMessage = message;
  }
}

export async function checkTlsCertificate({ host, port }) {
  const normalizedHost = normalizeHost(host);
  const normalizedPort = normalizePort(port);
  const resolvedAddresses = await resolvePublicAddresses(normalizedHost);
  const tlsResult = await connectTls(normalizedHost, normalizedPort, resolvedAddresses);
  const certificate = formatCertificate(tlsResult.peerCertificate, "server");
  const certificateValidationType = inferCertificateValidationType(tlsResult.peerCertificate);
  const chain = buildCertificateChain(tlsResult.peerCertificate);
  const issuerChainMetadata = buildIssuerChainMetadata(chain);
  const hostnameVerificationError = tls.checkServerIdentity(normalizedHost, tlsResult.peerCertificate);
  const hostnameMatches = !hostnameVerificationError;
  const hostnameError = hostnameMatches ? null : "The certificate does not match the requested hostname.";
  const warnings = getCertificateWarnings(chain);
  const summary = {
    resolves: true,
    trusted: tlsResult.authorized,
    hostnameMatches,
    notExpired: certificate.daysRemaining !== null && certificate.daysRemaining >= 0,
    chainProvided: chain.length > 1,
  };
  const checks = buildChecks({
    host: normalizedHost,
    resolvedAddresses,
    tlsResult,
    certificate,
    chain,
    hostnameMatches,
    hostnameError,
    warnings,
    serverProvidedCertificateCount: issuerChainMetadata.serverProvidedCertificateCount,
    issuerChainEntriesShown: issuerChainMetadata.issuerChain.length,
  });

  return {
    ok: true,
    host: normalizedHost,
    port: normalizedPort,
    resolvedAddresses,
    tls: {
      authorized: tlsResult.authorized,
      authorizationError: tlsResult.authorizationError,
      protocol: tlsResult.protocol,
      cipher: tlsResult.cipher,
    },
    certificate,
    certificateType: certificateValidationType.type,
    certificateTypeConfidence: certificateValidationType.confidence,
    certificateTypeReason: certificateValidationType.reason,
    certificatePolicyOids: certificateValidationType.policyOids,
    warnings,
    summary,
    checks,
    chain,
    ...issuerChainMetadata,
  };
}

function normalizeHost(host) {
  if (typeof host !== "string") {
    throw new TlsCheckError("INVALID_HOST", "Enter a valid public hostname.");
  }

  const normalizedHost = host.trim().toLowerCase();

  if (
    !normalizedHost ||
    normalizedHost.length > 253 ||
    normalizedHost === "localhost" ||
    normalizedHost.endsWith(".localhost") ||
    net.isIP(normalizedHost) !== 0 ||
    /[:/?#@[\]\\]/.test(normalizedHost) ||
    normalizedHost.endsWith(".")
  ) {
    throw new TlsCheckError("INVALID_HOST", "Enter a valid public hostname.");
  }

  const labels = normalizedHost.split(".");
  const hasValidLabels = labels.length >= 2 && labels.every((label) => {
    return (
      label.length >= 1 &&
      label.length <= 63 &&
      /^[a-z0-9-]+$/.test(label) &&
      !label.startsWith("-") &&
      !label.endsWith("-")
    );
  });

  if (!hasValidLabels) {
    throw new TlsCheckError("INVALID_HOST", "Enter a valid public hostname.");
  }

  return normalizedHost;
}

function normalizePort(port) {
  if (!Number.isInteger(port) || !SUPPORTED_TLS_PORTS.has(port)) {
    throw new TlsCheckError("INVALID_PORT", "Enter a supported TLS port.");
  }

  return port;
}

async function resolvePublicAddresses(host) {
  const addresses = await resolveAddresses(host);
  const publicAddresses = addresses.filter((address) => !isBlockedIp(address));

  if (publicAddresses.length === 0) {
    throw new TlsCheckError("BLOCKED_TARGET", "The hostname resolves only to blocked addresses.");
  }

  return publicAddresses;
}

async function resolveAddresses(host) {
  const lookups = await Promise.all([
    resolveDnsFamily(dns.resolve4(host)),
    resolveDnsFamily(dns.resolve6(host)),
  ]);

  const addresses = lookups.flat();

  if (addresses.length === 0) {
    try {
      const lookupAddresses = await dns.lookup(host, { all: true });
      addresses.push(...lookupAddresses.map((record) => record.address));
    } catch {
      throw new TlsCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
    }
  }

  if (addresses.length === 0) {
    throw new TlsCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
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

async function connectTls(servername, port, addresses) {
  const activeSockets = new Set();
  const timeout = setTimeout(() => {
    for (const socket of activeSockets) {
      socket.destroy(new Error("TLS connection timed out."));
    }
  }, CONNECT_TIMEOUT_MS);

  try {
    return await Promise.any(addresses.map((address) => {
      return connectTlsAddress(servername, port, address, activeSockets);
    }));
  } catch {
    throw new TlsCheckError("TLS_CONNECTION_FAILED", "TLS connection failed.");
  } finally {
    clearTimeout(timeout);

    for (const socket of activeSockets) {
      socket.destroy();
    }
  }
}

function connectTlsAddress(servername, port, address, activeSockets) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timeoutId;
    const fail = () => {
      if (!settled) {
        settled = true;
        clearTimeout(timeoutId);
        reject(new TlsCheckError("TLS_CONNECTION_FAILED", "TLS connection failed."));
      }
    };
    const socket = tls.connect({
      host: address,
      port,
      servername,
      rejectUnauthorized: false,
      timeout: CONNECT_TIMEOUT_MS,
    });

    timeoutId = setTimeout(() => {
      socket.destroy();
      fail();
    }, CONNECT_TIMEOUT_MS);

    activeSockets.add(socket);
    socket.once("close", () => {
      activeSockets.delete(socket);
      fail();
    });

    socket.once("secureConnect", () => {
      const cipher = socket.getCipher();
      const peerCertificate = socket.getPeerCertificate(true);

      settled = true;
      clearTimeout(timeoutId);
      socket.end();

      resolve({
        authorized: socket.authorized,
        authorizationError: socket.authorizationError || null,
        protocol: socket.getProtocol(),
        cipher: cipher?.standardName || cipher?.name || null,
        peerCertificate,
      });
    });

    socket.once("timeout", () => {
      socket.destroy(new Error("TLS connection timed out."));
      fail();
    });

    socket.once("error", () => {
      fail();
    });
  });
}

function buildCertificateChain(peerCertificate) {
  const chain = [];
  const seenFingerprints = new Set();
  let currentCertificate = peerCertificate;

  for (let depth = 0; currentCertificate && depth < 10; depth += 1) {
    const fingerprint = currentCertificate.fingerprint256 || currentCertificate.fingerprint || `depth:${depth}`;

    if (seenFingerprints.has(fingerprint)) {
      break;
    }

    seenFingerprints.add(fingerprint);
    chain.push(formatCertificate(currentCertificate, getCertificateType(currentCertificate, depth)));

    const issuerCertificate = currentCertificate.issuerCertificate;

    if (
      !issuerCertificate ||
      issuerCertificate === currentCertificate ||
      issuerCertificate.fingerprint256 === currentCertificate.fingerprint256
    ) {
      break;
    }

    currentCertificate = issuerCertificate;
  }

  return chain;
}

export function buildIssuerChain(chain) {
  if (!Array.isArray(chain)) {
    return [];
  }

  return chain.map((certificate, index) => ({
    level: getIssuerChainLevel(certificate, index),
    source: "peer-chain",
    subject: formatDistinguishedName(certificate.subject),
    issuer: formatDistinguishedName(certificate.issuer),
    validFrom: certificate.validFrom || null,
    validTo: certificate.validTo || null,
    fingerprint256: certificate.fingerprint256 || null,
  }));
}

export function buildIssuerChainMetadata(chain) {
  const issuerChain = buildIssuerChain(chain);
  const issuerChainComplete = issuerChain.some((entry) => entry.level === "root");

  return {
    serverProvidedCertificateCount: Array.isArray(chain) ? chain.length : 0,
    issuerChain,
    issuerChainComplete,
    issuerChainNote: issuerChainComplete
      ? "Issuer chain includes a self-signed/root certificate from the peer certificate chain."
      : "Full issuer chain was not available from the server response. Root certificates are commonly omitted from TLS handshakes.",
  };
}

function getIssuerChainLevel(certificate, index) {
  if (isSelfIssuedCertificate(certificate)) {
    return "root";
  }

  if (index === 0 || certificate?.type === "server") {
    return "leaf";
  }

  return "intermediate";
}

function isSelfIssuedCertificate(certificate) {
  return Boolean(
    certificate?.subject &&
    certificate?.issuer &&
    JSON.stringify(certificate.subject) === JSON.stringify(certificate.issuer)
  );
}

function formatDistinguishedName(value) {
  if (!value || typeof value !== "object") {
    return "Unavailable";
  }

  const entries = Object.entries(value)
    .flatMap(([key, entryValue]) => {
      const values = Array.isArray(entryValue) ? entryValue : [entryValue];

      return values
        .filter((item) => typeof item === "string" && item.trim().length > 0)
        .map((item) => `${key}: ${item.trim()}`);
    });

  return entries.length > 0 ? entries.join(", ") : "Unavailable";
}

function getCertificateType(certificate, depth) {
  if (depth === 0) {
    return "server";
  }

  if (
    certificate.ca === true &&
    certificate.subject &&
    certificate.issuer &&
    JSON.stringify(certificate.subject) === JSON.stringify(certificate.issuer)
  ) {
    return "root";
  }

  return "intermediate";
}

function formatCertificate(certificate, type = "chain") {
  if (!certificate || Object.keys(certificate).length === 0) {
    throw new TlsCheckError("CERTIFICATE_UNAVAILABLE", "Certificate information was unavailable.");
  }

  return {
    type,
    subject: certificate.subject || {},
    issuer: certificate.issuer || {},
    validFrom: certificate.valid_from || null,
    validTo: certificate.valid_to || null,
    daysRemaining: getDaysRemaining(certificate.valid_to),
    serialNumber: certificate.serialNumber || null,
    fingerprint256: certificate.fingerprint256 || null,
    subjectAltName: certificate.subjectaltname || null,
    signatureAlgorithm: certificate.signatureAlgorithm || certificate.sigalg || null,
    publicKeyAlgorithm: certificate.asymmetricKeyType || certificate.publicKeyAlgorithm || null,
    modulusLength: certificate.modulusLength || null,
    bits: certificate.bits || null,
  };
}

export function inferCertificateValidationType(certificate) {
  if (!certificate || Object.keys(certificate).length === 0) {
    return {
      type: "Unknown",
      confidence: "unknown",
      reason: "Certificate type could not be determined from policy OIDs or subject fields.",
      policyOids: [],
    };
  }

  const policyOids = getCertificatePolicyOids(certificate);

  for (const [oid, type, reason] of CAB_FORUM_POLICY_TYPES) {
    if (policyOids.includes(oid)) {
      return {
        type,
        confidence: "policy-oid",
        reason,
        policyOids,
      };
    }
  }

  if (hasEvLikeIssuer(certificate.issuer) && hasMeaningfulOrganization(certificate.subject) && hasEvLikeSubjectFields(certificate.subject)) {
    return {
      type: "EV",
      confidence: "heuristic",
      reason: "EV-like issuer and subject identity fields detected, but no EV policy OID was readable.",
      policyOids,
    };
  }

  if (hasMeaningfulOrganization(certificate.subject)) {
    return {
      type: "OV",
      confidence: "heuristic",
      reason: "Subject organization is present, but no OV/EV policy OID was readable.",
      policyOids,
    };
  }

  if (hasUsableCertificateDetails(certificate)) {
    return {
      type: "DV",
      confidence: "heuristic",
      reason: "No organization or OV/EV policy OID was detected.",
      policyOids,
    };
  }

  return {
    type: "Unknown",
    confidence: "unknown",
    reason: "Certificate type could not be determined from policy OIDs or subject fields.",
    policyOids,
  };
}

export function getCertificatePolicyOids(certificate) {
  const derResult = getCertificatePolicyOidDerResult(certificate);
  const policyOids = [
    ...getCertificatePolicyOidsFromLegacyObject(certificate),
    ...getCertificatePolicyOidsFromX509Certificate(certificate),
    ...derResult.oids,
  ];

  if (policyOids.length === 0 && !derResult.parsed) {
    policyOids.push(...getCertificatePolicyOidsFromOpenSsl(certificate));
  }

  return [...new Set(policyOids)];
}

function getCertificatePolicyOidsFromLegacyObject(certificate) {
  if (!Array.isArray(certificate?.certificatePolicies)) {
    return [];
  }

  return certificate.certificatePolicies
    .flatMap((policy) => extractOidStrings(policy))
    .filter((oid) => oid !== CERTIFICATE_POLICIES_EXTENSION_OID);
}

function getCertificatePolicyOidsFromX509Certificate(certificate) {
  try {
    const x509Certificate = createX509Certificate(certificate);

    if (!x509Certificate) {
      return [];
    }

    const legacyObject = typeof x509Certificate.toLegacyObject === "function"
      ? x509Certificate.toLegacyObject()
      : null;

    return getCertificatePolicyOidsFromLegacyObject(legacyObject);
  } catch {
    return [];
  }
}

function getCertificatePolicyOidsFromDer(certificate) {
  return getCertificatePolicyOidDerResult(certificate).oids;
}

function getCertificatePolicyOidDerResult(certificate) {
  if (!certificate?.raw) {
    return {
      oids: [],
      parsed: false,
    };
  }

  try {
    return {
      oids: parseCertificatePolicyOids(certificate.raw),
      parsed: true,
    };
  } catch {
    return {
      oids: [],
      parsed: false,
    };
  }
}

function getCertificatePolicyOidsFromOpenSsl(certificate) {
  try {
    const pem = certificateToPem(certificate);

    if (!pem) {
      return [];
    }

    const output = execFileSync("openssl", ["x509", "-noout", "-text"], {
      input: pem,
      encoding: "utf8",
      timeout: 3000,
      windowsHide: true,
      stdio: ["pipe", "pipe", "ignore"],
      maxBuffer: 256 * 1024,
    });

    return parseOpenSslCertificatePolicyOids(output);
  } catch {
    return [];
  }
}

function createX509Certificate(certificate) {
  if (certificate instanceof X509Certificate) {
    return certificate;
  }

  if (certificate?.raw) {
    return new X509Certificate(certificate.raw);
  }

  if (typeof certificate?.pem === "string") {
    return new X509Certificate(certificate.pem);
  }

  return null;
}

function certificateToPem(certificate) {
  if (typeof certificate?.pem === "string") {
    return certificate.pem;
  }

  if (!certificate?.raw) {
    return null;
  }

  return [
    "-----BEGIN CERTIFICATE-----",
    Buffer.from(certificate.raw).toString("base64").match(/.{1,64}/g)?.join("\n") || "",
    "-----END CERTIFICATE-----",
    "",
  ].join("\n");
}

function parseOpenSslCertificatePolicyOids(output) {
  const lines = output.split(/\r?\n/);
  const policyOids = [];
  let inPolicySection = false;
  let policyIndent = null;

  for (const line of lines) {
    if (!inPolicySection) {
      const match = line.match(/^(\s*)X509v3 Certificate Policies:/);

      if (match) {
        inPolicySection = true;
        policyIndent = match[1].length;
      }

      continue;
    }

    const indent = line.match(/^\s*/)?.[0].length || 0;

    if (line.trim() === "" || (policyIndent !== null && indent <= policyIndent && /^\s*X509v3 /.test(line))) {
      break;
    }

    for (const oid of extractOidStrings(line)) {
      if (oid !== CERTIFICATE_POLICIES_EXTENSION_OID) {
        policyOids.push(oid);
      }
    }
  }

  return [...new Set(policyOids)];
}

function parseCertificatePolicyOids(rawCertificate) {
  const der = Buffer.from(rawCertificate);
  const extensionValue = findCertificatePoliciesExtensionValue(der);

  if (!extensionValue) {
    return [];
  }

  const policies = [];
  const outerSequence = readDerTlv(extensionValue, 0);

  if (outerSequence.tag !== 0x30 || outerSequence.nextOffset !== extensionValue.length) {
    throw new Error("Invalid certificate policies extension.");
  }

  let offset = outerSequence.valueStart;

  while (offset < outerSequence.valueEnd) {
    const policyInfo = readDerTlv(extensionValue, offset);

    if (policyInfo.tag !== 0x30) {
      throw new Error("Invalid certificate policy entry.");
    }

    const policyOid = readDerTlv(extensionValue, policyInfo.valueStart);

    if (policyOid.tag !== 0x06 || policyOid.valueEnd > policyInfo.valueEnd) {
      throw new Error("Invalid certificate policy OID.");
    }

    policies.push(decodeDerOid(extensionValue.subarray(policyOid.valueStart, policyOid.valueEnd)));
    offset = policyInfo.nextOffset;
  }

  return policies;
}

function findCertificatePoliciesExtensionValue(der) {
  const certificate = readDerTlv(der, 0);

  if (certificate.tag !== 0x30 || certificate.nextOffset !== der.length) {
    throw new Error("Invalid certificate DER.");
  }

  const tbsCertificate = readDerTlv(der, certificate.valueStart);

  if (tbsCertificate.tag !== 0x30 || tbsCertificate.valueEnd > certificate.valueEnd) {
    throw new Error("Invalid TBS certificate.");
  }

  let offset = tbsCertificate.valueStart;

  while (offset < tbsCertificate.valueEnd) {
    const field = readDerTlv(der, offset);

    if (field.tag === 0xa3) {
      return findCertificatePoliciesExtensionValueInExtensions(der, field.valueStart, field.valueEnd);
    }

    offset = field.nextOffset;
  }

  return null;
}

function findCertificatePoliciesExtensionValueInExtensions(der, start, end) {
  const extensions = readDerTlv(der, start);

  if (extensions.tag !== 0x30 || extensions.valueEnd > end) {
    throw new Error("Invalid certificate extensions.");
  }

  let offset = extensions.valueStart;

  while (offset < extensions.valueEnd) {
    const extension = readDerTlv(der, offset);

    if (extension.tag !== 0x30) {
      throw new Error("Invalid certificate extension.");
    }

    const extensionOid = readDerTlv(der, extension.valueStart);

    if (extensionOid.tag !== 0x06 || extensionOid.valueEnd > extension.valueEnd) {
      throw new Error("Invalid certificate extension OID.");
    }

    const oid = decodeDerOid(der.subarray(extensionOid.valueStart, extensionOid.valueEnd));

    if (oid === CERTIFICATE_POLICIES_EXTENSION_OID) {
      return readExtensionValueAfterOid(der, extensionOid.nextOffset, extension.valueEnd);
    }

    offset = extension.nextOffset;
  }

  return null;
}

function readExtensionValueAfterOid(der, offset, end) {
  let currentOffset = offset;
  let next = readDerTlv(der, currentOffset);

  if (next.tag === 0x01) {
    currentOffset = next.nextOffset;
    next = readDerTlv(der, currentOffset);
  }

  if (next.tag !== 0x04 || next.valueEnd > end) {
    throw new Error("Invalid certificate policies extension value.");
  }

  return der.subarray(next.valueStart, next.valueEnd);
}

function readDerTlv(der, offset) {
  if (offset >= der.length) {
    throw new Error("Unexpected end of DER data.");
  }

  const tag = der[offset];
  const firstLengthByte = der[offset + 1];

  if (firstLengthByte === undefined) {
    throw new Error("Missing DER length.");
  }

  let length = firstLengthByte;
  let headerLength = 2;

  if ((firstLengthByte & 0x80) === 0x80) {
    const lengthBytes = firstLengthByte & 0x7f;

    if (lengthBytes === 0 || lengthBytes > 4 || offset + 2 + lengthBytes > der.length) {
      throw new Error("Invalid DER length.");
    }

    length = 0;

    for (let index = 0; index < lengthBytes; index += 1) {
      length = (length << 8) + der[offset + 2 + index];
    }

    headerLength += lengthBytes;
  }

  const valueStart = offset + headerLength;
  const valueEnd = valueStart + length;

  if (valueEnd > der.length) {
    throw new Error("DER length exceeds data.");
  }

  return {
    tag,
    valueStart,
    valueEnd,
    nextOffset: valueEnd,
  };
}

function decodeDerOid(value) {
  if (value.length === 0) {
    throw new Error("Empty DER OID.");
  }

  const subidentifiers = [];
  let currentValue = 0;
  let expectingContinuation = false;

  for (let index = 0; index < value.length; index += 1) {
    currentValue = (currentValue * 128) + (value[index] & 0x7f);
    expectingContinuation = (value[index] & 0x80) !== 0;

    if (!expectingContinuation) {
      subidentifiers.push(currentValue);
      currentValue = 0;
    }
  }

  if (expectingContinuation || subidentifiers.length === 0) {
    throw new Error("Incomplete DER OID.");
  }

  const firstSubidentifier = subidentifiers[0];
  const firstArc = firstSubidentifier >= 80 ? 2 : Math.floor(firstSubidentifier / 40);
  const secondArc = firstSubidentifier - (firstArc * 40);
  const oid = [firstArc, secondArc, ...subidentifiers.slice(1)];

  return oid.join(".");
}

function hasMeaningfulOrganization(subject) {
  if (!subject || typeof subject !== "object") {
    return false;
  }

  const organization = subject.O ?? subject.Organization ?? subject.organization;
  const values = Array.isArray(organization) ? organization : [organization];

  return values.some((value) => typeof value === "string" && value.trim().length > 0);
}

function hasEvLikeIssuer(issuer) {
  const issuerText = [
    issuer?.CN,
    issuer?.O,
    issuer?.Organization,
    issuer?.organization,
  ].flatMap((value) => Array.isArray(value) ? value : [value]).filter(Boolean).join(" ");

  return /\bEV\b/i.test(issuerText);
}

function hasEvLikeSubjectFields(subject) {
  if (!subject || typeof subject !== "object") {
    return false;
  }

  const evLikeFields = [
    "businessCategory",
    "serialNumber",
    "jurisdictionC",
    "jurisdictionST",
    "jurisdictionL",
    "jurisdictionCountryName",
    "jurisdictionStateOrProvinceName",
    "jurisdictionLocalityName",
    "organizationIdentifier",
  ];

  return evLikeFields.some((field) => hasNonEmptySubjectValue(subject[field]));
}

function hasUsableCertificateDetails(certificate) {
  return Boolean(
    certificate?.subject ||
    certificate?.issuer ||
    certificate?.valid_from ||
    certificate?.valid_to ||
    certificate?.raw,
  );
}

function hasNonEmptySubjectValue(value) {
  const values = Array.isArray(value) ? value : [value];

  return values.some((entry) => typeof entry === "string" && entry.trim().length > 0);
}

function extractOidStrings(value) {
  if (typeof value !== "string") {
    return [];
  }

  return value.match(/\b\d+(?:\.\d+){2,}\b/g) || [];
}

function buildChecks({
  host,
  resolvedAddresses,
  tlsResult,
  certificate,
  chain,
  hostnameMatches,
  hostnameError,
  warnings,
  serverProvidedCertificateCount,
  issuerChainEntriesShown,
}) {
  const checks = [
    {
      id: "dns_resolves",
      status: "pass",
      message: `${host} resolves to ${resolvedAddresses.join(", ")}`,
    },
    {
      id: "certificate_trusted",
      status: tlsResult.authorized ? "pass" : "fail",
      message: tlsResult.authorized
        ? "The certificate is trusted by the default trust store."
        : `The certificate is not trusted${tlsResult.authorizationError ? `: ${tlsResult.authorizationError}` : "."}`,
    },
    {
      id: "certificate_expiry",
      status: getExpiryStatus(certificate.daysRemaining),
      message: getExpiryMessage(certificate.daysRemaining),
    },
    {
      id: "hostname_match",
      status: hostnameMatches ? "pass" : "fail",
      message: hostnameMatches
        ? "The hostname is correctly listed in the certificate."
        : hostnameError,
    },
    {
      id: "certificate_chain",
      status: chain.length > 1 ? "pass" : "warn",
      message: formatCertificateChainSummaryMessage({
        issuerChainEntriesShown,
        serverProvidedCertificateCount,
      }),
    },
  ];

  if (warnings.some((warning) => warning.includes("weak signature algorithm"))) {
    checks.push({
      id: "weak_signature",
      status: "warn",
      message: "At least one certificate uses a weak signature algorithm.",
    });
  }

  return checks;
}

export function formatCertificateChainSummaryMessage({
  issuerChainEntriesShown,
  serverProvidedCertificateCount,
}) {
  return `Issuer chain entries shown: ${issuerChainEntriesShown}. Server-provided certificates: ${serverProvidedCertificateCount}.`;
}

function getExpiryStatus(daysRemaining) {
  if (daysRemaining === null || daysRemaining < 0) {
    return "fail";
  }

  return daysRemaining <= 30 ? "warn" : "pass";
}

function getExpiryMessage(daysRemaining) {
  if (daysRemaining === null) {
    return "The certificate expiration date could not be read.";
  }

  if (daysRemaining < 0) {
    return `The certificate expired ${Math.abs(daysRemaining)} day${Math.abs(daysRemaining) === 1 ? "" : "s"} ago.`;
  }

  return `The certificate expires in ${daysRemaining} day${daysRemaining === 1 ? "" : "s"}.`;
}

function getCertificateWarnings(chain) {
  return chain.flatMap((certificate, index) => {
    const signatureAlgorithm = certificate.signatureAlgorithm?.toLowerCase() || "";

    if (!signatureAlgorithm.includes("md5") && !signatureAlgorithm.includes("sha1")) {
      return [];
    }

    const label = index === 0 ? "server certificate" : `chain certificate ${index + 1}`;
    return [`The ${label} uses a weak signature algorithm: ${certificate.signatureAlgorithm}.`];
  });
}

function getDaysRemaining(validTo) {
  if (!validTo) {
    return null;
  }

  const expiresAt = new Date(validTo).getTime();

  if (!Number.isFinite(expiresAt)) {
    return null;
  }

  return Math.ceil((expiresAt - Date.now()) / 86400000);
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

  return groups.reduce((value, group) => {
    return (value << 16n) + BigInt(parseInt(group, 16));
  }, 0n);
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
