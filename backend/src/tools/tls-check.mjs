import dns from "node:dns/promises";
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
  const chain = buildCertificateChain(tlsResult.peerCertificate);
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
    warnings,
    summary,
    checks,
    chain,
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

function buildChecks({
  host,
  resolvedAddresses,
  tlsResult,
  certificate,
  chain,
  hostnameMatches,
  hostnameError,
  warnings,
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
      message: `The server provided ${chain.length} certificate${chain.length === 1 ? "" : "s"}.`,
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
