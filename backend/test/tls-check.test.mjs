import assert from "node:assert/strict";
import test from "node:test";
import {
  buildIssuerChain,
  buildIssuerChainMetadata,
  formatCertificateChainSummaryMessage,
  inferCertificateValidationType,
} from "../src/tools/tls-check.mjs";

test("classifies CA/B Forum EV policy OID as EV with policy confidence", () => {
  const result = inferCertificateValidationType({
    subject: {
      O: "Example Corp",
    },
    raw: certificateWithPolicies(["2.23.140.1.1"]),
  });

  assert.equal(result.type, "EV");
  assert.equal(result.confidence, "policy-oid");
  assert.deepEqual(result.policyOids, ["2.23.140.1.1"]);
});

test("classifies CA/B Forum OV policy OID as OV with policy confidence", () => {
  const result = inferCertificateValidationType({
    subject: {
      O: "Example Corp",
    },
    raw: certificateWithPolicies(["2.23.140.1.2.2"]),
  });

  assert.equal(result.type, "OV");
  assert.equal(result.confidence, "policy-oid");
  assert.equal(result.reason, "Certificate Policies contains CA/B Forum OV policy OID 2.23.140.1.2.2.");
});

test("classifies CA/B Forum DV policy OID as DV with policy confidence", () => {
  const result = inferCertificateValidationType({
    subject: {
      CN: "www.example.com",
    },
    raw: certificateWithPolicies(["2.23.140.1.2.1"]),
  });

  assert.equal(result.type, "DV");
  assert.equal(result.confidence, "policy-oid");
});

test("classifies CA/B Forum IV policy OID as IV with policy confidence", () => {
  const result = inferCertificateValidationType({
    subject: {
      CN: "person.example",
    },
    raw: certificateWithPolicies(["2.23.140.1.2.3"]),
  });

  assert.equal(result.type, "IV");
  assert.equal(result.confidence, "policy-oid");
  assert.equal(result.reason, "Certificate Policies contains CA/B Forum Individual Validated policy OID 2.23.140.1.2.3.");
});

test("classifies EV-named issuers with EV-like subject fields as EV heuristic when no EV policy is readable", () => {
  const result = inferCertificateValidationType({
    subject: {
      O: "Example Corp",
      businessCategory: "Private Organization",
      serialNumber: "1234567",
      jurisdictionC: "US",
    },
    issuer: {
      CN: "Thawte EV RSA CA G2",
    },
    raw: certificateWithPolicies(["2.16.840.1.113733.1.7.23.6"]),
  });

  assert.equal(result.type, "EV");
  assert.equal(result.confidence, "heuristic");
});

test("does not classify EV-named issuers as EV without EV-like subject fields", () => {
  const result = inferCertificateValidationType({
    subject: {
      O: "Example Corp",
      CN: "www.example.com",
    },
    issuer: {
      CN: "Thawte EV RSA CA G2",
    },
    raw: certificateWithPolicies([]),
  });

  assert.equal(result.type, "OV");
  assert.equal(result.confidence, "heuristic");
});

test("classifies subject organization only as OV heuristic", () => {
  const result = inferCertificateValidationType({
    subject: {
      O: "Example Corp",
    },
    raw: certificateWithPolicies([]),
  });

  assert.equal(result.type, "OV");
  assert.equal(result.confidence, "heuristic");
});

test("classifies certificates without organization or policy OIDs as DV heuristic", () => {
  const result = inferCertificateValidationType({
    subject: {
      CN: "www.example.com",
    },
    raw: certificateWithPolicies([]),
  });

  assert.equal(result.type, "DV");
  assert.equal(result.confidence, "heuristic");
});

test("classifies missing certificate data as Unknown", () => {
  assert.equal(inferCertificateValidationType(null).type, "Unknown");
  assert.equal(inferCertificateValidationType({}).type, "Unknown");
});

test("builds compact issuer chain entries without certificate blobs", () => {
  const issuerChain = buildIssuerChain([
    {
      type: "server",
      subject: { CN: "www.example.com" },
      issuer: { CN: "Example Intermediate CA", O: "Example Trust" },
      validFrom: "Jan 1 00:00:00 2026 GMT",
      validTo: "Apr 1 00:00:00 2026 GMT",
      fingerprint256: "AA:BB",
    },
    {
      type: "intermediate",
      subject: { CN: "Example Intermediate CA" },
      issuer: { CN: "Example Root CA" },
      validFrom: "Jan 1 00:00:00 2025 GMT",
      validTo: "Jan 1 00:00:00 2030 GMT",
      fingerprint256: "CC:DD",
    },
    {
      type: "root",
      subject: { CN: "Example Root CA" },
      issuer: { CN: "Example Root CA" },
      validFrom: "Jan 1 00:00:00 2020 GMT",
      validTo: "Jan 1 00:00:00 2040 GMT",
      fingerprint256: "EE:FF",
    },
  ]);

  assert.deepEqual(issuerChain.map((entry) => entry.level), ["leaf", "intermediate", "root"]);
  assert.deepEqual(issuerChain.map((entry) => entry.source), ["peer-chain", "peer-chain", "peer-chain"]);
  assert.equal(issuerChain[0].subject, "CN: www.example.com");
  assert.equal(issuerChain[0].issuer, "CN: Example Intermediate CA, O: Example Trust");
  assert.equal(issuerChain[0].fingerprint256, "AA:BB");
});

test("does not label non-self-issued chain entries as root", () => {
  const issuerChain = buildIssuerChain([
    {
      type: "root",
      subject: { CN: "Not Actually Root" },
      issuer: { CN: "Different Issuer" },
      validFrom: null,
      validTo: null,
      fingerprint256: "11:22",
    },
  ]);

  assert.equal(issuerChain[0].level, "leaf");
  assert.equal(issuerChain[0].source, "peer-chain");
});

test("issuer chain metadata count agrees with summary wording", () => {
  const chain = [
    {
      type: "server",
      subject: { CN: "www.example.com" },
      issuer: { CN: "Example Intermediate CA" },
      validFrom: null,
      validTo: null,
      fingerprint256: "AA:BB",
    },
    {
      type: "intermediate",
      subject: { CN: "Example Intermediate CA" },
      issuer: { CN: "Example Root CA" },
      validFrom: null,
      validTo: null,
      fingerprint256: "CC:DD",
    },
    {
      type: "root",
      subject: { CN: "Example Root CA" },
      issuer: { CN: "Example Root CA" },
      validFrom: null,
      validTo: null,
      fingerprint256: "EE:FF",
    },
  ];
  const metadata = buildIssuerChainMetadata(chain);
  const message = formatCertificateChainSummaryMessage({
    issuerChainEntriesShown: metadata.issuerChain.length,
    serverProvidedCertificateCount: metadata.serverProvidedCertificateCount,
  });

  assert.equal(metadata.serverProvidedCertificateCount, 3);
  assert.equal(metadata.issuerChain[0].level, "leaf");
  assert.equal(metadata.issuerChain[0].source, "peer-chain");
  assert.equal(message, "Issuer chain entries shown: 3. Server-provided certificates: 3.");
  assert.doesNotMatch(message, /The server provided 3 certificates/);
});

function certificateWithPolicies(policyOids) {
  const policyEntries = policyOids.map((policyOid) => sequence(objectIdentifier(policyOid)));
  const extensionValue = sequence(...policyEntries);
  const certificatePoliciesExtension = sequence(
    objectIdentifier("2.5.29.32"),
    octetString(extensionValue),
  );

  const extensions = contextConstructed(3, sequence(certificatePoliciesExtension));
  const tbsCertificate = sequence(
    integer(1),
    sequence(objectIdentifier("1.2.840.113549.1.1.11")),
    sequence(),
    sequence(),
    sequence(),
    sequence(),
    extensions,
  );

  return sequence(
    tbsCertificate,
    sequence(objectIdentifier("1.2.840.113549.1.1.11")),
    bitString(Buffer.from([0])),
  );
}

function sequence(...items) {
  return tlv(0x30, Buffer.concat(items));
}

function contextConstructed(tag, value) {
  return tlv(0xa0 + tag, value);
}

function integer(value) {
  return tlv(0x02, Buffer.from([value]));
}

function bitString(value) {
  return tlv(0x03, Buffer.concat([Buffer.from([0]), value]));
}

function octetString(value) {
  return tlv(0x04, value);
}

function objectIdentifier(value) {
  return tlv(0x06, encodeOid(value));
}

function tlv(tag, value) {
  return Buffer.concat([
    Buffer.from([tag]),
    encodeLength(value.length),
    value,
  ]);
}

function encodeLength(length) {
  if (length < 0x80) {
    return Buffer.from([length]);
  }

  const bytes = [];
  let remaining = length;

  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }

  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeOid(value) {
  const parts = value.split(".").map((part) => Number(part));
  const encoded = [parts[0] * 40 + parts[1]];

  for (const part of parts.slice(2)) {
    encoded.push(...encodeOidPart(part));
  }

  return Buffer.from(encoded);
}

function encodeOidPart(value) {
  const bytes = [value & 0x7f];
  let remaining = value >> 7;

  while (remaining > 0) {
    bytes.unshift(0x80 | (remaining & 0x7f));
    remaining >>= 7;
  }

  return bytes;
}
