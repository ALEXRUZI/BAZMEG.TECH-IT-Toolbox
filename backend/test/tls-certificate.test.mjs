import assert from "node:assert/strict";
import { after, test } from "node:test";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { X509Certificate } from "node:crypto";
import tls from "node:tls";
import { once } from "node:events";
import { formatTlsResult } from "../src/tools/tls-check.mjs";
import { getCertificateExpiration, inspectCertificateEvidence, inspectSignature } from "../src/tools/tls-certificate.mjs";

// Disposable test-only keys are generated locally and removed; none are committed.
const directory = mkdtempSync(join(existsSync("/tmp/opencode") ? "/tmp/opencode" : tmpdir(), "tls-correctness-"));
after(() => rmSync(directory, { recursive: true, force: true }));
function openssl(args) {
  return execFileSync("openssl", args, { timeout: 5000, maxBuffer: 256 * 1024, stdio: ["ignore", "pipe", "ignore"] });
}
function selfSigned(name, keyArgs, hash = "-sha256", ca = false) {
  const key = `${directory}/${name}.key`;
  const pem = openssl(["req", "-new", "-x509", "-newkey", ...keyArgs, "-nodes", "-keyout", key,
    "-subj", "/CN=www.example.com", "-days", "365", "-set_serial", "1", hash,
    "-addext", `basicConstraints=critical,CA:${ca ? "TRUE" : "FALSE"}`]);
  return { pem, key, x509: new X509Certificate(pem) };
}
const rsa = selfSigned("rsa", ["rsa:2048"]);
const ec = selfSigned("ec", ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
const ed = selfSigned("ed", ["ed25519"]);
const ed448 = selfSigned("ed448", ["ed448"]);
const pss = selfSigned("pss", ["rsa-pss:2048"]);
const pssSha1 = selfSigned("pss-sha1", ["rsa-pss:2048"], "-sha1");
const sha1 = selfSigned("sha1", ["rsa:2048"], "-sha1");
const md5 = selfSigned("md5", ["rsa:2048"], "-md5");
const root = selfSigned("root", ["rsa:2048"], "-sha256", true);
const dsaParameters = `${directory}/dsa-parameters.pem`;
openssl(["genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", "dsa_paramgen_bits:1024", "-out", dsaParameters]);
const dsa = selfSigned("dsa", [`dsa:${dsaParameters}`], "-sha1");
writeFileSync(`${directory}/root.pem`, root.pem);
function issued(name, issuer, ca, keyArgs = ["rsa:2048"], subject = name === "leaf" ? "www.example.com" : name) {
  const key = `${directory}/${name}.key`;
  const csr = `${directory}/${name}.csr`;
  openssl(["req", "-new", "-newkey", ...keyArgs, "-nodes", "-keyout", key, "-out", csr, "-subj", `/CN=${subject}`]);
  const issuerPem = `${directory}/${name}-issuer.pem`;
  const extensions = `${directory}/${name}.ext`;
  writeFileSync(issuerPem, issuer.pem);
  writeFileSync(extensions, `basicConstraints=critical,CA:${ca ? "TRUE" : "FALSE"}\nsubjectAltName=DNS:www.example.com\n`);
  const pem = openssl(["x509", "-req", "-in", csr, "-CA", issuerPem, "-CAkey", issuer.key,
    "-set_serial", ca ? "2" : "3", "-days", "365", "-sha256", "-extfile", extensions]);
  return { pem, key, x509: new X509Certificate(pem) };
}
const intermediate = issued("intermediate", root, true);
const leaf = issued("leaf", intermediate, false);
const direct = issued("direct", root, false);
const ecRsaSigned = issued("ec-rsa-signed", root, false, ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]);
const selfIssuedNotSelfSigned = issued("self-issued", root, false, ["rsa:2048"], "www.example.com");
const peer = (fixture) => fixture.x509.toLegacyObject();
function result(certificate, now = Date.parse("2026-10-10T00:00:00Z"), authorized = false) {
  return formatTlsResult("www.example.com", 443, {
    peerCertificate: certificate, authorized, authorizationError: authorized ? null : "UNVERIFIED_TEST_CHAIN",
    protocol: "TLSv1.3", cipher: "fixture",
  }, ["8.8.8.1"], now);
}

test("native Node 22 metadata uses DER and KeyObject, not fabricated legacy fields", () => {
  assert.equal(peer(rsa).signatureAlgorithm, undefined);
  assert.equal(peer(rsa).asymmetricKeyType, undefined);
  assert.equal(rsa.x509.signatureAlgorithm, undefined);
  const details = inspectCertificateEvidence(peer(rsa));
  assert.equal(details.signatureAlgorithm, "sha256WithRSAEncryption");
  assert.equal(details.signatureAlgorithmOid, "1.2.840.113549.1.1.11");
  assert.equal(details.publicKeyAlgorithm, "rsa");
  assert.equal(details.modulusLength, 2048);
  assert.equal(details.namedCurve, null);
  assert.equal(getCertificateExpiration(peer(rsa).valid_to, rsa.x509.validToDate.getTime()).expirationState, "expired");
  assert.equal(getCertificateExpiration(peer(rsa).valid_to, rsa.x509.validToDate.getTime()).expiresAt, rsa.x509.validToDate.getTime());
  const ecDetails = inspectCertificateEvidence(peer(ec));
  assert.equal(ecDetails.signatureAlgorithm, "ecdsa-with-SHA256");
  assert.equal(ecDetails.publicKeyAlgorithm, "ec");
  assert.equal(ecDetails.namedCurve, "prime256v1");
  assert.equal(ecDetails.modulusLength, null);
  assert.equal(ecDetails.bits, null);
  for (const [fixture, name] of [[ed, "Ed25519"], [ed448, "Ed448"]]) {
    const details = inspectCertificateEvidence(peer(fixture));
    assert.equal(details.signatureAlgorithm, name);
    assert.equal(details.publicKeyAlgorithm, name.toLowerCase());
    assert.equal(details.modulusLength, null);
  }
  const pssDetails = inspectCertificateEvidence(peer(pss));
  assert.equal(pssDetails.publicKeyAlgorithm, "rsa-pss");
  assert.equal(pssDetails.modulusLength, 2048);
  assert.equal(pssDetails.signatureAlgorithm, "RSASSA-PSS (SHA256)");
  assert.equal(inspectCertificateEvidence(peer(pssSha1)).signatureStrength, "weak");
  const mixed = inspectCertificateEvidence(peer(ecRsaSigned));
  assert.equal(mixed.publicKeyAlgorithm, "ec");
  assert.equal(mixed.signatureAlgorithm, "sha256WithRSAEncryption");
  assert.equal(mixed.modulusLength, null);
  const dsaDetails = inspectCertificateEvidence(peer(dsa));
  assert.equal(dsaDetails.publicKeyAlgorithm, "dsa");
  assert.equal(dsaDetails.modulusLength, null);
  assert.equal(dsaDetails.signatureStrength, "weak");
});

test("weak SHA-1/MD5 signatures work on native certificates in leaf and issuer positions", () => {
  for (const fixture of [sha1, md5, pssSha1, dsa]) {
    assert.equal(inspectCertificateEvidence(peer(fixture)).signatureStrength, "weak");
    const certificate = peer(rsa);
    certificate.issuerCertificate = peer(fixture);
    const diagnostic = result(certificate);
    assert.ok(diagnostic.warnings.some((warning) => warning.includes("chain certificate 2 uses a weak signature algorithm")));
    assert.ok(result(peer(fixture)).warnings.some((warning) => warning.includes("server certificate uses a weak signature algorithm")));
    assert.equal(diagnostic.checks.find((check) => check.id === "weak_signature").status, "warn");
  }
  const misleading = peer(rsa);
  misleading.issuer.CN = "MD5 SHA1 Trust";
  misleading.signatureAlgorithm = "md5WithRSAEncryption";
  assert.ok(!result(misleading).warnings.some((warning) => warning.includes("weak signature algorithm")));
});

const expiry = Date.parse("2030-01-01T00:00:00Z");
for (const [offset, state, status] of [
  [-1000, "expiring-soon", "warn"], [0, "expired", "fail"], [1000, "expired", "fail"],
  [3600000, "expired", "fail"], [23 * 3600000, "expired", "fail"], [3 * 86400000, "expired", "fail"],
  [-30 * 86400000, "expiring-soon", "warn"], [-30 * 86400000 - 1000, "valid", "pass"],
]) {
  test(`exact expiration offset ${offset} keeps summary, checks and warnings aligned`, () => {
    const certificate = peer(rsa);
    certificate.valid_to = "Jan  1 00:00:00 2030 GMT";
    const diagnostic = result(certificate, expiry + offset, true);
    assert.equal(diagnostic.certificate.expirationState, state);
    assert.equal(diagnostic.summary.notExpired, state !== "expired");
    assert.equal(diagnostic.checks.find((check) => check.id === "certificate_expiry").status, status);
    assert.equal(diagnostic.warnings.some((warning) => warning.includes("has expired")), state === "expired");
    assert.equal(diagnostic.summary.trusted, true, "expiration does not overwrite authorization");
    assert.equal(diagnostic.certificate.daysRemaining, Math.ceil(-offset / 86400000) || 0);
  });
}
test("missing, invalid and timezone-ambiguous expiration dates remain unknown", () => {
  for (const validTo of [null, undefined, "garbage", "2030-01-01", "Jan 1 00:00:00 2030", "2030-02-30T00:00:00Z", "Feb 30 00:00:00 2030 GMT"]) {
    assert.equal(getCertificateExpiration(validTo, expiry).expirationState, "unknown");
    const diagnostic = result({ ...peer(rsa), valid_to: validTo }, expiry);
    assert.equal(diagnostic.summary.notExpired, null);
    assert.equal(diagnostic.checks.find((check) => check.id === "certificate_expiry").status, "warn");
  }
  assert.deepEqual(getCertificateExpiration("2030-01-01T00:00:00.000Z", expiry), getCertificateExpiration("Jan  1 00:00:00 2030 GMT", expiry));
  assert.equal(getCertificateExpiration("2030-01-01T00:00:00Z", NaN).expirationState, "unknown");
});

test("real issuer evidence distinguishes CA/self-signature from self-issued non-CA leaf", () => {
  const certificate = peer(leaf);
  certificate.issuerCertificate = peer(intermediate);
  certificate.issuerCertificate.issuerCertificate = peer(root);
  certificate.issuerCertificate.issuerCertificate.issuerCertificate = certificate.issuerCertificate.issuerCertificate;
  const diagnostic = result(certificate);
  assert.deepEqual(diagnostic.issuerChain.map((entry) => entry.level), ["leaf", "intermediate", "self-signed-ca"]);
  assert.deepEqual(diagnostic.issuerChain.map((entry) => entry.source), ["peer", "inferred", "inferred"]);
  assert.equal(diagnostic.issuerChainComplete, null);
  assert.equal(diagnostic.serverProvidedCertificateCount, null);
  assert.equal(diagnostic.summary.chainProvided, null);
  assert.equal(diagnostic.summary.trusted, false);
  const nonCa = result(peer(rsa));
  assert.equal(nonCa.issuerChain[0].level, "leaf");
  assert.equal(nonCa.certificate.ca, false);
  assert.equal(nonCa.certificate.selfIssued, true);
  assert.equal(nonCa.certificate.selfSigned, true);
  const selfIssued = result(peer(selfIssuedNotSelfSigned));
  assert.equal(selfIssued.certificate.selfIssued, true);
  assert.equal(selfIssued.certificate.selfSigned, false);
  assert.equal(selfIssued.certificate.ca, false);
  assert.equal(selfIssued.issuerChain[0].level, "leaf");
  for (const chain of [peer(leaf), { ...peer(leaf), issuerCertificate: peer(intermediate) }, { subject: { CN: "www.example.com" } }]) {
    const diagnostic = result(chain);
    assert.equal(diagnostic.issuerChainComplete, null);
    assert.equal(diagnostic.serverProvidedCertificateCount, null);
    assert.equal(diagnostic.checks.find((check) => check.id === "certificate_chain").status, "warn");
  }
});

test("loopback TLS may supplement a transmitted leaf with a locally trusted root; never claim a wire count", { timeout: 10000 }, async () => {
  // Server sends only the direct leaf. Root is exclusively in the client's CA set.
  const sockets = new Set();
  const server = tls.createServer({ key: readFileSync(direct.key), cert: direct.pem }, (socket) => socket.end());
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.on("tlsClientError", () => {});
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, servername: "www.example.com", ca: root.pem, rejectUnauthorized: false });
  socket.setTimeout(5000, () => socket.destroy(new Error("Test TLS timeout")));
  try {
    await once(socket, "secureConnect");
    assert.equal(socket.authorized, true);
    const observed = socket.getPeerCertificate(true);
    assert.equal(observed.issuerCertificate.fingerprint256, root.x509.fingerprint256);
    const diagnostic = result(observed, Date.now(), socket.authorized);
    assert.equal(diagnostic.chain.length, 2);
    assert.equal(diagnostic.issuerChain[1].source, "inferred");
    assert.equal(diagnostic.serverProvidedCertificateCount, null);
    assert.equal(diagnostic.summary.trusted, true);
  } finally {
    socket.destroy();
    sockets.forEach((socket) => socket.destroy());
    await new Promise((resolve) => server.close(resolve));
  }
});

for (const includeIntermediate of [false, true]) {
  test(`loopback server ${includeIntermediate ? "includes" : "omits"} intermediate without inventing provenance`, { timeout: 10000 }, async () => {
    const sockets = new Set();
    const cert = includeIntermediate ? Buffer.concat([leaf.pem, intermediate.pem]) : leaf.pem;
    const server = tls.createServer({ key: readFileSync(leaf.key), cert }, (socket) => socket.end());
    server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
    server.on("tlsClientError", () => {});
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const socket = tls.connect({ host: "127.0.0.1", port: server.address().port, servername: "www.example.com", ca: root.pem, rejectUnauthorized: false });
    socket.setTimeout(5000, () => socket.destroy(new Error("Test TLS timeout")));
    try {
      await once(socket, "secureConnect");
      const diagnostic = result(socket.getPeerCertificate(true), Date.now(), socket.authorized);
      assert.equal(diagnostic.chain.length, includeIntermediate ? 3 : 1);
      assert.equal(diagnostic.summary.trusted, includeIntermediate);
      assert.equal(diagnostic.serverProvidedCertificateCount, null);
      assert.equal(diagnostic.issuerChainComplete, null);
      assert.ok(diagnostic.issuerChain.slice(1).every((entry) => entry.source === "inferred"));
    } finally {
      socket.destroy();
      sockets.forEach((socket) => socket.destroy());
      await new Promise((resolve) => server.close(resolve));
    }
  });
}

test("unknown OIDs survive and malformed bounded DER returns unknown without throwing", () => {
  const raw = Buffer.from(rsa.x509.raw);
  const known = Buffer.from("06092a864886f70d01010b", "hex");
  for (let offset = raw.indexOf(known); offset >= 0; offset = raw.indexOf(known, offset + known.length)) raw[offset + known.length - 1] = 99;
  assert.match(inspectSignature(raw).signatureAlgorithm, /Unknown algorithm/);
  assert.equal(inspectSignature(raw).signatureAlgorithmOid, "1.2.840.113549.1.1.99");
  assert.equal(inspectSignature(raw).signatureStrength, "unknown");
  const unknownDiagnostic = result({ ...peer(rsa), raw });
  assert.ok(unknownDiagnostic.warnings.some((warning) => warning.includes("signature strength is unknown")));
  for (const malformed of [Buffer.alloc(0), Buffer.from([0x30, 0x80]), Buffer.from([0x30, 0x84, 255, 255, 255, 255]),
    Buffer.from([0x30, 0x81, 1, 0]), rsa.x509.raw.subarray(0, 100), Buffer.alloc(256 * 1024 + 1)]) {
    assert.equal(inspectSignature(malformed).signatureStrength, "unknown");
    assert.equal(inspectCertificateEvidence({ raw: malformed }).publicKeyAlgorithm, null);
    assert.equal(inspectCertificateEvidence({ raw: malformed }).signatureStrength, "unknown");
  }
  const mismatch = Buffer.from(rsa.x509.raw);
  mismatch[mismatch.indexOf(known) + known.length - 1] = 12;
  assert.equal(inspectSignature(mismatch).signatureStrength, "unknown");
  const badTag = Buffer.from(rsa.x509.raw);
  badTag[0] = 0x31;
  assert.equal(inspectSignature(badTag).signatureStrength, "unknown");
  const pssUnknown = Buffer.from(pss.x509.raw);
  const sha256Oid = Buffer.from("0609608648016503040201", "hex");
  for (let offset = pssUnknown.indexOf(sha256Oid); offset >= 0; offset = pssUnknown.indexOf(sha256Oid, offset + sha256Oid.length)) pssUnknown[offset + sha256Oid.length - 1] = 99;
  assert.equal(inspectSignature(pssUnknown).signatureAlgorithm, "RSASSA-PSS (hash unverified)");
  assert.equal(inspectSignature(pssUnknown).signatureStrength, "unknown");
});
