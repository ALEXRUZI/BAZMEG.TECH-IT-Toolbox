import assert from "node:assert/strict";
import test from "node:test";
import dgram from "node:dgram";
import { EventEmitter } from "node:events";
import {
  BURST_RESOLVER_IDS,
  checkDns,
  DnsCheckError,
  getBurstResolverSummaries,
  getSingleResolverSummaries,
  normalizeDnsCheckRequest,
  resetDnsCheckState,
} from "../src/tools/dns-check.mjs";

test("validates supported record types with record-aware inputs", () => {
  const validByType = {
    A: { query: "example.com" },
    AAAA: { query: "example.com" },
    CNAME: { query: "www.example.com" },
    MX: { query: "example.com" },
    TXT: { query: "example.com" },
    NS: { query: "example.com" },
    SOA: { query: "example.com" },
    CAA: { query: "example.com" },
    PTR: { query: "8.8.8.8" },
    SRV: { service: "sip", protocol: "tcp", domain: "example.com" },
  };

  for (const [recordType, payload] of Object.entries(validByType)) {
    const request = normalizeDnsCheckRequest({
      mode: "single",
      resolverId: "cloudflare",
      recordType,
      ...payload,
    });

    assert.equal(request.recordType, recordType);
    assert.equal(request.mode, "single");
  }
});

test("rejects malformed and internal-only DNS inputs", () => {
  const tooLongName = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}.com`;
  const invalidPayloads = [
    { recordType: "A", query: "localhost" },
    { recordType: "AAAA", query: "printer.local" },
    { recordType: "CNAME", query: "bad..example.com" },
    { recordType: "MX", query: `${"a".repeat(64)}.example.com` },
    { recordType: "NS", query: tooLongName },
    { recordType: "PTR", query: "999.8.8.8" },
    { recordType: "PTR", query: "192.168.1.1" },
    { recordType: "PTR", query: "203.0.113.1" },
    { recordType: "SRV", query: "_sip._icmp.example.com" },
  ];

  for (const payload of invalidPayloads) {
    assert.throws(
      () => normalizeDnsCheckRequest({ mode: "single", resolverId: "cloudflare", ...payload }),
      DnsCheckError,
    );
  }
});

test("converts PTR input to server-side reverse DNS name", () => {
  const ipv4 = normalizeDnsCheckRequest({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "PTR",
    query: "8.8.4.4",
  });
  const ipv6 = normalizeDnsCheckRequest({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "PTR",
    query: "2001:4860:4860::8888",
  });

  assert.equal(ipv4.query.queryName, "4.4.8.8.in-addr.arpa");
  assert.equal(
    ipv6.query.queryName,
    "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa",
  );
});

test("builds and validates SRV names from fields or full query", () => {
  const fromFields = normalizeDnsCheckRequest({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "SRV",
    service: "sip",
    protocol: "tcp",
    domain: "example.com",
  });
  const fromQuery = normalizeDnsCheckRequest({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "SRV",
    query: "_xmpp-server._tcp.example.com",
  });

  assert.equal(fromFields.query.queryName, "_sip._tcp.example.com");
  assert.equal(fromFields.query.service, "_sip");
  assert.equal(fromFields.query.protocol, "_tcp");
  assert.equal(fromQuery.query.queryName, "_xmpp-server._tcp.example.com");
  assert.throws(
    () => normalizeDnsCheckRequest({
      mode: "single",
      resolverId: "cloudflare",
      recordType: "SRV",
      service: "sip",
      protocol: "icmp",
      domain: "example.com",
    }),
    DnsCheckError,
  );
});

test("accepts resolverId only and rejects custom resolver IP fields", () => {
  for (const forbiddenField of ["resolver", "resolverIp", "dohUrl", "dotHostname", "resolverHost", "url", "host"]) {
    assert.throws(
      () => normalizeDnsCheckRequest({
        mode: "single",
        resolverId: "cloudflare",
        [forbiddenField]: "1.1.1.1",
        recordType: "A",
        query: "example.com",
      }),
      /predefined DNS providers/,
    );
  }

  assert.throws(
    () => normalizeDnsCheckRequest({
      mode: "burst",
      resolverId: "1.1.1.1",
      recordType: "A",
      query: "example.com",
    }),
    /available for this DNS check mode/,
  );
});

test("rejects ANY, AXFR, and bulk input", () => {
  for (const recordType of ["ANY", "AXFR"]) {
    assert.throws(
      () => normalizeDnsCheckRequest({
        mode: "single",
        resolverId: "cloudflare",
        recordType,
        query: "example.com",
      }),
      /supported DNS record type/,
    );
  }

  assert.throws(
    () => normalizeDnsCheckRequest({
      mode: "single",
      resolverId: "cloudflare",
      recordType: "A",
      query: "example.com",
      queries: ["example.com", "example.net"],
    }),
    /one DNS query at a time/,
  );
});

test("cache metadata describes this site's cache", async () => {
  resetDnsCheckState();
  let nowMs = 1_000_000;
  let queryCount = 0;
  const queryDns = async () => {
    queryCount += 1;
    return dnsResponse({
      answer: [{ name: "example.com", type: "A", ttl: 60, data: "93.184.216.34" }],
    });
  };
  const payload = {
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "example.com",
    dnssec: false,
  };

  const first = await checkDns(payload, { clientIp: "203.0.113.10", now: () => nowMs, queryDns });
  nowMs += 11_000;
  const second = await checkDns(payload, { clientIp: "203.0.113.10", now: () => nowMs, queryDns });

  assert.equal(queryCount, 1);
  assert.deepEqual(first.cache, {
    fromCache: false,
    cacheScope: "site",
    cacheTtlSeconds: 60,
    cacheAgeSeconds: 0,
    cacheExpiresInSeconds: 60,
  });
  assert.equal(second.cache.fromCache, true);
  assert.equal(second.cache.cacheScope, "site");
  assert.equal(second.cache.cacheAgeSeconds, 11);
  assert.equal(second.cache.cacheExpiresInSeconds, 49);
});

test("single cache key separates DNSSEC option changes", async () => {
  resetDnsCheckState();
  let queryCount = 0;
  const queryDns = async (_server, name) => {
    queryCount += 1;
    return dnsResponse({
      answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }],
    });
  };

  const withoutDnssec = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "dnssec-cache.example.com",
    dnssec: false,
  }, { clientIp: "203.0.113.19", now: () => 1_500_000, queryDns });
  const withDnssec = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "dnssec-cache.example.com",
    dnssec: true,
  }, { clientIp: "203.0.113.19", now: () => 1_500_000, queryDns });

  assert.equal(withoutDnssec.cache.fromCache, false);
  assert.equal(withDnssec.cache.fromCache, false);
  assert.equal(queryCount, 4);
});

test("burst cache metadata uses 300 seconds and avoids repeat live checks", async () => {
  resetDnsCheckState();
  let nowMs = 4_000_000;
  let queryCount = 0;
  const payload = {
    mode: "burst",
    recordType: "A",
    query: "burst-cache.example.com",
    dnssec: true,
  };
  const queryDns = async (_server, name) => {
    queryCount += 1;
    return dnsResponse({
      answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }],
    });
  };

  const first = await checkDns(payload, { clientIp: "203.0.113.21", now: () => nowMs, queryDns });
  nowMs += 120_000;
  const second = await checkDns(payload, { clientIp: "203.0.113.21", now: () => nowMs, queryDns });

  assert.equal(queryCount, 10);
  assert.equal(first.cache.cacheTtlSeconds, 300);
  assert.equal(first.cache.cacheScope, "site");
  assert.equal(first.cache.fromCache, false);
  assert.equal(second.cache.fromCache, true);
  assert.equal(second.cache.cacheAgeSeconds, 120);
  assert.equal(second.cache.cacheExpiresInSeconds, 180);
});

test("cached requests consume zero DNS query tokens", async () => {
  resetDnsCheckState();
  let queryCount = 0;
  const queryDns = async () => {
    queryCount += 1;
    return dnsResponse({
      answer: [{ name: "cached.example.com", type: "A", ttl: 60, data: "93.184.216.34" }],
    });
  };
  const payload = {
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "cached.example.com",
    dnssec: false,
  };

  for (let index = 0; index < 120; index += 1) {
    const result = await checkDns(payload, { clientIp: "203.0.113.20", now: () => 2_000_000, queryDns });
    assert.equal(result.ok, true);
  }

  assert.equal(queryCount, 1);
});

test("burst live checks cost 10 internal tokens", async () => {
  resetDnsCheckState();
  const queryDns = async (_server, name) => dnsResponse({
    answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }],
  });

  for (let index = 0; index < 10; index += 1) {
    const result = await checkDns({
      mode: "burst",
      recordType: "A",
      query: `burst-${index}.example.com`,
      dnssec: false,
    }, { clientIp: "203.0.113.22", now: () => 2_500_000, queryDns });

    assert.equal(result.ok, true);
  }

  await assert.rejects(
    () => checkDns({
      mode: "burst",
      recordType: "A",
      query: "burst-10.example.com",
      dnssec: false,
    }, { clientIp: "203.0.113.22", now: () => 2_500_000, queryDns }),
    { code: "RATE_LIMITED" },
  );
});

test("rate limit returns a generic error without exposing limits or token counts", async () => {
  resetDnsCheckState();
  const queryDns = async (_server, name) => dnsResponse({
    answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }],
  });

  for (let index = 0; index < 100; index += 1) {
    await checkDns({
      mode: "single",
      resolverId: "cloudflare",
      recordType: "A",
      query: `host-${index}.example.com`,
      dnssec: false,
    }, { clientIp: "203.0.113.30", now: () => 3_000_000, queryDns });
  }

  await assert.rejects(
    () => checkDns({
      mode: "single",
      resolverId: "cloudflare",
      recordType: "A",
      query: "host-101.example.com",
      dnssec: false,
    }, { clientIp: "203.0.113.30", now: () => 3_000_000, queryDns }),
    (error) => {
      assert.equal(error.code, "RATE_LIMITED");
      assert.equal(error.safeMessage, "Too many live DNS checks were made recently. Please try again later.");
      assert.equal(/\d/.test(error.safeMessage), false);
      return true;
    },
  );
});

test("primary resolver is used first and fallback is only used after network-style failure", async () => {
  resetDnsCheckState();
  const successfulServers = [];
  const successResult = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "primary.example.com",
    dnssec: false,
  }, {
    clientIp: "203.0.113.31",
    queryDns: async (server, name) => {
      successfulServers.push(server);
      return dnsResponse({
        answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }],
      });
    },
  });

  assert.equal(successResult.ok, true);
  assert.deepEqual(successfulServers, ["1.1.1.1"]);

  resetDnsCheckState();
  const fallbackServers = [];
  const fallbackResult = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "fallback.example.com",
    dnssec: false,
  }, {
    clientIp: "203.0.113.32",
    queryDns: async (server, name) => {
      fallbackServers.push(server);

      if (server === "1.1.1.1") {
        throw Object.assign(new Error("timeout"), { code: "DNS_TIMEOUT" });
      }

      return dnsResponse({
        answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }],
      });
    },
  });

  assert.equal(fallbackResult.ok, true);
  assert.deepEqual(fallbackServers, ["1.1.1.1", "1.0.0.1"]);
});

test("burst excludes Neustar while single includes Neustar", () => {
  assert.equal(getSingleResolverSummaries().some((resolver) => resolver.id === "neustar"), true);
  assert.equal(getBurstResolverSummaries().some((resolver) => resolver.id === "neustar"), false);
  assert.equal(BURST_RESOLVER_IDS.length, 10);
  assert.deepEqual(getBurstResolverSummaries().map((resolver) => resolver.name), [
    "Cloudflare DNS",
    "Google DNS",
    "OpenDNS / Cisco",
    "Quad9",
    "FortiGuard DNS",
    "AdGuard DNS",
    "Verisign Public DNS",
    "DNS.WATCH",
    "Comodo Secure DNS",
    "Level3 / Lumen",
  ]);
});

test("burst DNSSEC is lightweight and includes the limitation note", async () => {
  resetDnsCheckState();
  const result = await checkDns({
    mode: "burst",
    recordType: "A",
    query: "dnssec-burst.example.com",
    dnssec: true,
  }, {
    clientIp: "203.0.113.33",
    queryDns: async (_server, name) => dnsResponse({
      flags: { ad: true },
      answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }],
    }),
  });

  assert.equal(result.dnssec.requested, false);
  assert.equal(result.dnssec.doFlagSent, false);
  assert.equal(result.dnssec.deepChecksDisabled, true);
  assert.match(result.dnssec.note, /Deep DNSSEC checks are disabled/);
  assert.equal(result.diagnostics.some((diagnostic) => diagnostic.id === "dnssec_deep_checks_disabled"), true);
  assert.equal(result.providers.every((provider) => provider.dnssec.deepChecksDisabled !== false), true);
});

test("MX diagnostics include target resolution and warnings", async () => {
  resetDnsCheckState();
  const result = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "MX",
    query: "example.com",
    dnssec: false,
  }, {
    clientIp: "203.0.113.34",
    queryDns: async (_server, name, type) => {
      if (type === "MX") {
        return dnsResponse({
          answer: [
            { name, type: "MX", ttl: 300, data: { preference: 10, exchange: "mail.example.com" } },
            { name, type: "MX", ttl: 300, data: { preference: 20, exchange: "alias.example.com" } },
          ],
        });
      }

      if (name === "mail.example.com" && type === "A") {
        return dnsResponse({ answer: [{ name, type: "A", ttl: 60, data: "93.184.216.34" }] });
      }

      if (name === "mail.example.com" && type === "AAAA") {
        return dnsResponse({ answer: [{ name, type: "AAAA", ttl: 60, data: "2606:2800:220:1:248:1893:25c8:1946" }] });
      }

      if (name === "alias.example.com" && type === "CNAME") {
        return dnsResponse({ answer: [{ name, type: "CNAME", ttl: 60, data: "mail.example.com" }] });
      }

      return dnsResponse();
    },
  });

  assert.equal(result.records[0].preference, 10);
  assert.equal(result.records[0].exchange, "mail.example.com");
  assert.equal(result.records[0].ttl, 300);
  assert.deepEqual(result.records[0].resolvedA, ["93.184.216.34"]);
  assert.deepEqual(result.records[0].resolvedAAAA, ["2606:2800:220:1:248:1893:25c8:1946"]);
  assert.equal(result.diagnostics.some((diagnostic) => diagnostic.id === "mx_host_resolution"), true);
  assert.equal(result.warnings.some((warning) => warning.includes("MX host does not resolve: alias.example.com")), true);
  assert.equal(result.warnings.some((warning) => warning.includes("MX target points to CNAME: alias.example.com")), true);
});

test("TXT diagnostics detect SPF, DKIM, DMARC, verification, and ACME records", async () => {
  resetDnsCheckState();
  const spfIncludes = Array.from({ length: 11 }, (_item, index) => `include:spf${index}.example.com`).join(" ");
  const result = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "TXT",
    query: "example.com",
    dnssec: false,
  }, {
    clientIp: "203.0.113.35",
    queryDns: async (_server, name, type) => {
      if (type === "TXT" && name === "example.com") {
        return dnsResponse({
          answer: [
            { name, type: "TXT", ttl: 60, data: [`v=spf1 ${spfIncludes} ptr redirect=spf.example.com +all`] },
            { name, type: "TXT", ttl: 60, data: ["v=spf1 -all"] },
            { name, type: "TXT", ttl: 60, data: ["v=DKIM1; k=rsa; p="] },
            { name, type: "TXT", ttl: 60, data: ["MS=ms12345678"] },
            { name, type: "TXT", ttl: 60, data: ["google-site-verification=abc123"] },
            { name, type: "TXT", ttl: 60, data: ["abcdefghijklmnopqrstuvwxyz123456"] },
          ],
        });
      }

      if (type === "TXT" && name === "_dmarc.example.com") {
        return dnsResponse({
          answer: [
            { name, type: "TXT", ttl: 60, data: ["v=DMARC1; p=none; sp=quarantine; rua=mailto:d@example.com; ruf=mailto:f@example.com; adkim=s; aspf=r; pct=50"] },
          ],
        });
      }

      return dnsResponse();
    },
  });

  const spf = result.diagnostics.find((diagnostic) => diagnostic.id === "spf");
  const dkim = result.diagnostics.find((diagnostic) => diagnostic.id === "dkim");
  const dmarc = result.diagnostics.find((diagnostic) => diagnostic.id === "dmarc");

  assert.ok(spf);
  assert.equal(spf.include.length, 11);
  assert.equal(Array.isArray(spf.mechanismDetails), true);
  assert.equal(spf.mechanismDetails[0].mechanism, "include");
  assert.equal(spf.mechanismDetails[0].value, "spf0.example.com");
  assert.equal(spf.mechanismDetails.at(-1).mechanism, "all");
  assert.equal(spf.mechanismDetails.at(-1).result, "pass");
  assert.equal(spf.redirect, "redirect=spf.example.com");
  assert.equal(spf.all, "+all");
  assert.equal(dkim.emptyPublicKey, true);
  assert.equal(dmarc.name, "_dmarc.example.com");
  assert.equal(dmarc.p, "none");
  assert.equal(dmarc.pct, "50");
  assert.equal(result.diagnostics.some((diagnostic) => diagnostic.id === "microsoft_365_verification"), true);
  assert.equal(result.diagnostics.some((diagnostic) => diagnostic.id === "google_verification"), true);
  assert.equal(result.diagnostics.some((diagnostic) => diagnostic.id === "acme_challenge"), true);
  assert.equal(result.warnings.some((warning) => warning.includes("Multiple SPF records")), true);
  assert.equal(result.warnings.some((warning) => warning.includes("more than 10")), true);
  assert.equal(result.warnings.some((warning) => warning.includes("deprecated ptr")), true);
  assert.equal(result.warnings.some((warning) => warning.includes("+all")), true);
  assert.equal(result.warnings.some((warning) => warning.includes("p=none")), true);
});

test("TXT diagnostics flag missing all and invalid-looking SPF mechanisms", async () => {
  resetDnsCheckState();
  const result = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "TXT",
    query: "spf-invalid.example.com",
    dnssec: false,
  }, {
    clientIp: "203.0.113.36",
    queryDns: async (_server, name, type) => {
      if (type === "TXT" && name === "spf-invalid.example.com") {
        return dnsResponse({
          answer: [
            { name, type: "TXT", ttl: 86400, data: ["v=spf1 include:spf.example.com nonsense:value"] },
          ],
        });
      }

      return dnsResponse();
    },
  });

  const spf = result.diagnostics.find((diagnostic) => diagnostic.id === "spf");

  assert.ok(spf);
  assert.equal(spf.mechanismDetails[0].valid, true);
  assert.equal(spf.mechanismDetails[1].valid, false);
  assert.equal(result.warnings.some((warning) => warning.includes("does not include an all mechanism")), true);
  assert.equal(result.warnings.some((warning) => warning.includes("invalid-looking")), true);
});

test("backend always returns the full structured DNS result", async () => {
  resetDnsCheckState();
  const result = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "example.com",
    display: "simple",
    dnssec: false,
  }, {
    clientIp: "203.0.113.40",
    queryDns: async () => dnsResponse({
      answer: [{ name: "example.com", type: "A", ttl: 60, data: "93.184.216.34" }],
      authority: [{ name: "example.com", type: "NS", ttl: 60, data: "ns1.example.com" }],
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(result.mode, "single");
  assert.equal(result.responseCode, "NOERROR");
  assert.equal(Array.isArray(result.records), true);
  assert.equal(Array.isArray(result.answer), true);
  assert.equal(Array.isArray(result.authority), true);
  assert.equal(Array.isArray(result.additional), true);
  assert.equal(Array.isArray(result.diagnostics), true);
  assert.equal(Array.isArray(result.warnings), true);
  assert.equal(typeof result.dnssec, "object");
  assert.equal(typeof result.raw, "object");
  assert.equal(typeof result.cache, "object");
});

test("omitted DNS response sections normalize to empty arrays", async () => {
  resetDnsCheckState();
  const result = await checkDns({
    mode: "single",
    resolverId: "cloudflare",
    recordType: "A",
    query: "missing-sections.example.com",
    dnssec: false,
  }, {
    clientIp: "203.0.113.41",
    queryDns: async () => ({
      id: 1,
      rcodeName: "NOERROR",
      flags: { ad: false },
      answer: [{ name: "missing-sections.example.com", type: "A", ttl: 60, data: "93.184.216.34" }],
    }),
  });

  assert.equal(result.ok, true);
  assert.equal(Array.isArray(result.records), true);
  assert.equal(Array.isArray(result.answer), true);
  assert.deepEqual(result.authority, []);
  assert.deepEqual(result.additional, []);
  assert.deepEqual(result.raw.question, []);
});

function dnsResponse({ answer = [], authority = [], additional = [], rcodeName = "NOERROR", flags = {} } = {}) {
  return {
    id: 1,
    rcode: rcodeName === "NOERROR" ? 0 : 3,
    rcodeName,
    flags: {
      qr: true,
      aa: false,
      tc: false,
      rd: true,
      ra: true,
      ad: false,
      cd: false,
      ...flags,
    },
    question: [],
    answer: answer.map(withDefaults),
    authority: authority.map(withDefaults),
    additional: additional.map(withDefaults),
  };
}

function withDefaults(record) {
  return {
    class: 1,
    ttl: 60,
    ...record,
  };
}

// Exercise the production transport, fallback, diagnostics and cache path without
// opening sockets or replacing the parser with pre-parsed results.
function udpHarness(t, { sendError, closeError } = {}) {
  resetDnsCheckState();
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const sockets = [];
  t.mock.method(dgram, "createSocket", (family) => {
    const socket = new EventEmitter();
    socket.family = family;
    socket.closeCount = 0;
    socket.send = (packet, port, server, callback) => {
      Object.assign(socket, { packet, port, server, sendCallback: callback });
      assert.equal(port, 53);
      if (sendError) {
        throw sendError;
      }
      callback(null);
    };
    socket.close = () => {
      socket.closeCount += 1;
      if (closeError) {
        throw closeError;
      }
      // Simulate an error while asynchronous close is still in progress.
      socket.emit("error", new Error("late transport error"));
      socket.emit("close");
    };
    sockets.push(socket);
    return socket;
  });
  const payload = {
    mode: "single", resolverId: "cloudflare", recordType: "A",
    query: "example.com", dnssec: false,
  };
  return {
    sockets,
    start: (overrides = {}) => checkDns({ ...payload, ...overrides }),
    reply: (socket, packet = wireResponse(socket), remote = {}) => socket.emit("message", packet, {
      address: socket.server, port: 53, ...remote,
    }),
  };
}

function wireResponse(socket, { flags = 0x8180, answer = true } = {}) {
  const packet = Buffer.from(socket.packet);
  packet.writeUInt16BE(flags, 2);
  if (!answer) {
    return packet;
  }
  packet.writeUInt16BE(1, 6);
  // Owner points to the question, A/IN, TTL=60, RDLENGTH=4.
  return Buffer.concat([packet, Buffer.from([
    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34,
  ])]);
}

function assertUdpClosed(socket) {
  assert.equal(socket.closeCount, 1);
  assert.equal(socket.listenerCount("message"), 0);
  assert.equal(socket.listenerCount("error"), 0);
  assert.equal(socket.listenerCount("close"), 0);
}

test("UDP accepts matching wire response and caches only its parsed records", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  const socket = h.sockets[0];
  assert.equal(socket.family, "udp4");
  h.reply(socket);
  const result = await pending;
  assert.equal(result.ok, true);
  assert.equal(result.records[0].address, "93.184.216.34");
  assert.equal(result.raw.id, socket.packet.readUInt16BE(0));
  assertUdpClosed(socket);
  t.mock.timers.tick(3000);
  socket.sendCallback(new Error("late send callback"));
  assertUdpClosed(socket);
  const cached = await h.start();
  assert.equal(cached.cache.fromCache, true);
  assert.deepEqual(cached.records, result.records);
  assert.equal(h.sockets.length, 1);
});

const invalidUdpPackets = [
  ["incorrect IPv4 source", (_packet, _socket, remote) => { remote.address = "1.0.0.1"; }],
  ["incorrect source port", (_packet, _socket, remote) => { remote.port = 5353; }],
  ["incorrect transaction ID", (packet) => { packet.writeUInt16BE(packet.readUInt16BE(0) ^ 1, 0); }],
  ["QR=0", (packet) => { packet.writeUInt16BE(0x0180, 2); }],
  ["nonstandard opcode", (packet) => { packet.writeUInt16BE(0x8980, 2); }],
  ["incorrect QNAME", (packet) => { packet[13] = 120; }],
  ["incorrect QTYPE", (packet, socket) => { packet.writeUInt16BE(28, socket.packet.length - 4); }],
  ["incorrect QCLASS", (packet, socket) => { packet.writeUInt16BE(3, socket.packet.length - 2); }],
  ["missing question", (packet) => { packet.writeUInt16BE(0, 4); }],
  ["multiple questions", (packet) => { packet.writeUInt16BE(2, 4); }],
  ["short header", (packet) => packet.subarray(0, 11)],
  ["truncated QNAME", (packet) => packet.subarray(0, 16)],
  ["truncated QTYPE", (packet, socket) => packet.subarray(0, socket.packet.length - 3)],
  ["truncated QCLASS", (packet, socket) => packet.subarray(0, socket.packet.length - 1)],
  ["unterminated QNAME", (packet, socket) => { packet[socket.packet.length - 5] = 1; }],
  ["reserved label encoding", (packet) => { packet[12] = 0x47; }],
  ["oversized label encoding", (packet) => { packet[12] = 0x87; }],
  ["self-referencing question pointer", (packet) => { packet[12] = 0xc0; packet[13] = 12; }],
  ["out-of-range question pointer", (packet) => { packet[12] = 0xff; packet[13] = 0xff; }],
  ["short question pointer", (packet) => Buffer.concat([packet.subarray(0, 12), Buffer.from([0xc0])])],
  ["pointer into header", (packet) => { packet[12] = 0xc0; packet[13] = 4; }],
  ["forward question pointer", (packet) => { packet[12] = 0xc0; packet[13] = 14; }],
  ["high-bit ASCII alias", (packet) => { packet[13] |= 0x80; }],
  ["embedded-dot label alias", (packet, socket) => Buffer.concat([
    packet.subarray(0, 12), Buffer.from([11]), Buffer.from("example.com"),
    Buffer.from([0]), packet.subarray(socket.packet.length - 4),
  ])],
  ["answer pointer cycle", (packet, socket) => {
    packet[socket.packet.length + 1] = socket.packet.length;
  }],
  ["truncated answer data", (packet) => packet.subarray(0, packet.length - 1)],
  ["truncated answer header", (packet, socket) => packet.subarray(0, socket.packet.length + 3)],
];

for (const [description, corrupt] of invalidUdpPackets) {
  test(`UDP ignores ${description}, then accepts a valid packet without fallback`, async (t) => {
    const h = udpHarness(t);
    const pending = h.start();
    const socket = h.sockets[0];
    let packet = wireResponse(socket);
    const remote = {};
    packet = corrupt(packet, socket, remote) || packet;
    h.reply(socket, packet, remote);
    assert.equal(socket.closeCount, 0, "invalid packet must not settle the query");
    assert.equal(socket.listenerCount("message"), 1);
    assert.equal(h.sockets.length, 1, "invalid packet must not start fallback");
    t.mock.timers.tick(2999);
    h.reply(socket);
    const result = await pending;
    assert.equal(result.records[0].address, "93.184.216.34");
    assert.equal(h.sockets.length, 1);
    assertUdpClosed(socket);
    const cached = await h.start();
    assert.equal(cached.cache.fromCache, true);
    assert.deepEqual(cached.records, result.records);
  });
}

test("UDP repeated mismatches retain each original 3-second deadline and timeout normally", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  for (const endpoint of ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]) {
    const socket = h.sockets.at(-1);
    assert.equal(socket.server, endpoint);
    const bad = wireResponse(socket);
    bad.writeUInt16BE(bad.readUInt16BE(0) ^ 1, 0);
    for (let index = 0; index < 3; index += 1) {
      t.mock.timers.tick(999);
      h.reply(socket, bad);
      assert.equal(socket.closeCount, 0);
    }
    t.mock.timers.tick(3);
    assertUdpClosed(socket);
    // Allow existing provider fallback to advance, without any real waits.
    await new Promise(setImmediate);
  }
  const result = await pending;
  assert.equal(result.ok, false);
  assert.equal(result.status, "timeout");
  assert.deepEqual(result.records, []);
  assert.deepEqual(result.raw, { error: "timeout" });
  assert.equal(h.sockets.length, 4);
});

test("UDP matching NXDOMAIN keeps negative-response diagnostics", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  h.reply(h.sockets[0], wireResponse(h.sockets[0], { flags: 0x8183, answer: false }));
  const result = await pending;
  assert.equal(result.responseCode, "NXDOMAIN");
  assert.equal(result.status, "nxdomain");
  assert.deepEqual(result.records, []);
  assert.equal(h.sockets.length, 1);
  assertUdpClosed(h.sockets[0]);
});

test("UDP QNAME comparison permits ASCII case changes", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  const socket = h.sockets[0];
  const packet = wireResponse(socket);
  Buffer.from("EXAMPLE").copy(packet, 13);
  Buffer.from("COM").copy(packet, 21);
  h.reply(socket, packet);
  assert.equal((await pending).status, "ok");
  assertUdpClosed(socket);
});

test("UDP source comparison accepts equivalent IPv6 and ignores a different IPv6 endpoint", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  for (let index = 0; index < 2; index += 1) {
    h.sockets[index].emit("error", Object.assign(new Error("offline"), { code: "ENETUNREACH" }));
    assertUdpClosed(h.sockets[index]);
    await new Promise(setImmediate);
  }
  const socket = h.sockets[2];
  assert.equal(socket.family, "udp6");
  h.reply(socket, wireResponse(socket), { address: "2606:4700:4700::1001" });
  h.reply(socket, wireResponse(socket), { address: "1.1.1.1" });
  assert.equal(socket.closeCount, 0);
  h.reply(socket, wireResponse(socket), { address: "2606:4700:4700:0000:0000:0000:0000:1111" });
  assert.equal((await pending).status, "ok");
  assertUdpClosed(socket);
});

test("UDP socket errors release timers and listeners and retain sanitized failure", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  const socket = h.sockets[0];
  socket.emit("error", new Error("private socket details"));
  const result = await pending;
  assert.equal(result.status, "resolver-error");
  assert.deepEqual(result.raw, { error: "resolver-error" });
  assert.deepEqual(result.warnings, ["The resolver returned an error."]);
  assertUdpClosed(socket);
  t.mock.timers.tick(3000);
  socket.sendCallback(new Error("late callback"));
  assertUdpClosed(socket);
});

test("UDP send callback errors clean up and do not leak transport details", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  const socket = h.sockets[0];
  socket.sendCallback(new Error("private send details"));
  assert.equal((await pending).status, "resolver-error");
  assertUdpClosed(socket);
});

test("UDP synchronous send failure cleans up even when the unbound socket cannot close", async (t) => {
  const h = udpHarness(t, {
    sendError: new Error("private send details"),
    closeError: Object.assign(new Error("not running"), { code: "ERR_SOCKET_DGRAM_NOT_RUNNING" }),
  });
  const result = await h.start();
  assert.equal(result.status, "resolver-error");
  assert.deepEqual(result.warnings, ["The resolver returned an error."]);
  assertUdpClosed(h.sockets[0]);
  t.mock.timers.tick(3000);
  assertUdpClosed(h.sockets[0]);
});

test("UDP preserves normalized IDN, PTR and SRV question identities", async (t) => {
  const h = udpHarness(t);
  for (const input of [
    { query: "bücher.example", recordType: "A" },
    { query: "8.8.8.8", recordType: "PTR" },
    { query: "_sip._tcp.example.com", recordType: "SRV" },
  ]) {
    const pending = h.start(input);
    const socket = h.sockets.at(-1);
    h.reply(socket, wireResponse(socket, { answer: false }));
    const result = await pending;
    const expected = normalizeDnsCheckRequest({ mode: "single", resolverId: "cloudflare", ...input });
    assert.equal(result.raw.question[0].name, expected.query.queryName);
    assert.equal(result.raw.question[0].type, input.recordType);
    assertUdpClosed(socket);
  }
});

test("TXT owner labels allow underscores without relaxing hostnames or public-name limits", () => {
  const normalize = (query, recordType = "TXT") => normalizeDnsCheckRequest({ mode: "single", resolverId: "cloudflare", recordType, query });
  for (const query of ["example.com", "_dmarc.example.com", "selector._domainkey.example.com", "_acme-challenge.example.com", "selector_name._domainkey.example.com", "_dmarc.bücher.example", "_".repeat(63) + ".example.com"]) {
    assert.ok(normalize(query).query.queryName);
  }
  assert.equal(normalize("_dmarc.BÜCHER.example.").query.queryName, "_dmarc.xn--bcher-kva.example");
  const maximum = [63, 63, 63, 61].map((length) => "a".repeat(length)).join(".");
  assert.equal(normalize(maximum).query.queryName.length, 253);
  assert.throws(() => normalize("é".repeat(60) + ".example.com"), DnsCheckError);
  for (const query of [maximum + "a", "a".repeat(64) + ".example.com", "_bad..example.com", "_bad-.example.com", "-bad.example.com", "bad!name.example.com", "bad name.example.com", "bad\tname.example.com", "bad\u0000.example.com", "\ud800.example.com", "\u200d.example.com", "_dmarc.local", "_dmarc.internal", "_dmarc.lan", "_dmarc.home", "_dmarc.home.arpa", "_dmarc.localhost", "8.8.8.8"]) {
    assert.throws(() => normalize(query), DnsCheckError, query);
  }
  for (const type of ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "CAA"]) {
    assert.throws(() => normalize("selector_name._domainkey.example.com", type), DnsCheckError);
  }
});

test("TXT helper owners query the intended name without duplicate DMARC prefixes", async () => {
  for (const query of ["example.com", "_dmarc.example.com", "selector_name._domainkey.example.com", "_acme-challenge.example.com"]) {
    resetDnsCheckState();
    const queries = [];
    const result = await checkDns({ mode: "single", resolverId: "cloudflare", recordType: "TXT", query, dnssec: false }, {
      queryDns: async (_server, name, type) => {
        queries.push(name);
        return dnsResponse({ answer: [{ name, type, data: [name.startsWith("_dmarc.") ? "v=DMARC1; p=reject" : "offline TXT value"] }] });
      },
    });
    assert.equal(result.ok, true);
    assert.equal(result.query.queryName, query);
    assert.deepEqual(queries, query === "_dmarc.example.com" ? [query] : [query, "_dmarc.example.com"]);
    assert.equal(result.diagnostics.find((item) => item.id === "dmarc").name, "_dmarc.example.com");
  }
});

const wireClassifications = [
  [0x8180, true, "NOERROR", "ok", true],
  [0x8180, false, "NOERROR", "no-record", true],
  [0x8183, false, "NXDOMAIN", "nxdomain", true],
  [0x8182, false, "SERVFAIL", "servfail", false],
  [0x8185, false, "REFUSED", "refused", false],
  [0x8181, true, "FORMERR", "formerr", false],
  [0x8184, false, "NOTIMP", "notimp", false],
  [0x818f, true, "RCODE_15", "rcode-error", false],
  [0x8380, false, "NOERROR", "incomplete", false],
  [0x8380, true, "NOERROR", "incomplete", false],
  [0x8383, false, "NXDOMAIN", "incomplete", false],
  [0x8382, true, "SERVFAIL", "incomplete", false],
];

for (const [flags, answer, responseCode, status, ok] of wireClassifications) {
  test(`UDP classifies ${responseCode} TC=${Boolean(flags & 0x200)} answers=${answer} as ${status}, with correct cache policy`, async (t) => {
    const h = udpHarness(t);
    const pending = h.start();
    h.reply(h.sockets[0], wireResponse(h.sockets[0], { flags, answer }));
    const result = await pending;
    assert.equal(result.ok, ok);
    assert.equal(result.status, status);
    assert.equal(result.responseCode, responseCode);
    assert.equal(result.raw.rcode, flags & 15);
    assert.equal(result.raw.flags.tc, Boolean(flags & 0x200));
    assert.equal(result.records.length, answer ? 1 : 0);
    assert.equal(h.sockets.length, 1, "RCODE/TC replies do not trigger transport fallback");
    assertUdpClosed(h.sockets[0]);
    if (!ok) assert.ok(result.warnings.length);
    if (status === "incomplete") {
      assert.match(result.warnings.join(" "), /partial/);
      assert.ok(!result.warnings.some((warning) => /DNSSEC validation failure|sinkholes/.test(warning)));
      assert.deepEqual(result.diagnostics, []);
    }
    const retry = h.start();
    if (!ok) h.reply(h.sockets[1]);
    assert.equal((await retry).cache.fromCache, ok);
  });
}

test("UDP preserves EDNS extended error RCODE rather than classifying low bits as NOERROR", async (t) => {
  const h = udpHarness(t);
  const pending = h.start();
  const packet = wireResponse(h.sockets[0], { answer: false });
  packet.writeUInt16BE(1, 10);
  h.reply(h.sockets[0], Buffer.concat([packet, Buffer.from([0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0])]));
  const result = await pending;
  assert.equal(result.raw.rcode, 16);
  assert.equal(result.responseCode, "RCODE_16");
  assert.equal(result.status, "rcode-error");
  assert.equal(result.ok, false);
});

test("UDP rejects unsafe partial TC packets and malformed RDATA before accepting a complete reply", async (t) => {
  const h = udpHarness(t);
  for (const [type, data] of [[1, [1, 2, 3]], [16, []], [16, [5, 97]], [5, [0xc0]], [15, [0]], [33, [0]], [6, [0]], [257, [0, 5, 97]]]) {
    const pending = h.start({ query: `bad-${type}-${data.length}.example.com` });
    const socket = h.sockets.at(-1);
    const question = wireResponse(socket, { answer: false, flags: 0x8380 });
    question.writeUInt16BE(1, 6);
    const header = Buffer.from([0xc0, 0x0c, 0, 0, 0, 1, 0, 0, 0, 60, 0, data.length]);
    header.writeUInt16BE(type, 2);
    h.reply(socket, Buffer.concat([question, header, Buffer.from(data)]));
    assert.equal(socket.closeCount, 0);
    h.reply(socket);
    assert.equal((await pending).status, "ok");
    assertUdpClosed(socket);
  }
});

test("complete SERVFAIL preserves possible DNSSEC status but TC takes precedence", async () => {
  for (const tc of [false, true]) {
    resetDnsCheckState();
    let queries = 0;
    const result = await checkDns({ mode: "single", resolverId: "cloudflare", query: "example.com", recordType: "A", dnssec: true }, {
      queryDns: async () => { queries++; return dnsResponse({ rcodeName: "SERVFAIL", flags: { tc } }); },
    });
    assert.equal(result.status, tc ? "incomplete" : "possible-dnssec-failure");
    assert.equal(queries, 1, "failed primary replies must not drive enrichment");
  }
});

test("burst mixed outcomes never infer filtering, absence or different answers from failed providers", async () => {
  for (const errorStatus of ["SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "RCODE_15", "TC", "TIMEOUT"]) {
    resetDnsCheckState();
    const result = await checkDns({ mode: "burst", recordType: "A", query: "example.com" }, { queryDns: async (server, name) => {
      if (server === "1.1.1.1") {
        if (errorStatus === "TIMEOUT") throw new Error("offline transport");
        return dnsResponse({ rcodeName: errorStatus === "TC" ? "NOERROR" : errorStatus, flags: { tc: errorStatus === "TC" }, answer: [{ name, type: "A", data: "0.0.0.0" }] });
      }
      return dnsResponse({ answer: [{ name, type: "A", data: server === "8.8.8.8" ? "8.8.8.8" : "93.184.216.34" }] });
    } });
    assert.equal(result.ok, false);
    assert.equal(result.status, "partial-failure");
    assert.equal(result.providers.length, 10);
    assert.equal(result.providers.filter((provider) => provider.ok).length, 9);
    assert.match(result.warnings.join(" "), /No full-provider comparison/);
    assert.ok(!result.warnings.includes("Providers returned different answers."));
  }
});

test("burst all-negative/all-failed and complete differing answers retain accurate statuses", async () => {
  for (const [rcodeName, tc, expected] of [["NXDOMAIN", false, "nxdomain"], ["NOERROR", false, "no-record"], ["FORMERR", false, "resolver-error"], ["NOERROR", true, "incomplete"]]) {
    resetDnsCheckState();
    const result = await checkDns({ mode: "burst", query: "example.com", recordType: "A" }, { queryDns: async () => dnsResponse({ rcodeName, flags: { tc } }) });
    assert.equal(result.status, expected);
    assert.equal(result.ok, ["nxdomain", "no-record"].includes(expected));
  }
  resetDnsCheckState();
  const result = await checkDns({ mode: "burst", query: "example.com", recordType: "A" }, { queryDns: async (server, name) => dnsResponse({ answer: [{ name, type: "A", data: server === "1.1.1.1" ? "8.8.8.8" : "93.184.216.34" }] }) });
  assert.equal(result.status, "different-answer");
  assert.equal(result.ok, true);
  resetDnsCheckState();
  const negatives = await checkDns({ mode: "burst", query: "example.com", recordType: "A" }, {
    queryDns: async (server) => dnsResponse({ rcodeName: server === "1.1.1.1" ? "NXDOMAIN" : "NOERROR" }),
  });
  assert.equal(negatives.status, "different-answer", "NXDOMAIN and NODATA are distinct complete negative answers");
  assert.equal(negatives.ok, true);
});

test("incomplete optional TXT/DNSSEC replies do not establish record absence and are not cached", async () => {
  for (const mode of ["single", "burst"]) {
    resetDnsCheckState();
    let calls = 0;
    const payload = { mode, ...(mode === "single" ? { resolverId: "cloudflare" } : {}), recordType: "TXT", query: "example.com", dnssec: true };
    const queryDns = async (_server, name, type) => {
      calls++;
      return name === "example.com" && type === "TXT" ? dnsResponse({ answer: [{ name, type, data: ["v=spf1 -all"] }] }) : dnsResponse({ flags: { tc: true } });
    };
    const result = await checkDns(payload, { queryDns });
    for (const provider of result.providers || [result]) {
      assert.ok(provider.diagnostics.some((item) => item.id === "optional_diagnostics_incomplete"));
      assert.ok(!provider.warnings.some((warning) => warning.includes("No DMARC")));
      assert.ok(!provider.diagnostics.some((item) => item.id === "dnssec_deep_checks"));
    }
    const before = calls;
    assert.equal((await checkDns(payload, { queryDns })).cache.fromCache, false);
    assert.ok(calls > before);
  }
});
