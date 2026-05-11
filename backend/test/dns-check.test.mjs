import assert from "node:assert/strict";
import test from "node:test";
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
