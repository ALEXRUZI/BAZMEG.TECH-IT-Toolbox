import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import test from "node:test";
import {
  checkHttpHeader,
  HTTP_HEADER_CACHE_TTL_SECONDS,
  HTTP_PORTS,
  HTTPS_PORTS,
  HttpHeaderCheckError,
  isBlockedPublicAddress,
  normalizeHttpHeaderCheckRequest,
  requestHeadersAddress,
  resetHttpHeaderCheckState,
} from "../src/tools/http-header-check.mjs";

test("accepts and normalizes public website inputs", () => {
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "example.com" }).cleanHost, "example.com");
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "https://example.com/path?x=1" }).cleanHost, "example.com");
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "HTTP://EXAMPLE.COM/" }).cleanHost, "example.com");
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "https://www.example.com///" }).cleanHost, "www.example.com");
});

test("rejects unsupported schemes", () => {
  for (const target of ["file://example.com", "ftp://example.com", "gopher://example.com", "ssh://example.com"]) {
    assert.throws(
      () => normalizeHttpHeaderCheckRequest({ target }),
      { code: "UNSUPPORTED_PROTOCOL" },
    );
  }
});

test("rejects IPv4 literals", () => {
  for (const target of ["1.1.1.1", "127.0.0.1", "192.168.1.1", "169.254.169.254"]) {
    assert.throws(
      () => normalizeHttpHeaderCheckRequest({ target }),
      { code: "IP_NOT_ALLOWED" },
    );
  }
});

test("rejects IPv6 literals", () => {
  for (const target of ["::1", "[::1]", "2606:4700:4700::1111"]) {
    assert.throws(
      () => normalizeHttpHeaderCheckRequest({ target }),
      { code: "IP_NOT_ALLOWED" },
    );
  }
});

test("rejects local and internal hostnames", () => {
  for (const target of ["localhost", "nas", "router.local", "server01.internal"]) {
    assert.throws(
      () => normalizeHttpHeaderCheckRequest({ target }),
      { code: "LOCAL_HOSTNAME_NOT_ALLOWED" },
    );
  }
});

test("rejects DNS results resolving to private, link-local, metadata, or reserved addresses", async () => {
  resetHttpHeaderCheckState();

  for (const address of ["10.0.0.8", "169.254.169.254", "192.168.1.20", "fe80::1", "2001:db8::1"]) {
    await assert.rejects(
      () => checkHttpHeader({ target: `blocked-${address.replace(/[:.]/g, "-")}.example.com` }, {
        resolveAddresses: fakeResolver({ default: [address] }),
        requestUrl: okResponse,
      }),
      { code: "BLOCKED_TARGET" },
    );
  }

  assert.equal(isBlockedPublicAddress("93.184.216.34"), false);
  assert.equal(isBlockedPublicAddress("169.254.169.254"), true);
});

test("revalidates redirect target and blocks unsafe redirect locations", async () => {
  const unsafeLocations = [
    "http://localhost/",
    "http://127.0.0.1/",
    "http://169.254.169.254/",
    "http://192.168.1.1/",
    "file://example.com/path",
  ];

  for (const location of unsafeLocations) {
    resetHttpHeaderCheckState();
    const result = await checkHttpHeader({ target: "example.com" }, {
      resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
      requestUrl: async () => redirectResponse(location),
    });

    assert.equal(result.ok, false);
    assert.equal(result.checks[0].findings[0].code, "BLOCKED_REDIRECT");
    assert.match(result.checks[0].chainDisplay, /--> X$/);
  }
});

test("revalidates redirect DNS results and blocks private redirect resolution", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com" }, {
    resolveAddresses: fakeResolver({
      "example.com": ["93.184.216.34"],
      "next.example.com": ["10.0.0.1"],
    }),
    requestUrl: async (url) => {
      if (url.hostname === "example.com") {
        return redirectResponse("https://next.example.com");
      }

      return okResponse();
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.checks[0].findings[0].code, "BLOCKED_REDIRECT");
  assert.equal(result.checks[0].blockedRedirect.from, "https://next.example.com");
});

test("max 2 redirects produces chain ending in X and TOO_MANY_REDIRECTS finding", async () => {
  resetHttpHeaderCheckState();
  const locations = new Map([
    ["example.com", "https://example2.com"],
    ["example2.com", "https://example3.com"],
    ["example3.com", "https://example4.com"],
  ]);
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "auto" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async (url) => redirectResponse(locations.get(url.hostname)),
  });

  assert.equal(result.ok, false);
  assert.equal(result.checks[0].redirectsFollowed, 2);
  assert.equal(result.checks[0].chainDisplay, "http://example.com --> https://example2.com --> https://example3.com --> X");
  assert.deepEqual(result.checks[0].redirects, [
    {
      from: "http://example.com",
      to: "https://example2.com",
      status: 301,
      statusText: "Moved Permanently",
      location: "https://example2.com",
    },
    {
      from: "https://example2.com",
      to: "https://example3.com",
      status: 301,
      statusText: "Moved Permanently",
      location: "https://example3.com",
    },
    {
      from: "https://example3.com",
      to: "X",
      status: 301,
      statusText: "Moved Permanently",
      location: "https://example4.com",
    },
  ]);
  assert.equal(result.checks[0].findings[0].code, "TOO_MANY_REDIRECTS");
});

test("redirect response includes structured hop status codes", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "auto" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async (url) => {
      if (url.hostname === "example.com") {
        return redirectResponse("https://example2.com", 301, "Moved Permanently");
      }

      if (url.hostname === "example2.com") {
        return redirectResponse("https://example3.com", 302, "Found");
      }

      return okResponse();
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.checks[0].chainDisplay, "http://example.com --> https://example2.com --> https://example3.com");
  assert.deepEqual(result.checks[0].redirects, [
    {
      from: "http://example.com",
      to: "https://example2.com",
      status: 301,
      statusText: "Moved Permanently",
      location: "https://example2.com",
    },
    {
      from: "https://example2.com",
      to: "https://example3.com",
      status: 302,
      statusText: "Found",
      location: "https://example3.com",
    },
  ]);
});

test("protocol modes enforce standard and dropdown-only ports", async () => {
  assert.deepEqual(HTTP_PORTS, [80, 8000, 8008, 8080, 8081, 8888]);
  assert.deepEqual(HTTPS_PORTS, [443, 4443, 8443, 8444, 9443, 10443]);
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "auto", port: 8443 }).port, null);
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "both", port: 8443 }).port, null);
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "https" }).port, 443);
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "https", port: 8443 }).port, 8443);
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "http" }).port, 80);
  assert.equal(normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "http", port: 8080 }).port, 8080);
  assert.throws(() => normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "https", port: 8080 }), { code: "INVALID_PORT" });
  assert.throws(() => normalizeHttpHeaderCheckRequest({ target: "example.com", protocolMode: "http", port: 443 }), { code: "INVALID_PORT" });
  assert.throws(() => normalizeHttpHeaderCheckRequest({ target: "https://example.com:8443" }), { code: "INVALID_PORT" });

  resetHttpHeaderCheckState();
  const seen = [];
  await checkHttpHeader({ target: "example.com", protocolMode: "auto", port: 8443 }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async (url) => {
      seen.push([url.protocol, url.hostname, url.port || "80"]);
      return okResponse();
    },
  });
  assert.deepEqual(seen, [["http:", "example.com", "80"]]);

  resetHttpHeaderCheckState();
  const bothSeen = [];
  const both = await checkHttpHeader({ target: "example.com", protocolMode: "both", port: 8443 }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async (url) => {
      bothSeen.push([url.protocol, url.port || (url.protocol === "https:" ? "443" : "80")]);
      return okResponse();
    },
  });
  assert.equal(both.budget.tokensConsumed, 2);
  assert.deepEqual(bothSeen, [["http:", "80"], ["https:", "443"]]);

  resetHttpHeaderCheckState();
  const httpsSeen = [];
  await checkHttpHeader({ target: "example.com", protocolMode: "https" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async (url) => {
      httpsSeen.push([url.protocol, url.port || "443"]);
      return okResponse();
    },
  });
  assert.deepEqual(httpsSeen, [["https:", "443"]]);
});

test("cache consumes zero tokens and both mode reuses individual protocol checks", async () => {
  resetHttpHeaderCheckState();
  let nowMs = 1_000_000;
  let requestCount = 0;
  const options = {
    now: () => nowMs,
    clientIp: "203.0.113.50",
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async () => {
      requestCount += 1;
      return okResponse();
    },
  };

  const first = await checkHttpHeader({ target: "example.com", protocolMode: "http" }, options);
  assert.equal(first.checks[0].cacheTtlSeconds, HTTP_HEADER_CACHE_TTL_SECONDS);
  assert.equal(first.checks[0].cacheAgeSeconds, 0);
  assert.equal(first.checks[0].cacheExpiresInSeconds, HTTP_HEADER_CACHE_TTL_SECONDS);

  nowMs += 12_000;
  const second = await checkHttpHeader({ target: "example.com", protocolMode: "http" }, options);

  assert.equal(first.budget.tokensConsumed, 1);
  assert.equal(second.budget.tokensConsumed, 0);
  assert.equal(second.budget.cachedChecks, 1);
  assert.equal(second.checks[0].cached, true);
  assert.equal(second.checks[0].cacheTtlSeconds, HTTP_HEADER_CACHE_TTL_SECONDS);
  assert.equal(second.checks[0].cacheAgeSeconds, 12);
  assert.equal(second.checks[0].cacheExpiresInSeconds, 48);
  assert.equal(requestCount, 1);

  resetHttpHeaderCheckState();
  requestCount = 0;
  const warmHttp = await checkHttpHeader({ target: "example.com", protocolMode: "http" }, options);
  const both = await checkHttpHeader({ target: "example.com", protocolMode: "both" }, options);
  const bothCached = await checkHttpHeader({ target: "example.com", protocolMode: "both" }, options);

  assert.equal(warmHttp.budget.tokensConsumed, 1);
  assert.equal(both.budget.tokensConsumed, 1);
  assert.equal(both.budget.cachedChecks, 1);
  assert.equal(bothCached.budget.tokensConsumed, 0);
  assert.equal(bothCached.budget.cachedChecks, 2);
  assert.equal(both.cache.ttlSeconds, HTTP_HEADER_CACHE_TTL_SECONDS);
  assert.equal(HTTP_HEADER_CACHE_TTL_SECONDS, 60);

  nowMs += 61_000;
  const afterTtl = await checkHttpHeader({ target: "example.com", protocolMode: "both" }, options);

  assert.equal(afterTtl.budget.tokensConsumed, 2);
});

test("header analysis reports contextual security, cookie, CORS, and legacy findings", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "https" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async () => ({
      status: 200,
      statusText: "OK",
      headers: [
        { name: "server", value: "nginx" },
        { name: "x-powered-by", value: "Express" },
        { name: "x-xss-protection", value: "1; mode=block" },
        { name: "set-cookie", value: "sid=abc; Path=/" },
        { name: "access-control-allow-origin", value: "*" },
        { name: "access-control-allow-credentials", value: "true" },
      ],
    }),
  });
  const codes = result.checks[0].findings.map((finding) => finding.code);

  assert.equal(codes.includes("MISSING_CSP"), true);
  assert.equal(codes.includes("X_POWERED_BY_EXPOSED"), true);
  assert.equal(codes.includes("SERVER_EXPOSED"), true);
  assert.equal(codes.includes("LEGACY_X_XSS_PROTECTION"), true);
  assert.equal(codes.includes("COOKIE_MISSING_SECURE"), true);
  assert.equal(codes.includes("COOKIE_MISSING_HTTPONLY"), true);
  assert.equal(codes.includes("COOKIE_MISSING_SAMESITE"), true);
  assert.equal(codes.includes("CORS_WILDCARD_WITH_CREDENTIALS"), true);
  assert.equal(codes.includes("MISSING_X_XSS_PROTECTION"), false);
});

test("header analysis reports duplicate Content-Security-Policy headers", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "https" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async () => secureResponse([
      { name: "content-security-policy", value: "default-src 'self'; frame-ancestors 'none'" },
      { name: "content-security-policy", value: "script-src 'self'" },
    ]),
  });
  const finding = result.checks[0].findings.find((entry) => entry.code === "DUPLICATE_CSP_HEADER");

  assert.deepEqual({
    severity: finding?.severity,
    title: finding?.title,
    detail: finding?.detail,
    recommendation: finding?.recommendation,
  }, {
    severity: "warning",
    title: "Multiple Content-Security-Policy headers",
    detail: "Multiple CSP headers were returned. Browsers may enforce all policies, but this is harder to audit and can cause unexpected behavior.",
    recommendation: "Consolidate CSP configuration where possible and verify the effective policy.",
  });
});

test("header analysis reports identical duplicate X-Frame-Options headers", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "https" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async () => secureResponse([
      { name: "x-frame-options", value: "DENY" },
      { name: "x-frame-options", value: "DENY" },
    ]),
  });
  const finding = result.checks[0].findings.find((entry) => entry.code === "DUPLICATE_SECURITY_HEADER");

  assert.deepEqual({
    severity: finding?.severity,
    title: finding?.title,
    detail: finding?.detail,
  }, {
    severity: "info",
    title: "Duplicate security header",
    detail: "The response returns the same security header more than once.",
  });
});

test("header analysis reports CSP values containing private 10/8 addresses", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "https" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async () => secureResponse([
      { name: "content-security-policy", value: "default-src 'self'; frame-ancestors https://10.10.190.243 https://10.10.190.244" },
    ]),
  });
  const finding = result.checks[0].findings.find((entry) => entry.code === "CSP_EXPOSES_PRIVATE_IP");

  assert.deepEqual({
    severity: finding?.severity,
    title: finding?.title,
    detail: finding?.detail,
    recommendation: finding?.recommendation,
  }, {
    severity: "warning",
    title: "CSP exposes private IP address",
    detail: "The Content-Security-Policy references private/internal IP addresses.",
    recommendation: "Avoid exposing internal infrastructure details in public response headers.",
  });
  assert.deepEqual(finding?.metadata, {
    privateIps: ["10.10.190.243", "10.10.190.244"],
    references: [{
      header: "content-security-policy",
      value: "default-src 'self'; frame-ancestors https://10.10.190.243 https://10.10.190.244",
      privateIps: ["10.10.190.243", "10.10.190.244"],
    }],
  });
});

test("header analysis reports CSP values containing private 192.168/16 addresses", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "https" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async () => secureResponse([
      { name: "content-security-policy", value: "default-src 'self'; connect-src https://192.168.1.1:8443" },
    ]),
  });
  const codes = result.checks[0].findings.map((entry) => entry.code);

  assert.equal(codes.includes("CSP_EXPOSES_PRIVATE_IP"), true);
});

test("header analysis does not report private IP exposure for public CSP domains", async () => {
  resetHttpHeaderCheckState();
  const result = await checkHttpHeader({ target: "example.com", protocolMode: "https" }, {
    resolveAddresses: fakeResolver({ default: ["93.184.216.34"] }),
    requestUrl: async () => secureResponse([
      { name: "content-security-policy", value: "default-src 'self'; frame-ancestors https://example.com https://cdn.example.com" },
    ]),
  });
  const codes = result.checks[0].findings.map((entry) => entry.code);

  assert.equal(codes.includes("CSP_EXPOSES_PRIVATE_IP"), false);
});

test("HTTPS request to validated IP uses hostname for SNI, Host, certificate verification, and path", async (t) => {
  const capturedOptions = [];
  const hostnameVerificationCalls = [];
  let responseDestroyed = false;

  t.mock.method(tls, "checkServerIdentity", (hostname, cert) => {
    hostnameVerificationCalls.push({ hostname, cert });
    return undefined;
  });

  t.mock.method(https, "request", (options, callback) => {
    capturedOptions.push(options);
    const request = new EventEmitter();
    request.end = () => {
      queueMicrotask(() => {
        callback({
          statusCode: 204,
          statusMessage: "No Content",
          rawHeaders: ["Server", "unit-test"],
          destroy() {
            responseDestroyed = true;
          },
        });
      });
    };
    request.destroy = (error) => {
      if (error) {
        queueMicrotask(() => request.emit("error", error));
      }
    };
    return request;
  });

  const response = await requestHeadersAddress(new URL("https://www.example.test:8443/path?q=1"), "93.184.216.34", 1000);

  assert.equal(response.status, 204);
  assert.equal(capturedOptions.length, 1);
  assert.equal(capturedOptions[0].host, "93.184.216.34");
  assert.equal(capturedOptions[0].servername, "www.example.test");
  assert.equal(capturedOptions[0].headers.Host, "www.example.test:8443");
  assert.equal(capturedOptions[0].path, "/path?q=1");
  assert.equal(capturedOptions[0].method, "GET");
  assert.notEqual(capturedOptions[0].rejectUnauthorized, false);
  assert.equal(typeof capturedOptions[0].checkServerIdentity, "function");
  capturedOptions[0].checkServerIdentity("93.184.216.34", { subject: { CN: "www.example.test" } });
  assert.deepEqual(hostnameVerificationCalls, [{
    hostname: "www.example.test",
    cert: { subject: { CN: "www.example.test" } },
  }]);
  assert.equal(responseDestroyed, true);
});

test("standard-port Host header uses URL hostname and not the resolved IP", async (t) => {
  const capturedOptions = [];

  t.mock.method(https, "request", (options, callback) => {
    capturedOptions.push(options);
    const request = new EventEmitter();
    request.end = () => {
      queueMicrotask(() => {
        callback({
          statusCode: 200,
          statusMessage: "OK",
          rawHeaders: [],
          destroy() {},
        });
      });
    };
    request.destroy = (error) => {
      if (error) {
        queueMicrotask(() => request.emit("error", error));
      }
    };
    return request;
  });

  await requestHeadersAddress(new URL("https://www.example.test/"), "93.184.216.34", 1000);

  assert.equal(capturedOptions[0].host, "93.184.216.34");
  assert.equal(capturedOptions[0].headers.Host, "www.example.test");
});

test("medirex-style HTTP apex to HTTPS www redirect succeeds with mocked request layer", async () => {
  resetHttpHeaderCheckState();
  const attempts = [];
  const result = await checkHttpHeader({ target: "medirex.sk", protocolMode: "auto" }, {
    resolveAddresses: fakeResolver({
      "medirex.sk": ["93.184.216.34"],
      "www.medirex.sk": ["1.1.1.1"],
    }),
    requestUrl: async (url, options) => {
      attempts.push({
        url: `${url.protocol}//${url.hostname}${url.pathname}`,
        addresses: options.addresses,
      });

      if (url.hostname === "medirex.sk") {
        return redirectResponse("https://www.medirex.sk/");
      }

      return okResponse();
    },
  });

  assert.equal(result.ok, true);
  assert.equal(result.checks[0].finalUrl, "https://www.medirex.sk");
  assert.equal(result.checks[0].chainDisplay, "http://medirex.sk --> https://www.medirex.sk");
  assert.deepEqual(attempts, [
    { url: "http://medirex.sk/", addresses: ["93.184.216.34"] },
    { url: "https://www.medirex.sk/", addresses: ["1.1.1.1"] },
  ]);
});

test("all address attempts fail with classified error, preserved cause, and safe logs", async (t) => {
  resetHttpHeaderCheckState();
  const failures = [
    Object.assign(new Error("socket reset by peer"), { code: "ECONNRESET" }),
    Object.assign(new Error("connect refused"), { code: "ECONNREFUSED" }),
  ];
  const logEntries = [];

  t.mock.method(http, "request", () => {
    const request = new EventEmitter();
    request.end = () => {
      const failure = failures.shift();
      queueMicrotask(() => request.emit("error", failure));
    };
    request.destroy = (error) => {
      if (error) {
        queueMicrotask(() => request.emit("error", error));
      }
    };
    return request;
  });

  await assert.rejects(
    () => checkHttpHeader({ target: "failure.example", protocolMode: "http" }, {
      resolveAddresses: fakeResolver({ "failure.example": ["93.184.216.34", "1.1.1.1"] }),
      logger: {
        warn(entry) {
          logEntries.push(entry);
        },
      },
    }),
    (error) => {
      assert.equal(error.code, "CONNECTION_REFUSED");
      assert.equal(error.safeMessage, "Connection refused by the website.");
      assert.equal(error.cause?.code, "ECONNREFUSED");
      return true;
    },
  );

  assert.equal(logEntries.length, 2);
  assert.deepEqual(logEntries.map((entry) => entry.address), ["93.184.216.34", "1.1.1.1"]);
  assert.deepEqual(logEntries.map((entry) => entry.hostname), ["failure.example", "failure.example"]);
  assert.deepEqual(logEntries.map((entry) => entry.url), ["http://failure.example", "http://failure.example"]);
  assert.deepEqual(logEntries.map((entry) => entry.errorCode), ["ECONNRESET", "ECONNREFUSED"]);
  assert.equal(Object.hasOwn(logEntries[0], "stack"), false);
});

test("request timeout is classified safely", async (t) => {
  resetHttpHeaderCheckState();

  t.mock.method(http, "request", () => {
    const request = new EventEmitter();
    request.end = () => {
      queueMicrotask(() => request.emit("timeout"));
    };
    request.destroy = (error) => {
      if (error) {
        queueMicrotask(() => request.emit("error", error));
      }
    };
    return request;
  });

  await assert.rejects(
    () => checkHttpHeader({ target: "timeout.example", protocolMode: "http" }, {
      resolveAddresses: fakeResolver({ "timeout.example": ["93.184.216.34"] }),
    }),
    (error) => {
      assert.equal(error.code, "REQUEST_TIMEOUT");
      assert.equal(error.safeMessage, "HTTP header request timed out.");
      assert.equal(error.cause?.code, "REQUEST_TIMEOUT");
      return true;
    },
  );
});

test("TLS request failure is classified safely", async (t) => {
  resetHttpHeaderCheckState();

  t.mock.method(https, "request", () => {
    const request = new EventEmitter();
    request.end = () => {
      const error = Object.assign(new Error("certificate subject alt name mismatch"), {
        code: "ERR_TLS_CERT_ALTNAME_INVALID",
      });
      queueMicrotask(() => request.emit("error", error));
    };
    request.destroy = (error) => {
      if (error) {
        queueMicrotask(() => request.emit("error", error));
      }
    };
    return request;
  });

  await assert.rejects(
    () => checkHttpHeader({ target: "tlsfail.example", protocolMode: "https" }, {
      resolveAddresses: fakeResolver({ "tlsfail.example": ["93.184.216.34"] }),
    }),
    (error) => {
      assert.equal(error.code, "TLS_CONNECTION_FAILED");
      assert.equal(error.safeMessage, "TLS connection failed while checking the website.");
      assert.equal(error.cause?.code, "ERR_TLS_CERT_ALTNAME_INVALID");
      return true;
    },
  );
});

function fakeResolver(addressesByHost) {
  return async (host) => {
    const addresses = addressesByHost[host] || addressesByHost.default || ["93.184.216.34"];

    if (addresses.some((address) => isBlockedPublicAddress(address))) {
      throw new HttpHeaderCheckError("BLOCKED_TARGET", "Target resolved to a blocked/private/internal address.");
    }

    return addresses;
  };
}

async function okResponse() {
  return {
    status: 200,
    statusText: "OK",
    headers: [
      { name: "content-type", value: "text/html; charset=UTF-8" },
      { name: "cache-control", value: "max-age=60" },
    ],
  };
}

async function secureResponse(headers = []) {
  const baselineHeaders = [
    { name: "strict-transport-security", value: "max-age=31536000; includeSubDomains" },
    { name: "content-security-policy", value: "default-src 'self'; frame-ancestors 'none'" },
    { name: "x-content-type-options", value: "nosniff" },
    { name: "x-frame-options", value: "DENY" },
    { name: "referrer-policy", value: "no-referrer" },
    { name: "cache-control", value: "max-age=60" },
  ];
  const replacedNames = new Set(headers.map((header) => header.name.toLowerCase()));

  return {
    status: 200,
    statusText: "OK",
    headers: [
      ...baselineHeaders.filter((header) => !replacedNames.has(header.name)),
      ...headers,
    ],
  };
}

function redirectResponse(location, status = 301, statusText = "Moved Permanently") {
  return {
    status,
    statusText,
    headers: [
      { name: "location", value: location },
      { name: "server", value: "test" },
    ],
  };
}
