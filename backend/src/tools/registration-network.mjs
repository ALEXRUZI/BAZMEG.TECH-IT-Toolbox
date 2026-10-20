import https from "node:https";
import net from "node:net";
import { lookup } from "node:dns/promises";
import { isBlockedPublicAddress } from "./http-header-check.mjs";
import { ipNumber, RegistrationError, fail } from "./registration-input.mjs";
import { REGISTRATION_LIMITS as L, acquireRegistrationResource } from "./registration-resources.mjs";

export function validateRegistrationDestination(value, protocol) {
  if (typeof value !== "string" || value.length > 2048 || /[\p{Cc}\p{Cf}\s\\]/u.test(value)) fail("SECURITY_REJECTION", "Unsafe registration destination rejected.");
  let url;
  try { url = new URL(protocol === "whois" && !value.includes("://") ? `whois://${value}` : value); }
  catch { fail("SECURITY_REJECTION", "Invalid registration destination rejected."); }
  if (url.protocol !== (protocol === "whois" ? "whois:" : "https:") || url.username || url.password || url.hash
    || (url.port && url.port !== (protocol === "whois" ? "43" : "443"))
    || (protocol === "whois" && (url.pathname && url.pathname !== "/" || url.search))) fail("SECURITY_REJECTION", "Unsafe registration scheme, credentials, path, or port rejected.");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  // Registry discovery supplies DNS hostnames, not literal endpoints.
  if (net.isIP(host) || host.length > 253 || !host.includes(".") || host.split(".").some((v) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v))
    || /\.(?:local|localhost|lan|home|internal|intranet|corp|localdomain|invalid|test)$/.test(host)) fail("SECURITY_REJECTION", "Unsafe registration hostname rejected.");
  if (protocol === "whois") { url.port = "43"; url.pathname = ""; }
  return url;
}

export function blockedRegistrationAddress(address) {
  if (!net.isIP(address) || isBlockedPublicAddress(address)) return true;
  if (net.isIP(address) === 4) return address.startsWith("192.88.99.");
  // Only ordinary global unicast; exclude mapped, compatible, transition,
  // documentation and special-use ranges conservatively.
  const n = ipNumber(address);
  return (n >> 125n) !== 1n || (n >> 112n) === 0x2002n || (n >> 108n) === 0x3fff0n;
}

export async function resolveRegistrationHost(host, operation, options = {}) {
  operation.assertLive();
  const release = acquireRegistrationResource("dns");
  const work = Promise.resolve().then(() => { operation.assertLive(); return (options.lookup || lookup)(host, { all: true, verbatim: true }); });
  // OS DNS cannot be cancelled: hold this independent slot until it settles.
  work.then(release, release);
  let addresses;
  try { addresses = await operation.wait(() => work, L.dnsMs); }
  catch (error) { if (error instanceof RegistrationError) throw error; fail("TEMPORARY_FAILURE", "Registration destination DNS lookup failed."); }
  if (!Array.isArray(addresses) || !addresses.length || addresses.length > 32) fail("SECURITY_REJECTION", "Invalid registration DNS answer rejected.");
  if (addresses.some((v) => !v || blockedRegistrationAddress(v.address) || v.family !== net.isIP(v.address))) fail("SECURITY_REJECTION", "Blocked or mixed registration DNS destinations rejected.");
  return addresses[0];
}

export async function registrationExchange(destination, protocol, query, operation, options = {}, maxBytes = L.responseBytes) {
  const url = validateRegistrationDestination(destination, protocol);
  operation.exchange();
  const address = await resolveRegistrationHost(url.hostname, operation, options);
  const spec = { url, protocol, query, address, operation, maxBytes };
  // Production transport owns its attempt timer so a timeout destroys the
  // socket before rejecting, rather than racing an outer wait timer.
  const response = options.transport ? await operation.wait(() => options.transport(spec)) : await transport(spec);
  operation.assertLive();
  // Enforce the same bounds for injected transports used by offline tests.
  if (!response || typeof response.text !== "string") fail("MALFORMED_REPLY", "Malformed registration transport reply.");
  if (Buffer.byteLength(response.text) > maxBytes) fail("RESPONSE_TOO_LARGE", "Registration response exceeds the byte limit.");
  if (options.transport) operation.bytes(Buffer.byteLength(response.text));
  return { ...response, source: url.href };
}

export function transport({ url, protocol, query, address, operation, maxBytes }, adapters = {}) {
  const releaseSlot = acquireRegistrationResource("socket");
  let released = false;
  const release = () => { if (!released) { released = true; releaseSlot(); } };
  return new Promise((resolve, reject) => {
    let socket, request, response, done = false, bytes = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(new RegistrationError("UPSTREAM_TIMEOUT", "Registration upstream request timed out.")), L.attemptMs);
    const abort = () => finish(operation.signal.reason);
    const finish = (error, value) => {
      if (done) return; done = true;
      clearTimeout(timer); operation.signal.removeEventListener("abort", abort);
      response?.destroy(); request?.destroy(); socket?.destroy();
      if (error) reject(error); else resolve(value);
    };
    const failed = (error) => {
      if (error?.code === "HPE_HEADER_OVERFLOW") { finish(new RegistrationError("RESPONSE_TOO_LARGE", "Registration response headers exceed the byte limit.")); return; }
      const certificateFailure = typeof error?.code === "string" && (/^(?:CERT_|ERR_TLS_CERT_)/.test(error.code)
        || ["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_GET_ISSUER_CERT", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_VERIFY_LEAF_SIGNATURE"].includes(error.code));
      finish(new RegistrationError(certificateFailure ? "SECURITY_REJECTION" : "TEMPORARY_FAILURE", certificateFailure ? "RDAP certificate verification failed." : "Registration upstream connection failed."));
    };
    const received = (chunk) => {
      try {
        bytes += chunk.length; operation.bytes(chunk.length);
        if (bytes > maxBytes) fail("RESPONSE_TOO_LARGE", "Registration response exceeds the byte limit.");
        chunks.push(chunk);
      } catch (error) { finish(error); }
    };
    const ownSocket = (value) => { socket = value; socket.once("close", release); };
    operation.signal.addEventListener("abort", abort, { once: true });
    try {
      operation.assertLive();
      if (protocol === "whois") {
        socket = (adapters.connect || net.connect)({ host: address.address, family: address.family, port: 43 });
        ownSocket(socket);
        socket.on("error", failed); socket.on("data", received);
        socket.once("connect", () => socket.write(`${query}\r\n`, "ascii"));
        socket.once("end", () => finish(null, { text: Buffer.concat(chunks).toString("utf8"), status: 200, headers: {} }));
        socket.once("close", () => { if (!done) failed(); });
      } else {
        request = (adapters.request || https.request)(url, {
          method: "GET", agent: false, family: address.family, servername: url.hostname,
          rejectUnauthorized: true, maxHeaderSize: 16384,
          lookup: (_host, opts, cb) => opts.all ? cb(null, [address]) : cb(null, address.address, address.family),
          headers: { Accept: "application/rdap+json, application/json", "Accept-Encoding": "identity", "User-Agent": "IT-Toolbox-Registration/1" },
        }, (res) => {
          response = res;
          if (res.headers["content-encoding"] && res.headers["content-encoding"] !== "identity") {
            finish(new RegistrationError("MALFORMED_REPLY", "Compressed registration replies are unsupported.")); return;
          }
          res.on("data", received); res.on("error", failed); res.once("aborted", failed);
          res.once("end", () => finish(null, { status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
        });
        request.once("socket", ownSocket); request.on("error", failed);
        request.once("close", () => { if (!socket) release(); }); request.end();
      }
    } catch (error) { if (!socket && !request) release(); finish(error); }
  });
}
