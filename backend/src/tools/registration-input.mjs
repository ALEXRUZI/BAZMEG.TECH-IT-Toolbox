import net from "node:net";
import { domainToASCII } from "node:url";

export class RegistrationError extends Error {
  constructor(code, message) { super(message); this.code = code; this.safeMessage = message; this.attempts = []; }
}
export const fail = (code, message) => { throw new RegistrationError(code, message); };

export function normalizeRegistration(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)
    || Object.keys(payload).some((key) => !["target", "protocolMode"].includes(key))) {
    fail("INVALID_INPUT", "Provide one registration identifier and protocol mode only.");
  }
  const input = payload.target;
  if (typeof input !== "string" || input.length > 512 || /[\p{Cc}\p{Cf}]/u.test(input)) {
    fail("INVALID_INPUT", "Enter one domain, IPv4/IPv6 address, or AS-prefixed ASN.");
  }
  const value = input.trim();
  if (!value || /[\s/?#@\\\[\],;%]/u.test(value)) fail("INVALID_INPUT", "Enter one domain, IPv4/IPv6 address, or AS-prefixed ASN.");
  const mode = payload.protocolMode === undefined ? "auto" : payload.protocolMode;
  if (!["auto", "rdap", "whois"].includes(mode)) fail("INVALID_MODE", "Choose Auto, RDAP-only, or WHOIS-only.");
  let kind, canonical;
  if (/^AS\d+$/i.test(value)) {
    const number = Number(value.slice(2));
    if (!Number.isInteger(number) || number < 1 || number > 4294967295) fail("INVALID_INPUT", "ASN must be AS1 through AS4294967295.");
    kind = "asn"; canonical = `AS${number}`;
  } else if (net.isIP(value)) {
    kind = net.isIP(value) === 4 ? "ipv4" : "ipv6";
    canonical = kind === "ipv6" ? new URL(`https://[${value}]/`).hostname.slice(1, -1) : value;
  } else {
    if (/^[\d.]+$/.test(value) || value.includes(":")) fail("INVALID_INPUT", "Enter a valid individual IP address, not a URL or port.");
    canonical = domainToASCII(value.replace(/\.$/, "").toLowerCase()).toLowerCase();
    const labels = canonical.split(".");
    if (!canonical || canonical.length > 253 || labels.length < 2 || labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
      || /^\d+$/.test(labels.at(-1))) fail("INVALID_INPUT", "Enter a valid domain with at least two labels.");
    kind = "domain";
  }
  return { original: input, canonical, kind, protocolMode: mode };
}

// Registration identifiers are data, never connection destinations. This also
// permits inspecting reserved IP registration space without connecting to it.
export function ipNumber(address) {
  if (net.isIP(address) === 4) return address.split(".").reduce((n, v) => (n << 8n) + BigInt(v), 0n);
  let text = address.toLowerCase();
  if (text.includes(".")) {
    const tail = text.slice(text.lastIndexOf(":") + 1), n = ipNumber(tail);
    text = text.slice(0, text.lastIndexOf(":") + 1) + `${(n >> 16n).toString(16)}:${(n & 65535n).toString(16)}`;
  }
  const [a, b] = text.split("::");
  const left = a ? a.split(":") : [], right = b ? b.split(":") : [];
  const groups = text.includes("::") ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right] : left;
  return BigInt(`0x${groups.map((v) => v.padStart(4, "0")).join("")}`);
}
