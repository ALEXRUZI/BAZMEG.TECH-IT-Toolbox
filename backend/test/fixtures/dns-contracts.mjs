// Shared offline contract fixtures: actual checkDns outputs, not frontend-only
// approximations. Network work is injected; production wire parsing is covered
// by dns-check.test.mjs. No sockets or public DNS queries are made here.
import { checkDns, normalizeDnsCheckRequest, resetDnsCheckState } from "../../src/tools/dns-check.mjs";

export function normalizeFixtureRequest(payload) {
  return normalizeDnsCheckRequest(payload);
}

export async function createTxtContractFixture(payload) {
  resetDnsCheckState();
  return checkDns(payload, { queryDns: async (_server, name, type) => ({
    rcode: 0, rcodeName: "NOERROR", flags: { tc: false, ad: false },
    question: [{ name, type, class: 1 }],
    answer: type === "TXT" ? [{ name, type, ttl: 60, data: ["offline TXT fixture"] }] : [], authority: [], additional: [],
  }) });
}

export async function createDnsContractFixtures() {
  const fixtures = {};
  const payload = { mode: "single", resolverId: "cloudflare", recordType: "A", query: "example.com", dnssec: false };
  const response = (rcodeName = "NOERROR", tc = false, answer = []) => ({
    id: 1234, rcodeName, rcode: ({ NOERROR: 0, NXDOMAIN: 3, FORMERR: 1, NOTIMP: 4 })[rcodeName],
    flags: { qr: true, tc, ad: false }, question: [{ name: "example.com", type: "A", class: 1 }],
    answer, authority: [], additional: [],
  });
  const answer = [{ name: "example.com", type: "A", ttl: 60, data: "93.184.216.34" }];
  for (const [key, rcode, tc, records] of [
    ["success", "NOERROR", false, answer], ["nxdomain", "NXDOMAIN", false, []],
    ["incomplete", "NOERROR", true, answer], ["formerr", "FORMERR", false, []], ["notimp", "NOTIMP", false, []],
  ]) {
    resetDnsCheckState();
    fixtures[key] = await checkDns(payload, { queryDns: async () => response(rcode, tc, records) });
  }
  for (const [key, code] of [["timeout", "DNS_TIMEOUT"], ["resolverError", "OFFLINE_FAILURE"]]) {
    resetDnsCheckState();
    fixtures[key] = await checkDns(payload, { queryDns: async () => { throw Object.assign(new Error("private fixture detail"), { code }); } });
  }
  resetDnsCheckState();
  fixtures.burst = await checkDns({ mode: "burst", recordType: "A", query: "example.com" }, {
    queryDns: async (server) => {
      if (server === "8.8.8.8") throw new Error("private fixture detail");
      return response("NOERROR", server === "1.1.1.1", answer);
    },
  });
  resetDnsCheckState();
  return fixtures;
}
