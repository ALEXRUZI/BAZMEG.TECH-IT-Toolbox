import assert from "node:assert/strict";
import test from "node:test";
import Fastify from "fastify";
import { registerDnsRoute } from "../src/dns-route.mjs";
import { createDnsContractFixtures } from "./fixtures/dns-contracts.mjs";

test("DNS route preserves completed negative/failure/incomplete diagnostic contracts with HTTP 200", async (t) => {
  const fixtures = await createDnsContractFixtures();
  const app = Fastify();
  t.after(() => app.close());
  let selected;
  registerDnsRoute(app, () => "offline-client", async () => selected);
  for (const [key, fixture] of Object.entries(fixtures)) {
    selected = fixture;
    const result = await app.inject({ method: "POST", url: "/api/tools/dns-check", payload: {} });
    assert.equal(result.statusCode, 200, key);
    assert.deepEqual(result.json(), fixture);
    assert.equal("error" in fixture, false);
    if (["timeout", "resolverError", "formerr", "notimp", "incomplete", "burst"].includes(key)) {
      assert.equal(fixture.ok, false, key);
      assert.ok(fixture.warnings.length);
    }
    assert.equal(JSON.stringify(fixture).includes("private fixture detail"), false);
  }
});
