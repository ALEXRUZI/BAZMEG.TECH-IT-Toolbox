import { lookupRegistration, RegistrationError } from "./tools/registration-lookup.mjs";

export function registerRegistrationRoute(app, getClientIp, check = lookupRegistration) {
  app.post("/api/tools/rdap-lookup", { bodyLimit: 2048 }, async (request, reply) => {
    const controller = new AbortController();
    const aborted = () => controller.abort();
    const closed = () => { if (!reply.raw.writableFinished) aborted(); };
    request.raw.once("aborted", aborted); reply.raw.once("close", closed);
    try {
      if (request.raw.aborted || reply.raw.destroyed) aborted();
      const result = await check(request.body || {}, { clientIp: getClientIp(request), signal: controller.signal });
      if (!controller.signal.aborted) return result;
    } catch (error) {
      if (controller.signal.aborted) return;
      const safe = error instanceof RegistrationError ? error : new RegistrationError("LOOKUP_FAILED", "Registration lookup failed.");
      const status = ["INVALID_INPUT", "INVALID_MODE", "SECURITY_REJECTION"].includes(safe.code) ? 400
        : ["RATE_LIMITED", "UPSTREAM_RATE_LIMITED"].includes(safe.code) ? 429
        : ["CAPACITY_EXHAUSTED", "DISCOVERY_UNAVAILABLE", "UNSUPPORTED_DISCOVERY", "PROTOCOL_UNAVAILABLE"].includes(safe.code) ? 503
        : ["DEADLINE_EXHAUSTED", "UPSTREAM_TIMEOUT"].includes(safe.code) ? 504 : safe.code === "CANCELLED" ? 499 : 502;
      return reply.code(status).send({ ok: false, error: { code: safe.code, message: safe.safeMessage }, attempts: safe.attempts, rawResponses: safe.rawResponses ?? [] });
    } finally {
      request.raw.removeListener("aborted", aborted); reply.raw.removeListener("close", closed);
    }
  });
}
