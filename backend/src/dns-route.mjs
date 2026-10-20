import { checkDns, DnsCheckError } from "./tools/dns-check.mjs";

export function registerDnsRoute(app, getClientIp, check = checkDns) {
  app.post("/api/tools/dns-check", async (request, reply) => {
    const controller = new AbortController();
    const aborted = () => controller.abort();
    // Request 'close' includes normal POST-body completion, not just disconnects.
    const closed = () => { if (!reply.raw.writableFinished) aborted(); };
    request.raw.once("aborted", aborted);
    reply.raw.once("close", closed);
    try {
      if (request.raw.aborted || reply.raw.destroyed) aborted();
      const result = await check(request.body || {}, { clientIp: getClientIp(request), signal: controller.signal });
      if (!controller.signal.aborted) return result;
    } catch (error) {
      if (controller.signal.aborted) return;
      const safeError = error instanceof DnsCheckError
        ? error : new DnsCheckError("DNS_CHECK_FAILED", "DNS check failed.");
      const statusCode = safeError.code === "RATE_LIMITED" ? 429
        : safeError.code === "DNS_CAPACITY_EXHAUSTED" ? 503
        : safeError.code === "DNS_DIAGNOSTIC_TIMEOUT" ? 504
        : safeError.code === "DNS_CHECK_CANCELLED" ? 499
        : ["INVALID_MODE", "INVALID_RECORD_TYPE", "INVALID_QUERY", "INVALID_RESOLVER",
          "CUSTOM_RESOLVER_NOT_ALLOWED", "BULK_INPUT_NOT_ALLOWED"].includes(safeError.code) ? 400 : 502;
      return reply.code(statusCode).send({ ok: false, error: { code: safeError.code, message: safeError.safeMessage } });
    } finally {
      request.raw.removeListener("aborted", aborted);
      reply.raw.removeListener("close", closed);
    }
  });
}
