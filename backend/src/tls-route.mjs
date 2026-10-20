import { checkTlsCertificate, TlsCheckError } from "./tools/tls-check.mjs";

export function registerTlsRoute(app, getClientIp, check = checkTlsCertificate) {
  app.post("/api/tools/tls-check", async (request, reply) => {
    const controller = new AbortController();
    const aborted = () => controller.abort();
    // IncomingMessage 'close' also fires on normal POST body completion.
    // ServerResponse 'close' before writableFinished means a disconnected client.
    const closed = () => { if (!reply.raw.writableFinished) aborted(); };
    request.raw.once("aborted", aborted);
    reply.raw.once("close", closed);
    try {
      if (request.raw.aborted || reply.raw.destroyed) aborted();
      return await check(request.body || {}, { clientIp: getClientIp(request), signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) return;
      const safeError = error instanceof TlsCheckError
        ? error : new TlsCheckError("TLS_CONNECTION_FAILED", "TLS connection failed.");
      const statusCode = safeError.code === "RATE_LIMITED" ? 429
        : safeError.code === "TLS_CAPACITY_EXHAUSTED" ? 503
        : safeError.code === "TLS_DIAGNOSTIC_TIMEOUT" ? 504
        : safeError.code === "TLS_CHECK_CANCELLED" ? 499
        : ["INVALID_HOST", "INVALID_PORT", "DNS_LOOKUP_FAILED", "BLOCKED_TARGET"].includes(safeError.code) ? 400 : 502;
      return reply.code(statusCode).send({ ok: false, error: { code: safeError.code, message: safeError.safeMessage } });
    } finally {
      request.raw.removeListener("aborted", aborted);
      reply.raw.removeListener("close", closed);
    }
  });
}
