import { checkHttpHeader, HttpHeaderCheckError } from "./tools/http-header-check.mjs";

export function registerHttpRoute(app, getClientIp, check = checkHttpHeader) {
  app.post("/api/tools/http-header-check", async (request, reply) => {
    const controller = new AbortController();
    const aborted = () => controller.abort();
    const closed = () => { if (!reply.raw.writableFinished) aborted(); };
    request.raw.once("aborted", aborted);
    reply.raw.once("close", closed);
    try {
      if (request.raw.aborted || reply.raw.destroyed) aborted();
      const result = await check(request.body || {}, {
        clientIp: getClientIp(request), logger: request.log, signal: controller.signal,
      });
      if (!controller.signal.aborted) return result;
    } catch (error) {
      if (controller.signal.aborted) return;
      const safeError = error instanceof HttpHeaderCheckError
        ? error : new HttpHeaderCheckError("HTTP_HEADER_CHECK_FAILED", "HTTP header check failed.");
      const statusCode = safeError.code === "RATE_LIMITED" ? 429
        : safeError.code === "HTTP_CAPACITY_EXHAUSTED" ? 503
        : safeError.code === "HTTP_DIAGNOSTIC_TIMEOUT" ? 504
        : safeError.code === "HTTP_CHECK_CANCELLED" ? 499
        : ["INVALID_TARGET", "UNSUPPORTED_PROTOCOL", "IP_NOT_ALLOWED", "LOCAL_HOSTNAME_NOT_ALLOWED",
          "INVALID_PORT", "DNS_LOOKUP_FAILED", "BLOCKED_TARGET", "BLOCKED_REDIRECT"].includes(safeError.code) ? 400 : 502;
      return reply.code(statusCode).send({ ok: false, error: { code: safeError.code, message: safeError.safeMessage } });
    } finally {
      request.raw.removeListener("aborted", aborted);
      reply.raw.removeListener("close", closed);
    }
  });
}
