import Fastify from "fastify";
import net from "node:net";
import { checkDns, DnsCheckError } from "./tools/dns-check.mjs";
import { checkTlsCertificate, TlsCheckError } from "./tools/tls-check.mjs";

const app = Fastify({
  logger: true,
  trustProxy: true,
});

const BACKEND_SECRET = process.env.BACKEND_SECRET;

app.addHook("onRequest", async (request, reply) => {
  if (request.url === "/healthz") {
    return;
  }

  const providedSecret = request.headers["x-toolbox-backend-secret"];

  if (!BACKEND_SECRET || providedSecret !== BACKEND_SECRET) {
    return reply.code(401).send({
      error: "unauthorized",
    });
  }
});

app.get("/healthz", async () => {
  return {
    status: "ok",
    service: "toolbox-api",
  };
});

app.get("/api/ping", async (request) => {
  return {
    ok: true,
    message: "toolbox API reachable",
  };
});

app.post("/api/tools/tls-check", async (request, reply) => {
  try {
    return await checkTlsCertificate(request.body || {});
  } catch (error) {
    const safeError = error instanceof TlsCheckError
      ? error
      : new TlsCheckError("TLS_CONNECTION_FAILED", "TLS connection failed.");

    const statusCode = [
      "INVALID_HOST",
      "INVALID_PORT",
      "DNS_LOOKUP_FAILED",
      "BLOCKED_TARGET",
    ].includes(safeError.code) ? 400 : 502;

    return reply.code(statusCode).send({
      ok: false,
      error: {
        code: safeError.code,
        message: safeError.safeMessage,
      },
    });
  }
});

app.post("/api/tools/dns-check", async (request, reply) => {
  try {
    return await checkDns(request.body || {}, {
      clientIp: getClientIp(request),
    });
  } catch (error) {
    const safeError = error instanceof DnsCheckError
      ? error
      : new DnsCheckError("DNS_CHECK_FAILED", "DNS check failed.");

    const statusCode = safeError.code === "RATE_LIMITED"
      ? 429
      : [
        "INVALID_MODE",
        "INVALID_RECORD_TYPE",
        "INVALID_QUERY",
        "INVALID_RESOLVER",
        "CUSTOM_RESOLVER_NOT_ALLOWED",
        "BULK_INPUT_NOT_ALLOWED",
      ].includes(safeError.code) ? 400 : 502;

    return reply.code(statusCode).send({
      ok: false,
      error: {
        code: safeError.code,
        message: safeError.safeMessage,
      },
    });
  }
});

function getClientIp(request) {
  const trustToolboxProxyHeader = process.env.TRUST_TOOLBOX_PROXY_HEADERS === "true";
  const toolboxClientIp = request.headers["x-toolbox-client-ip"];

  if (trustToolboxProxyHeader && typeof toolboxClientIp === "string" && netSafeIp(toolboxClientIp)) {
    return toolboxClientIp;
  }

  if (trustToolboxProxyHeader && request.ip) {
    return request.ip;
  }

  return request.socket?.remoteAddress || "unknown";
}

function netSafeIp(value) {
  return typeof value === "string" && net.isIP(value) !== 0;
}

const port = Number(process.env.PORT || 3001);

app.listen({ host: "127.0.0.1", port });
