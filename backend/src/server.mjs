import Fastify from "fastify";
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

const port = Number(process.env.PORT || 3001);

app.listen({ host: "127.0.0.1", port });
