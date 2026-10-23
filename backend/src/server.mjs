import Fastify from "fastify";
import net from "node:net";
import { registerDnsRoute } from "./dns-route.mjs";
import { registerHttpRoute } from "./http-route.mjs";
import { registerTlsRoute } from "./tls-route.mjs";
import { registerRegistrationRoute } from "./registration-route.mjs";
import { releaseInfo, acceptedAuthorization } from "./release-info.mjs";

const app = Fastify({
  logger: true,
  trustProxy: true,
});

const BACKEND_SECRET = process.env.BACKEND_SECRET;
const release = releaseInfo();

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

// Protected by the same authentication hook as every other /api endpoint.
app.get("/api/release", async (request, reply) => {
  reply.header("Cache-Control", "no-store");
  return { ok: true, ...release, authorization: acceptedAuthorization(release) };
});

registerTlsRoute(app, getClientIp);

registerDnsRoute(app, getClientIp);

registerHttpRoute(app, getClientIp);
registerRegistrationRoute(app, getClientIp);

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
// Explicit opt-in for an isolated container network; local default stays loopback.
const bindAddress = process.env.TOOLBOX_BIND_ADDRESS || "127.0.0.1";
if (!["127.0.0.1", "0.0.0.0"].includes(bindAddress)) {
  throw new Error("Invalid TOOLBOX_BIND_ADDRESS");
}

app.listen({ host: bindAddress, port });
