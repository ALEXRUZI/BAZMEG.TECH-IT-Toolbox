import Fastify from "fastify";

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
    message: "pong from Netcup backend",
    clientIp: request.ip,
  };
});

const port = Number(process.env.PORT || 3001);

app.listen({ host: "127.0.0.1", port });
