interface Env {
  BACKEND_ORIGIN: string;
  BACKEND_SECRET: string;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const incomingUrl = new URL(context.request.url);
  const upstreamUrl = new URL(context.env.BACKEND_ORIGIN);

  upstreamUrl.pathname = incomingUrl.pathname;
  upstreamUrl.search = incomingUrl.search;

  const headers = new Headers(context.request.headers);

  headers.delete("x-toolbox-client-ip");
  headers.delete("x-toolbox-backend-secret");

  const clientIp = context.request.headers.get("CF-Connecting-IP");

  headers.set("X-Toolbox-Backend-Secret", context.env.BACKEND_SECRET);
  headers.set("X-Forwarded-Host", incomingUrl.host);

  if (clientIp) {
    headers.set("X-Toolbox-Client-IP", clientIp);
  }

  headers.delete("host");
  headers.delete("connection");
  headers.delete("keep-alive");
  headers.delete("proxy-authenticate");
  headers.delete("proxy-authorization");
  headers.delete("te");
  headers.delete("trailer");
  headers.delete("transfer-encoding");
  headers.delete("upgrade");

  const method = context.request.method.toUpperCase();

  return fetch(upstreamUrl.toString(), {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : context.request.body,
    redirect: "manual",
  });
};
