interface Env {
  BACKEND_ORIGIN?: string;
  BACKEND_SECRET?: string;
}

function proxyError(status: number, code: string, message: string): Response {
  return Response.json({ ok: false, error: { code, message } }, {
    status,
    headers: { 'Cache-Control': 'no-store' },
  });
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const incomingUrl = new URL(context.request.url);
  let upstreamUrl: URL;
  const headers = new Headers(context.request.headers);
  const secret = context.env.BACKEND_SECRET;

  try {
    if (!secret || secret.trim() !== secret || /[\x00-\x1f\x7f]/.test(secret)) {
      throw new Error('Invalid configuration');
    }
    // Headers also rejects values outside the runtime's HTTP ByteString range.
    headers.set('X-Toolbox-Backend-Secret', secret);
    if (!context.env.BACKEND_ORIGIN) throw new Error('Invalid configuration');
    upstreamUrl = new URL(context.env.BACKEND_ORIGIN);
    if (!['https:', 'http:'].includes(upstreamUrl.protocol) || upstreamUrl.username || upstreamUrl.password) {
      throw new Error('Invalid configuration');
    }
  } catch {
    return proxyError(503, 'PAGES_PROXY_CONFIGURATION', 'API proxy configuration is unavailable.');
  }

  upstreamUrl.pathname = incomingUrl.pathname;
  upstreamUrl.search = incomingUrl.search;
  upstreamUrl.hash = '';

  const clientIp = context.request.headers.get("CF-Connecting-IP");

  // Remove Connection-nominated headers before reconstructing protected headers.
  for (const name of (headers.get('connection') ?? '').split(',')) {
    const token = name.trim();
    if (/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(token)) headers.delete(token);
  }
  // Snapshot names so deleting a header cannot skip the next family member.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith('x-forwarded-')) headers.delete(name);
  }
  for (const name of [
    'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade',
    'forwarded',
    'x-real-ip', 'true-client-ip', 'cf-connecting-ip',
    'x-toolbox-client-ip', 'x-toolbox-backend-secret',
  ]) headers.delete(name);

  // CF-Connecting-IP is trusted only on requests delivered by the Cloudflare edge.
  headers.set("X-Toolbox-Backend-Secret", secret);
  headers.set("X-Forwarded-Host", incomingUrl.host);

  if (clientIp) {
    headers.set("X-Toolbox-Client-IP", clientIp);
  }

  const method = context.request.method.toUpperCase();

  if (context.request.signal.aborted) {
    return proxyError(499, 'PAGES_PROXY_CANCELLED', 'API proxy request was cancelled.');
  }
  try {
    return await fetch(upstreamUrl.toString(), {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : context.request.body,
      redirect: "manual",
      signal: context.request.signal,
    });
  } catch {
    return context.request.signal.aborted
      ? proxyError(499, 'PAGES_PROXY_CANCELLED', 'API proxy request was cancelled.')
      : proxyError(502, 'PAGES_PROXY_UNAVAILABLE', 'API backend is unavailable.');
  }
};
