import type { TlsCheckResponse } from './tlsTypes';

export async function fetchTlsCertificateCheck(host: string, port: number) {
  const response = await fetch('/api/tools/tls-check', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      host,
      port,
    }),
  });
  const body = (await response.json()) as TlsCheckResponse;

  return { response, body };
}
