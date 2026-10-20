import type { HttpHeaderCheckResponse, HttpHeaderProtocolMode } from './httpHeaderTypes';

export type HttpHeaderCheckPayload = {
  target: string;
  protocolMode: HttpHeaderProtocolMode;
  port?: number;
};

export async function fetchHttpHeaderCheck(payload: HttpHeaderCheckPayload) {
  const response = await fetch('/api/tools/http-header-check', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const body = (await response.json()) as HttpHeaderCheckResponse;

  return { response, body };
}
