import type { HttpHeaderCheck, HttpHeaderCheckSuccess, HttpHeaderFindingSeverity, HttpHeaderProtocolMode, HttpHeaderRedirect } from './httpHeaderTypes';

export const httpHeaderProtocolModeLabels: Record<HttpHeaderProtocolMode, string> = {
  auto: 'Auto / Follow redirect',
  https: 'HTTPS only',
  http: 'HTTP only',
  both: 'Both HTTP and HTTPS',
};

export function getPublicHttpHeaderResult(result: HttpHeaderCheckSuccess) {
  const publicResult: Omit<HttpHeaderCheckSuccess, 'budget'> & { budget?: HttpHeaderCheckSuccess['budget'] } = { ...result };
  delete publicResult.budget;

  return publicResult;
}

export function formatHttpHeaderRedirectStatus(redirect: HttpHeaderRedirect) {
  const statusText = redirect.statusText || getHttpStatusStandardText(redirect.status);

  return statusText ? `${redirect.status} ${statusText}` : String(redirect.status);
}

export function getHttpHeaderInputPortSummary(result: HttpHeaderCheckSuccess) {
  if (result.input.protocolMode === 'auto') {
    return { label: 'Port', value: 'standard Auto behavior' };
  }

  if (result.input.protocolMode === 'both') {
    return { label: 'Ports', value: 'HTTP 80 and HTTPS 443' };
  }

  const matchingCheck = result.checks.find((check) => check.protocol === result.input.protocolMode) || result.checks[0];

  return {
    label: 'Port',
    value: matchingCheck ? String(matchingCheck.port) : 'Unavailable',
  };
}

export function formatHttpHeaderProtocolLabel(protocol: HttpHeaderCheck['protocol']) {
  return protocol === 'auto' ? 'AUTO' : protocol.toUpperCase();
}

export function getFiniteSeconds(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? Math.max(0, Math.floor(value)) : null;
}

export function httpHeaderFindingClass(severity: HttpHeaderFindingSeverity) {
  if (severity === 'critical') {
    return 'border-red-300/35 bg-red-500/10 text-red-50';
  }

  if (severity === 'warning') {
    return 'border-amber-300/35 bg-amber-400/10 text-amber-50';
  }

  if (severity === 'pass') {
    return 'border-emerald-400/35 bg-emerald-500/10 text-emerald-50';
  }

  return 'border-sky-300/25 bg-sky-400/10 text-sky-50';
}

export type HttpStatusFamilyKey = '2xx' | '3xx' | '4xx' | '5xx';

export const httpStatusFamilies: Array<{
  key: HttpStatusFamilyKey;
  code: number;
  label: string;
  buttonClass: string;
  codes: Array<{
    code: number;
    label: string;
    detail: string;
  }>;
}> = [
  {
    key: '2xx',
    code: 200,
    label: 'Success',
    buttonClass: 'border-emerald-300/45 bg-emerald-400/15 text-emerald-50 hover:bg-emerald-400/25',
    codes: [
      { code: 200, label: 'OK', detail: 'The request succeeded.' },
      { code: 201, label: 'Created', detail: 'A new resource was created.' },
      { code: 202, label: 'Accepted', detail: 'The request was accepted for processing.' },
      { code: 204, label: 'No Content', detail: 'The request succeeded with no body.' },
      { code: 206, label: 'Partial Content', detail: 'Only part of the resource was returned.' },
    ],
  },
  {
    key: '3xx',
    code: 300,
    label: 'Redirection',
    buttonClass: 'border-slate-300/45 bg-slate-300/15 text-slate-50 hover:bg-slate-300/25',
    codes: [
      { code: 300, label: 'Multiple Choices', detail: 'Several response options are available.' },
      { code: 301, label: 'Moved Permanently', detail: 'The resource has a permanent new URL.' },
      { code: 302, label: 'Found', detail: 'The resource is temporarily elsewhere.' },
      { code: 303, label: 'See Other', detail: 'Fetch the result from another URL.' },
      { code: 304, label: 'Not Modified', detail: 'A cached copy may be reused.' },
      { code: 307, label: 'Temporary Redirect', detail: 'Repeat the same method at another URL.' },
      { code: 308, label: 'Permanent Redirect', detail: 'Repeat the same method at the permanent URL.' },
    ],
  },
  {
    key: '4xx',
    code: 400,
    label: 'Client error',
    buttonClass: 'border-amber-300/50 bg-amber-300/15 text-amber-50 hover:bg-amber-300/25',
    codes: [
      { code: 400, label: 'Bad Request', detail: 'The server could not parse the request.' },
      { code: 401, label: 'Unauthorized', detail: 'Authentication is required.' },
      { code: 403, label: 'Forbidden', detail: 'The server refused access.' },
      { code: 404, label: 'Not Found', detail: 'The requested resource does not exist.' },
      { code: 405, label: 'Method Not Allowed', detail: 'That HTTP method is not allowed here.' },
      { code: 408, label: 'Request Timeout', detail: 'The server timed out waiting.' },
      { code: 409, label: 'Conflict', detail: 'The request conflicts with current state.' },
      { code: 410, label: 'Gone', detail: 'The resource is no longer available.' },
      { code: 413, label: 'Payload Too Large', detail: 'The request body is too large.' },
      { code: 415, label: 'Unsupported Media Type', detail: 'The content type is not supported.' },
      { code: 418, label: "I'm a teapot", detail: 'A deliberately non-serious status code.' },
      { code: 421, label: 'Misdirected Request', detail: 'The request reached the wrong server.' },
      { code: 422, label: 'Unprocessable Content', detail: 'The request was understood but invalid.' },
      { code: 425, label: 'Too Early', detail: 'The server is unwilling to risk replay.' },
      { code: 426, label: 'Upgrade Required', detail: 'A protocol upgrade is required.' },
      { code: 429, label: 'Too Many Requests', detail: 'The client has sent too many requests.' },
      { code: 431, label: 'Request Header Fields Too Large', detail: 'Request headers are too large.' },
      { code: 451, label: 'Unavailable For Legal Reasons', detail: 'Access is restricted for legal reasons.' },
    ],
  },
  {
    key: '5xx',
    code: 500,
    label: 'Server error',
    buttonClass: 'border-red-300/45 bg-red-400/15 text-red-50 hover:bg-red-400/25',
    codes: [
      { code: 500, label: 'Internal Server Error', detail: 'The server hit an unexpected error.' },
      { code: 501, label: 'Not Implemented', detail: 'The server does not support the feature.' },
      { code: 502, label: 'Bad Gateway', detail: 'A proxy received a bad upstream response.' },
      { code: 503, label: 'Service Unavailable', detail: 'The server is unavailable or overloaded.' },
      { code: 504, label: 'Gateway Timeout', detail: 'A proxy timed out waiting upstream.' },
      { code: 505, label: 'HTTP Version Not Supported', detail: 'The HTTP version is unsupported.' },
      { code: 507, label: 'Insufficient Storage', detail: 'The server lacks storage for the request.' },
      { code: 508, label: 'Loop Detected', detail: 'The server detected an infinite loop.' },
      { code: 510, label: 'Not Extended', detail: 'Further extensions are required.' },
      { code: 511, label: 'Network Authentication Required', detail: 'Network access requires authentication.' },
    ],
  },
];

export function getHttpStatusStandardText(status: number) {
  for (const family of httpStatusFamilies) {
    const match = family.codes.find((entry) => entry.code === status);

    if (match) {
      return match.label;
    }
  }

  return null;
}

export function getHttpStatusBadgeClass(status: number) {
  if (status >= 200 && status < 300) {
    return 'bg-emerald-700 text-white border-emerald-300/60';
  }

  if (status >= 300 && status < 400) {
    return 'bg-slate-700 text-white border-slate-300/60';
  }

  if (status >= 400 && status < 500) {
    return 'bg-amber-700 text-white border-amber-300/60';
  }

  if (status >= 500 && status < 600) {
    return 'bg-red-700 text-white border-red-300/60';
  }

  return 'bg-slate-700 text-white border-slate-300/60';
}

export function formatSeconds(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value} seconds` : null;
}

export function formatMilliseconds(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value} ms` : null;
}
