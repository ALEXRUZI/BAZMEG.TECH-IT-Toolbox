export function base64UrlDecode(value: string) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = window.atob(base64);

  return new Uint8Array([...binary].map((character) => character.charCodeAt(0)));
}

export function base64Encode(der: Uint8Array) {
  const binary = Array.from(der, (byte) => String.fromCharCode(byte)).join('');

  return window.btoa(binary).match(/.{1,64}/g)?.join('\n') ?? '';
}

export function pemEncode(label: string, der: Uint8Array) {
  const lines = base64Encode(der).split('\n');

  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].join('\n');
}
