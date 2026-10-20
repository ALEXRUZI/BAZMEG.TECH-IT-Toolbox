export function validateCsrCommonName(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'Common Name is required.';
  }

  if (trimmedValue.length > 253) {
    return 'Common Name must be 253 characters or fewer.';
  }

  if (!isValidDnsName(trimmedValue) && !isValidIpAddress(trimmedValue)) {
    return 'Use a DNS name, wildcard DNS name, IPv4 address, or IPv6 address.';
  }

  return '';
}

export function validateCsrCountry(value: string) {
  return /^[A-Z]{2}$/.test(value.trim().toUpperCase())
    ? ''
    : 'Country must be a two-letter ISO code, for example DE or US.';
}

export function validateCsrEmail(value: string) {
  // Check before trimming: unsupported characters must never disappear during normalization.
  if (/[^\x20-\x7e]/.test(value)) {
    return 'Use an ASCII email address without control characters; Unicode email addresses are not supported.';
  }

  const email = value.trim();
  if (!email) return ''; // Optional subject attribute.

  const parts = email.split('@');
  const [local, domain] = parts;
  const validLocal = local.length <= 64 && /^[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+)*$/.test(local);
  const validDomain = domain && domain.includes('.') && isValidDnsName(domain) && !domain.startsWith('*.');

  return parts.length === 2 && email.length <= 254 && validLocal && validDomain
    ? ''
    : 'Enter a valid email address.';
}

export function validateCsrSan(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) {
    return 'SAN value is required.';
  }

  if (!isValidDnsName(trimmedValue) && !isValidIpAddress(trimmedValue)) {
    return 'Use a DNS name, wildcard DNS name, IPv4 address, or IPv6 address.';
  }

  return '';
}

export function getCsrSanWarning(value: string) {
  const trimmedValue = value.trim().toLowerCase();

  if (!trimmedValue) {
    return '';
  }

  if (trimmedValue === 'localhost') {
    return 'localhost is not suitable for public CA certificates. Use an internal/private CA.';
  }

  if (isValidIpAddress(trimmedValue) && !isPublicIpAddress(trimmedValue)) {
    return 'Private, loopback, and link-local IPs are not suitable for public CA certificates. Use an internal/private CA.';
  }

  return '';
}

function isValidDnsName(value: string) {
  const normalizedValue = value.toLowerCase();
  const withoutWildcard = normalizedValue.startsWith('*.') ? normalizedValue.slice(2) : normalizedValue;

  if (!withoutWildcard || withoutWildcard.length > 253 || withoutWildcard.endsWith('.')) {
    return false;
  }

  return withoutWildcard.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

export function isValidIpAddress(value: string) {
  return isValidIpv4Address(value) || isValidIpv6Address(value);
}

function isPublicIpAddress(value: string) {
  return isValidIpv4Address(value) ? isPublicIpv4Address(value) : isPublicIpv6Address(value);
}

function isPublicIpv4Address(value: string) {
  const [firstOctet, secondOctet] = value.split('.').map((octet) => Number(octet));

  if (firstOctet === 10 || firstOctet === 127 || firstOctet === 0) {
    return false;
  }

  if (firstOctet === 172 && secondOctet >= 16 && secondOctet <= 31) {
    return false;
  }

  if (firstOctet === 192 && secondOctet === 168) {
    return false;
  }

  if (firstOctet === 169 && secondOctet === 254) {
    return false;
  }

  return true;
}

function isPublicIpv6Address(value: string) {
  const bytes = parseIpAddress(value);
  const firstByte = bytes[0];
  const secondByte = bytes[1];

  if (
    bytes.every((byte) => byte === 0) ||
    bytes.every((byte, index) => (index === 15 ? byte === 1 : byte === 0))
  ) {
    return false;
  }

  if ((firstByte & 0xfe) === 0xfc) {
    return false;
  }

  if (firstByte === 0xfe && (secondByte & 0xc0) === 0x80) {
    return false;
  }

  return true;
}

function isValidIpv4Address(value: string) {
  const octets = value.split('.');

  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255)
  );
}

function isValidIpv6Address(value: string) {
  if (!value.includes(':')) {
    return false;
  }

  const normalizedValue = value.toLowerCase();

  if (!/^[0-9a-f:.]+$/.test(normalizedValue)) {
    return false;
  }

  const parts = normalizedValue.split('::');

  if (parts.length > 2) {
    return false;
  }

  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const groups = [...left, ...right];
  const hasValidGroups = groups.every((group) => /^[0-9a-f]{1,4}$/.test(group));

  return hasValidGroups && (parts.length === 2 ? groups.length < 8 : groups.length === 8);
}

export function parseIpAddress(value: string) {
  if (isValidIpv4Address(value)) {
    return new Uint8Array(value.split('.').map((octet) => Number(octet)));
  }

  const parts = value.toLowerCase().split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const missingGroupCount = 8 - left.length - right.length;
  const groups = [...left, ...Array(Math.max(missingGroupCount, 0)).fill('0'), ...right].map((group) =>
    parseInt(group, 16)
  );
  const bytes = new Uint8Array(16);

  groups.forEach((group, index) => {
    bytes[index * 2] = group >> 8;
    bytes[index * 2 + 1] = group & 255;
  });

  return bytes;
}
