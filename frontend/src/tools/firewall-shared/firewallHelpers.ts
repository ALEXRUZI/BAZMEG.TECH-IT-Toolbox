export function validateIpv4Cidr(value: string) {
  const trimmedValue = value.trim();
  if (!trimmedValue) {
    return 'Source is required.';
  }
  const [ip, prefix, extra] = trimmedValue.split('/');
  if (extra !== undefined) {
    return 'Use only one CIDR prefix, for example 10.10.190.14/32.';
  }
  if (prefix !== undefined) {
    if (!/^\d+$/.test(prefix)) {
      return 'CIDR prefix must be a number from 0 to 32.';
    }
    const prefixNumber = Number(prefix);
    if (prefixNumber < 0 || prefixNumber > 32) {
      return 'CIDR prefix must be between 0 and 32.';
    }
  }
  const octets = ip.split('.');
  if (octets.length !== 4) {
    return 'IPv4 address must have 4 octets.';
  }
  const hasInvalidOctet = octets.some((octet) => {
    if (!/^\d+$/.test(octet)) {
      return true;
    }
    const octetNumber = Number(octet);
    return octetNumber < 0 || octetNumber > 255;
  });
  if (hasInvalidOctet) {
    return 'Each IPv4 octet must be a number from 0 to 255.';
  }
  return null;
}

export function validatePort(value: string) {
  const trimmedValue = value.trim();
  if (!trimmedValue) {
    return 'Port is required.';
  }
  if (!/^\d+$/.test(trimmedValue)) {
    return 'Port must be a number.';
  }
  const portNumber = Number(trimmedValue);
  if (portNumber < 1 || portNumber > 65535) {
    return 'Port must be between 1 and 65535.';
  }
  return null;
}

export const firewallExamples = {
  source: '10.20.30.40/32',
  sourcePort: '2049',
  destination: '10.20.30.40/32',
  destinationPort: '2049',
};
