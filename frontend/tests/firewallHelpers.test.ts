// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { validateIpv4Cidr, validatePort } from '../src/tools/firewall-shared/firewallHelpers';
import { validateZoneName } from '../src/tools/firewalld-generator/firewalldHelpers';

describe('IPv4/CIDR validation (IPv6 is not supported)', () => {
  it.each(['0.0.0.0/0', '255.255.255.255/32', '192.0.2.1', ' 10.0.0.0/24 '])('accepts %s', (value) => {
    expect(validateIpv4Cidr(value)).toBeNull();
  });
  it.each([
    ['', 'Source is required.'],
    ['2001:db8::1', 'IPv4 address must have 4 octets.'],
    ['10.0.0.1/33', 'CIDR prefix must be between 0 and 32.'],
    ['10.0.0.1/no', 'CIDR prefix must be a number from 0 to 32.'],
    ['10.0.0.1/24/32', 'Use only one CIDR prefix, for example 10.10.190.14/32.'],
    ['256.0.0.1', 'Each IPv4 octet must be a number from 0 to 255.'],
    ['a.0.0.1', 'Each IPv4 octet must be a number from 0 to 255.'],
  ])('rejects %s', (value, message) => expect(validateIpv4Cidr(value)).toBe(message));
});

describe('ports', () => {
  it.each(['1', '65535', '443', ' 53 '])('accepts %s', (value) => expect(validatePort(value)).toBeNull());
  it.each([
    ['', 'Port is required.'], ['https', 'Port must be a number.'],
    ['0', 'Port must be between 1 and 65535.'], ['65536', 'Port must be between 1 and 65535.'],
  ])('rejects %s', (value, message) => expect(validatePort(value)).toBe(message));
});

describe('custom zones', () => {
  it.each(['app-zone', 'Zone_2', ' public '])('accepts %s', (value) => expect(validateZoneName(value)).toBeNull());
  it('requires a name', () => expect(validateZoneName(' ')).toBe('Zone name is required.'));
  it.each(['2zone', 'bad zone', 'zone;reboot'])('rejects %s', (value) => {
    expect(validateZoneName(value)).toBe('Zone name must start with a letter and use only letters, numbers, hyphens, or underscores.');
  });
});
