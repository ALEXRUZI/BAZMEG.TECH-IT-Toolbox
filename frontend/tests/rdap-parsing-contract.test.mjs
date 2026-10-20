import { afterEach, describe, it, expect } from 'vitest';
import { createElement } from 'react';
import { cleanup, render, within } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseWhois, parseRdap } from '../../backend/src/tools/registration-parse.mjs';
import { validateRegistrationResponse } from '../src/tools/rdap-whois/rdapApi';
import { registrationContactFields, expirationRemaining, overviewValues, publishedDnssec, normalizedExport } from '../src/tools/rdap-whois/rdapHelpers';
import { RegistrationOverview } from '../src/tools/rdap-whois/RdapResults';
import { registrationFixture } from '../e2e/fixtures/rdap';

const raw = (name) => readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../../backend/test/fixtures/registration', name), 'utf8');
const result = (normalized, canonical, protocol) => ({ ...structuredClone(registrationFixture), protocol, source: normalized.details.attribution?.Domain?.source ?? registrationFixture.source, input: { ...registrationFixture.input, canonical }, normalized, outcome: normalized.outcome });
afterEach(cleanup);

describe('actual backend parser to browser validation and overview contract', () => {
  it('renders scoped NSSET output on screen and image while preserving hostile fields in full evidence exports', () => {
    const text = raw('cznic-auxiliary-adversarial-whois.txt');
    const parsed = parseWhois(text, { kind: 'domain', canonical: 'example.cz' }, 'whois://whois.nic.cz:43');
    const value = result(parsed, 'example.cz', 'whois');
    value.rawResponses = [{ protocol: 'whois', phase: 'query', source: value.source, timestamp: value.timestamp, text }];
    expect(validateRegistrationResponse(value)).toEqual(value);
    expect(registrationContactFields(value, 'registrant').Name).toEqual(['Fixture Holder']);
    expect(registrationContactFields(value, 'registrar')['Registrar code']).toEqual(['REG-TEST (Registry registrar ID)']);
    expect(publishedDnssec(value)).toBeNull(); expect(parsed.fields.Status).toBeUndefined();
    for (const image of [false, true]) {
      const view = render(createElement(RegistrationOverview, { result: value, calculatedAt: 0, image }));
      const overview = within(view.getByRole('heading', { name: 'Registration overview' }).closest('section'));
      expect(overview.getByText('Fixture Holder')).toBeInTheDocument();
      expect(overview.getByText('ns1.example.test')).toBeInTheDocument();
      expect(view.container.textContent).not.toMatch(/Auxiliary|AUXILIARY|Keyset|KEYSET|9999|1997-|false-holder/);
      expect(view.container.querySelector('button')).toBeNull();
      if (image) expect(view.container.querySelector('pre, details')).toBeNull();
      view.unmount();
    }
    expect(JSON.stringify(normalizedExport(value))).toContain('AUXILIARY-STATUS');
    expect(JSON.stringify(normalizedExport(value))).toContain('line:11');
    expect(value.rawResponses[0].text).toBe(text);
  });
  it.each(['net', 'cz', 'de', 'uk', 'org', 'tech'])('validates live-derived %s normalized RDAP, retaining evidence without nested contact attribution', (tld) => {
    const parsed = parseRdap(raw(`${tld}-rdap.json`), 'domain', 200, `example.${tld}`);
    const value = result(parsed, `example.${tld}`, 'rdap');
    expect(validateRegistrationResponse(value)).toEqual(value);
    expect(publishedDnssec(value)).not.toBeNull();
    if (tld === 'tech') expect(registrationContactFields(value, 'registrant').Name).toEqual(['Redacted']);
  });
  it('validates SK-NIC object evidence, calendar precision, nameservers and role-separated details', () => {
    const parsed = parseWhois(raw('sknic-whois.txt'), { kind: 'domain', canonical: 'example.sk' }, 'whois://whois.sk-nic.sk:43');
    const value = result(parsed, 'example.sk', 'whois');
    expect(validateRegistrationResponse(value)).toEqual(value);
    expect(overviewValues(value, 'Created')).toEqual(['2003-06-10 (calendar date)']);
    expect(expirationRemaining(value, 0)).toContain('Calendar date only');
    expect(registrationContactFields(value, 'registrar')['Registrar code']).toEqual(['REG-TEST (Registry registrar ID)']);
    expect(parsed.details.attribution['Registrant email'].evidence[0].record).not.toBe(parsed.details.attribution['Registrar email'].evidence[0].record);
  });
  it('keeps unsupported EURid fields separate from explicit redaction and missing registrar email', () => {
    const parsed = parseWhois(raw('eurid-whois.txt'), { kind: 'domain', canonical: 'example.eu' }, 'whois://whois.eu:43');
    const value = result(parsed, 'example.eu', 'whois');
    expect(validateRegistrationResponse(value)).toEqual(value);
    expect(overviewValues(value, 'Expires')).toEqual(['Unsupported field or format; see detailed evidence']);
    expect(registrationContactFields(value, 'registrant').Email).toEqual(['Redacted']);
    expect(registrationContactFields(value, 'registrar').Email).toEqual([]);
  });
  it('rejects malformed attribution states, arrays, provenance and evidence types', () => {
    const parsed = parseWhois(raw('sknic-whois.txt'), { kind: 'domain', canonical: 'example.sk' }, 'whois://whois.sk-nic.sk:43');
    for (const patch of [{ state: 'guessed' }, { protocol: 'http' }, { source: {} }, { evidence: 'text' }, { evidence: [{ value: 42, state: 'available', record: 'r', role: 'registrant', location: 'line:1' }] }]) {
      const value = result(structuredClone(parsed), 'example.sk', 'whois');
      Object.assign(value.normalized.details.attribution['Registrant name'], patch);
      expect(() => validateRegistrationResponse(value)).toThrow('invalid response');
    }
  });
});
