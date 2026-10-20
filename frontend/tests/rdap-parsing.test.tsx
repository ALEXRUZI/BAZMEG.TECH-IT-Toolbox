import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { RegistrationOverview } from '../src/tools/rdap-whois/RdapResults';
import { registrationFixture } from '../e2e/fixtures/rdap';
import { normalizedExport } from '../src/tools/rdap-whois/rdapHelpers';

afterEach(cleanup);
it('keeps conflicting primary values out of screen and image, with evidence retained in full exports', () => {
  const result = structuredClone(registrationFixture);
  result.normalized.fields.Expires = ['2030-01-01', '2031-01-01'];
  result.normalized.fields['Registrant name'] = ['Uncertain holder one', 'Uncertain holder two'];
  result.normalized.conflicts = ['Expires', 'Registrant name'];
  result.normalized.details.attribution = { Expires: { state: 'ambiguous', protocol: 'whois', source: result.source, evidence: [
    { value: '2030-01-01', record: 'whois:0', role: 'domain', location: 'line:2', state: 'available' },
    { value: '2031-01-01', record: 'whois:0', role: 'domain', location: 'line:3', state: 'available' },
  ] } };
  for (const image of [false, true]) {
    const view = render(<RegistrationOverview result={result} calculatedAt={0} image={image} />);
    const overview = within(screen.getByRole('heading', { name: 'Registration overview' }).closest('section')!);
    expect(overview.queryByText('Uncertain holder one')).toBeNull();
    expect(overview.queryByText('2030-01-01')).toBeNull();
    expect(overview.getByText('Conflicting expiration values; no calculation')).toBeInTheDocument();
    expect(view.container.querySelectorAll('button')).toHaveLength(0);
    if (image) expect(view.container.querySelector('pre, details')).toBeNull();
    view.unmount();
  }
  expect(normalizedExport(result).normalized.details.attribution).toEqual(result.normalized.details.attribution);
});
it('labels calendar dates without inventing midnight, expiry time or timezone', () => {
  const result = structuredClone(registrationFixture);
  result.normalized.fields.Expires = ['2030-01-01']; result.normalized.fields.Created = ['2000-01-01'];
  render(<RegistrationOverview result={result} calculatedAt={0} image />);
  expect(screen.getByText('2030-01-01 (calendar date)')).toBeInTheDocument();
  expect(screen.getByText('2000-01-01 (calendar date)')).toBeInTheDocument();
  expect(screen.getByText('Calendar date only; exact expiration time and timezone unpublished')).toBeInTheDocument();
});
