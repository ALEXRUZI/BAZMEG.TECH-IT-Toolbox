import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EpochTool } from '../src/tools/epoch-converter/EpochTool';

function field(label: string, tag: 'input' | 'select' = 'input') {
  return screen.getByRole(tag === 'select' ? 'combobox' : 'textbox', { name: label });
}

function conversion() {
  const element = screen.getByRole('heading', { name: 'Timestamp to local time' }).parentElement;
  if (!element) throw new Error('Missing timestamp conversion section');
  return element;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
});
afterEach(() => vi.useRealTimers());

describe('Epoch timestamp range validation', () => {
  // ISO output is timezone-independent; browser tests separately pin local time to UTC.
  it.each([
    ['seconds', '8640000000000', '+275760-09-13T00:00:00.000Z'],
    ['milliseconds', '8640000000000000', '+275760-09-13T00:00:00.000Z'],
    ['seconds', '-8640000000000', '-271821-04-20T00:00:00.000Z'],
    ['milliseconds', '-8640000000000000', '-271821-04-20T00:00:00.000Z'],
    ['seconds', '0', '1970-01-01T00:00:00.000Z'],
    ['milliseconds', '0', '1970-01-01T00:00:00.000Z'],
    ['seconds', '1704067200', '2024-01-01T00:00:00.000Z'],
    ['milliseconds', '1704067200000', '2024-01-01T00:00:00.000Z'],
    ['seconds', '-1', '1969-12-31T23:59:59.000Z'],
    ['milliseconds', '-1000', '1969-12-31T23:59:59.000Z'],
    ['seconds', '0.001', '1970-01-01T00:00:00.001Z'],
    ['seconds', '1e3', '1970-01-01T00:16:40.000Z'],
    ['seconds', '0x3e8', '1970-01-01T00:16:40.000Z'],
    ['milliseconds', ' +1000 ', '1970-01-01T00:00:01.000Z'],
  ])('preserves %s conversion for %s', (unit, timestamp, iso) => {
    render(<EpochTool />);
    fireEvent.change(field('Unit', 'select'), { target: { value: unit } });
    fireEvent.change(field('Unix timestamp'), { target: { value: timestamp } });
    expect(conversion().querySelector('pre')?.textContent?.split('\n').at(-1)).toBe(iso);
    expect(screen.queryByText('Unix timestamp is outside the supported date range.')).not.toBeInTheDocument();
  });

  it.each([
    ['seconds', '8640000000001'], ['milliseconds', '8640000000000001'],
    ['seconds', '-8640000000001'], ['milliseconds', '-8640000000000001'],
    ['seconds', '1e308'], ['milliseconds', '1e308'],
  ])('rejects out-of-range %s value %s and recovers', (unit, timestamp) => {
    render(<EpochTool />);
    fireEvent.change(field('Unit', 'select'), { target: { value: unit } });
    fireEvent.change(field('Unix timestamp'), { target: { value: timestamp } });
    expect(screen.getByText('Unix timestamp is outside the supported date range.')).toBeVisible();
    expect(conversion().querySelector('pre')).toBeNull();
    expect(screen.getByRole('heading', { name: 'Epoch & Unix timestamp conversion' })).toBeVisible();
    fireEvent.change(field('Unix timestamp'), { target: { value: '0' } });
    expect(conversion().querySelector('pre')?.textContent).toContain('1970-01-01T00:00:00.000Z');
  });

  it.each(['', ' ', 'not-a-number', 'NaN', 'Infinity', '-Infinity', '1e309'])('preserves the numeric error for %j', (timestamp) => {
    render(<EpochTool />);
    fireEvent.change(field('Unix timestamp'), { target: { value: timestamp } });
    expect(screen.getByText('Unix timestamp must be a number.')).toBeVisible();
    expect(conversion().querySelector('pre')).toBeNull();
    expect(screen.queryByText('Unix timestamp is outside the supported date range.')).not.toBeInTheDocument();
  });
});
