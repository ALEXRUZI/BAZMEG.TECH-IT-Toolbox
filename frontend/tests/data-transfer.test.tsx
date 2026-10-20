import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DataTransferCalculator } from '../src/tools/data-transfer-calculator/DataTransferCalculator';

afterEach(() => vi.unstubAllGlobals());

describe('Data Transfer arithmetic regression', () => {
  it('renders the default transfer duration', () => {
    render(<DataTransferCalculator />);
    expect(screen.getByText('4 min 27 sec', { exact: true })).toBeInTheDocument();
  });

  it('preserves a finite duration when finite inputs overflow intermediate unit conversions', () => {
    render(<DataTransferCalculator />);
    const [size, speed] = screen.getAllByRole('textbox');
    const [sizeUnit, speedUnit] = screen.getAllByRole('combobox');
    fireEvent.change(size, { target: { value: '1e300' } });
    fireEvent.change(sizeUnit, { target: { value: 'PB' } });
    fireEvent.change(speed, { target: { value: '1e300' } });
    fireEvent.change(speedUnit, { target: { value: 'Gbps' } });

    // Equal input magnitudes cancel: (8 * 10^15) / 10^9 = 8,000,000 seconds.
    expect(screen.getByText('92 d 14 h 13 min 20 sec', { exact: true })).toBeInTheDocument();
  });
});

function setField(label: string, value: string) {
  const input = screen.getByRole('textbox', { name: label });
  fireEvent.change(input, { target: { value } });
}

function setUnits(first: string, second: string) {
  const selects = screen.getAllByRole('combobox');
  fireEvent.change(selects[0], { target: { value: first } });
  fireEvent.change(selects[1], { target: { value: second } });
}

function numberText(value: number) {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(value);
}

function readFormattedNumber(text: string) {
  const parts = new Intl.NumberFormat().formatToParts(12345.6);
  const group = parts.find((part) => part.type === 'group')?.value ?? ',';
  const decimal = parts.find((part) => part.type === 'decimal')?.value ?? '.';
  return Number(text.replaceAll(group, '').replace(decimal, '.'));
}

function details() { return document.querySelector('pre')!.textContent!; }
function expectSafeOutput() {
  expect(document.querySelector('article')!.textContent).not.toMatch(/NaN|[-+]?Infinity|\u221e/);
}

describe('Data Transfer stable arithmetic across modes', () => {
  it.each([
    ['speed', '15,015,015.02 bps\n15.02 Mbps\n1.88 MB/s'],
    ['size', '499.5 MB\n0.5 GB\n0 TB\n0 PB\n0 PiB'],
  ])('preserves ordinary default %s output', (mode, expected) => {
    render(<DataTransferCalculator />);
    fireEvent.click(screen.getByRole('button', { name: new RegExp(`Find ${mode}`) }));
    const parts = new Intl.NumberFormat().formatToParts(12345.6);
    const group = parts.find((part) => part.type === 'group')?.value ?? ',';
    const decimal = parts.find((part) => part.type === 'decimal')?.value ?? '.';
    expect(details()).toBe(expected.replaceAll(',', '__GROUP__').replaceAll('.', decimal).replaceAll('__GROUP__', group));
  });

  it.each([
    ['1', 'GB', '1', 'MB/s', 1000, '16 min 40 sec'],
    ['1', 'GiB', '1', 'Mbps', 8589.934592, '2 h 23 min 10 sec'],
    ['8', 'b', '1', 'B/s', 1, '1 sec'],
    ['1e-300', 'b', '1e-300', 'bps', 1, '1 sec'],
    ['5e-324', 'b', '5e-324', 'bps', 1, '1 sec'],
  ])('finds time for %s %s at %s %s', (size, sizeUnit, speed, speedUnit, seconds, duration) => {
    render(<DataTransferCalculator />);
    setField('File size', size); setField('Transfer speed', speed); setUnits(sizeUnit, speedUnit);
    expect(screen.getByText(duration, { exact: true })).toBeInTheDocument();
    expect(details()).toBe(`${numberText(Number(seconds))} seconds\n${numberText(Number(seconds) / 60)} minutes\n${numberText(Number(seconds) / 3600)} hours`);
    expectSafeOutput();
  });

  it.each([
    ['1e300', 'PB', '1e300', 'days', 92592592592.59259],
    ['1e300', 'PB', '1e308', 'days', 925.9259259259259],
    ['1e-300', 'PB', '1e-300', 'seconds', 8e15],
    ['1', 'GiB', '1', 'hours', 2386092.942222222],
    ['1', 'MB', '1', 'minutes', 133333.33333333333],
  ])('finds speed for %s %s in %s %s', (size, sizeUnit, time, timeUnit, bps) => {
    render(<DataTransferCalculator />);
    fireEvent.click(screen.getByRole('button', { name: /Find speed/ }));
    setField('File size', size); setField('Transfer time', time); setUnits(sizeUnit, timeUnit);
    expect(details()).toBe(`${numberText(Number(bps))} bps\n${numberText(Number(bps) / 1e6)} Mbps\n${numberText(Number(bps) / 8e6)} MB/s`);
    expectSafeOutput();
  });

  it('retains finite Mbps and MB/s when supplementary bps exceeds the range', () => {
    render(<DataTransferCalculator />);
    fireEvent.click(screen.getByRole('button', { name: /Find speed/ }));
    setField('File size', '1e299'); setField('Transfer time', '1'); setUnits('GB', 'seconds');
    expect(screen.getByText(`${numberText(8e302)} Mbps`, { exact: true })).toBeInTheDocument();
    expect(details()).toContain('Result exceeds the supported numeric range. (bps)');
    expect(details()).toContain(`${numberText(1e302)} MB/s`);
    expectSafeOutput();
  });

  it.each([
    ['1', 'Mbps', '1', 'days', 10.8],
    ['1', 'B/s', '1', 'seconds', 1e-9],
    ['1e300', 'Gbps', '1', 'seconds', 1.25e299],
    ['1e200', 'Gbps', '1e100', 'seconds', 1.25e299],
    ['1e-300', 'GB/s', '1e-25', 'days', 8.64e-321],
  ])('finds size at %s %s for %s %s', (speed, speedUnit, time, timeUnit, gigabytes) => {
    render(<DataTransferCalculator />);
    fireEvent.click(screen.getByRole('button', { name: /Find size/ }));
    setField('Transfer speed', speed); setField('Transfer time', time); setUnits(speedUnit, timeUnit);
    const primary = screen.getByText('Transferable data size', { exact: true }).nextElementSibling!.textContent!;
    if (Number(gigabytes) > 1e100) {
      // Binary64 multiplication can differ by a few ULPs; allow 1e-12 relative error, not overflow.
      const actual = readFormattedNumber(primary.replace(/ GB$/, ''));
      expect(Number.isFinite(actual)).toBe(true);
      expect(actual / Number(gigabytes)).toBeCloseTo(1, 12);
    } else {
      expect(primary).toBe(`${numberText(Number(gigabytes))} GB`);
    }
    expect(primary).not.toContain('below the supported numeric range');
    if (Number(gigabytes) < 1e-320) {
      // The GB value is representable, but its PB and PiB equivalents genuinely underflow.
      expect(details()).toContain('Result is below the supported numeric range. (PB)');
      expect(details()).toContain('Result is below the supported numeric range. (PiB)');
    }
    expectSafeOutput();
  });

  it.each(['time', 'speed', 'size'])('reports genuinely unrepresentable %s results without invalid numbers', (mode) => {
    render(<DataTransferCalculator />);
    if (mode !== 'time') fireEvent.click(screen.getByRole('button', { name: new RegExp(`Find ${mode}`) }));
    if (mode === 'time') {
      setField('File size', '1e308'); setField('Transfer speed', '5e-324'); setUnits('PB', 'bps');
    } else if (mode === 'speed') {
      setField('File size', '1e308'); setField('Transfer time', '5e-324'); setUnits('PB', 'seconds');
    } else {
      setField('Transfer speed', '1e308'); setField('Transfer time', '1e308'); setUnits('Gbps', 'days');
    }
    expect(details()).toContain('Result exceeds the supported numeric range.');
    expectSafeOutput();
  });

  it('distinguishes true underflow from formatting a representable tiny duration as zero', () => {
    render(<DataTransferCalculator />);
    setField('File size', '5e-324'); setField('Transfer speed', '1e308'); setUnits('b', 'Gbps');
    expect(screen.getByText('Result is below the supported numeric range.', { exact: true })).toBeInTheDocument();
    setField('File size', '1e-300'); setField('Transfer speed', '1'); setUnits('b', 'bps');
    expect(screen.getByText('0 sec', { exact: true })).toBeInTheDocument();
    expect(details()).not.toContain('below the supported numeric range');
    expectSafeOutput();
  });

  it.each(['0', '-1', '', 'abc', 'NaN', 'Infinity', '-Infinity'])('rejects invalid numeric input %j and recovers', (value) => {
    render(<DataTransferCalculator />);
    setField('File size', value);
    expect(screen.getByText('Enter a file size greater than zero.')).toBeInTheDocument();
    expect(document.querySelector('pre')).toBeNull();
    setField('File size', '500');
    expect(screen.getByText('4 min 27 sec', { exact: true })).toBeInTheDocument();
  });

  it.each(['0', '-1', '', 'NaN', 'Infinity'])('validates speed and duration input %j independently', (value) => {
    render(<DataTransferCalculator />);
    setField('Transfer speed', value);
    expect(screen.getByText('Enter a transfer speed greater than zero.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Find speed/ }));
    setField('Transfer time', value);
    expect(screen.getByText('Enter a transfer time greater than zero.')).toBeInTheDocument();
    expect(document.querySelector('pre')).toBeNull();
  });

  it('preserves mode state, sample restoration and clipboard details', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', Object.create(navigator, { clipboard: { value: { writeText } } }));
    render(<DataTransferCalculator />);
    const size = screen.getAllByRole('textbox')[0];
    fireEvent.focus(size); expect(size).toHaveValue('');
    fireEvent.blur(size); expect(size).toHaveValue('500');
    setField('File size', '1'); setUnits('GB', 'Mbps');
    fireEvent.click(screen.getByRole('button', { name: /Find speed/ }));
    expect(screen.getAllByRole('textbox')[0]).toHaveValue('1');
    fireEvent.click(screen.getByRole('button', { name: /Find time/ }));
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Copy' })));
    expect(writeText).toHaveBeenCalledWith(details());
  });
});
