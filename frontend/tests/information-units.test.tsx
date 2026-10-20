import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { InformationUnitsCalculator } from '../src/tools/information-units-calculator/InformationUnitsCalculator';

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('Information Units arithmetic regression', () => {
  it('converts eight bits to one byte', () => {
    render(<InformationUnitsCalculator />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: '8' } });
    const [from, to] = screen.getAllByRole('combobox');
    fireEvent.change(from, { target: { value: 'b' } });
    fireEvent.change(to, { target: { value: 'B' } });
    expect(screen.getByText('1 B', { exact: true })).toBeInTheDocument();
    expect(screen.getByText('1 B/s', { exact: true })).toBeInTheDocument();
  });

  it('preserves a large finite value when converting a unit to itself', () => {
    render(<InformationUnitsCalculator />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: '1e300' } });
    const [from, to] = screen.getAllByRole('combobox');
    fireEvent.change(from, { target: { value: 'PB' } });
    fireEvent.change(to, { target: { value: 'PB' } });

    // An identity conversion must retain the input, irrespective of the unit factor.
    // Format the independent expected value with the environment's locale.
    const expected = new Intl.NumberFormat(undefined, { maximumFractionDigits: 8 }).format(1e300);
    expect(screen.getByText(`${expected} PB`, { exact: true })).toBeInTheDocument();
    expect(screen.getByText(`${expected} PB/s`, { exact: true })).toBeInTheDocument();
  });
});

function configure(value: string, fromUnit: string, toUnit: string) {
  fireEvent.change(screen.getByRole('textbox'), { target: { value } });
  const [from, to] = screen.getAllByRole('combobox');
  fireEvent.change(from, { target: { value: fromUnit } });
  fireEvent.change(to, { target: { value: toUnit } });
}

function expectSafeOutput() {
  const resultPanels = screen.getByText('Converted value', { exact: true }).parentElement!.parentElement!;
  expect(resultPanels.textContent).not.toMatch(/NaN|[-+]?Infinity|\u221e/);
}

describe('Information Units finite results and range limits', () => {
  const units = ['b', 'Kb', 'Mb', 'Gb', 'Tb', 'Pb', 'B', 'KB', 'MB', 'GB', 'TB', 'PB',
    'Kib', 'Mib', 'Gib', 'Tib', 'Pib', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];

  it.each(units)('preserves a large finite identity conversion for %s', (unit) => {
    render(<InformationUnitsCalculator />);
    configure('1e300', unit, unit);
    const expected = new Intl.NumberFormat(undefined, { maximumFractionDigits: 8 }).format(1e300);
    expect(screen.getByText(`${expected} ${unit}`, { exact: true })).toBeInTheDocument();
    expect(screen.getByText(`${expected} ${unit}/s`, { exact: true })).toBeInTheDocument();
    expectSafeOutput();
  });

  it.each([
    ['1', 'KB', 'KiB', '0.9765625'],
    ['1', 'KiB', 'KB', '1.024'],
    ['1', 'MB', 'MiB', '0.95367432'],
    ['1', 'MiB', 'MB', '1.048576'],
    ['1', 'GB', 'GiB', '0.93132257'],
    ['1', 'GiB', 'GB', '1.07374182'],
    ['1', 'TB', 'TiB', '0.9094947'],
    ['1', 'TiB', 'TB', '1.09951163'],
    ['1', 'PB', 'PiB', '0.88817842'],
    ['1', 'PiB', 'PB', '1.12589991'],
    ['1', 'B', 'b', '8'],
    ['1', 'Kib', 'b', '1024'],
    ['0.5', 'MiB', 'KiB', '512'],
  ])('converts %s %s to %s with established precision', (value, from, to, expected) => {
    render(<InformationUnitsCalculator />);
    configure(value, from, to);
    const text = new Intl.NumberFormat(undefined, { maximumFractionDigits: 8 }).format(Number(expected));
    expect(screen.getByText(`${text} ${to}`, { exact: true })).toBeInTheDocument();
    expectSafeOutput();
  });

  it('retains a finite non-identity conversion when the bit intermediate overflows', () => {
    render(<InformationUnitsCalculator />);
    configure('1e300', 'PB', 'TB');
    const expected = new Intl.NumberFormat(undefined, { maximumFractionDigits: 8 }).format(1e303);
    expect(screen.getByText(`${expected} TB`, { exact: true })).toBeInTheDocument();
    for (const pre of document.querySelectorAll('pre')) expect(pre.textContent).toContain('Result exceeds the supported numeric range.');
    expectSafeOutput();
  });

  it('reports genuine converted-result overflow while retaining the input detail', () => {
    render(<InformationUnitsCalculator />);
    configure('1e308', 'PB', 'b');
    expect(screen.getByText('Result exceeds the supported numeric range. (b)', { exact: true })).toBeInTheDocument();
    expect(document.querySelector('pre')!.textContent).toContain(' PB\n');
    expectSafeOutput();
  });

  it('handles the smallest positive identity without avoidable underflow', () => {
    render(<InformationUnitsCalculator />);
    configure('5e-324', 'PiB', 'PiB');
    // Display rounding is unchanged: this positive representable result rounds to zero.
    expect(screen.getByText('0 PiB', { exact: true })).toBeInTheDocument();
    expect(document.querySelector('article')!.textContent).not.toContain('below the supported numeric range');
    expectSafeOutput();
  });

  it.each([Number.MIN_VALUE, 2 ** -1022, Number.MAX_VALUE])('retains the actual finite identity value %s before display rounding', (value) => {
    const OriginalNumberFormat = Intl.NumberFormat;
    const formattedValues: number[] = [];
    vi.spyOn(Intl, 'NumberFormat').mockImplementation(function (locales, options) {
      const formatter = new OriginalNumberFormat(locales, options);
      const format = formatter.format;
      Object.defineProperty(formatter, 'format', { value: (number: number) => {
        formattedValues.push(number);
        return format(number);
      } });
      return formatter;
    });
    const { rerender } = render(<InformationUnitsCalculator />);
    configure(String(value), 'PiB', 'PiB');
    formattedValues.length = 0;
    rerender(<InformationUnitsCalculator />);
    // Inspect the number passed to display formatting, not the rounded zero or grouped text.
    expect(formattedValues.slice(0, 2)).toEqual([value, value]);
    expectSafeOutput();
  });

  it('reports genuinely unrepresentable positive underflow', () => {
    render(<InformationUnitsCalculator />);
    configure('5e-324', 'b', 'PiB');
    expect(screen.getByText('Result is below the supported numeric range. (PiB)', { exact: true })).toBeInTheDocument();
    expectSafeOutput();
  });

  it.each(['0', '-1', '', 'NaN', 'Infinity', 'text'])('rejects invalid input %j and recovers', (value) => {
    render(<InformationUnitsCalculator />);
    configure(value, 'b', 'B');
    expect(screen.getByText('Enter a value greater than zero.')).toBeInTheDocument();
    expect(document.querySelectorAll('pre')).toHaveLength(0);
    configure('8', 'b', 'B');
    expect(screen.getByText('1 B', { exact: true })).toBeInTheDocument();
  });

  it('restores the sample and copies each independent result with its range limitation', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', Object.create(navigator, { clipboard: { value: { writeText } } }));
    render(<InformationUnitsCalculator />);
    const input = screen.getByRole('textbox');
    fireEvent.focus(input); expect(input).toHaveValue('');
    fireEvent.blur(input); expect(input).toHaveValue('1024');
    configure('1e300', 'PB', 'PB');
    const commands = [...document.querySelectorAll('pre')].map((pre) => pre.textContent);
    const buttons = screen.getAllByRole('button', { name: 'Copy' });
    for (const [index, button] of buttons.entries()) {
      await act(async () => fireEvent.click(button));
      expect(writeText).toHaveBeenNthCalledWith(index + 1, commands[index]);
    }
    expectSafeOutput();
  });
});
