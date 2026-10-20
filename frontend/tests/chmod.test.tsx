import { fireEvent, render, screen, within } from '@testing-library/react';
import { spawnSync } from 'node:child_process';
import { describe, expect, it, vi } from 'vitest';
import { ChmodCalculator } from '../src/tools/chmod-calculator/ChmodCalculator';

const groups = ['owner', 'group', 'others'];
const digitBits = [[], ['Execute'], ['Write'], ['Write', 'Execute'], ['Read'], ['Read', 'Execute'], ['Read', 'Write'], ['Read', 'Write', 'Execute']];

function setDigit(group: string, digit: number) {
  const container = screen.getByRole('group', { name: group });
  for (const bit of ['Read', 'Write', 'Execute']) {
    const control = within(container).getByRole<HTMLInputElement>('checkbox', { name: bit });
    if (control.checked !== digitBits[digit].includes(bit)) fireEvent.click(control);
  }
}

function command() { return document.querySelector('pre')?.textContent; }

// Only the harmless function runs: no chmod binary and no external commands on PATH.
function shellArguments(command: string) {
  const result = spawnSync('/bin/sh', ['-c', `PATH=''
chmod() { printf '%s\\0' "$@"; }
touch() { printf 'Unexpected command substitution' >&2; }
${command}`], { encoding: 'utf8', timeout: 2000 });
  expect(result.status).toBe(0);
  expect(result.stderr).toBe('');
  expect(result.stdout.endsWith('\0')).toBe(true);
  return result.stdout.split('\0').slice(0, -1);
}

describe('chmod command regression', () => {
  it('defaults to 755 and the sample path', () => {
    render(<ChmodCalculator />);
    expect(command()).toBe("chmod 755 -- '/var/www/html'");
    expect(screen.getAllByRole('checkbox').map((box) => (box as HTMLInputElement).checked)).toEqual([true, true, true, true, false, true, true, false, true]);
  });

  for (const [index, group] of groups.entries()) {
    it.each([0, 1, 2, 3, 4, 5, 6, 7])(`independently sets ${group} to %i`, (digit) => {
      render(<ChmodCalculator />);
      setDigit(group, digit);
      const expected = ['7', '5', '5'];
      expected[index] = String(digit);
      expect(command()).toBe(`chmod ${expected.join('')} -- '/var/www/html'`);
      groups.forEach((name, i) => {
        const container = screen.getByRole('group', { name });
        for (const bit of ['Read', 'Write', 'Execute']) {
          expect(within(container).getByRole<HTMLInputElement>('checkbox', { name: bit }).checked).toBe(digitBits[Number(expected[i])].includes(bit));
        }
      });
    });
  }

  it.each(['644', '600', '700', '777', '000'])('generates mode %s with simultaneous group changes', (mode) => {
    render(<ChmodCalculator />);
    groups.forEach((group, i) => setDigit(group, Number(mode[i])));
    expect(command()).toBe(`chmod ${mode} -- '/var/www/html'`);
  });

  it.each([
    'file name.txt', "it's a file", '$(touch /tmp/example)', 'file; echo test', '-recursive',
    'line one\nline two', '  leading and trailing  ', '\t tab\t', '"double quotes"',
    '`touch /tmp/example`', '(file) & * ? > < | # $HOME', 'c:\\files\\name', '文件-é-🔒', '   ',
  ])('preserves exact shell argument boundaries for %j', (path) => {
    render(<ChmodCalculator />);
    const input = screen.getByRole('textbox');
    fireEvent.change(input, { target: { value: path } });
    fireEvent.blur(input);
    expect(input).toHaveValue(path);
    expect(shellArguments(command()!)).toEqual(['755', '--', path]);
  });

  it('clears the example on focus, suppresses incomplete commands, and restores on blur', () => {
    render(<ChmodCalculator />);
    const input = screen.getByRole('textbox');
    fireEvent.focus(input);
    expect(input).toHaveValue('');
    expect(command()).toBeUndefined();
    expect(screen.getByRole('status')).toHaveTextContent('Enter a path');
    expect(screen.queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
    fireEvent.blur(input);
    expect(input).toHaveValue('/var/www/html');
    expect(command()).toBe("chmod 755 -- '/var/www/html'");
  });

  it('copies the exact safely quoted command', () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    try {
      render(<ChmodCalculator />);
      fireEvent.change(screen.getByRole('textbox'), { target: { value: "  it's $HOME\nfile  " } });
      const generated = command()!;
      fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
      expect(writeText).toHaveBeenCalledWith(generated);
      expect(shellArguments(generated)).toEqual(['755', '--', "  it's $HOME\nfile  "]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('rejects NUL, which cannot be represented in a Linux filename', () => {
    render(<ChmodCalculator />);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'a\0b' } });
    expect(command()).toBeUndefined();
    expect(screen.getByRole('status')).toHaveTextContent('NUL');
    expect(screen.queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
  });
});
