import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PasswordSecretGenerator } from '../src/tools/password-secret-generator/PasswordSecretGenerator';
import { estimatePasswordEntropy, estimatePassphraseEntropy, estimateRecoveryCodeEntropy, formatEntropy, generateRecoveryCodes, getSecretStrength, buildPasswordPool } from '../src/tools/password-secret-generator/passwordGenerator';
import { passwordPresets, passphraseWords, passwordCharacters } from '../src/tools/password-secret-generator/passwordPresets';

// Disposable deterministic output also avoids dumping random credentials on a UI assertion failure.
beforeEach(() => {
  vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => {
    (array as Uint32Array).fill(9);
    return array;
  });
});
afterEach(() => vi.restoreAllMocks());

describe('recovery-code per-code entropy', () => {
  it('counts eight random characters, not the formatting hyphen or list size', () => {
    expect(estimateRecoveryCodeEntropy('digits')).toBeCloseTo(26.5754247591);
    expect(formatEntropy(estimateRecoveryCodeEntropy('digits'))).toBe('26.6 bits');
    expect(estimateRecoveryCodeEntropy('alphanumeric')).toBe(40);
  });

  it('keeps entropy and strength unchanged at every count and updates for format', () => {
    render(<PasswordSecretGenerator />);
    fireEvent.click(screen.getByRole('button', { name: 'Recovery codes' }));
    for (const format of ['digits', 'alphanumeric'] as const) {
      fireEvent.change(screen.getByLabelText('Format'), { target: { value: format } });
      for (const count of [5, 10, 20]) {
        fireEvent.change(screen.getByLabelText('Code count'), { target: { value: String(count) } });
        expect(screen.getByText('Entropy per code').parentElement?.textContent?.includes(formatEntropy(estimateRecoveryCodeEntropy(format)))).toBe(true);
        expect(screen.getByText(`${getSecretStrength(estimateRecoveryCodeEntropy(format)).label} per code`)).toBeVisible();
        const codes = document.querySelector('pre')?.textContent?.trim().split('\n') ?? [];
        expect(codes.length).toBe(count);
        const pattern = format === 'digits' ? /^\d{4}-\d{4}$/ : /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$/;
        expect(codes.every((code) => pattern.test(code))).toBe(true);
      }
    }
    expect(screen.getByText(/individually usable one-time credential/)).toHaveTextContent(/server-side online attempt limits, single-use enforcement, and secure storage/);
    expect(screen.getByText(/More simultaneously valid codes/)).toHaveTextContent(/do not strengthen each code/);
    expect(screen.getByText(/not an authentication-system security/)).toBeVisible();
  });

  it('preserves rejection sampling, alphabet, grouping and code counts', () => {
    let calls = 0;
    const random = vi.spyOn(crypto, 'getRandomValues').mockImplementation((array) => {
      (array as Uint32Array)[0] = calls++ === 0 ? 0xffffffff : 9;
      return array;
    });
    const digits = generateRecoveryCodes(5, 'digits');
    expect(digits.length).toBe(5);
    expect(digits.every((code) => code === '9999-9999')).toBe(true);
    expect(random).toHaveBeenCalledTimes(41); // Rejected first draw plus 5 * 8 accepted draws.
    random.mockImplementation((array) => { (array as Uint32Array)[0] = 31; return array; });
    for (const count of [5, 10, 20] as const) {
      const codes = generateRecoveryCodes(count, 'alphanumeric');
      expect(codes.length).toBe(count);
      expect(codes.every((code) => code === '9999-9999')).toBe(true);
    }
  });

  it('leaves other modes entropy calculations and displayed estimates unchanged', () => {
    expect(estimatePasswordEntropy(20, 10)).toBe(20 * Math.log2(10));
    expect(estimatePassphraseEntropy(4, 'random', true, true)).toBe(4 * Math.log2(passphraseWords.length) + 4 + Math.log2(10) + Math.log2(passwordCharacters.safeSymbols.length));
    render(<PasswordSecretGenerator />);
    const entropyText = () => screen.getByText('Entropy estimate').parentElement?.textContent ?? '';
    expect(entropyText().includes(formatEntropy(estimatePasswordEntropy(passwordPresets.general.length, buildPasswordPool({ preset: 'general', ...passwordPresets.general }).length)))).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Passphrase' }));
    expect(entropyText().includes(formatEntropy(estimatePassphraseEntropy(4, 'lowercase', false, false)))).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'PIN' }));
    expect(entropyText().includes(formatEntropy(6 * Math.log2(10)))).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'API key / token' }));
    expect(entropyText().includes('256 bits')).toBe(true);
    const selects = screen.getAllByRole('combobox');
    for (const bits of [128, 192, 256]) {
      fireEvent.change(selects[0], { target: { value: String(bits) } });
      expect(entropyText().includes(`${bits} bits`)).toBe(true);
    }
    fireEvent.change(selects[1], { target: { value: 'uuid' } });
    expect(entropyText().includes('122 bits')).toBe(true);
  });
});
