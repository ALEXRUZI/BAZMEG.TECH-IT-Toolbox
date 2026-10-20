import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, test, vi } from 'vitest';
import { SshOutputOption } from '../src/tools/ssh-key-generator/SshOutputOption';
import { algorithms, supportedFormats, unsupportedFormatExplanation } from '../src/tools/ssh-key-generator/sshAlgorithms';
import type { OutputFormat } from '../src/tools/ssh-key-generator/sshTypes';

for (const algorithm of algorithms) test(`${algorithm.id} presentation follows serialization metadata`, () => {
  const formats: OutputFormat[] = ['public', 'openssh', 'ppk', 'ssh1'];
  const view = render(<>{formats.map(format => <SshOutputOption key={format} label={format} explanation={unsupportedFormatExplanation(algorithm.id, format)} disabled={!supportedFormats(algorithm.id).includes(format)} checked onChange={() => {}} />)}</>);
  for (const format of formats) {
    const supported = supportedFormats(algorithm.id).includes(format), checkbox = screen.getByRole('checkbox', { name: format });
    if (supported) {
      expect(checkbox).toBeEnabled(); expect(checkbox).toBeChecked();
      expect(screen.getByText(format, { exact: true })).not.toHaveClass('line-through');
      expect(screen.queryByRole('button', { name: `Why ${format} is unavailable` })).toBeNull();
    } else {
      expect(checkbox).toBeDisabled(); expect(checkbox).not.toBeChecked();
      expect(screen.getByText(format, { exact: true })).toHaveClass('line-through', 'opacity-60');
      expect(checkbox).toHaveAccessibleDescription(unsupportedFormatExplanation(algorithm.id, format));
    }
  }
  view.unmount();
});

test('explanations are short, format-specific and do not guess unknown imported algorithms', () => {
  expect(unsupportedFormatExplanation('ed448', 'openssh')).toBe('OpenSSH private-key format is not supported for Ed448.');
  expect(unsupportedFormatExplanation('rsa1', 'openssh')).toBe('OpenSSH private-key format is not supported for SSH-1 RSA.');
  expect(unsupportedFormatExplanation('rsa1', 'ppk')).toBe('PuTTY PPK v3 is not supported for SSH-1 RSA.');
  expect(unsupportedFormatExplanation('ed25519', 'ssh1')).toBe('SSH-1 private-key format is only available for historical SSH-1 RSA keys.');
  for (const id of [undefined, 'unknown']) for (const format of ['openssh', 'ppk', 'ssh1'] as const) expect(unsupportedFormatExplanation(id, format)).toBe('');
});

test('information supports hover, keyboard, click, dismissal and disabled selection', async () => {
  const user = userEvent.setup(), change = vi.fn();
  const explanation = unsupportedFormatExplanation('ed448', 'openssh');
  const view = render(<SshOutputOption label="OpenSSH private" explanation={explanation} disabled checked={false} onChange={change} />);
  const info = screen.getByRole('button', { name: 'Why OpenSSH private is unavailable' });
  expect(info).toHaveAccessibleDescription(explanation);
  expect(screen.queryByRole('tooltip')).toBeNull();
  await user.hover(info); expect(screen.getByRole('tooltip')).toBeVisible();
  await user.unhover(info); expect(screen.queryByRole('tooltip')).toBeNull();
  await user.tab(); expect(info).toHaveFocus(); expect(screen.getByRole('tooltip')).toBeVisible();
  await user.keyboard('{Escape}'); expect(screen.queryByRole('tooltip')).toBeNull(); expect(info).toHaveFocus();
  await user.keyboard('{Enter}'); expect(screen.getByRole('tooltip')).toBeVisible();
  await user.keyboard('{Enter}'); expect(screen.queryByRole('tooltip')).toBeNull();
  await user.keyboard(' '); expect(screen.getByRole('tooltip')).toBeVisible();
  await user.tab(); expect(info).not.toHaveFocus();
  expect(screen.queryByRole('tooltip')).toBeNull();
  await user.click(info); expect(screen.getByRole('tooltip')).toBeVisible();
  await user.click(info); expect(screen.queryByRole('tooltip')).toBeNull();
  await user.click(screen.getByRole('checkbox')); expect(change).not.toHaveBeenCalled();
  view.unmount();
});

for (const [algorithm, label, format] of [['ed448', 'OpenSSH private', 'openssh'], ['rsa1', 'PPK v3 private', 'ppk']] as const) test(`${algorithm} unavailable label shares a continuous hover boundary with its checkbox, icon and tooltip`, async () => {
  const user = userEvent.setup(), change = vi.fn();
  const explanation = unsupportedFormatExplanation(algorithm, format);
  const view = render(<SshOutputOption label={label} explanation={explanation} disabled checked onChange={change} />);
  const text = screen.getByText(label, { exact: true }), checkbox = screen.getByRole('checkbox', { name: label });
  const info = screen.getByRole('button', { name: `Why ${label} is unavailable` });
  await user.hover(text); expect(screen.getByRole('tooltip')).toHaveTextContent(explanation);
  const tooltip = screen.getByRole('tooltip');
  await user.hover(info); expect(tooltip).toBeVisible();
  await user.hover(tooltip); expect(tooltip).toBeVisible();
  await user.hover(checkbox); expect(tooltip).toBeVisible();
  await user.unhover(checkbox); expect(screen.queryByRole('tooltip')).toBeNull();
  await user.click(text); await user.click(checkbox);
  expect(checkbox).toBeDisabled(); expect(checkbox).not.toBeChecked(); expect(change).not.toHaveBeenCalled();
  view.unmount();
});
