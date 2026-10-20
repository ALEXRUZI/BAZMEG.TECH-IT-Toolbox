import { useState } from 'react';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ExampleTextInput, Field, FieldDescription, FieldError, FieldInput, FieldSelect, FieldTextarea, HelpTooltip, Label } from '../src/components/Panel';
import { CsrGenerator } from '../src/tools/csr-generator/CsrGenerator';
import { DnsChecker } from '../src/tools/dns-checker/DnsChecker';
import { JsonYamlFormatter } from '../src/tools/json-yaml-formatter/JsonYamlFormatter';

describe('AUD-019 shared field associations', () => {
  it('names native controls, focuses through labels, and gives repeated instances unique stable IDs', async () => {
    const user = userEvent.setup();
    function Fields() {
      return <><Field><Label>Target</Label><div><FieldInput /></div></Field>
        <Field><Label>Mode</Label><FieldSelect><option>A</option></FieldSelect></Field>
        <Field><Label>Content</Label><FieldTextarea /></Field></>;
    }
    const { container, rerender } = render(<><Fields /><Fields /></>);
    const controls = [...container.querySelectorAll('input, select, textarea')];
    const ids = controls.map((control) => control.id);
    expect(new Set(ids).size).toBe(6);
    expect(ids.every(Boolean)).toBe(true);
    for (const label of container.querySelectorAll('label')) {
      await user.click(label);
      expect(document.getElementById(label.htmlFor)).toHaveFocus();
    }
    expect(screen.getAllByRole('textbox', { name: 'Target' })).toHaveLength(2);
    expect(screen.getAllByRole('combobox', { name: 'Mode' })).toHaveLength(2);
    expect(screen.getAllByRole('textbox', { name: 'Content' })).toHaveLength(2);
    rerender(<><Fields /><Fields /></>);
    expect([...container.querySelectorAll('input, select, textarea')].map((control) => control.id)).toEqual(ids);
  });

  it('merges existing descriptions, helper text and changing errors without stale references', () => {
    function Example({ error }: { error: string }) {
      return <><p id="external-help">External help</p><Field error={error} description="Field help">
        <Label>Value</Label><FieldInput aria-describedby="external-help" />
        <FieldError /><FieldDescription />
      </Field></>;
    }
    const { rerender } = render(<Example error="Invalid value" />);
    const input = screen.getByRole('textbox', { name: 'Value' });
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('External help Invalid value Field help');
    const id = input.id;
    rerender(<Example error="" />);
    expect(input.id).toBe(id);
    expect(input).not.toHaveAttribute('aria-invalid');
    expect(input).toHaveAccessibleDescription('External help Field help');
    expect(document.getElementById(`${id}-error`)).toBeNull();
  });

  it('preserves caller-owned explicit IDs and native properties', () => {
    render(<Field id="explicit"><Label>Amount</Label><FieldInput id="explicit" type="number" min={1} autoComplete="off" disabled /></Field>);
    expect(screen.getByRole('spinbutton', { name: 'Amount' })).toHaveAttribute('id', 'explicit');
    expect(screen.getByLabelText('Amount')).toBeDisabled();
    expect(screen.getByLabelText('Amount')).toHaveAttribute('autocomplete', 'off');
  });

  it('preserves example-value focus, editing and blur behavior', async () => {
    const user = userEvent.setup();
    function Example() {
      const [value, setValue] = useState('');
      return <Field><Label>Domain</Label><ExampleTextInput value={value} example="example.com" onChange={setValue} /></Field>;
    }
    render(<Example />);
    const input = screen.getByRole('textbox', { name: 'Domain' });
    expect(input).toHaveValue('example.com');
    await user.click(screen.getByText('Domain', { selector: 'label' }));
    expect(input).toHaveFocus();
    expect(input).toHaveValue('');
    await user.tab();
    expect(input).toHaveValue('example.com');
    await user.click(input);
    await user.type(input, 'example.test');
    await user.tab();
    expect(input).toHaveValue('example.test');
  });
});

describe('AUD-019 help disclosure', () => {
  it('dismisses on keyboard blur despite active hover, then reopens on fresh entry or focus', async () => {
    const user = userEvent.setup();
    render(<><HelpTooltip label="Help with ports" text="Use a supported port." /><button type="button">Next</button></>);
    const help = screen.getByRole('button', { name: 'Help with ports' });
    await user.hover(help);
    expect(help).toHaveAttribute('aria-expanded', 'true');
    await user.tab();
    expect(help).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Next' })).toHaveFocus();
    expect(help).toHaveAttribute('aria-expanded', 'false');
    await user.unhover(help);
    expect(help).toHaveAttribute('aria-expanded', 'false');
    await user.hover(help);
    expect(help).toHaveAttribute('aria-expanded', 'true');
    await user.unhover(help);
    await user.tab({ shift: true });
    expect(help).toHaveFocus();
    expect(help).toHaveAttribute('aria-expanded', 'true');
  });

  it('supports Tab, Space, Enter, Escape, hover and blur without submitting a form', async () => {
    const user = userEvent.setup();
    const submit = vi.fn((event) => event.preventDefault());
    render(<form onSubmit={submit}><HelpTooltip label="Help with ports" text="Use a supported port." /><button type="button">Next</button></form>);
    const help = screen.getByRole('button', { name: 'Help with ports' });
    await user.tab();
    expect(help).toHaveFocus();
    expect(help).toHaveAccessibleDescription('Use a supported port.');
    expect(help).toHaveAttribute('aria-expanded', 'true');
    await user.keyboard(' ');
    await user.keyboard('{Escape}');
    expect(help).toHaveAttribute('aria-expanded', 'false');
    await user.keyboard('{Enter}');
    expect(help).toHaveAttribute('aria-expanded', 'true');
    await user.tab();
    expect(screen.getByRole('button', { name: 'Next' })).toHaveFocus();
    expect(help).toHaveAttribute('aria-expanded', 'false');
    await user.hover(help);
    expect(help).toHaveAttribute('aria-expanded', 'true');
    await user.unhover(help);
    expect(help).toHaveAttribute('aria-expanded', 'false');
    expect(submit).not.toHaveBeenCalled();
  });
});

describe('AUD-019 representative tool errors and conditional fields', () => {
  it('labels dynamic SANs individually and retains email validation associations', async () => {
    const user = userEvent.setup();
    render(<CsrGenerator />);
    await user.click(screen.getByRole('button', { name: 'Add SAN' }));
    const first = screen.getByRole('textbox', { name: 'SAN 1' });
    const second = screen.getByRole('textbox', { name: 'SAN 2' });
    expect(first.id).not.toBe(second.id);
    await user.clear(second);
    await user.type(second, 'bad..name');
    expect(second).toHaveAttribute('aria-invalid', 'true');
    expect(second).toHaveAccessibleDescription();
    await user.click(screen.getByRole('button', { name: 'Remove SAN 2' }));
    expect(screen.queryByRole('textbox', { name: 'SAN 2' })).toBeNull();
    await user.type(screen.getByLabelText('Email'), 'invalid');
    expect(screen.getByLabelText('Email')).toHaveAccessibleDescription('Enter a valid email address.');
    await user.click(screen.getByRole('button', { name: /Advanced export format/ }));
    await user.click(screen.getByRole('radio', { name: /Encrypted PKCS#8/ }));
    expect(screen.getByLabelText('Encryption password *')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByLabelText('Encryption password *')).toHaveAccessibleDescription('Password is required for encrypted private key export.');
    // No secrets are generated or entered in this test.
  });

  it('connects DNS shared validation to each affected SRV and DKIM input', async () => {
    const user = userEvent.setup();
    render(<DnsChecker />);
    await user.selectOptions(screen.getByRole('combobox', { name: 'Record type' }), 'SRV');
    await user.type(screen.getByLabelText('Service'), 'bad..service');
    for (const name of ['Service', 'Domain']) {
      expect(screen.getByLabelText(name)).toHaveAttribute('aria-invalid', 'true');
      expect(screen.getByLabelText(name)).toHaveAccessibleDescription();
    }
    await user.selectOptions(screen.getByRole('combobox', { name: 'Record type' }), 'TXT');
    await user.selectOptions(screen.getByRole('combobox', { name: 'TXT helper' }), 'dkim');
    await user.type(screen.getByLabelText('Selector'), 'bad..selector');
    expect(screen.getByLabelText('Selector')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByLabelText('Selector')).toHaveAccessibleDescription();
    expect(screen.getByLabelText('Domain')).toHaveAccessibleDescription();
  });

  it('preserves JSON/YAML explicit names and error recovery', async () => {
    const user = userEvent.setup();
    render(<JsonYamlFormatter />);
    const input = screen.getByRole('textbox', { name: 'Input' });
    await user.clear(input);
    await user.type(input, 'invalid');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription();
    expect(within(document.body).getByRole('combobox', { name: 'Indent' })).toBeInTheDocument();
    await user.clear(input);
    await user.paste('{"valid":true}');
    expect(input).toHaveAttribute('aria-invalid', 'false');
    expect(input).not.toHaveAttribute('aria-describedby');
  });
});
