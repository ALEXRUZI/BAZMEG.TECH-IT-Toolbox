import { spawnSync } from 'node:child_process';
import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { FirewallGenerator } from '../src/tools/ufw-generator/UfwGenerator';
import { NftablesGenerator } from '../src/tools/nftables-generator/NftablesGenerator';
import { FirewalldGenerator } from '../src/tools/firewalld-generator/FirewalldGenerator';
import { FirewalldZonesBlock } from '../src/tools/firewalld-generator/FirewalldZonesBlock';

// Query the control's actual accessible name.
function field(label: string, tag: 'input' | 'select' = 'input') {
  return screen.getByRole(tag === 'select' ? 'combobox' : 'textbox', { name: label });
}
function commands() {
  return [...document.querySelectorAll('pre')].map((element) => element.textContent);
}

// Independent POSIX tokenization, never executes firewall commands.
function shellTokens(value: string) {
  const result = spawnSync('python3', ['-c', 'import json, shlex, sys; print(json.dumps(shlex.split(sys.argv[1])))', value], {
    encoding: 'utf8', timeout: 2000,
  });
  expect(result.status).toBe(0);
  return JSON.parse(result.stdout) as string[];
}

function richPanel() {
  return screen.getByRole('heading', { name: 'Firewalld rich-rule generator' }).closest('article')!;
}

function richCommands() {
  return [...richPanel().querySelectorAll('pre')].map((element) => element.textContent!);
}

function validateRichRule(rule: string) {
  // Optional upstream offline parser; no daemon or firewall operations.
  if (process.env.FIREWALLD_PYTHONPATH) {
    const result = spawnSync('python3', ['-c',
      'import sys; from firewall.core.rich import Rich_Rule; Rich_Rule(rule_str=sys.argv[1]).check()', rule,
    ], { encoding: 'utf8', timeout: 2000, env: { ...process.env, PYTHONPATH: process.env.FIREWALLD_PYTHONPATH } });
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
  }
  return shellTokens(rule);
}

describe('UFW commands', () => {
  it.each([
    ['tcp', 'sudo ufw allow proto tcp from 10.20.30.40/32 to any port 2049'],
    ['udp', 'sudo ufw allow proto udp from 10.20.30.40/32 to any port 2049'],
  ])('formats %s', async (protocol, expected) => {
    render(<FirewallGenerator />);
    await userEvent.selectOptions(field('Protocol', 'select'), protocol);
    expect(commands()).toEqual([expected]);
  });
  it('includes optional source port and destination restrictions', async () => {
    render(<FirewallGenerator />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('checkbox', { name: 'Add source port' }));
    await user.click(screen.getByRole('checkbox', { name: 'Add destination IPv4' }));
    await user.type(field('Source IPv4'), '192.0.2.0/24');
    await user.type(field('Source port'), '1234');
    await user.type(field('Destination IPv4'), '198.51.100.8');
    await user.type(field('Destination port'), '443');
    expect(commands()).toEqual(['sudo ufw allow proto tcp from 192.0.2.0/24 port 1234 to 198.51.100.8 port 443']);
  });
  it.each(['tcp', 'udp'])('suppresses ICMP and restores %s with all restrictions', async (protocol) => {
    render(<FirewallGenerator />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('checkbox', { name: 'Add source port' }));
    await user.click(screen.getByRole('checkbox', { name: 'Add destination IPv4' }));
    await user.selectOptions(field('Protocol', 'select'), 'icmp');
    expect(screen.getByRole('status')).toHaveTextContent('standard UFW CLI does not support');
    expect(screen.getByRole('status')).toHaveTextContent('/etc/ufw/before.rules');
    expect(screen.getByRole('status')).toHaveTextContent('existing firewall policy');
    expect(commands()).toEqual([]);
    expect(screen.queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
    await user.selectOptions(field('Protocol', 'select'), protocol);
    expect(shellTokens(commands()[0]!)).toEqual([
      'sudo', 'ufw', 'allow', 'proto', protocol, 'from', '10.20.30.40/32', 'port', '2049',
      'to', '10.20.30.40/32', 'port', '2049',
    ]);
  });
  it.each([
    ['Source IPv4', '192.0.2.1; echo injected'], ['Destination IPv4', '198.51.100.1$(echo injected)'],
    ['Source port', '22; echo injected'], ['Destination port', '443`echo injected`'],
    ['Source port', '0'], ['Destination IPv4', '198.51.100.1/33'],
  ])('rejects invalid or shell-active %s: %s', async (label, value) => {
    render(<FirewallGenerator />);
    await userEvent.click(screen.getByRole('checkbox', { name: 'Add source port' }));
    await userEvent.click(screen.getByRole('checkbox', { name: 'Add destination IPv4' }));
    fireEvent.change(field(label), { target: { value } });
    expect(commands()).toEqual([]);
    expect(screen.queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
  });
  it('normalizes only validated surrounding firewall whitespace', () => {
    render(<FirewallGenerator />);
    fireEvent.change(field('Source IPv4'), { target: { value: '\t192.0.2.1 ' } });
    fireEvent.change(field('Destination port'), { target: { value: ' 443\t' } });
    expect(shellTokens(commands()[0]!)).toEqual(['sudo', 'ufw', 'allow', 'proto', 'tcp', 'from', '192.0.2.1', 'to', 'any', 'port', '443']);
  });
  it.each([['Source IPv4', '999.0.0.1'], ['Destination port', '65536']])('suppresses invalid %s commands', async (label, value) => {
    render(<FirewallGenerator />);
    await userEvent.type(field(label), value);
    expect(commands()).toEqual([]);
    expect(screen.getByText('Fix the IPv4 address, CIDR prefix, or port before using the generated command.')).toBeVisible();
  });
});

describe('nftables commands', () => {
  it.each([
    ['tcp', 'input', 'accept', 'sudo nft add rule inet filter input ip saddr 10.20.30.40/32 tcp dport 2049 accept'],
    ['udp', 'forward', 'drop', 'sudo nft add rule inet filter forward ip saddr 10.20.30.40/32 udp dport 2049 drop'],
    ['icmp', 'output', 'reject', 'sudo nft add rule inet filter output ip saddr 10.20.30.40/32 icmp type echo-request reject'],
  ])('formats %s %s %s in the fixed inet filter table', async (protocol, chain, action, expected) => {
    render(<NftablesGenerator />);
    const user = userEvent.setup();
    await user.selectOptions(field('Protocol', 'select'), protocol);
    await user.selectOptions(field('Chain', 'select'), chain);
    await user.selectOptions(field('Action', 'select'), action);
    expect(commands()).toEqual([expected]);
  });
  it('includes source port and destination IPv4', async () => {
    render(<NftablesGenerator />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('checkbox', { name: 'Add source port' }));
    await user.click(screen.getByRole('checkbox', { name: 'Add destination IPv4' }));
    expect(commands()).toEqual(['sudo nft add rule inet filter input ip saddr 10.20.30.40/32 ip daddr 10.20.30.40/32 tcp sport 2049 tcp dport 2049 accept']);
  });
  it.each([['Source IPv4', '2001:db8::1'], ['Destination port', 'no']])('rejects unsupported/invalid %s', async (label, value) => {
    render(<NftablesGenerator />);
    await userEvent.type(field(label), value);
    expect(commands()).toEqual([]);
  });
});

describe('firewalld', () => {
  for (const protocol of ['tcp', 'udp', 'icmp']) {
    it.each(['runtime', 'permanent'])(`retains source and destination with one primary element for ${protocol} %s`, async (mode) => {
      render(<FirewalldGenerator />);
      const panel = richPanel();
      const user = userEvent.setup();
      await user.selectOptions(within(panel).getByRole('combobox', { name: 'Protocol' }), protocol);
      await user.selectOptions(field('Rule mode', 'select'), mode);
      await user.click(within(panel).getByRole('checkbox', { name: 'Add destination IPv4' }));
      fireEvent.change(field('Source IPv4'), { target: { value: ' 192.0.2.0/24\t' } });
      fireEvent.change(field('Destination IPv4'), { target: { value: ' 198.51.100.8 ' } });
      if (protocol !== 'icmp') fireEvent.change(field('Destination port'), { target: { value: ' 443 ' } });
      const argv = shellTokens(richCommands()[0]);
      expect(argv.slice(0, -1)).toEqual(['sudo', 'firewall-cmd', ...(mode === 'permanent' ? ['--permanent'] : [])]);
      expect(argv.at(-1)).toMatch(/^--add-rich-rule=/);
      const rule = validateRichRule(argv.at(-1)!.slice('--add-rich-rule='.length));
      expect(rule).toEqual([
        'rule', 'family=ipv4', 'source', 'address=192.0.2.0/24', 'destination', 'address=198.51.100.8',
        ...(protocol === 'icmp' ? ['protocol', 'value=icmp'] : ['port', 'port=443', `protocol=${protocol}`]), 'accept',
      ]);
      expect(rule.filter((token) => ['source-port', 'port', 'protocol'].includes(token))).toHaveLength(1);
      expect(richCommands()).toHaveLength(mode === 'permanent' ? 2 : 1);
    });
    it.each(['runtime', 'permanent'])(`suppresses source-port conflict without broadening ${protocol} %s`, async (mode) => {
      render(<FirewalldGenerator />);
      const panel = richPanel();
      const user = userEvent.setup();
      await user.selectOptions(field('Rule mode', 'select'), mode);
      await user.click(within(panel).getByRole('checkbox', { name: /Add source port/ }));
      await user.selectOptions(within(panel).getByRole('combobox', { name: 'Protocol' }), protocol);
      expect(within(panel).getByRole('status')).toHaveTextContent('cannot combine');
      expect(richCommands()).toEqual([]);
      expect(within(panel).queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
      expect(within(panel).getByRole('checkbox', { name: /Add source port/ })).toBeChecked();
      await user.click(within(panel).getByRole('checkbox', { name: /Add source port/ }));
      expect(richCommands()[0]).toContain(protocol === 'icmp' ? 'protocol value="icmp"' : `port port="2049" protocol="${protocol}"`);
    });
  }
  it.each([
    ['Source IPv4', '192.0.2.1; echo injected'], ['Destination IPv4', '198.51.100.1\''],
    ['Destination port', '443$(echo injected)'], ['Source IPv4', '999.0.0.1'],
    ['Destination IPv4', '198.51.100.1/33'], ['Destination port', '65536'],
  ])('suppresses invalid rich-rule %s: %s and reload', async (label, value) => {
    render(<FirewalldGenerator />);
    await userEvent.click(within(richPanel()).getByRole('checkbox', { name: 'Add destination IPv4' }));
    fireEvent.change(field(label), { target: { value } });
    expect(richCommands()).toEqual([]);
    expect(within(richPanel()).queryByRole('button', { name: 'Copy' })).not.toBeInTheDocument();
  });
  it('retains source-port validation while the combination is unsupported', async () => {
    render(<FirewalldGenerator />);
    await userEvent.click(within(richPanel()).getByRole('checkbox', { name: /Add source port/ }));
    fireEvent.change(field('Source port'), { target: { value: '0' } });
    expect(within(richPanel()).getByText('Port must be between 1 and 65535.')).toBeVisible();
    expect(richCommands()).toEqual([]);
  });
  it.each([
    ['tcp', 'permanent', `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.20.30.40/32" port port="2049" protocol="tcp" accept'`],
    ['udp', 'runtime', `sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.20.30.40/32" port port="2049" protocol="udp" accept'`],
    ['icmp', 'runtime', `sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.20.30.40/32" protocol value="icmp" accept'`],
  ])('formats rich rules for %s %s', async (protocol, mode, expected) => {
    render(<FirewalldGenerator />);
    const user = userEvent.setup();
    const rich = screen.getByRole('heading', { name: 'Firewalld rich-rule generator' }).closest('article')!;
    await user.selectOptions(within(rich).getByRole('combobox', { name: 'Protocol' }), protocol);
    await user.selectOptions(field('Rule mode', 'select'), mode);
    expect(commands()).toContain(expected);
    expect(commands().includes('sudo firewall-cmd --reload')).toBe(mode === 'permanent');
  });
  it('changes zones, presets, protocol and runtime flags', async () => {
    render(<FirewalldZonesBlock />);
    const user = userEvent.setup();
    await user.selectOptions(field('Predefined zone', 'select'), 'internal');
    await user.click(screen.getByRole('checkbox', { name: 'Add destination port' }));
    await user.click(screen.getByRole('button', { name: /^HTTPS\s*443$/ }));
    expect(commands()).toContain('sudo firewall-cmd --permanent --zone=internal --add-port=443/tcp');
    await user.selectOptions(field('Protocol', 'select'), 'udp');
    await user.selectOptions(field('Zone mode', 'select'), 'runtime');
    expect(commands()).toContain('sudo firewall-cmd --zone=internal --add-port=443/udp');
    expect(commands()).toContain('sudo firewall-cmd --zone=internal --list-all');
  });
  it('switches services and ICMP without leaving port rules enabled', async () => {
    render(<FirewalldZonesBlock />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('checkbox', { name: 'Add destination port' }));
    await user.click(screen.getByRole('checkbox', { name: 'Add service' }));
    await user.selectOptions(field('Service', 'select'), 'https');
    expect(commands()).toContain('sudo firewall-cmd --permanent --zone=public --add-service=https');
    expect(screen.getByRole('checkbox', { name: 'Add destination port' })).not.toBeChecked();
    await user.click(screen.getByRole('checkbox', { name: /Configure ICMP/ }));
    await user.selectOptions(field('ICMP action', 'select'), 'block');
    expect(commands()).toContain('sudo firewall-cmd --permanent --zone=public --add-icmp-block=echo-request');
    expect(screen.getByRole('checkbox', { name: 'Add service' })).not.toBeChecked();
  });
  it('creates valid custom zones and suppresses invalid names', async () => {
    render(<FirewalldZonesBlock />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Custom zone' }));
    await user.type(field('Custom zone name'), 'test-zone');
    expect(commands()).toContain('sudo firewall-cmd --permanent --new-zone=test-zone');
    await user.clear(field('Custom zone name'));
    await user.type(field('Custom zone name'), '1invalid');
    expect(commands()).toEqual([]);
  });
  it('suppresses invalid zone ports', async () => {
    render(<FirewalldZonesBlock />);
    await userEvent.click(screen.getByRole('checkbox', { name: 'Add destination port' }));
    await userEvent.type(field('Destination port'), '0');
    expect(commands()).toEqual([]);
    expect(screen.getByText('Port must be between 1 and 65535.')).toBeVisible();
  });
});
