import { test, expect, openTool, field, copyText } from './fixtures/test';

test('UFW generates, switches protocol, validates, and copies', async ({ page }) => {
  const tool = await openTool(page, 'UFW generator', 'UFW command generator');
  await field(tool, 'Source IPv4').fill('192.0.2.0/24');
  await field(tool, 'Destination port').fill('443');
  await expect(tool.locator('pre')).toHaveText('sudo ufw allow proto tcp from 192.0.2.0/24 to any port 443');
  await field(tool, 'Protocol', 'combobox').selectOption('udp');
  const command = 'sudo ufw allow proto udp from 192.0.2.0/24 to any port 443';
  await expect(tool.locator('pre')).toHaveText(command);
  await copyText(page, tool, command);
  await field(tool, 'Destination port').fill('65536');
  await expect(tool.getByText('Port must be between 1 and 65535.')).toBeVisible();
  await expect(tool.locator('pre')).toHaveCount(0);
});

test('UFW ICMP explains unsupported syntax and restores TCP/UDP restrictions', async ({ page }) => {
  const tool = await openTool(page, 'UFW generator', 'UFW command generator');
  await tool.getByRole('checkbox', { name: 'Add source port' }).check();
  await tool.getByRole('checkbox', { name: 'Add destination IPv4' }).check();
  await field(tool, 'Source port').fill('1234');
  await field(tool, 'Destination IPv4').fill('198.51.100.8');
  await field(tool, 'Destination port').fill('443');
  for (const protocol of ['tcp', 'udp']) {
    await field(tool, 'Protocol', 'combobox').selectOption('icmp');
    await expect(tool.getByRole('status')).toContainText('standard UFW CLI does not support');
    await expect(tool.getByRole('status')).toContainText('/etc/ufw/before.rules');
    await expect(tool.getByRole('status')).toContainText('existing firewall policy');
    await expect(tool.locator('pre')).toHaveCount(0);
    await expect(tool.getByRole('button', { name: 'Copy' })).toHaveCount(0);
    await field(tool, 'Protocol', 'combobox').selectOption(protocol);
    const command = `sudo ufw allow proto ${protocol} from 10.20.30.40/32 port 1234 to 198.51.100.8 port 443`;
    await expect(tool.locator('pre')).toHaveText(command);
    await copyText(page, tool, command);
  }
});
