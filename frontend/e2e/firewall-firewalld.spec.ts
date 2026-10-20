import { test, expect, openTool, field, copyText } from './fixtures/test';

test('firewalld rich rules switch permanent/runtime and copy', async ({ page }) => {
  const tool = await openTool(page, 'Firewalld generator', 'Firewalld rich-rule generator');
  await field(tool, 'Source IPv4').fill('192.0.2.1');
  await tool.getByRole('button', { name: /^HTTPS\s*443$/ }).click();
  await expect(tool.locator('pre').first()).toHaveText(`sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.0.2.1" port port="443" protocol="tcp" accept'`);
  await field(tool, 'Rule mode', 'combobox').selectOption('runtime');
  await field(tool, 'Protocol', 'combobox').selectOption('udp');
  const command = `sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.0.2.1" port port="443" protocol="udp" accept'`;
  await expect(tool.locator('pre')).toHaveText(command);
  await copyText(page, tool, command);
});

test('firewalld source-port conflicts suppress primary command and reload without dropping restrictions', async ({ page }) => {
  const tool = await openTool(page, 'Firewalld generator', 'Firewalld rich-rule generator');
  await tool.getByRole('checkbox', { name: 'Add destination IPv4' }).check();
  await field(tool, 'Destination IPv4').fill('198.51.100.8');
  await tool.getByRole('checkbox', { name: /Add source port/ }).check();
  for (const protocol of ['tcp', 'udp', 'icmp']) {
    await field(tool, 'Protocol', 'combobox').selectOption(protocol);
    for (const mode of ['permanent', 'runtime']) {
      await field(tool, 'Rule mode', 'combobox').selectOption(mode);
      await expect(tool.getByRole('status')).toContainText('cannot combine');
      await expect(tool.locator('pre')).toHaveCount(0);
      await expect(tool.getByRole('button', { name: 'Copy' })).toHaveCount(0);
      await expect(tool.getByRole('checkbox', { name: /Add source port/ })).toBeChecked();
    }
  }
  await tool.getByRole('checkbox', { name: /Add source port/ }).uncheck();
  const command = `sudo firewall-cmd --add-rich-rule='rule family="ipv4" source address="10.20.30.40/32" destination address="198.51.100.8" protocol value="icmp" accept'`;
  await expect(tool.locator('pre')).toHaveText(command);
  await copyText(page, tool, command);
  await field(tool, 'Protocol', 'combobox').selectOption('tcp');
  await expect(tool.locator('pre')).toContainText('destination address="198.51.100.8" port port="2049" protocol="tcp"');
});

test('firewalld zones change ports, zones, mode and validation', async ({ page }) => {
  await openTool(page, 'Firewalld generator', 'Firewalld rich-rule generator');
  const tool = page.getByRole('article').filter({ has: page.getByRole('heading', { name: 'Firewalld zones', exact: true }) });
  await field(tool, 'Predefined zone', 'combobox').selectOption('internal');
  await tool.getByRole('checkbox', { name: 'Add destination port' }).check();
  await tool.getByRole('button', { name: /^HTTPS\s*443$/ }).click();
  await expect(tool.locator('pre').first()).toHaveText('sudo firewall-cmd --permanent --zone=internal --add-port=443/tcp');
  await field(tool, 'Zone mode', 'combobox').selectOption('runtime');
  await field(tool, 'Protocol', 'combobox').selectOption('udp');
  const command = 'sudo firewall-cmd --zone=internal --add-port=443/udp';
  await expect(tool.locator('pre').first()).toHaveText(command);
  await copyText(page, tool.locator('pre').first().locator('..'), command);
  await field(tool, 'Destination port').fill('0');
  await expect(tool.getByText('Port must be between 1 and 65535.')).toBeVisible();
  await expect(tool.locator('pre')).toHaveCount(0);
});
