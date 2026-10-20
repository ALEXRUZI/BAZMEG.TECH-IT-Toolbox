import { test, expect, openTool, field, copyText } from './fixtures/test';

test('nftables generates IPv4 rules and rejects unsupported IPv6', async ({ page }) => {
  const tool = await openTool(page, 'nftables generator');
  await field(tool, 'Source IPv4').fill('192.0.2.1');
  await field(tool, 'Destination port').fill('53');
  await expect(tool.locator('pre')).toHaveText('sudo nft add rule inet filter input ip saddr 192.0.2.1 tcp dport 53 accept');
  await field(tool, 'Protocol', 'combobox').selectOption('udp');
  await field(tool, 'Chain', 'combobox').selectOption('forward');
  await field(tool, 'Action', 'combobox').selectOption('drop');
  const command = 'sudo nft add rule inet filter forward ip saddr 192.0.2.1 udp dport 53 drop';
  await expect(tool.locator('pre')).toHaveText(command);
  await copyText(page, tool, command);
  await field(tool, 'Protocol', 'combobox').selectOption('icmp');
  await expect(tool.locator('pre')).toHaveText('sudo nft add rule inet filter forward ip saddr 192.0.2.1 icmp type echo-request drop');
  await field(tool, 'Source IPv4').fill('2001:db8::1');
  await expect(tool.getByText('IPv4 address must have 4 octets.')).toBeVisible();
  await expect(tool.locator('pre')).toHaveCount(0);
});
