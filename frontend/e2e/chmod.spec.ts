import { test } from './fixtures/toolRegression';
import { expect, field, openTool, copyText } from './fixtures/test';

test('chmod changes permissions independently, quotes paths and copies', async ({ page }) => {
  const panel = await openTool(page, 'chmod calculator');
  await expect(panel.locator('pre')).toHaveText("chmod 755 -- '/var/www/html'");
  const group = (name: string) => panel.getByRole('group', { name, exact: true });
  await group('owner').getByRole('checkbox', { name: 'Execute' }).uncheck();
  await group('group').getByRole('checkbox', { name: 'Execute' }).uncheck();
  await group('others').getByRole('checkbox', { name: 'Execute' }).uncheck();
  await expect(panel.locator('pre')).toHaveText("chmod 644 -- '/var/www/html'");
  await group('group').getByRole('checkbox', { name: 'Read' }).uncheck();
  await group('others').getByRole('checkbox', { name: 'Read' }).uncheck();
  await expect(panel.locator('pre')).toHaveText("chmod 600 -- '/var/www/html'");
  await expect(group('owner').getByRole('checkbox', { name: 'Write' })).toBeChecked();
  await field(panel, 'Path').fill('/tmp/file with spaces');
  const expected = "chmod 600 -- '/tmp/file with spaces'";
  await expect(panel.locator('pre')).toHaveText(expected);
  await copyText(page, panel, expected);
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'Cron generator', exact: true }) }).click();
  await expect(page.getByRole('article').locator('pre')).toHaveText('0 2 * * * /usr/local/bin/backup.sh');
});

test('chmod empty example path has no command or copy until blur', async ({ page }) => {
  const panel = await openTool(page, 'chmod calculator');
  const input = field(panel, 'Path');
  await input.focus();
  await expect(input).toHaveValue('');
  await expect(panel.locator('pre')).toHaveCount(0);
  await expect(panel.getByRole('button', { name: 'Copy' })).toHaveCount(0);
  await expect(panel.getByRole('status')).toContainText('Enter a path');
  await input.blur();
  await expect(input).toHaveValue('/var/www/html');
  await expect(panel.locator('pre')).toHaveText("chmod 755 -- '/var/www/html'");
});

test('chmod retains multiline and whitespace paths in clipboard output', async ({ page }) => {
  const panel = await openTool(page, 'chmod calculator');
  const path = "  it's $(touch /tmp/example); `echo test`\n文件\\name  ";
  await field(panel, 'Path').fill(path);
  await field(panel, 'Path').blur();
  await expect(field(panel, 'Path')).toHaveValue(path);
  const expected = `chmod 755 -- '${path.replace(/'/g, "'\\''")}'`;
  expect(await panel.locator('pre').textContent()).toBe(expected);
  await copyText(page, panel, expected);
});
