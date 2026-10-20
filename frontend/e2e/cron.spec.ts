import { test } from './fixtures/toolRegression';
import { expect, field, openTool, copyText } from './fixtures/test';

test('Cron presets and custom schedules preserve five-field output and copy', async ({ page }) => {
  const panel = await openTool(page, 'Cron generator');
  await expect(panel.locator('pre')).toHaveText('0 2 * * * /usr/local/bin/backup.sh');
  await field(panel, 'Schedule preset', 'combobox').selectOption('every-15-minutes');
  await expect(panel.locator('pre')).toHaveText('*/15 * * * * /usr/local/bin/backup.sh');
  await panel.getByRole('button', { name: 'Custom schedule', exact: true }).click();
  for (const [label, value] of [['Minute', '1,15'], ['Hour', '8-18/2'], ['Day of month', '1-10'], ['Month', '6'], ['Day of week', '1-5']]) {
    await field(panel, label).fill(value);
  }
  await field(panel, 'Command').fill('echo example >> /tmp/log');
  const expected = '1,15 8-18/2 1-10 6 1-5 echo example >> /tmp/log';
  await expect(panel.locator('pre')).toHaveText(expected);
  await copyText(page, panel, expected);
  await panel.getByRole('button', { name: 'Preset schedule', exact: true }).click();
  await expect(panel.locator('pre')).toHaveText('*/15 * * * * echo example >> /tmp/log');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'chmod calculator', exact: true }) }).click();
  await expect(page.getByRole('article').locator('pre')).toHaveText("chmod 755 -- '/var/www/html'");
});

test('Cron invalid fields hide output, display existing messages and recover', async ({ page }) => {
  const panel = await openTool(page, 'Cron generator');
  await panel.getByRole('button', { name: 'Custom schedule', exact: true }).click();
  for (const [value, message] of [
    ['60', 'Allowed range is 0-59.'], ['*/0', 'Step must be a positive safe integer (1-9007199254740991).'],
    ['5-1', 'Range start must be smaller than range end.'],
    ['', 'Minute is required. Use a value between 0 and 59, or * for every value.'],
  ]) {
    await field(panel, 'Minute').fill(value);
    await expect(panel.getByText(message, { exact: true })).toBeVisible();
    await expect(panel.locator('pre')).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Copy', exact: true })).toHaveCount(0);
    await expect(panel.getByText('Fix the cron field values before using the generated crontab line.', { exact: true })).toBeVisible();
  }
  await field(panel, 'Minute').fill('*');
  await expect(panel.locator('pre')).toHaveText('* 2 * * * /usr/local/bin/backup.sh');
});

test('Cron rejects unsafe and malformed steps and recovers without changing valid dialect', async ({ page }) => {
  const panel = await openTool(page, 'Cron generator');
  await panel.getByRole('button', { name: 'Custom schedule', exact: true }).click();
  const minute = field(panel, 'Minute');
  for (const value of ['*/0', '*/-1', '*/1.5', '*/abc', '*/Infinity', '*/NaN', '*/1e309', `*/${'9'.repeat(309)}`, '*/9007199254740992', '*/9007199254740993', '*/1 2', '*/ 2', '*/', '1,*/0', '*/5,1/']) {
    await minute.fill(value);
    await expect(minute).toHaveValue(value);
    await expect(minute).toHaveAttribute('aria-invalid', 'true');
    await expect(minute).toHaveAccessibleDescription('Step must be a positive safe integer (1-9007199254740991).');
    await expect(panel.locator('pre')).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Copy', exact: true })).toHaveCount(0);
    await minute.fill('*/5');
    await expect(panel.locator('pre')).toHaveText('*/5 2 * * * /usr/local/bin/backup.sh');
    await expect(minute).not.toHaveAttribute('aria-invalid', 'true');
  }
  await minute.fill('1/2/3');
  await expect(minute).toHaveAccessibleDescription('Use values like *, */5, 1, 1-5, or 1-10/2.');
  await expect(panel.locator('pre')).toHaveCount(0);
  for (const value of ['*/1', '*/5', '*/15', '*/999', '1-10/2', '5/2', '*/5,1-10/2,5/2', '*/9007199254740991']) {
    await minute.fill(value);
    await expect(panel.locator('pre')).toHaveText(`${value} 2 * * * /usr/local/bin/backup.sh`);
  }
});

test('Cron rejects preserved control characters with accessible errors and retains surrounding ASCII spaces', async ({ page }) => {
  const panel = await openTool(page, 'Cron generator');
  await panel.getByRole('button', { name: 'Custom schedule', exact: true }).click();
  const minute = field(panel, 'Minute');
  for (const value of ['*/5\t', '*/5\u007f', '*/5\u2028', '*/5\u2029']) {
    await minute.fill(value);
    await expect(minute).toHaveValue(value);
    await expect(minute).toHaveAttribute('aria-invalid', 'true');
    await expect(minute).toHaveAccessibleDescription('Cron schedule fields must not contain control characters or line separators.');
    await expect(panel.getByText('Cron schedule fields must not contain control characters or line separators.', { exact: true })).toBeVisible();
    await expect(panel.locator('pre')).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Copy', exact: true })).toHaveCount(0);
    await minute.fill('*/5');
    await expect(minute).not.toHaveAttribute('aria-invalid', 'true');
    await expect(panel.locator('pre')).toHaveText('*/5 2 * * * /usr/local/bin/backup.sh');
    await expect(panel.getByRole('button', { name: 'Copy', exact: true })).toBeVisible();
  }
  await minute.fill(' 5 ');
  expect(await panel.locator('pre').textContent()).toBe(' 5  2 * * * /usr/local/bin/backup.sh');
});
