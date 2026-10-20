import { test, expect, openTool } from './fixtures/test';

test('search filters tools and preserves the selected workbench', async ({ page }) => {
  const ufw = await openTool(page, 'UFW generator', 'UFW command generator');
  const search = page.getByRole('textbox', { name: 'Search tools', exact: true });
  await search.fill('nftables');
  await expect(page.getByRole('heading', { name: 'nftables generator', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'UFW generator', exact: true })).toHaveCount(0);
  await expect(ufw).toBeVisible();
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'nftables generator', exact: true }) }).click();
  await expect(page.getByRole('heading', { name: 'UFW command generator', exact: true })).toHaveCount(0);
  await expect(page.getByRole('article').getByRole('heading', { name: 'nftables generator', exact: true })).toBeVisible();
  await search.fill('no-such-tool-8675309');
  await expect(page.getByRole('button').filter({ has: page.getByRole('heading', { level: 3 }) })).toHaveCount(0);
});

test('planned tools still render their existing notice', async ({ page }) => {
  const tool = await openTool(page, 'Subnet Calculator');
  await expect(tool.getByText(/This UI is planned for a later version\./)).toBeVisible();
});
