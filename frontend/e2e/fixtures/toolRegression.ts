import { test as guardedTest, expect } from './test';

export const test = guardedTest.extend<{ javascriptErrors: void }>({
  javascriptErrors: [async ({ page }, use) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await use();
    expect(errors, 'Tool interactions must not cause unhandled JavaScript exceptions').toEqual([]);
  }, { auto: true }],
});
