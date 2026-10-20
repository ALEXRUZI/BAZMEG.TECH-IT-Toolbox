import { writeFileSync } from 'node:fs';
import { expect, test, vi } from 'vitest';
import type { FullConfig, FullResult, Suite, TestCase, TestResult, TestStep } from '@playwright/test/reporter';
import SafeFailureReporter from '../e2e/safeFailureReporter';

vi.mock('node:fs', () => {
  const fs = { mkdirSync: vi.fn(), writeFileSync: vi.fn() };
  return { ...fs, default: fs };
});

test('failure artifacts allowlist metadata and checkpoints; never copy secret-bearing results', () => {
  const secret = 'disposable-secret-must-not-leak';
  const reporter = new SafeFailureReporter();
  reporter.onBegin({ rootDir: '/project/frontend/e2e', version: '1.64.0' } as FullConfig, {} as Suite);
  const testCase = { title: secret, location: { file: `/private/${secret}/ssh-key-generator.spec.ts`, line: 293 } } as TestCase;
  const result = { retry: 1, status: 'timedOut', duration: 120_000, errors: [{ message: secret }], attachments: [{ path: secret }], stdout: [secret], stderr: [secret], annotations: [{ type: 'arbitrary', description: secret }, { type: 'ssh-navigation-count', description: '2' }, { type: 'ssh-vite-reload-count', description: secret }] } as unknown as TestResult;
  reporter.onTestBegin(testCase, result);
  reporter.onStepBegin(testCase, result, { title: 'SSH binary file ready' } as TestStep);
  reporter.onStepBegin(testCase, result, { title: secret } as TestStep);
  reporter.onStepEnd(testCase, result, { title: secret, error: { message: secret } } as TestStep);
  reporter.onStepEnd(testCase, result, { title: 'SSH binary file ready', error: { message: secret } } as TestStep);
  reporter.onTestEnd(testCase, result);
  reporter.onEnd({ status: 'failed', errors: [{ message: secret }] } as unknown as FullResult);
  const writes = vi.mocked(writeFileSync).mock.calls;
  for (const [path, content] of writes) {
    expect(path).toBe('/project/frontend/e2e-diagnostics/summary.json');
    expect(String(content)).not.toContain(secret);
  }
  const summary = JSON.parse(String(writes.at(-1)![1]));
  expect(summary.status).toBe('failed');
  expect(summary.attempts).toEqual([{ file: 'ssh-key-generator.spec.ts', line: 293, retry: 1, status: 'timedOut', durationMs: 120_000, checkpoint: 'SSH binary file ready', checkpointStatus: 'failed', failedCheckpoints: ['SSH binary file ready'], navigations: 2 }]);
});

test('unfinished checkpoints and retries are retained without arbitrary titles or error data', () => {
  const reporter = new SafeFailureReporter();
  reporter.onBegin({ rootDir: '/project/frontend/e2e', version: 'unsafe-version-string' } as FullConfig, {} as Suite);
  const testCase = { title: 'never serialize', location: { file: '/private/unsafe name.spec.ts', line: 3 } } as TestCase;
  for (const retry of [0, 1]) {
    const result = { retry, status: 'timedOut', duration: 120_000 } as TestResult;
    reporter.onTestBegin(testCase, result);
    reporter.onStepBegin(testCase, result, { title: 'SSH clipboard comparison' } as TestStep);
    reporter.onTestEnd(testCase, result);
  }
  reporter.onEnd({ status: 'failed' } as FullResult);
  const summary = JSON.parse(String(vi.mocked(writeFileSync).mock.calls.at(-1)![1]));
  expect(summary.environment.playwright).toBe('unknown');
  expect(summary.attempts.map((attempt: { retry: number }) => attempt.retry)).toEqual([0, 1]);
  expect(summary.attempts[1]).toMatchObject({ file: 'unknown', checkpoint: 'SSH clipboard comparison', checkpointStatus: 'running' });
  expect(JSON.stringify(summary)).not.toContain('never serialize');
});

test('successful teardown does not erase the failing body checkpoint', () => {
  const reporter = new SafeFailureReporter();
  reporter.onBegin({ rootDir: '/project/frontend/e2e', version: '1.64.0' } as FullConfig, {} as Suite);
  const testCase = { location: { file: 'ssh-key-generator.spec.ts', line: 293 } } as TestCase;
  const result = { retry: 0, status: 'failed', duration: 10_000 } as TestResult;
  reporter.onTestBegin(testCase, result);
  reporter.onStepBegin(testCase, result, { title: 'SSH download completion' } as TestStep);
  reporter.onStepEnd(testCase, result, { title: 'SSH download completion', error: { message: 'never serialize' } } as TestStep);
  reporter.onStepBegin(testCase, result, { title: 'SSH clipboard cleanup' } as TestStep);
  reporter.onStepEnd(testCase, result, { title: 'SSH clipboard cleanup' } as TestStep);
  reporter.onTestEnd(testCase, result);
  reporter.onEnd({ status: 'failed' } as FullResult);
  const summary = JSON.parse(String(vi.mocked(writeFileSync).mock.calls.at(-1)![1]));
  expect(summary.attempts[0]).toMatchObject({ checkpoint: 'SSH clipboard cleanup', checkpointStatus: 'passed', failedCheckpoints: ['SSH download completion'] });
});
