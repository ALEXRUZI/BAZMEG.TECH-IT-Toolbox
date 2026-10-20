import { mkdirSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import type { FullConfig, FullResult, Reporter, Suite, TestCase, TestResult, TestStep } from '@playwright/test/reporter';
import { sshCheckpoints } from './fixtures/sshCheckpoints';

const checkpoints = new Set<string>(sshCheckpoints);
const statuses = new Set(['passed', 'failed', 'timedOut', 'timedout', 'skipped', 'interrupted']);
type Attempt = {
  file: string; line: number; retry: number; status: string; durationMs?: number;
  checkpoint?: string; checkpointStatus?: string;
  failedCheckpoints?: string[];
  navigations?: number;
};
const number = (value: number) => Number.isFinite(value) && value >= 0 ? value : 0;

// Allowlist, not redaction: raw results include secret-bearing error snippets,
// attachments, stdout, DOM and API arguments. None are read or serialized here.
export default class SafeFailureReporter implements Reporter {
  private path = '';
  private attempts: Attempt[] = [];
  private active = new Map<TestResult, Attempt>();
  private environment = { node: process.version, platform: process.platform, playwright: '' };
  onBegin(config: FullConfig, _suite: Suite) {
    const directory = join(config.rootDir, '..', 'e2e-diagnostics');
    mkdirSync(directory, { recursive: true });
    this.path = join(directory, 'summary.json');
    this.environment.playwright = /^\d+\.\d+\.\d+$/.test(config.version) ? config.version : 'unknown';
    this.save('running');
  }
  onTestBegin(test: TestCase, result: TestResult) {
    const file = basename(test.location.file);
    const attempt: Attempt = {
      file: /^[a-z0-9-]+\.spec\.ts$/.test(file) ? file : 'unknown',
      line: number(test.location.line), retry: number(result.retry), status: 'running',
    };
    this.attempts.push(attempt); this.active.set(result, attempt); this.save('running');
  }
  onStepBegin(_test: TestCase, result: TestResult, step: TestStep) {
    const attempt = this.active.get(result);
    if (!attempt || !checkpoints.has(step.title)) return;
    attempt.checkpoint = step.title; attempt.checkpointStatus = 'running'; this.save('running');
  }
  onStepEnd(_test: TestCase, result: TestResult, step: TestStep) {
    const attempt = this.active.get(result);
    if (!attempt || !checkpoints.has(step.title)) return;
    if (step.error) {
      attempt.failedCheckpoints ??= [];
      if (!attempt.failedCheckpoints.includes(step.title)) attempt.failedCheckpoints.push(step.title);
    }
    if (attempt.checkpoint === step.title) attempt.checkpointStatus = step.error ? 'failed' : 'passed';
    this.save('running');
  }
  onTestEnd(_test: TestCase, result: TestResult) {
    const attempt = this.active.get(result);
    if (!attempt) return;
    attempt.status = statuses.has(result.status) ? result.status : 'unknown';
    for (const annotation of result.annotations ?? []) {
      if (!/^\d{1,6}$/.test(annotation.description ?? '')) continue;
      if (annotation.type === 'ssh-navigation-count') attempt.navigations = Number(annotation.description);
    }
    attempt.durationMs = number(result.duration); this.active.delete(result); this.save('running');
  }
  onEnd(result: FullResult) { this.save(statuses.has(result.status) ? result.status : 'unknown'); }
  private save(status: string) {
    writeFileSync(this.path, JSON.stringify({ schema: 1, environment: this.environment, status, attempts: this.attempts }, null, 2) + '\n');
  }
}
