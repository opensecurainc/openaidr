import { defineConfig } from '@playwright/test';
import path from 'node:path';

const output = process.env.E2E_OUTPUT || path.resolve('../../build/e2e');
export default defineConfig({
  testDir: 'e2e',
  workers: 1,
  retries: 0,
  timeout: 420_000,
  expect: {timeout: 30_000},
  // scripts/e2e_report.py renders results.json as one flat page in E2E_OUTPUT/report.
  reporter: [
    ['list'],
    ['json', {outputFile: path.join(output, 'results.json')}],
    ['junit', {outputFile: path.join(output, 'junit.xml')}],
  ],
  outputDir: path.join(output, 'results'),
  use: {browserName: 'chromium', viewport: {width: 1440, height: 1000}, locale: 'en-US',
    // Network traces retain authentication headers. Attach sanitized API evidence instead.
    trace: 'off', screenshot: 'off'},
});
