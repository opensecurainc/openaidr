import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export function buildInfo({ development = false } = {}) {
  const script = fileURLToPath(new URL('./build_version.py', import.meta.url));
  return JSON.parse(execFileSync(
    process.env.OPENAIDR_PYTHON || (process.platform === 'win32' ? 'python' : 'python3'),
    [script, ...(development ? ['--development'] : [])],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] },
  ));
}
