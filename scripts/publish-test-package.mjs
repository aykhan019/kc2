import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const nameArg = process.argv.find((arg) => arg.startsWith('--name='));
const name = nameArg?.slice('--name='.length);
if (!name || !/^@?[a-z0-9][a-z0-9._~-]*(?:\/[a-z0-9][a-z0-9._~-]*)?$/.test(name)) {
  throw new Error("usage: npm run publish:test-package -- --name='@your-npm-username/kc2-lab-test'");
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc2-lab-package-'));
try {
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name,
    version: '1.0.0',
    private: false,
    description: 'Disposable KC2 research mailbox package',
    license: 'UNLICENSED',
  }, null, 2) + '\n');
  fs.writeFileSync(path.join(dir, 'README.md'), '# Disposable KC2 lab mailbox\n');
  execFileSync('npm', ['publish', '--access', 'public'], { cwd: dir, stdio: 'inherit' });
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
