import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const roots = ['src', 'tests', 'scripts'];

function javascriptFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) return javascriptFiles(target);
    return entry.isFile() && entry.name.endsWith('.js') ? [target] : [];
  });
}

const files = roots.filter((root) => fs.existsSync(root)).flatMap(javascriptFiles).sort();
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout);
    process.exit(result.status ?? 1);
  }
}

console.log(`syntax check passed (${files.length} JavaScript files)`);
