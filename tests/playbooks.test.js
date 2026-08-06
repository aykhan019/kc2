// Unit tests for the attacker playbook store in src/attacker/playbooks.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  MAX_STEP_LEN,
  MAX_STEPS,
  deletePlaybook,
  loadPlaybooks,
  parseSteps,
  savePlaybooks,
  setPlaybook,
  validatePlaybooks,
} from '../src/attacker/playbooks.js';

function tmpFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc2-playbooks-'));
  return path.join(dir, 'playbooks.json');
}

test('parseSteps splits on whitespace-delimited "then" and trims', () => {
  assert.deepEqual(parseSteps('task a1 cd .. then task a1 ls then task a1 exec pwd'), [
    'task a1 cd ..',
    'task a1 ls',
    'task a1 exec pwd',
  ]);
  assert.deepEqual(parseSteps('task a1 pwd'), ['task a1 pwd']);
  assert.deepEqual(parseSteps('  then  task a1 pwd then '), ['task a1 pwd']);
  assert.deepEqual(parseSteps(''), []);
  assert.deepEqual(parseSteps(undefined), []);
  // "then" inside a word is not a separator
  assert.deepEqual(parseSteps('task a1 echo thence'), ['task a1 echo thence']);
});

test('setPlaybook adds and replaces with validated names and steps', () => {
  let map = {};
  map = setPlaybook(map, 'recon', ['task a1 pwd', 'task a1 ls']);
  assert.deepEqual(map.recon, ['task a1 pwd', 'task a1 ls']);
  map = setPlaybook(map, 'recon', ['task a1 whoami']);
  assert.deepEqual(map.recon, ['task a1 whoami']);

  assert.throws(() => setPlaybook(map, 'bad name!', ['task a1 pwd']), /invalid playbook name/);
  assert.throws(() => setPlaybook(map, '', ['task a1 pwd']), /invalid playbook name/);
  assert.throws(() => setPlaybook(map, 'x', []), /at least one step/);
  assert.throws(() => setPlaybook(map, 'x', ['   ']), /non-empty/);
  assert.throws(() => setPlaybook(map, 'x', ['y'.repeat(MAX_STEP_LEN + 1)]), /exceeds/);
  assert.throws(
    () => setPlaybook(map, 'x', Array(MAX_STEPS + 1).fill('task a1 pwd')),
    /at most/,
  );
});

test('deletePlaybook removes existing and rejects unknown names', () => {
  const map = { recon: ['task a1 pwd'], demo: ['task a1 ping'] };
  const next = deletePlaybook(map, 'recon');
  assert.deepEqual(Object.keys(next), ['demo']);
  assert.deepEqual(map.recon, ['task a1 pwd']); // original untouched
  assert.throws(() => deletePlaybook(map, 'nope'), /unknown playbook/);
});

test('loadPlaybooks returns empty for a missing file', () => {
  assert.deepEqual(loadPlaybooks(tmpFile()), {});
});

test('save/load round-trips playbooks and writes an owner-only file', () => {
  const file = tmpFile();
  const map = { recon: ['task a1 cd ..', 'task a1 ls'], check: ['task a1 exec pwd'] };
  savePlaybooks(file, map);
  assert.deepEqual(loadPlaybooks(file), map);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
});

test('loadPlaybooks fails loud on corrupt JSON and never truncates it', () => {
  const file = tmpFile();
  fs.writeFileSync(file, '{not json');
  assert.throws(() => loadPlaybooks(file), /corrupt/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{not json');
});

test('loadPlaybooks rejects structurally invalid files', () => {
  const file = tmpFile();
  fs.writeFileSync(file, JSON.stringify(['task a1 pwd']));
  assert.throws(() => loadPlaybooks(file), /invalid/);

  fs.writeFileSync(file, JSON.stringify({ recon: 'task a1 pwd' }));
  assert.throws(() => loadPlaybooks(file), /invalid/);

  fs.writeFileSync(file, JSON.stringify({ 'bad name': ['task a1 pwd'] }));
  assert.throws(() => loadPlaybooks(file), /invalid/);
});

test('validatePlaybooks normalizes step whitespace', () => {
  assert.deepEqual(validatePlaybooks({ recon: ['  task a1 pwd  '] }), { recon: ['task a1 pwd'] });
  assert.throws(() => validatePlaybooks(null), /JSON object/);
  assert.throws(() => validatePlaybooks({ a: [1] }), /non-empty/);
});
