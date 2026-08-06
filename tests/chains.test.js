// Unit tests for the attacker chain store in src/attacker/chains.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  MAX_STEP_LEN,
  MAX_STEPS,
  assertValidSteps,
  deleteChain,
  loadChains,
  migrateLegacyPlaybooks,
  migrateLegacyStep,
  parseChainFlags,
  saveChains,
  setChain,
  tokenize,
  validateChains,
} from '../src/attacker/chains.js';

function tmpFile(name = 'chains.json') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc2-chains-'));
  return path.join(dir, name);
}

test('tokenize splits on whitespace and honors quotes', () => {
  assert.deepEqual(tokenize('chain add -n recon -s "exec pwd"'), [
    'chain',
    'add',
    '-n',
    'recon',
    '-s',
    'exec pwd',
  ]);
  assert.deepEqual(tokenize("-s 'cd ..' -s ls"), ['-s', 'cd ..', '-s', 'ls']);
  assert.deepEqual(tokenize(''), []);
  assert.deepEqual(tokenize(undefined), []);
  assert.throws(() => tokenize('-s "exec pwd'), /unterminated quote/);
});

test('parseChainFlags parses short/long flags, = form, and positionals', () => {
  const { flags, positional } = parseChainFlags([
    'recon',
    '-a',
    'agent1',
    '-s',
    'cd ..',
    '--step',
    'ls',
    '--name=demo',
    '--description=Quick host survey',
  ]);
  assert.equal(flags.name, 'demo');
  assert.equal(flags.description, 'Quick host survey');
  assert.equal(flags.agent, 'agent1');
  assert.deepEqual(flags.steps, ['cd ..', 'ls']);
  assert.deepEqual(positional, ['recon']);
});

test('parseChainFlags accepts --agent and --agentId spellings', () => {
  for (const flag of ['-a', '--agent', '--agentId', '--agent-id', '--agent=agent1']) {
    const { flags } = parseChainFlags(flag.includes('=') ? [flag] : [flag, 'agent1']);
    assert.equal(flags.agent, 'agent1', flag);
  }
});

test('parseChainFlags rejects unknown flags and missing values', () => {
  assert.throws(() => parseChainFlags(['--nope']), /unknown flag/);
  assert.throws(() => parseChainFlags(['-n']), /needs a value/);
  assert.throws(() => parseChainFlags(['-s']), /needs a value/);
});

test('setChain adds and replaces immutable described chains', () => {
  let map = {};
  map = setChain(map, 'recon', 'Quick directory survey', ['pwd', 'ls']);
  assert.deepEqual(map.recon, { description: 'Quick directory survey', steps: ['pwd', 'ls'] });
  map = setChain(map, 'recon', 'Identity check', ['whoami']);
  assert.deepEqual(map.recon, { description: 'Identity check', steps: ['whoami'] });

  assert.throws(() => setChain(map, 'bad name!', 'Description', ['pwd']), /invalid chain name/);
  assert.throws(() => setChain(map, '', 'Description', ['pwd']), /invalid chain name/);
  assert.throws(() => setChain(map, 'x', '', ['pwd']), /description/);
  assert.throws(() => setChain(map, 'x', 'Description', []), /at least one step/);
  assert.throws(() => setChain(map, 'x', 'Description', ['   ']), /non-empty/);
  assert.throws(() => setChain(map, 'x', 'Description', ['y'.repeat(MAX_STEP_LEN + 1)]), /exceeds/);
  assert.throws(() => setChain(map, 'x', 'Description', Array(MAX_STEPS + 1).fill('pwd')), /at most/);
});

test('assertValidSteps enforces bare task ops with valid arguments', () => {
  assertValidSteps(['cd ..', 'exec pwd', 'find /tmp conf', 'volume 50']);
  // legacy "task <agent> ..." steps are rejected: chains are agent-agnostic
  assert.throws(() => assertValidSteps(['task agent1 pwd']), /unknown op "task"/);
  assert.throws(() => assertValidSteps(['nope']), /unknown op "nope"/);
  assert.throws(() => assertValidSteps(['ping extra']), /takes no arguments/);
  assert.throws(() => assertValidSteps(['exec']), /usage: -s exec/);
  assert.throws(() => assertValidSteps(['volume 101']), /usage: -s volume/);
  assert.throws(() => assertValidSteps(['openurl ftp://x']), /http\(s\)/);
});

test('deleteChain removes existing and rejects unknown names', () => {
  const map = {
    recon: { description: 'Current directory', steps: ['pwd'] },
    demo: { description: 'Connectivity', steps: ['ping'] },
  };
  const next = deleteChain(map, 'recon');
  assert.deepEqual(Object.keys(next), ['demo']);
  assert.deepEqual(map.recon, { description: 'Current directory', steps: ['pwd'] }); // original untouched
  assert.throws(() => deleteChain(map, 'nope'), /unknown chain/);
});

test('loadChains returns empty for a missing file', () => {
  assert.deepEqual(loadChains(tmpFile()), {});
});

test('save/load round-trips chains and writes an owner-only file', () => {
  const file = tmpFile();
  const map = {
    recon: { description: 'Directory survey', steps: ['cd ..', 'ls'] },
    check: { description: 'Working directory check', steps: ['exec pwd'] },
  };
  saveChains(file, map);
  assert.deepEqual(loadChains(file), map);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
});

test('loadChains fails loud on corrupt JSON and never truncates it', () => {
  const file = tmpFile();
  fs.writeFileSync(file, '{not json');
  assert.throws(() => loadChains(file), /corrupt/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{not json');
});

test('loadChains rejects structurally invalid files', () => {
  const file = tmpFile();
  fs.writeFileSync(file, JSON.stringify(['pwd']));
  assert.throws(() => loadChains(file), /invalid/);

  fs.writeFileSync(file, JSON.stringify({ recon: 'pwd' }));
  assert.throws(() => loadChains(file), /invalid/);

  fs.writeFileSync(file, JSON.stringify({ 'bad name': ['pwd'] }));
  assert.throws(() => loadChains(file), /invalid/);
});

test('validateChains normalizes step whitespace and accepts legacy arrays', () => {
  assert.deepEqual(validateChains({ recon: { description: 'Directory check', steps: ['  pwd  '] } }), {
    recon: { description: 'Directory check', steps: ['pwd'] },
  });
  assert.deepEqual(validateChains({ legacy: ['pwd'] }), {
    legacy: { description: 'Legacy chain (add a description)', steps: ['pwd'] },
  });
  assert.throws(() => validateChains({ recon: { description: '', steps: ['pwd'] } }), /description/);
  assert.throws(() => validateChains(null), /JSON object/);
  assert.throws(() => validateChains({ a: [1] }), /non-empty/);
});

test('migrateLegacyStep strips the "task <agentId>" prefix', () => {
  assert.equal(migrateLegacyStep('task aff7a036a cd ..'), 'cd ..');
  assert.equal(migrateLegacyStep('task agent1 exec pwd'), 'exec pwd');
  assert.equal(migrateLegacyStep('task all ls /tmp'), 'ls /tmp');
  // no legacy prefix: returned trimmed, unchanged
  assert.equal(migrateLegacyStep('  pwd  '), 'pwd');
});

test('migrateLegacyPlaybooks converts the store and keeps a .bak', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc2-chains-'));
  const file = path.join(dir, 'chains.json');
  const legacy = path.join(dir, 'playbooks.json');
  fs.writeFileSync(legacy, JSON.stringify({ recon: ['task a1 cd ..', 'task a1 ls', 'task a1 exec pwd'] }));

  assert.equal(migrateLegacyPlaybooks(file), legacy);
  assert.deepEqual(loadChains(file), {
    recon: { description: 'Legacy chain (add a description)', steps: ['cd ..', 'ls', 'exec pwd'] },
  });
  assert.ok(!fs.existsSync(legacy), 'legacy file renamed away');
  assert.ok(fs.existsSync(`${legacy}.bak`), 'legacy kept as .bak');

  // second call is a no-op: the chain file now exists
  assert.equal(migrateLegacyPlaybooks(file), null);
});

test('migrateLegacyPlaybooks no-ops without a legacy file', () => {
  assert.equal(migrateLegacyPlaybooks(tmpFile()), null);
});

test('migrateLegacyPlaybooks refuses non-task legacy steps and keeps the file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc2-chains-'));
  const file = path.join(dir, 'chains.json');
  const legacy = path.join(dir, 'playbooks.json');
  fs.writeFileSync(legacy, JSON.stringify({ mixed: ['task a1 pwd', 'poll'] }));

  assert.throws(() => migrateLegacyPlaybooks(file), /could not be migrated/);
  assert.ok(fs.existsSync(legacy), 'legacy file left in place for manual fixing');
  assert.ok(!fs.existsSync(file), 'no partial chain file written');
});

test('migrateLegacyPlaybooks fails loud on a corrupt legacy file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kc2-chains-'));
  const legacy = path.join(dir, 'playbooks.json');
  fs.writeFileSync(legacy, '{not json');
  assert.throws(() => migrateLegacyPlaybooks(path.join(dir, 'chains.json')), /corrupt/);
});
