import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runTask, ALLOWED_OPS } from '../src/victim/tasks.js';
import {
  defaultState,
  loadState,
  processDistTags,
  saveState,
  selectCommands,
} from '../src/victim/agent.js';
import { encodeCommandTag, TASK_OPS } from '../src/common/protocol.js';
import { pendingDirectTasks } from '../src/attacker/cli.js';

const AGENT = 'a1b2c3d4';

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-agent-'));
}

const silentLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

class FakeClient {
  constructor() {
    this.setCalls = [];
  }
  async setDistTag(tag, version) {
    this.setCalls.push([tag, version]);
  }
}

// ---------------------------------------------------------------------------
// task dispatch
// ---------------------------------------------------------------------------

test('task dispatch: echo', () => {
  const r = runTask('echo', { text: 'hello' });
  assert.deepEqual(r, { ok: true, output: 'echo: hello' });
});

test('task dispatch: ping / time / sysinfo', () => {
  assert.deepEqual(runTask('ping'), { ok: true, output: 'pong' });
  const t = runTask('time');
  assert.ok(t.ok && !Number.isNaN(Date.parse(t.output)));
  const s = runTask('sysinfo');
  assert.ok(s.ok);
  assert.match(s.output, new RegExp(`platform=${os.platform()}`));
  assert.match(s.output, /arch=/);
});

test('task dispatch: unknown ops are refused, never executed', () => {
  for (const op of ['exec', 'shell', 'rm', 'eval', '']) {
    const r = runTask(op);
    assert.equal(r.ok, false);
    assert.match(r.error, /disallowed|unknown/);
  }
});

test('allowlist matches the protocol op set', () => {
  assert.deepEqual([...ALLOWED_OPS].sort(), [...TASK_OPS].sort());
});

// ---------------------------------------------------------------------------
// command selection / dedup
// ---------------------------------------------------------------------------

test('selectCommands picks only new commands addressed to me or all', () => {
  const tags = {
    latest: '1.0.0',
    [encodeCommandTag(AGENT, 1, { op: 'ping' })]: '1.0.0',
    [encodeCommandTag(AGENT, 2, { op: 'echo', args: { text: 'hi' } })]: '1.0.0',
    [encodeCommandTag('otheragent', 1, { op: 'ping' })]: '1.0.0',
    [encodeCommandTag('all', 1, { op: 'time' })]: '1.0.0',
  };
  const state = defaultState();
  state.lastSeq[AGENT] = 1; // seq 1 already processed
  const { commands, skipped } = selectCommands(tags, state, AGENT);
  assert.equal(skipped.length, 0);
  assert.deepEqual(
    commands.map((c) => [c.agentId, c.seq, c.payload.op]),
    [['all', 1, 'time'], [AGENT, 2, 'echo']],
  );
});

test('malformed tags are skipped, not fatal', () => {
  const tags = {
    'x-cmd-broken': '1.0.0',
    'x-cmd-a1-notaseq-Zm9v': '1.0.0',
    [encodeCommandTag(AGENT, 1, { op: 'ping' })]: '1.0.0',
  };
  const { commands, skipped } = selectCommands(tags, defaultState(), AGENT);
  assert.equal(commands.length, 1);
  assert.equal(skipped.length, 2);
});

// ---------------------------------------------------------------------------
// processing: execution, dedup, result publishing
// ---------------------------------------------------------------------------

test('processDistTags executes new commands and publishes pinned result tags', async () => {
  const cmdTag = encodeCommandTag(AGENT, 1, { op: 'echo', args: { text: 'hi there' } });
  const state = defaultState();
  const client = new FakeClient();
  const stats = await processDistTags({
    distTags: { latest: '1.0.0', [cmdTag]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });
  assert.deepEqual(stats, { executed: 1, resultsPublished: 1, skipped: 0 });
  assert.equal(state.lastSeq[AGENT], 1);
  assert.equal(client.setCalls.length, 1);
  const [tag, version] = client.setCalls[0];
  assert.equal(version, '1.0.0');
  assert.match(tag, /^x-res-a1b2c3d4-1-1of1-/);
});

test('same command tag is executed exactly once, even across state reload', async () => {
  const dir = tmpdir();
  const statePath = path.join(dir, 'victim-state.json');
  const cmdTag = encodeCommandTag(AGENT, 7, { op: 'ping' });
  const distTags = { latest: '1.0.0', [cmdTag]: '1.0.0' };

  // first run: process and persist
  const state1 = loadState(statePath);
  const client1 = new FakeClient();
  const r1 = await processDistTags({
    distTags,
    state: state1,
    agentId: AGENT,
    client: client1,
    logger: silentLogger,
    save: () => saveState(statePath, state1),
  });
  assert.equal(r1.executed, 1);
  assert.equal(client1.setCalls.length, 1);

  // simulate restart: fresh state object reloaded from disk, same tags visible
  const state2 = loadState(statePath);
  const client2 = new FakeClient();
  const r2 = await processDistTags({
    distTags,
    state: state2,
    agentId: AGENT,
    client: client2,
    logger: silentLogger,
    save: () => saveState(statePath, state2),
  });
  assert.equal(r2.executed, 0, 'reloaded state must dedup the same command tag');
  assert.equal(client2.setCalls.length, 0);
});

test('broadcast commands dedup independently of direct commands', async () => {
  const state = defaultState();
  const client = new FakeClient();
  const distTags = {
    [encodeCommandTag('all', 1, { op: 'ping' })]: '1.0.0',
    [encodeCommandTag(AGENT, 1, { op: 'ping' })]: '1.0.0',
  };
  const r = await processDistTags({
    distTags,
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });
  assert.equal(r.executed, 2, 'all#1 and <me>#1 are different seq spaces');
  assert.equal(state.lastSeq.all, 1);
  assert.equal(state.lastSeq[AGENT], 1);
});

test('state is marked processed even when result publishing fails', async () => {
  const cmdTag = encodeCommandTag(AGENT, 3, { op: 'ping' });
  const state = defaultState();
  const failingClient = {
    async setDistTag() {
      throw new Error('HTTP 401');
    },
  };
  const r = await processDistTags({
    distTags: { [cmdTag]: '1.0.0' },
    state,
    agentId: AGENT,
    client: failingClient,
    logger: silentLogger,
  });
  assert.equal(r.executed, 1);
  assert.equal(r.resultsPublished, 0);
  assert.equal(state.lastSeq[AGENT], 3, 'at-most-once execution beats at-least-once delivery');
});

test('large task output is published as multiple chunk tags', async () => {
  // sysinfo output (~200+ chars JSON) exceeds one tag from a tiny command
  const cmdTag = encodeCommandTag(AGENT, 1, { op: 'sysinfo' });
  const state = defaultState();
  const client = new FakeClient();
  await processDistTags({
    distTags: { [cmdTag]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });
  assert.ok(client.setCalls.length > 1, 'expected chunked result');
  for (const [tag] of client.setCalls) {
    assert.ok(tag.length <= 214);
    assert.match(tag, /^x-res-a1b2c3d4-1-\d+of\d+-/);
  }
});

test('state file round-trip and corruption resilience', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'state.json');
  const s = defaultState();
  s.agentId = AGENT;
  s.lastSeq[AGENT] = 5;
  saveState(p, s);
  assert.deepEqual(loadState(p), s);
  fs.writeFileSync(p, 'not json {');
  assert.deepEqual(loadState(p), defaultState(), 'corrupt state file falls back to defaults');
});

test('pending direct tasks are derived from local request/response history', () => {
  const history = [
    { dir: 'out', target: 'agent1', seq: 3, op: 'pwd', ts: 1000 },
    { dir: 'out', target: 'agent2', seq: 4, op: 'ping', ts: 2000 },
    { dir: 'out', target: 'agent1', seq: 5, op: 'pwd', ts: 2500 },
    { dir: 'out', target: 'all', seq: 5, op: 'ping', ts: 3000 },
    { dir: 'in', agentId: 'agent2', seq: 4, op: 'ping', ts: 4000 },
    { dir: 'in', agentId: 'agent1', seq: 5, op: 'ping', ts: 5000 },
  ];

  assert.deepEqual(pendingDirectTasks(history), [history[0], history[2]]);
});
