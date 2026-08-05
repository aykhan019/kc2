import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runTask, ALLOWED_OPS } from '../src/victim/tasks.js';
import {
  defaultState,
  isCommandExpired,
  loadState,
  processDistTags,
  publishHeartbeat,
  publishResultTags,
  runHeartbeatLoop,
  saveState,
  selectCommands,
} from '../src/victim/agent.js';
import { decodeAnnounceTag, encodeAnnounceTag, encodeCommandTag, TASK_OPS } from '../src/common/protocol.js';
import {
  createSingleFlight,
  formatLiveNotification,
  pendingDirectTasks,
  sanitizeRegistryText,
  wasCommandSentLocally,
} from '../src/attacker/cli.js';
import {
  agentPresenceStatus,
  assertDirectTargetOnline,
  invalidateAgentPresence,
  isAgentOnline,
  loadAttackerState,
  mergeAgentInfo,
  observeHeartbeatSet,
} from '../src/attacker/presence.js';

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

test('runtime rejects legacy broadcast tags that have no per-agent heartbeat lease', async () => {
  const broadcast = encodeCommandTag('all', 1, { op: 'ping', ts: 1 });
  const state = defaultState();
  const client = new FakeClient();
  const stats = await processDistTags({
    distTags: { [broadcast]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
    validLeases: new Set(['current']),
  });

  assert.equal(stats.executed, 0);
  assert.equal(stats.skipped, 1);
  assert.equal(state.lastSeq.all, 1);
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

test('direct commands require a recent heartbeat lease without comparing host clocks', async () => {
  const valid = encodeCommandTag(AGENT, 1, { op: 'ping', ts: 9_999_999_999, lease: 'lease-new' });
  const stale = encodeCommandTag(AGENT, 2, { op: 'ping', ts: 1, lease: 'lease-old' });
  const state = defaultState();
  const client = new FakeClient();
  const stats = await processDistTags({
    distTags: { [stale]: '1.0.0', [valid]: '1.0.0' },
    state,
    agentId: AGENT,
    client,
    logger: silentLogger,
    validLeases: new Set(['lease-new']),
  });

  assert.equal(isCommandExpired({ ts: 9_000 }, 10_000, 1_000), true);
  assert.equal(isCommandExpired({}, 10_000, 1_000), true);
  assert.equal(stats.executed, 1);
  assert.equal(stats.skipped, 1);
  assert.equal(state.lastSeq[AGENT], 2);
  assert.equal(client.setCalls.length, 1);
  assert.deepEqual(client.deleteCalls.sort(), [stale, valid].sort());
});

test('heartbeat is published before older own announce tags are deleted', async () => {
  const oldOwn = encodeAnnounceTag(AGENT, { ts: 1_000, host: 'old' });
  const foreign = encodeAnnounceTag('otheragent', { ts: 1_000 });
  const client = new FakeClient();
  const tag = await publishHeartbeat({
    client,
    agentId: AGENT,
    distTags: { [oldOwn]: '1.0.0', [foreign]: '1.0.0' },
    now: 2_000,
    cwd: '/tmp/lab',
    host: 'host1',
    logger: silentLogger,
  });

  assert.deepEqual(client.events, [['set', tag], ['delete', oldOwn]]);
});

test('heartbeat lease becomes valid immediately after publish, before cleanup finishes', async () => {
  const oldOwn = encodeAnnounceTag(AGENT, { ts: 1_000, lease: 'old' });
  const client = new FakeClient();
  let publishedLease = '';
  const tag = await publishHeartbeat({
    client,
    agentId: AGENT,
    distTags: { [oldOwn]: '1.0.0' },
    now: 2_000,
    lease: 'new',
    cwd: '/tmp',
    host: 'host1',
    onPublished: () => {
      publishedLease = 'new';
      client.events.push(['lease', 'new']);
    },
    logger: silentLogger,
  });

  assert.equal(publishedLease, 'new');
  assert.deepEqual(client.events, [['set', tag], ['lease', 'new'], ['delete', oldOwn]]);
});

test('heartbeat drops oversized optional metadata but keeps its lease', async () => {
  const client = new FakeClient();
  const tag = await publishHeartbeat({
    client,
    agentId: AGENT,
    distTags: {},
    now: 2_000,
    cwd: `/${'deep/'.repeat(100)}`,
    host: 'host'.repeat(100),
    lease: 'lease-123',
    logger: silentLogger,
  });
  const decoded = decodeAnnounceTag(tag);

  assert.ok(tag.length <= 214);
  assert.equal(decoded.payload.ts, 2_000);
  assert.equal(decoded.payload.lease, 'lease-123');
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
  assert.deepEqual(pendingDirectTasks(history, { now: 7_000, ttlMs: 5_000 }), [history[2]]);
  const taggedHistory = [{ dir: 'out', target: 'agent1', seq: 3, tag: 'exact-tag' }];
  assert.equal(wasCommandSentLocally(taggedHistory, 'exact-tag'), true);
  assert.equal(wasCommandSentLocally(taggedHistory, 'forged-same-seq-tag'), false);
});

test('registry result text cannot inject terminal controls or unbounded output', () => {
  assert.equal(sanitizeRegistryText('\u001b[31mFAIL\nnext\tline'), 'FAIL\\nnext\\tline');
  assert.equal(sanitizeRegistryText('x'.repeat(5_000)).length, 4_000);
});

test('persistent tags do not refresh agent presence', () => {
  const current = { host: 'host1', lastSeen: 1_000 };
  assert.deepEqual(mergeAgentInfo(current, {}), current);
  assert.deepEqual(mergeAgentInfo(current, { lastSeen: 900 }), current);
  assert.deepEqual(mergeAgentInfo(current, { lastSeen: 1_100 }), {
    host: 'host1',
    lastSeen: 1_100,
  });
  assert.equal(isAgentOnline(current, 2_000, 1_000), true);
  assert.equal(isAgentOnline(current, 2_001, 1_000), false);

  const state = { agentInfo: { online: { lastSeen: 1_500 }, offline: { lastSeen: 500 } } };
  assert.doesNotThrow(() => assertDirectTargetOnline(state, 'online', 2_000, 1_000));
  assert.throws(() => assertDirectTargetOnline(state, 'offline', 2_000, 1_000), /offline/);
  assert.throws(() => assertDirectTargetOnline(state, 'unknown', 2_000, 1_000), /not online/);
});

test('direct tasking refuses an agent whose presence is unknown', () => {
  const state = { agentInfo: { maybe: { baselineAt: 1_500 } } };
  assert.throws(() => assertDirectTargetOnline(state, 'maybe', 2_000, 1_000), /presence is unknown/);
});

test('heartbeat liveness uses local observation time, not the victim clock', () => {
  const first = observeHeartbeatSet({}, ['future-clock-tag'], {
    ts: 9_999_999_999,
    host: 'clock-ahead',
  }, 1_000);

  assert.equal(first.lastSeen, 0, 'the first snapshot is only a baseline');
  assert.equal(agentPresenceStatus(first, 1_000, 90_000, true), 'unknown');

  const repeated = observeHeartbeatSet(first, ['future-clock-tag'], {
    ts: 9_999_999_999,
    host: 'clock-ahead',
  }, 31_000);
  assert.equal(repeated.lastSeen, 0, 'a persistent tag is not a new heartbeat');

  const next = observeHeartbeatSet(repeated, ['future-clock-tag', 'behind-clock-tag'], {
    ts: 1,
    host: 'clock-behind',
    lease: 'lease-new',
  }, 32_000);
  assert.equal(next.lastSeen, 32_000);
  assert.equal(next.lease, 'lease-new');
  assert.equal(agentPresenceStatus(next, 33_000, 90_000, true), 'online');
  assert.equal(agentPresenceStatus(next, 122_001, 90_000, true), 'offline');
});

test('repeated and stale heartbeat snapshots do not refresh or revert metadata', () => {
  const baseline = observeHeartbeatSet({}, ['beat-a'], { ts: 100, host: 'old' }, 1_000);
  const fresh = observeHeartbeatSet(baseline, ['beat-a', 'beat-b'], { ts: 50, host: 'new' }, 2_000);
  const repeated = observeHeartbeatSet(fresh, ['beat-b', 'beat-a'], { ts: 100, host: 'old' }, 3_000);
  const stale = observeHeartbeatSet(repeated, ['beat-a'], { ts: 100, host: 'old' }, 4_000);

  assert.equal(fresh.lastSeen, 2_000);
  assert.equal(fresh.host, 'new');
  assert.equal(repeated.lastSeen, 2_000);
  assert.equal(repeated.host, 'new');
  assert.equal(stale.lastSeen, 2_000);
  assert.equal(stale.host, 'new');
});

test('a stable heartbeat snapshot larger than 256 tags does not refresh presence', () => {
  const tags = Array.from({ length: 257 }, (_, index) => `beat-${index}`);
  const baseline = observeHeartbeatSet({}, tags, { ts: 1 }, 1_000);
  const repeated = observeHeartbeatSet(baseline, tags, { ts: 1 }, 2_000);

  assert.equal(baseline.heartbeatTags.length, 257);
  assert.equal(repeated.lastSeen, 0);
});

test('heartbeat metadata is bounded and strips terminal control characters', () => {
  const info = observeHeartbeatSet({}, ['beat-a'], {
    ts: 1,
    host: '\u001b[31mhost\nspoofed',
    cwd: `/tmp/${'x'.repeat(500)}\r`,
  }, 1_000);

  assert.equal(info.host, 'hostspoofed');
  assert.ok(info.cwd.length <= 160);
  assert.doesNotMatch(info.host + info.cwd, /[\u0000-\u001f\u007f-\u009f]/);
});

test('legacy attacker state does not restore remote timestamps as live presence', () => {
  const dir = tmpdir();
  const statePath = path.join(dir, 'attacker-state.json');
  fs.writeFileSync(statePath, JSON.stringify({
    presenceVersion: 1,
    agents: [AGENT],
    agentInfo: { [AGENT]: { ts: 9_999_999_999, host: 'future-host', cwd: '/tmp' } },
  }));

  const loaded = loadAttackerState(statePath);
  assert.equal(loaded.presenceVersion, 2);
  assert.equal(loaded.agentInfo[AGENT].lastSeen, 0);
  assert.equal(loaded.agentInfo[AGENT].host, 'future-host');
  assert.equal(agentPresenceStatus(loaded.agentInfo[AGENT], 1_000, 90_000, true), 'unknown');
});

test('presence becomes unknown after refresh failure or explicit invalidation', () => {
  const online = { lastSeen: 10_000, heartbeatTags: ['beat-1'] };
  assert.equal(agentPresenceStatus(online, 10_500, 90_000, true), 'online');
  assert.equal(agentPresenceStatus(online, 10_500, 90_000, false), 'unknown');

  const invalidated = invalidateAgentPresence(online, 11_000);
  assert.equal(invalidated.lastSeen, 0);
  assert.deepEqual(invalidated.heartbeatTags, ['beat-1']);
  assert.equal(agentPresenceStatus(invalidated, 11_001, 90_000, true), 'unknown');
  assert.equal(agentPresenceStatus(invalidated, 101_001, 90_000, true), 'offline');
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

test('heartbeat loop continues while result-like asynchronous work is in progress', async () => {
  let running = true;
  let beats = 0;
  const loop = runHeartbeatLoop({
    heartbeatMs: 5,
    isRunning: () => running,
    publish: async () => { beats++; },
    logger: silentLogger,
    sleepSliceMs: 2,
  });

  for (let i = 0; i < 15; i++) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  running = false;
  await loop;

  assert.ok(beats >= 3, `expected independent heartbeats during uploads, got ${beats}`);
});

test('live notifications clear an existing terminal prompt first', () => {
  assert.equal(formatLiveNotification('task done', true), '\r\x1b[2Ktask done');
  assert.equal(formatLiveNotification('task done', false), 'task done');
});
