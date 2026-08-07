// Command handlers for the attacker REPL.
import path from 'node:path';
import { isLabTag } from '../common/protocol.js';
import { OP_DEFS, parseOpArgs } from '../common/ops.js';
import { renameAgent, resolveAgentReference, assertKnownAgent } from './state.js';
import { formatHistoryEntry, PROMPT_TEXT } from './cli-display.js';
import { assertValidName, deleteChain, loadChains, migrateLegacyPlaybooks, parseChainFlags, saveChains, setChain, tokenize } from './chains.js';

function renderHelp({ section, cmdName, gold, dim }) {
  const rows = [
    ['task <agentId|all> <op> [args]', 'task one known agent or broadcast to all'],
    ['attach <agentId>', 'attach the prompt to one known agent', true], ['detach', 'leave attached-agent mode', true],
    ['rename <agentId> <name>', 'assign a durable local display name', true], ['chain list|add|delete|run', 'manage named task sequences', true],
    ['agents', 'list historically discovered agents'], ['history [n]', 'last n requests/responses (default 20)'],
    ['poll', 'fetch results'], ['clean', 'delete lab tags'], ['stats', 'local counters'], ['help', 'this help'], ['exit', 'save state and quit'],
  ];
  const table = (items) => { const width = Math.max(...items.map(([left]) => left.length)); return items.map(([left, right, featured]) => `  ${featured ? gold(left) : cmdName(left)}${' '.repeat(width - left.length + 4)}${dim(right)}`).join('\n'); };
  const taskRows = OP_DEFS.filter((op) => op.group !== 'fun').map((op) => [op.usage, op.summary, op.name === 'exec']);
  const funRows = OP_DEFS.filter((op) => op.group === 'fun').map((op) => [op.usage, op.summary]);
  return [
    '', section('  COMMANDS'), table(rows), '', section(`  TASK OPS (${taskRows.length})`), table(taskRows), '',
    section(`  FUN OPS (${funRows.length})`), table(funRows), '',
    dim('  path args are absolute or relative to the agent cwd (see pwd/cd).'),
    dim('  chain flags: -n/--name, -a/--agent|--agentId, -s/--step (repeatable; quote steps with spaces).'),
    dim('  agent discoveries and task results print as live notifications.'),
    dim('  attached mode is a routing shortcut; results still arrive asynchronously through the registry.'),
    dim('  KC2 task ops are convenient built-ins; exec can invoke any OS program with arguments when enableExec=true (no shell parsing).'),
    '',
  ].join('\n');
}

export function createCommands(context) {
  const { colors: { c, section, cmdName, gold, dim }, getState, setState, statePath, save, pollOnce, dispatchTask, parseTaskLine, agentLabel, setPrompt, getAttachedAgentId, setAttachedAgentId, client, setCleaning } = context;
  let state = getState();
  return {
    help() {
      console.log(renderHelp({ section, cmdName, gold, dim }));
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
      setAttachedAgentId(resolvedAgentId);
      setPrompt(`${agentLabel(resolvedAgentId)}@kc2> `);
      console.log(`attached to ${agentLabel(resolvedAgentId)}; bare KC2 task operations now target it; results remain asynchronous`);
    },

    rename(line) {
      const tokens = line.trim().split(/\s+/);
      if (tokens.length !== 3) throw new Error('usage: rename <agentId> <name>');
      state = renameAgent(state, tokens[1], tokens[2]);
      setState(state);
      save();
      const agentId = resolveAgentReference(state, tokens[2]);
      console.log(`renamed ${agentId} to ${tokens[2]} (local display name)`);
    },

    detach() {
      if (!getAttachedAgentId()) {
        console.log('not attached; prompt is already kc2>');
        return;
      }
      setAttachedAgentId(undefined);
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
      for (const e of entries) console.log(formatHistoryEntry(e, c));
    },

    async clean() {
      setCleaning(true);
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
        setCleaning(false);
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
          const gap = ' '.repeat(Math.max(1, 32 - n.length));
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

}
