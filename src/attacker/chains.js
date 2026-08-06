// Named task chains for the attacker CLI: reusable sequences of task ops
// stored as one human-editable JSON object, name -> [steps]:
//
//   {
//     "recon": ["cd ..", "ls", "exec pwd"]
//   }
//
// A step is one task op line (op + args, no target — see src/common/ops.js).
// Chains are agent-agnostic: the target agent is chosen at run time.
//
//   chain add -n recon -s "cd .." -s "ls" -s "exec pwd"
//   chain run recon -a agent1
//
// The file is validated on every load (fail loud, never silently truncate)
// and written with owner-only permissions, like the state file. A legacy
// playbooks.json (steps of the form "task <agentId> <op> ...") is migrated
// automatically on first use and renamed to playbooks.json.bak.
import fs from 'node:fs';
import path from 'node:path';
import { getOpDef, parseOpArgs } from '../common/ops.js';

export const CHAIN_NAME_RE = /^[A-Za-z0-9_-]{1,32}$/;
export const MAX_CHAINS = 50;
export const MAX_STEPS = 100;
export const MAX_STEP_LEN = 500;
export const CHAIN_FILE_MAX_BYTES = 256 * 1024;
export const CHAINS_FILE = 'chains.json';
export const LEGACY_PLAYBOOKS_FILE = 'playbooks.json';

const LEGACY_STEP_RE = /^task\s+\S+\s+(.+)$/s;

/**
 * Split a command line into tokens, honoring single and double quotes:
 *   chain add -n recon -s "exec pwd"  ->  ['chain','add','-n','recon','-s','exec pwd']
 * Throws on an unterminated quote instead of guessing.
 */
export function tokenize(line) {
  const tokens = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(String(line ?? ''))) !== null) {
    const token = m[1] ?? m[2] ?? m[3];
    if (token.startsWith('"') || token.startsWith("'")) {
      throw new Error(`unterminated quote near "${token}"`);
    }
    tokens.push(token);
  }
  return tokens;
}

/**
 * Parse chain subcommand flags. Supported:
 *   -n, --name <name>              chain name
 *   -a, --agent, --agentId <id>    target agent id (or "all") for `run`
 *   -s, --step "<op> [args]"       one step; repeatable, order preserved
 * Long flags also accept the --flag=value form. Anything else that does not
 * start with "-" is returned as positional (e.g. the name in `chain run X`).
 */
export function parseChainFlags(tokens) {
  const flags = { steps: [] };
  const positional = [];
  for (let i = 0; i < tokens.length; i++) {
    let tok = tokens[i];
    let inline;
    if (tok.startsWith('--') && tok.includes('=')) {
      const eq = tok.indexOf('=');
      inline = tok.slice(eq + 1);
      tok = tok.slice(0, eq);
    }
    const value = () => {
      if (inline !== undefined) return inline;
      const v = tokens[++i];
      if (v === undefined) throw new Error(`flag ${tok} needs a value`);
      return v;
    };
    switch (tok) {
      case '-n':
      case '--name':
        flags.name = value();
        break;
      case '-a':
      case '--agent':
      case '--agentId':
      case '--agent-id':
        flags.agent = value();
        break;
      case '-s':
      case '--step':
        flags.steps.push(value());
        break;
      default:
        if (tok.startsWith('-')) throw new Error(`unknown flag "${tok}"`);
        positional.push(tok);
    }
  }
  return { flags, positional };
}

export function assertValidName(name) {
  if (!CHAIN_NAME_RE.test(String(name ?? ''))) {
    throw new Error(`invalid chain name "${name}" — use 1-32 of A-Z a-z 0-9 _ -`);
  }
}

/** A chain step is one task op line: "<op> [args...]" (no target agent). */
export function assertValidStep(step, index) {
  const label = index === undefined ? 'step' : `step ${index + 1}`;
  const [op, ...rest] = tokenize(step);
  if (!getOpDef(op)) {
    throw new Error(
      `${label}: unknown op "${op}" — steps are bare task ops (see help), ` +
        'without a target agent or "task" prefix',
    );
  }
  try {
    parseOpArgs(op, rest, '-s');
  } catch (err) {
    throw new Error(`${label}: ${err.message}`);
  }
}

export function assertValidSteps(steps) {
  if (!Array.isArray(steps) || steps.length === 0) {
    throw new Error('a chain needs at least one step');
  }
  if (steps.length > MAX_STEPS) {
    throw new Error(`a chain holds at most ${MAX_STEPS} steps`);
  }
  for (const [i, step] of steps.entries()) {
    if (typeof step !== 'string' || step.trim() === '') {
      throw new Error(`step ${i + 1} is not a non-empty op string`);
    }
    if (step.length > MAX_STEP_LEN) {
      throw new Error(`step ${i + 1} exceeds ${MAX_STEP_LEN} characters`);
    }
    assertValidStep(step.trim(), i);
  }
}

/** Validate a raw loaded/saved object; throws on any structural problem. */
export function validateChains(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('chain file must contain a JSON object of name -> [steps]');
  }
  const entries = Object.entries(raw);
  if (entries.length > MAX_CHAINS) {
    throw new Error(`chain file holds at most ${MAX_CHAINS} chains`);
  }
  const out = {};
  for (const [name, steps] of entries) {
    assertValidName(name);
    assertValidSteps(steps);
    out[name] = steps.map((s) => s.trim());
  }
  return out;
}

/** Load the chain file. Missing file means "no chains yet". */
export function loadChains(file) {
  if (!fs.existsSync(file)) return {};
  const stat = fs.statSync(file);
  if (stat.size > CHAIN_FILE_MAX_BYTES) {
    throw new Error(`chain file exceeds ${CHAIN_FILE_MAX_BYTES} bytes — refusing to load`);
  }
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`chain file is corrupt (${err.message}) — fix or delete ${file}`);
  }
  try {
    return validateChains(raw);
  } catch (err) {
    throw new Error(`chain file is invalid: ${err.message} — fix or delete ${file}`);
  }
}

export function saveChains(file, chains) {
  const valid = validateChains(chains);
  fs.writeFileSync(file, `${JSON.stringify(valid, null, 2)}\n`, { mode: 0o600 });
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}

/** Return a new map with the chain added (or replaced), caps enforced. */
export function setChain(map, name, steps) {
  assertValidName(name);
  assertValidSteps(steps);
  if (!Object.hasOwn(map, name) && Object.keys(map).length >= MAX_CHAINS) {
    throw new Error(`chain limit reached (${MAX_CHAINS}) — delete one first`);
  }
  return { ...map, [name]: steps.map((s) => s.trim()) };
}

/** Return a new map without the named chain; throws if it does not exist. */
export function deleteChain(map, name) {
  if (!Object.hasOwn(map, name)) {
    throw new Error(`unknown chain "${name}"`);
  }
  const out = { ...map };
  delete out[name];
  return out;
}

/**
 * Convert one legacy playbook step ("task <agentId> <op> [args...]") to an
 * agent-agnostic chain step ("<op> [args...]"). Steps without the legacy
 * "task <target>" prefix are returned trimmed, unchanged.
 */
export function migrateLegacyStep(step) {
  const m = LEGACY_STEP_RE.exec(String(step ?? '').trim());
  return m ? m[1].trim() : String(step ?? '').trim();
}

/**
 * Migrate a legacy playbooks.json next to the chain file, once. No-op when
 * the chain file already exists or no legacy file exists. On success the
 * migrated chains are saved and the legacy file is renamed to
 * playbooks.json.bak; on any problem the legacy file is left untouched and
 * the error says how to fix it by hand.
 * Returns the legacy path when a migration happened, null otherwise.
 */
export function migrateLegacyPlaybooks(file, legacyFile = path.join(path.dirname(file), LEGACY_PLAYBOOKS_FILE)) {
  if (fs.existsSync(file) || !fs.existsSync(legacyFile)) return null;
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(legacyFile, 'utf8'));
  } catch (err) {
    throw new Error(`legacy playbook file is corrupt (${err.message}) — fix or delete ${legacyFile}`);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`legacy playbook file must contain a JSON object of name -> [steps] — fix or delete ${legacyFile}`);
  }
  const migrated = {};
  for (const [name, steps] of Object.entries(raw)) {
    if (!Array.isArray(steps)) {
      throw new Error(`legacy playbook "${name}" is not a list of steps — fix or delete ${legacyFile}`);
    }
    migrated[name] = steps.map(migrateLegacyStep);
  }
  try {
    saveChains(file, migrated);
  } catch (err) {
    throw new Error(
      `legacy playbook file could not be migrated automatically: ${err.message} — ` +
        `edit ${legacyFile} by hand (steps must be bare task ops) or delete it`,
    );
  }
  fs.renameSync(legacyFile, `${legacyFile}.bak`);
  return legacyFile;
}
