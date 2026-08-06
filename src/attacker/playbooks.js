// Named command playbooks for the attacker CLI: reusable sequences of CLI
// commands stored as one human-editable JSON object, name -> [steps]:
//
//   {
//     "recon": [
//       "task agent1 cd ..",
//       "task agent1 ls",
//       "task agent1 exec pwd"
//     ]
//   }
//
// Steps are ordinary CLI command lines, exactly as typed at the kc2>
// prompt; when adding from the CLI, steps are separated with " then ":
//   playbook add recon task agent1 cd .. then task agent1 ls
//
// The file is validated on every load (fail loud, never silently truncate)
// and written with owner-only permissions, like the state file.
import fs from 'node:fs';

export const PLAYBOOK_NAME_RE = /^[A-Za-z0-9_-]{1,32}$/;
export const MAX_PLAYBOOKS = 50;
export const MAX_STEPS = 100;
export const MAX_STEP_LEN = 500;
export const PLAYBOOK_FILE_MAX_BYTES = 256 * 1024;

/**
 * Split a "a then b then c" chain into trimmed, non-empty steps.
 * Note: the separator is whitespace-delimited "then", so a step that
 * itself contains " then " (e.g. inside echo text) cannot be chained
 * this way — edit the JSON file directly for those.
 */
export function parseSteps(text) {
  return String(text ?? '')
    .split(/\s+then\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function assertValidName(name) {
  if (!PLAYBOOK_NAME_RE.test(String(name ?? ''))) {
    throw new Error(
      `invalid playbook name "${name}" — use 1-32 of A-Z a-z 0-9 _ -`,
    );
  }
}

export function assertValidSteps(steps) {
  if (!Array.isArray(steps) || steps.length === 0) {
    throw new Error('a playbook needs at least one step');
  }
  if (steps.length > MAX_STEPS) {
    throw new Error(`a playbook holds at most ${MAX_STEPS} steps`);
  }
  for (const [i, step] of steps.entries()) {
    if (typeof step !== 'string' || step.trim() === '') {
      throw new Error(`step ${i + 1} is not a non-empty command string`);
    }
    if (step.length > MAX_STEP_LEN) {
      throw new Error(`step ${i + 1} exceeds ${MAX_STEP_LEN} characters`);
    }
  }
}

/** Validate a raw loaded/saved object; throws on any structural problem. */
export function validatePlaybooks(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('playbook file must contain a JSON object of name -> [steps]');
  }
  const entries = Object.entries(raw);
  if (entries.length > MAX_PLAYBOOKS) {
    throw new Error(`playbook file holds at most ${MAX_PLAYBOOKS} playbooks`);
  }
  const out = {};
  for (const [name, steps] of entries) {
    assertValidName(name);
    assertValidSteps(steps);
    out[name] = steps.map((s) => s.trim());
  }
  return out;
}

/** Load the playbook file. Missing file means "no playbooks yet". */
export function loadPlaybooks(file) {
  if (!fs.existsSync(file)) return {};
  const stat = fs.statSync(file);
  if (stat.size > PLAYBOOK_FILE_MAX_BYTES) {
    throw new Error(`playbook file exceeds ${PLAYBOOK_FILE_MAX_BYTES} bytes — refusing to load`);
  }
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`playbook file is corrupt (${err.message}) — fix or delete ${file}`);
  }
  try {
    return validatePlaybooks(raw);
  } catch (err) {
    throw new Error(`playbook file is invalid: ${err.message} — fix or delete ${file}`);
  }
}

export function savePlaybooks(file, playbooks) {
  const valid = validatePlaybooks(playbooks);
  fs.writeFileSync(file, `${JSON.stringify(valid, null, 2)}\n`, { mode: 0o600 });
  if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
}

/** Return a new map with the playbook added (or replaced), caps enforced. */
export function setPlaybook(map, name, steps) {
  assertValidName(name);
  assertValidSteps(steps);
  if (!Object.hasOwn(map, name) && Object.keys(map).length >= MAX_PLAYBOOKS) {
    throw new Error(`playbook limit reached (${MAX_PLAYBOOKS}) — delete one first`);
  }
  return { ...map, [name]: steps.map((s) => s.trim()) };
}

/** Return a new map without the named playbook; throws if it does not exist. */
export function deletePlaybook(map, name) {
  if (!Object.hasOwn(map, name)) {
    throw new Error(`unknown playbook "${name}"`);
  }
  const out = { ...map };
  delete out[name];
  return out;
}
