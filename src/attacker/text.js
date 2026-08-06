// Text and control-flow utilities for the attacker CLI: sanitizing
// registry-controlled text for terminal display, formatting multi-line
// task output, and small async/history helpers. Pure functions only —
// no colors, no I/O — so they stay trivially testable.

export const REGISTRY_TEXT_MAX = 4_000;
const ANSI_CSI_RE = /\x1b\[[0-?]*[ -/]*[@-~]/g;
const TERMINAL_CONTROL_RE = /[\x00-\x1f\x7f-\x9f]/g;

/** Render registry-controlled text without terminal escapes or unbounded output. */
export function sanitizeRegistryText(value, maxLength = REGISTRY_TEXT_MAX) {
  const text = typeof value === 'string' ? value : String(value ?? '');
  return text
    .replace(ANSI_CSI_RE, '')
    .replace(TERMINAL_CONTROL_RE, (character) => {
      // Newlines are safe once escape sequences are gone: keep them so
      // multi-line task output stays readable in the CLI.
      if (character === '\n') return '\n';
      if (character === '\t') return '\\t';
      return '';
    })
    .slice(0, maxLength);
}

/**
 * Format a result body for display: inline after the header when it is a
 * single line, otherwise as an indented block on the following lines.
 */
export function formatResultBody(body) {
  if (!body.includes('\n')) return ` ${body}`;
  const lines = body.split('\n').map((line) => `  ${line}`);
  return `\n${lines.join('\n')}`;
}

export function formatLiveNotification(line, clearPrompt) {
  return clearPrompt ? `\r\x1b[2K${line}` : line;
}

/**
 * Row geometry of the wrapped prompt+input block in a terminal: which row
 * the cursor sits on (0 = first row of the block) and how many rows the
 * block spans in total. The CLI uses this to erase the WHOLE block before
 * printing a live notification over it — readline's own refresh only
 * clears the cursor row, which shreds long, multi-row input lines into
 * stray prompt fragments.
 */
export function inputBlockGeometry(lineLength, cursor, { promptWidth, columns } = {}) {
  const cols = Math.max(1, Math.floor(columns) || 80);
  const prompt = Math.max(0, promptWidth | 0);
  const line = Math.max(0, lineLength | 0);
  const at = Math.min(line, Math.max(0, cursor | 0));
  const cursorRow = Math.floor((prompt + at) / cols);
  const totalRows = Math.floor((prompt + line) / cols) + 1;
  return { cursorRow, totalRows };
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
