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
