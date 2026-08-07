// Presentation and persistence helpers for the attacker CLI.
import fs from 'node:fs';
import path from 'node:path';
import { styleText } from 'node:util';
import { formatResultBody, sanitizeRegistryText } from './text.js';

export const PROMPT_TEXT = 'kc2> ';
export const HISTORY_MAX = 200;
export const HISTORY_OUTPUT_MAX = 300;

export function createPalette(isTty) {
  const color = (value, text) => (isTty ? styleText(value, text) : text);
  return { color, section: (text) => color(['bold', 'cyan'], text), cmdName: (text) => color(['bold', 'white'], text), gold: (text) => color(['bold', 'yellow'], text), dim: (text) => color('dim', text) };
}

export function timestamp() { return new Date().toTimeString().slice(0, 8); }

export function pushHistory(state, entry) {
  state.history.push(entry);
  if (state.history.length > HISTORY_MAX) state.history.splice(0, state.history.length - HISTORY_MAX);
}

export function saveDownload(agentId, result, downloadDir = 'downloads') {
  const dir = path.resolve(downloadDir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!Number.isSafeInteger(result.seq) || result.seq < 1) throw new Error('missing or invalid result sequence');
  if (!Number.isSafeInteger(result.file.size) || result.file.size < 0) throw new Error('missing or invalid file size');
  if (typeof result.file.dataB64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(result.file.dataB64)) throw new Error('file payload is not valid base64');
  const filename = path.basename(String(result.file.name)).replace(/[^A-Za-z0-9._-]/g, '_') || 'file.bin';
  const output = path.join(dir, `${agentId}-seq${result.seq}-${filename}`);
  if (path.dirname(output) !== dir) throw new Error('resolved download path escapes downloads/');
  const data = Buffer.from(result.file.dataB64, 'base64');
  if (data.length !== result.file.size) throw new Error(`decoded size mismatch (${data.length} bytes, expected ${result.file.size})`);
  fs.writeFileSync(output, data, { mode: 0o600 });
  if (process.platform !== 'win32') fs.chmodSync(output, 0o600);
  return output;
}

export function formatHistoryEntry(entry, color) {
  const at = new Date(entry.ts).toTimeString().slice(0, 8);
  if (entry.dir === 'out') {
    const args = entry.args && Object.keys(entry.args).length > 0 ? ` ${JSON.stringify(entry.args)}` : '';
    return `[${at}] ${color('blue', '->')} ${entry.target} #${entry.seq} ${entry.op}${args}`;
  }
  const status = entry.ok ? color('green', 'ok') : color('red', 'FAIL');
  const body = sanitizeRegistryText(entry.ok ? entry.output : entry.error, HISTORY_OUTPUT_MAX);
  const op = sanitizeRegistryText(entry.op ?? '?', 64);
  return `[${at}] ${color('magenta', '<-')} ${entry.agentId} #${entry.seq} ${op} ${status}:${formatResultBody(body)}`;
}
