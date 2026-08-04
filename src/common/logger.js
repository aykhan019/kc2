// Leveled, timestamped, colored-on-TTY logger that also appends to a log file.
import fs from 'node:fs';
import path from 'node:path';
import { styleText } from 'node:util';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const COLORS = { debug: 'gray', info: 'cyan', warn: 'yellow', error: 'red' };

/**
 * @param {object} opts
 * @param {string} [opts.level]   minimum level: debug|info|warn|error
 * @param {string} [opts.logFile] path to append logs to ('' disables file logging)
 * @param {boolean} [opts.tty]    force colored output on/off (defaults to stdout TTY)
 * @param {boolean} [opts.console] set false to log only to the file (REPL use)
 */
export function createLogger({ level = 'info', logFile = '', tty = process.stdout.isTTY, console: toConsole = true } = {}) {
  const min = LEVELS[level] ?? LEVELS.info;
  let fd = null;
  if (logFile) {
    const abs = path.resolve(logFile);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fd = fs.openSync(abs, 'a');
  }

  function write(lvl, msg, meta) {
    if (LEVELS[lvl] < min) return;
    const ts = new Date().toISOString();
    let line = `[${ts}] [${lvl.toUpperCase().padEnd(5)}] ${msg}`;
    if (meta !== undefined) {
      line += ' ' + (typeof meta === 'string' ? meta : JSON.stringify(meta));
    }
    if (toConsole) {
      const out = tty ? styleText(COLORS[lvl], line) : line;
      if (lvl === 'warn' || lvl === 'error') {
        console.error(out);
      } else {
        console.log(out);
      }
    }
    if (fd !== null) {
      try {
        fs.writeSync(fd, line + '\n');
      } catch {
        // never let logging kill the process
      }
    }
  }

  return {
    debug: (msg, meta) => write('debug', msg, meta),
    info: (msg, meta) => write('info', msg, meta),
    warn: (msg, meta) => write('warn', msg, meta),
    error: (msg, meta) => write('error', msg, meta),
    close: () => {
      if (fd !== null) {
        try {
          fs.closeSync(fd);
        } catch {
          /* ignore */
        }
        fd = null;
      }
    },
  };
}
