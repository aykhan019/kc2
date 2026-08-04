import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createLogger } from '../src/common/logger.js';

test('logger strips terminal controls and keeps each event on one physical line', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-logger-'));
  const logFile = path.join(dir, 'lab.log');
  const logger = createLogger({ logFile, console: false });

  logger.warn('safe\n\u001b]0;title\u0007\u001b[31mFORGED\r\tend');
  logger.close();

  const output = fs.readFileSync(logFile, 'utf8');
  assert.ok(output.endsWith('\n'));
  assert.equal(output.trimEnd().split('\n').length, 1);
  const line = output.slice(0, -1);
  assert.doesNotMatch(line, /[\u0000-\u001f\u007f-\u009f]/u);
  assert.match(line, /safe.*FORGED.*end/);
});

test('logger sanitizes string metadata and serializes object metadata', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-c2-logger-'));
  const logFile = path.join(dir, 'lab.log');
  const logger = createLogger({ logFile, console: false });

  logger.info('string meta', 'line\nvalue');
  logger.info('object meta', { ok: true });
  logger.close();

  const lines = fs.readFileSync(logFile, 'utf8').trimEnd().split('\n');
  assert.equal(lines.length, 2);
  assert.match(lines[0], /string meta line\\nvalue$/);
  assert.match(lines[1], /object meta \{"ok":true\}$/);
});

test('logger honors levels and routes console severities', () => {
  const logged = [];
  const errored = [];
  const originalLog = console.log;
  const originalError = console.error;
  console.log = (line) => logged.push(line);
  console.error = (line) => errored.push(line);

  try {
    const logger = createLogger({ level: 'warn', tty: false });
    logger.debug('hidden debug');
    logger.info('hidden info');
    logger.warn('visible warn');
    logger.error('visible error');
    logger.close();

    const infoLogger = createLogger({ tty: false });
    infoLogger.info('visible info');
    infoLogger.close();
  } finally {
    console.log = originalLog;
    console.error = originalError;
  }

  assert.equal(logged.length, 1);
  assert.match(logged[0], /visible info/);
  assert.equal(errored.length, 2);
  assert.match(errored[0], /visible warn/);
  assert.match(errored[1], /visible error/);
});
