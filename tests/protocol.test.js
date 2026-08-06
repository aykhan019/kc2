import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_TAG_LEN,
  PINNED_VERSION,
  ProtocolError,
  assertValidTagName,
  decodeAnnounceTag,
  decodeCommandChunkTag,
  decodeCommandHeader,
  decodeCommandTag,
  decodePayload,
  decodeResultTag,
  encodeAnnounceTag,
  encodeCommandTag,
  encodeCommandTags,
  encodePayload,
  encodeResultTags,
  isAnnounceTag,
  isChunkedCommandTag,
  isCommandTag,
  isLabTag,
  isResultTag,
  reassembleCommand,
  reassembleResult,
} from '../src/common/protocol.js';

const AGENT = 'a1b2c3d4';

test('command tag round-trip', () => {
  const payload = { op: 'echo', args: { text: 'hello world' }, ts: 1720000000000 };
  const tag = encodeCommandTag(AGENT, 7, payload);
  const decoded = decodeCommandTag(tag);
  assert.equal(decoded.agentId, AGENT);
  assert.equal(decoded.seq, 7);
  assert.deepEqual(decoded.payload, payload);
});

test('broadcast command tag round-trip', () => {
  const tag = encodeCommandTag('all', 1, { op: 'ping' });
  const decoded = decodeCommandTag(tag);
  assert.equal(decoded.agentId, 'all');
  assert.equal(decoded.seq, 1);
});

test('command tag name satisfies npm dist-tag rules', () => {
  const tag = encodeCommandTag(AGENT, 42, { op: 'sysinfo', ts: 1 });
  assert.ok(tag.startsWith('x-cmd-'), 'sentinel prefix present');
  assert.ok(tag.length <= MAX_TAG_LEN);
  assert.equal(encodeURIComponent(tag), tag, 'must survive URL encoding unchanged');
  assert.ok(!/^[0-9v]/.test(tag), 'must not start with digit/v (semver-ish)');
  assert.equal(PINNED_VERSION, '1.0.0');
});

test('command tag with payload containing "-" characters round-trips', () => {
  // JSON with characters that base64url-encode to '-' or '_' (0xfb/0xff bytes)
  const payload = { op: 'echo', args: { text: 'ûÿü ûÿü' } };
  const tag = encodeCommandTag(AGENT, 3, payload);
  const decoded = decodeCommandTag(tag);
  assert.deepEqual(decoded.payload, payload);
});

test('oversized command payload is rejected by the encoder', () => {
  const payload = { op: 'echo', args: { text: 'A'.repeat(1000) } };
  assert.throws(() => encodeCommandTag(AGENT, 1, payload), ProtocolError);
  assert.throws(() => encodeCommandTag(AGENT, 1, payload), /214/);
});

test('invalid agent ids are rejected on encode', () => {
  for (const bad of ['', 'has-dash', 'sp ace', 'a'.repeat(65), 'UPPER-ok?']) {
    assert.throws(() => encodeCommandTag(bad, 1, { op: 'ping' }), ProtocolError);
  }
});

test('invalid seq values are rejected on encode', () => {
  for (const bad of [0, -1, 1.5, NaN, '3']) {
    assert.throws(() => encodeCommandTag(AGENT, bad, { op: 'ping' }), ProtocolError);
  }
});

test('unsafe command sequence values are rejected on decode', () => {
  const valid = encodeCommandTag(AGENT, 1, { op: 'ping' });
  const unsafe = valid.replace(`-${AGENT}-1-`, `-${AGENT}-999999999999999999999-`);
  assert.throws(() => decodeCommandTag(unsafe), /positive safe integer/);
});

test('malformed command tags throw ProtocolError', () => {
  assert.throws(() => decodeCommandTag('latest'), ProtocolError);
  assert.throws(() => decodeCommandTag('x-cmd-'), ProtocolError);
  assert.throws(() => decodeCommandTag('x-cmd-a1-notaseq-Zm9v'), ProtocolError);
  assert.throws(() => decodeCommandTag('x-cmd-a1-3-!!!'), ProtocolError);
  // valid base64url but not JSON
  assert.throws(() => decodeCommandTag(`x-cmd-a1-3-${Buffer.from('not json').toString('base64url')}`), ProtocolError);
  // valid JSON but missing "op"
  assert.throws(() => decodeCommandTag(`x-cmd-a1-3-${encodePayload({ nope: 1 })}`), ProtocolError);
});

test('encodeCommandTags keeps fitting payloads in the legacy single-tag format', () => {
  const payload = { op: 'echo', args: { text: 'short' }, ts: 1720000000000 };
  const tags = encodeCommandTags(AGENT, 7, payload);
  assert.deepEqual(tags, [encodeCommandTag(AGENT, 7, payload)]);
  assert.ok(!isChunkedCommandTag(tags[0]));
  assert.deepEqual(decodeCommandTag(tags[0]).payload, payload);
  assert.deepEqual(decodeCommandHeader(tags[0]), { agentId: AGENT, seq: 7 });
});

test('oversized command is chunked; every tag fits; reassembly works out of order', () => {
  const payload = { op: 'echo', args: { text: 'X'.repeat(2000) }, ts: 1720000000000 };
  const tags = encodeCommandTags(AGENT, 11, payload);
  assert.ok(tags.length > 1, `expected multiple chunk tags, got ${tags.length}`);
  const parts = [];
  for (const tag of tags) {
    assert.ok(tag.length <= MAX_TAG_LEN, `tag too long: ${tag.length}`);
    assert.equal(encodeURIComponent(tag), tag);
    assert.ok(isChunkedCommandTag(tag));
    assert.ok(isCommandTag(tag), 'chunk tags must still classify as command tags');
    const part = decodeCommandChunkTag(tag);
    assert.equal(part.agentId, AGENT);
    assert.equal(part.seq, 11);
    assert.equal(part.total, tags.length);
    parts.push(part);
    // legacy decoders refuse chunk tags: old victims skip, never run partials
    assert.throws(() => decodeCommandTag(tag), ProtocolError);
  }
  const shuffled = [...parts].reverse();
  assert.deepEqual(reassembleCommand(shuffled), payload);
  assert.deepEqual(decodeCommandHeader(tags[0]), { agentId: AGENT, seq: 11 });
});

test('reassembleCommand rejects incomplete, inconsistent, or op-less chunks', () => {
  const payload = { op: 'echo', args: { text: 'Y'.repeat(1500) }, ts: 1 };
  const tags = encodeCommandTags(AGENT, 3, payload);
  const parts = tags.map(decodeCommandChunkTag);
  assert.throws(() => reassembleCommand(parts.slice(1)), /incomplete command/);
  assert.throws(() => reassembleCommand([]), /no command chunks/);
  const alien = { ...parts[0], agentId: 'zz' };
  assert.throws(() => reassembleCommand([parts[0], alien]), /inconsistent/);
  const badTotal = { ...parts[0], total: parts[0].total + 1 };
  assert.throws(() => reassembleCommand([badTotal, ...parts.slice(1)]), /inconsistent/);
});

test('malformed command chunk tags throw ProtocolError', () => {
  assert.throws(() => decodeCommandChunkTag('x-cmd-a1-3-eyJvcCI6InBpbmcifQ'), /not a chunked/);
  assert.throws(() => decodeCommandChunkTag('x-cmd-a1-3-0of2-Zm9v'), /out of range/);
  assert.throws(() => decodeCommandChunkTag('x-cmd-a1-3-1of1-Zm9v'), /out of range/);
  assert.throws(() => decodeCommandChunkTag('x-cmd-a1-3-3of2-Zm9v'), /out of range/);
  assert.throws(() => decodeCommandChunkTag('x-cmd-a1-3-1of2-!!!'), /bad payload/);
  // an agentId with '-' shifts the fields, so the chunk spec no longer parses
  assert.throws(() => decodeCommandChunkTag('x-cmd-bad-id-3-1of2-Zm9v'), /not a chunked/);
});

test('single-chunk result round-trip', () => {
  const payload = { seq: 5, ok: true, output: 'pong' };
  const tags = encodeResultTags(AGENT, 5, payload);
  assert.equal(tags.length, 1);
  assert.match(tags[0], /^x-res-a1b2c3d4-5-1of1-/);
  const part = decodeResultTag(tags[0]);
  assert.deepEqual({ agentId: part.agentId, seq: part.seq, chunk: part.chunk, total: part.total }, {
    agentId: AGENT, seq: 5, chunk: 1, total: 1,
  });
  assert.deepEqual(reassembleResult([part]), payload);
});

test('large result is chunked; every chunk respects the 214-char limit; reassembly works', () => {
  const payload = { seq: 9, ok: true, output: 'X'.repeat(5000) };
  const tags = encodeResultTags(AGENT, 9, payload);
  assert.ok(tags.length > 1, `expected multiple chunks, got ${tags.length}`);
  let declaredTotal = null;
  const parts = [];
  for (const tag of tags) {
    assert.ok(tag.length <= MAX_TAG_LEN, `tag too long: ${tag.length}`);
    assert.equal(encodeURIComponent(tag), tag);
    const part = decodeResultTag(tag);
    declaredTotal ??= part.total;
    assert.equal(part.total, tags.length);
    parts.push(part);
  }
  assert.equal(declaredTotal, tags.length);
  assert.deepEqual(reassembleResult(parts), payload);
});

test('result chunks reassemble regardless of order', () => {
  const payload = { seq: 2, ok: false, error: 'Y'.repeat(1500) };
  const tags = encodeResultTags(AGENT, 2, payload);
  const parts = tags.map(decodeResultTag).reverse();
  assert.deepEqual(reassembleResult(parts), payload);
});

test('result payload sequence must match its validated tag sequence', () => {
  const forged = encodeResultTags(AGENT, 7, {
    seq: 'x/../../../../tmp/overwrite',
    ok: true,
    output: 'forged',
  }).map(decodeResultTag);

  assert.throws(() => reassembleResult(forged), /sequence mismatch/);
});

test('incomplete or inconsistent chunks are rejected', () => {
  const payload = { seq: 4, ok: true, output: 'Z'.repeat(2000) };
  const tags = encodeResultTags(AGENT, 4, payload);
  assert.ok(tags.length > 1);
  const parts = tags.map(decodeResultTag);
  // drop one chunk
  assert.throws(() => reassembleResult(parts.slice(1)), /incomplete/);
  // mix in a chunk from another seq
  const other = decodeResultTag(encodeResultTags(AGENT, 99, payload)[0]);
  assert.throws(() => reassembleResult([...parts, other]), /inconsistent/);
  assert.throws(() => reassembleResult([]), ProtocolError);
});

test('malformed result tags throw ProtocolError', () => {
  assert.throws(() => decodeResultTag('x-res-a1-2-3-Zm9v'), ProtocolError); // bad chunk spec
  assert.throws(() => decodeResultTag('x-res-a1-2-2of1-Zm9v'), ProtocolError); // chunk > total
  assert.throws(() => decodeResultTag('x-res-a1-2-0of1-Zm9v'), ProtocolError); // chunk 0
  assert.throws(() => decodeResultTag('x-cmd-a1-2-1of1-Zm9v'), ProtocolError); // wrong prefix
  assert.throws(() => decodeResultTag('x-res-a1-x-1of1-Zm9v'), ProtocolError);
});

test('tag classification helpers', () => {
  const cmd = encodeCommandTag(AGENT, 1, { op: 'ping' });
  const res = encodeResultTags(AGENT, 1, { ok: true, output: 'pong' })[0];
  const ann = encodeAnnounceTag(AGENT, { ts: 1 });
  assert.ok(isCommandTag(cmd) && !isCommandTag(res) && !isCommandTag('latest'));
  assert.ok(isResultTag(res) && !isResultTag(cmd) && !isResultTag('latest'));
  assert.ok(isAnnounceTag(ann) && !isAnnounceTag(cmd) && !isAnnounceTag(res));
  assert.ok(isLabTag(cmd) && isLabTag(res) && isLabTag(ann));
  assert.ok(!isLabTag('latest') && !isLabTag('beta'));
});

test('announce tag round-trip', () => {
  const payload = { ts: 1720000000000, cwd: '/tmp/lab', host: 'vm1' };
  const tag = encodeAnnounceTag(AGENT, payload);
  assert.ok(tag.length <= MAX_TAG_LEN);
  const decoded = decodeAnnounceTag(tag);
  assert.equal(decoded.agentId, AGENT);
  assert.deepEqual(decoded.payload, payload);
});

test('malformed announce tags throw ProtocolError', () => {
  assert.throws(() => decodeAnnounceTag('x-ann-broken'), ProtocolError); // too few fields
  assert.throws(() => decodeAnnounceTag('x-ann-a b-Zm9v'), ProtocolError); // bad agentId
  assert.throws(() => decodeAnnounceTag('x-cmd-a1-1-Zm9v'), ProtocolError); // wrong prefix
});

test('assertValidTagName enforces npm constraints', () => {
  assert.throws(() => assertValidTagName('x'.repeat(215)), /214/);
  assert.throws(() => assertValidTagName('x-has space'), /URL-encode/);
  assert.throws(() => assertValidTagName('1.2.3'), /digit/);
  assert.doesNotThrow(() => assertValidTagName('x-cmd-a-1-Zm9v'));
});

test('decodePayload rejects non-base64url input', () => {
  assert.throws(() => decodePayload('abc+def/=='), ProtocolError);
  assert.ok(decodePayload(encodePayload({ a: 1 })).a === 1);
});
