import fs from 'node:fs';

const PRESENCE_VERSION = 2;
const METADATA_MAX = 160;
const ANSI_ESCAPE_RE = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/g;

function safeMetadata(value, fallback) {
  if (typeof value !== 'string') return fallback;
  return value.replace(ANSI_ESCAPE_RE, '').replace(CONTROL_RE, '').slice(0, METADATA_MAX);
}

export function defaultAttackerState() {
  return {
    presenceVersion: PRESENCE_VERSION,
    nextSeq: {},
    sent: 0,
    received: 0,
    perAgent: {},
    seenResults: [],
    agents: [],
    agentInfo: {},
    history: [],
  };
}

export function loadAttackerState(statePath) {
  const state = defaultAttackerState();
  try {
    const raw = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    if (!raw || typeof raw !== 'object') return state;

    const migratePresence = raw.presenceVersion !== PRESENCE_VERSION;
    for (const key of Object.keys(state)) {
      if (raw[key] !== undefined) state[key] = raw[key];
    }
    if (migratePresence) {
      state.agentInfo = Object.fromEntries(
        Object.entries(state.agentInfo).map(([agentId, info]) => [
          agentId,
          {
            host: info?.host,
            cwd: info?.cwd,
            sourceTs: Number.isFinite(Number(info?.ts)) ? Number(info.ts) : undefined,
            lastSeen: 0,
            baselineAt: 0,
          },
        ]),
      );
      state.presenceVersion = PRESENCE_VERSION;
    }
  } catch {
    // Missing or corrupt state starts fresh.
  }
  return state;
}

export function mergeAgentInfo(previous = {}, update = {}) {
  const previousSeen = Number(previous.lastSeen) || 0;
  const updateSeen = Number(update.lastSeen);
  if (Number.isFinite(updateSeen) && updateSeen < previousSeen) return { ...previous };
  return {
    ...previous,
    ...update,
    lastSeen: Number.isFinite(updateSeen) ? Math.max(previousSeen, updateSeen) : previousSeen,
  };
}

/** Advance liveness only when a distinct heartbeat tag appears. */
export function observeHeartbeatSet(previous = {}, heartbeatTags = [], payload = {}, observedAt = Date.now()) {
  const knownTags = Array.isArray(previous.heartbeatTags) ? previous.heartbeatTags : null;
  const currentTags = [...new Set(heartbeatTags.filter((tag) => typeof tag === 'string'))];
  const known = new Set(knownTags ?? []);
  const sawNewHeartbeat = knownTags !== null && currentTags.some((tag) => !known.has(tag));
  const updateMetadata = knownTags === null || sawNewHeartbeat;

  return {
    ...previous,
    host: updateMetadata ? safeMetadata(payload.host, previous.host) : previous.host,
    cwd: updateMetadata ? safeMetadata(payload.cwd, previous.cwd) : previous.cwd,
    sourceTs: updateMetadata && Number.isFinite(Number(payload.ts))
      ? Number(payload.ts)
      : previous.sourceTs,
    lease: updateMetadata && typeof payload.lease === 'string'
      ? payload.lease
      : previous.lease,
    heartbeatTags: currentTags,
    baselineAt: Number(previous.baselineAt) || observedAt,
    lastSeen: sawNewHeartbeat ? observedAt : (Number(previous.lastSeen) || 0),
  };
}

export function invalidateAgentPresence(info = {}, invalidatedAt = Date.now()) {
  return {
    ...info,
    heartbeatTags: Array.isArray(info.heartbeatTags) ? [...info.heartbeatTags] : [],
    lastSeen: 0,
    baselineAt: invalidatedAt,
  };
}

export function agentPresenceStatus(info, now, offlineMs, registryFresh = true) {
  if (!registryFresh) return 'unknown';

  const lastSeen = Number(info?.lastSeen);
  if (Number.isFinite(lastSeen) && lastSeen > 0) {
    const age = now - lastSeen;
    if (age < 0) return 'unknown';
    return age <= offlineMs ? 'online' : 'offline';
  }

  const baselineAt = Number(info?.baselineAt);
  if (Number.isFinite(baselineAt) && baselineAt > 0) {
    const age = now - baselineAt;
    if (age < 0 || age <= offlineMs) return 'unknown';
    return 'offline';
  }
  return 'unknown';
}

export function isAgentOnline(info, now, offlineMs) {
  return agentPresenceStatus(info, now, offlineMs, true) === 'online';
}

export function assertDirectTargetOnline(state, target, now, offlineMs, registryFresh = true) {
  if (target === 'all') return;
  const info = state.agentInfo?.[target];
  if (!info) throw new Error(`agent "${target}" is not online; task not sent`);
  const status = agentPresenceStatus(info, now, offlineMs, registryFresh);
  if (status === 'online') return;
  if (status === 'unknown') {
    throw new Error(`agent "${target}" presence is unknown; task not sent`);
  }
  throw new Error(`agent "${target}" is offline; task not sent`);
}
