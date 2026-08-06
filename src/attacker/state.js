import fs from 'node:fs';

const AGENT_ID_RE = /^[A-Za-z0-9_]{1,64}$/;
const isRecord = (value) => value && typeof value === 'object' && !Array.isArray(value);
const nonNegativeInteger = (value, fallback = 0) => (
  Number.isSafeInteger(value) && value >= 0 ? value : fallback
);

export function defaultAttackerState() {
  return {
    nextSeq: {},
    sent: 0,
    received: 0,
    perAgent: {},
    seenResults: [],
    agents: [],
    agentAliases: {},
    history: [],
  };
}

/** Load durable attacker data while ignoring legacy heartbeat-only fields. */
export function loadAttackerState(statePath) {
  const state = defaultAttackerState();
  try {
    const raw = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    if (!raw || typeof raw !== 'object') return state;
    const nextSeq = isRecord(raw.nextSeq)
      ? Object.fromEntries(
        Object.entries(raw.nextSeq)
          .filter(([agentId, seq]) => AGENT_ID_RE.test(agentId) && Number.isSafeInteger(seq) && seq >= 0),
      )
      : state.nextSeq;
    const perAgent = isRecord(raw.perAgent)
      ? Object.fromEntries(
        Object.entries(raw.perAgent)
          .filter(([agentId, count]) => AGENT_ID_RE.test(agentId) && Number.isSafeInteger(count) && count >= 0),
      )
      : state.perAgent;
    const agents = Array.isArray(raw.agents)
      ? [...new Set(raw.agents.filter((agentId) => typeof agentId === 'string' && AGENT_ID_RE.test(agentId)))]
      : state.agents;
    const agentAliases = isRecord(raw.agentAliases)
      ? Object.fromEntries(
        Object.entries(raw.agentAliases).filter(([agentId, alias]) => (
          agents.includes(agentId)
          && typeof alias === 'string'
          && AGENT_ID_RE.test(alias)
          && alias !== 'all'
          && alias !== agentId
          && !agents.includes(alias)
        )),
      )
      : state.agentAliases;
    const uniqueAliases = new Set();
    const sanitizedAliases = Object.fromEntries(
      Object.entries(agentAliases).filter(([, alias]) => {
        if (uniqueAliases.has(alias)) return false;
        uniqueAliases.add(alias);
        return true;
      }),
    );
    return {
      nextSeq,
      sent: nonNegativeInteger(raw.sent),
      received: nonNegativeInteger(raw.received),
      perAgent,
      seenResults: Array.isArray(raw.seenResults)
        ? raw.seenResults.filter((key) => typeof key === 'string')
        : state.seenResults,
      agents,
      agentAliases: sanitizedAliases,
      history: Array.isArray(raw.history)
        ? raw.history.filter((entry) => isRecord(entry))
        : state.history,
    };
  } catch (err) {
    if (err?.code === 'ENOENT') return state;
    throw new Error(`cannot load attacker state file "${statePath}": ${err.message}`, { cause: err });
  }
}

export function assertKnownAgent(state, target) {
  if (!Array.isArray(state?.agents) || !state.agents.includes(target)) {
    throw new Error(`agent "${target}" is not known; task not sent`);
  }
}

/** Resolve either a registry identity or its locally assigned display name. */
export function resolveAgentReference(state, reference) {
  if (!Array.isArray(state?.agents)) return undefined;
  if (state.agents.includes(reference)) return reference;
  return Object.entries(state.agentAliases ?? {}).find(([, alias]) => alias === reference)?.[0];
}

/**
 * Give a known agent a durable, local-only name. The registry identity remains
 * unchanged, so in-flight task results and announcements keep routing safely.
 */
export function renameAgent(state, reference, alias) {
  const agentId = resolveAgentReference(state, reference);
  if (!agentId) throw new Error(`agent "${reference}" is not known; rename not applied`);
  if (alias === 'all') throw new Error('agent alias "all" is reserved');
  if (!AGENT_ID_RE.test(alias)) {
    throw new Error('invalid agent alias: use 1-64 letters, numbers, or underscores');
  }
  if (alias === agentId) throw new Error('agent alias is already the registry identity');
  if (state.agents.includes(alias) && alias !== agentId) {
    throw new Error(`agent alias "${alias}" conflicts with a known agent ID`);
  }
  const conflict = Object.entries(state.agentAliases ?? {})
    .find(([id, existing]) => id !== agentId && existing === alias);
  if (conflict) throw new Error(`agent alias "${alias}" is already in use`);
  return {
    ...state,
    agentAliases: { ...state.agentAliases, [agentId]: alias },
  };
}
