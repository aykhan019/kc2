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
    return {
      nextSeq,
      sent: nonNegativeInteger(raw.sent),
      received: nonNegativeInteger(raw.received),
      perAgent,
      seenResults: Array.isArray(raw.seenResults)
        ? raw.seenResults.filter((key) => typeof key === 'string')
        : state.seenResults,
      agents: Array.isArray(raw.agents)
        ? [...new Set(raw.agents.filter((agentId) => typeof agentId === 'string' && AGENT_ID_RE.test(agentId)))]
        : state.agents,
      history: Array.isArray(raw.history)
        ? raw.history.filter((entry) => isRecord(entry))
        : state.history,
    };
  } catch {
    return state;
  }
}

export function assertKnownAgent(state, target) {
  if (!Array.isArray(state?.agents) || !state.agents.includes(target)) {
    throw new Error(`agent "${target}" is not known; task not sent`);
  }
}
