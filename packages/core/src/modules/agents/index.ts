// The agents module (ADR-004, ADR-011 §1): an organisation's AI agents and
// their keys (C1-1), both authority tables read through their signed states.
// A key's ID is listed in the directory, so a request carrying the key can be
// placed in its organisation before any is known. The routes come at C1-2,
// which exports what they use.
export { AGENT, AGENT_KEY } from './domain/agent.ts';
export { AGENT_KEYS } from './infrastructure/agent-keys.ts';
export { AGENTS } from './infrastructure/agents.ts';
