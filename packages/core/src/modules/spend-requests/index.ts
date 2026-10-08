// The spend-requests module (ADR-004, PRD §3 `SpendRequest`, §3.2, §4.2;
// Phase 2 D): an agent's spend requests, an authority table read through its
// signed state, and the order claims that keep one order from being paid
// twice (D1). Deciding and reserving through them, with the agent's route,
// come with D3–D4r.
export { SPEND_REQUEST, type SpendRequestStatus } from './domain/spend-request.ts';
export { SPEND_REQUESTS } from './infrastructure/requests.ts';
export type { SpendRequestsTables } from './infrastructure/tables.ts';
