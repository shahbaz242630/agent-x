// 6E2/6E4: the MCP endpoint's address and the protocol versions it speaks, in a
// file of their own with no imports, so the deploy checks can read the same
// table the server speaks (deploy/azure/policy.ts: the alert on a version we
// don't speak) without loading the MCP SDK.

/** The MCP endpoint's address. */
export const MCP_PATH = '/v1/mcp';

/**
 * The MCP versions this server speaks, newest first: the one table. The 2026 revision is reached by
 * `server/discover`, the 2025 ones by `initialize` (or a request naming none: 2025-03-26).
 */
export const PROTOCOLS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'] as const;
