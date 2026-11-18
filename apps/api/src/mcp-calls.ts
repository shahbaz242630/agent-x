// 6E2 (BR-20; AG3): listing and calling the MCP tools (mcp-tools.ts), apart
// from the wire that carries them and from how the caller was let in. The
// transport (mcp.ts: the official SDK, both protocol eras) hands a call here with the
// agent the API already accepted; what comes back is MCP's own tool result,
// the same over any transport or sign-in the endpoint may later take.
//
// - A call answered: its twin's body written through the twin's own answer
//   schema (SEC-AG-05), every text in it made plain (SEC-MCP-03), beside a
//   summary of fixed words.
// - A call refused: `isError`, its twin's reason code, the code's own words and
//   the HTTP status its twin would have answered; for a busy refusal, how long
//   to wait. Nothing the caller sent is echoed.
// - A twin's use case failing: answered by its operation, as the error path
//   answers its twin (errors.ts: a decision in trouble is busy, never a 500),
//   and logged with the error path's own lines.
import type { AcceptedKey } from '@agentx/core/modules/agents';
import { REASON_CODES, type ReasonCode } from '@agentx/core/shared-kernel';

import { pathIdsOf } from './activity-recorder.ts';
import { BUSY_RETRY_SECONDS, type LogFailure, responseFor } from './errors.ts';
import { SEND_AGAIN_CODES } from './idempotent-writes.ts';
import {
  type AgentUseCases,
  checkedInput,
  inputSchemaOf,
  outputSchemaOf,
  type McpTool,
  plainTexts,
  type TwinnedTool,
} from './mcp-tools.ts';
import type { Refused } from './refused.ts';

/** What a call was, for its activity row and its request's line: the tool, and the status its twin would answer. */
export interface ToolCalled {
  readonly tool: string;
  readonly status: number;
  /** The reason code of a refusal; none for an answer. */
  readonly reason: ReasonCode | undefined;
  /** The UUIDs its twin's path would have named. */
  readonly pathIds: readonly string[];
}

/**
 * Each tool as MCP defines one (tools/list), whatever carries it: its name, title, description with the scopes its
 * twin needs, input schema (closed), output schema (its twin's answer) and explicit hints.
 */
export const toolDefinitions = (tools: readonly TwinnedTool[]) =>
  tools.map((twinnedTool) => {
    const { name, title, description, hints } = twinnedTool.tool;
    const { scopes } = twinnedTool.twin;
    return {
      name,
      title,
      description: `${description} Needs ${scopes.length === 0 ? 'no scope' : 'the scopes ' + scopes.join(', ')}.`,
      inputSchema: inputSchemaOf(twinnedTool),
      outputSchema: outputSchemaOf(twinnedTool),
      annotations: { title, ...hints },
    };
  });

/**
 * A result's text: its summary, then its structured content as JSON, as MCP asks of a tool with structured results so
 * a client that reads text alone still has it all. The JSON is the plain content's, never anything sent.
 */
const textsOf = (summary: string, structuredContent: unknown) => [
  { type: 'text' as const, text: summary },
  { type: 'text' as const, text: JSON.stringify(structuredContent) },
];

/** Refusals sent again after a wait: a busy organisation, agent or platform, or a key still being worked on. */
const RETRY_CODES: ReadonlySet<string> = new Set([...SEND_AGAIN_CODES, 'IDEMPOTENCY_KEY_BUSY']);

/** A tool's result for a refusal: its reason code's own words, never anything the caller sent. */
const refusedResult = ({ status, code }: Refused, correlationId: string) => {
  const structuredContent = {
    error: {
      code,
      message: REASON_CODES[code],
      correlationId,
      status,
      ...(RETRY_CODES.has(code) && { retryAfterSeconds: BUSY_RETRY_SECONDS }),
    },
  };
  return {
    content: textsOf(`Refused (${String(status)} ${code}): ${REASON_CODES[code]}`, structuredContent),
    structuredContent,
    isError: true,
  };
};

/** A tool's call not answered, as its twin's route refuses it (answerRefusal): its key's own answers too. */
const refusalOf = (answer: Refused | { readonly outcome: 'conflict' | 'busy' }): Refused => {
  if (answer.outcome === 'refused') return answer;
  return {
    outcome: 'refused',
    status: 409,
    code: answer.outcome === 'conflict' ? 'IDEMPOTENCY_KEY_REUSED' : 'IDEMPOTENCY_KEY_BUSY',
  };
};

/** Calls a tool for an agent the API has accepted: its result, and what the call was. */
export async function callTool(
  twinnedTool: TwinnedTool,
  sent: Readonly<Record<string, unknown>>,
  {
    agent,
    correlationId,
    useCases,
    logFailure,
  }: {
    readonly agent: AcceptedKey;
    readonly correlationId: string;
    readonly useCases: AgentUseCases;
    readonly logFailure: LogFailure;
  },
) {
  const { tool, twin } = twinnedTool;
  let pathIds: readonly string[] = [];
  let settled: Awaited<ReturnType<McpTool['answer']>>;
  try {
    const checked = checkedInput(twinnedTool, agent, sent);
    if (checked.outcome === 'refused') {
      settled = checked;
    } else {
      pathIds = pathIdsOf(checked.parts.params);
      settled = await tool.answer(useCases, { agent, ...checked.parts, idempotent: checked.idempotent, correlationId });
      // Written through its twin's own answer schema (SEC-AG-05) in here (6F1 G5), so an answer that fails it is a
      // logged failure, as its twin's would be, never an unlogged throw.
      if (settled.outcome === 'answered') settled = { ...settled, body: twin.answer.parse(settled.body) };
    }
  } catch (error) {
    // As the error path answers its twin: by its operation, so a decision in trouble is busy, never a 500.
    const { status, code } = responseFor(error, twin.operation);
    logFailure(error, { correlationId, status, operation: twin.operation, orgId: agent.orgId });
    settled = { outcome: 'refused', status, code };
  }
  if (settled.outcome === 'answered') {
    const called: ToolCalled = { tool: tool.name, status: twin.status, reason: undefined, pathIds };
    // Already written through its twin's answer schema above; every text in it made plain.
    const structuredContent = plainTexts(settled.body);
    const result = { content: textsOf(settled.summary, structuredContent), structuredContent, isError: false };
    return { result, called };
  }
  const refused = refusalOf(settled);
  const called: ToolCalled = { tool: tool.name, status: refused.status, reason: refused.code, pathIds };
  return { result: refusedResult(refused, correlationId), called };
}
