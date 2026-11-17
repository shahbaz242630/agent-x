// BR-19 (6E1c): the guide for agent builders, docs/api/README.md, can't go
// stale without a test failing. It names every scope and every operation an
// agent may call that the OpenAPI document holds; every operation and reason
// code it names is one the document still holds. The document stays the one
// source of truth: the guide never copies its list of codes.
import { readFileSync } from 'node:fs';

import { KEY_DAYS, KEY_PREFIX, SCOPES } from '@agentx/core/modules/agents';
import { isReasonCode } from '@agentx/core/shared-kernel';
import { IDEMPOTENCY_RETENTION_DAYS } from '@agentx/platform/db';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { GUIDE_URL } from './api-guide.ts';
import { IDEMPOTENCY_KEY_RULE } from './write-operations.ts';

const GUIDE = readFileSync(new URL('../../../docs/api/README.md', import.meta.url), 'utf8');

const DOCUMENT = z
  .object({
    paths: z.record(
      z.string(),
      z.record(
        z.string(),
        z.object({ 'x-access': z.array(z.string()), 'x-agent-scopes': z.array(z.string()).optional() }),
      ),
    ),
  })
  .parse(JSON.parse(readFileSync(new URL('../openapi.json', import.meta.url), 'utf8')));

/** Every operation the document holds, as "METHOD /path", with who may call it. */
const operations = Object.entries(DOCUMENT.paths).flatMap(([path, item]) =>
  Object.entries(item).map(([method, operation]) => ({
    at: `${method.toUpperCase()} ${path}`,
    access: operation['x-access'],
    scopes: operation['x-agent-scopes'] ?? [],
  })),
);

describe('BR-19 the guide for agent builders matches the OpenAPI document', () => {
  it('names every scope an agent key can hold', () => {
    expect(SCOPES.filter((scope) => !GUIDE.includes(`\`${scope}\``))).toEqual([]);
  });

  it("puts each operation an agent may call in the scope table's row for each scope it needs", () => {
    // A table row starts with its scope; prettier pads the cell after it.
    const rowOf = (scope: string) => GUIDE.split(/\r?\n/).find((line) => line.startsWith(`| \`${scope}\` `)) ?? '';
    const missing = operations
      .filter(({ access, at }) => access.includes('agent') && !at.startsWith('HEAD '))
      .flatMap(({ at, scopes }) =>
        scopes.filter((scope) => !rowOf(scope).includes(`\`${at}\``)).map((scope) => `${at}: ${scope}`),
      );
    expect(missing).toEqual([]);
  });

  it("states the numbers and forms the code holds: a key's life, its prefix, the idempotency key's rule and how long keys are kept", () => {
    expect(GUIDE).toContain(`${String(KEY_DAYS)} days after it is made`);
    expect(GUIDE).toContain(`\`${KEY_PREFIX}<keyId>_<secret>\``);
    expect(GUIDE).toContain(IDEMPOTENCY_KEY_RULE);
    expect(GUIDE).toContain(`at least ${String(IDEMPOTENCY_RETENTION_DAYS)} days`);
  });

  it('names every operation an agent may call (HEAD aside, which Fastify adds to each GET)', () => {
    const missing = operations
      .filter(({ at, access }) => access.includes('agent') && !at.startsWith('HEAD '))
      .filter(({ at }) => !GUIDE.includes(`\`${at}\``));
    expect(missing.map(({ at }) => at)).toEqual([]);
  });

  it('names only operations the document holds', () => {
    const held = new Set(operations.map(({ at }) => at));
    const named = [...GUIDE.matchAll(/`((?:GET|POST|PUT|PATCH|DELETE) \/[^`\s]*)`/g)].map((match) => match[1]);
    expect(named.length).toBeGreaterThan(0);
    expect(named.filter((at) => at === undefined || !held.has(at))).toEqual([]);
  });

  it('names only reason codes the document holds, and only a few of them: the document keeps the list', () => {
    const named = [...GUIDE.matchAll(/`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`/g)].map((match) => match[1]);
    expect(named.length).toBeGreaterThan(0);
    expect(named.filter((code) => code === undefined || !isReasonCode(code))).toEqual([]);
    expect(new Set(named).size).toBeLessThan(10);
  });

  it('points at the OpenAPI document as its source of truth, and is where the document says it is', () => {
    expect(GUIDE).toContain('](../../apps/api/openapi.json)');
    expect(GUIDE_URL.endsWith('/docs/api/README.md')).toBe(true);
  });
});
