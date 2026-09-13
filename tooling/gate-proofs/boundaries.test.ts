// Gate proof for the module-boundary rules (ADR-004, ADR-010): each fixture
// folder breaks one rule, and dependency-cruiser must report exactly the rules
// that folder breaks. A rule weakened in .dependency-cruiser.js fails here.
import { cruise } from 'dependency-cruiser';
import extractDepcruiseOptions from 'dependency-cruiser/config-utl/extract-depcruise-options';
import { beforeAll, describe, expect, it } from 'vitest';

const FIXTURES = 'tooling/gate-proofs/fixtures/boundaries';

/** Fixture folder → the rules its files break. */
const EXPECTED: Record<string, string[]> = {
  'application-to-infrastructure': ['application-not-to-infrastructure'],
  'business-to-platform': ['business-code-not-to-platform'],
  circular: ['no-circular'],
  clean: [],
  'cloud-sdk': ['no-cloud-sdk', 'not-to-unresolvable'],
  'deep-import': ['no-deep-module-imports'],
  'deep-import-from-outside': ['no-deep-module-imports-from-outside'],
  'dev-dependency': ['product-code-uses-declared-dependencies'],
  'domain-purity': ['domain-is-pure'],
  // A stand-in package under node_modules, so the rule is proven against an installed path too.
  'installed-cloud-sdk': ['no-cloud-sdk', 'product-code-uses-declared-dependencies'],
  'module-map': ['module-map/agents'],
  'observability-sdk': ['not-to-unresolvable', 'observability-sdks-only-in-platform-observability'],
  'platform-to-modules': ['platform-not-to-modules'],
  'postgres-driver': ['not-to-unresolvable', 'postgres-driver-only-in-platform-db'],
  'query-builder': ['not-to-unresolvable', 'query-builder-only-in-infrastructure'],
  'shared-kernel-leaf': ['shared-kernel-is-a-leaf'],
  'testing-in-product': ['testing-only-in-tests'],
  // Imports a tool that resolves only from the repository root's devDependencies.
  'undeclared-dependency': ['product-code-uses-declared-dependencies'],
  'unknown-module': ['module-map/suppliers', 'module-not-in-map/imported', 'module-not-in-map/imports'],
};

let brokenRulesByFolder: Map<string, Set<string>>;

beforeAll(async () => {
  const options = await extractDepcruiseOptions('./.dependency-cruiser.js');
  const { output } = await cruise([FIXTURES], options);
  if (typeof output === 'string') {
    throw new TypeError('dependency-cruiser returned a report instead of a cruise result');
  }

  brokenRulesByFolder = new Map();
  for (const violation of output.summary.violations) {
    const folder = violation.from.slice(FIXTURES.length + 1).split('/')[0] ?? '';
    const rules = brokenRulesByFolder.get(folder) ?? new Set<string>();
    rules.add(violation.rule.name);
    brokenRulesByFolder.set(folder, rules);
  }
});

describe('module boundaries: every rule rejects its broken fixture', () => {
  it.each(Object.entries(EXPECTED))('%s', (folder, rules) => {
    expect([...(brokenRulesByFolder.get(folder) ?? [])].sort()).toEqual(rules);
  });

  it('reports no violation from a folder without an expectation', () => {
    expect([...brokenRulesByFolder.keys()].filter((folder) => !(folder in EXPECTED))).toEqual([]);
  });
});
