// Gate proof for the module-boundary rules (ADR-004, ADR-010, SEC-WEB-05, SEC-DATA-03): each
// fixture folder breaks one rule, and dependency-cruiser must report exactly
// the rules that folder breaks. A rule weakened in .dependency-cruiser.js fails
// here. For the rules built from a list of banned modules, every list entry
// also has its own fixture file, which must break the rule on its own.
import { readdirSync } from 'node:fs';
import path from 'node:path';

import { cruise, type IViolation } from 'dependency-cruiser';
import extractDepcruiseOptions from 'dependency-cruiser/config-utl/extract-depcruise-options';
import { beforeAll, describe, expect, it } from 'vitest';

import { CLOUD_SDKS, HTTP_CLIENTS, NETWORK_CORE_MODULES, OTHER_LOGGERS, TELEMETRY_SDKS } from '../banned-modules.ts';

const FIXTURES = 'tooling/gate-proofs/fixtures/boundaries';

/** Fixture folder → the rules its files break. */
const EXPECTED: Record<string, string[]> = {
  'application-to-infrastructure': ['application-not-to-infrastructure'],
  'business-to-platform': ['business-code-not-to-platform'],
  circular: ['no-circular'],
  // Also holds allowed cases: the outbound client importing node:https, and a
  // type-only import of node:http elsewhere.
  clean: [],
  'cloud-sdk': ['no-cloud-sdk', 'not-to-unresolvable'],
  'cloud-sdks': ['no-cloud-sdk', 'not-to-unresolvable'],
  'deep-import': ['no-deep-module-imports'],
  'deep-import-from-outside': ['no-deep-module-imports-from-outside'],
  'dev-dependency': ['product-code-uses-declared-dependencies'],
  'domain-purity': ['domain-is-pure'],
  'http-clients': ['network-only-through-platform-outbound', 'not-to-unresolvable'],
  // A stand-in package under node_modules, so the rule is proven against an installed path too.
  'installed-cloud-sdk': ['no-cloud-sdk', 'product-code-uses-declared-dependencies'],
  'module-map': ['module-map/agents'],
  // A test file outside the outbound folder is not exempt.
  'network-module-in-test': ['network-only-through-platform-outbound'],
  'network-modules': ['network-only-through-platform-outbound'],
  'other-loggers': ['no-other-logger', 'not-to-unresolvable'],
  // The logger's library, imported outside the logger (ADR-013).
  'logger-outside-observability': ['logger-only-in-platform-observability', 'not-to-unresolvable'],
  'platform-to-modules': ['platform-not-to-modules'],
  'postgres-driver': ['not-to-unresolvable', 'postgres-driver-only-in-platform-db'],
  // The test harness's db folder may use the driver; the rest of the testing package may not.
  'postgres-driver-in-testing': ['not-to-unresolvable', 'postgres-driver-only-in-platform-db'],
  // The two places the driver is allowed. The fixture has no installed driver, so only
  // not-to-unresolvable fires; the driver rule must not.
  'postgres-driver-allowed': ['not-to-unresolvable'],
  'query-builder': ['not-to-unresolvable', 'query-builder-only-in-infrastructure'],
  'shared-kernel-leaf': ['shared-kernel-is-a-leaf'],
  // The observability folder may import the logger's library, but no telemetry SDK.
  'telemetry-in-observability': ['no-telemetry-sdk', 'not-to-unresolvable'],
  'telemetry-sdks': ['no-telemetry-sdk', 'not-to-unresolvable'],
  'testing-in-product': ['testing-only-in-tests'],
  // Imports a tool that resolves only from the repository root's devDependencies.
  'undeclared-dependency': ['product-code-uses-declared-dependencies'],
  'unknown-module': ['module-map/suppliers', 'module-not-in-map/imported', 'module-not-in-map/imports'],
};

/**
 * Folder → the rule, and the banned-module list with one fixture file per
 * entry. Files are named after the module they import, with `/` written as `+`.
 */
const ONE_FILE_PER_ENTRY: Record<string, { rule: string; list: readonly string[] }> = {
  'cloud-sdks': { rule: 'no-cloud-sdk', list: CLOUD_SDKS },
  'http-clients': { rule: 'network-only-through-platform-outbound', list: HTTP_CLIENTS },
  'network-modules': { rule: 'network-only-through-platform-outbound', list: NETWORK_CORE_MODULES },
  'telemetry-sdks': { rule: 'no-telemetry-sdk', list: TELEMETRY_SDKS },
  'other-loggers': { rule: 'no-other-logger', list: OTHER_LOGGERS },
};
const ENTRY_FILES = 'packages/core/src/modules/suppliers/infrastructure';

let violations: IViolation[];

const folderOf = (file: string): string => file.slice(FIXTURES.length + 1).split('/')[0] ?? '';
const moduleOf = (file: string): string => path.basename(file, '.ts').replace('+', '/');

beforeAll(async () => {
  const options = await extractDepcruiseOptions('./.dependency-cruiser.js');
  const { output } = await cruise([FIXTURES], options);
  if (typeof output === 'string') {
    throw new TypeError('dependency-cruiser returned a report instead of a cruise result');
  }
  violations = output.summary.violations;
});

describe('module boundaries: every rule rejects its broken fixture', () => {
  const rulesBrokenIn = (folder: string): string[] =>
    [...new Set(violations.filter((v) => folderOf(v.from) === folder).map((v) => v.rule.name))].sort();

  it.each(Object.entries(EXPECTED))('%s', (folder, rules) => {
    expect(rulesBrokenIn(folder)).toEqual(rules);
  });

  it('reports no violation from a folder without an expectation', () => {
    expect([...new Set(violations.map((v) => folderOf(v.from)))].filter((folder) => !(folder in EXPECTED))).toEqual([]);
  });
});

describe('module boundaries: every entry in a banned-module list has its own broken fixture', () => {
  describe.each(Object.entries(ONE_FILE_PER_ENTRY))('%s', (folder, { rule, list }) => {
    const modules = readdirSync(path.join(FIXTURES, folder, ENTRY_FILES))
      .map(moduleOf)
      .sort();

    it('has a fixture for every entry', () => {
      const missing = list.filter((entry) => !modules.some((name) => new RegExp(`^(?:${entry})(?:/|$)`).test(name)));
      expect(missing).toEqual([]);
    });

    it(`breaks ${rule} with each fixture on its own`, () => {
      const breaking = violations.filter((v) => folderOf(v.from) === folder && v.rule.name === rule);
      expect([...new Set(breaking.map((v) => moduleOf(v.from)))].sort()).toEqual(modules);
    });
  });
});
