// B4-6c: the API knows the login service's break-glass admin by the login
// name Zitadel gives the admin it is first set up with, made from its username
// and first organisation. Staging (apps.bicep) and the compose stack set up
// Zitadel with the very username and organisation the API expects, or the API
// would let that admin sign in; this holds each to them.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

import {
  BREAK_GLASS_USERNAME,
  FIRST_ORGANIZATION,
} from '../../packages/core/src/modules/identity/domain/break-glass.ts';

/** A setting's literal value in apps.bicep's list of Zitadel's settings: `name: '…'` then `value: '…'`. */
function bicepSetting(text: string, name: string): string | undefined {
  const found = new RegExp(`name: '${name}'\\s*\\r?\\n\\s*value: '([^']*)'`).exec(text);
  return found?.[1];
}

describe('B4-6c Zitadel is first set up with the break-glass admin the API refuses', () => {
  it('on staging (apps.bicep)', () => {
    const text = readFileSync('deploy/azure/apps.bicep', 'utf8');

    expect(bicepSetting(text, 'ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME')).toBe(BREAK_GLASS_USERNAME);
    expect(bicepSetting(text, 'ZITADEL_FIRSTINSTANCE_ORG_NAME')).toBe(FIRST_ORGANIZATION);
  });

  it('on the compose stack', () => {
    const file = parse(readFileSync('deploy/compose/compose.yaml', 'utf8'), { merge: true }) as {
      services: Record<string, { environment?: Record<string, string> }>;
    };
    const setUp = Object.values(file.services).filter(
      (service) => service.environment?.ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME !== undefined,
    );

    expect(setUp.length).toBeGreaterThan(0);
    for (const service of setUp) {
      expect(service.environment?.ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME).toBe(BREAK_GLASS_USERNAME);
      expect(service.environment?.ZITADEL_FIRSTINSTANCE_ORG_NAME).toBe(FIRST_ORGANIZATION);
    }
  });
});
