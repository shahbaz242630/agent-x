// Gate proof for the format check: Prettier, with the repository's settings,
// must reject badly formatted code and must not be told to skip product code.
import * as prettier from 'prettier';
import { beforeAll, describe, expect, it } from 'vitest';

const FILE = 'packages/core/src/shared-kernel/clock.ts';
let options: prettier.Options;

beforeAll(async () => {
  options = { ...(await prettier.resolveConfig(FILE)), filepath: FILE };
});

describe('format: badly formatted code fails the check', () => {
  it('accepts code in the house style', async () => {
    expect(await prettier.check("export const limits = { perOrder: 'AED' };\n", options)).toBe(true);
  });

  it.each([
    ['cramped spacing', "export const limits = {perOrder:'AED'};\n"],
    ['double quotes', 'export const limits = { perOrder: "AED" };\n'],
    ['a missing semicolon', "export const limits = { perOrder: 'AED' }\n"],
  ])('rejects %s', async (_name, code) => {
    expect(await prettier.check(code, options)).toBe(false);
  });

  it('checks product code (it is not in .prettierignore)', async () => {
    const info = await prettier.getFileInfo(FILE, { ignorePath: '.prettierignore' });
    expect(info.ignored).toBe(false);
  });
});
