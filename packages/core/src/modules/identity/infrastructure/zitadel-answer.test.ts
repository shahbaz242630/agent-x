// B6-2b: reading an answer from the login service, bounded.
import { describe, expect, it } from 'vitest';

import { boundedText } from './zitadel-answer.ts';

const tooLarge = () => new Error('too large');

describe('an answer from the login service, bounded (B6-2b)', () => {
  it('reads a body up to the bound, and an answer with no body as empty', async () => {
    expect(await boundedText(new Response('abcd'), 4, tooLarge)).toBe('abcd');
    expect(await boundedText(new Response(null, { status: 204 }), 4, tooLarge)).toBe('');
  });

  it('refuses a body past the bound, however the answer declares its length', async () => {
    const answer = new Response('abcde', { headers: { 'content-length': '1' } });

    await expect(boundedText(answer, 4, tooLarge)).rejects.toThrow('too large');
  });
});
