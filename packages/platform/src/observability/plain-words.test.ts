import { describe, expect, it } from 'vitest';

import { PLAIN_WORDS, saysFor } from './plain-words.ts';
import { redactJson } from './redact.ts';

const ENTRIES = Object.entries(PLAIN_WORDS);
/** Whole sentences: a capital first, a full stop last. */
const SENTENCES = /^[A-Z].*\.$/s;
/** What a code reads like: an event name, a field name or a run of digits like an ID. */
const CODE_LIKE = /[a-z]\.[a-z]|[a-z]_[a-z]|[a-z][A-Z]|\d{3}/;
const MOST_CHARACTERS = 300;

describe('decision 29: every warning and error has plain words', () => {
  it('lists the warnings and errors, and the logger’s own two', () => {
    expect(ENTRIES.length).toBeGreaterThan(100);
    expect(PLAIN_WORDS).toHaveProperty(['log.suppressed']);
    expect(PLAIN_WORDS).toHaveProperty(['log.invalid_event']);
  });

  it.each(ENTRIES)('%s: three short whole sentences, with no code in them', (event, words) => {
    for (const part of [words.happened, words.broke, words.next]) {
      expect(part).toMatch(SENTENCES);
      expect(part).not.toMatch(CODE_LIKE);
    }
    expect(saysFor(event).length).toBeLessThan(MOST_CHARACTERS);
  });

  it.each(ENTRIES)('%s: the redaction leaves the words whole', (event) => {
    expect(redactJson(saysFor(event))).toBe(saysFor(event));
  });

  it('joins the three parts in order', () => {
    const words = PLAIN_WORDS['log.invalid_event'];
    expect(saysFor('log.invalid_event')).toBe(`${words.happened} ${words.broke} ${words.next}`);
  });

  it('still says something for an event with no words, which only a cast can log', () => {
    expect(saysFor('not.catalogued')).toMatch(/^Something went wrong that has no plain words yet\. /);
    expect(saysFor('toString')).toMatch(/^Something went wrong/);
  });
});
