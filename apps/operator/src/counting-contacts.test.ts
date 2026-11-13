// OR2b: the counting contacts as the operator's log line shows them, each address masked, never whole.
import { createLogger } from '@agentx/platform/observability';
import { describe, expect, it } from 'vitest';

import { shownContacts } from './counting-contacts.ts';

const CONTACTS = [
  {
    id: '0199a0f0-0000-7000-8000-0000000000c1',
    email: 'sara@company.example.test',
    countsFrom: new Date('2026-10-08T09:00:00Z'),
  },
  { id: '0199a0f0-0000-7000-8000-0000000000c2', email: 'finance+ops@acme.example.test', countsFrom: new Date(0) },
];

describe('the counting contacts shown (OR2b)', () => {
  it('names each by its ID, its address masked as a reset email shows it, and its start', () => {
    expect(shownContacts(CONTACTS)).toEqual([
      { contactId: CONTACTS[0]?.id, masked: 's***@company.example.test', countsFrom: '2026-10-08T09:00:00.000Z' },
      { contactId: CONTACTS[1]?.id, masked: 'f***@acme.example.test', countsFrom: '1970-01-01T00:00:00.000Z' },
    ]);
  });

  it('logs them masked, the redactor keeping the masked form and never seeing a whole address', () => {
    const lines: string[] = [];
    const logger = createLogger({
      service: 'test',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 1000 } },
      destination: { write: (line: string) => lines.push(line) },
    });
    logger.info('operator.counting_contacts', { count: 2, contacts: shownContacts(CONTACTS) });
    const [line = ''] = lines;
    expect(line).toContain('s***@company.example.test');
    expect(line).toContain('f***@acme.example.test');
    expect(line).not.toContain('sara');
    expect(line).not.toContain('finance');
  });
});
