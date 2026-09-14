import { describe, expect, it } from 'vitest';

import { isForeignWrite } from './origin-check.ts';

const OURS = 'https://app.agentx.example';

describe('SEC-WEB-01 which requests the Origin rule refuses', () => {
  it.each(['GET', 'HEAD'])('never %s, which only reads', (method) => {
    expect(isForeignWrite(method, undefined, OURS)).toBe(false);
    expect(isForeignWrite(method, 'https://evil.example', OURS)).toBe(false);
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'QUERY', 'get'])(
    '%s without our origin, since it may change something',
    (method) => {
      expect(isForeignWrite(method, undefined, OURS)).toBe(true);
      expect(isForeignWrite(method, 'https://evil.example', OURS)).toBe(true);
      expect(isForeignWrite(method, OURS, OURS)).toBe(false);
    },
  );
});
