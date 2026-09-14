import { describe, expect, it } from 'vitest';

import { expiredContainerIds, parsePublishedPort } from './docker.ts';
import { POSTGRES_IMAGES } from './postgres-images.ts';

describe('the test database images', () => {
  it('covers the oldest and newest Postgres we support (ADR-010: 16 and 18)', () => {
    expect(Object.keys(POSTGRES_IMAGES)).toEqual(['db-pg16', 'db-pg18']);
  });

  it.each(Object.entries(POSTGRES_IMAGES))(
    'pins %s by digest, to an exact release of its major version',
    (project, image) => {
      const major = project.replace('db-pg', '');
      expect(image).toMatch(new RegExp(`^postgres:${major}\\.\\d+-[a-z]+@sha256:[0-9a-f]{64}$`));
    },
  );
});

describe('parsePublishedPort', () => {
  it('reads the port Docker published on 127.0.0.1', () => {
    expect(parsePublishedPort('127.0.0.1:55001\n')).toBe(55_001);
    expect(parsePublishedPort('[::1]:55002\n127.0.0.1:55001')).toBe(55_001);
  });

  it.each(['', '0.0.0.0:55001', '[::]:55001', '127.0.0.1:0', '127.0.0.1:65536', 'garbage'])(
    'refuses output with no usable 127.0.0.1 port: %j',
    (output) => {
      expect(() => parsePublishedPort(output)).toThrow(/published no port/);
    },
  );
});

describe('expiredContainerIds', () => {
  const now = 1_000_000;

  it('picks the containers whose expiry has passed, or has no readable expiry', () => {
    const listing = ['aaa 999999', 'bbb 1000000', 'ccc 1000001', 'ddd', 'eee soon', ''].join('\n');
    expect(expiredContainerIds(listing, now)).toEqual(['aaa', 'bbb', 'ddd', 'eee']);
  });

  it('picks nothing from an empty listing', () => {
    expect(expiredContainerIds('\n', now)).toEqual([]);
  });
});
