import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import {
  downloadPinned,
  downloadPinnedTo,
  type Fetch,
  sha256Of,
  sha256OfFile,
  type StreamingFetch,
} from './pinned-download.ts';

const dir = mkdtempSync(path.join(tmpdir(), 'agentx-pinned-'));
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("hashing an installed tool's file", () => {
  it('reads it in pieces and gets the same SHA-256 as hashing it whole, across piece boundaries', () => {
    for (const size of [0, 1, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1, 3 * 1024 * 1024 + 7]) {
      const bytes = Uint8Array.from({ length: size }, (_, index) => (index * 31 + 7) % 256);
      const file = path.join(dir, `file-${String(size)}`);
      writeFileSync(file, bytes);
      expect(sha256OfFile(file)).toBe(sha256Of(bytes));
    }
  });

  it('reports a missing file as missing, and any other failure as an error', () => {
    expect(sha256OfFile(path.join(dir, 'absent'))).toBeUndefined();
    expect(() => sha256OfFile(dir)).toThrow();
  });
});

/** A release file served in pieces, as a slow line delivers it. */
const serve =
  (pieces: readonly Uint8Array[], status = 200): StreamingFetch =>
  () =>
    Promise.resolve({
      ok: status === 200,
      status,
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          for (const piece of pieces) controller.enqueue(piece);
          controller.close();
        },
      }),
    });

describe('a large download, written as it arrives', () => {
  const pieces = Array.from({ length: 40 }, (_, index) =>
    Uint8Array.from({ length: 4099 }, (__, at) => (index + at) % 256),
  );
  const whole = Buffer.concat(pieces);
  const pin = sha256Of(whole);

  it('installs it at the target, whole and runnable, and leaves nothing beside it', async () => {
    const target = path.join(mkdtempSync(path.join(dir, 'stream-')), 'tool', '1.0', 'tool');
    await downloadPinnedTo('https://example.invalid/tool', 'tool', pin, target, serve(pieces));
    expect(readFileSync(target).equals(whole)).toBe(true);
    expect(readdirSync(path.dirname(target))).toEqual(['tool']);
    if (process.platform !== 'win32') expect(statSync(target).mode & 0o111).not.toBe(0);
  });

  it('refuses a file that does not match its pin, and installs nothing', async () => {
    const target = path.join(mkdtempSync(path.join(dir, 'stream-')), 'tool');
    const tampered = [...pieces.slice(0, -1), Uint8Array.from([1, 2, 3])];
    await expect(
      downloadPinnedTo('https://example.invalid/tool', 'tool', pin, target, serve(tampered)),
    ).rejects.toThrow(/tool does not match its pinned SHA-256 \(got [0-9a-f]{64}\); nothing was installed\./);
    expect(existsSync(target)).toBe(false);
    expect(readdirSync(path.dirname(target))).toEqual([]);
  });

  it('refuses a failed request, or one with no body, before writing anything', async () => {
    const target = path.join(mkdtempSync(path.join(dir, 'stream-')), 'absent', 'tool');
    await expect(
      downloadPinnedTo('https://example.invalid/tool', 'tool', pin, target, serve(pieces, 404)),
    ).rejects.toThrow('Downloading tool failed: HTTP 404.');
    const empty: StreamingFetch = () => Promise.resolve({ ok: true, status: 200, body: null });
    await expect(downloadPinnedTo('https://example.invalid/tool', 'tool', pin, target, empty)).rejects.toThrow(
      'Downloading tool failed: HTTP 200.',
    );
    expect(existsSync(path.dirname(target))).toBe(false);
  });

  it('leaves nothing when the line drops partway', async () => {
    const target = path.join(mkdtempSync(path.join(dir, 'stream-')), 'tool');
    const dropping: StreamingFetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(pieces[0] ?? new Uint8Array());
            controller.error(new Error('the line dropped'));
          },
        }),
      });
    await expect(downloadPinnedTo('https://example.invalid/tool', 'tool', pin, target, dropping)).rejects.toThrow(
      'the line dropped',
    );
    expect(readdirSync(path.dirname(target))).toEqual([]);
  });

  it('gives the download a deadline, so a stall fails instead of hanging', async () => {
    const target = path.join(mkdtempSync(path.join(dir, 'stream-')), 'tool');
    const signals: unknown[] = [];
    const recording: StreamingFetch = (url, init) => {
      signals.push(init?.signal);
      return serve(pieces)(url);
    };
    await downloadPinnedTo('https://example.invalid/tool', 'tool', pin, target, recording);
    expect(signals).toHaveLength(1);
    expect(signals[0]).toBeInstanceOf(AbortSignal);
  });
});

describe('a download GitHub fails now and then (S35, S59, S70)', () => {
  const file = Uint8Array.from([1, 2, 3, 4]);
  const pin = sha256Of(file);
  const ok = { ok: true, status: 200, arrayBuffer: () => Promise.resolve(file.slice().buffer) };
  const failing = (status: number) => ({ ok: false, status, arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)) });
  /**
   * A fetch that gives each answer in turn, counting the calls (an Error is
   * thrown, as a dropped line is), and a pause that records its length only.
   */
  const answering = (...answers: readonly (Awaited<ReturnType<Fetch>> | Error)[]) => {
    const calls: string[] = [];
    const waits: number[] = [];
    const fetchFile: Fetch = (url) => {
      calls.push(url);
      const answer = answers[calls.length - 1];
      if (answer === undefined) return Promise.reject(new Error('asked too often'));
      return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
    };
    const wait = (ms: number) => {
      waits.push(ms);
      return Promise.resolve();
    };
    const download = () => downloadPinned('https://example.invalid/tool', 'tool', pin, fetchFile, wait);
    return { calls, waits, download };
  };

  it('asks again after a server error or a dropped line, waiting longer each time', async () => {
    const { calls, waits, download } = answering(failing(500), new TypeError('fetch failed'), ok);

    expect(await download()).toEqual(file);
    expect(calls).toHaveLength(3);
    expect(waits).toEqual([2000, 4000]);
  });

  it.each([
    ['server errors', [failing(502), failing(503), failing(504)], 'Downloading tool failed: HTTP 504.'],
    ['dropped lines', [new TypeError('one'), new TypeError('two'), new TypeError('fetch failed')], 'fetch failed'],
  ])('gives up after three tries, with the last answer: %s', async (_what, answers, last) => {
    const { calls, download } = answering(...answers);

    await expect(download()).rejects.toThrow(last);
    expect(calls).toHaveLength(3);
  });

  it.each([
    ['a 404', failing(404), 'Downloading tool failed: HTTP 404.'],
    ['a deadline passed', new DOMException('the deadline passed', 'TimeoutError'), 'the deadline passed'],
    ['an abort', new DOMException('stopped', 'AbortError'), 'stopped'],
  ])('never asks again after %s', async (_what, answer, error) => {
    const { calls, download } = answering(answer, ok);

    await expect(download()).rejects.toThrow(error);
    expect(calls).toHaveLength(1);
  });

  it('asks again for a large file too', async () => {
    const target = path.join(mkdtempSync(path.join(dir, 'retry-')), 'tool');
    const failed = serve([file], 500);
    const served = serve([file]);
    let calls = 0;
    const streaming: StreamingFetch = (url) => {
      calls += 1;
      return calls === 1 ? failed(url) : served(url);
    };

    await downloadPinnedTo('https://example.invalid/tool', 'tool', pin, target, streaming, () => Promise.resolve());
    expect(readFileSync(target)).toEqual(Buffer.from(file));
    expect(calls).toBe(2);
  });
});
