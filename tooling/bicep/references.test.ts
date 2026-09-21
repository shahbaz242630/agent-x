// Asking Bicep which files a deployment reads (T1a). A stand-in server answers
// as a test says, one way for each way an answer can be wrong; the real pinned
// Bicep answers the rest (deploy/azure/release.test.ts asks it about our own
// deployments).
import { EventEmitter } from 'node:events';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { describe, expect, it, vi } from 'vitest';

import { fileReferences, type Server } from './references.ts';

/** One message, framed as Bicep frames them. */
const framed = (message: unknown): string => {
  const body = JSON.stringify(message);
  return `Content-Length: ${String(Buffer.byteLength(body))}\r\n\r\n${body}`;
};

/** A question as the stand-in read it. */
interface Question {
  readonly jsonrpc: unknown;
  readonly id: number;
  readonly method: unknown;
  readonly params: { readonly path: string };
}

/** Every framed message in some text. */
function questionsIn(text: string): Question[] {
  const found: Question[] = [];
  let rest = text;
  for (;;) {
    const header = /^Content-Length: (\d+)\r\n\r\n/.exec(rest);
    if (header === null) return found;
    const start = header[0].length;
    const length = Number(header[1]);
    found.push(JSON.parse(rest.slice(start, start + length)) as Question);
    rest = rest.slice(start + length);
  }
}

/** A stand-in server: what it was asked, and what it sends back, when the test says. */
class Stub extends EventEmitter implements Server {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly questions: Question[] = [];
  killed = false;

  constructor(answer?: (questions: readonly Question[], stub: Stub) => void) {
    super();
    this.stdin.on('data', (chunk: Buffer) => {
      this.questions.push(...questionsIn(chunk.toString('utf8')));
      answer?.(this.questions, this);
    });
  }

  send(text: string): void {
    this.stdout.write(text);
  }

  kill(): boolean {
    this.killed = true;
    return true;
  }
}

/** Asks the stand-in about the files, with its outcome: the answers or the error, and the stand-in. */
async function asked(
  files: readonly string[],
  answer?: (questions: readonly Question[], stub: Stub) => void,
  deadlineMs = 5_000,
): Promise<{ answers?: ReadonlyMap<string, readonly string[]>; error?: string; stub: Stub }> {
  const stub = new Stub(answer);
  try {
    const answers = await fileReferences(files, { start: () => stub, deadlineMs });
    return { answers, stub };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error), stub };
  }
}

/** Answers each question with a list naming its file. */
const listing =
  (reply: (question: Question) => unknown = (question) => ({ filePaths: [question.params.path, 'names.bicep'] })) =>
  (questions: readonly Question[], stub: Stub): void => {
    for (const question of questions) stub.send(framed({ jsonrpc: '2.0', id: question.id, result: reply(question) }));
  };

describe('asking Bicep which files a deployment reads', () => {
  it('asks once for each file, numbered from 1, and gives back each list by its file', async () => {
    const { answers, stub } = await asked(['a.bicepparam', 'b.bicepparam'], listing());
    expect(stub.questions).toEqual([
      { jsonrpc: '2.0', id: 1, method: 'bicep/getFileReferences', params: { path: 'a.bicepparam' } },
      { jsonrpc: '2.0', id: 2, method: 'bicep/getFileReferences', params: { path: 'b.bicepparam' } },
    ]);
    expect(answers).toEqual(
      new Map([
        ['a.bicepparam', ['a.bicepparam', 'names.bicep']],
        ['b.bicepparam', ['b.bicepparam', 'names.bicep']],
      ]),
    );
    // Stopped once every answer is in.
    expect(stub.killed).toBe(true);
    expect(stub.stdin.writableEnded).toBe(true);
  });

  it('takes answers in any order, split anywhere, past a notification, and each header in any case', async () => {
    const { answers } = await asked(['a.bicepparam', 'b.bicepparam'], (questions, stub) => {
      const body = JSON.stringify({ jsonrpc: '2.0', id: 1, result: { filePaths: ['x.bicep'] } });
      const text = [
        framed({ jsonrpc: '2.0', method: 'window/logMessage', params: { message: 'hello' } }),
        framed({ jsonrpc: '2.0', id: 2, result: { filePaths: ['y.bicep'] } }),
        `content-length:${String(Buffer.byteLength(body))}\r\nContent-Type: application/json\r\n\r\n${body}`,
      ].join('');
      expect(questions).toHaveLength(2);
      // One character at a time: a header, or a body, split between two reads.
      for (const character of text) stub.send(character);
    });
    expect(answers).toEqual(
      new Map([
        ['a.bicepparam', ['x.bicep']],
        ['b.bicepparam', ['y.bicep']],
      ]),
    );
  });

  it('starts nothing when asked about nothing', async () => {
    let started = false;
    const answers = await fileReferences([], {
      start: () => {
        started = true;
        return new Stub();
      },
    });
    expect(answers).toEqual(new Map());
    expect(started).toBe(false);
  });

  it("refuses an answer that isn't one, whatever came before it, and stops the server", async () => {
    const cases: [(question: Question) => unknown, string][] = [
      [() => ({ filePaths: 'a.bicep' }), "Bicep's answer for a.bicepparam isn't a list of files"],
      [() => ({ filePaths: [1] }), "Bicep's answer for a.bicepparam isn't a list of files"],
      // A deployment reads at least its own parameters file.
      [() => ({ filePaths: [] }), "Bicep's answer for a.bicepparam isn't a list of files"],
      [() => ({}), "Bicep's answer for a.bicepparam isn't a list of files"],
      [() => null, "Bicep's answer for a.bicepparam isn't a list of files"],
    ];
    for (const [reply, message] of cases) {
      const { error, stub } = await asked(['a.bicepparam'], listing(reply));
      expect(error).toBe(message);
      expect(stub.killed).toBe(true);
    }
  });

  it('says why when Bicep says it could not tell, or gives no reason', async () => {
    const failing =
      (error: unknown) =>
      (questions: readonly Question[], stub: Stub): void => {
        stub.send(framed({ jsonrpc: '2.0', id: questions[0]?.id, error }));
      };
    expect((await asked(['a.bicepparam'], failing({ code: -32000, message: 'Could not find file' }))).error).toBe(
      "Bicep couldn't say what a.bicepparam reads: Could not find file",
    );
    expect((await asked(['a.bicepparam'], failing({ code: -32000 }))).error).toBe(
      "Bicep couldn't say what a.bicepparam reads: it gave no reason",
    );
    expect((await asked(['a.bicepparam'], failing('broken'))).error).toBe(
      "Bicep couldn't say what a.bicepparam reads: it gave no reason",
    );
  });

  it("refuses an answer to a question it wasn't asked, or one answered twice", async () => {
    for (const id of [0, 3, '1', null]) {
      const { error } = await asked(['a.bicepparam', 'b.bicepparam'], (_questions, stub) => {
        stub.send(framed({ jsonrpc: '2.0', id, result: { filePaths: ['x.bicep'] } }));
      });
      expect(error).toBe("Bicep answered a question it wasn't asked");
    }
    const twice = await asked(['a.bicepparam', 'b.bicepparam'], (_questions, stub) => {
      stub.send(framed({ jsonrpc: '2.0', id: 1, result: { filePaths: ['x.bicep'] } }));
      stub.send(framed({ jsonrpc: '2.0', id: 1, result: { filePaths: ['x.bicep'] } }));
    });
    expect(twice.error).toBe("Bicep answered a question it wasn't asked");
  });

  it('refuses a message framed wrongly, or too long to be a list of files', async () => {
    const sending = (text: string) => (_questions: readonly Question[], stub: Stub) => {
      stub.send(text);
    };
    const cases: [string, string][] = [
      ['Content-Type: application/json\r\n\r\n{}', "a message from Bicep didn't give one Content-Length"],
      ['Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}', "a message from Bicep didn't give one Content-Length"],
      ['Content-Length: two\r\n\r\n{}', "a message from Bicep didn't give one Content-Length"],
      ['Content-Length: 1048577\r\n\r\n{}', 'a message from Bicep would hold 1048577 bytes, too many'],
      [`Content-Length: 2${' '.repeat(1100)}`, "a message from Bicep didn't end its header"],
      ['Content-Length: 3\r\n\r\n{x}', "a message from Bicep wasn't JSON"],
    ];
    for (const [text, message] of cases) {
      const { error, stub } = await asked(['a.bicepparam'], sending(text));
      expect(error).toBe(message);
      expect(stub.killed).toBe(true);
    }
  });

  it('says why when Bicep stops, fails to start or takes no questions, with what it said of it', async () => {
    const stopping =
      (code: number | null, signal: string | null, said = '') =>
      (_questions: readonly Question[], stub: Stub) => {
        stub.stderr.write(said);
        // What it said is read before it is judged to have stopped.
        setImmediate(() => stub.emit('close', code, signal));
      };
    expect((await asked(['a.bicepparam'], stopping(1, null, 'Unhandled exception\n'))).error).toBe(
      'Bicep stopped before answering (status 1): Unhandled exception',
    );
    expect((await asked(['a.bicepparam'], stopping(null, 'SIGKILL'))).error).toBe(
      'Bicep stopped before answering (SIGKILL)',
    );
    // Only the end of a long complaint is kept.
    const long = await asked(['a.bicepparam'], stopping(1, null, `${'x'.repeat(3000)}the end`));
    expect(long.error?.endsWith('xthe end')).toBe(true);
    expect(long.error?.length).toBeLessThan(2100);

    const failed = await asked(['a.bicepparam'], (_questions, stub) => {
      stub.emit('error', new Error('spawn bicep ENOENT'));
    });
    expect(failed.error).toBe("Bicep couldn't be run (spawn bicep ENOENT)");
    const refused = await asked(['a.bicepparam'], (_questions, stub) => {
      stub.stdin.emit('error', new Error('write EPIPE'));
    });
    expect(refused.error).toBe('Bicep took no questions (write EPIPE)');
  });

  it("gives up when Bicep doesn't answer every question in time, and stops it", async () => {
    const { error, stub } = await asked(
      ['a.bicepparam', 'b.bicepparam'],
      (questions, stub_) => {
        stub_.send(framed({ jsonrpc: '2.0', id: questions[0]?.id, result: { filePaths: ['x.bicep'] } }));
      },
      50,
    );
    expect(error).toBe("Bicep didn't answer within 0.05 s");
    expect(stub.killed).toBe(true);
  });

  // A deadline left running would hold CI's release open for its minute.
  it('leaves no deadline running once it has ended, answered or not', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      expect((await asked(['a.bicepparam'], listing())).answers?.size).toBe(1);
      expect(vi.getTimerCount()).toBe(0);
      expect(
        (
          await asked(
            ['a.bicepparam'],
            listing(() => ({})),
          )
        ).error,
      ).toMatch(/isn't a list of files/);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('is what the pinned Bicep answers, and its error for a file that is not there', async () => {
    const dir = fileURLToPath(new URL('../../deploy/azure/', import.meta.url));
    const params = path.join(dir, 'staging.certificates.bicepparam');
    const missing = path.join(dir, 'missing.bicepparam');
    const answers = await fileReferences([params]);
    expect(answers.get(params)).toContain(path.join(dir, 'certificates.bicep'));
    await expect(fileReferences([params, missing])).rejects.toThrow(
      `Bicep couldn't say what ${missing} reads: An error occurred reading file.`,
    );
  }, 60_000);
});
