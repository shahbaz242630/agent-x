import { describe, expect, it } from 'vitest';

import { firstFileIn } from './tar.ts';

const BLOCK = 512;

/**
 * One tar entry as Docker writes it: a POSIX header with its checksum, then
 * the data padded to a block. `patch` changes the header before the checksum
 * is taken, so a test can plant a bad field behind a valid checksum.
 */
function entry(name: string, type: string, data: Buffer, patch: (header: Buffer) => void = () => undefined): Buffer {
  const header = Buffer.alloc(BLOCK);
  header.write(name, 0, 100, 'latin1');
  header.write('0000644 ', 100, 'latin1'); // mode
  header.write('0000000 ', 108, 'latin1'); // uid
  header.write('0000000 ', 116, 'latin1'); // gid
  header.write(`${data.length.toString(8).padStart(11, '0')} `, 124, 'latin1');
  header.write('00000000000 ', 136, 'latin1'); // mtime
  header.write(type, 156, 'latin1');
  header.write('ustar', 257, 'latin1');
  header.write('00', 263, 'latin1');
  patch(header);
  header.fill(0x20, 148, 156);
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(sum.toString(8).padStart(6, '0'), 148, 'latin1');
  header[154] = 0;
  const padded = Buffer.alloc(Math.ceil(data.length / BLOCK) * BLOCK);
  data.copy(padded);
  return Buffer.concat([header, padded]);
}

const END = Buffer.alloc(BLOCK * 2);
const CONTENTS = Buffer.from('an-opaque-token-value\n');

describe('reading a file out of `docker compose cp … -`', () => {
  it('returns the one file in the archive', () => {
    expect(firstFileIn(Buffer.concat([entry('automation.pat', '0', CONTENTS), END]))).toEqual(CONTENTS);
  });

  it('reads a file whose type is the old NUL form', () => {
    const archive = Buffer.concat([entry('automation.pat', String.fromCharCode(0), CONTENTS), END]);
    expect(firstFileIn(archive)).toEqual(CONTENTS);
  });

  it('steps over an extended header and a directory before the file', () => {
    const pax = entry('PaxHeaders/automation.pat', 'x', Buffer.from('27 mtime=1757894400.123456\n'));
    const directory = entry('pat-automation/', '5', Buffer.alloc(0));
    expect(firstFileIn(Buffer.concat([pax, directory, entry('automation.pat', '0', CONTENTS), END]))).toEqual(CONTENTS);
  });

  it('reads data that fills whole blocks, and an empty file', () => {
    const exact = Buffer.alloc(BLOCK * 2, 0x61);
    expect(firstFileIn(Buffer.concat([entry('big', '0', exact), END]))).toEqual(exact);
    expect(firstFileIn(Buffer.concat([entry('empty', '0', Buffer.alloc(0)), END]))).toEqual(Buffer.alloc(0));
  });

  it('refuses an archive with no file in it', () => {
    expect(() => firstFileIn(END)).toThrow('the archive holds no file');
    expect(() => firstFileIn(Buffer.alloc(0))).toThrow('the archive holds no file');
    expect(() => firstFileIn(Buffer.concat([entry('dir/', '5', Buffer.alloc(0)), END]))).toThrow(
      'the archive holds no file',
    );
  });

  it('refuses a damaged header rather than read the wrong bytes', () => {
    const archive = Buffer.concat([entry('automation.pat', '0', CONTENTS), END]);
    archive[0] = 0x41;
    expect(() => firstFileIn(archive)).toThrow('the archive has a damaged header');
  });

  it('refuses an archive cut short inside the file', () => {
    const archive = entry('automation.pat', '0', Buffer.alloc(BLOCK * 3, 0x61));
    expect(() => firstFileIn(archive.subarray(0, BLOCK * 2))).toThrow('the archive ends inside an entry');
  });

  it('refuses malformed and binary-encoded numbers', () => {
    const letters = entry('automation.pat', '0', CONTENTS, (header) => header.write('1234567x    ', 124, 'latin1'));
    expect(() => firstFileIn(letters)).toThrow('the archive has a malformed number');

    const binary = entry('automation.pat', '0', CONTENTS, (header) => {
      header[124] = 0x80;
    });
    expect(() => firstFileIn(binary)).toThrow('the archive uses a size this reader does not read');
  });
});
