// Reads a file out of the tar stream that `docker compose cp <service>:<file> -`
// writes to stdout, so a token copied out of the stack never touches the
// host's disk. Just enough of the format for what Docker writes: 512-byte
// POSIX headers, with extended (PAX) headers or directories allowed before the
// file.
const BLOCK = 512;

const SIZE = { start: 124, end: 136 };
const CHECKSUM = { start: 148, end: 156 };
const TYPE = 156;
const REGULAR_FILE = new Set([0x30, 0x00]); // '0', and the old NUL form
const NUL = String.fromCharCode(0);

/** An octal number field: digits, perhaps space-padded, ended by NUL or space. */
function octal(field: Buffer): number {
  if (((field[0] ?? 0) & 0x80) !== 0) throw new Error('the archive uses a size this reader does not read');
  const text = (field.toString('latin1').split(NUL)[0] ?? '').trim();
  if (!/^[0-7]+$/.test(text)) throw new Error('the archive has a malformed number');
  return Number.parseInt(text, 8);
}

/** A header's own check: the sum of its bytes with the checksum field counted as spaces. */
function checksumMatches(header: Buffer): boolean {
  let sum = 0;
  header.forEach((byte, index) => {
    sum += index >= CHECKSUM.start && index < CHECKSUM.end ? 0x20 : byte;
  });
  return sum === octal(header.subarray(CHECKSUM.start, CHECKSUM.end));
}

/** The contents of the first regular file in a tar archive. */
export function firstFileIn(archive: Buffer): Buffer {
  let offset = 0;
  while (offset + BLOCK <= archive.length) {
    const header = archive.subarray(offset, offset + BLOCK);
    if (header.every((byte) => byte === 0)) break; // the end-of-archive marker
    if (!checksumMatches(header)) throw new Error('the archive has a damaged header');
    const size = octal(header.subarray(SIZE.start, SIZE.end));
    const start = offset + BLOCK;
    if (start + size > archive.length) throw new Error('the archive ends inside an entry');
    if (REGULAR_FILE.has(header[TYPE] ?? -1)) return archive.subarray(start, start + size);
    // An extended header, a directory or a link: step over its data.
    offset = start + Math.ceil(size / BLOCK) * BLOCK;
  }
  throw new Error('the archive holds no file');
}
