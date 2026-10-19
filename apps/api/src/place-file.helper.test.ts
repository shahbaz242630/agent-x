// A small place file for tests, in the MaxMind DB format DB-IP's City Lite is
// written in (https://maxmind.github.io/MaxMind-DB/): a search tree of 24-bit
// records over IPv6 (IPv4 under ::/96), the data section, then the metadata.
// Only what the tests need: maps, strings, arrays, booleans and whole numbers.

/** A network and the record its addresses are looked up to. */
export interface PlaceNetwork {
  /** `203.0.113.0/24` or `2001:db8::/32`. */
  readonly network: string;
  readonly record: unknown;
}

type DataType = 'map' | 'string' | 'uint32' | 'uint64' | 'array' | 'boolean';
const TYPE_NUMBER: Record<DataType, number> = { string: 2, uint32: 6, map: 7, uint64: 9, array: 11, boolean: 14 };

/** A field's control bytes: its type and its size, which the tests keep under 29 (one byte). */
function control(type: DataType, size: number): Buffer {
  if (size >= 29) throw new RangeError('the place file holds fields of under 29 bytes or entries');
  const number = TYPE_NUMBER[type];
  return number <= 7 ? Buffer.from([(number << 5) | size]) : Buffer.from([size, number - 7]);
}

/** A whole number in as few big-endian bytes as it takes: a bigint as uint64, a number as uint32. */
function wholeNumber(value: number | bigint): Buffer {
  const bytes: number[] = [];
  for (let left = BigInt(value); left > 0n; left /= 256n) bytes.unshift(Number(left % 256n));
  return Buffer.concat([control(typeof value === 'bigint' ? 'uint64' : 'uint32', bytes.length), Buffer.from(bytes)]);
}

function encoded(value: unknown): Buffer {
  if (typeof value === 'string') {
    const text = Buffer.from(value, 'utf8');
    return Buffer.concat([control('string', text.length), text]);
  }
  if (typeof value === 'number' || typeof value === 'bigint') return wholeNumber(value);
  if (typeof value === 'boolean') return control('boolean', value ? 1 : 0);
  if (Array.isArray(value)) return Buffer.concat([control('array', value.length), ...value.map(encoded)]);
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value);
    return Buffer.concat([
      control('map', entries.length),
      ...entries.flatMap(([key, item]) => [encoded(key), encoded(item)]),
    ]);
  }
  throw new TypeError(`the place file can't hold ${typeof value}`);
}

/** A network's first 128 bits and how many of them it fixes. */
function bitsOf(network: string): { readonly bits: boolean[]; readonly prefix: number } {
  const [address = '', length = ''] = network.split('/');
  const bytes = new Uint8Array(16);
  if (address.includes(':')) {
    const [head = '', tail = ''] = address.split('::');
    const groups = (part: string) => (part === '' ? [] : part.split(':').map((group) => Number.parseInt(group, 16)));
    const [first, last] = [groups(head), groups(tail)];
    const written = [...first, ...Array<number>(8 - first.length - last.length).fill(0), ...last];
    written.forEach((group, index) => {
      bytes[index * 2] = group >> 8;
      bytes[index * 2 + 1] = group & 0xff;
    });
  } else {
    address.split('.').forEach((octet, index) => {
      bytes[12 + index] = Number(octet);
    });
  }
  const bits = [...bytes].flatMap((byte) => Array.from({ length: 8 }, (_, bit) => ((byte >> (7 - bit)) & 1) === 1));
  return { bits, prefix: Number(length) + (address.includes(':') ? 0 : 96) };
}

/** A branch of the tree: to another node, to a record by its offset in the data section, or to nothing. */
type Branch = { readonly node: number } | { readonly data: number } | undefined;

/** A DB-IP-shaped place file holding these networks; `databaseType` names another kind of file. */
export function placeFile(networks: readonly PlaceNetwork[], databaseType = 'DBIP-City-Lite'): Buffer {
  const tree: Branch[][] = [[undefined, undefined]];
  const data: Buffer[] = [];
  let dataLength = 0;
  for (const { network, record } of networks) {
    const { bits, prefix } = bitsOf(network);
    // Down the network's bits to the last one's node, adding the nodes it needs on the way.
    let pair = tree[0] ?? [];
    for (const bit of bits.slice(0, prefix - 1)) {
      const branch = pair[Number(bit)];
      if (branch !== undefined && 'node' in branch) {
        pair = tree[branch.node] ?? [];
      } else {
        const next: Branch[] = [undefined, undefined];
        pair[Number(bit)] = { node: tree.push(next) - 1 };
        pair = next;
      }
    }
    pair[Number(bits[prefix - 1])] = { data: dataLength };
    const bytes = encoded(record);
    data.push(bytes);
    dataLength += bytes.length;
  }
  const nodeCount = tree.length;
  /** A record's number: a node's, the count for nothing, past the count and the separator for a record. */
  const value = (branch: Branch): number => {
    if (branch === undefined) return nodeCount;
    if ('node' in branch) return branch.node;
    return nodeCount + 16 + branch.data;
  };
  const search = Buffer.alloc(nodeCount * 6);
  tree.forEach(([left, right], index) => {
    search.writeUIntBE(value(left), index * 6, 3);
    search.writeUIntBE(value(right), index * 6 + 3, 3);
  });
  const metadata = encoded({
    binary_format_major_version: 2,
    binary_format_minor_version: 0,
    database_type: databaseType,
    description: { en: 'test places' },
    ip_version: 6,
    languages: ['en'],
    node_count: nodeCount,
    record_size: 24,
    build_epoch: BigInt(Date.UTC(2026, 9, 1) / 1000),
  });
  return Buffer.concat([
    search,
    Buffer.alloc(16),
    ...data,
    Buffer.from('ABCDEF4D61784D696E642E636F6D', 'hex'),
    metadata,
  ]);
}
