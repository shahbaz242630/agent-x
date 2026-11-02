// Fair turns for a background job's work (4D2e Stage F; PL-62, PL-63): a lane
// per organisation, one item per lane per pass, so an organisation with
// thousands waiting never keeps a small one from its turn.
//
// A lane reads a page when it runs empty, by its own turn, never ahead. Its
// cursor is kept between runs: a run cut short (its time budget, a stop) goes
// on where it left off next run, and a lane that reached its end wraps to the
// start next run, so a long run of requests left waiting never keeps a younger
// one out. A lane ends its turn on a reason that is its whole organisation's:
// the next run tries the same item again, and nothing behind it is walked for
// the same answer. The pages take no locks and skip none (no SKIP LOCKED): what
// keeps an item safe is its own transaction, not its place in a lane.
//
// A run never overlaps itself (scheduleRuns) and only moves forward through a
// lane, so no item is read twice in a run; it ends once all it started has.

/** A reason a request waits that is its whole organisation's: every request behind it would wait for the same. */
const ORGANISATION_WIDE = new Set(['organization', 'anchor_pending']);
const ORGANISATION_WIDE_FAMILIES = ['hold_', 'pause_'];

/** Whether a waiting reason, comma-joined, ends its lane's turn. */
export const isOrganisationWide = (why: string): boolean =>
  why
    .split(',')
    .some(
      (reason) =>
        ORGANISATION_WIDE.has(reason) || ORGANISATION_WIDE_FAMILIES.some((family) => reason.startsWith(family)),
    );

/** What one item's work came to for its lane: go on to the next, or end the lane's turn. */
export type LaneStep = 'next' | 'end_turn';

/**
 * How a lane's turn in a run ended: `whole`, it reached its end, every item
 * tried since the last wrap; `ended`, an item ended its turn; `failed`, a page
 * or item couldn't be read or worked; `cut`, the run stopped before it got there.
 */
type LaneOutcome = 'whole' | 'ended' | 'failed' | 'cut';

export interface FairLanes {
  /** Runs one pass after another over the lanes, until each is done or `stopped` says so: how each lane's turn ended. Never throws. */
  run(lanes: readonly string[], stopped: () => boolean): Promise<ReadonlyMap<string, LaneOutcome>>;
}

interface Lane<Item> {
  readonly id: string;
  /** Read, not yet taken. */
  buffer: Item[];
  /** The last item taken: the next page reads after it. */
  after: string | undefined;
  /** No page is left to read. */
  exhausted: boolean;
  /** A page is being read: no other turn until it is. */
  reading: boolean;
  /** Being made ready for its items, holding no turn: none until it is. */
  parked: boolean;
  active: number;
  /** Ended or failed: no more turns this run. */
  closed: 'ended' | 'failed' | undefined;
  /** Where the next run starts once closed: before the item that ended the turn, so it is tried again. */
  restart: string | undefined;
}

export function createFairLanes<Item>({
  total,
  limitOf,
  page,
  idOf,
  read,
  prepare,
  work,
  thrown,
}: {
  /** How many items may be worked at once, across every lane. */
  readonly total: number;
  /** How many of this lane's may be worked at once now. */
  readonly limitOf: (lane: string) => number;
  /** How many items a read asks for: fewer back means the lane's end. */
  readonly page: number;
  /** An item's ID, in the order its lane is read. */
  readonly idOf: (item: Item) => string;
  /** The page after `after`, oldest first, or null where it couldn't be read (the reader says why). */
  readonly read: (lane: string, after: string | undefined) => Promise<readonly Item[] | null>;
  /**
   * What the lane needs before its items can go (a chain's first anchor), or
   * nothing: waited for holding no turn, so one slow lane keeps no other waiting.
   */
  readonly prepare?: (lane: string) => Promise<void> | undefined;
  readonly work: (lane: string, item: Item) => Promise<LaneStep>;
  /** A page, item or preparation that threw (none should): says why. */
  readonly thrown: (lane: string, error: unknown) => void;
}): FairLanes {
  // A lane's place, kept between runs: one absent starts at its beginning.
  let cursors = new Map<string, string>();
  // The lane that last had a turn: the next run starts after it, so a run cut short never favours the first lanes.
  let lastLane: string | undefined;

  return {
    run(ids, stopped) {
      const lanes = rotated(ids, lastLane).map((id): Lane<Item> => ({
        id,
        buffer: [],
        after: cursors.get(id),
        exhausted: false,
        reading: false,
        parked: false,
        active: 0,
        closed: undefined,
        restart: undefined,
      }));
      // In turn order: a lane given a turn goes to the back, a finished one leaves, so a pass costs a step a turn.
      const open = new Set(lanes);
      const { promise: done, resolve: finish } = Promise.withResolvers<undefined>();
      let working = 0;
      let parked = 0;

      const finished = (lane: Lane<Item>): boolean =>
        lane.closed !== undefined || (lane.exhausted && lane.buffer.length === 0 && !lane.reading);

      /** The next lane with a turn to take, or none now (each finished one on the way past let go). */
      const nextLane = (): Lane<Item> | undefined => {
        for (const lane of open) {
          if (finished(lane)) open.delete(lane);
          else if (!lane.reading && !lane.parked && lane.active < limitOf(lane.id)) {
            open.delete(lane);
            open.add(lane);
            return lane;
          }
        }
        return undefined;
      };

      const close = (lane: Lane<Item>, how: 'ended' | 'failed', before: string | undefined): void => {
        // Several at once may close it: the earliest is where the next run starts.
        if (lane.closed === undefined || (before ?? '') < (lane.restart ?? '')) lane.restart = before;
        lane.closed ??= how;
        lane.buffer = [];
      };

      /** Holds the lane back, holding no turn, until what it needs is ready. */
      const park = (lane: Lane<Item>, preparing: Promise<void>): void => {
        lane.parked = true;
        parked += 1;
        void preparing
          .catch((error: unknown) => {
            thrown(lane.id, error);
          })
          .finally(() => {
            lane.parked = false;
            parked -= 1;
            pump();
          });
      };

      /** The lane's next page in its buffer, where it ran empty; false where none is to work on now. */
      const fill = async (lane: Lane<Item>): Promise<boolean> => {
        lane.reading = true;
        try {
          const items = await read(lane.id, lane.after);
          if (items === null) {
            close(lane, 'failed', lane.after);
            return false;
          }
          lane.buffer = [...items];
          lane.exhausted = items.length < page;
        } finally {
          lane.reading = false;
        }
        const preparing = lane.buffer.length > 0 ? prepare?.(lane.id) : undefined;
        if (preparing !== undefined) park(lane, preparing);
        return preparing === undefined;
      };

      /** One lane's turn: its page if it ran empty, then one item. */
      const turn = async (lane: Lane<Item>): Promise<void> => {
        try {
          if (lane.buffer.length === 0 && !(await fill(lane))) return;
          // Its read may have taken long enough for the run to stop.
          const item = stopped() ? undefined : lane.buffer.shift();
          if (item === undefined) return;
          const before = lane.after;
          lane.after = idOf(item);
          lane.active += 1;
          try {
            const step = work(lane.id, item);
            // Its page in hand and its item begun, oldest first: the lane's next item can have a turn beside this one.
            pump();
            if ((await step) === 'end_turn') close(lane, 'ended', before);
          } finally {
            lane.active -= 1;
          }
        } catch (error) {
          thrown(lane.id, error);
          close(lane, 'failed', lane.after);
        }
      };

      const pump = (): void => {
        while (working < total && !stopped()) {
          const lane = nextLane();
          if (lane === undefined) break;
          lastLane = lane.id;
          working += 1;
          void turn(lane).finally(() => {
            working -= 1;
            pump();
          });
        }
        if (working === 0 && parked === 0) finish(undefined);
      };

      pump();
      return done.then(() => {
        cursors = new Map();
        const outcomes = new Map<string, LaneOutcome>();
        for (const lane of lanes) {
          const outcome = lane.closed ?? (finished(lane) ? 'whole' : 'cut');
          outcomes.set(lane.id, outcome);
          const place = lane.closed === undefined ? lane.after : lane.restart;
          // Whole: wrapped, so the next run starts again at its beginning.
          if (outcome !== 'whole' && place !== undefined) cursors.set(lane.id, place);
        }
        return outcomes;
      });
    },
  };
}

/** The lanes starting after `last`, wrapping; as listed where it isn't among them. */
function rotated(ids: readonly string[], last: string | undefined): readonly string[] {
  const at = last === undefined ? -1 : ids.indexOf(last);
  return [...ids.slice(at + 1), ...ids.slice(0, at + 1)];
}

/**
 * At most `limit` at once; those marked `ahead` go before any waiting without
 * (a payment's answer ahead of a new payment's start: it frees its bank slot,
 * and the money it speaks for is already at the bank).
 */
export function createGate(limit: number): {
  run<T>(work: () => Promise<T>, ahead?: boolean): Promise<T>;
} {
  let inside = 0;
  const first: (() => void)[] = [];
  const rest: (() => void)[] = [];

  const entered = async (ahead: boolean): Promise<void> => {
    if (inside < limit) {
      inside += 1;
      return;
    }
    const { promise, resolve } = Promise.withResolvers<undefined>();
    (ahead ? first : rest).push(() => {
      resolve(undefined);
    });
    await promise;
  };

  const left = (): void => {
    // Handed straight to the next, so no one arriving in between gets past those waiting.
    const next = first.shift() ?? rest.shift();
    if (next === undefined) inside -= 1;
    else next();
  };

  return {
    async run(work, ahead = false) {
      await entered(ahead);
      try {
        return await work();
      } finally {
        left();
      }
    },
  };
}
