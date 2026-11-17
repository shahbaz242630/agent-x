# Checking a downloaded audit log

An organisation's admins can download its audit log as NDJSON (one event a line, newest first). Anyone holding that file can check it outside Agent X with `tooling/chain-check/check-audit-chain.mjs`: one file, Node.js 24 or later, nothing to install. It uses Node's own modules alone and never reaches the network.

```
node check-audit-chain.mjs audit-log.ndjson --org <the organisation's ID>
```

The organisation's ID is part of every hash, so the check needs it.

## Verdicts

| Verdict          | Exit code | Means                                                                                                                                                                                                                |
| ---------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PASSED`         | 0         | Every check passed, and every event's hash was recomputed from its contents.                                                                                                                                         |
| `FAILED`         | 1         | A check failed. Each problem is named by event and line.                                                                                                                                                             |
| `NOT CHECKED`    | 2         | The file, or the command, could not be read.                                                                                                                                                                         |
| `PARTLY CHECKED` | 3         | No check failed, but some events' hashes could not be recomputed. The verdict says how many events' contents were confirmed and names those that were not. Their links to the events around them were still checked. |

## What it proves

For the events in the file:

- their numbers follow one another, none missing, repeated or out of place;
- each event names the hash of the one before it, and event 1 names the starting hash (64 zeros);
- each event's hash is SHA-256 over its chain's name (`organisation:<ID>`), the hash before it, its number, ID, time, actor, action, subject and facts, each part written as a 4-byte big-endian length and then its bytes, the facts as compact JSON with their keys in order. That is exactly how Agent X computes it, so a changed fact, time, person or action shows.

## What it cannot prove

- **Events whose seal is left out.** A signed state's event carries a keyed fingerprint that is Agent X's own seal and is never put in a download. Its line says `sealOmitted: true`, and its hash can't be recomputed: the verdict is `PARTLY CHECKED`, never `PASSED`. The checker can't tell from a line alone whether its action really is one that carries a signed state.
- **Downloads from before `sealOmitted`.** Such a file can't tell a signed state's event from an edited one, so an event whose hash doesn't recompute is named as not confirmed (`PARTLY CHECKED`), not passed or failed by a guess. A file where some lines carry `sealOmitted` and others don't was put together by hand: there, a line without it whose hash doesn't recompute is `FAILED`.
- **A rewrite of the whole chain.** Every event also carries a MAC made with a key that no download holds. Without that key, someone could rewrite the chain from some point onwards with every hash computed afresh, and this check would still pass. Agent X's own checks hold the key and a separately kept anchor, and catch that.
- **Events outside the file.** A download of a date range starts after event 1 and ends before the newest. The check can't see what came before its first event or after its last.
