# Load test, 2026-10-31 (local, API 2 CPU)

**Passed.**

Commit `3a28de72`, run at 2026-10-31T17:37:28.188Z, on a laptop: the compose stack's database and API only, the API
given 2 CPU(s) (staging has half), 1 GiB and ten connections as staging, k6 straight to it. 2 ms was added to every packet the database sent, as Azure's network adds it. As on staging today, the hand-off is
paused: its timer re-checks the approved requests each run, and that work is in these numbers. Laptop numbers compare versions;
they do not close PL-38, which closes on the same run on Azure, production-sized, before live.

## Requests (k6)

| Phase | Requests | New | Not sent | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3485 | 3364 | 0 | 83.5 | 111.0 | 136.7 | 237.4 | 0 | 0 | 0 |
| 2 | 3535 | 3414 | 0 | 84.1 | 114.3 | 146.1 | 321.2 | 0 | 0 | 0 |

Target: a request p95 under 500 ms, with every planned request sent: the steady traffic, not the spike.
Database trips a request (the app's round trips over the phase, its timers' included: its statements by pg_stat_statements, less those sent in another's trip): phase 1 30.2, phase 2 30.2, phase 3 30.2, phase 4 30.4, phase 5 29.0.
Phase 2's spike, 50 requests at once from the capped agent, queued on its month's lock by design: p50 1176.5 ms, p95 1964.3 ms, max 2042.9 ms.

## Decisions (the API’s log)

| Traffic | Decisions | p50 ms | p95 ms | p99 ms | Max ms |
| --- | --- | --- | --- | --- | --- |
| Steady | 6728 | 61 | 89 | 117 | 245 |
| The spike | 50 | 980 | 1682 | 1744 | 1744 |

Target: a steady decision p95 under 150 ms, timed over its whole transaction (lock waits, retries, the reservation, signing).
Allowed at once: 3500 of the 6728 steady decisions; the rest wait for a person, or are denied. Hand-offs are paused, so what follows an allowed request isn't timed.

## Many agents in one organisation (apart from the numbers above; the same 150 ms decision target, not yet failing a run)

Ten agents of one organisation, 25 requests a second between them, picked at random, with the same duplicates and replays. They share its chain head, and in the second row each supplier’s lock too.

| Setup | Requests | Not sent | Request p95 ms | Decisions | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Each agent with its own three suppliers | 3485 | 0 | 121.0 | 3364 | 63 | 98 | 120 | 187 | 0 | 0 | 0 |
| All agents sharing three suppliers | 3481 | 0 | 167.8 | 3361 | 65 | 142 | 185 | 480 | 0 | 0 | 0 |

Decision target met in each: p95 under 150 ms.

## One organisation's trouble beside others (the same 150 ms decision target, not yet failing a run)

Ten calm organisations, sending what the steady traffic sends, beside a busy organisation (25 requests a second on three shared suppliers) and a stuck one (5 a second, two of its three suppliers held locked for the phase). The calm ones should read as the quiet phases do.

| Traffic | Requests | Request p95 ms | 5xx | 429 | Decisions | p50 ms | p95 ms | p99 ms | Connection wait p95 ms | Own agent wait p95 ms | Trips p50 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Quiet (phases 1 and 2) | | | | | 6728 | 61 | 89 | 117 | 0 | 0 | 19 |
| Calm, beside the others | 3485 | 132.4 | 0 | 0 | 3364 | 65 | 100 | 149 | 0 | 0 | 19 |
| Busy organisation | 3000 | 130.0 | 0 | 0 | 3000 | 71 | 97 | 144 | 0 | 0 | 19 |
| Stuck organisation | 549 | 32155.2 | 488 | 0 | 61 | 14791 | 19584 | 19998 | 9979 | 9888 | 20 |

Decision target met by the calm organisations: p95 under 150 ms.
Warnings or errors while it ran: api.lock_wait_ran_out 123, spend_request.agent_busy 243, db.organisation_busy 124, hold_history.failed 1.

## Checks

- The database after the run: passed (each request once, every month within its limit, holdings exactly matching decisions, one open claim an order, no integrity hold).
- The holdings check at the restart: 50 run(s) over 23292 request(s).
- Warnings or errors logged: 0; lines suppressed: 0.
