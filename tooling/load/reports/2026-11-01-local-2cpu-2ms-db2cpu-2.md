# Load test, 2026-11-01 (local, API 2 CPU, database 2 CPU)

**Passed.**

**But many agents in one organisation missed the 150 ms decision target: see below.**

Commit `99ba160a`, run at 2026-11-01T20:54:04.428Z, on a laptop: the compose stack's database and API only, the API
given 2 CPU(s) (staging has half), 1 GiB and the load run's twenty connections, k6 straight to it. 2 ms was added to every packet the database sent, as Azure's network adds it. The database was held to 2 CPU(s), so it can fill up as Azure's does. As on staging today, the hand-off is
paused: its timer re-checks the approved requests each run, and that work is in these numbers. Laptop numbers compare versions;
they do not close PL-38, which closes on the same run on Azure, production-sized, before live.

## Requests (k6)

| Phase | Requests | New | Not sent | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3482 | 3362 | 0 | 87.1 | 118.0 | 148.2 | 246.1 | 0 | 0 | 0 |
| 2 | 3533 | 3413 | 0 | 89.3 | 122.1 | 159.9 | 263.6 | 0 | 0 | 0 |

Target: a request p95 under 500 ms, with every planned request sent: the steady traffic, not the spike.
Database trips a request (the app's round trips over the phase, its timers' included: its statements by pg_stat_statements, less those sent in another's trip): phase 1 30.2, phase 2 30.2, phase 3 30.2, phase 4 30.4, phase 5 29.0.
Phase 2's spike, 50 requests at once from the capped agent, queued on its month's lock by design: p50 1351.6 ms, p95 2234.8 ms, max 2336.8 ms.

## Decisions (the API’s log)

| Traffic | Decisions | p50 ms | p95 ms | p99 ms | Max ms |
| --- | --- | --- | --- | --- | --- |
| Steady | 6725 | 64 | 94 | 127 | 212 |
| The spike | 50 | 1139 | 1987 | 2068 | 2068 |

Target: a steady decision p95 under 150 ms, timed over its whole transaction (lock waits, retries, the reservation, signing).
Allowed at once: 3498 of the 6725 steady decisions; the rest wait for a person, or are denied. Hand-offs are paused, so what follows an allowed request isn't timed.

## Many agents in one organisation (apart from the numbers above; the same 150 ms decision target, not yet failing a run)

Ten agents of one organisation, 25 requests a second between them, picked at random, with the same duplicates and replays. They share its chain head, and in the second row each supplier’s lock too.

| Setup | Requests | Not sent | Request p95 ms | Decisions | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed | Connection wait p95 ms | Own agent wait p95 ms | Supplier wait p95 ms | Gate wait p95 ms | Trips p50 | Decision rows trip p95 ms (the supplier's lock inside) | Chain head trip p95 ms | Turned away busy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Each agent with its own three suppliers | 3483 | 0 | 138.4 | 3362 | 69 | 110 | 143 | 196 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 19 | 24.5 | 8.8 | 0 |
| All agents sharing three suppliers | 3484 | 0 | 202.9 | 3363 | 73 | 173 | 244 | 548 | 0 | 0 | 0 | 0.1 | 0 | 0 | 0 | 19 | 101.2 | 8.9 | 0 |

**Decision target missed (150 ms).** All agents sharing three suppliers: a decision's p95 was 173 ms.

## One organisation's trouble beside others (the same 150 ms decision target, not yet failing a run)

Ten calm organisations, sending what the steady traffic sends, beside a busy organisation (25 requests a second on three shared suppliers) and a stuck one (5 a second, two of its three suppliers held locked for the phase). The calm ones should read as the quiet phases do.

| Traffic | Requests | Request p95 ms | 5xx | 429 | Decisions | p50 ms | p95 ms | p99 ms | Connection wait p95 ms | Own agent wait p95 ms | Supplier wait p95 ms | Gate wait p95 ms | Trips p50 | Decision rows trip p95 ms (the supplier's lock inside) | Chain head trip p95 ms | Turned away busy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Quiet (phases 1 and 2) | | | | | 6725 | 64 | 94 | 127 | 0 | 0 | 0 | 0 | 19 | 19.1 | 3.3 | 0 |
| Calm, beside the others | 3483 | 164.6 | 0 | 0 | 3363 | 71 | 127 | 229 | 0.1 | 0 | 0 | 0 | 19 | 41.8 | 4.1 | 0 |
| Busy organisation | 3001 | 353.1 | 0 | 0 | 3001 | 79 | 242 | 602 | 51.4 | 0 | 0 | 0 | 20 | 67 | 5.5 | 0 |
| Stuck organisation | 550 | 32918.1 | 496 | 0 | 54 | 14763 | 19724 | 19876 | 9923.2 | 9908 | 0 | 0 | 20 | 73.3 | 6 | 382 |

Decision target met by the calm organisations: p95 under 150 ms.
Warnings or errors while it ran: api.lock_wait_ran_out 116, db.organisation_busy 143, spend_request.agent_busy 239.
An admin's freeze of the stuck organisation, asked near the phase's end: not frozen: its wait for the organisation's lock ran out, after 5991 ms.

## Checks

- The database after the run: passed (each request once, every month within its limit, holdings exactly matching decisions, one open claim an order, no integrity hold).
- The holdings check at the restart: 50 run(s) over 23280 request(s).
- Warnings or errors logged: 0; lines suppressed: 0.
- Decisions turned away because the whole platform was full: 0.
