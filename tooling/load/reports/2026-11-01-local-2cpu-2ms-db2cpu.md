# Load test, 2026-11-01 (local, API 2 CPU, database 2 CPU)

**Passed.**

**But many agents in one organisation missed the 150 ms decision target: see below.**

Commit `2f791952`, run at 2026-11-01T20:34:40.389Z, on a laptop: the compose stack's database and API only, the API
given 2 CPU(s) (staging has half), 1 GiB and the load run's twenty connections, k6 straight to it. 2 ms was added to every packet the database sent, as Azure's network adds it. The database was held to 2 CPU(s), so it can fill up as Azure's does. As on staging today, the hand-off is
paused: its timer re-checks the approved requests each run, and that work is in these numbers. Laptop numbers compare versions;
they do not close PL-38, which closes on the same run on Azure, production-sized, before live.
The fair gate: 20 decisions at once, 6 an organisation, 100 waiting an organisation, 10000 ms wait.

## Requests (k6)

| Phase | Requests | New | Not sent | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 3483 | 3363 | 0 | 87.0 | 115.0 | 147.5 | 241.1 | 0 | 0 | 0 |
| 2 | 3535 | 3414 | 0 | 88.5 | 120.1 | 153.7 | 245.4 | 0 | 0 | 0 |

Target: a request p95 under 500 ms, with every planned request sent: the steady traffic, not the spike.
Database trips a request (the app's round trips over the phase, its timers' included: its statements by pg_stat_statements, less those sent in another's trip): phase 1 30.3, phase 2 30.2, phase 3 30.2, phase 4 30.4, phase 5 29.3.
Phase 2's spike, 50 requests at once from the capped agent, queued on its month's lock by design: p50 1185.6 ms, p95 1994.3 ms, max 2079.4 ms.

## Decisions (the API’s log)

| Traffic | Decisions | p50 ms | p95 ms | p99 ms | Max ms |
| --- | --- | --- | --- | --- | --- |
| Steady | 6727 | 64 | 94 | 124 | 193 |
| The spike | 50 | 980 | 1763 | 1828 | 1828 |

Target: a steady decision p95 under 150 ms, timed over its whole transaction (lock waits, retries, the reservation, signing).
Allowed at once: 3499 of the 6727 steady decisions; the rest wait for a person, or are denied. Hand-offs are paused, so what follows an allowed request isn't timed.

## Many agents in one organisation (apart from the numbers above; the same 150 ms decision target, not yet failing a run)

Ten agents of one organisation, 25 requests a second between them, picked at random, with the same duplicates and replays. They share its chain head, and in the second row each supplier’s lock too.

| Setup | Requests | Not sent | Request p95 ms | Decisions | p50 ms | p95 ms | p99 ms | Max ms | 5xx | 429 | Checks failed | Connection wait p95 ms | Own agent wait p95 ms | Supplier wait p95 ms | Gate wait p95 ms | Trips p50 | Decision rows trip p95 ms (the supplier's lock inside) | Chain head trip p95 ms | Turned away busy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Each agent with its own three suppliers | 3485 | 0 | 133.3 | 3364 | 67 | 106 | 132 | 214 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 19 | 25.3 | 7.2 | 0 |
| All agents sharing three suppliers | 3484 | 0 | 194.4 | 3363 | 72 | 167 | 236 | 465 | 0 | 0 | 0 | 0.4 | 0 | 48 | 0 | 19 | 48.4 | 8.2 | 0 |

**Decision target missed (150 ms).** All agents sharing three suppliers: a decision's p95 was 167 ms.

## One organisation's trouble beside others (the same 150 ms decision target, not yet failing a run)

Ten calm organisations, sending what the steady traffic sends, beside a busy organisation (25 requests a second on three shared suppliers) and a stuck one (5 a second, two of its three suppliers held locked for the phase). The calm ones should read as the quiet phases do.

| Traffic | Requests | Request p95 ms | 5xx | 429 | Decisions | p50 ms | p95 ms | p99 ms | Connection wait p95 ms | Own agent wait p95 ms | Supplier wait p95 ms | Gate wait p95 ms | Trips p50 | Decision rows trip p95 ms (the supplier's lock inside) | Chain head trip p95 ms | Turned away busy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Quiet (phases 1 and 2) | | | | | 6727 | 64 | 94 | 124 | 0 | 0 | 0 | 0 | 19 | 18.6 | 3.3 | 0 |
| Calm, beside the others | 3483 | 157.5 | 0 | 0 | 3362 | 71 | 125 | 220 | 0 | 0 | 0 | 0 | 19 | 40.1 | 4.2 | 0 |
| Busy organisation | 3001 | 184.2 | 0 | 0 | 3001 | 78 | 150 | 988 | 0.4 | 0 | 1 | 0 | 20 | 43.1 | 5.5 | 0 |
| Stuck organisation | 601 | 12824.5 | 406 | 0 | 195 | 279 | 8693 | 9862 | 1.2 | 8585 | 0 | 0 | 20 | 56.1 | 5.9 | 354 |

An admin's freeze of the stuck organisation, asked near the phase's end: not frozen: it ran past the limit on a statement, after 9694 ms. A freeze that took makes the stuck organisation's last seconds quick 409s, so this phase's numbers compare only between runs whose freeze answered alike.
Decision target met by the calm organisations: p95 under 150 ms.
Warnings or errors while it ran: spend_request.supplier_busy 339, api.lock_wait_ran_out 52, spend_request.agent_busy 15.

## Checks

- The database after the run: passed (each request once, every month within its limit, holdings exactly matching decisions, one open claim an order, no integrity hold).
- The holdings check at the restart: 50 run(s) over 23425 request(s).
- Warnings or errors logged: 0; lines suppressed: 0.
- Requests turned away because the whole platform was full, a full pool's included: 0.
