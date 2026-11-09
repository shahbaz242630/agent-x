-- agentx: no transaction (concurrent index)
-- S180 (PL-62): an agent's month total read from its index alone. Every decision under
-- a mandate sums the agent's month (monthSpentRead: every reservation but a released
-- one, in the cap's currency). 0040's index found those rows, but each one's amount
-- was then read from the table, one page a reservation, as an agent's are spread among
-- every other agent's: on Stage G (Azure, 9 Nov) an agent at its organisation's cap
-- held ~4,000, so the read touched ~3,470 pages, about a third of the database's work
-- for a decision. This index holds the currency, the amount and the request beside
-- the month, so the read (and an approval's or a carry's, which leave requests out by
-- their ID) answers from the index: same rows, same answers, a few pages.
--
-- Built concurrently, outside a transaction (the first line; migrate.ts), as 0074's:
-- reads and writes of the reservations go on while it builds, at any size; its lock
-- holds back only other changes to the table's shape or a VACUUM. org_id leads, as
-- ADR-005 §1 asks of every tenant index; no table, column or grant changes. Then
-- 0040's index goes, concurrently too: the new one serves every read it served.
CREATE INDEX CONCURRENTLY IF NOT EXISTS held_in_an_agents_month_summed ON limit_reservations.reservations (org_id, agent_id, month, currency)
  INCLUDE (amount_minor, request_id) WHERE state <> 'RELEASED';
DROP INDEX CONCURRENTLY IF EXISTS limit_reservations.held_in_an_agents_month;
