// No bank details are kept with a supplier by default (BRD BR-21, ADR-014
// §3): its payee is the partner's reference. A supplier's name, trade licence
// and source's reference are free text, so an IBAN typed into one would be
// kept as typed (Carry-Forward, E2-2 note a). Here, not in the domain: the
// providers module's check reads text as a person would (ADR-004 keeps a
// domain to its own folder and the shared kernel).
import { holdsAnIban } from '../../providers/index.ts';
import { type SupplierDetails, SupplierDetailsRefused, supplierDetails } from '../domain/supplier.ts';

/** What the refusal says: never the text, nor which field held it. */
export const ACCOUNT_NUMBER_KEPT = 'an account number is never kept with a supplier: register it as its payee';

/**
 * The details as a version keeps them (`supplierDetails`), or
 * SupplierDetailsRefused: its own problems first, then an IBAN with valid
 * check digits, joined or in groups, in any of the free text. A long
 * reference whose check digits fail is kept, so registry numbers are unaffected.
 */
export function keptSupplierDetails(details: SupplierDetails): SupplierDetails {
  const kept = supplierDetails(details);
  const texts = [kept.displayName, kept.contacts.tradeLicence ?? '', kept.source.ref];
  if (texts.some((text) => holdsAnIban(text))) throw new SupplierDetailsRefused([ACCOUNT_NUMBER_KEPT]);
  return kept;
}
