// The suppliers module (ADR-004, PRD §3 `Supplier` / `SupplierVersion`; Phase
// 1 E): an organisation's suppliers and the versions of their details, both
// authority tables read through their signed states (E1-1). Adding and
// listing them, with their routes, is composed in the API (E1-2); a payee is
// registered with the partner through the providers module's adapter (E2).
export {
  contactsHeld,
  reactivationOf,
  SOURCE_KINDS,
  type SourceKind,
  stillVerified,
  SUPPLIER,
  type SupplierContacts,
  type SupplierDetails,
  SupplierDetailsRefused,
  supplierDetails,
  type SupplierStatus,
} from './domain/supplier.ts';
export {
  addSupplier,
  addVersion,
  contactsOf,
  MOST_SUPPLIERS_A_PAGE,
  type NewSupplier,
  type NewVersion,
  reactivateSupplier,
  SUPPLIER_VERSIONS,
  type SupplierCheck,
  SupplierContactsUnreadable,
  type SupplierRecord,
  SUPPLIERS,
  type SupplierShown,
  suppliersAddedSince,
  suppliersPage,
  supplierOf,
  type SuppliersTransaction,
  unverifySupplier,
  type VersionCheck,
  type VersionRecord,
  verifySupplier,
  versionOf,
} from './infrastructure/suppliers.ts';
export type { SuppliersTables } from './infrastructure/tables.ts';
