// The suppliers module (ADR-004, PRD §3 `Supplier` / `SupplierVersion`; Phase
// 1 E): an organisation's suppliers and the versions of their details, both
// authority tables read through their signed states (E1-1). Adding and
// listing them, with their routes, is composed in the API (E1-2); a payee is
// registered with the partner through the providers module's adapter, each
// registration an authority table of its own, and its reference kept on a new
// version (E2).
export {
  BENEFICIARY_REGISTRATION,
  NAME_CHECKS,
  type NameCheck,
  payeeKeySource,
  type PayeeKeySource,
  REGISTRATION_FAILURES,
  REGISTRATION_ROUTES,
  type RegistrationFailure,
  type RegistrationRoute,
  type RegistrationStatus,
} from './domain/registration.ts';
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
  confirmPayeeChange,
  withdrawPayeeChange,
  contactsOf,
  MOST_SUPPLIERS_A_PAGE,
  MOST_SUPPLIERS_ADDED_A_DAY,
  type NewSupplier,
  type NewVersion,
  nextVersionNumber,
  oneSupplierAddAtATime,
  reactivateSupplier,
  stagePayeeChange,
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
  suspendSupplier,
  unverifySupplier,
  type VersionCheck,
  type VersionRecord,
  verifySupplier,
  versionOf,
} from './infrastructure/suppliers.ts';
export { normalisedIban, payeeFingerprint, type PayeeKey, payeeKeyOf } from './infrastructure/payee-key.ts';
export {
  BENEFICIARY_REGISTRATIONS,
  isPayeeTaken,
  MOST_PAYEE_REGISTRATIONS_A_DAY,
  type NewRegistration,
  onePayeeChangeAtATime,
  recordFailed,
  recordLost,
  recordRegistered,
  type RegistrationCheck,
  registrationOf,
  type RegistrationRecord,
  registrationsStartedSince,
  startRegistration,
  supplierWithPayeeKey,
} from './infrastructure/registrations.ts';
export type { SuppliersTables } from './infrastructure/tables.ts';
