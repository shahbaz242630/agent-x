// Whether an agent's order reference may be shown to a paid supplier as its
// invoice number (AG11, 6F1 audit G6; partner S203). The remittance email goes
// to someone outside the organisation under Agent X's name, and the order
// reference is the agent's free text: shown only when it is invoice-shaped,
// so nothing in it reads as a link, a web or an email address. Otherwise the
// email shows our own payment reference in its place.

/** The most characters an order reference shown as an invoice number may have. */
export const INVOICE_NUMBER_MOST = 35;

/** ASCII letters and digits, spaces and `- / _ . #` alone: a look-alike, invisible or bidi character fails. */
const INVOICE_CHARACTERS = /^[A-Za-z0-9 /_.#-]+$/;
const LETTER_OR_DIGIT = /[A-Za-z0-9]/;

/** `http` or `www.` anywhere: a link or web address, its `://` refused by the characters already. */
const LINK_WORD = /http|www\./i;

/**
 * A dot is refused unless a letter or digit comes before it and a digit after: a domain's tail is never all
 * digits, so `INV.2026.001` passes while `evil.com`, `pay.example.ae` or `INV.2026.pdf` don't.
 */
const DOT_NOT_BEFORE_DIGIT = /(?<![A-Za-z0-9])\.|\.(?!\d)/;

/** Four dot-separated groups of 1 to 3 digits standing alone: an internet address (10.0.0.1). */
const INTERNET_ADDRESS = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/;

/** Which reference named the payment in a supplier's remittance email, or `withheld`: as its audit event keeps it, never the text. */
export type RemittanceReference = 'order_reference' | 'payment_reference' | 'withheld';

/** Whether the order reference is invoice-shaped, and so may be shown to its supplier as the invoice number. */
export function invoiceShaped(orderReference: string): boolean {
  return (
    orderReference.length <= INVOICE_NUMBER_MOST &&
    INVOICE_CHARACTERS.test(orderReference) &&
    LETTER_OR_DIGIT.test(orderReference) &&
    !LINK_WORD.test(orderReference) &&
    !DOT_NOT_BEFORE_DIGIT.test(orderReference) &&
    !INTERNET_ADDRESS.test(orderReference)
  );
}
