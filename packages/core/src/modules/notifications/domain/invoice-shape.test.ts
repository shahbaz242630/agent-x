import { describe, expect, it } from 'vitest';
import { invoiceShaped, INVOICE_NUMBER_MOST } from './invoice-shape.ts';

const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);
const RIGHT_TO_LEFT_OVERRIDE = String.fromCodePoint(0x202e);
const CYRILLIC_A = String.fromCodePoint(0x0430);
const FULLWIDTH_ONE = String.fromCodePoint(0xff11);
const ARABIC_INDIC_FIVE = String.fromCodePoint(0x0665);
const NO_BREAK_SPACE = String.fromCodePoint(0x00a0);

describe('an order reference shown as a supplier’s invoice number (AG11, 6F1 G6; partner S203)', () => {
  it.each([
    'INV-2026-0042',
    'INV 2026 0042',
    'PO/2026/17',
    'ORDER_17',
    '#4471',
    'INV.2026.001',
    'INV.2026',
    '2026.11.19.1',
    '1.2.3.4.5',
    '10.0.0.1234',
    'A',
    '7',
    'inv-0042',
    'X'.repeat(INVOICE_NUMBER_MOST),
  ])('shows %j: letters, digits, spaces and - / _ . # alone, each dot before a digit', (reference) => {
    expect(invoiceShaped(reference)).toBe(true);
  });

  it.each([
    ['too long', 'X'.repeat(INVOICE_NUMBER_MOST + 1)],
    ['empty', ''],
    ['no letter or digit', '-/_ #'],
    ['a link', 'https://evil.example/pay'],
    ['a link without its colon', 'https//evil/pay'],
    ['http alone', 'HTTP-0042'],
    ['a web address', 'www.evil.ae'],
    ['www and a dot before digits', 'www.123'],
    ['a domain', 'evil.com'],
    ['a domain with a path', 'evil.com/pay'],
    ['a sub-domain', 'pay.example.ae'],
    ['a domain whose name is digits', '123.com'],
    ['a TLD-like tail after digits', 'INV.2026.pdf'],
    ['a dot before nothing', 'INV 2026.'],
    ['a dot before a space', 'INV. 2026'],
    ['a dot first', '.2026'],
    ['a dot after a space', 'INV .2026'],
    ['a dot after a dash', 'INV-.2026'],
    ['an internet address', '10.0.0.1'],
    ['an internet address inside', 'PAY 192.168.1.20 NOW'],
    ['an email address', 'billing@evil.com'],
    ['an @ alone', 'INV@0042'],
    ['a colon', 'INV:0042'],
    ['a question mark', 'INV?0042'],
    ['a newline', 'INV\n0042'],
    ['a tab', 'INV\t0042'],
    ['a zero-width space', `INV${ZERO_WIDTH_SPACE}0042`],
    ['a right-to-left override', `INV-${RIGHT_TO_LEFT_OVERRIDE}2400`],
    ['a Cyrillic look-alike', `INV-${CYRILLIC_A}042`],
    ['a fullwidth digit', `INV-${FULLWIDTH_ONE}042`],
    ['an Arabic-Indic digit', `INV-${ARABIC_INDIC_FIVE}042`],
    ['a no-break space', `INV${NO_BREAK_SPACE}0042`],
    ['Arabic text', 'فاتورة 42'],
    ['an accented letter', 'FACTURÉ-42'],
  ])('refuses %s (%j)', (_why, reference) => {
    expect(invoiceShaped(reference)).toBe(false);
  });
});
