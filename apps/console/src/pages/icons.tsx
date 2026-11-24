// The console's icons (CO11, Calm Ledger): thin stroked line drawings, one
// colour (the text's own), drawn inline so they need no request and follow the
// light and dark themes. Decorative only: each sits beside its own words.
const PATHS = {
  mark: 'M5 5l6 7-6 7M19 5l-6 7 6 7',
  approve: 'M4 5.5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v13a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM8.5 12.5l2.3 2.3 4.7-5',
  pay: 'M4 8h13M13.5 4.5 17 8l-3.5 3.5M20 16H7M10.5 12.5 7 16l3.5 3.5',
  agent:
    'M7.5 7h9a3 3 0 0 1 3 3v6a3 3 0 0 1-3 3h-9a3 3 0 0 1-3-3v-6a3 3 0 0 1 3-3zM12 7V4M9.5 12.5v1M14.5 12.5v1M2.5 12v3M21.5 12v3',
  doc: 'M14 3.5H6.5v17h11V7zM14 3.5V7h3.5M9 11.5h6M9 15h6',
  rules: 'M4 7h10M18 7h2M4 17h4M12 17h8M16 4.5v5M10 14.5v5',
  truck:
    'M2.5 6.5h11v10h-11zM13.5 10h4l3 3.5v3h-7M8.3 17.5a1.8 1.8 0 1 1-3.6 0 1.8 1.8 0 0 1 3.6 0M18.8 17.5a1.8 1.8 0 1 1-3.6 0 1.8 1.8 0 0 1 3.6 0',
  bank: 'M3 9.5 12 4l9 5.5M5 10v7M9.7 10v7M14.3 10v7M19 10v7M3 20h18',
  people:
    'M12.2 8.5a3.2 3.2 0 1 1-6.4 0 3.2 3.2 0 0 1 6.4 0M3 19.5c.6-3.3 3-5 6-5s5.4 1.7 6 5M15.5 5.6a3.2 3.2 0 0 1 0 6M17.5 14.8c1.8.6 3 2.2 3.5 4.7',
  records: 'M5 4.5h14v15H5zM8.5 8.5h7M8.5 12h7M8.5 15.5h4',
  shield: 'M12 3 4.5 6v5.5c0 4.5 3.2 8 7.5 9.5 4.3-1.5 7.5-5 7.5-9.5V6zM9 12l2.2 2.2L15.5 10',
  lock: 'M6.5 10.5h11a1.5 1.5 0 0 1 1.5 1.5v7a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 19v-7a1.5 1.5 0 0 1 1.5-1.5zM8 10.5V8a4 4 0 0 1 8 0v2.5',
  user: 'M15.5 8a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0M5 20c.8-3.7 3.6-5.5 7-5.5s6.2 1.8 7 5.5',
  gear: 'M12 2.8v2.4M12 18.8v2.4M21.2 12h-2.4M5.2 12H2.8M18.5 5.5l-1.7 1.7M7.2 16.8l-1.7 1.7M18.5 18.5l-1.7-1.7M7.2 7.2 5.5 5.5M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0M18.5 12a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0',
  search: 'M17.5 11a6.5 6.5 0 1 1-13 0 6.5 6.5 0 0 1 13 0M20 20l-4.3-4.3',
  updown: 'M8 9.5l4-4 4 4M8 14.5l4 4 4-4',
  arrow: 'M5 12h14M13.5 6.5 19 12l-5.5 5.5',
  brake: 'M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3zM9.5 9v6M14.5 9v6',
  fingerprint:
    'M7.5 5.5A8 8 0 0 1 20 12v1.5M4.3 9.5A8 8 0 0 0 4 12v3M8 12a4 4 0 0 1 8 0v2.5c0 2-.4 3.8-1.2 5.5M12 12v3c0 2.5-.7 4.3-2 5.8M8 15.5c0 1.5-.4 2.8-1.2 4',
  sign: 'M4 18.5c2.5 0 3.5-7 5.5-7s1 5 3 5 2-3 3.5-3 1.5 2 4 2M4 21h16',
  pin: 'M12 21s-6.5-5.6-6.5-11a6.5 6.5 0 0 1 13 0C18.5 15.4 12 21 12 21zM14.3 10a2.3 2.3 0 1 1-4.6 0 2.3 2.3 0 0 1 4.6 0',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  more: 'M12 6h.01M12 12h.01M12 18h.01',
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18 }: { readonly name: IconName; readonly size?: number }) {
  return (
    <svg className="ico" width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <path d={PATHS[name]} />
    </svg>
  );
}
