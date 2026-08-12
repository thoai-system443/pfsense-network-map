/** CSV writing for the export buttons.
 *
 * Values here come out of an uploaded config.xml, which is somebody else's file.
 * Two things follow from that: fields have to be quoted properly because
 * descriptions contain commas and quotes, and a field starting with a formula
 * character has to be neutralised or Excel runs it when the file is opened.
 */

/** Characters Excel and Sheets treat as the start of a formula. */
const FORMULA_START = /^[=+\-@\t\r]/;

const NEEDS_QUOTES = /[",\n\r]/;

export function csvField(value: string): string {
  const safe = FORMULA_START.test(value) ? `'${value}` : value;
  return NEEDS_QUOTES.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function toCsv(headers: string[], rows: string[][]): string {
  return [headers, ...rows].map((row) => row.map(csvField).join(",")).join("\r\n");
}

export function downloadCsv(filename: string, csv: string): void {
  // The BOM is what makes Excel read the file as UTF-8. Without it, an interface
  // described in Vietnamese comes out as mojibake.
  const blob = new Blob([`﻿${csv}`], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
