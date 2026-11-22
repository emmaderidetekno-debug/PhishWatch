"use strict";

/**
 * CSV export with spreadsheet-formula neutralisation.
 *
 * Quoting is not enough on its own: Excel, LibreOffice and Sheets all evaluate a
 * cell whose text starts with = + - @ (and some also treat a leading tab or CR
 * as an escape into a formula). A campaign label is operator-supplied text, so
 * a label like =HYPERLINK("http://x","click") would execute on open. Every value
 * is therefore treated as untrusted on export and prefixed with a single quote,
 * which spreadsheets read as "this is text", before normal quoting.
 */

const COLUMNS = ["timestamp", "campaignLabel", "method", "classification", "confidence", "reason"];

// Characters that make a spreadsheet interpret the cell as a formula or command.
const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

// Leading whitespace cannot be relied on to keep a formula inert, so it is
// stripped for the test while the original text is preserved in the output.
const LEADING_NOISE = /^[\s\u00a0\u200b\ufeff]+/;

function neutraliseCell(value) {
  const text = value === null || value === undefined ? "" : String(value);
  if (text.length === 0) return text;

  const probe = text.replace(LEADING_NOISE, "");
  if (FORMULA_TRIGGER.test(probe)) return `'${text}`;
  return text;
}

function quoteCell(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

function eventsToCsv(events = []) {
  const lines = [COLUMNS.join(",")];
  for (const event of events) {
    lines.push(COLUMNS.map(column => quoteCell(neutraliseCell(event[column]))).join(","));
  }
  // BOM so Excel reads UTF-8, CRLF line endings as spreadsheets expect.
  return `\ufeff${lines.join("\r\n")}\r\n`;
}

module.exports = { COLUMNS, neutraliseCell, quoteCell, eventsToCsv };
