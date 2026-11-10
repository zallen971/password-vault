// CSV reading and writing (RFC 4180: quoted fields, embedded commas and newlines).

/** @returns {string[][]} rows of cells; blank lines are dropped. */
export function parseCsv(text) {
  const input = String(text).replace(/^﻿/, '');
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  let wasQuoted = false;

  const endCell = () => {
    row.push(cell);
    cell = '';
    wasQuoted = false;
  };
  const endRow = () => {
    endCell();
    if (row.length > 1 || row[0] !== '') rows.push(row);
    row = [];
  };

  for (let i = 0; i < input.length; i += 1) {
    const char = input[i];
    if (quoted) {
      if (char === '"') {
        if (input[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        cell += char;
      }
    } else if (char === '"' && cell === '' && !wasQuoted) {
      quoted = true;
      wasQuoted = true;
    } else if (char === ',') {
      endCell();
    } else if (char === '\n') {
      endRow();
    } else if (char === '\r') {
      if (input[i + 1] === '\n') i += 1;
      endRow();
    } else {
      cell += char;
    }
  }
  if (cell !== '' || wasQuoted || row.length) endRow();
  return rows;
}

/** Reads a CSV with a header row into objects keyed by lower-cased header. */
export function parseCsvRecords(text) {
  const [header, ...rows] = parseCsv(text);
  if (!header) return { headers: [], records: [] };
  const headers = header.map((name) => name.trim().toLowerCase());
  const records = rows.map((cells) => Object.fromEntries(headers.map((name, index) => [name, cells[index] ?? ''])));
  return { headers, records };
}

// Values are written exactly as they are. Exports exist to be imported again,
// so "defusing" cells that look like spreadsheet formulas would silently
// corrupt any password that happens to start with = + - or @.
function escapeCell(value) {
  const text = value == null ? '' : String(value);
  return /[",\r\n]/.test(text) || /^\s|\s$/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** @param {unknown[][]} rows */
export function toCsv(rows) {
  return rows.map((row) => row.map(escapeCell).join(',')).join('\r\n') + '\r\n';
}
