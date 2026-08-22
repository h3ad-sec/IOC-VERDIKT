
/* ── IOC-VERDIKT Export Engine ────────────────────────────────────────────
   No scoring/verdict engine exists in this tool, export reflects that:
   each source column holds the same human-readable status text shown in
   the results table (via srcState()/srcLabel() from ui.js), not a score. */

/* Set by openExportModal(i) when launched from the detail modal's EXPORT
   button, scopes every export function to that one IOC. Reset once the
   export completes so the results-panel EXPORT button goes back to normal. */
let exportScopeIndex = null;

function getExportRows(order) {
  if (exportScopeIndex != null) {
    const r = scanResults[exportScopeIndex];
    return (r && r.done) ? [r] : [];
  }
  let rows = scanResults.filter(r => r.done);
  if (order === 'type') rows = [...rows].sort((a, b) => a.ioc.type.localeCompare(b.ioc.type));
  return rows;
}

function rowToFlat(entry) {
  const flat = {
    'IOC':  entry.ioc.value,
    'Type': entry.ioc.label,
  };
  for (const k of ROW_SRC_ORDER) {
    const active = (TYPE_SOURCES[entry.ioc.type] || []).includes(k);
    flat[SRC_META[k].name] = active ? srcLabel(k, entry[k], srcState(k, entry[k])) : '-';
  }
  return flat;
}

function downloadFile(content, filename, mimeType) {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* IST (UTC+5:30, no DST), computed from epoch ms so it's correct regardless
   of the browser's own local timezone. */
function toIST(d = new Date()) {
  return new Date(d.getTime() + d.getTimezoneOffset() * 60000 + 5.5 * 3600000);
}
function expDateTag() {
  const ist = toIST();
  const pad = n => String(n).padStart(2, '0');
  return `${ist.getFullYear()}-${pad(ist.getMonth() + 1)}-${pad(ist.getDate())}`;
}
function expTimestampIST() {
  const ist = toIST();
  const pad = n => String(n).padStart(2, '0');
  return `${ist.getFullYear()}-${pad(ist.getMonth() + 1)}-${pad(ist.getDate())} ${pad(ist.getHours())}:${pad(ist.getMinutes())}:${pad(ist.getSeconds())} IST`;
}

/* ── CSV ──────────────────────────────────────────────────────────────────── */
function exportCSV(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const flat = rows.map(rowToFlat);
  const headers = [...new Set(flat.flatMap(r => Object.keys(r)))];
  const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [
    headers.map(escape).join(','),
    ...flat.map(r => headers.map(h => escape(r[h] ?? '')).join(',')),
  ];
  downloadFile('﻿' + lines.join('\r\n'), `ioc-verdikt-${order}-${expDateTag()}.csv`, 'text/csv;charset=utf-8;');
  showToast(`CSV exported - ${rows.length} row${rows.length !== 1 ? 's' : ''}`, 'success');
}

/* ── JSON ─────────────────────────────────────────────────────────────────── */
function exportJSON(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const withRaw = r => ({
    ...rowToFlat(r),
    sources: ROW_SRC_ORDER.reduce((acc, k) => { acc[k] = r[k]; return acc; }, {}),
  });
  let out;
  if (order === 'type') {
    out = {};
    for (const r of rows) { const k = r.ioc.type; (out[k] = out[k] || []).push(withRaw(r)); }
  } else {
    out = rows.map(withRaw);
  }
  downloadFile(JSON.stringify(out, null, 2), `ioc-verdikt-${order}-${expDateTag()}.json`, 'application/json');
  showToast(`JSON exported - ${rows.length} entr${rows.length !== 1 ? 'ies' : 'y'}`, 'success');
}

/* ── Markdown ─────────────────────────────────────────────────────────────── */
function exportMarkdown(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const cols = ['IOC', 'Type', ...ROW_SRC_ORDER.map(k => SRC_META[k].name)];
  const esc  = v => String(v ?? '-').replace(/\|/g, '\\|');
  const mkTable = list => {
    const hdr = '| ' + cols.join(' | ') + ' |';
    const sep = '| ' + cols.map(() => '---').join(' | ') + ' |';
    const body = list.map(r => '| ' + cols.map(c => esc(rowToFlat(r)[c])).join(' | ') + ' |').join('\n');
    return `${hdr}\n${sep}\n${body}`;
  };
  let md = `# IOC-VERDIKT Export\n_Generated: ${expTimestampIST()}_\n\n`;
  if (order === 'type') {
    const groups = {};
    for (const r of rows) { (groups[r.ioc.type] = groups[r.ioc.type] || []).push(r); }
    md += Object.entries(groups).map(([k, rs]) => `## ${k.toUpperCase()} (${rs.length})\n\n${mkTable(rs)}`).join('\n\n');
  } else {
    md += mkTable(rows);
  }
  downloadFile(md, `ioc-verdikt-${order}-${expDateTag()}.md`, 'text/markdown;charset=utf-8;');
  showToast(`Markdown exported - ${rows.length} entr${rows.length !== 1 ? 'ies' : 'y'}`, 'success');
}

/* ── Plain text ───────────────────────────────────────────────────────────── */
function exportTXT(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  const block = r => {
    const flat = rowToFlat(r);
    return Object.entries(flat).map(([k, v]) => `${k}: ${v}`).join('\n');
  };
  let txt = `IOC-VERDIKT Export\nGenerated: ${expTimestampIST()}\n\n`;
  if (order === 'type') {
    const groups = {};
    for (const r of rows) { (groups[r.ioc.type] = groups[r.ioc.type] || []).push(r); }
    txt += Object.entries(groups)
      .map(([k, rs]) => `== ${k.toUpperCase()} (${rs.length}) ==\n\n` + rs.map(block).join('\n\n---\n\n'))
      .join('\n\n');
  } else {
    txt += rows.map(block).join('\n\n---\n\n');
  }
  downloadFile(txt, `ioc-verdikt-${order}-${expDateTag()}.txt`, 'text/plain;charset=utf-8;');
  showToast(`TXT exported - ${rows.length} entr${rows.length !== 1 ? 'ies' : 'y'}`, 'success');
}

/* ── Excel (.xlsx via SheetJS) ───────────────────────────────────────────── */
function exportExcel(order) {
  const rows = getExportRows(order);
  if (!rows.length) { showToast('No completed results to export', 'error'); return; }
  if (typeof XLSX === 'undefined') { showToast('Excel library not ready - refresh and try again', 'error'); return; }
  const wb = XLSX.utils.book_new();
  if (order === 'type') {
    const groups = {};
    for (const r of rows) { (groups[r.ioc.type] = groups[r.ioc.type] || []).push(rowToFlat(r)); }
    for (const [k, rs] of Object.entries(groups))
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rs), k.slice(0, 31));
  } else {
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(rows.map(rowToFlat)), 'Results');
  }
  XLSX.writeFile(wb, `ioc-verdikt-${order}-${expDateTag()}.xlsx`);
  showToast(`Excel exported - ${rows.length} row${rows.length !== 1 ? 's' : ''}`, 'success');
}

/* ── Export modal ────────────────────────────────────────────────────────── */
function openExportModal(scopeIndex) {
  exportScopeIndex = scopeIndex != null ? scopeIndex : null;
  const scoped = exportScopeIndex != null;
  if (scoped ? !scanResults[exportScopeIndex]?.done : !scanResults.filter(r => r.done).length) {
    showToast('No completed results to export', 'error');
    exportScopeIndex = null;
    return;
  }
  document.querySelector('.exp-order-group')?.classList.toggle('hidden', scoped);
  document.getElementById('export-modal')?.classList.add('open');
}

function closeExportModal(e) {
  if (e && e.target !== document.getElementById('export-modal')) return;
  document.getElementById('export-modal')?.classList.remove('open');
  exportScopeIndex = null;
}

function doExport() {
  const fmt   = document.querySelector('input[name="exp-fmt"]:checked')?.value   || 'csv';
  const order = document.querySelector('input[name="exp-order"]:checked')?.value || 'serial';
  document.getElementById('export-modal')?.classList.remove('open');
  if (fmt === 'csv')  exportCSV(order);
  else if (fmt === 'json') exportJSON(order);
  else if (fmt === 'md')   exportMarkdown(order);
  else if (fmt === 'txt')  exportTXT(order);
  else if (fmt === 'xls')  exportExcel(order);
  exportScopeIndex = null;
}
