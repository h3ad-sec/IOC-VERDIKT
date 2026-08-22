
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
    flat[SRC_META[k].name] = active ? srcLabel(k, entry[k], srcState(k, entry[k])) : 'N/A';
  }
  if (entry.ioc.type === 'ip' || entry.ioc.type === 'ipv6')
    Object.assign(flat, ipDetailColumns(entry));
  Object.assign(flat, threatFoxDetailColumns(entry));
  Object.assign(flat, malwareBazaarDetailColumns(entry));
  Object.assign(flat, hybridAnalysisDetailColumns(entry));
  return flat;
}

/* Type-agnostic detail columns, added only when that source was actually
   queried for this row's IOC type (unlike ipDetailColumns() above, these
   three sources apply across ip/hash/domain combinations, not just
   ip/ipv6, so gating is per-source rather than per-row-type). */
function srcDetailVal(src, fn) {
  if (!src || src.skipped || src.noKey) return '-';
  if (src.error) return `Error: ${src.error}`;
  const v = fn(src);
  return (v === null || v === undefined || v === '') ? '-' : v;
}

function threatFoxDetailColumns(entry) {
  if (!(TYPE_SOURCES[entry.ioc.type] || []).includes('tf')) return {};
  const tf = entry.tf;
  return {
    'TF_Reporter':      srcDetailVal(tf, s => s.reporter),
    'TF_Reference':     srcDetailVal(tf, s => s.reference),
    'TF_MalwareAlias':  srcDetailVal(tf, s => s.malwareAlias),
    'TF_MalpediaLink':  srcDetailVal(tf, s => s.malpediaLink),
    'TF_IOCTypeDesc':   srcDetailVal(tf, s => s.iocTypeDesc),
    'TF_Tags':          srcDetailVal(tf, s => s.tags?.join('; ')),
  };
}

function malwareBazaarDetailColumns(entry) {
  if (!(TYPE_SOURCES[entry.ioc.type] || []).includes('mb')) return {};
  const mb = entry.mb;
  return {
    'MB_CodeSign_Subject':  srcDetailVal(mb, s => s.codeSignSubject),
    'MB_CodeSign_Issuer':   srcDetailVal(mb, s => s.codeSignIssuer),
    'MB_CodeSign_ValidTo':  srcDetailVal(mb, s => s.codeSignValidTo),
    'MB_YaraRules':         srcDetailVal(mb, s => s.yaraRules?.join('; ')),
  };
}

function hybridAnalysisDetailColumns(entry) {
  if (!(TYPE_SOURCES[entry.ioc.type] || []).includes('ha')) return {};
  const ha = entry.ha;
  return {
    'HA_AVDetect':      srcDetailVal(ha, s => s.avDetect != null ? `${s.avDetect}%` : null),
    'HA_MITRE_ATTCK':   srcDetailVal(ha, s => s.mitreAttacks?.join('; ')),
    'HA_NetworkIOCs':   srcDetailVal(ha, s => s.networkIOCs?.join('; ')),
    'HA_Signatures':    srcDetailVal(ha, s => s.signatures?.join('; ')),
  };
}

/* Extra per-field columns for IP/IPv6 rows, appended alongside (not instead
   of) the compact per-source status columns above, ported from X-VERDIKT's
   rowToFlat(). No scoring fields since this tool has no scoring engine. */
function ipDetailColumns(entry) {
  const srcVal = (src, fn) => {
    if (!src || src.skipped || src.noKey) return '-';
    if (src.error) return `Error: ${src.error}`;
    const v = fn(src);
    return (v === null || v === undefined || v === '') ? '-' : v;
  };
  const vt = entry.vt, ab = entry.ab, otx = entry.otx, il = entry.il;
  return {
    'VT_IP':              srcVal(vt, s => s.ip),
    'VT_ASN':             srcVal(vt, s => s.asn != null ? 'AS' + s.asn : null),
    'VT_AS_Owner':        srcVal(vt, s => s.as_owner),
    'VT_Country':         srcVal(vt, s => s.country),
    'VT_Reputation':      srcVal(vt, s => s.reputation != null ? String(s.reputation) : null),
    'VT_Detections':      srcVal(vt, s => `${s.malicious||0}/${s.total||0} engines`),
    'VT_Network':         srcVal(vt, s => s.network),
    'VT_JARM':            srcVal(vt, s => s.jarm),
    'VT_Tags':            srcVal(vt, s => s.tags?.join('; ')),
    'VT_Cert_SubjectCN':  srcVal(vt, s => s.cert_subject_cn),
    'VT_Cert_IssuerCN':   srcVal(vt, s => s.cert_issuer_cn),
    'VT_Cert_SelfSigned': srcVal(vt, s => s.cert_self_signed != null ? String(s.cert_self_signed) : null),
    'VT_Cert_ValidUntil': srcVal(vt, s => s.cert_valid_until),
    'VT_Cert_SHA256':     srcVal(vt, s => s.cert_thumbprint),
    'AB_IPAddress':       srcVal(ab, s => s.ipAddress),
    'AB_IsPublic':        srcVal(ab, s => s.isPublic != null ? String(s.isPublic) : null),
    'AB_IPVersion':       srcVal(ab, s => s.ipVersion != null ? 'IPv' + s.ipVersion : null),
    'AB_IsWhitelisted':   srcVal(ab, s => s.isWhitelisted != null ? String(s.isWhitelisted) : null),
    'AB_AbuseScore':      srcVal(ab, s => `${s.score||0}%`),
    'AB_UsageType':       srcVal(ab, s => s.usageType),
    'AB_ISP':             srcVal(ab, s => s.isp),
    'AB_Domain':          srcVal(ab, s => s.domain),
    'AB_Hostnames':       srcVal(ab, s => s.hostnames?.join('; ')),
    'AB_IsTor':           srcVal(ab, s => String(s.isTor)),
    'AB_TotalReports':    srcVal(ab, s => s.totalReports != null ? String(s.totalReports) : null),
    'AB_LastReported':    srcVal(ab, s => s.lastReportedAt),
    'OTX_PulseCount':     srcVal(otx, s => String(s.pulseCount)),
    'OTX_Subscribers':    srcVal(otx, s => String(s.subscriberCount || 0)),
    'OTX_IndicatorCount': srcVal(otx, s => String(s.indicatorCount || 0)),
    'OTX_Validation':     srcVal(otx, s => s.validation),
    'OTX_PulseSources':   srcVal(otx, s => s.pulseSources?.join('; ')),
    'IL_Country':         srcVal(il, s => s.country && s.country_code ? `${s.country} (${s.country_code})` : (s.country || s.country_code)),
    'IL_City':            srcVal(il, s => s.city),
    'IL_Subdivision':     srcVal(il, s => s.subdivision),
    'IL_Continent':       srcVal(il, s => s.continent),
    'IL_Coordinates':     srcVal(il, s => (s.latitude != null && s.longitude != null) ? `${s.latitude}, ${s.longitude}` : null),
    'IL_TimeZone':        srcVal(il, s => s.time_zone),
    'IL_PostalCode':      srcVal(il, s => s.postal_code),
    'IL_Network':         srcVal(il, s => s.network),
    'IL_ASN':             srcVal(il, s => s.asn != null ? 'AS' + s.asn : null),
    'IL_ASN_Name':        srcVal(il, s => s.asn_name),
    'IL_ISP':             srcVal(il, s => s.isp),
    'IL_Organization':    srcVal(il, s => s.organization),
    'IL_Domain_Resolved': srcVal(il, s => s.domain),
    'IL_Flags':           srcVal(il, s => ['is_abuser','is_tor','is_bogon','is_vpn','is_proxy','is_anonymous','is_hosting','is_icloud_relay'].filter(f => s[f]).join('; ') || 'Clean'),
  };
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
  const esc  = v => String(v ?? '-').replace(/\|/g, '\\|');
  const mkTable = list => {
    const flatRows = list.map(rowToFlat);
    const cols = [...new Set(flatRows.flatMap(r => Object.keys(r)))];
    const hdr = '| ' + cols.join(' | ') + ' |';
    const sep = '| ' + cols.map(() => '---').join(' | ') + ' |';
    const body = flatRows.map(r => '| ' + cols.map(c => esc(r[c])).join(' | ') + ' |').join('\n');
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
