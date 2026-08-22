
let currentTypeFilter = 'all';
let currentSearch     = '';
let _currentModalEntry = null;
let _currentModalIndex = null;

const TYPE_BADGES = {
  ip:          '<span class="type-badge type-ip">IPv4</span>',
  ipv6:        '<span class="type-badge type-ipv6">IPv6</span>',
  domain:      '<span class="type-badge type-domain">Domain</span>',
  url:         '<span class="type-badge type-url">URL</span>',
  hash_md5:    '<span class="type-badge type-hash">MD5</span>',
  hash_sha1:   '<span class="type-badge type-hash">SHA-1</span>',
  hash_sha256: '<span class="type-badge type-hash">SHA-256</span>',
  hash_sha512: '<span class="type-badge type-hash">SHA-512</span>',
};

const SRC_META = {
  vt:  { label: 'VT',  name: 'VIRUSTOTAL',      color: 'var(--vt)'  },
  ab:  { label: 'AB',  name: 'ABUSEIPDB',       color: 'var(--ab)'  },
  otx: { label: 'OTX', name: 'ALIENVAULT OTX',  color: 'var(--otx)' },
  tf:  { label: 'TF',  name: 'THREATFOX',       color: 'var(--tf)'  },
  us:  { label: 'US',  name: 'URLSCAN',         color: 'var(--us)'  },
  uh:  { label: 'UH',  name: 'URLHAUS',         color: 'var(--uh)'  },
  mb:  { label: 'MB',  name: 'MALWAREBAZAAR',   color: 'var(--mb)'  },
  ha:  { label: 'HA',  name: 'HYBRIDANALYSIS',  color: 'var(--ha)'  },
  fs:  { label: 'FS',  name: 'FILESCAN.IO',     color: 'var(--fs)'  },
  il:  { label: 'IL',  name: 'IPLOCATE',        color: 'var(--il)'  },
};

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function escapeAttr(s) { return escapeHtml(s); }
function truncate(s, n) { s = String(s||''); return s.length > n ? s.slice(0,n)+'…' : s; }

function showToast(msg, type = 'info') {
  let t = document.getElementById('iv-toast');
  if (!t) {
    t = document.createElement('div'); t.id = 'iv-toast';
    t.style.cssText = 'position:fixed;bottom:80px;right:24px;z-index:9999;padding:11px 18px;font-family:var(--mono);font-size:13px;border:1px solid;border-radius:4px;pointer-events:none;transition:opacity .25s,transform .25s;max-width:340px;opacity:0;transform:translateY(10px);';
    document.body.appendChild(t);
  }
  const styles = {
    success: 'background:rgba(0,255,159,.08);border-color:rgba(0,255,159,.4);color:var(--accent)',
    error:   'background:rgba(255,59,92,.08);border-color:rgba(255,59,92,.4);color:var(--red)',
    warning: 'background:rgba(255,214,10,.08);border-color:rgba(255,214,10,.4);color:var(--yellow)',
    info:    'background:rgba(59,130,246,.08);border-color:rgba(59,130,246,.4);color:var(--accent2)',
  };
  t.style.cssText = t.style.cssText.replace(/background:[^;]+;?|border-color:[^;]+;?|color:[^;]+;?/g, '') + (styles[type] || styles.info);
  t.textContent = msg;
  requestAnimationFrame(() => { t.style.opacity = '1'; t.style.transform = 'translateY(0)'; });
  clearTimeout(t._tid);
  t._tid = setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateY(10px)'; }, 3200);
}

/* Clipboard writes have no visible failure mode by default — a rejected
   promise (permission denied, unfocused document, no HTTPS context, etc.)
   just does nothing with zero feedback. Always fall back to the legacy
   execCommand path and always toast success or failure explicitly. */
function copyText(text, successMsg) {
  const legacyFallback = () => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-1000px;left:-1000px;opacity:0;';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch(_) { ok = false; }
    document.body.removeChild(ta);
    if (ok) showToast(successMsg, 'success');
    else showToast('Copy failed — select and copy manually', 'error');
  };

  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => showToast(successMsg, 'success'))
      .catch(legacyFallback);
  } else {
    legacyFallback();
  }
}

function copyToClipboard(val) {
  copyText(val, 'Copied!');
}

function copyAllIOCs() {
  if (!scanResults.length) { showToast('No IOCs to copy', 'error'); return; }
  const text = scanResults.map(r => r.ioc.value).join('\n');
  copyText(text, `Copied ${scanResults.length} IOC${scanResults.length !== 1 ? 's' : ''}`);
}

/* ── Per-source state derivation (hit / clean / error / skip / no-key) ───── */
function srcState(k, data) {
  if (!data) return 'loading';
  if (data.noKey) return 'nokey';
  if (data.skipped) return 'skip';
  if (data.error) return 'error';
  switch (k) {
    case 'vt':  return (data.malicious > 0 || data.suspicious > 0) ? 'hit' : 'clean';
    case 'ab':  return (data.score || 0) > 0 ? 'hit' : 'clean';
    case 'otx': return (data.pulseCount || 0) > 0 ? 'hit' : 'clean';
    case 'tf':  return !data.notFound && (data.iocCount || 0) > 0 ? 'hit' : 'clean';
    case 'us':  return !data.notFound && (data.flaggedCount || 0) > 0 ? 'hit' : 'clean';
    case 'uh':  return !data.notFound && (data.urlsCount || 0) > 0 ? 'hit' : 'clean';
    case 'mb':  return !data.notFound && (data.count || 0) > 0 ? 'hit' : 'clean';
    case 'ha':  return !data.notFound && ((data.maliciousCount || 0) > 0 || data.verdict === 'malicious' || (data.count || 0) > 0) ? 'hit' : 'clean';
    case 'fs':  return !data.notFound && ((data.maliciousCount || 0) > 0 || (data.count || 0) > 0) ? 'hit' : 'clean';
    case 'il': {
      if (!data.ip) return 'error';
      const flags = ['is_abuser','is_anonymous','is_vpn','is_proxy','is_tor','is_hosting','is_bogon'];
      return flags.some(f => data[f]) ? 'hit' : 'clean';
    }
    default: return 'clean';
  }
}

function srcLabel(k, data, state) {
  if (state === 'nokey')   return 'NO KEY';
  if (state === 'skip')    return 'N/A';
  if (state === 'loading') return '…';
  if (state === 'error')   return truncate(data.error || 'ERROR', 16);
  switch (k) {
    case 'vt':  return data.total > 0 ? `${data.malicious}/${data.total}` : 'no data';
    case 'ab':  return `${data.score || 0}%`;
    case 'otx': return `${data.pulseCount || 0} pulse${(data.pulseCount || 0) !== 1 ? 's' : ''}`;
    case 'tf':  return data.notFound ? 'no C2' : `${data.iocCount} C2`;
    case 'us':  return data.notFound ? 'no scans' : `${data.flaggedCount || 0}/${data.total || 0}`;
    case 'uh':  return data.notFound ? 'not found' : `${data.urlsCount || 0} URL${(data.urlsCount || 0) !== 1 ? 's' : ''}`;
    case 'mb':  return data.notFound ? 'not found' : `${data.count || 0} sample${(data.count || 0) !== 1 ? 's' : ''}`;
    case 'ha':  return data.notFound ? 'no hits' : `${data.count || 0} hit${(data.count || 0) !== 1 ? 's' : ''}`;
    case 'fs':  return data.notFound ? 'not found' : `${data.count || 0} report${(data.count || 0) !== 1 ? 's' : ''}`;
    case 'il': {
      const flags = ['is_abuser','is_vpn','is_proxy','is_tor','is_hosting','is_bogon'].filter(f => data[f]).map(f => f.replace('is_','').toUpperCase());
      return flags.length ? flags.join('·') : (data.country_code || 'OK');
    }
    default: return '';
  }
}

/* ── Result table ────────────────────────────────────────────────────────── */
function renderResultRows(results) {
  document.getElementById('results-body').innerHTML = results.map((e, i) => buildRow(e, i)).join('');
  document.getElementById('results-meta').innerHTML = `<span>${results.length}</span> IOC${results.length !== 1 ? 's' : ''} queued`;
  applyFilters();
}

const ROW_SRC_ORDER = ['vt','ab','otx','tf','il','us','uh','mb','ha','fs'];

function buildRow(entry, i) {
  return `<tr data-row="${i}" data-type="${escapeAttr(entry.ioc.type)}" data-ioc="${escapeAttr(entry.ioc.value)}">${buildRowCells(entry, i)}</tr>`;
}

function buildRowCells(entry, i) {
  const { ioc, done } = entry;
  const privateBadge = ioc.isPrivate ? '<div class="ioc-private-badge">PRIVATE</div>' : '';
  const typeBadge    = TYPE_BADGES[ioc.type] || `<span class="type-badge">${escapeHtml(ioc.label)}</span>`;
  const displayVal = ioc.type === 'url' || ioc.type.startsWith('hash_')
    ? truncate(ioc.value, 48) : ioc.value;

  const iocCells = `<td class="td-ioc">
      <div class="ioc-val-wrap">
        <span class="ioc-val" title="${escapeAttr(ioc.value)}">${escapeHtml(displayVal)}</span>
        <button class="ioc-copy-btn" onclick="copyToClipboard('${escapeAttr(ioc.value)}')" title="Copy">⎘</button>
      </div>
      ${privateBadge}
    </td>
    <td>${typeBadge}</td>`;

  const srcCells = ROW_SRC_ORDER.map(k => buildSourceCell(k, entry, done)).join('');

  const detailCell = `<td>${done ? `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>` : '<span class="src-loading">…</span>'}</td>`;

  return iocCells + srcCells + detailCell;
}

function buildSourceCell(k, entry, done) {
  const active = (TYPE_SOURCES[entry.ioc.type] || []).includes(k);
  const meta = SRC_META[k];
  if (!active) return `<td class="td-src td-src-na" title="${escapeAttr(meta.name + ': not applicable to this IOC type')}">–</td>`;
  if (!done) return `<td class="td-src"><span class="src-badge state-loading" style="color:${meta.color}"><span class="src-dot"></span></span></td>`;
  const data  = entry[k];
  const state = srcState(k, data);
  const label = srcLabel(k, data, state);
  return `<td class="td-src"><span class="src-badge state-${state}" style="color:${meta.color}" title="${escapeAttr(meta.name + ': ' + label)}"><span class="src-dot"></span>${escapeHtml(label)}</span></td>`;
}

function updateRow(i, entry) {
  const row = document.querySelector(`tr[data-row="${i}"]`);
  if (row) row.innerHTML = buildRowCells(entry, i);
  applyFilters();
}

function updateRowLoading(i) {
  const row = document.querySelector(`tr[data-row="${i}"]`);
  if (!row) return;
  row.innerHTML = buildRowCells(scanResults[i], i);
}

/* ── Filters ─────────────────────────────────────────────────────────────── */
function filterByType(t, btn) {
  currentTypeFilter = t;
  document.querySelectorAll('.type-filter[data-tfilter]').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  applyFilters();
}

function searchResults(val) { currentSearch = val.toLowerCase().trim(); applyFilters(); }

function applyFilters() {
  document.querySelectorAll('#results-body tr').forEach(row => {
    const tp = row.dataset.type || '';
    const ioc = (row.dataset.ioc || '').toLowerCase();
    const matchT = currentTypeFilter === 'all' || tp === currentTypeFilter
                   || (currentTypeFilter === 'hash' && tp.startsWith('hash_'))
                   || (currentTypeFilter === 'ip' && (tp === 'ip' || tp === 'ipv6'));
    const matchS = !currentSearch || ioc.includes(currentSearch);
    row.classList.toggle('hidden', !(matchT && matchS));
  });
}

/* ── Key services ─────────────────────────────────────────────────────────── */
const ALL_KEY_SERVICES = ['vt','abuseipdb','otx','threatfox','urlscan','urlhaus','malwarebazaar','hybridanalysis','filescan','iplocate'];

function toggleKey(id) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
  inp.nextElementSibling.textContent = inp.type === 'password' ? 'SHOW' : 'HIDE';
}

function saveKeys() {
  ALL_KEY_SERVICES.forEach(s => {
    const v = document.getElementById(`${s}-key`)?.value.trim();
    if (v) localStorage.setItem(`iv_${s}_key`, v);
  });
  updateKeysNavBadge();
  const msg = document.getElementById('key-saved-msg');
  msg.textContent = '✓ Saved'; msg.classList.add('show');
  setTimeout(() => msg.classList.remove('show'), 3000);
}

function clearKeys() {
  ALL_KEY_SERVICES.forEach(s => localStorage.removeItem(`iv_${s}_key`));
  ALL_KEY_SERVICES.forEach(s => { const el = document.getElementById(`${s}-key`); if (el) el.value = ''; });
  updateKeysNavBadge();
  const msg = document.getElementById('key-saved-msg');
  msg.textContent = 'Cleared'; msg.classList.add('show');
  setTimeout(() => msg.classList.remove('show'), 2000);
}

function loadSavedKeys() {
  ALL_KEY_SERVICES.forEach(s => {
    const v = localStorage.getItem(`iv_${s}_key`);
    const el = document.getElementById(`${s}-key`);
    if (v && el) el.value = v;
  });
}

/* ── Modal — formatted per-source intel cards ────────────────────────────── */
function openModal(i) {
  const entry = scanResults[i];
  if (!entry) return;
  _currentModalEntry = entry;
  _currentModalIndex = i;
  const displayVal = entry.ioc.type === 'url' || entry.ioc.type.startsWith('hash_')
    ? truncate(entry.ioc.value, 60) : entry.ioc.value;
  document.getElementById('modal-title').innerHTML = `${escapeHtml(displayVal)}
    <span style="color:var(--muted);font-size:11px;margin-left:12px">${escapeHtml(entry.ioc.label)}</span>`;
  document.getElementById('modal-body').innerHTML = buildModalContent(entry);
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() { document.getElementById('modal-overlay')?.classList.remove('open'); }

function copyModalDetails() {
  const entry = _currentModalEntry;
  if (!entry) return;
  const keys = TYPE_SOURCES[entry.ioc.type] || [];
  const lines = [`IOC: ${entry.ioc.value} (${entry.ioc.label})`];
  for (const k of keys) {
    const data  = entry[k];
    const state = srcState(k, data);
    lines.push(`${SRC_META[k].name}: ${srcLabel(k, data, state)}`);
  }
  copyText(lines.join('\n'), 'Copied');
}

/* ── Modal — formatted per-source intel cards ────────────────────────────
   Ported from X-VERDIKT/js/ui.js (kv, buildVTBlock, buildAbuseIPDBBlock,
   buildOTXBlock, buildMBIntelBlock/buildMBContent, buildMainCard,
   buildURLScanContent, buildThreatFoxContent, buildURLhausContent,
   buildHAContent, buildFileScanContent) with score/verdict fields stripped
   (IOC-VERDIKT has no scoring engine) and BYOK-specific `noKey` state added
   to every na/skip/error branch. buildIPLocateBlock is new — X-VERDIKT
   only renders IPLocate in its separate IP Intel table, not this modal. */

function kv(k, v, col) {
  if (v == null || v === '' || v === 'null') return '';
  const val = typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v);
  const colorClass = col ? ` style="color:${col}"` : '';
  return `<div class="modal-k">${escapeHtml(k)}</div><div class="modal-v"${colorClass}>${escapeHtml(val)}</div>`;
}

/* Community vote / date formatting shared by the VT card branches below. */
function fmtVotes(tv) {
  if (!tv || (tv.harmless == null && tv.malicious == null)) return null;
  return `${tv.harmless || 0} harmless · ${tv.malicious || 0} malicious`;
}
function fmtUnixDate(ts) {
  if (ts == null) return null;
  const n = Number(ts);
  if (!Number.isFinite(n)) return null;
  return new Date(n * 1000).toISOString().split('T')[0];
}

/* AbuseIPDB numeric report-category IDs → names (docs.abuseipdb.com/#categories). */
const ABUSEIPDB_CATEGORIES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
};

function naMsg(data) {
  if (data?.noKey) return 'No API key configured for this source';
  if (data?.skipped) return data.reason || 'Not applicable to this IOC type';
  if (data?.error) return typeof data.error === 'string' ? data.error : 'Error';
  return 'Not available';
}

function buildVTBlock(vt, iocType) {
  if (!vt || vt.noKey || vt.skipped || vt.error) {
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL</div><div class="intel-na">${escapeHtml(naMsg(vt))}</div></div>`;
  }
  const scoreColor = vt.malicious > 0 ? 'var(--red)' : vt.suspicious > 0 ? 'var(--yellow)' : 'var(--accent)';
  const lastStats = `${vt.malicious} mal · ${vt.suspicious} sus · ${vt.harmless} harm · ${vt.undetected} undet · ${vt.total} total`;
  const linkHtml = vt.link ? ` <a href="${escapeAttr(vt.link)}" target="_blank" class="modal-link">↗</a>` : '';

  /* IP / IPv6 */
  if (iocType === 'ip' || iocType === 'ipv6') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('IP', vt.ip)}
        ${kv('ASN', vt.asn != null ? `AS${vt.asn}` : null)}
        ${kv('AS Owner', vt.as_owner)}
        ${kv('Country', vt.country)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : vt.reputation > 0 ? 'var(--accent)' : null)}
        ${kv('Total Votes', fmtVotes(vt.raw?.data?.attributes?.total_votes))}
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('Network', vt.network)}
        ${kv('JARM', vt.jarm ? truncate(vt.jarm, 32) : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
      ${(vt.cert_subject_cn || vt.cert_issuer_cn) ? `
      <div class="intel-sub-label">TLS CERTIFICATE</div>
      <div class="modal-kv-grid">
        ${kv('Subject CN', vt.cert_subject_cn)}
        ${kv('Issuer CN', vt.cert_issuer_cn)}
        ${kv('Valid Until', vt.cert_valid_until)}
      </div>` : ''}
    </div>`;
  }

  /* Domain */
  if (iocType === 'domain') {
    const dnsRecords = (vt.raw?.data?.attributes?.last_dns_records || []).slice(0, 6);
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Domain', vt.domain)}
        ${kv('Registrar', vt.registrar)}
        ${kv('Categories', vt.categories)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : null)}
        ${kv('Total Votes', fmtVotes(vt.raw?.data?.attributes?.total_votes))}
        ${kv('Creation Date', fmtUnixDate(vt.raw?.data?.attributes?.creation_date))}
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
      ${dnsRecords.length ? `<div class="intel-sub-label">DNS RECORDS</div><div class="modal-tags">${dnsRecords.map(r => `<span class="modal-tag">${escapeHtml(r.type || '?')}: ${escapeHtml(truncate(r.value ?? '', 40))}</span>`).join('')}</div>` : ''}
      ${(vt.cert_subject_cn || vt.cert_issuer_cn) ? `
      <div class="intel-sub-label">TLS CERTIFICATE</div>
      <div class="modal-kv-grid">
        ${kv('Subject CN', vt.cert_subject_cn)}
        ${kv('Issuer CN', vt.cert_issuer_cn)}
      </div>` : ''}
    </div>`;
  }

  /* URL */
  if (iocType === 'url') {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('Title', vt.title ? truncate(vt.title, 48) : null)}
        ${kv('Final URL', vt.finalUrl ? truncate(vt.finalUrl, 48) : null)}
        ${kv('Categories', vt.categories)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : null)}
        ${kv('Total Votes', fmtVotes(vt.raw?.data?.attributes?.total_votes))}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  /* Hash */
  if (iocType.startsWith('hash_')) {
    const fattrs = vt.raw?.data?.attributes || {};
    const ptc = fattrs.popular_threat_classification || null;
    const threatCats = (ptc?.popular_threat_category || []).slice(0, 5);
    const sig = fattrs.signature_info || null;
    const sigVerified = sig?.verified || null;
    const sigSigners = sig?.signers || null;
    const sigUnsigned = !!sigVerified && /unsign|invalid/i.test(sigVerified);
    const names = (fattrs.names || []).filter(n => n && n !== vt.name).slice(0, 8);
    const packers = fattrs.packers || null;
    const packerChips = packers ? Object.entries(packers).slice(0, 5).map(([tool, val]) => `${tool}: ${val}`) : [];
    const yaraRules = [...new Set((fattrs.crowdsourced_yara_results || []).map(r => r.rule_name).filter(Boolean))].slice(0, 8);
    const sigmaRules = [...new Set((fattrs.sigma_analysis_results || []).map(r => r.rule_title).filter(Boolean))].slice(0, 8);

    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Suggested Label', ptc?.suggested_threat_label, ptc?.suggested_threat_label ? 'var(--red)' : null)}
        ${kv('File Name', vt.name)}
        ${kv('File Type', vt.fileType)}
        ${kv('Size', vt.size)}
        ${kv('First Seen', vt.firstSeen)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('Signature', sigVerified, sigUnsigned ? 'var(--red)' : (sigVerified ? 'var(--accent)' : null))}
        ${kv('Signer', sigSigners ? truncate(sigSigners, 60) : null)}
        ${kv('Total Votes', fmtVotes(fattrs.total_votes))}
        ${kv('MD5', vt.md5 ? truncate(vt.md5, 40) : null)}
        ${kv('SHA-1', vt.sha1 ? truncate(vt.sha1, 40) : null)}
        ${kv('SHA-256', vt.sha256 ? truncate(vt.sha256, 44) : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
      ${threatCats.length ? `<div class="intel-sub-label">THREAT CATEGORY</div><div class="modal-tags">${threatCats.map(c => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(c.value)} (${c.count})</span>`).join('')}</div>` : ''}
      ${names.length ? `<div class="intel-sub-label">ALSO KNOWN AS</div><div class="modal-tags">${names.map(n => `<span class="modal-tag">${escapeHtml(truncate(n, 40))}</span>`).join('')}</div>` : ''}
      ${packerChips.length ? `<div class="intel-sub-label">PACKERS</div><div class="modal-tags">${packerChips.map(p => `<span class="modal-tag" style="color:var(--yellow)">${escapeHtml(p)}</span>`).join('')}</div>` : ''}
      ${yaraRules.length ? `<div class="intel-sub-label">YARA MATCHES</div><div class="modal-tags">${yaraRules.map(r => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(r)}</span>`).join('')}</div>` : ''}
      ${sigmaRules.length ? `<div class="intel-sub-label">SIGMA MATCHES</div><div class="modal-tags">${sigmaRules.map(r => `<span class="modal-tag" style="color:var(--yellow)">${escapeHtml(r)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  /* Fallback */
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
    <div class="modal-kv-grid">${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}</div>
  </div>`;
}

function buildAbuseIPDBBlock(ab) {
  if (!ab || ab.noKey || ab.error) {
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB</div><div class="intel-na">${escapeHtml(naMsg(ab))}</div></div>`;
  }
  if (ab.skipped) {
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB</div><div class="intel-na">${escapeHtml(ab.reason || 'IP only')}</div></div>`;
  }
  const scoreCol = ab.score >= 75 ? 'var(--red)' : ab.score >= 25 ? 'var(--yellow)' : 'var(--accent)';
  const reports = ab.raw?.data?.reports || [];
  const recentCats = [...new Set(
    reports.slice(0, 5).flatMap(r => (r.categories || []).map(c => ABUSEIPDB_CATEGORIES[c] || `#${c}`))
  )].slice(0, 8);
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB ${ab.link ? `<a href="${escapeAttr(ab.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('IP Address', ab.ipAddress)}
      ${kv('IP Version', ab.ipVersion != null ? `IPv${ab.ipVersion}` : null)}
      ${kv('Country', ab.raw?.data?.countryName)}
      ${kv('Is Public', ab.isPublic)}
      ${kv('Whitelisted', ab.isWhitelisted)}
      ${kv('Abuse Score', `${ab.score}%`, scoreCol)}
      ${kv('Usage Type', ab.usageType)}
      ${kv('ISP', ab.isp)}
      ${kv('Domain', ab.domain)}
      ${kv('Is Tor', ab.isTor)}
      ${kv('Total Reports', ab.totalReports != null ? String(ab.totalReports) : null)}
      ${kv('Distinct Reporters', ab.raw?.data?.numDistinctUsers != null ? String(ab.raw.data.numDistinctUsers) : null)}
      ${kv('Last Reported', ab.lastReportedAt?.split('T')[0])}
    </div>
    ${recentCats.length ? `<div class="intel-sub-label">REPORTED FOR</div><div class="modal-tags">${recentCats.map(c => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(c)}</span>`).join('')}</div>` : ''}
    ${ab.hostnames?.length ? `<div class="intel-sub-label">HOSTNAMES</div><div class="modal-tags">${ab.hostnames.slice(0,6).map(h => `<span class="modal-tag">${escapeHtml(h)}</span>`).join('')}</div>` : ''}
  </div>`;
}

/* Per-pulse detail (not aggregated) for the top 1-3 pulses — freshness,
   TLP, targeted industries, and direct reference links so an analyst can
   reach ground truth instead of just a pulse count. */
function buildOTXPulseDetail(otx) {
  const pulses = otx.raw?.pulse_info?.pulses;
  if (!Array.isArray(pulses) || !pulses.length) return '';
  const top = pulses.slice(0, 3);
  return top.map((p, idx) => {
    const rows = [
      kv('Pulse Name', p.name ? truncate(p.name, 60) : null),
      kv('Created', p.created ? String(p.created).split('T')[0] : null),
      kv('Modified', p.modified ? String(p.modified).split('T')[0] : null),
      kv('TLP', p.TLP ? String(p.TLP).toUpperCase() : null),
      kv('Industries', p.industries?.length ? p.industries.join(', ') : null),
    ].filter(Boolean).join('');
    const refs = (p.references || []).filter(Boolean).slice(0, 4);
    const refsHtml = refs.length
      ? `<div class="modal-tags">${refs.map(r => `<a href="${escapeAttr(r)}" target="_blank" class="modal-tag" style="text-decoration:none">${escapeHtml(truncate(r, 44))}</a>`).join('')}</div>`
      : '';
    if (!rows && !refsHtml) return '';
    return `<div class="intel-sub-label">${top.length > 1 ? `PULSE ${idx + 1}` : 'PULSE DETAIL'}</div>
      ${rows ? `<div class="modal-kv-grid">${rows}</div>` : ''}
      ${refsHtml}`;
  }).join('');
}

function buildOTXBlock(otx) {
  if (!otx || otx.noKey || otx.skipped || otx.error) {
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--otx)">ALIENVAULT OTX</div><div class="intel-na">${escapeHtml(naMsg(otx))}</div></div>`;
  }
  const pulseCol = otx.pulseCount >= 5 ? 'var(--red)' : otx.pulseCount >= 1 ? 'var(--yellow)' : 'var(--accent)';
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--otx)">ALIENVAULT OTX ${otx.link ? `<a href="${escapeAttr(otx.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('Pulse Count', String(otx.pulseCount), pulseCol)}
      ${kv('Subscriber Count', otx.subscriberCount > 0 ? String(otx.subscriberCount) : null)}
      ${kv('Indicator Count', otx.indicatorCount > 0 ? String(otx.indicatorCount) : null)}
      ${kv('Validation', otx.validation)}
      ${kv('Recent Pulse', otx.recentPulse ? truncate(otx.recentPulse, 44) : null)}
    </div>
    ${otx.pulseSources?.length ? `<div class="intel-sub-label">PULSE SOURCES</div><div class="modal-tags">${otx.pulseSources.map(s => `<span class="modal-tag">${escapeHtml(s)}</span>`).join('')}</div>` : ''}
    ${otx.malwareFamilies?.length ? `<div class="intel-sub-label">MALWARE FAMILIES</div><div class="modal-tags">${otx.malwareFamilies.map(f => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(f)}</span>`).join('')}</div>` : ''}
    ${otx.adversaries?.length ? `<div class="intel-sub-label">ADVERSARIES</div><div class="modal-tags">${otx.adversaries.map(a => `<span class="modal-tag" style="color:var(--yellow)">${escapeHtml(a)}</span>`).join('')}</div>` : ''}
    ${buildOTXPulseDetail(otx)}
  </div>`;
}

function buildMBIntelBlock(mb) {
  if (!mb || mb.noKey || mb.error)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na">${escapeHtml(naMsg(mb))}</div></div>`;
  if (mb.skipped)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na">${escapeHtml(mb.reason || 'Skipped')}</div></div>`;
  if (mb.notFound || !mb.count)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na" style="color:var(--accent)">Not found in malware database</div></div>`;
  /* Full vendor payload for the first match — imphash/ssdeep/tlsh, delivery
     method and intelligence counters aren't in the parsed mb object, so pull
     them straight from the untouched API response abuse.ch returns. */
  const mbItem = mb.raw?.data?.[0];
  const mbIntel = mbItem?.intelligence;
  const mbTags = mbItem?.tags?.length ? mbItem.tags : null;
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR ${mb.link ? `<a href="${escapeAttr(mb.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('Samples', String(mb.count), 'var(--red)')}
      ${kv('File Name', mb.fileName)}
      ${kv('File Type', mb.fileType)}
      ${kv('First Seen', mb.firstSeen)}
      ${kv('Delivery Method', mbItem?.delivery_method)}
      ${kv('Imphash', mbItem?.imphash ? truncate(mbItem.imphash, 40) : null)}
      ${kv('ssdeep', mbItem?.ssdeep ? truncate(mbItem.ssdeep, 48) : null)}
      ${kv('TLSH', mbItem?.tlsh ? truncate(mbItem.tlsh, 48) : null)}
      ${kv('ClamAV', mbIntel?.clamav)}
      ${kv('Downloads', mbIntel?.downloads != null ? String(mbIntel.downloads) : null)}
      ${kv('Uploads', mbIntel?.uploads != null ? String(mbIntel.uploads) : null)}
    </div>
    ${mb.families?.length ? `<div class="intel-sub-label">MALWARE FAMILIES</div><div class="modal-tags">${mb.families.slice(0,5).map(f => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(f)}</span>`).join('')}</div>` : ''}
    ${mbTags ? `<div class="intel-sub-label">TAGS</div><div class="modal-tags">${mbTags.slice(0,8).map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}${mbTags.length > 8 ? `<span class="modal-tag">+${mbTags.length - 8} more</span>` : ''}</div>` : ''}
  </div>`;
}

function buildMBContent(mb) {
  if (!mb || mb.noKey) return `<div class="intel-na">${escapeHtml(naMsg(mb))}</div>`;
  if (mb.skipped) return `<div class="intel-na">${escapeHtml(mb.reason || 'Skipped')}</div>`;
  if (mb.error) return `<div class="intel-na">Error: ${escapeHtml(mb.error)}</div>`;
  if (mb.notFound || !mb.count) return `<div class="intel-na" style="color:var(--accent)">Not found</div>`;
  const lines = [
    mb.fileName ? `<div class="modal-k">File Name</div><div class="modal-v">${escapeHtml(mb.fileName)}</div>` : '',
    `<div class="modal-k">Samples</div><div class="modal-v" style="color:var(--red)">${mb.count}</div>`,
  ];
  if (mb.fileType) lines.push(`<div class="modal-k">File Type</div><div class="modal-v">${escapeHtml(mb.fileType)}</div>`);
  if (mb.families?.length) lines.push(`<div class="modal-k">Families</div><div class="modal-v" style="color:var(--red)">${escapeHtml(mb.families.join(', '))}</div>`);
  if (mb.firstSeen) lines.push(`<div class="modal-k">First Seen</div><div class="modal-v">${mb.firstSeen}</div>`);
  const mbItem = mb.raw?.data?.[0];
  if (mbItem?.delivery_method) lines.push(`<div class="modal-k">Delivery Method</div><div class="modal-v">${escapeHtml(mbItem.delivery_method)}</div>`);
  if (mbItem?.imphash) lines.push(`<div class="modal-k">Imphash</div><div class="modal-v">${escapeHtml(truncate(mbItem.imphash, 40))}</div>`);
  return `<div class="modal-kv-grid">${lines.filter(Boolean).join('')}</div>`;
}

function buildMainCard(title, col, content, link) {
  const lnk = link ? ` <a href="${escapeAttr(link)}" target="_blank" class="modal-link">↗</a>` : '';
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:${col}">${title}${lnk}</div>
    ${content}
  </div>`;
}

function buildURLScanContent(us) {
  if (!us || us.noKey) return `<div class="intel-na">${escapeHtml(naMsg(us))}</div>`;
  if (us.skipped) return `<div class="intel-na">${escapeHtml(us.reason || 'Skipped')}</div>`;
  if (us.error) return `<div class="intel-na">Error: ${escapeHtml(us.error)}</div>`;
  if (us.notFound || !us.total) return `<div class="intel-na" style="color:var(--accent)">No scans found</div>`;
  const lines = [`<div class="modal-k">Total Scans</div><div class="modal-v">${us.total}</div>`];
  if (us.flaggedCount) lines.push(`<div class="modal-k">Flagged (malicious/phishing)</div><div class="modal-v" style="color:var(--red)">${us.flaggedCount}</div>`);

  /* us.raw.results[] is the search endpoint's summary payload — confirmed live
     against /api/v1/search/?q=... — each item carries page.ip/page.asn/
     page.asnname/page.server plus a "result" URL to the full per-scan report
     and (sometimes) task.tags. It does NOT carry verdicts/score per item —
     that only exists on the full /result/{uuid}/ report — so no per-scan
     malicious score is surfaced here. Infra fields below are from the single
     most recent scan (raw.results[0]), not an aggregate across all scans. */
  const rawResults = us.raw?.results || [];
  const latest = rawResults[0]?.page;
  lines.push(kv('Latest Scan IP', latest?.ip));
  lines.push(kv('Latest Scan ASN', latest?.asn ? `${latest.asn}${latest.asnname ? ' · ' + latest.asnname : ''}` : null));
  lines.push(kv('Server', latest?.server));

  let out = `<div class="modal-kv-grid">${lines.join('')}</div>`;
  if (us.recent?.length) {
    out += `<div class="intel-sub-label">RECENT SCANS</div><div class="modal-tags">${us.recent.slice(0,3).map((r, i) => {
      const raw = rawResults[i];
      const style = r.flagged ? ' style="color:var(--red);border-color:rgba(255,59,92,.3)"' : '';
      const label = `${escapeHtml(truncate(r.domain || r.url, 36))} · ${escapeHtml(r.date)}${raw?.task?.tags?.length ? ' · ' + escapeHtml(raw.task.tags.slice(0,3).join(', ')) : ''}`;
      return raw?.result
        ? `<a class="modal-tag" href="${escapeAttr(raw.result)}" target="_blank"${style}>${label} ↗</a>`
        : `<span class="modal-tag"${style}>${label}</span>`;
    }).join('')}</div>`;
  }
  return out;
}

function buildThreatFoxContent(tf) {
  if (!tf || tf.noKey) return `<div class="intel-na">${escapeHtml(naMsg(tf))}</div>`;
  if (tf.skipped) return `<div class="intel-na">${escapeHtml(tf.reason || 'Skipped')}</div>`;
  if (tf.error) return `<div class="intel-na">Error: ${escapeHtml(tf.error)}</div>`;
  if (tf.notFound) return `<div class="intel-na" style="color:var(--accent)">No IOCs found</div>`;
  const lines = [`<div class="modal-k">IOC Count</div><div class="modal-v" style="color:var(--red)">${tf.iocCount}</div>`];
  if (tf.maxConfidence) lines.push(`<div class="modal-k">Confidence</div><div class="modal-v">${tf.maxConfidence}%</div>`);
  if (tf.firstSeen) lines.push(`<div class="modal-k">First Seen</div><div class="modal-v">${tf.firstSeen}</div>`);
  if (tf.lastSeen)  lines.push(`<div class="modal-k">Last Seen</div><div class="modal-v">${tf.lastSeen}</div>`);
  if (tf.threatTypes?.length)     lines.push(`<div class="modal-k">Threat Type</div><div class="modal-v">${escapeHtml(tf.threatTypes.join(', '))}</div>`);
  if (tf.malwareFamilies?.length) lines.push(`<div class="modal-k">Malware</div><div class="modal-v" style="color:var(--red)">${escapeHtml(tf.malwareFamilies.slice(0,3).join(', '))}</div>`);

  /* Top 1-2 raw matches — reporter/reference/tags aren't aggregated onto
     the parsed object, so pull them straight from tf.raw.data. */
  const tfMatches = (tf.raw?.data || []).slice(0, 2);
  const reporters = [...new Set(tfMatches.map(m => m.reporter).filter(Boolean))];
  if (reporters.length) lines.push(kv('Reporter', reporters.join(', ')));

  let out = `<div class="modal-kv-grid">${lines.join('')}</div>`;

  const refs = [...new Set(tfMatches.map(m => m.reference).filter(Boolean))];
  if (refs.length) {
    out += `<div class="intel-sub-label">SOURCE REPORT${refs.length > 1 ? 'S' : ''}</div>` +
      refs.map(r => `<div class="modal-kv-grid"><div class="modal-k"></div><div class="modal-v"><a href="${escapeAttr(r)}" target="_blank" class="modal-link" style="margin-left:0">↗ ${escapeHtml(truncate(r, 50))}</a></div></div>`).join('');
  }

  const tfTags = [...new Set(tfMatches.flatMap(m => m.tags || []))];
  if (tfTags.length) {
    out += `<div class="intel-sub-label">TAGS</div><div class="modal-tags">${tfTags.slice(0, 10).map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>`;
  }

  return out;
}

function buildURLhausContent(uh) {
  if (!uh || uh.noKey) return `<div class="intel-na">${escapeHtml(naMsg(uh))}</div>`;
  if (uh.skipped) return `<div class="intel-na">${escapeHtml(uh.reason || 'Skipped')}</div>`;
  if (uh.error) return `<div class="intel-na">Error: ${escapeHtml(uh.error)}</div>`;
  if (uh.notFound) return `<div class="intel-na" style="color:var(--accent)">No URLs found</div>`;
  const lines = [`<div class="modal-k">URLs Listed</div><div class="modal-v" style="color:var(--red)">${uh.urlsCount}</div>`];
  if (uh.onlineCount) lines.push(`<div class="modal-k">Online</div><div class="modal-v" style="color:var(--red)">${uh.onlineCount}</div>`);
  if (uh.threats?.length) lines.push(`<div class="modal-k">Threat</div><div class="modal-v">${escapeHtml(uh.threats.join(', '))}</div>`);
  if (uh.tags?.length)    lines.push(`<div class="modal-k">Tags</div><div class="modal-v">${escapeHtml(uh.tags.join(', '))}</div>`);
  if (uh.dateAdded) lines.push(`<div class="modal-k">First Seen</div><div class="modal-v">${uh.dateAdded}</div>`);

  /* Raw shape differs by lookup type — url lookup nests file info under
     payloads[0], hash lookup has it at the top level, host lookup has
     neither. Duck-type off uh.raw instead of requiring an iocType param. */
  const raw = uh.raw || {};
  const payload = raw.payloads?.[0] || null;
  const isHashLookup = !!(raw.md5_hash || raw.sha256_hash);
  const fileName  = payload?.filename || null;
  const fileType  = payload?.file_type || (isHashLookup ? raw.file_type : null);
  const signature = payload?.signature || (isHashLookup ? raw.signature : null);
  const vt        = payload?.virustotal || (isHashLookup ? raw.virustotal : null);
  const blacklists = raw.blacklists || null;

  if (fileName)  lines.push(kv('File Name', fileName));
  if (fileType)  lines.push(kv('File Type', fileType));
  if (signature) lines.push(kv('Signature', signature, 'var(--red)'));

  let out = `<div class="modal-kv-grid">${lines.join('')}</div>`;

  if (vt?.result || vt?.link) {
    out += `<div class="intel-sub-label">VIRUSTOTAL CROSS-REFERENCE</div><div class="modal-kv-grid">
      ${kv('Detections', vt.result)}
      ${vt.link ? `<div class="modal-k">Report</div><div class="modal-v"><a href="${escapeAttr(vt.link)}" target="_blank" class="modal-link" style="margin-left:0">↗ View on VirusTotal</a></div>` : ''}
    </div>`;
  }

  if (blacklists && (blacklists.spamhaus_dbl || blacklists.surbl)) {
    out += `<div class="intel-sub-label">BLACKLISTS</div><div class="modal-kv-grid">
      ${kv('Spamhaus DBL', blacklists.spamhaus_dbl)}
      ${kv('SURBL', blacklists.surbl)}
    </div>`;
  }

  return out;
}

function buildHAContent(ha) {
  if (!ha || ha.noKey) return `<div class="intel-na">${escapeHtml(naMsg(ha))}</div>`;
  if (ha.skipped) return `<div class="intel-na">${escapeHtml(ha.reason || 'Skipped')}</div>`;
  if (ha.error) return `<div class="intel-na">Error: ${escapeHtml(ha.error)}</div>`;
  if (ha.notFound || !ha.count) return `<div class="intel-na" style="color:var(--accent)">No sandbox matches</div>`;

  const verdictCol = ha.verdict === 'malicious' ? 'var(--red)' : ha.verdict === 'suspicious' ? 'var(--yellow)' : 'var(--accent)';

  /* Full vendor payload — ha.raw mirrors what parseHybridAnalysisResponse()
     read from: either an array of per-environment result objects, or a
     single object carrying result/results/reports. mitre_attcks, hosts,
     domains, signatures and av_detect all live down in there, not on the
     parsed ha object, so pull them straight from the untouched response. */
  const haResults = Array.isArray(ha.raw) ? ha.raw : (ha.raw?.result || ha.raw?.results || ha.raw?.reports || []);
  const haOverview = Array.isArray(ha.raw) ? {} : (ha.raw || {});
  const haPool = haResults.slice(0, 5).concat(haOverview);

  const lines = [];
  lines.push(`<div class="modal-k">Sandbox Hits</div><div class="modal-v">${ha.count}${ha.maliciousCount ? ` (${ha.maliciousCount} malicious)` : ''}</div>`);
  if (ha.verdict)   lines.push(`<div class="modal-k">Verdict</div><div class="modal-v" style="color:${verdictCol}">${escapeHtml(ha.verdict.toUpperCase())}</div>`);
  if (ha.maxScore)  lines.push(`<div class="modal-k">Threat Score</div><div class="modal-v" style="color:${verdictCol}">${ha.maxScore} / 100</div>`);
  const avDetect = haPool.map(r => r?.av_detect).find(v => typeof v === 'number');
  if (avDetect != null) lines.push(`<div class="modal-k">AV Detect</div><div class="modal-v">${avDetect}%</div>`);
  if (ha.families?.length)  lines.push(`<div class="modal-k">Malware Family</div><div class="modal-v" style="color:var(--red)">${escapeHtml(ha.families.slice(0,3).join(', '))}</div>`);
  if (ha.sha256)  lines.push(`<div class="modal-k">SHA-256</div><div class="modal-v">${escapeHtml(ha.sha256)}</div>`);
  let out = `<div class="modal-kv-grid">${lines.join('')}</div>`;
  if (ha.tags?.length) out += `<div class="modal-tags">${ha.tags.map(t => `<span class="modal-tag" style="color:var(--ha);border-color:rgba(132,204,22,.3)">${escapeHtml(t)}</span>`).join('')}</div>`;

  /* MITRE ATT&CK techniques matched during detonation — the single highest
     SOC-value field HA returns and previously unused entirely. */
  const mitreMap = new Map();
  haPool.forEach(r => (Array.isArray(r?.mitre_attcks) ? r.mitre_attcks : []).forEach(m => {
    const key = m?.attck_id || m?.technique_id || m?.technique;
    if (key && !mitreMap.has(key)) mitreMap.set(key, m);
  }));
  const mitre = [...mitreMap.values()];
  if (mitre.length) {
    out += `<div class="intel-sub-label">MITRE ATT&CK</div><div class="modal-tags">${mitre.slice(0, 8).map(m => {
      const id = m.attck_id || m.technique_id, name = m.technique;
      const label = id && name ? `${id} · ${name}` : (id || name || 'Unknown');
      return `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(label)}</span>`;
    }).join('')}${mitre.length > 8 ? `<span class="modal-tag">+${mitre.length - 8} more</span>` : ''}</div>`;
  }

  /* Network IOCs the sample contacted during detonation. */
  const hosts = [...new Set(haPool.flatMap(r => [
    ...(Array.isArray(r?.hosts) ? r.hosts : []),
    ...(Array.isArray(r?.domains) ? r.domains : []),
    ...(Array.isArray(r?.compromised_hosts) ? r.compromised_hosts : []),
  ]).filter(Boolean))];
  if (hosts.length) {
    out += `<div class="intel-sub-label">NETWORK IOCS</div><div class="modal-tags">${hosts.slice(0, 8).map(h => `<span class="modal-tag">${escapeHtml(h)}</span>`).join('')}${hosts.length > 8 ? `<span class="modal-tag">+${hosts.length - 8} more</span>` : ''}</div>`;
  }

  /* Behavioral signatures from the sandbox run — name/description field
     naming isn't confirmed in current docs, so try both. */
  const sigs = [...new Set(haPool.flatMap(r => (Array.isArray(r?.signatures) ? r.signatures : []).map(s => s?.name || s?.description)).filter(Boolean))];
  if (sigs.length) {
    out += `<div class="intel-sub-label">BEHAVIORAL SIGNATURES</div><div class="modal-tags">${sigs.slice(0, 6).map(s => `<span class="modal-tag" style="color:var(--yellow)">${escapeHtml(truncate(s, 48))}</span>`).join('')}${sigs.length > 6 ? `<span class="modal-tag">+${sigs.length - 6} more</span>` : ''}</div>`;
  }

  return out;
}

function buildFileScanContent(fs) {
  if (!fs || fs.noKey) return `<div class="intel-na">${escapeHtml(naMsg(fs))}</div>`;
  if (fs.skipped) return `<div class="intel-na">${escapeHtml(fs.reason || 'Skipped')}</div>`;
  if (fs.error) return `<div class="intel-na">Error: ${escapeHtml(fs.error)}</div>`;
  if (fs.notFound || !fs.count) return `<div class="intel-na" style="color:var(--accent)">No reports found</div>`;
  const tlCol = (fs.maxThreatLevel || 0) >= 7 ? 'var(--red)' : (fs.maxThreatLevel || 0) >= 4 ? 'var(--yellow)' : 'var(--accent)';
  const lines = [];
  lines.push(`<div class="modal-k">Reports</div><div class="modal-v">${fs.count}</div>`);
  if (fs.maliciousCount) lines.push(`<div class="modal-k">Malicious</div><div class="modal-v" style="color:var(--red)">${fs.maliciousCount}</div>`);
  lines.push(`<div class="modal-k">Threat Level</div><div class="modal-v" style="color:${tlCol}">${fs.maxThreatLevel || 0} / 10</div>`);
  if (fs.verdicts?.length) lines.push(`<div class="modal-k">Verdict</div><div class="modal-v" style="color:${tlCol}">${escapeHtml(fs.verdicts.join(', '))}</div>`);
  if (fs.families?.length) lines.push(`<div class="modal-k">Malware Family</div><div class="modal-v" style="color:var(--red)">${escapeHtml(fs.families.slice(0,3).join(', '))}</div>`);

  /* Full vendor payload — FileScan.io's public docs page/openapi spec don't
     expose a stable, fully-confirmed schema for this endpoint, so field
     nesting is uncertain (top-level on the item vs. under item.file). Try
     both locations defensively rather than assume one. */
  const fsItems = fs.raw?.items || [];
  const maxConfidence = fsItems.reduce((max, i) => {
    const c = i?.file?.confidence ?? i?.confidence;
    return (typeof c === 'number' && c > max) ? c : max;
  }, -1);
  if (maxConfidence >= 0) lines.push(`<div class="modal-k">Confidence</div><div class="modal-v">${Math.round(maxConfidence <= 1 ? maxConfidence * 100 : maxConfidence)}%</div>`);

  let out = `<div class="modal-kv-grid">${lines.join('')}</div>`;

  const fsTags = [...new Set(fsItems.slice(0, 5).flatMap(i => i?.file?.tags || i?.tags || []).filter(Boolean))];
  if (fsTags.length) {
    out += `<div class="intel-sub-label">TAGS</div><div class="modal-tags">${fsTags.slice(0, 8).map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}${fsTags.length > 8 ? `<span class="modal-tag">+${fsTags.length - 8} more</span>` : ''}</div>`;
  }

  const fsMitre = [...new Set(fsItems.slice(0, 5).flatMap(i => i?.file?.mitre_techniques || i?.mitre_techniques || []).filter(Boolean))];
  if (fsMitre.length) {
    out += `<div class="intel-sub-label">MITRE ATT&CK</div><div class="modal-tags">${fsMitre.slice(0, 8).map(t => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(typeof t === 'string' ? t : (t?.id || t?.name || String(t)))}</span>`).join('')}${fsMitre.length > 8 ? `<span class="modal-tag">+${fsMitre.length - 8} more</span>` : ''}</div>`;
  }

  return out;
}

/* IPLocate — no equivalent in X-VERDIKT's per-IOC modal (there it only
   appears in the separate IP Intel table). Built fresh from
   parseIPLocateResponse()'s field list, following the same kv()/modal-tags
   pattern as the ported blocks above. */
function buildIPLocateBlock(il) {
  if (!il || il.noKey)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--il)">IPLOCATE</div><div class="intel-na">${escapeHtml(naMsg(il))}</div></div>`;
  if (il.skipped)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--il)">IPLOCATE</div><div class="intel-na">${escapeHtml(il.reason || 'IP only')}</div></div>`;
  if (il.error)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--il)">IPLOCATE</div><div class="intel-na">${escapeHtml(typeof il.error === 'string' ? il.error : 'Error')}</div></div>`;
  if (il.notFound)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--il)">IPLOCATE</div><div class="intel-na" style="color:var(--accent)">No data found for this IP</div></div>`;

  const linkHtml = il.link ? ` <a href="${escapeAttr(il.link)}" target="_blank" class="modal-link">↗</a>` : '';
  const HIGH_RISK = { is_abuser: 1, is_tor: 1, is_anonymous: 1 };
  const FLAG_LABELS = {
    is_abuser: 'Abuser', is_anonymous: 'Anonymous', is_vpn: 'VPN', is_proxy: 'Proxy',
    is_tor: 'Tor', is_hosting: 'Hosting', is_icloud_relay: 'iCloud Relay', is_bogon: 'Bogon',
  };
  const activeFlags = Object.keys(FLAG_LABELS).filter(f => il[f]);
  const tagsHtml = activeFlags.length
    ? `<div class="intel-sub-label">PRIVACY / ABUSE FLAGS</div><div class="modal-tags">${activeFlags.map(f =>
        `<span class="modal-tag" style="color:${HIGH_RISK[f] ? 'var(--red)' : 'var(--yellow)'};border-color:${HIGH_RISK[f] ? 'rgba(255,59,92,.3)' : 'rgba(255,214,10,.3)'}">${escapeHtml(FLAG_LABELS[f])}</span>`
      ).join('')}</div>`
    : '';

  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--il)">IPLOCATE${linkHtml}</div>
    <div class="modal-kv-grid">
      ${kv('Country', il.country && il.country_code ? `${il.country} (${il.country_code})` : (il.country || il.country_code))}
      ${kv('City', il.city)}
      ${kv('Subdivision', il.subdivision)}
      ${kv('Continent', il.continent)}
      ${kv('Time Zone', il.time_zone)}
      ${kv('Network', il.network)}
      ${kv('ASN', il.asn != null ? `AS${il.asn}` : null)}
      ${kv('ASN Name', il.asn_name)}
      ${kv('ISP', il.isp)}
      ${kv('Organization', il.organization)}
      ${kv('Domain', il.domain)}
      ${kv('Company Type', il.raw?.company?.type)}
      ${kv('Hosting Provider', il.raw?.hosting?.provider)}
      ${kv('Abuse Contact', il.raw?.abuse?.email)}
    </div>
    ${tagsHtml}
  </div>`;
}

function buildModalContent(entry) {
  const iocType = entry.ioc.type;
  const keys = TYPE_SOURCES[iocType] || [];
  const cardFor = {
    vt:  () => buildVTBlock(entry.vt, iocType),
    ab:  () => buildAbuseIPDBBlock(entry.ab),
    otx: () => buildOTXBlock(entry.otx),
    tf:  () => buildMainCard('THREATFOX', 'var(--tf)', buildThreatFoxContent(entry.tf), entry.tf?.link),
    us:  () => buildMainCard('URLSCAN', 'var(--us)', buildURLScanContent(entry.us), entry.us?.link),
    uh:  () => buildMainCard('URLHAUS', 'var(--uh)', buildURLhausContent(entry.uh), entry.uh?.link),
    mb:  () => buildMBIntelBlock(entry.mb),
    ha:  () => buildMainCard('HYBRIDANALYSIS', 'var(--ha)', buildHAContent(entry.ha), entry.ha?.link),
    fs:  () => buildMainCard('FILESCAN.IO', 'var(--fs)', buildFileScanContent(entry.fs), entry.fs?.link),
    il:  () => buildIPLocateBlock(entry.il),
  };
  const cards = keys.map(k => cardFor[k] ? cardFor[k]() : '').join('');
  return `<div class="modal-intel-grid">${cards}</div>`;
}
