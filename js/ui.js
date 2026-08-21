
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
    t.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;padding:11px 18px;font-family:var(--mono);font-size:13px;border:1px solid;border-radius:4px;pointer-events:none;transition:opacity .3s;max-width:340px;';
    document.body.appendChild(t);
  }
  const styles = {
    success: 'background:rgba(0,255,159,.08);border-color:rgba(0,255,159,.4);color:var(--accent)',
    error:   'background:rgba(255,59,92,.08);border-color:rgba(255,59,92,.4);color:var(--red)',
    warning: 'background:rgba(255,214,10,.08);border-color:rgba(255,214,10,.4);color:var(--yellow)',
    info:    'background:rgba(59,130,246,.08);border-color:rgba(59,130,246,.4);color:var(--accent2)',
  };
  t.style.cssText += styles[type] || styles.info;
  t.textContent = msg; t.style.opacity = '1';
  clearTimeout(t._tid);
  t._tid = setTimeout(() => { t.style.opacity = '0'; }, 3200);
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
    case 'us':  return !data.notFound && (data.maliciousCount || 0) > 0 ? 'hit' : 'clean';
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
    case 'us':  return data.notFound ? 'no scans' : `${data.maliciousCount || 0}/${data.total || 0}`;
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
  const msg = document.getElementById('key-saved-msg');
  msg.textContent = '✓ Saved'; msg.classList.add('show');
  setTimeout(() => msg.classList.remove('show'), 3000);
}

function clearKeys() {
  ALL_KEY_SERVICES.forEach(s => localStorage.removeItem(`iv_${s}_key`));
  ALL_KEY_SERVICES.forEach(s => { const el = document.getElementById(`${s}-key`); if (el) el.value = ''; });
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
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Domain', vt.domain)}
        ${kv('Registrar', vt.registrar)}
        ${kv('Categories', vt.categories)}
        ${kv('Reputation', vt.reputation != null ? String(vt.reputation) : null, vt.reputation < 0 ? 'var(--red)' : null)}
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('Last Scan', vt.last_analysis_date)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
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
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  /* Hash */
  if (iocType.startsWith('hash_')) {
    return `<div class="intel-block">
      <div class="intel-block-title" style="color:var(--vt)">VIRUSTOTAL${linkHtml}</div>
      <div class="modal-kv-grid">
        ${kv('Detections', vt.total > 0 ? lastStats : 'No engines ran', scoreColor)}
        ${kv('File Name', vt.name)}
        ${kv('File Type', vt.fileType)}
        ${kv('Size', vt.size)}
        ${kv('First Seen', vt.firstSeen)}
        ${kv('Last Scan', vt.last_analysis_date)}
        ${kv('MD5', vt.md5 ? truncate(vt.md5, 40) : null)}
        ${kv('SHA-1', vt.sha1 ? truncate(vt.sha1, 40) : null)}
        ${kv('SHA-256', vt.sha256 ? truncate(vt.sha256, 44) : null)}
      </div>
      ${vt.tags?.length ? `<div class="modal-tags">${vt.tags.map(t => `<span class="modal-tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
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
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--ab)">ABUSEIPDB ${ab.link ? `<a href="${escapeAttr(ab.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('IP Address', ab.ipAddress)}
      ${kv('IP Version', ab.ipVersion != null ? `IPv${ab.ipVersion}` : null)}
      ${kv('Is Public', ab.isPublic)}
      ${kv('Whitelisted', ab.isWhitelisted)}
      ${kv('Abuse Score', `${ab.score}%`, scoreCol)}
      ${kv('Usage Type', ab.usageType)}
      ${kv('ISP', ab.isp)}
      ${kv('Domain', ab.domain)}
      ${kv('Is Tor', ab.isTor)}
      ${kv('Total Reports', ab.totalReports != null ? String(ab.totalReports) : null)}
      ${kv('Last Reported', ab.lastReportedAt?.split('T')[0])}
    </div>
    ${ab.hostnames?.length ? `<div class="intel-sub-label">HOSTNAMES</div><div class="modal-tags">${ab.hostnames.slice(0,6).map(h => `<span class="modal-tag">${escapeHtml(h)}</span>`).join('')}</div>` : ''}
  </div>`;
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
  </div>`;
}

function buildMBIntelBlock(mb) {
  if (!mb || mb.noKey || mb.error)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na">${escapeHtml(naMsg(mb))}</div></div>`;
  if (mb.skipped)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na">${escapeHtml(mb.reason || 'Skipped')}</div></div>`;
  if (mb.notFound || !mb.count)
    return `<div class="intel-block"><div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR</div><div class="intel-na" style="color:var(--accent)">Not found in malware database</div></div>`;
  return `<div class="intel-block">
    <div class="intel-block-title" style="color:var(--mb)">MALWAREBAZAAR ${mb.link ? `<a href="${escapeAttr(mb.link)}" target="_blank" class="modal-link">↗</a>` : ''}</div>
    <div class="modal-kv-grid">
      ${kv('Samples', String(mb.count), 'var(--red)')}
      ${kv('File Name', mb.fileName)}
      ${kv('File Type', mb.fileType)}
      ${kv('First Seen', mb.firstSeen)}
    </div>
    ${mb.families?.length ? `<div class="intel-sub-label">MALWARE FAMILIES</div><div class="modal-tags">${mb.families.slice(0,5).map(f => `<span class="modal-tag" style="color:var(--red);border-color:rgba(255,59,92,.3)">${escapeHtml(f)}</span>`).join('')}</div>` : ''}
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
  if (us.maliciousCount) lines.push(`<div class="modal-k">Malicious</div><div class="modal-v" style="color:var(--red)">${us.maliciousCount}</div>`);
  let out = `<div class="modal-kv-grid">${lines.join('')}</div>`;
  if (us.recent?.length) {
    out += `<div class="intel-sub-label">RECENT SCANS</div><div class="modal-tags">${us.recent.slice(0,3).map(r => `<span class="modal-tag"${r.malicious ? ' style="color:var(--red);border-color:rgba(255,59,92,.3)"' : ''}>${escapeHtml(truncate(r.domain || r.url, 36))} · ${escapeHtml(r.date)}</span>`).join('')}</div>`;
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
  return `<div class="modal-kv-grid">${lines.join('')}</div>`;
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
  return `<div class="modal-kv-grid">${lines.join('')}</div>`;
}

function buildHAContent(ha) {
  if (!ha || ha.noKey) return `<div class="intel-na">${escapeHtml(naMsg(ha))}</div>`;
  if (ha.skipped) return `<div class="intel-na">${escapeHtml(ha.reason || 'Skipped')}</div>`;
  if (ha.error) return `<div class="intel-na">Error: ${escapeHtml(ha.error)}</div>`;
  if (ha.notFound || !ha.count) return `<div class="intel-na" style="color:var(--accent)">No sandbox matches</div>`;

  const verdictCol = ha.verdict === 'malicious' ? 'var(--red)' : ha.verdict === 'suspicious' ? 'var(--yellow)' : 'var(--accent)';
  const lines = [];
  lines.push(`<div class="modal-k">Sandbox Hits</div><div class="modal-v">${ha.count}${ha.maliciousCount ? ` (${ha.maliciousCount} malicious)` : ''}</div>`);
  if (ha.verdict)   lines.push(`<div class="modal-k">Verdict</div><div class="modal-v" style="color:${verdictCol}">${escapeHtml(ha.verdict.toUpperCase())}</div>`);
  if (ha.maxScore)  lines.push(`<div class="modal-k">Threat Score</div><div class="modal-v" style="color:${verdictCol}">${ha.maxScore} / 100</div>`);
  if (ha.families?.length)  lines.push(`<div class="modal-k">Malware Family</div><div class="modal-v" style="color:var(--red)">${escapeHtml(ha.families.slice(0,3).join(', '))}</div>`);
  if (ha.sha256)  lines.push(`<div class="modal-k">SHA-256</div><div class="modal-v">${escapeHtml(ha.sha256)}</div>`);
  let out = `<div class="modal-kv-grid">${lines.join('')}</div>`;
  if (ha.tags?.length) out += `<div class="modal-tags">${ha.tags.map(t => `<span class="modal-tag" style="color:var(--ha);border-color:rgba(132,204,22,.3)">${escapeHtml(t)}</span>`).join('')}</div>`;
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
  return `<div class="modal-kv-grid">${lines.join('')}</div>`;
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
