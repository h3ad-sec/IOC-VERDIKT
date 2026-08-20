
let currentTypeFilter = 'all';
let currentSearch     = '';
let _currentModalEntry = null;

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

function copyToClipboard(val) {
  navigator.clipboard.writeText(val).then(() => showToast('Copied!', 'success'));
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

function buildRow(entry, i) {
  const { ioc, done } = entry;
  const privateBadge = ioc.isPrivate ? '<div class="ioc-private-badge">PRIVATE</div>' : '';
  const typeBadge    = TYPE_BADGES[ioc.type] || `<span class="type-badge">${escapeHtml(ioc.label)}</span>`;
  const displayVal = ioc.type === 'url' || ioc.type.startsWith('hash_')
    ? truncate(ioc.value, 48) : ioc.value;

  return `<tr data-row="${i}" data-type="${escapeAttr(ioc.type)}" data-ioc="${escapeAttr(ioc.value)}">
    <td class="td-ioc">
      <div class="ioc-val-wrap">
        <span class="ioc-val" title="${escapeAttr(ioc.value)}">${escapeHtml(displayVal)}</span>
        <button class="ioc-copy-btn" onclick="copyToClipboard('${escapeAttr(ioc.value)}')" title="Copy">⎘</button>
      </div>
      ${privateBadge}
    </td>
    <td>${typeBadge}</td>
    <td id="src-${i}" class="col-sources">${buildSourceBadges(entry, done)}</td>
    <td>${done ? `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>` : '<span class="src-loading">…</span>'}</td>
  </tr>`;
}

function buildSourceBadges(entry, done) {
  const keys = TYPE_SOURCES[entry.ioc.type] || [];
  if (!done) return '<div class="src-badges">' + keys.map(k => `<span class="src-badge state-loading" style="color:${SRC_META[k].color}"><span class="src-dot"></span>${SRC_META[k].label}</span>`).join('') + '</div>';
  return '<div class="src-badges">' + keys.map(k => {
    const data = entry[k];
    const state = srcState(k, data);
    const label = srcLabel(k, data, state);
    const meta = SRC_META[k];
    return `<span class="src-badge state-${state}" style="color:${meta.color}" title="${escapeAttr(meta.name + ': ' + label)}"><span class="src-dot"></span>${meta.label} ${escapeHtml(label)}</span>`;
  }).join('') + '</div>';
}

function updateRow(i, entry) {
  const srcEl = document.getElementById(`src-${i}`);
  if (srcEl) srcEl.innerHTML = buildSourceBadges(entry, true);
  const row = document.querySelector(`tr[data-row="${i}"]`);
  if (row) {
    const lastTd = row.querySelector('td:last-child');
    if (lastTd) lastTd.innerHTML = `<button class="btn-detail" onclick="openModal(${i})">DETAIL</button>`;
  }
  applyFilters();
}

function updateRowLoading(i) {
  const row = document.querySelector(`tr[data-row="${i}"]`);
  if (!row) return;
  const srcEl = row.querySelector(`#src-${i}`);
  if (srcEl) srcEl.innerHTML = buildSourceBadges(scanResults[i], false);
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

/* ── Modal — raw per-source JSON ─────────────────────────────────────────── */
function openModal(i) {
  const entry = scanResults[i];
  if (!entry) return;
  _currentModalEntry = entry;
  const displayVal = entry.ioc.type === 'url' || entry.ioc.type.startsWith('hash_')
    ? truncate(entry.ioc.value, 60) : entry.ioc.value;
  document.getElementById('modal-title').innerHTML = `${escapeHtml(displayVal)}
    <span style="color:var(--muted);font-size:11px;margin-left:12px">${escapeHtml(entry.ioc.label)}</span>`;
  document.getElementById('modal-body').innerHTML = buildModalContent(entry);
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() { document.getElementById('modal-overlay')?.classList.remove('open'); }

function buildModalContent(entry) {
  const keys = TYPE_SOURCES[entry.ioc.type] || [];
  return keys.map(k => {
    const data = entry[k];
    const state = srcState(k, data);
    const meta = SRC_META[k];
    const label = srcLabel(k, data, state);
    const link = data?.link ? `<a href="${escapeAttr(data.link)}" target="_blank" rel="noopener" class="modal-link">View on vendor ↗</a>` : '';
    let body;
    if (state === 'nokey') {
      body = `<div class="raw-json" style="color:var(--muted)">No API key configured for this source — add one in SOURCE KEYS above.</div>`;
    } else if (state === 'skip') {
      body = `<div class="raw-json" style="color:var(--muted)">${escapeHtml(data?.reason || 'Not applicable to this IOC type')}</div>`;
    } else if (state === 'error') {
      body = `<div class="raw-json" style="color:var(--red)">${escapeHtml(data?.error || 'Error')}</div>`;
    } else {
      const raw = data?.raw !== undefined ? data.raw : data;
      body = `<pre class="raw-json">${escapeHtml(JSON.stringify(raw, null, 2))}</pre>`;
    }
    return `<div class="raw-source-block">
      <div class="raw-source-header">
        <span class="raw-source-name" style="color:${meta.color}">${meta.name}</span>
        <span class="src-badge state-${state}" style="color:${meta.color}"><span class="src-dot"></span>${escapeHtml(label)}</span>
        ${link}
      </div>
      ${body}
    </div>`;
  }).join('');
}
