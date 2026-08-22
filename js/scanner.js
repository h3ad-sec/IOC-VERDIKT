
let scanResults   = [];
let isScanning    = false;
let stopRequested = false;
let totalScanned  = 0;

/* Conservative VT free-tier pacing by default (4 req/min) — protects the
   user's own key from immediate rate-limiting on bulk scans. No "paid"
   override in v1; users on a paid VT key will just see requests trickle
   slightly slower than necessary. */
const VtBucket = {
  tokens: 4, max: 4, refillRate: 4, lastRefill: Date.now(),
  async acquire() {
    const now = Date.now();
    this.tokens = Math.min(this.max, this.tokens + ((now - this.lastRefill) / 60000) * this.refillRate);
    this.lastRefill = now;
    if (this.tokens >= 1) { this.tokens--; return; }
    const waitMs = ((1 - this.tokens) / this.refillRate) * 60000;
    updateProgressSub(`VT rate limit — waiting ${Math.ceil(waitMs / 1000)}s…`);
    await sleep(waitMs);
    this.tokens = 0; this.lastRefill = Date.now();
  }
};

async function fetchWithRetry(fn, retries = 2, ms = 10000) {
  for (let i = 0; i <= retries; i++) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), ms);
      const r = await fn(ctrl.signal);
      clearTimeout(t); return r;
    } catch(e) {
      if (i === retries) throw e;
      if (e.name === 'AbortError') throw new Error('Timeout');
      await sleep(1000 * (i + 1));
    }
  }
}

/* Sources active per IOC type — short key -> API method */
const SRC_FN = {
  vt: (ioc, sig) => API.virusTotal(ioc, sig),
  ab: (ioc, sig) => API.abuseIPDB(ioc, sig),
  otx:(ioc, sig) => API.otx(ioc, sig),
  tf: (ioc, sig) => API.threatfox(ioc, sig),
  us: (ioc, sig) => API.urlscan(ioc, sig),
  uh: (ioc, sig) => API.urlhaus(ioc, sig),
  mb: (ioc, sig) => API.malwarebazaar(ioc, sig),
  ha: (ioc, sig) => API.hybridanalysis(ioc, sig),
  fs: (ioc, sig) => API.filescan(ioc, sig),
  il: (ioc, sig) => API.iplocate(ioc, sig),
};

const TYPE_SOURCES = {
  ip:          ['ab','vt','otx','tf','il'],
  ipv6:        ['ab','vt','otx','tf','il'],
  domain:      ['vt','otx','tf','us'],
  url:         ['vt','otx','us','uh'],
  hash_md5:    ['vt','otx','tf','mb','ha','fs'],
  hash_sha1:   ['vt','otx','tf','mb','ha','fs'],
  hash_sha256: ['vt','otx','tf','mb','ha','fs'],
  hash_sha512: ['vt','otx','tf','mb','ha','fs'],
};

const ALL_SRC_KEYS = ['vt','ab','otx','tf','us','uh','mb','ha','fs','il'];

async function startScan() {
  const raw = getInputText();
  if (!raw?.trim()) return;

  let { iocs } = parseIOCsWithMeta(raw);
  if (typeof filterIOCsByMode === 'function' && typeof currentMode !== 'undefined')
    iocs = filterIOCsByMode(iocs, currentMode);
  if (!iocs.length) { showToast('No valid IOCs detected', 'error'); return; }

  const privateCount = iocs.filter(i => i.isPrivate).length;
  if (privateCount > 0)
    showToast(`${privateCount} private IP${privateCount > 1 ? 's' : ''} detected — will skip external queries`, 'warning');

  VtBucket.tokens = 4; VtBucket.lastRefill = Date.now();

  isScanning = true; stopRequested = false; scanResults = []; totalScanned = 0;

  currentSearch = '';
  currentTypeFilter = 'all';
  const searchInput = document.getElementById('result-search');
  if (searchInput) searchInput.value = '';
  document.querySelectorAll('.type-filter[data-tfilter]').forEach(b => b.classList.toggle('active', b.dataset.tfilter === 'all'));

  for (const ioc of iocs) {
    const entry = { ioc, done: false };
    for (const k of ALL_SRC_KEYS) entry[k] = null;
    scanResults.push(entry);
  }

  document.getElementById('results-panel').style.display = '';
  document.getElementById('progress-container').style.display = '';
  setScanBtnState('scanning');

  renderResultRows(scanResults);

  for (let i = 0; i < iocs.length; i++) {
    if (stopRequested) break;
    const ioc = iocs[i], entry = scanResults[i];
    updateProgress(i, iocs.length, ioc.value);
    updateRowLoading(i);
    await runParallelScan(entry);
    entry.done = true;
    totalScanned++;
    updateRow(i, entry);
    updateHeaderCount();
  }

  isScanning = false;
  updateProgress(totalScanned, iocs.length, stopRequested ? 'Stopped' : 'Complete');
  setScanBtnState('idle');
  setTimeout(() => { document.getElementById('progress-container').style.display = 'none'; }, 2000);
  const n = iocs.length;
  showToast(
    stopRequested
      ? `Stopped — ${totalScanned} IOC${totalScanned !== 1 ? 's' : ''} analyzed`
      : `IOC-VERDIKT complete — ${n} IOC${n !== 1 ? 's' : ''} analyzed`,
    'success'
  );
}

async function runParallelScan(entry) {
  const { ioc } = entry;
  const t = ioc.type;

  if (ioc.isPrivate) {
    for (const k of ALL_SRC_KEYS) entry[k] = { skipped: true, reason: 'Private IP — skipped' };
    return;
  }

  const active = TYPE_SOURCES[t] || [];
  const jobs = ALL_SRC_KEYS.map(k => {
    if (!active.includes(k)) return Promise.resolve({ skipped: true, reason: 'N/A for this IOC type' });
    if (k === 'vt') {
      return (async () => { await VtBucket.acquire(); return fetchWithRetry(sig => SRC_FN.vt(ioc, sig)); })()
        .catch(e => ({ error: e.message || 'Failed' }));
    }
    return fetchWithRetry(sig => SRC_FN[k](ioc, sig)).catch(e => ({ error: e.message || 'Failed' }));
  });

  const results = await Promise.all(jobs);
  ALL_SRC_KEYS.forEach((k, i) => { entry[k] = results[i]; });
}

function stopScan() { stopRequested = true; showToast('Stopping after current IOC…', 'warning'); }

function setScanBtnState(state) {
  const btn = document.getElementById('scan-btn'), stop = document.getElementById('stop-btn');
  if (state === 'scanning') {
    btn.disabled = true; btn.style.display = 'none'; stop.style.display = '';
  } else {
    btn.disabled = false; btn.style.display = ''; stop.style.display = 'none';
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.5"/><path d="M7 4.5v2.5l1.8 1.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg> ANALYZE`;
  }
}

function updateProgress(done, total, label) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-stats').textContent = `${done} / ${total}`;
  const complete = label === 'Complete' || label === 'Stopped' || done >= total;
  document.getElementById('progress-label').textContent = complete ? 'IOC-VERDIKT COMPLETE' : 'ANALYZING…';
  document.getElementById('progress-sub').innerHTML = complete
    ? `<span style="color:var(--accent)">✓ ${totalScanned} IOC${totalScanned !== 1 ? 's' : ''} analyzed</span><span style="color:var(--muted)">${pct}%</span>`
    : `<span style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%">${escapeHtml(label)}</span><span style="color:var(--muted)">${pct}%</span>`;
}
function updateProgressSub(msg) { const el = document.getElementById('progress-sub'); if (el) el.innerHTML = `<span style="color:var(--yellow)">${escapeHtml(msg)}</span>`; }
function updateHeaderCount() { const el = document.getElementById('session-count'); if (el) el.textContent = totalScanned; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
