
function switchView(view) {
  document.getElementById('view-overview').style.display = view === 'overview' ? '' : 'none';
  document.getElementById('view-workspace').style.display = view === 'overview' ? 'none' : '';
  document.querySelectorAll('.view-tab').forEach(t => t.classList.toggle('active', t.dataset.view === view));
  localStorage.setItem('iv_view', view);
  if (view === 'overview') window.scrollTo({ top: 0 });
}

let currentMode = 'all';

const MODE_CONFIG = {
  all: {
    label: 'IOC',
    types: null,
    placeholder: `Paste IOCs — one per line or comma/space separated\n\nExamples:\n  8.8.8.8\n  evil.example.com\n  https://malware.example.com/payload.exe\n  44d88612fea8a8f36de82e1278abb02f  (MD5)\n  1[.]2[.]3[.]4  (defanged)\n\nCtrl+Enter to analyze`,
  },
  ip: {
    label: 'IP / IPv6',
    types: ['ip', 'ipv6'],
    placeholder: `Paste IPs — one per line\n\nExamples:\n  8.8.8.8\n  1[.]2[.]3[.]4  (defanged)\n  2001:db8::1\n\nCtrl+Enter to analyze`,
  },
  hash: {
    label: 'Hash',
    types: ['hash_md5', 'hash_sha1', 'hash_sha256', 'hash_sha512'],
    placeholder: `Paste file hashes — one per line\n\nExamples:\n  44d88612fea8a8f36de82e1278abb02f  (MD5)\n  da39a3ee5e6b4b0d3255bfef95601890afd80709  (SHA-1)\n  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  (SHA-256)\n\nCtrl+Enter to analyze`,
  },
  domain: {
    label: 'Domain/URL',
    types: ['domain', 'url'],
    placeholder: `Paste domains or URLs — one per line\n\nExamples:\n  evil.example.com\n  malware[.]example.com  (defanged)\n  https://malware.example.com/payload.exe\n  hxxps://phishing[.]site/login\n\nCtrl+Enter to analyze`,
  },
};

function filterIOCsByMode(iocs, mode) {
  const allowed = MODE_CONFIG[mode]?.types;
  if (!allowed) return iocs;
  return iocs.filter(ioc => allowed.includes(ioc.type));
}

function switchMode(mode, btn) {
  currentMode = mode;
  document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  const ta = document.getElementById('ioc-input');
  if (ta) ta.placeholder = MODE_CONFIG[mode].placeholder;
  parseIOCsRealtime();
}

function switchInputTab(tab, btn) {
  document.querySelectorAll('.input-tab').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(`tab-${tab}`).classList.add('active');
}

function scanSingleIOC() {
  const input = document.getElementById('single-ip-input');
  const val = input?.value.trim();
  if (!val) return;
  document.getElementById('ioc-input').value = val;
  parseIOCsRealtime();
  startScan();
  input.value = '';
}

document.addEventListener('DOMContentLoaded', () => {
  switchView(localStorage.getItem('iv_view') === 'overview' ? 'overview' : 'workspace');

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closeModal();
      closeKeysModal();
      if (typeof closeExportModal === 'function') closeExportModal();
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const btn = document.getElementById('scan-btn');
      if (!btn?.disabled) startScan();
    }
    if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const tag = e.target?.tagName;
      const typing = tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable;
      if (!typing) { e.preventDefault(); openKeysModal(); }
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      document.getElementById('single-ip-input')?.focus();
    }
  });

  loadSavedKeys();
  updateKeysNavBadge();

  const hasAnyKey = ALL_KEY_SERVICES.some(s => getKey(s));
  const promptShown = sessionStorage.getItem('iv_key_prompt_seen');
  if (!hasAnyKey && !promptShown) {
    sessionStorage.setItem('iv_key_prompt_seen', '1');
    document.getElementById('keyprompt-modal')?.classList.add('open');
  }
});

function skipKeyPrompt(e) {
  if (e && e.target !== document.getElementById('keyprompt-modal')) return;
  document.getElementById('keyprompt-modal')?.classList.remove('open');
}

function goToKeySetup() {
  document.getElementById('keyprompt-modal')?.classList.remove('open');
  openKeysModal();
}

function openKeysModal() {
  document.getElementById('keys-modal')?.classList.add('open');
}

function closeKeysModal(e) {
  if (e && e.target !== document.getElementById('keys-modal')) return;
  document.getElementById('keys-modal')?.classList.remove('open');
}

function updateKeysNavBadge() {
  const n = ALL_KEY_SERVICES.filter(s => getKey(s)).length;
  const text = n > 0 ? ` (${n}/${ALL_KEY_SERVICES.length})` : '';
  const el = document.getElementById('nav-keys-count');
  if (el) el.textContent = text;
  const drawerEl = document.getElementById('nav-keys-count-drawer');
  if (drawerEl) drawerEl.textContent = text;
}

/* ── Clear all ────────────────────────────────────────────────────────────── */
function clearAll() {
  const inp = document.getElementById('ioc-input'); if (inp) inp.value = '';
  const info = document.getElementById('ioc-parsed-info'); if (info) info.textContent = '';
  const sc = document.getElementById('scan-count'); if (sc) sc.textContent = '';
  document.getElementById('results-panel').style.display = 'none';
  document.getElementById('results-body').innerHTML = '';
  document.getElementById('results-meta').innerHTML = '';
  const btn = document.getElementById('scan-btn'); if (btn) btn.disabled = true;
  scanResults = []; totalScanned = 0;
}

/* ── File upload ──────────────────────────────────────────────────────────── */
function handleDragOver(e)  { e.preventDefault(); document.getElementById('upload-zone')?.classList.add('dragover'); }
function handleDragLeave()  { document.getElementById('upload-zone')?.classList.remove('dragover'); }
function handleDrop(e) { e.preventDefault(); document.getElementById('upload-zone')?.classList.remove('dragover'); const f = e.dataTransfer.files[0]; if (f) processFile(f); }
function handleFileUpload(e) { const f = e.target.files[0]; if (f) processFile(f); e.target.value = ''; }

function processFile(file) {
  const badge = document.getElementById('upload-badge');
  if (badge) { badge.textContent = file.name; badge.style.display = ''; }
  const ext = file.name.split('.').pop().toLowerCase();

  if (ext === 'xlsx' || ext === 'xls') {
    if (typeof XLSX === 'undefined') { showToast('Excel library not ready — try again', 'error'); return; }
    const r = new FileReader();
    r.onload = e => {
      try {
        const wb = XLSX.read(new Uint8Array(e.target.result), { type: 'array' });
        const csv = XLSX.utils.sheet_to_csv(wb.Sheets[wb.SheetNames[0]]);
        loadTextIntoInput(csv, file.name);
      } catch(_) { showToast('Failed to parse Excel file', 'error'); }
    };
    r.readAsArrayBuffer(file);
  } else if (ext === 'json') {
    const r = new FileReader();
    r.onload = e => {
      try {
        const obj = JSON.parse(e.target.result);
        const vals = [];
        (function extract(o) {
          if (typeof o === 'string') vals.push(o);
          else if (Array.isArray(o)) o.forEach(extract);
          else if (o && typeof o === 'object') Object.values(o).forEach(extract);
        })(obj);
        loadTextIntoInput(vals.join('\n'), file.name);
      } catch(_) { loadTextIntoInput(e.target.result, file.name); }
    };
    r.readAsText(file);
  } else {
    const r = new FileReader();
    r.onload = e => loadTextIntoInput(e.target.result, file.name);
    r.readAsText(file);
  }
}

function loadTextIntoInput(text, filename) {
  const firstTab = document.querySelector('.input-tab');
  if (firstTab) switchInputTab('text', firstTab);
  document.getElementById('ioc-input').value = text;
  parseIOCsRealtime();
  showToast(`File loaded${filename ? ': ' + filename : ''}`, 'success');
}

/* ── Key import (txt/csv/md/json/xlsx → key input fields) ────────────────── */
const KEY_ALIASES = {
  vt:             ['vt', 'virustotal', 'virus total'],
  abuseipdb:      ['ab', 'abuseipdb', 'abuse ipdb', 'abuse-ipdb'],
  otx:            ['otx', 'alienvault', 'alienvault otx', 'alien vault'],
  threatfox:      ['tf', 'threatfox', 'threat fox'],
  iplocate:       ['il', 'iplocate', 'ip locate'],
  urlscan:        ['us', 'urlscan', 'url scan'],
  urlhaus:        ['uh', 'urlhaus', 'url haus'],
  malwarebazaar:  ['mb', 'malwarebazaar', 'malware bazaar'],
  hybridanalysis: ['ha', 'hybridanalysis', 'hybrid analysis'],
  filescan:       ['fs', 'filescan', 'filescan.io', 'file scan'],
};

function normalizeKeyName(raw) {
  const clean = String(raw || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!clean) return null;
  for (const [service, aliases] of Object.entries(KEY_ALIASES)) {
    if (aliases.some(a => a.replace(/[^a-z0-9]/g, '') === clean)) return service;
  }
  return null;
}

/* txt/csv/md all share one parser: markdown table rows ("| Source | Key |"),
   and source:key / source=key / source,key lines all reduce to the same
   [name, value] pairs. */
function parseKeyPairsFromText(text) {
  const pairs = [];
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('|')) {
      const cells = line.split('|').map(c => c.trim()).filter(Boolean);
      if (cells.length >= 2 && !/^-+$/.test(cells[0])) pairs.push([cells[0], cells[1]]);
      continue;
    }
    const m = line.match(/^([^=:,\t/]+)[=:,\t/]\s*(.+)$/);
    if (m) pairs.push([m[1].trim(), m[2].trim().replace(/^["']|["']$/g, '')]);
  }
  return pairs;
}

function applyImportedKeys(pairs) {
  let matched = 0, skipped = 0;
  for (const [rawName, rawValue] of pairs) {
    const service = normalizeKeyName(rawName);
    const value = String(rawValue ?? '').trim();
    const el = service && document.getElementById(`${service}-key`);
    if (el && value) { el.value = value; matched++; } else skipped++;
  }
  if (matched) showToast(`Imported ${matched} key${matched !== 1 ? 's' : ''}${skipped ? ` · ${skipped} unrecognized` : ''} — review, then SAVE KEYS`, 'success');
  else showToast('No recognizable source keys found in that file', 'error');
}

function handleKeyImport(e) {
  const file = e.target.files[0];
  if (!file) return;
  const ext = file.name.split('.').pop().toLowerCase();

  if (ext === 'xlsx' || ext === 'xls') {
    if (typeof XLSX === 'undefined') { showToast('Excel library not ready — try again', 'error'); return; }
    const r = new FileReader();
    r.onload = ev => {
      try {
        const wb = XLSX.read(new Uint8Array(ev.target.result), { type: 'array' });
        const rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]], { header: 1 });
        applyImportedKeys(rows.filter(row => row.length >= 2).map(row => [row[0], row[1]]));
      } catch(_) { showToast('Failed to parse Excel file', 'error'); }
    };
    r.readAsArrayBuffer(file);
  } else if (ext === 'json') {
    const r = new FileReader();
    r.onload = ev => {
      try {
        const obj = JSON.parse(ev.target.result);
        const pairs = Array.isArray(obj)
          ? obj.map(o => [o.source ?? o.name ?? o.service, o.key ?? o.value ?? o.apikey ?? o.apiKey]).filter(p => p[0] != null)
          : (obj && typeof obj === 'object') ? Object.entries(obj) : [];
        applyImportedKeys(pairs);
      } catch(_) { showToast('Failed to parse JSON file', 'error'); }
    };
    r.readAsText(file);
  } else {
    const r = new FileReader();
    r.onload = ev => applyImportedKeys(parseKeyPairsFromText(ev.target.result));
    r.readAsText(file);
  }
  e.target.value = '';
}

function downloadKeyTemplate() {
  const fmt = document.getElementById('key-template-format')?.value || 'json';
  const services = ALL_KEY_SERVICES;
  const dateTag = expDateTag();
  const base = `ioc-verdikt-keys-template-${dateTag}`;

  if (fmt === 'json') {
    const obj = {};
    services.forEach(s => { obj[s] = ''; });
    downloadFile(JSON.stringify(obj, null, 2), `${base}.json`, 'application/json');
  } else if (fmt === 'txt') {
    downloadFile(services.map(s => `${s}=`).join('\n') + '\n', `${base}.txt`, 'text/plain;charset=utf-8;');
  } else if (fmt === 'csv') {
    const lines = ['source,key', ...services.map(s => `${s},`)];
    downloadFile('﻿' + lines.join('\r\n'), `${base}.csv`, 'text/csv;charset=utf-8;');
  } else if (fmt === 'md') {
    const rows = ['| Source | Key |', '|---|---|', ...services.map(s => `| ${s} |  |`)];
    downloadFile(rows.join('\n') + '\n', `${base}.md`, 'text/markdown;charset=utf-8;');
  } else if (fmt === 'xlsx') {
    if (typeof XLSX === 'undefined') { showToast('Excel library not ready — try again', 'error'); return; }
    const wb = XLSX.utils.book_new();
    const sheet = XLSX.utils.aoa_to_sheet([['source', 'key'], ...services.map(s => [s, ''])]);
    XLSX.utils.book_append_sheet(wb, sheet, 'Keys');
    XLSX.writeFile(wb, `${base}.xlsx`);
  }
  showToast('Template downloaded', 'success');
}
