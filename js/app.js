
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
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const btn = document.getElementById('scan-btn');
      if (!btn?.disabled) startScan();
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
  const el = document.getElementById('nav-keys-count');
  if (!el) return;
  const n = ALL_KEY_SERVICES.filter(s => getKey(s)).length;
  el.textContent = n > 0 ? ` (${n}/${ALL_KEY_SERVICES.length})` : '';
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
