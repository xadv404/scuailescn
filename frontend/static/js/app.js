/* ═══════════════════════════════════════════════════════════════
   Pentest Audit Scanner v5 — Frontend
══════════════════════════════════════════════════════════════ */
'use strict';

const API     = '';
const POLL_MS = 3000;

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

async function apiFetch(path, options = {}) {
  const r = await fetch(API + path, { headers: { 'Content-Type': 'application/json' }, ...options });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { const e = await r.json(); msg = JSON.stringify(e.detail) || msg; } catch (_) {}
    throw new Error(msg);
  }
  return r.json();
}

function toast(msg, type = 'info', ms = 4500) {
  const el = document.createElement('div');
  el.className = `toast toast--${type}`;
  el.textContent = msg;
  $('#toast-container').appendChild(el);
  setTimeout(() => el.remove(), ms);
}

const escHtml = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const truncate = (s, n = 55) => s.length > n ? s.slice(0, n - 1) + '…' : s;
const fmtDate  = iso => iso ? new Date(iso).toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';
const fmtDur   = s  => s == null ? '—' : (Math.floor(s/60) > 0 ? `${Math.floor(s/60)}m ` : '') + `${Math.round(s%60)}s`;

function severityClass(sev) {
  return {critical:'critical',high:'high',medium:'medium',low:'low',info:'info',none:'none'}[(sev||'none').toLowerCase()] || 'none';
}

/* ── Clock ─────────────────────────────────────────────────── */
function startClock() {
  const el = $('#header-clock');
  if (!el) return;
  const tick = () => el.textContent = new Date().toLocaleTimeString('fr-FR');
  tick(); setInterval(tick, 1000);
}

/* ── Health ─────────────────────────────────────────────────── */
async function checkHealth() {
  const pill = $('#sqlmap-pill'), label = $('#sqlmap-label');
  try {
    const d = await apiFetch('/api/health');
    if (d.sqlmap_available) {
      pill.className = 'pill pill--ok'; label.textContent = 'SQLMap actif';
    } else {
      pill.className = 'pill pill--warn'; label.textContent = 'SQLMap manquant';
    }
  } catch (_) { pill.className = 'pill pill--err'; label.textContent = 'API hors ligne'; }
}

/* ── Tabs ───────────────────────────────────────────────────── */
function switchTab(tab) {
  $('#panel-file').style.display = tab === 'file' ? '' : 'none';
  $('#panel-url').style.display  = tab === 'url'  ? '' : 'none';
  $('#tab-file').classList.toggle('tab--active', tab === 'file');
  $('#tab-url').classList.toggle('tab--active',  tab === 'url');
}
window.switchTab = switchTab;

/* ── Pipeline steps animator ────────────────────────────────── */
const _stepMap = {
  'recon':   '#pstep-recon',
  'detect':  '#pstep-detect',
  'analyze': '#pstep-analyze',
  'extract': '#pstep-extract',
  'csv':     '#pstep-csv',
};
const _pct_to_step = pct => {
  if (pct < 20) return 'recon';
  if (pct < 45) return 'detect';
  if (pct < 65) return 'analyze';
  if (pct < 80) return 'extract';
  return 'csv';
};
function animatePipeline(pct, completed = false, failed = false) {
  const active = completed ? 'csv' : _pct_to_step(pct);
  for (const [key, sel] of Object.entries(_stepMap)) {
    const el = $(sel);
    if (!el) continue;
    el.classList.remove('pstep--active', 'pstep--done', 'pstep--fail');
    const steps = Object.keys(_stepMap);
    const activeIdx = steps.indexOf(active);
    const thisIdx   = steps.indexOf(key);
    if (failed && key === active) { el.classList.add('pstep--fail'); }
    else if (thisIdx < activeIdx || (completed && thisIdx <= activeIdx)) { el.classList.add('pstep--done'); }
    else if (thisIdx === activeIdx) { el.classList.add('pstep--active'); }
  }
}

/* ── Drop zone / file upload ────────────────────────────────── */
let _pendingUrls = [];

function initDropZone() {
  const dz  = $('#drop-zone');
  const inp = $('#file-input');

  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dz--over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('dz--over'));
  dz.addEventListener('drop', e => {
    e.preventDefault();
    dz.classList.remove('dz--over');
    const f = e.dataTransfer.files[0];
    if (f) readFile(f);
  });

  inp.addEventListener('change', () => { if (inp.files[0]) readFile(inp.files[0]); });
}

function readFile(file) {
  const reader = new FileReader();
  reader.onload = e => previewTargets(e.target.result, file.name);
  reader.readAsText(file);
}

function previewTargets(text, filename) {
  const urls = text.split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
  _pendingUrls = urls;

  const preview = $('#file-preview');
  preview.style.display = '';
  preview.innerHTML = `
    <div class="preview-header">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/></svg>
      ${escHtml(filename)} — <strong>${urls.length}</strong> cible${urls.length > 1 ? 's' : ''} détectée${urls.length > 1 ? 's' : ''}
    </div>
    <ul class="preview-list">
      ${urls.slice(0, 10).map(u => `<li>${escHtml(u)}</li>`).join('')}
      ${urls.length > 10 ? `<li class="preview-more">… et ${urls.length - 10} autres</li>` : ''}
    </ul>`;
}

/* ── URL manual input ───────────────────────────────────────── */
let _urlCount = 0;
function addUrlRow(val = '') {
  _urlCount++;
  const id  = `url-${_urlCount}`;
  const row = document.createElement('div');
  row.className = 'url-row'; row.id = id;
  row.innerHTML = `
    <input class="url-input" type="url" placeholder="https://target.com/page?id=1"
           value="${escHtml(val)}" autocomplete="off" spellcheck="false" />
    <button class="url-remove" title="Supprimer" data-row="${id}">×</button>`;
  $('#url-container').appendChild(row);
  row.querySelector('.url-remove').addEventListener('click', () => {
    if ($$('.url-row').length > 1) row.remove();
  });
}
function getManualUrls() {
  return $$('.url-input').map(i => i.value.trim()).filter(Boolean);
}

/* ── Start scan ─────────────────────────────────────────────── */
async function startScan() {
  const activeTab = $('#tab-file').classList.contains('tab--active') ? 'file' : 'url';
  const btn = $('#btn-start');

  let urls = [];
  let useUpload = false;

  if (activeTab === 'file') {
    const inp  = $('#file-input');
    const file = inp.files[0];
    if (file) {
      useUpload = true;
    } else if (_pendingUrls.length) {
      urls = _pendingUrls;
    } else {
      toast('Déposez un fichier targets.txt ou saisissez des URLs.', 'error');
      return;
    }
  } else {
    urls = getManualUrls();
    if (!urls.length) {
      toast('Saisissez au moins une URL.', 'error');
      return;
    }
    const invalid = urls.filter(u => !/^https?:\/\/.+/.test(u));
    if (invalid.length) {
      toast('URL(s) invalide(s) — http/https requis.', 'error');
      return;
    }
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Lancement…';
  animatePipeline(5);

  try {
    let result;
    if (useUpload) {
      const fd = new FormData();
      fd.append('file', $('#file-input').files[0]);
      const r = await fetch('/api/targets/upload', { method: 'POST', body: fd });
      if (!r.ok) { const e = await r.json(); throw new Error(JSON.stringify(e.detail)); }
      result = await r.json();
    } else {
      result = await apiFetch('/api/scan/start', {
        method: 'POST',
        body: JSON.stringify({ urls }),
      });
    }
    toast(`${result.queued} cible${result.queued > 1 ? 's' : ''} en cours d'audit…`, 'success');
    result.scan_ids.forEach(id => startPolling(id));
  } catch (err) {
    toast('Erreur : ' + err.message, 'error');
    animatePipeline(0);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16"><polygon points="5 3 19 12 5 21 5 3"/></svg> Lancer l'audit`;
  }
}

/* ── Polling ────────────────────────────────────────────────── */
const activePolls = new Map();

function riskColor(score) {
  if (score >= 70) return 'var(--red)';
  if (score >= 40) return 'var(--orange)';
  if (score >= 15) return 'var(--yellow)';
  return 'var(--green)';
}

function renderScanRow(data) {
  const { scan_id, status, progress, progress_pct, url, error, summary, sqli_confirmed, csv_files } = data;
  const pct    = Math.min(100, Math.max(0, Math.round(progress_pct || 0)));
  const done   = status === 'completed';
  const failed = status === 'failed';
  const risk   = summary?.risk_level || 'N/A';
  const score  = summary?.risk_score ?? null;
  const barBg  = failed ? 'var(--red)' : done ? 'var(--green)' : 'linear-gradient(90deg,var(--accent),#58a6ff)';

  const sqliTag = sqli_confirmed
    ? `<span class="sqli-tag">⚡ SQLi</span>`
    : '';

  const csvBtns = (csv_files || []).map(f =>
    `<a class="btn btn--csv btn--sm" href="/api/scan/${escHtml(scan_id)}/csv/${encodeURIComponent(f.filename)}" download="${escHtml(f.filename)}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/></svg>
      ${escHtml(f.filename)} <span class="csv-size">${f.size_kb}kb</span>
    </a>`
  ).join('');

  return `
  <div class="scan-row scan-row--${status}" id="scan-${scan_id}">
    <div class="scan-row-top">
      <div class="scan-url-wrap">
        <span class="scan-url">${escHtml(truncate(url || '—', 60))}</span>
        <span class="scan-id-tag">#${escHtml(scan_id)}</span>
      </div>
      <div class="scan-badges">
        ${sqliTag}
        ${done ? `<span class="badge badge--${severityClass((risk).toLowerCase())}">${escHtml(risk)}</span>` : ''}
        ${done && score != null ? `<span class="score-tag" style="color:${riskColor(score)}">${score}/100</span>` : ''}
        ${!done && !failed ? '<span class="spinner"></span>' : ''}
        ${failed ? '<span class="badge badge--critical">ÉCHEC</span>' : ''}
      </div>
    </div>
    <div class="progress-bar-wrap">
      <div class="progress-bar" style="width:${pct}%;background:${barBg}"></div>
    </div>
    <div class="progress-label">
      <span>${escHtml(failed ? (error || 'Erreur') : (progress || status))}</span>
      <span>${pct}%</span>
    </div>
    ${done ? `
    <div class="scan-row-actions">
      <button class="btn btn--ghost btn--sm" onclick="openReport('${escHtml(scan_id)}')">
        Voir le rapport
      </button>
      ${csvBtns}
      <button class="btn btn--danger btn--sm" onclick="removeScan('${escHtml(scan_id)}')">×</button>
    </div>` : ''}
  </div>`;
}

function upsertRow(data) {
  const el   = $(`#scan-${data.scan_id}`);
  const html = renderScanRow(data);
  if (el) { el.outerHTML = html; }
  else { $('#active-list').insertAdjacentHTML('afterbegin', html); }
  const runCount = $$('#active-list .scan-row--running, #active-list .scan-row--pending').length;
  $('#active-count').textContent = $$('#active-list .scan-row').length;
  $('#section-active').style.display = '';
  animatePipeline(data.progress_pct || 0, data.status === 'completed', data.status === 'failed');
}

async function pollScan(scan_id) {
  try {
    const data = await apiFetch(`/api/scan/${scan_id}/status`);
    upsertRow(data);

    if (data.status === 'completed' || data.status === 'failed') {
      clearInterval(activePolls.get(scan_id));
      activePolls.delete(scan_id);
      loadReports();

      if (data.status === 'completed') {
        const sqli  = data.sqli_confirmed;
        const score = data.summary?.risk_score;
        const risk  = data.summary?.risk_level || 'N/A';
        const csvN  = (data.csv_files || []).length;
        toast(
          `#${scan_id} terminé — Risque: ${risk} (${score}/100)${sqli ? ' ⚡ SQLi confirmé' : ''}${csvN ? ` — ${csvN} CSV` : ''}`,
          sqli || score >= 40 ? 'error' : 'success'
        );
      } else {
        toast(`#${scan_id} a échoué`, 'error');
      }
    }
  } catch (err) {
    console.error('Poll error:', err);
  }
}

function startPolling(scan_id) {
  pollScan(scan_id);
  const id = setInterval(() => pollScan(scan_id), POLL_MS);
  activePolls.set(scan_id, id);
}

async function removeScan(scan_id) {
  try {
    await apiFetch(`/api/scan/${scan_id}`, { method: 'DELETE' });
    $(`#scan-${scan_id}`)?.remove();
    $('#active-count').textContent = $$('#active-list .scan-row').length;
    if (!$$('#active-list .scan-row').length) $('#section-active').style.display = 'none';
    loadReports();
    toast('Scan supprimé', 'info');
  } catch (err) { toast('Erreur : ' + err.message, 'error'); }
}
window.removeScan = removeScan;

/* ── Reports list ───────────────────────────────────────────── */
async function loadReports() {
  const c = $('#reports-list');
  try {
    const reports = await apiFetch('/api/reports');
    if (!reports.length) { c.innerHTML = '<p class="empty-state">Aucun audit disponible.</p>'; return; }
    c.innerHTML = `
    <table class="report-table">
      <thead><tr>
        <th>ID</th><th>Cible</th><th>Date</th>
        <th>DB</th><th>SQLi</th><th>Risque</th><th>Score</th><th>Statut</th>
        <th style="text-align:right">Actions</th>
      </tr></thead>
      <tbody>
        ${reports.map(r => `
        <tr>
          <td class="mono">${escHtml(r.scan_id||'—')}</td>
          <td class="target-cell" title="${escHtml(r.target||'')}">${escHtml(truncate(r.target||'—',38))}</td>
          <td style="font-size:11px">${fmtDate(r.date)}</td>
          <td class="db-cell">${escHtml(r.database_type||'—')}</td>
          <td>${r.sqli_confirmed ? '<span class="sqli-tag">⚡ OUI</span>' : '<span class="muted-tag">non</span>'}</td>
          <td><span class="badge badge--${severityClass((r.risk_level||'none').toLowerCase())}">${escHtml(r.risk_level||'N/A')}</span></td>
          <td><span style="color:${riskColor(r.risk_score||0)};font-weight:600;font-size:12px">${r.risk_score != null ? r.risk_score+'/100' : '—'}</span></td>
          <td><span class="badge badge--status-${r.status}">${escHtml(r.status||'—')}</span></td>
          <td class="actions-cell">
            <button class="btn btn--ghost btn--sm" onclick="openReport('${escHtml(r.scan_id)}')">Rapport</button>
            <button class="btn btn--ghost btn--sm" onclick="openCsvModal('${escHtml(r.scan_id)}')">CSV</button>
            <button class="btn btn--viewer btn--sm" onclick="openViewer('${escHtml(r.scan_id)}')">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18"/></svg>
              Données
            </button>
            <button class="btn btn--danger btn--sm" onclick="removeScan('${escHtml(r.scan_id)}')">×</button>
          </td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  } catch (err) {
    c.innerHTML = `<p class="empty-state">Erreur : ${escHtml(err.message)}</p>`;
  }
}

/* ── Results Viewer ─────────────────────────────────────────── */
const _viewer = {
  scanId:       null,
  filename:     null,
  tableName:    null,
  page:         1,
  perPage:      50,
  search:       '',
  sortCol:      '',
  sortDir:      'asc',
  debounce:     null,
};

async function openViewer(scan_id) {
  _viewer.scanId    = scan_id;
  _viewer.filename  = null;
  _viewer.tableName = null;
  _viewer.page      = 1;
  _viewer.search    = '';
  _viewer.sortCol   = '';
  _viewer.sortDir   = 'asc';

  const section = $('#section-viewer');
  section.style.display = '';
  $('#viewer-scan-id').textContent = `#${scan_id}`;
  $('#viewer-main').innerHTML = '<p class="viewer-empty">Sélectionner une table dans la liste à gauche.</p>';
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  await loadViewerTables(scan_id);
}
window.openViewer = openViewer;

async function loadViewerTables(scan_id) {
  const sidebar = $('#viewer-sidebar');
  sidebar.innerHTML = '<p class="viewer-empty">Chargement…</p>';
  try {
    const data = await apiFetch(`/api/scan/${encodeURIComponent(scan_id)}/tables`);
    const dbs  = (data.databases || []).filter(d => d.tables.length > 0);

    if (!dbs.length) {
      sidebar.innerHTML = '<p class="viewer-empty">Aucune table extraite.<br><span style="font-size:10px;color:var(--text-muted)">SQLi requis pour l\'extraction.</span></p>';
      return;
    }

    let html = '<div class="viewer-db-list">';
    for (const db of dbs) {
      html += `
      <div class="viewer-db-item">
        <div class="viewer-db-name">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12">
            <ellipse cx="12" cy="5" rx="9" ry="3"/>
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
          </svg>
          ${escHtml(db.name)}
        </div>
        <div class="viewer-table-list">`;
      for (const t of db.tables) {
        html += `
          <div class="viewer-table-item"
               data-filename="${escHtml(t.filename)}"
               onclick="openTable(${JSON.stringify(scan_id)},${JSON.stringify(t.filename)},${JSON.stringify(t.table)})">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11">
              <rect x="3" y="3" width="18" height="18" rx="2"/>
              <path d="M3 9h18M3 15h18M9 3v18"/>
            </svg>
            <span class="viewer-table-name">${escHtml(t.table)}</span>
            <span class="viewer-row-count">${t.row_count}</span>
          </div>`;
      }
      html += '</div></div>';
    }
    html += '</div>';
    sidebar.innerHTML = html;
  } catch (err) {
    sidebar.innerHTML = `<p class="viewer-empty">Erreur : ${escHtml(err.message)}</p>`;
  }
}

async function openTable(scan_id, filename, table_name) {
  _viewer.filename  = filename;
  _viewer.tableName = table_name;
  _viewer.page      = 1;
  _viewer.search    = '';
  _viewer.sortCol   = '';
  _viewer.sortDir   = 'asc';

  $$('.viewer-table-item').forEach(el => el.classList.remove('viewer-table-item--active'));
  $(`.viewer-table-item[data-filename="${CSS.escape(filename)}"]`)?.classList.add('viewer-table-item--active');

  await loadTablePage();
}
window.openTable = openTable;

async function loadTablePage() {
  if (!_viewer.scanId || !_viewer.filename) return;
  const main = $('#viewer-main');

  const params = new URLSearchParams({ page: _viewer.page, per_page: _viewer.perPage });
  if (_viewer.search)  params.set('search',   _viewer.search);
  if (_viewer.sortCol) { params.set('sort_col', _viewer.sortCol); params.set('sort_dir', _viewer.sortDir); }

  try {
    const data = await apiFetch(
      `/api/scan/${encodeURIComponent(_viewer.scanId)}/table/${encodeURIComponent(_viewer.filename)}?${params}`
    );
    main.innerHTML = renderViewerTable(data);

    const inp = $('#viewer-search');
    if (inp) {
      inp.value = _viewer.search;
      inp.focus();
      inp.addEventListener('input', () => {
        clearTimeout(_viewer.debounce);
        _viewer.debounce = setTimeout(() => {
          _viewer.search = inp.value.trim();
          _viewer.page   = 1;
          loadTablePage();
        }, 300);
      });
    }

    $$('.viewer-th-sort', main).forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.col;
        if (_viewer.sortCol === col) {
          _viewer.sortDir = _viewer.sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          _viewer.sortCol = col;
          _viewer.sortDir = 'asc';
        }
        _viewer.page = 1;
        loadTablePage();
      });
    });

    $$('.viewer-page-btn', main).forEach(btn => {
      btn.addEventListener('click', () => {
        const p = parseInt(btn.dataset.page, 10);
        if (!isNaN(p)) { _viewer.page = p; loadTablePage(); }
      });
    });
  } catch (err) {
    main.innerHTML = `<p class="viewer-empty">Erreur : ${escHtml(err.message)}</p>`;
  }
}

function renderViewerTable(data) {
  const { columns, rows, total, page, per_page, total_pages, capped_at, search } = data;
  if (!columns.length) return '<p class="viewer-empty">Table vide.</p>';

  const capNote = total >= capped_at
    ? `<span class="viewer-cap-note">⚠ limité aux ${capped_at} premières lignes</span>`
    : '';

  const startRow = (page - 1) * per_page + 1;
  const endRow   = Math.min(page * per_page, total);

  // Pagination range
  const range = [];
  const lo = Math.max(1, page - 2), hi = Math.min(total_pages, page + 2);
  if (lo > 1)             { range.push(1); if (lo > 2) range.push('…'); }
  for (let i = lo; i <= hi; i++) range.push(i);
  if (hi < total_pages)   { if (hi < total_pages - 1) range.push('…'); range.push(total_pages); }

  return `
  <div class="viewer-toolbar">
    <div class="viewer-breadcrumb">
      <span class="viewer-bc-table">${escHtml(_viewer.tableName || data.filename)}</span>
    </div>
    <div class="viewer-toolbar-right">
      <span class="viewer-info">${total ? `${startRow}–${endRow} / ${total} ligne${total>1?'s':''}` : '0 ligne'} ${search ? `· "${escHtml(search)}"` : ''} ${capNote}</span>
      <label class="viewer-search-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="viewer-search" class="viewer-search" type="text" placeholder="Rechercher…" autocomplete="off" />
      </label>
    </div>
  </div>

  <div class="viewer-table-wrap">
    <table class="data-table">
      <thead><tr>
        ${columns.map(col => {
          const active = _viewer.sortCol === col;
          const dir    = active ? _viewer.sortDir : '';
          return `<th class="viewer-th-sort${active ? ' sort--'+dir : ''}" data-col="${escHtml(col)}">
            ${escHtml(col)}<span class="sort-icon">${active ? (dir==='asc'?'↑':'↓') : '↕'}</span>
          </th>`;
        }).join('')}
      </tr></thead>
      <tbody>
        ${rows.length
          ? rows.map(row => `<tr>${columns.map(col => {
              const v = String(row[col] ?? '');
              return `<td title="${escHtml(v)}">${escHtml(truncate(v, 80))}</td>`;
            }).join('')}</tr>`).join('')
          : `<tr><td colspan="${columns.length}" class="viewer-empty">Aucun résultat.</td></tr>`}
      </tbody>
    </table>
  </div>

  ${total_pages > 1 ? `
  <div class="viewer-pagination">
    <button class="viewer-page-btn" data-page="${page-1}" ${page<=1?'disabled':''}>‹</button>
    <div class="viewer-page-nums">
      ${range.map(p => p === '…'
        ? `<span class="viewer-page-ellipsis">…</span>`
        : `<button class="viewer-page-btn${p===page?' viewer-page-btn--active':''}" data-page="${p}">${p}</button>`
      ).join('')}
    </div>
    <button class="viewer-page-btn" data-page="${page+1}" ${page>=total_pages?'disabled':''}>›</button>
    <span class="viewer-page-info">${page} / ${total_pages}</span>
  </div>` : ''}`
  ;
}

/* ── CSV modal ──────────────────────────────────────────────── */
async function openCsvModal(scan_id) {
  try {
    const data = await apiFetch(`/api/scan/${scan_id}/csv`);
    const files = data.files || [];
    if (!files.length) { toast('Aucun CSV disponible pour ce scan', 'info'); return; }
    const body = $('#modal-body');
    $('#modal-title').textContent = `CSV — #${scan_id}`;
    body.innerHTML = `
      <div class="csv-file-list">
        ${files.map(f => `
        <a class="csv-file-card" href="/api/scan/${escHtml(scan_id)}/csv/${encodeURIComponent(f.filename)}" download="${escHtml(f.filename)}">
          <span class="csv-file-icon">⬇</span>
          <div>
            <div class="csv-file-name">${escHtml(f.filename)}</div>
            <div class="csv-file-meta">${f.type} — ${f.size_kb} KB</div>
          </div>
        </a>`).join('')}
      </div>`;
    $('#modal-overlay').style.display = 'flex';
  } catch (err) { toast('Erreur CSV : ' + err.message, 'error'); }
}
window.openCsvModal = openCsvModal;

/* ── Report modal ───────────────────────────────────────────── */
let _currentReport = null;

async function openReport(scan_id) {
  const overlay = $('#modal-overlay'), body = $('#modal-body');
  body.innerHTML = '<p class="empty-state">Chargement…</p>';
  overlay.style.display = 'flex';
  try {
    const report = await apiFetch(`/api/scan/${scan_id}/report`);
    _currentReport = report;
    body.innerHTML = renderReport(report);
    $('#modal-title').textContent = `Rapport #${scan_id}`;
    $$('.finding-header', body).forEach(h =>
      h.addEventListener('click', () => h.closest('.finding-card').classList.toggle('is-open'))
    );
  } catch (err) {
    body.innerHTML = `<p class="empty-state" style="color:var(--red)">Erreur : ${escHtml(err.message)}</p>`;
  }
}
window.openReport = openReport;

/* ── Report renderer ────────────────────────────────────────── */
function renderReport(r) {
  const ss       = r.scan_summary || r.summary || {};
  const sev      = ss.severity || ss.severity_breakdown || {};
  const findings = r.findings  || [];
  const recs     = r.recommendations || [];
  const risk     = ss.risk_level || 'NONE';
  const vuln     = ss.vulnerable;
  const dbType   = ss.database_type || 'Non détecté';
  const score    = ss.risk_score ?? null;
  const cats     = ss.categories || {};
  const techs    = ss.technologies || [];
  const phases   = ss.phases || [];
  const sqli     = ss.sqli_confirmed || false;

  return `
  <div class="dashboard-stats">
    <div class="stat-card ${vuln ? 'stat--critical' : 'stat--safe'}">
      <div class="stat-value">${vuln ? '⚠' : '✓'}</div>
      <div class="stat-label">${vuln ? 'Vulnérable' : 'Sain'}</div>
    </div>
    <div class="stat-card ${severityCard(risk)}">
      <div class="stat-value">${escHtml(risk)}</div>
      <div class="stat-label">Risque</div>
    </div>
    ${score != null ? `
    <div class="stat-card">
      <div class="stat-value" style="color:${riskColor(score)}">${score}<span style="font-size:14px;opacity:.6">/100</span></div>
      <div class="stat-label">Score</div>
      <div class="risk-bar-track"><div class="risk-bar-fill" style="width:${score}%;background:${riskColor(score)}"></div></div>
    </div>` : ''}
    <div class="stat-card">
      <div class="stat-value" style="color:var(--accent)">${findings.length}</div>
      <div class="stat-label">Findings</div>
    </div>
    <div class="stat-card ${sqli ? 'stat--sqli' : ''}">
      <div class="stat-value">${sqli ? '⚡ OUI' : 'NON'}</div>
      <div class="stat-label">SQLi</div>
    </div>
    <div class="stat-card stat--db">
      <div class="stat-value" style="font-size:14px">${escHtml(dbType)}</div>
      <div class="stat-label">Base de données</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:var(--text-secondary)">${escHtml(fmtDur(r.duration_seconds))}</div>
      <div class="stat-label">Durée</div>
    </div>
  </div>

  <div class="report-meta-grid">
    <div class="meta-block"><div class="label">Cible</div><div class="value mono">${escHtml(r.target||'—')}</div></div>
    <div class="meta-block"><div class="label">Scan ID</div><div class="value mono">${escHtml(r.scan_id||'—')}</div></div>
    <div class="meta-block"><div class="label">Statut</div><div class="value"><span class="badge badge--status-${r.status}">${escHtml(r.status)}</span></div></div>
    <div class="meta-block"><div class="label">Date</div><div class="value">${fmtDate(r.date)}</div></div>
  </div>

  ${techs.length ? `
  <div class="section-title">Technologies</div>
  <div class="tech-chips">${techs.map(t => `<span class="tech-chip">${escHtml(t)}</span>`).join('')}</div>` : ''}

  ${phases.length ? `
  <div class="section-title">Pipeline d'exécution</div>
  <div class="phases-grid">
    ${phases.map((p, i) => `
    <div class="phase-card">
      <div class="phase-num">${i+1}</div>
      <div class="phase-info">
        <div class="phase-name">${escHtml(p.name)}</div>
        <div class="phase-modules">${(p.modules||[]).map(m => `<code>${escHtml(m)}</code>`).join('')}</div>
      </div>
      <div class="phase-stats">
        <span class="phase-findings">${p.findings}</span>
        <span class="phase-dur">${p.duration_s}s</span>
      </div>
    </div>`).join('')}
  </div>` : ''}

  ${Object.keys(cats).length ? `
  <div class="section-title">Résultats par catégorie</div>
  <div class="category-grid">
    ${Object.entries(cats).map(([cat, d]) => renderCatCard(cat, d)).join('')}
  </div>` : ''}

  ${findings.length ? `
  <div class="section-title">Répartition par criticité</div>
  ${renderSevChart(sev)}` : ''}

  <div class="section-title">Constats (${findings.length})</div>
  ${!findings.length
    ? '<p class="empty-state">Aucune vulnérabilité détectée.</p>'
    : findings.map(f => renderFinding(f)).join('')}

  ${recs.length ? `
  <div class="section-title">Plan de remédiation</div>
  ${recs.map(rec => `
  <div class="rec-card" style="border-left-color:var(--sev-${severityClass(rec.priority)})">
    <div class="rec-priority">${escHtml(rec.priority)}</div>
    <div class="rec-finding">${escHtml(rec.related_finding)}</div>
    <div class="rec-action">${escHtml(rec.action)}</div>
  </div>`).join('')}` : ''}

  ${r.error ? `<div class="section-title">Erreur</div><div class="evidence-block">${escHtml(r.error)}</div>` : ''}

  <div class="disclaimer">${escHtml(r.report_metadata?.disclaimer||'')}</div>`;
}

function severityCard(r) {
  const m = {critical:'stat--critical',high:'stat--high',medium:'stat--medium',none:'stat--safe'};
  return m[(r||'').toLowerCase()] || '';
}

function renderCatCard(cat, data) {
  const sev  = data.severity || {};
  const cnt  = data.count || 0;
  const top  = ['critical','high','medium','low','info'].find(l => (sev[l]||0) > 0) || 'info';
  const pills = ['critical','high','medium','low','info']
    .filter(l => (sev[l]||0) > 0)
    .map(l => `<span class="cat-sev-pill cat-sev--${l}">${sev[l]} ${l}</span>`)
    .join('');
  return `
  <div class="category-card category-card--${top}">
    <div class="category-card-title">${escHtml(cat)}</div>
    <div class="category-card-count">${cnt} finding${cnt > 1 ? 's' : ''}</div>
    <div class="category-sev-pills">${pills}</div>
  </div>`;
}

function renderSevChart(sev) {
  const levels = ['critical','high','medium','low','info'];
  const max = Math.max(...levels.map(l => sev[l] || 0), 1);
  return `<div class="sev-bar-chart">
    ${levels.map(l => {
      const cnt = sev[l] || 0;
      return `<div class="sev-bar-row sev--${l}">
        <div class="sev-bar-label">${l}</div>
        <div class="sev-bar-track"><div class="sev-bar-fill" style="width:${Math.round((cnt/max)*100)}%"></div></div>
        <div class="sev-bar-count">${cnt}</div>
      </div>`;
    }).join('')}
  </div>`;
}

function renderFinding(f) {
  const ev = f.evidence || '';
  const snippets = typeof ev === 'string' && ev ? [ev] : (Array.isArray(ev?.snippets) ? ev.snippets : []);
  return `
  <div class="finding-card">
    <div class="finding-header">
      <span class="badge badge--${severityClass(f.severity)}">${escHtml((f.severity||'info').toUpperCase())}</span>
      <span class="finding-title">${escHtml(f.description || f.name || f.type || '—')}</span>
      <span class="finding-chevron">▶</span>
    </div>
    <div class="finding-body">
      <dl>
        ${f.category ? `<dt>Catégorie</dt><dd>${escHtml(f.category)}</dd>` : ''}
        ${f.confidence ? `<dt>Confiance</dt><dd><span class="badge badge--${severityClass(f.severity)}" style="opacity:.8">${escHtml(f.confidence)}</span></dd>` : ''}
        <dt>Localisation</dt><dd class="mono" style="font-size:12px">${escHtml(f.location||'—')}</dd>
        <dt>Impact</dt><dd>${escHtml(f.impact||'—')}</dd>
        <dt>Recommandation</dt><dd>${escHtml(f.recommendation||'—')}</dd>
        ${snippets.length ? `<dt>Preuve technique</dt><dd><div class="evidence-block">${snippets.map(s => escHtml(s)).join('\n')}</div></dd>` : ''}
      </dl>
    </div>
  </div>`;
}

/* ── Export JSON ─────────────────────────────────────────────── */
function exportReport() {
  if (!_currentReport) return;
  const blob = new Blob([JSON.stringify(_currentReport, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `audit-${_currentReport.scan_id}-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Bootstrap ───────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  checkHealth();
  setInterval(checkHealth, 30_000);

  addUrlRow();
  $('#btn-add-url').addEventListener('click', () => addUrlRow());
  $('#btn-start').addEventListener('click', startScan);
  $('#btn-refresh').addEventListener('click', loadReports);
  $('#btn-export').addEventListener('click', exportReport);
  $('#btn-close-modal').addEventListener('click', () => {
    $('#modal-overlay').style.display = 'none';
    _currentReport = null;
  });
  $('#modal-overlay').addEventListener('click', e => {
    if (e.target === $('#modal-overlay')) {
      $('#modal-overlay').style.display = 'none';
      _currentReport = null;
    }
  });

  $('#btn-close-viewer').addEventListener('click', () => {
    $('#section-viewer').style.display = 'none';
    _viewer.scanId = null;
  });

  initDropZone();
  loadReports();
});
