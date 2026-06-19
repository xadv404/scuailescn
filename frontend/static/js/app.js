/* ═══════════════════════════════════════════════════════════════
   SQL Audit Scanner – Frontend Application
══════════════════════════════════════════════════════════════ */
'use strict';

const API = '';          // same origin
const POLL_MS = 3000;    // status poll interval

/* ── Utility ──────────────────────────────────────────────────── */
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

async function apiFetch(path, options = {}) {
  const r = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { const e = await r.json(); msg = e.detail?.validation_errors?.join('\n') || JSON.stringify(e.detail) || msg; }
    catch (_) {}
    throw new Error(msg);
  }
  return r.json();
}

function toast(message, type = 'info', duration = 4000) {
  const el = document.createElement('div');
  el.className = `toast toast--${type}`;
  el.textContent = message;
  $('#toast-container').appendChild(el);
  setTimeout(() => el.remove(), duration);
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('fr-FR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function fmtDuration(secs) {
  if (secs == null) return '—';
  const m = Math.floor(secs / 60), s = Math.round(secs % 60);
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function severityClass(sev) {
  const map = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info', none: 'none' };
  return map[(sev || 'none').toLowerCase()] || 'none';
}

function truncate(str, n = 60) {
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

/* ── Clock ─────────────────────────────────────────────────────── */
function startClock() {
  const el = $('#header-clock');
  if (!el) return;
  const tick = () => {
    el.textContent = new Date().toLocaleTimeString('fr-FR');
  };
  tick();
  setInterval(tick, 1000);
}

/* ── SQLMap health check ───────────────────────────────────────── */
async function checkHealth() {
  const pill  = $('#sqlmap-pill');
  const label = $('#sqlmap-label');
  try {
    const data = await apiFetch('/api/health');
    if (data.sqlmap_available) {
      pill.className  = 'pill pill--ok';
      label.textContent = 'SQLMap disponible';
    } else {
      pill.className  = 'pill pill--err';
      label.textContent = 'SQLMap introuvable';
    }
  } catch (_) {
    pill.className  = 'pill pill--err';
    label.textContent = 'API hors ligne';
  }
}

/* ── URL inputs ─────────────────────────────────────────────────── */
let urlCount = 0;

function addUrlRow(value = '') {
  urlCount++;
  const id = `url-${urlCount}`;
  const row = document.createElement('div');
  row.className = 'url-row';
  row.id = id;
  row.innerHTML = `
    <input class="url-input" type="url" placeholder="https://exemple.com/page?id=1"
           value="${escHtml(value)}" autocomplete="off" spellcheck="false" />
    <button class="url-remove" title="Supprimer" data-row="${id}">×</button>`;
  $('#url-container').appendChild(row);

  row.querySelector('.url-remove').addEventListener('click', () => {
    if ($$('.url-row').length > 1) row.remove();
  });
}

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function getUrls() {
  return $$('.url-input').map(i => i.value.trim()).filter(Boolean);
}

function clearUrlErrors() {
  $$('.url-input').forEach(i => i.classList.remove('is-invalid'));
}

/* ── Active scans ───────────────────────────────────────────────── */
const activePolls = new Map(); // scan_id → intervalId

function progressPercent(status, progress) {
  if (status === 'completed' || status === 'failed') return 100;
  if (progress?.includes('Initialising')) return 15;
  if (progress?.includes('Running'))      return 40;
  if (progress?.includes('Analys'))       return 75;
  if (progress?.includes('Generating'))   return 90;
  return 10;
}

function renderScanCard(data) {
  const { scan_id, status, progress, url, error, summary } = data;
  const pct = progressPercent(status, progress);
  const barColor = status === 'failed' ? 'var(--red)'
                 : status === 'completed' ? 'var(--green)'
                 : 'linear-gradient(90deg,var(--accent),#58a6ff)';

  let rightContent = '';
  if (status === 'running' || status === 'pending') {
    rightContent = `<span class="spinner"></span>`;
  } else if (status === 'completed' && summary) {
    const risk = (summary.risk_level || 'NONE').toLowerCase();
    rightContent = `<span class="badge badge--${severityClass(risk)}">${summary.risk_level}</span>`;
  } else if (status === 'failed') {
    rightContent = `<span class="badge badge--critical">ÉCHEC</span>`;
  }

  return `
  <div class="scan-card scan-card--${status}" id="scan-${scan_id}">
    <div class="scan-card-header">
      <span class="scan-url" title="${escHtml(url || '')}">${escHtml(truncate(url || '—', 55))}</span>
      <span class="scan-id-tag">#${scan_id}</span>
      ${rightContent}
    </div>
    <div class="progress-bar-wrap">
      <div class="progress-bar" style="width:${pct}%;background:${barColor}"></div>
    </div>
    <div class="progress-label">
      <span>${escHtml(status === 'failed' ? (error || 'Erreur inconnue') : (progress || status))}</span>
      <span>${pct}%</span>
    </div>
    ${status === 'completed' ? `
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn btn--ghost btn--sm" onclick="openReport('${scan_id}')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        Voir le rapport
      </button>
      <button class="btn btn--danger btn--sm" onclick="removeScan('${scan_id}')">Supprimer</button>
    </div>` : ''}
  </div>`;
}

function upsertScanCard(data) {
  const existing = $(`#scan-${data.scan_id}`);
  const html = renderScanCard(data);
  if (existing) {
    existing.outerHTML = html;
  } else {
    const list = $('#active-list');
    list.insertAdjacentHTML('afterbegin', html);
  }
  $('#section-active').style.display = '';
}

async function pollScan(scan_id) {
  try {
    const data = await apiFetch(`/api/scan/${scan_id}/status`);
    upsertScanCard(data);

    if (data.status === 'completed' || data.status === 'failed') {
      clearInterval(activePolls.get(scan_id));
      activePolls.delete(scan_id);
      loadReports();

      if (data.status === 'completed') {
        const risk = data.summary?.risk_level || 'N/A';
        const vuln = data.summary?.vulnerable;
        toast(
          `Scan #${scan_id} terminé — Risque : ${risk}${vuln ? ' ⚠ Vulnérable' : ''}`,
          vuln ? 'error' : 'success'
        );
      } else {
        toast(`Scan #${scan_id} a échoué`, 'error');
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
    if (!$('#active-list').children.length) {
      $('#section-active').style.display = 'none';
    }
    loadReports();
    toast('Scan supprimé', 'info');
  } catch (err) {
    toast('Erreur lors de la suppression : ' + err.message, 'error');
  }
}

/* ── Start scan ─────────────────────────────────────────────────── */
async function startScan() {
  clearUrlErrors();
  const urls = getUrls();

  if (!urls.length) {
    toast('Veuillez saisir au moins une URL.', 'error');
    $$('.url-input')[0]?.focus();
    return;
  }

  // Basic client-side URL validation
  let hasError = false;
  $$('.url-input').forEach(input => {
    const v = input.value.trim();
    if (v && !/^https?:\/\/.+/.test(v)) {
      input.classList.add('is-invalid');
      hasError = true;
    }
  });
  if (hasError) {
    toast("Une ou plusieurs URLs sont invalides (http/https requis).", 'error');
    return;
  }

  const btn = $('#btn-start');
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Lancement…`;

  try {
    const result = await apiFetch('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify({ urls }),
    });

    toast(`${result.queued} scan(s) lancé(s)`, 'success');
    result.scan_ids.forEach(id => startPolling(id));
  } catch (err) {
    toast('Erreur : ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Lancer le scan`;
  }
}

/* ── Reports list ───────────────────────────────────────────────── */
async function loadReports() {
  const container = $('#reports-list');
  try {
    const reports = await apiFetch('/api/reports');
    if (!reports.length) {
      container.innerHTML = '<p class="empty-state">Aucun rapport disponible.</p>';
      return;
    }
    container.innerHTML = `
    <table class="report-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Cible</th>
          <th>Date</th>
          <th>Risque</th>
          <th>Statut</th>
          <th style="text-align:right">Actions</th>
        </tr>
      </thead>
      <tbody>
        ${reports.map(r => `
        <tr>
          <td>${escHtml(r.scan_id || '—')}</td>
          <td class="target-cell" title="${escHtml(r.target || '')}">${escHtml(truncate(r.target || '—', 45))}</td>
          <td>${fmtDate(r.date)}</td>
          <td><span class="badge badge--${severityClass((r.risk_level||'none').toLowerCase())}">${escHtml(r.risk_level || 'N/A')}</span></td>
          <td><span class="badge badge--status-${r.status}">${escHtml(r.status || '—')}</span></td>
          <td class="actions-cell">
            <button class="btn btn--ghost btn--sm" onclick="openReport('${r.scan_id}')">Rapport</button>
            <button class="btn btn--danger btn--sm" onclick="removeScan('${r.scan_id}')">×</button>
          </td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  } catch (err) {
    container.innerHTML = `<p class="empty-state">Erreur de chargement : ${escHtml(err.message)}</p>`;
  }
}

/* ── Report modal ───────────────────────────────────────────────── */
let _currentReport = null;

async function openReport(scan_id) {
  const overlay = $('#modal-overlay');
  const body    = $('#modal-body');
  body.innerHTML = '<p class="empty-state">Chargement…</p>';
  overlay.style.display = 'flex';

  try {
    const report = await apiFetch(`/api/scan/${scan_id}/report`);
    _currentReport = report;
    body.innerHTML = renderReport(report);
    $('#modal-title').textContent = `Rapport #${scan_id}`;

    // Collapsible findings
    $$('.finding-header', body).forEach(h => {
      h.addEventListener('click', () => h.closest('.finding-card').classList.toggle('is-open'));
    });
  } catch (err) {
    body.innerHTML = `<p class="empty-state" style="color:var(--red)">Erreur : ${escHtml(err.message)}</p>`;
  }
}

function renderReport(r) {
  const sum = r.summary || {};
  const sev = sum.severity_breakdown || {};
  const findings = r.findings || [];
  const vuln = sum.vulnerable;
  const risk = (sum.risk_level || 'NONE');

  return `
  <!-- Meta grid -->
  <div class="report-meta-grid">
    <div class="meta-block">
      <div class="label">Cible</div>
      <div class="value value--mono">${escHtml(truncate(r.target || '—', 40))}</div>
    </div>
    <div class="meta-block">
      <div class="label">Niveau de risque global</div>
      <div class="value"><span class="badge badge--${severityClass(risk.toLowerCase())}">${escHtml(risk)}</span></div>
    </div>
    <div class="meta-block">
      <div class="label">Vulnérable</div>
      <div class="value" style="color:${vuln ? 'var(--red)' : 'var(--green)'}">${vuln ? '⚠ Oui' : '✓ Non détecté'}</div>
    </div>
    <div class="meta-block">
      <div class="label">Durée</div>
      <div class="value">${fmtDuration(r.duration_seconds)}</div>
    </div>
    <div class="meta-block">
      <div class="label">Statut</div>
      <div class="value"><span class="badge badge--status-${r.status}">${escHtml(r.status)}</span></div>
    </div>
    <div class="meta-block">
      <div class="label">Date</div>
      <div class="value" style="font-size:13px">${fmtDate(r.date)}</div>
    </div>
    <div class="meta-block">
      <div class="label">Scan ID</div>
      <div class="value value--mono">${escHtml(r.scan_id)}</div>
    </div>
    <div class="meta-block">
      <div class="label">Résultats</div>
      <div class="value">${findings.length} trouvé(s)</div>
    </div>
  </div>

  <!-- Severity summary -->
  ${findings.length ? `
  <div class="section-title">Résumé par criticité</div>
  <div class="severity-bar">
    ${['critical','high','medium','low','info'].filter(s => sev[s] > 0).map(s => `
      <div class="severity-pill">
        <span class="badge badge--${s}">${s}</span>
        <span class="count">${sev[s]}</span>
      </div>`).join('')}
  </div>` : ''}

  <!-- Findings -->
  <div class="section-title">Constats (${findings.length})</div>
  ${findings.length === 0
    ? '<p class="empty-state">Aucune injection SQL détectée sur cette cible.</p>'
    : findings.map(f => renderFinding(f)).join('')}

  ${r.error ? `
  <div class="section-title">Erreur</div>
  <div class="evidence-block">${escHtml(r.error)}</div>` : ''}

  <!-- Disclaimer -->
  <div style="margin-top:28px;padding:14px 16px;background:rgba(139,148,158,.05);border:1px solid var(--border);border-radius:8px;font-size:11px;color:var(--text-muted);line-height:1.6">
    ${escHtml(r.report_metadata?.disclaimer || '')}
  </div>`;
}

function renderFinding(f) {
  const ev = f.evidence || {};
  const snippets = (ev.snippets || []).filter(Boolean);
  return `
  <div class="finding-card">
    <div class="finding-header">
      <span class="badge badge--${severityClass(f.severity)}">${escHtml((f.severity||'info').toUpperCase())}</span>
      <span class="finding-title">${escHtml(f.description || f.type)}</span>
      <span class="finding-chevron">▶</span>
    </div>
    <div class="finding-body">
      <dl>
        <dt>Type</dt>
        <dd>${escHtml(f.type || '—')}</dd>
        <dt>Localisation</dt>
        <dd><span style="font-family:var(--font-mono);font-size:12px">${escHtml(f.location || '—')}</span></dd>
        <dt>Description</dt>
        <dd>${escHtml(f.description || '—')}</dd>
        <dt>Impact potentiel</dt>
        <dd>${escHtml(f.impact || '—')}</dd>
        <dt>Recommandation</dt>
        <dd>${escHtml(f.recommendation || '—')}</dd>
        ${snippets.length ? `
        <dt>Preuve technique (extrait sanitisé)</dt>
        <dd>
          <div class="evidence-block">${snippets.map(s => escHtml(s)).join('\n')}</div>
          <span style="font-size:11px;color:var(--text-muted)">${ev.occurrences || 0} occurrence(s) détectée(s)</span>
        </dd>` : ''}
      </dl>
    </div>
  </div>`;
}

/* ── Export JSON ─────────────────────────────────────────────────── */
function exportReport() {
  if (!_currentReport) return;
  const json = JSON.stringify(_currentReport, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sql-audit-${_currentReport.scan_id}-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Rapport exporté', 'success');
}

/* ── Bootstrap ──────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  checkHealth();
  setInterval(checkHealth, 30_000);

  addUrlRow();

  $('#btn-add-url').addEventListener('click', () => addUrlRow());
  $('#btn-start').addEventListener('click', startScan);
  $('#btn-refresh-reports').addEventListener('click', loadReports);
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

  loadReports();
});

// Make functions accessible to inline onclick handlers
window.openReport   = openReport;
window.removeScan   = removeScan;
