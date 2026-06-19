/* ═══════════════════════════════════════════════════════════════
   SQL Audit Scanner v5 – Frontend Application
══════════════════════════════════════════════════════════════ */
'use strict';

const API     = '';
const POLL_MS = 3000;

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
    try {
      const e = await r.json();
      msg = e.detail?.validation_errors?.join('\n')
         || e.detail?.config_errors?.join('\n')
         || JSON.stringify(e.detail)
         || msg;
    } catch (_) {}
    throw new Error(msg);
  }
  return r.json();
}

function toast(message, type = 'info', duration = 4500) {
  const el = document.createElement('div');
  el.className = `toast toast--${type}`;
  el.textContent = message;
  $('#toast-container').appendChild(el);
  setTimeout(() => el.remove(), duration);
}

function escHtml(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function truncate(str, n = 60) {
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
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
  const map = { critical:'critical', high:'high', medium:'medium', low:'low', info:'info', none:'none' };
  return map[(sev || 'none').toLowerCase()] || 'none';
}

/* ── Clock ─────────────────────────────────────────────────────── */
function startClock() {
  const el = $('#header-clock');
  if (!el) return;
  const tick = () => el.textContent = new Date().toLocaleTimeString('fr-FR');
  tick();
  setInterval(tick, 1000);
}

/* ── Health check ──────────────────────────────────────────────── */
async function checkHealth() {
  const pill  = $('#sqlmap-pill');
  const label = $('#sqlmap-label');
  try {
    const data = await apiFetch('/api/health');
    if (data.sqlmap_available) {
      pill.className = 'pill pill--ok';
      label.textContent = 'SQLMap disponible';
    } else {
      pill.className = 'pill pill--err';
      label.textContent = 'SQLMap introuvable';
    }
  } catch (_) {
    pill.className = 'pill pill--err';
    label.textContent = 'API hors ligne';
  }
}

/* ── Secret field toggle ────────────────────────────────────────── */
function toggleSecret(id, btn) {
  const inp = document.getElementById(id);
  if (!inp) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.style.color = 'var(--accent)';
  } else {
    inp.type = 'password';
    btn.style.color = '';
  }
}
window.toggleSecret = toggleSecret;

/* ── Configuration panel ────────────────────────────────────────── */
async function loadDefaultConfig() {
  try {
    const cfg = await apiFetch('/api/config/defaults');
    applyConfigToForm(cfg);
  } catch (_) {}
}

function applyConfigToForm(cfg) {
  if (!cfg) return;
  if (cfg.user_agent) $('#cfg-user-agent').value = cfg.user_agent;
  if (cfg.cookies)    $('#cfg-cookies').value    = cfg.cookies;
  if (cfg.auth_bearer)$('#cfg-bearer').value     = cfg.auth_bearer;

  const hdrs = cfg.headers;
  if (hdrs && typeof hdrs === 'object' && Object.keys(hdrs).length) {
    $('#cfg-headers').value = Object.entries(hdrs).map(([k,v]) => `${k}: ${v}`).join('\n');
  }

  if (cfg.threads)    { $('#cfg-threads').value  = cfg.threads;  $('#cfg-threads-display').textContent  = cfg.threads; }
  if (cfg.timeout)    { $('#cfg-timeout').value  = cfg.timeout;  $('#cfg-timeout-display').textContent  = cfg.timeout; }
  if (cfg.level)      $('#cfg-level').value      = cfg.level;
  if (cfg.risk)       $('#cfg-risk').value        = cfg.risk;

  if (cfg.techniques) {
    const techs = String(cfg.techniques).toUpperCase();
    $$('.tech-cb').forEach(cb => { cb.checked = techs.includes(cb.value); });
  }
  if (cfg.test_forms != null) $('#cfg-forms').checked = !!cfg.test_forms;
  if (cfg.smart_mode != null) $('#cfg-smart').checked = !!cfg.smart_mode;
}

function getScanConfig() {
  const techniques = $$('.tech-cb').filter(cb => cb.checked).map(cb => cb.value).join('');
  const headersRaw = $('#cfg-headers').value.trim();
  const headersObj = {};
  if (headersRaw) {
    headersRaw.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        headersObj[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      }
    });
  }
  return {
    user_agent:  $('#cfg-user-agent').value.trim() || undefined,
    cookies:     $('#cfg-cookies').value.trim()    || undefined,
    auth_bearer: $('#cfg-bearer').value.trim()     || undefined,
    headers:     Object.keys(headersObj).length ? headersObj : undefined,
    threads:     parseInt($('#cfg-threads').value),
    timeout:     parseInt($('#cfg-timeout').value),
    level:       parseInt($('#cfg-level').value),
    risk:        parseInt($('#cfg-risk').value),
    techniques:  techniques || 'BEUSTQ',
    test_forms:  $('#cfg-forms').checked,
    smart_mode:  $('#cfg-smart').checked,
  };
}

function initConfigPanel() {
  const btn   = $('#btn-config-toggle');
  const panel = $('#config-panel');

  btn.addEventListener('click', () => {
    const open = panel.classList.toggle('is-open');
    btn.setAttribute('aria-expanded', String(open));
    panel.setAttribute('aria-hidden', String(!open));
  });

  $('#btn-config-reset').addEventListener('click', () => {
    loadDefaultConfig();
    toast('Configuration réinitialisée', 'info');
  });
}

/* ── URL inputs ─────────────────────────────────────────────────── */
let urlCount = 0;

function addUrlRow(value = '') {
  urlCount++;
  const id  = `url-${urlCount}`;
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

function getUrls() {
  return $$('.url-input').map(i => i.value.trim()).filter(Boolean);
}

function clearUrlErrors() {
  $$('.url-input').forEach(i => i.classList.remove('is-invalid'));
}

/* ── Active scans ───────────────────────────────────────────────── */
const activePolls = new Map();

function progressPercent(status, progress, progress_pct) {
  if (progress_pct != null) return Math.min(100, Math.max(0, Math.round(progress_pct)));
  if (status === 'completed' || status === 'failed') return 100;
  if ((progress||'').includes('Initialisation')) return 5;
  if ((progress||'').includes('Modules passifs')) return 30;
  if ((progress||'').includes('SQLMap'))          return 55;
  if ((progress||'').includes('Analyse'))         return 80;
  if ((progress||'').includes('Génération'))      return 90;
  return 10;
}

function renderScanCard(data) {
  const { scan_id, status, progress, progress_pct, url, error, summary } = data;
  const pct = progressPercent(status, progress, progress_pct);
  const barBg = status === 'failed'    ? 'var(--red)'
              : status === 'completed' ? 'var(--green)'
              : 'linear-gradient(90deg,var(--accent),#58a6ff)';

  let rightBadge = '';
  if (status === 'running' || status === 'pending') {
    rightBadge = '<span class="spinner"></span>';
  } else if (status === 'completed' && summary) {
    const risk = (summary.risk_level || 'NONE').toLowerCase();
    rightBadge = `<span class="badge badge--${severityClass(risk)}">${escHtml(summary.risk_level)}</span>`;
  } else if (status === 'failed') {
    rightBadge = '<span class="badge badge--critical">ÉCHEC</span>';
  }

  const dbLine = summary?.database_type && summary.database_type !== 'Non détecté'
    ? `<span style="font-family:var(--font-mono);font-size:11px;color:var(--purple);margin-left:auto">${escHtml(summary.database_type)}</span>`
    : '';

  const scoreTag = summary?.risk_score != null && status === 'completed'
    ? `<span class="risk-score-tag" style="${riskScoreColor(summary.risk_score)}">Score: ${summary.risk_score}/100</span>`
    : '';

  return `
  <div class="scan-card scan-card--${status}" id="scan-${scan_id}">
    <div class="scan-card-header">
      <span class="scan-url" title="${escHtml(url||'')}">${escHtml(truncate(url||'—',55))}</span>
      <span class="scan-id-tag">#${escHtml(scan_id)}</span>
      ${dbLine}
      ${scoreTag}
      ${rightBadge}
    </div>
    <div class="progress-bar-wrap">
      <div class="progress-bar" style="width:${pct}%;background:${barBg}"></div>
    </div>
    <div class="progress-label">
      <span>${escHtml(status==='failed'?(error||'Erreur inconnue'):(progress||status))}</span>
      <span>${pct}%</span>
    </div>
    ${status === 'completed' ? `
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn btn--ghost btn--sm" onclick="openReport('${escHtml(scan_id)}')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        Voir le rapport
      </button>
      <button class="btn btn--danger btn--sm" onclick="removeScan('${escHtml(scan_id)}')">Supprimer</button>
    </div>` : ''}
  </div>`;
}

function riskScoreColor(score) {
  if (score >= 70) return 'color:var(--red)';
  if (score >= 40) return 'color:var(--orange)';
  if (score >= 15) return 'color:var(--yellow)';
  return 'color:var(--green)';
}

function upsertScanCard(data) {
  const existing = $(`#scan-${data.scan_id}`);
  const html = renderScanCard(data);
  if (existing) {
    existing.outerHTML = html;
  } else {
    $('#active-list').insertAdjacentHTML('afterbegin', html);
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
        const risk  = data.summary?.risk_level || 'N/A';
        const score = data.summary?.risk_score;
        const vuln  = data.summary?.vulnerable;
        const db    = data.summary?.database_type;
        toast(
          `Scan #${scan_id} terminé — Risque : ${risk}${score != null ? ` (${score}/100)` : ''}${db && db !== 'Non détecté' ? ' — ' + db : ''}${vuln ? ' ⚠' : ''}`,
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
    if (!$$('#active-list > *').length) $('#section-active').style.display = 'none';
    loadReports();
    toast('Scan supprimé', 'info');
  } catch (err) {
    toast('Erreur : ' + err.message, 'error');
  }
}

/* ── Scan type ─────────────────────────────────────────────────── */
function getScanType() {
  return document.querySelector('input[name="scan_type"]:checked')?.value || 'full_scan';
}

function initScanTypeCards() {
  document.querySelectorAll('input[name="scan_type"]').forEach(radio => {
    radio.addEventListener('change', () => {
      document.querySelectorAll('.scan-type-card').forEach(c => c.classList.remove('scan-type-card--active'));
      radio.closest('.scan-type-card')?.classList.add('scan-type-card--active');
    });
  });
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

  let hasError = false;
  $$('.url-input').forEach(input => {
    const v = input.value.trim();
    if (v && !/^https?:\/\/.+/.test(v)) {
      input.classList.add('is-invalid');
      hasError = true;
    }
  });
  if (hasError) {
    toast('URL(s) invalide(s) — http/https requis.', 'error');
    return;
  }

  const btn = $('#btn-start');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Lancement…';

  try {
    const scan_config = getScanConfig();
    const scan_type   = getScanType();
    const result = await apiFetch('/api/scan/start', {
      method: 'POST',
      body: JSON.stringify({ urls, scan_type, scan_config }),
    });
    const modeLabel = scan_type === 'deep_scan' ? 'Deep Scan' : 'Full Scan';
    toast(`${result.queued} scan(s) lancé(s) — mode ${modeLabel}`, 'success');
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
      <thead><tr>
        <th>ID</th><th>Cible</th><th>Date</th>
        <th>Moteur DB</th><th>Risque</th><th>Score</th><th>Statut</th>
        <th style="text-align:right">Actions</th>
      </tr></thead>
      <tbody>
        ${reports.map(r => `
        <tr>
          <td>${escHtml(r.scan_id||'—')}</td>
          <td class="target-cell" title="${escHtml(r.target||'')}">${escHtml(truncate(r.target||'—',40))}</td>
          <td>${fmtDate(r.date)}</td>
          <td class="db-cell">${escHtml(r.database_type||'—')}</td>
          <td><span class="badge badge--${severityClass((r.risk_level||'none').toLowerCase())}">${escHtml(r.risk_level||'N/A')}</span></td>
          <td><span style="${riskScoreColor(r.risk_score||0)};font-weight:600;font-size:12px">${r.risk_score != null ? r.risk_score+'/100' : '—'}</span></td>
          <td><span class="badge badge--status-${r.status}">${escHtml(r.status||'—')}</span></td>
          <td class="actions-cell">
            <button class="btn btn--ghost btn--sm" onclick="openReport('${escHtml(r.scan_id)}')">Rapport</button>
            <button class="btn btn--danger btn--sm" onclick="removeScan('${escHtml(r.scan_id)}')">×</button>
          </td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  } catch (err) {
    container.innerHTML = `<p class="empty-state">Erreur : ${escHtml(err.message)}</p>`;
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
    $$('.finding-header', body).forEach(h =>
      h.addEventListener('click', () => h.closest('.finding-card').classList.toggle('is-open'))
    );
  } catch (err) {
    body.innerHTML = `<p class="empty-state" style="color:var(--red)">Erreur : ${escHtml(err.message)}</p>`;
  }
}

/* ── Report renderer ────────────────────────────────────────────── */
function renderReport(r) {
  const ss         = r.scan_summary || r.summary || {};
  const sev        = ss.severity || ss.severity_breakdown || {};
  const findings   = r.findings  || [];
  const recs       = r.recommendations || [];
  const cfg        = r.scan_config || {};
  const risk       = ss.risk_level || 'NONE';
  const vuln       = ss.vulnerable;
  const dbType     = ss.database_type || 'Non détecté';
  const dbEngines  = ss.database_engines || {};
  const riskScore  = ss.risk_score ?? null;
  const categories = ss.categories || {};
  const techs      = ss.technologies || [];
  const phases     = ss.phases || [];
  const scanType   = r.scan_type || 'full_scan';

  return `
  <!-- ── Dashboard stats ────────────────────────────────────── -->
  <div class="dashboard-stats">
    <div class="stat-card ${vuln ? 'stat--critical' : 'stat--safe'}">
      <div class="stat-value">${vuln ? '⚠' : '✓'}</div>
      <div class="stat-label">${vuln ? 'Vulnérable' : 'Sain'}</div>
    </div>
    <div class="stat-card ${severityCard(risk)}">
      <div class="stat-value">${escHtml(risk)}</div>
      <div class="stat-label">Risque global</div>
    </div>
    ${riskScore != null ? `
    <div class="stat-card">
      <div class="stat-value risk-score-gauge" style="${riskScoreColor(riskScore)}">${riskScore}<span style="font-size:14px;font-weight:400;opacity:.7">/100</span></div>
      <div class="stat-label">Score de risque</div>
      <div class="risk-bar-track"><div class="risk-bar-fill" style="width:${riskScore}%;background:${riskScoreBg(riskScore)}"></div></div>
    </div>` : ''}
    <div class="stat-card">
      <div class="stat-value" style="color:var(--accent)">${findings.length}</div>
      <div class="stat-label">Findings</div>
    </div>
    <div class="stat-card stat--db">
      <div class="stat-value">${escHtml(dbType)}</div>
      <div class="stat-label">Moteur SQL</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" style="color:var(--text-secondary)">${escHtml(fmtDuration(r.duration_seconds))}</div>
      <div class="stat-label">Durée</div>
    </div>
  </div>

  <!-- ── Meta grid ──────────────────────────────────────────── -->
  <div class="report-meta-grid">
    <div class="meta-block"><div class="label">Cible</div><div class="value value--mono">${escHtml(truncate(r.target||'—',48))}</div></div>
    <div class="meta-block"><div class="label">Scan ID</div><div class="value value--mono">${escHtml(r.scan_id||'—')}</div></div>
    <div class="meta-block"><div class="label">Statut</div><div class="value"><span class="badge badge--status-${r.status}">${escHtml(r.status)}</span></div></div>
    <div class="meta-block"><div class="label">Mode</div><div class="value"><span class="badge badge--mode">${scanType === 'deep_scan' ? 'Deep Scan' : 'Full Scan'}</span></div></div>
    <div class="meta-block"><div class="label">Date début</div><div class="value" style="font-size:12px">${fmtDate(r.date)}</div></div>
    <div class="meta-block"><div class="label">Date fin</div><div class="value" style="font-size:12px">${fmtDate(r.end_date)}</div></div>
  </div>

  <!-- ── Pipeline phases ────────────────────────────────────── -->
  ${phases.length ? `
  <div class="section-title">Phases d'exécution</div>
  <div class="phases-grid">
    ${phases.map((p, i) => `
    <div class="phase-card">
      <div class="phase-num">${i + 1}</div>
      <div class="phase-info">
        <div class="phase-name">${escHtml(p.name)}</div>
        <div class="phase-modules">${(p.modules||[]).map(m => `<code>${escHtml(m)}</code>`).join(' ')}</div>
      </div>
      <div class="phase-stats">
        <span class="phase-findings">${p.findings} résultat${p.findings!==1?'s':''}</span>
        <span class="phase-dur">${p.duration_s}s</span>
      </div>
    </div>`).join('')}
  </div>` : ''}

  <!-- ── Technologies detected ─────────────────────────────── -->
  ${techs.length ? `
  <div class="section-title">Technologies détectées</div>
  <div class="tech-chips">
    ${techs.map(t => `<span class="tech-chip">${escHtml(t)}</span>`).join('')}
  </div>` : ''}

  <!-- ── Category breakdown ─────────────────────────────────── -->
  ${Object.keys(categories).length ? `
  <div class="section-title">Résultats par catégorie</div>
  <div class="category-grid">
    ${Object.entries(categories).map(([cat, data]) => renderCategoryCard(cat, data)).join('')}
  </div>` : ''}

  <!-- ── Severity bar chart ─────────────────────────────────── -->
  ${findings.length ? `
  <div class="section-title">Répartition par criticité</div>
  ${renderSevChart(sev)}` : ''}

  <!-- ── DB engine breakdown ────────────────────────────────── -->
  ${Object.keys(dbEngines).length ? `
  <div class="section-title">Moteurs SQL détectés</div>
  <div class="db-engine-grid">
    ${Object.entries(dbEngines).map(([db, cnt]) => `
    <div class="db-engine-chip">
      <span class="db-name">${escHtml(db)}</span>
      <span class="db-count">${cnt}</span>
    </div>`).join('')}
  </div>` : ''}

  <!-- ── Findings ───────────────────────────────────────────── -->
  <div class="section-title">Constats (${findings.length})</div>
  ${findings.length === 0
    ? '<p class="empty-state">Aucune vulnérabilité détectée sur cette cible.</p>'
    : findings.map(f => renderFinding(f)).join('')}

  <!-- ── Recommendations ────────────────────────────────────── -->
  ${recs.length ? `
  <div class="section-title">Plan de remédiation (${recs.length} action${recs.length>1?'s':''})</div>
  ${recs.map(rec => `
  <div class="rec-card" style="border-left-color:var(--sev-${severityClass(rec.priority)})">
    <div class="rec-priority">${escHtml(rec.priority)}</div>
    <div class="rec-finding">${escHtml(rec.related_finding)}</div>
    <div class="rec-action">${escHtml(rec.action)}</div>
  </div>`).join('')}` : ''}

  <!-- ── Scan configuration used ────────────────────────────── -->
  ${Object.keys(cfg).length ? `
  <div class="section-title">Configuration utilisée</div>
  <div class="config-summary-grid">
    ${Object.entries(cfg).filter(([,v]) => v !== undefined && v !== '' && v !== null).map(([k, v]) => `
    <div class="cfg-item">
      <div class="cfg-key">${escHtml(k)}</div>
      <div class="cfg-val">${escHtml(typeof v === 'object' ? JSON.stringify(v) : String(v))}</div>
    </div>`).join('')}
  </div>` : ''}

  <!-- ── Error ──────────────────────────────────────────────── -->
  ${r.error ? `<div class="section-title">Erreur</div><div class="evidence-block">${escHtml(r.error)}</div>` : ''}

  <!-- ── Disclaimer ─────────────────────────────────────────── -->
  <div style="margin-top:28px;padding:12px 16px;background:rgba(139,148,158,.04);border:1px solid var(--border);border-radius:8px;font-size:11px;color:var(--text-muted);line-height:1.7">
    ${escHtml(r.report_metadata?.disclaimer||'')}
  </div>`;
}

function severityCard(risk) {
  const r = (risk||'').toLowerCase();
  if (r === 'critical') return 'stat--critical';
  if (r === 'high')     return 'stat--high';
  if (r === 'medium')   return 'stat--medium';
  if (r === 'none')     return 'stat--safe';
  return '';
}

function riskScoreBg(score) {
  if (score >= 70) return 'var(--red)';
  if (score >= 40) return 'var(--orange)';
  if (score >= 15) return 'var(--yellow)';
  return 'var(--green)';
}

function renderCategoryCard(cat, data) {
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
    <div class="category-sev-pills">${pills || '<span class="cat-sev-pill cat-sev--info">0 finding</span>'}</div>
  </div>`;
}

function renderSevChart(sev) {
  const levels = ['critical','high','medium','low','info'];
  const max    = Math.max(...levels.map(l => sev[l] || 0), 1);
  return `
  <div class="sev-bar-chart">
    ${levels.map(l => {
      const cnt = sev[l] || 0;
      const pct = Math.round((cnt / max) * 100);
      return `
      <div class="sev-bar-row sev--${l}">
        <div class="sev-bar-label">${l}</div>
        <div class="sev-bar-track"><div class="sev-bar-fill" style="width:${pct}%"></div></div>
        <div class="sev-bar-count">${cnt}</div>
      </div>`;
    }).join('')}
  </div>`;
}

function renderFinding(f) {
  const ev       = f.evidence || {};
  // evidence may be a string (passive) or object (sqlmap)
  const snippets = typeof ev === 'object' && ev.snippets
    ? (ev.snippets || []).filter(Boolean)
    : (typeof ev === 'string' && ev ? [ev] : []);
  const occurrences = typeof ev === 'object' ? (ev.occurrences || 0) : 0;
  const confidence  = f.confidence ? `<dt>Confiance</dt><dd><span class="badge badge--${severityClass(f.severity)}" style="opacity:.8">${escHtml(f.confidence)}</span></dd>` : '';
  const category    = f.category   ? `<dt>Catégorie</dt><dd>${escHtml(f.category)}</dd>` : '';

  return `
  <div class="finding-card">
    <div class="finding-header">
      <span class="badge badge--${severityClass(f.severity)}">${escHtml((f.severity||'info').toUpperCase())}</span>
      <span class="finding-title">${escHtml(f.description || f.type)}</span>
      <span class="finding-chevron">▶</span>
    </div>
    <div class="finding-body">
      <dl>
        <dt>Type</dt><dd>${escHtml(f.type||'—')}</dd>
        ${category}
        ${confidence}
        <dt>Localisation</dt>
        <dd><span style="font-family:var(--font-mono);font-size:12px">${escHtml(f.location||'—')}</span></dd>
        <dt>Description</dt><dd>${escHtml(f.description||'—')}</dd>
        <dt>Impact potentiel</dt><dd>${escHtml(f.impact||'—')}</dd>
        <dt>Recommandation</dt><dd>${escHtml(f.recommendation||'—')}</dd>
        ${snippets.length ? `
        <dt>Preuve technique (extrait sanitisé)</dt>
        <dd>
          <div class="evidence-block">${snippets.map(s => escHtml(s)).join('\n')}</div>
          ${occurrences ? `<span style="font-size:11px;color:var(--text-muted)">${occurrences} occurrence(s)</span>` : ''}
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
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `sql-audit-${_currentReport.scan_id}-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Rapport exporté en JSON', 'success');
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

  initConfigPanel();
  initScanTypeCards();
  loadDefaultConfig();

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

window.openReport  = openReport;
window.removeScan  = removeScan;
