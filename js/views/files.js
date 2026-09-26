/** M2 — File & Folder Eraser: choose targets → analyze storage → erase → report. */
import { api, apiUrl, badge, bytes, confirmDanger, esc, getOperator, icon, pickPaths, progressBlock,
  reportError, requireOperator, statusBadge, toast, waitForJob } from '../core.js';

const S = { paths: [], analysis: null, analyzing: false, method: 'dod', clean: true, approver: '', job: null, report: null };
let root, appRef;

const METHODS = [
  { id: 'zero', label: 'Zeros', passes: 1 },
  { id: 'random', label: 'Random', passes: 1 },
  { id: 'dod', label: 'DoD 3-pass', passes: 3 },
];

export async function show(el, _params, app) {
  root = el;
  appRef = app;
  render();
}

function assuranceTone(level) {
  return { High: 'ok', Limited: 'warn', 'Not effective': 'bad' }[level] || 'warn';
}

function render() {
  const a = S.analysis;
  const blocked = a?.blocked?.length;
  const running = S.job && S.job.status === 'RUNNING';
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">File & Folder Eraser <span class="code-tag">M2</span></h1>
        <p class="page-desc">Erase selected files and folders together with their metadata and the traces the operating system keeps about them. WipeX tells you honestly how much assurance an overwrite gives on each drive.</p>
      </div>
    </div>
    <div class="grid cols-side">
      <div class="stack">
        <div class="card">
          <div class="card-head">
            <div><div class="card-title">1 · Targets</div><div class="card-sub">Files and folders to erase. System locations are protected.</div></div>
            <div class="row">
              <button class="btn btn-secondary btn-sm" id="fe-sandbox" title="Create disposable sample files inside the WipeX workspace">${icon('plus', 14)} Sample files</button>
              <button class="btn btn-primary btn-sm" id="fe-add">${icon('folder', 14)} Add files or folders</button>
            </div>
          </div>
          <div class="card-body">
            ${S.paths.length ? `<div class="path-list">${S.paths.map((p, i) => `
              <div class="path-item">${icon('file', 15)}<span class="p" title="${esc(p)}">${esc(p)}</span>
              <button class="btn btn-ghost btn-sm" data-rm="${i}" title="Remove">${icon('x', 14)}</button></div>`).join('')}</div>`
            : `<div class="empty"><strong>No targets yet</strong>Add files or folders, or create sample files to try the eraser safely.</div>`}
            <div class="row" style="margin-top:12px">
              <input class="input mono" id="fe-path" placeholder="…or paste a full path and press Enter" style="flex:1">
              <button class="btn btn-secondary" id="fe-analyze" ${S.paths.length && !S.analyzing ? '' : 'disabled'}>${icon('search', 15)} ${S.analyzing ? 'Analyzing…' : 'Analyze'}</button>
            </div>
          </div>
        </div>

        ${a ? analysisCard(a) : ''}
        ${S.job ? jobCard() : ''}
      </div>

      <div class="stack">
        <div class="card">
          <div class="card-head"><span class="card-title">2 · Options</span></div>
          <div class="card-body stack" style="gap:14px">
            <div class="field"><span class="label">Overwrite pattern</span>
              <div class="seg">${METHODS.map(m => `<button data-m="${m.id}" class="${S.method === m.id ? 'on' : ''}">${m.label}</button>`).join('')}</div>
              <span class="hint">${S.method === 'dod' ? 'Zeros, ones, random — three passes with fsync after each.' : 'Single pass with fsync. On flash storage one pass is as effective as many.'}</span></div>
            <label class="check"><input type="checkbox" id="fe-clean" ${S.clean ? 'checked' : ''}>
              <span>Remove OS traces<span class="hint">Recent Items shortcuts (Windows), recently-used entries and thumbnails (Linux). Shared databases such as Jump Lists are reported, not modified.</span></span></label>
            <div class="field"><label for="fe-approver">Approver ${appRef.health?.dualApproval ? '(required)' : '(optional)'}</label>
              <input class="input" id="fe-approver" value="${esc(S.approver)}" placeholder="Second person confirming"></div>
          </div>
          <div class="card-foot">
            <button class="btn btn-danger" id="fe-erase" ${a && !blocked && !running && S.paths.length ? '' : 'disabled'}>Erase ${a ? `${a.items.reduce((n, i) => n + (i.fileCount || 0), 0)} file(s)` : ''}</button>
          </div>
        </div>
        <div class="card card-pad">
          <div class="card-title" style="margin-bottom:8px">What WipeX does to each file</div>
          <ol class="module-feats" style="padding-left:18px;gap:5px">
            <li>Overwrites alternate data streams (e.g. Zone.Identifier)</li>
            <li>Overwrites the content in place and flushes to disk</li>
            <li>Truncates, renames 3× with random names, resets timestamps</li>
            <li>Deletes the file; folders are removed bottom-up</li>
            <li>Removes traces and writes a signed audit entry</li>
          </ol>
        </div>
      </div>
    </div>`;

  root.querySelector('#fe-add').addEventListener('click', async () => {
    const picked = await pickPaths();
    if (picked?.length) { S.paths = [...new Set([...S.paths, ...picked])]; S.analysis = null; render(); }
  });
  root.querySelector('#fe-sandbox').addEventListener('click', createSandbox);
  root.querySelector('#fe-path').addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.value.trim()) { S.paths = [...new Set([...S.paths, e.target.value.trim()])]; S.analysis = null; render(); }
  });
  root.querySelectorAll('[data-rm]').forEach(b => b.addEventListener('click', () => { S.paths.splice(+b.dataset.rm, 1); S.analysis = null; render(); }));
  root.querySelector('#fe-analyze').addEventListener('click', analyze);
  root.querySelectorAll('[data-m]').forEach(b => b.addEventListener('click', () => { S.method = b.dataset.m; render(); }));
  root.querySelector('#fe-clean').addEventListener('change', e => { S.clean = e.target.checked; });
  root.querySelector('#fe-approver').addEventListener('input', e => { S.approver = e.target.value; });
  root.querySelector('#fe-erase').addEventListener('click', erase);
}

function analysisCard(a) {
  const t = a.traces || {};
  const traceRows = [
    ...(t.recentShortcuts || []).map(x => [x.path, 'Recent Items shortcut', 'Will be erased']),
    ...(t.jumpLists || []).map(x => [x.path, 'Jump List', 'Reported only']),
    ...(t.thumbnails || []).map(x => [x.path, 'Thumbnail', x.action === 'delete' ? 'Will be erased' : 'Reported only']),
    ...(t.recentlyUsed || []).map(x => [x.path, 'Recently-used entry', 'Entry will be removed']),
  ];
  return `
    <div class="card">
      <div class="card-head"><div><div class="card-title">Storage assessment</div><div class="card-sub">How much an in-place overwrite can guarantee on each volume</div></div></div>
      <div class="card-body stack">
        ${a.volumes.map(v => `
          <div class="notice ${assuranceTone(v.assurance)}">${icon(v.assurance === 'High' ? 'check' : 'alert', 18)}
            <div><strong>${esc(v.volume)} · ${esc(v.fileSystem)} on ${esc(v.mediaType)}${v.busType ? ` (${esc(v.busType)})` : ''} — assurance: ${esc(v.assurance)}</strong>
            ${esc(v.advice)}${v.notes?.length ? `<ul style="margin:6px 0 0;padding-left:18px">${v.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
            ${v.assurance !== 'High' ? '<div style="margin-top:8px"><a class="btn btn-secondary btn-sm" href="#/drive">Use Drive Eraser (M1) instead</a></div>' : ''}</div>
          </div>`).join('')}
        <div class="table-wrap" style="border:1px solid var(--border);border-radius:6px"><table class="table">
          <thead><tr><th>Target</th><th class="num">Files</th><th class="num">Size</th><th class="num">Streams</th><th>Status</th></tr></thead>
          <tbody>${a.items.map(i => `<tr>
            <td class="trunc mono" title="${esc(i.path)}">${esc(i.path)}</td>
            <td class="num">${i.fileCount ?? '—'}</td><td class="num">${i.exists ? bytes(i.bytes) : '—'}</td><td class="num">${i.streams ?? '—'}</td>
            <td>${!i.exists ? badge('Not found', 'bad') : i.blocked ? `<span title="${esc(i.blocked)}">${badge('Blocked', 'bad')}</span>` : badge('Ready', 'ok')}</td></tr>`).join('')}</tbody></table></div>
        ${a.blocked.length ? `<div class="notice bad">${icon('lock', 16)}<div><strong>Some targets are blocked</strong>${a.items.filter(i => i.blocked).map(i => esc(i.blocked)).join('<br>')}</div></div>` : ''}
        <div>
          <div class="label" style="margin-bottom:6px">Traces found (${t.total || 0})</div>
          ${traceRows.length ? `<div class="table-wrap" style="border:1px solid var(--border);border-radius:6px"><table class="table"><tbody>
            ${traceRows.map(r => `<tr><td class="trunc mono" title="${esc(r[0])}">${esc(r[0])}</td><td class="nowrap">${esc(r[1])}</td><td class="nowrap">${badge(r[2], r[2].startsWith('Will') || r[2].startsWith('Entry') ? 'info' : '')}</td></tr>`).join('')}
          </tbody></table></div>` : '<div class="muted small">No shortcuts, jump lists or thumbnails reference these files.</div>'}
        </div>
      </div>
    </div>`;
}

function jobCard() {
  const j = S.job;
  if (j.status === 'RUNNING') {
    return `<div class="card card-pad"><div class="card-title" style="margin-bottom:10px">Erasing…</div>${progressBlock(j.progress, j.message)}</div>`;
  }
  if (j.status === 'FAILED') {
    return `<div class="verdict bad"><span class="verdict-icon">${icon('x', 22, 2.6)}</span><div><div class="verdict-title">Erasure failed</div><div class="verdict-text">${esc(j.message)}</div></div></div>`;
  }
  const r = j.result;
  return `
    <div class="card">
      <div class="card-head"><div><div class="card-title">Report</div><div class="card-sub mono">${esc(r.jobId)}</div></div>
        <a class="btn btn-primary btn-sm" href="${apiUrl(`/api/files/report/${j.id}.pdf`)}" target="_blank" rel="noopener">${icon('download', 14)} PDF report</a></div>
      <div class="card-body stack">
        <div class="verdict ${r.verdict === 'PASS' ? '' : 'warn'}"><span class="verdict-icon">${icon(r.verdict === 'PASS' ? 'check' : 'alert', 22, 2.6)}</span>
          <div><div class="verdict-title">${r.verdict === 'PASS' ? 'All targets erased' : 'Completed with failures'}</div><div class="verdict-text">${esc(r.summary)}</div></div></div>
        <div class="table-wrap" style="border:1px solid var(--border);border-radius:6px;max-height:280px;overflow:auto"><table class="table">
          <thead><tr><th>Original path</th><th class="num">Bytes</th><th>Streams</th><th>Removed</th></tr></thead>
          <tbody>${r.files.map(f => `<tr><td class="trunc mono" title="${esc(f.path)}">${esc(f.path)}</td><td class="num">${f.size.toLocaleString()}</td>
            <td>${f.streams.map(s => esc(s.name)).join(', ') || '—'}</td><td>${f.verified ? badge('Yes', 'ok') : badge('No', 'bad')}</td></tr>`).join('')}
            ${r.failures.map(f => `<tr><td class="trunc mono">${esc(f.path)}</td><td colspan="3">${badge('Failed', 'bad')} ${esc(f.error)}</td></tr>`).join('')}</tbody></table></div>
        ${r.traces.length ? `<div><div class="label" style="margin-bottom:6px">Trace cleanup</div>${r.traces.map(t => `<div class="small"><span class="mono">${esc(t.path)}</span> — ${esc(t.result)}</div>`).join('')}</div>` : ''}
      </div>
    </div>`;
}

async function createSandbox() {
  try {
    const sb = await api('/api/files/sandbox', { method: 'POST' });
    S.paths = [...new Set([...S.paths, sb.path])];
    S.analysis = null;
    render();
    toast(`Sample files created. ${sb.notes.join('. ')}`, 'ok');
    analyze();
  } catch (e) { reportError(e); }
}

async function analyze() {
  S.analyzing = true;
  render();
  try {
    S.analysis = await api('/api/files/analyze', { method: 'POST', body: { paths: S.paths } });
  } catch (e) { reportError(e); }
  S.analyzing = false;
  render();
}

async function erase() {
  const operator = await requireOperator();
  if (!operator) return;
  const a = S.analysis;
  const files = a.items.reduce((n, i) => n + (i.fileCount || 0), 0);
  const ok = await confirmDanger({
    title: `Erase ${files} file(s)?`,
    sub: 'The selected files and folders will be overwritten and deleted. This cannot be undone.',
    rows: [['Targets', `${S.paths.length} path(s)`], ['Size', bytes(a.items.reduce((n, i) => n + (i.bytes || 0), 0))],
           ['Pattern', METHODS.find(m => m.id === S.method).label], ['Remove traces', S.clean ? 'Yes' : 'No'],
           ['Assurance', a.volumes.map(v => `${esc(v.volume)} ${esc(v.assurance)}`).join(', ')], ['Operator', esc(operator)]],
  });
  if (!ok) return;
  try {
    const { jobId } = await api('/api/files/erase', { method: 'POST', body: { paths: S.paths, method: S.method, cleanTraces: S.clean, operator, approver: S.approver } });
    S.job = { id: jobId, status: 'RUNNING', progress: 0, message: 'Starting' };
    render();
    const job = await waitForJob(jobId, j => { S.job = j; if (root.classList.contains('active')) render(); });
    S.job = job;
    if (job.status === 'COMPLETED') { S.paths = []; S.analysis = null; toast('Erasure complete', 'ok'); }
    render();
  } catch (e) { reportError(e); }
}
