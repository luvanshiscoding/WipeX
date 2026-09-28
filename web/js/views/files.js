/** Erase selected files and folders: pick them in a file browser, remove the traces the system keeps, prove nothing is left. */
import { api, apiUrl, badge, bytes, confirmDanger, demo, esc, getOperator, icon, progressBlock,
  refreshDemo, reportError, toast, waitForJob } from '../core.js';
import { mountExplorer } from '../explorer.js';

const S = { selected: new Map(), analysis: null, analyzing: false, method: 'random', methodChosen: false, clean: true, journal: true, job: null, demo: null };
let root, appRef, xp = null;
const visible = () => root?.isConnected && root.closest('.view')?.classList.contains('active');
const paths = () => [...S.selected.keys()];

const METHODS = [
  { id: 'dod', label: '3 passes (zeros, ones, random)' },
  { id: 'random', label: '1 pass, random data' },
  { id: 'zero', label: '1 pass, zeros' },
];

const ASSURANCE = {
  High: ['ok', 'check', 'Overwritten data cannot be read back from this drive.'],
  Limited: ['warn', 'info', 'Flash or SSD: WipeX removes everything it can reach, but hidden spare blocks may keep old copies. For certainty, erase the whole drive.'],
  'Not effective': ['bad', 'alert', 'Copy-on-write file system: overwriting cannot reach the old data. Erase the whole drive instead.'],
};

export async function show(el, _params, app) {
  appRef = app;
  if (root !== el) xp = null;
  root = el;
  render();
}

const fileCount = (a) => a.items.reduce((n, i) => n + (i.fileCount || 0), 0);
const totalBytes = (a) => a.items.reduce((n, i) => n + (i.bytes || 0), 0);

function render() {
  if (S.demo !== demo.enabled) {             // switching demo mode starts a fresh selection
    if (S.demo !== null) { S.selected.clear(); S.analysis = null; }
    S.demo = demo.enabled;
    xp = null;
  }
  if (!xp || !root.querySelector('#fe-xp')) {
    root.innerHTML = `
      <div class="card xp-card">
        <div class="card-head"><div><div class="card-title">1 · ${demo.enabled ? 'Choose sample files' : 'Choose files and folders'}</div>
          <div class="card-sub">${demo.enabled ? 'Demo mode: only the sample files WipeX created are shown' : 'Tick what to erase · double-click a folder to open it · USB drives first'}</div></div></div>
        <div id="fe-xp"></div>
      </div>
      <div id="fe-tray"></div>
      <div id="fe-rest"></div>`;
    const host = root.querySelector('#fe-xp');
    host.addEventListener('click', e => { if (e.target.closest('#fe-sandbox')) createSandbox(); });
    xp = mountExplorer(host, {
      demo: demo.enabled, selected: S.selected,
      onChange: () => { S.analysis = null; renderTray(); renderRest(); },
      actions: demo.enabled ? `<button class="btn btn-primary btn-sm" id="fe-sandbox">${icon('plus', 14)} Create sample files</button>` : '',
    });
  }
  renderTray();
  renderRest();
}

function renderTray() {
  const el = root.querySelector('#fe-tray');
  if (!el) return;
  const items = [...S.selected.values()];
  if (!items.length) { el.innerHTML = ''; return; }
  const running = S.job?.status === 'RUNNING';
  el.innerHTML = `
    <div class="sel-tray">
      <div class="sel-chips">${items.map(e => `<span class="sel-chip" title="${esc(e.path)}">${icon(e.isDir ? 'folder' : 'file', 14)}<span>${esc(e.drive ? `${e.label} (${e.drive})` : e.name)}</span>
        <button data-unsel="${esc(e.path)}" title="Remove from the selection" aria-label="Remove">${icon('x', 12)}</button></span>`).join('')}</div>
      <div class="sel-actions">
        <span class="muted small">${items.length} selected</span>
        <button class="btn btn-ghost btn-sm" id="fe-clear">Clear</button>
        ${S.analysis ? '' : `<button class="btn btn-primary" id="fe-check" ${S.analyzing || running ? 'disabled' : ''}>Review selection ${icon('arrow', 15)}</button>`}
      </div>
    </div>`;
  el.querySelectorAll('[data-unsel]').forEach(b => b.addEventListener('click', () => {
    S.selected.delete(b.dataset.unsel); S.analysis = null; xp?.render(); renderTray(); renderRest();
  }));
  el.querySelector('#fe-clear').addEventListener('click', () => { S.selected.clear(); S.analysis = null; xp?.render(); renderTray(); renderRest(); });
  el.querySelector('#fe-check')?.addEventListener('click', analyze);
}

function renderRest() {
  const el = root.querySelector('#fe-rest');
  if (!el) return;
  const a = S.analysis;
  const running = S.job?.status === 'RUNNING';
  el.innerHTML = `
    ${S.analyzing ? `<div class="card card-pad" style="margin-top:16px">${progressBlock(null, 'Checking the drive…')}</div>` : ''}
    ${a && !S.analyzing ? prepareCard(a, running) : ''}
    ${S.job ? jobCard() : ''}`;
  bind(el);
}

function prepareCard(a, running) {
  const blocked = a.items.filter(i => i.blocked);
  const missing = a.items.filter(i => !i.exists);
  const journal = a.volumes.some(v => v.changeJournal);
  const t = a.traces || {};
  const traceRows = [
    ...(t.recentShortcuts || []).map(x => [x.path, 'Recent items shortcut']),
    ...(t.jumpLists || []).map(x => [x.path, 'Jump List']),
    ...(t.thumbnails || []).map(x => [x.path, 'Thumbnail cache']),
    ...(t.recentlyUsed || []).map(x => [x.path, 'Recently used list']),
    ...(t.finderMetadata || []).map(x => [x.path, 'Finder metadata']),
    ...(t.quarantineEvents || []).map(x => [x.path, 'Download record']),
  ];
  return `
    <div class="card" style="margin-top:16px">
      <div class="card-head"><span class="card-title">2 · Before you erase</span>
        <span class="card-sub">${fileCount(a)} file(s) · ${bytes(totalBytes(a))}</span></div>
      <div class="card-body stack">
        ${a.volumes.map(v => {
          const [tone, ic, text] = ASSURANCE[v.assurance] || ['warn', 'info', v.advice];
          return `<div class="notice ${tone}">${icon(ic, 18)}<div><strong>Drive ${esc(v.volume)} · ${esc(v.fileSystem)} · ${esc(v.mediaType)}</strong>${esc(text)}
            ${v.assurance !== 'High' ? '<div style="margin-top:6px"><a href="#/erase?mode=drive">Erase the whole drive instead</a></div>' : ''}</div></div>`;
        }).join('')}
        ${a.items.filter(i => i.wholeDrive).map(i => `<div class="notice warn">${icon('usb', 18)}<div><strong>Everything on ${esc(i.path)} will be destroyed</strong>All ${i.fileCount} file(s) and every folder on this USB drive. The drive itself stays usable.</div></div>`).join('')}
        ${blocked.length ? `<div class="notice bad">${icon('lock', 16)}<div><strong>Cannot erase some items</strong>${blocked.map(i => `${esc(i.path)}: ${esc(i.blocked)}`).join('<br>')}</div></div>` : ''}
        ${missing.length ? `<div class="notice warn">${icon('alert', 16)}<div><strong>Not found</strong>${missing.map(i => esc(i.path)).join('<br>')}</div></div>` : ''}
        ${patternLine(a)}
        <label class="check"><input type="checkbox" id="fe-clean" ${S.clean ? 'checked' : ''}>
          <span>Remove the traces the system keeps<span class="hint">${appRef.health?.platform === 'Darwin' ? 'Recent items, Finder metadata and download records' : appRef.health?.platform === 'Linux' ? 'Recently used lists and thumbnails' : 'Recent-files shortcuts and Jump Lists'}${traceRows.length ? ` (${traceRows.length} found)` : ''}</span></span></label>
        ${journal ? `<label class="check"><input type="checkbox" id="fe-journal" ${S.journal ? 'checked' : ''}>
          <span>Clear the drive's change journal<span class="hint">NTFS logs file names, including deleted ones</span></span></label>` : ''}
      </div>
      <details class="more"><summary>Advanced options and details</summary><div class="more-body stack">
        <div class="field"><label for="fe-method">Overwrite pattern</label>
          <select class="select" id="fe-method">${METHODS.map(m => `<option value="${m.id}" ${S.method === m.id ? 'selected' : ''}>${esc(m.label)}${m.id === a.pattern?.recommended ? ' (recommended)' : ''}</option>`).join('')}</select>
          <span class="hint">Three passes follow the older DoD 5220.22-M practice; they add time, not assurance.</span></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Item</th><th class="num">Files</th><th class="num">Size</th><th class="num">Hidden streams / attributes</th></tr></thead>
          <tbody>${a.items.filter(i => i.exists).map(i => `<tr><td class="trunc mono" title="${esc(i.path)}">${esc(i.path)}</td><td class="num">${i.fileCount}</td><td class="num">${bytes(i.bytes)}</td><td class="num">${(i.streams || 0) + (i.xattrs || 0)}</td></tr>`).join('')}</tbody></table></div>
        ${traceRows.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>Trace</th><th>Type</th></tr></thead><tbody>${traceRows.map(r => `<tr><td class="trunc mono">${esc(r[0])}</td><td>${esc(r[1])}</td></tr>`).join('')}</tbody></table></div>` : ''}
        ${a.volumes.flatMap(v => v.notes || []).map(n => `<div class="muted small">${esc(n)}</div>`).join('')}
      </div></details>
      <div class="card-foot">
        <button class="btn btn-danger btn-lg" id="fe-erase" ${!blocked.length && !running && fileCount(a) ? '' : 'disabled'}>Permanently delete ${fileCount(a)} file(s)</button>
      </div>
    </div>`;
}

function patternLine(a) {
  const p = a.pattern;
  if (!p) return '';
  const m = METHODS.find(x => x.id === S.method);
  const rec = S.method === p.recommended;
  return `<div class="rec-line">${icon('star', 14)}<span>Overwrite: <b>${esc(m?.label || S.method)}</b> ${rec ? badge('Recommended', 'ok') : badge('Your choice', '')}
    <span class="muted small">${esc(rec ? p.reason : 'Change it under Advanced options')}</span></span></div>`;
}

const removedTraces = (r) => r.traces.filter(t => /erased|removed/.test(t.result)).length;

function checkLine(ok, text) {
  return `<div><span class="check-ic ${ok === true ? '' : ok === false ? 'bad' : 'skip'}">${icon(ok === true ? 'check' : ok === false ? 'x' : 'minus', 12, 2.6)}</span><span>${esc(text)}</span></div>`;
}

function jobCard() {
  const j = S.job;
  if (j.status === 'RUNNING') return `<div class="card card-pad" style="margin-top:16px"><div class="card-title" style="margin-bottom:10px">Erasing…</div>${progressBlock(j.progress, j.message)}</div>`;
  if (j.status === 'FAILED') return `<div class="verdict bad" style="margin-top:16px"><span class="verdict-icon">${icon('x', 22, 2.6)}</span><div><div class="verdict-title">Erasure could not run</div><div class="verdict-text">${esc(j.message)}</div></div></div>`;
  const r = j.result;
  const tc = r.traceCheck || {};
  const overwrote = !r.failures.length && r.files.every(f => f.verified);
  const title = r.verdict === 'PASS' ? 'Permanently deleted: no trace found'
    : r.verdict === 'TRACES_REMAIN' ? 'Deleted, but some traces remain'
    : r.verdict === 'ERASED_UNVERIFIED' ? 'Deleted and overwritten; the drive check could not run' : 'Some files could not be erased';
  const ran = (tc.folders || []).length > 0;
  const skipped = tc.skipped || [];
  const journalHits = (tc.journal || []).reduce((n, x) => n + (x.recordsWithNames || 0), 0);
  return `
    <div class="card" style="margin-top:16px">
      <div class="card-head"><span class="card-title">Result</span>
        <a class="btn btn-secondary btn-sm" href="${apiUrl(`/api/files/report/${j.id}.pdf`)}" target="_blank" rel="noopener">${icon('download', 14)} Report</a></div>
      <div class="card-body">
        <div class="verdict ${r.verdict === 'PASS' ? '' : 'warn'}"><span class="verdict-icon">${icon(r.verdict === 'PASS' ? 'check' : 'alert', 22, 2.6)}</span>
          <div><div class="verdict-title">${esc(title)}</div><div class="verdict-text">${r.files.length} file(s), ${bytes(r.bytesOverwritten)} overwritten and removed.</div></div></div>
        <div class="verdict-list">
          ${checkLine(overwrote, overwrote ? 'Content overwritten, names scrambled, files removed' : `${r.failures.length} item(s) failed`)}
          ${ran ? checkLine(!(tc.namesFound || []).length, (tc.namesFound || []).length ? 'Original names still visible on the drive' : 'Original names no longer on the drive') : checkLine(null, tc.summary || 'Drive check not run')}
          ${ran ? checkLine(!(tc.contentFound || []).length, (tc.contentFound || []).length ? 'Some content can still be recovered' : 'Recovery attempt found none of the content') : ''}
          ${ran && skipped.length ? checkLine(null, `${skipped.length} folder(s) could not be checked: ${skipped[0].reason}`) : ''}
          ${(tc.journal || []).length ? checkLine(!journalHits, journalHits ? `${journalHits} change-journal record(s) still name the files (tick "Clear the drive's change journal" next time)` : 'Change journal holds none of the names') : ''}
          ${removedTraces(r) ? checkLine(true, `${removedTraces(r)} system trace(s) removed (recent-file lists, shortcuts, thumbnails)`) : ''}
        </div>
      </div>
      <details class="more"><summary>Technical details</summary><div class="more-body stack">
        <div class="table-wrap"><table class="table"><thead><tr><th>Original file</th><th class="num">Bytes</th><th>Hidden streams / attributes</th></tr></thead>
          <tbody>${r.files.map(f => `<tr><td class="trunc mono" title="${esc(f.path)}">${esc(f.path)}</td><td class="num">${f.size.toLocaleString()}</td>
            <td>${[...f.streams, ...(f.xattrs || [])].map(s => esc(s.name)).join(', ') || '—'}</td></tr>`).join('')}
            ${r.failures.map(f => `<tr><td class="trunc mono">${esc(f.path)}</td><td colspan="2">${badge('Failed', 'bad')} ${esc(f.error)}</td></tr>`).join('')}</tbody></table></div>
        ${[...r.traces, ...(r.journal || [])].map(t => `<div class="small"><span class="mono">${esc(t.path || t.volume)}</span>: ${esc(t.result)}</div>`).join('')}
        <div class="muted small">Pattern: ${esc((METHODS.find(m => m.id === r.method) || {}).label || r.method)} · Directory entries reused: ${r.directorySlotsReused || 0} · Job ${esc(r.jobId)} · ${esc(tc.summary || '')}</div>
      </div></details>
    </div>`;
}

function bind(el) {
  el.querySelector('#fe-clean')?.addEventListener('change', e => { S.clean = e.target.checked; });
  el.querySelector('#fe-journal')?.addEventListener('change', e => { S.journal = e.target.checked; });
  el.querySelector('#fe-method')?.addEventListener('change', e => { S.method = e.target.value; S.methodChosen = true; renderRest(); });
  el.querySelector('#fe-erase')?.addEventListener('click', erase);
}

async function createSandbox() {
  try {
    const sb = await api('/api/files/sandbox', { method: 'POST' });
    toast('Sample files created', 'ok');
    S.selected.clear();
    S.selected.set(sb.path, { path: sb.path, name: `Sample set ${sb.path.split(/[\\/]/).pop()}`, isDir: true, size: 0 });
    await xp?.go('');
    analyze();
  } catch (e) { reportError(e); }
}

async function analyze() {
  if (!S.selected.size) return;
  S.analyzing = true;
  S.job = null;
  renderTray(); renderRest();
  try {
    S.analysis = await api('/api/files/analyze', { method: 'POST', body: { paths: paths() } });
    if (!S.methodChosen && S.analysis.pattern) S.method = S.analysis.pattern.recommended;
  } catch (e) { reportError(e); S.analysis = null; }
  S.analyzing = false;
  renderTray(); renderRest();
  root.querySelector('#fe-rest .card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function erase() {
  const a = S.analysis;
  const journal = S.journal && a.volumes.some(v => v.changeJournal);
  const ok = await confirmDanger({
    title: `Permanently delete ${fileCount(a)} file(s)?`,
    sub: 'The files are overwritten and removed. They cannot be recovered afterwards.',
    rows: [['Items', paths().map(p => `<div class="mono small trunc">${esc(p)}</div>`).join('')], ['Size', bytes(totalBytes(a))],
           ['Remove system traces', S.clean ? 'Yes' : 'No'], ['Clear change journal', journal ? 'Yes' : 'No'], ['Operator', esc(getOperator())]],
    confirmLabel: 'Delete permanently',
    approval: appRef.health?.dualApproval ? 'required' : '',
  });
  if (!ok) return;
  const erased = paths();
  try {
    const { jobId } = await api('/api/files/erase', { method: 'POST', body: {
      paths: erased, method: S.method, cleanTraces: S.clean, clearJournal: journal,
      approver: ok.approver || '', approverPassword: ok.approverPassword || '' } });
    S.job = { id: jobId, status: 'RUNNING', progress: 0, message: 'Starting' };
    S.analysis = null;
    renderTray(); renderRest();
    const job = await waitForJob(jobId, j => { S.job = j; if (visible()) renderRest(); });
    S.job = job;
    if (job.status === 'COMPLETED') {
      S.selected.clear();
      // If the browser shows a folder that was just erased, step out to where it was
      const norm = (p) => p.toLowerCase().replace(/[\\/]+$/, '');
      const cur = norm(xp?.path || '');
      const gone = erased.find(p => cur && (cur === norm(p) || cur.startsWith(`${norm(p)}\\`) || cur.startsWith(`${norm(p)}/`)));
      if (gone) xp.go(gone.replace(/[\\/]+$/, '').replace(/[\\/][^\\/]+$/, '')); else xp?.refresh();
    }
    refreshDemo();
    if (visible()) { renderTray(); renderRest(); }
  } catch (e) { reportError(e); }
}
