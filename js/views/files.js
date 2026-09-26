/** Permanently delete files and folders, remove the traces Windows keeps, then prove nothing is left. */
import { api, apiUrl, badge, bytes, confirmDanger, esc, getOperator, icon, pickPaths, progressBlock,
  reportError, toast, waitForJob } from '../core.js';

const S = { paths: [], analysis: null, analyzing: false, method: 'dod', clean: true, journal: true, job: null };
let root, appRef;

const METHODS = [
  { id: 'dod', label: '3 passes (zeros, ones, random)' },
  { id: 'random', label: '1 pass, random data' },
  { id: 'zero', label: '1 pass, zeros' },
];

const ASSURANCE = {
  High: ['ok', 'check', 'Overwritten data cannot be read back from this drive.'],
  Limited: ['warn', 'info', 'This is an SSD or flash drive. WipeX overwrites the file and removes every trace it can reach, but the drive may keep old copies in hidden spare blocks. For absolute certainty, erase the whole drive.'],
  'Not effective': ['bad', 'alert', 'This file system writes changes to new places (copy-on-write), so overwriting cannot reach the old data. Erase the whole drive instead.'],
};

export async function show(el, _params, app) {
  root = el;
  appRef = app;
  render();
}

const fileCount = (a) => a.items.reduce((n, i) => n + (i.fileCount || 0), 0);
const totalBytes = (a) => a.items.reduce((n, i) => n + (i.bytes || 0), 0);

function render() {
  const a = S.analysis;
  const running = S.job?.status === 'RUNNING';
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Permanently delete files</h1>
        <p class="page-desc">Destroy chosen files and folders so they cannot be recovered or traced: their content, their names and the records Windows keeps about them. Afterwards WipeX checks the drive to prove nothing is left.</p>
      </div>
    </div>
    <div class="card">
      <div class="card-head">
        <span class="card-title">1 · Choose files or folders</span>
        <div class="row">
          <button class="btn btn-secondary btn-sm" id="fe-sandbox" title="Create disposable sample files to try this safely">${icon('plus', 14)} Create sample files</button>
          <button class="btn btn-primary btn-sm" id="fe-add">${icon('folder', 14)} Add files or folders</button>
        </div>
      </div>
      <div class="card-body">
        ${S.paths.length ? `<div class="path-list">${S.paths.map((p, i) => `
          <div class="path-item">${icon('file', 15)}<span class="p" title="${esc(p)}">${esc(p)}</span>
          <button class="btn btn-ghost btn-sm" data-rm="${i}" title="Remove from the list">${icon('x', 14)}</button></div>`).join('')}</div>`
        : '<div class="empty">Nothing selected yet. Add files or folders, or create sample files to try it safely.</div>'}
        <input class="input mono" id="fe-path" placeholder="…or paste a full path and press Enter" style="margin-top:12px">
      </div>
    </div>
    ${S.analyzing ? `<div class="card card-pad" style="margin-top:16px">${progressBlock(null, 'Checking the drive…')}</div>` : ''}
    ${a && !S.analyzing ? prepareCard(a, running) : ''}
    ${S.job ? jobCard() : ''}`;
  bind();
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
            ${v.assurance !== 'High' ? '<div style="margin-top:6px"><a href="#/drive">Erase a whole drive instead</a></div>' : ''}</div></div>`;
        }).join('')}
        ${blocked.length ? `<div class="notice bad">${icon('lock', 16)}<div><strong>Cannot erase some items</strong>${blocked.map(i => `${esc(i.path)}: ${esc(i.blocked)}`).join('<br>')}</div></div>` : ''}
        ${missing.length ? `<div class="notice warn">${icon('alert', 16)}<div><strong>Not found</strong>${missing.map(i => esc(i.path)).join('<br>')}</div></div>` : ''}
        <label class="check"><input type="checkbox" id="fe-clean" ${S.clean ? 'checked' : ''}>
          <span>Remove the traces Windows keeps<span class="hint">Recent-files shortcuts and Jump Lists that point to these files${traceRows.length ? ` (${traceRows.length} found)` : ''}.</span></span></label>
        ${journal ? `<label class="check"><input type="checkbox" id="fe-journal" ${S.journal ? 'checked' : ''}>
          <span>Clear the drive's change journal<span class="hint">NTFS keeps a log of file names, including deleted ones. WipeX empties it and starts a fresh one.</span></span></label>` : ''}
      </div>
      <details class="more"><summary>Advanced options and details</summary><div class="more-body stack">
        <div class="field"><label for="fe-method">Overwrite pattern</label>
          <select class="select" id="fe-method">${METHODS.map(m => `<option value="${m.id}" ${S.method === m.id ? 'selected' : ''}>${esc(m.label)}</option>`).join('')}</select>
          <span class="hint">One pass is enough on modern drives; three passes follow the older DoD 5220.22-M practice.</span></div>
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
    : r.verdict === 'TRACES_REMAIN' ? 'Deleted, but some traces remain' : 'Some files could not be erased';
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
          ${checkLine(tc.checked ? !(tc.namesFound || []).length : null, tc.checked ? ((tc.namesFound || []).length ? 'Original names still visible in the folder' : 'Original names no longer on the drive') : tc.summary || 'Drive check not run')}
          ${checkLine(tc.checked ? !(tc.contentFound || []).length : null, tc.checked ? ((tc.contentFound || []).length ? 'Some content can still be recovered' : 'Recovery attempt found none of the content') : 'Recovery attempt not run')}
          ${(tc.journal || []).length ? checkLine(!journalHits, journalHits ? `${journalHits} change-journal record(s) still name the files (tick "Clear the drive's change journal" next time)` : 'Change journal holds none of the names') : ''}
          ${removedTraces(r) ? checkLine(true, `${removedTraces(r)} Windows trace(s) removed (recent-files shortcuts, Jump Lists)`) : ''}
        </div>
      </div>
      <details class="more"><summary>Technical details</summary><div class="more-body stack">
        <div class="table-wrap"><table class="table"><thead><tr><th>Original file</th><th class="num">Bytes</th><th>Hidden streams / attributes</th></tr></thead>
          <tbody>${r.files.map(f => `<tr><td class="trunc mono" title="${esc(f.path)}">${esc(f.path)}</td><td class="num">${f.size.toLocaleString()}</td>
            <td>${[...f.streams, ...(f.xattrs || [])].map(s => esc(s.name)).join(', ') || '—'}</td></tr>`).join('')}
            ${r.failures.map(f => `<tr><td class="trunc mono">${esc(f.path)}</td><td colspan="2">${badge('Failed', 'bad')} ${esc(f.error)}</td></tr>`).join('')}</tbody></table></div>
        ${[...r.traces, ...(r.journal || [])].map(t => `<div class="small"><span class="mono">${esc(t.path || t.volume)}</span>: ${esc(t.result)}</div>`).join('')}
        <div class="muted small">Pattern: ${esc((METHODS.find(m => m.id === r.method) || {}).label || r.method)} · Job ${esc(r.jobId)} · ${esc(tc.summary || '')}</div>
      </div></details>
    </div>`;
}

function bind() {
  const add = (list) => { S.paths = [...new Set([...S.paths, ...list])]; analyze(); };
  root.querySelector('#fe-add').addEventListener('click', async () => {
    const picked = await pickPaths();
    if (picked?.length) add(picked);
  });
  root.querySelector('#fe-sandbox').addEventListener('click', createSandbox);
  root.querySelector('#fe-path').addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.value.trim()) add([e.target.value.trim()]);
  });
  root.querySelectorAll('[data-rm]').forEach(b => b.addEventListener('click', () => {
    S.paths.splice(+b.dataset.rm, 1);
    if (S.paths.length) analyze(); else { S.analysis = null; render(); }
  }));
  root.querySelector('#fe-clean')?.addEventListener('change', e => { S.clean = e.target.checked; });
  root.querySelector('#fe-journal')?.addEventListener('change', e => { S.journal = e.target.checked; });
  root.querySelector('#fe-method')?.addEventListener('change', e => { S.method = e.target.value; });
  root.querySelector('#fe-erase')?.addEventListener('click', erase);
}

async function createSandbox() {
  try {
    const sb = await api('/api/files/sandbox', { method: 'POST' });
    toast('Sample files created in the WipeX folder', 'ok');
    S.paths = [...new Set([...S.paths, sb.path])];
    analyze();
  } catch (e) { reportError(e); }
}

async function analyze() {
  S.analyzing = true;
  S.job = null;
  render();
  try {
    S.analysis = await api('/api/files/analyze', { method: 'POST', body: { paths: S.paths } });
  } catch (e) { reportError(e); S.analysis = null; }
  S.analyzing = false;
  render();
}

async function erase() {
  const a = S.analysis;
  const journal = S.journal && a.volumes.some(v => v.changeJournal);
  const ok = await confirmDanger({
    title: `Permanently delete ${fileCount(a)} file(s)?`,
    sub: 'The files are overwritten and removed. They cannot be recovered afterwards.',
    rows: [['Items', S.paths.map(p => `<div class="mono small trunc">${esc(p)}</div>`).join('')], ['Size', bytes(totalBytes(a))],
           ['Remove Windows traces', S.clean ? 'Yes' : 'No'], ['Clear change journal', journal ? 'Yes' : 'No'], ['Operator', esc(getOperator())]],
    confirmLabel: 'Delete permanently',
    approval: appRef.health?.dualApproval ? 'required' : '',
  });
  if (!ok) return;
  try {
    const { jobId } = await api('/api/files/erase', { method: 'POST', body: {
      paths: S.paths, method: S.method, cleanTraces: S.clean, clearJournal: journal,
      approver: ok.approver || '', approverPassword: ok.approverPassword || '' } });
    S.job = { id: jobId, status: 'RUNNING', progress: 0, message: 'Starting' };
    S.analysis = null;
    render();
    const job = await waitForJob(jobId, j => { S.job = j; if (root.classList.contains('active')) render(); });
    S.job = job;
    if (job.status === 'COMPLETED') S.paths = [];
    render();
  } catch (e) { reportError(e); }
}
