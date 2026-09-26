/** Recover deleted files: choose where to look, scan, review what can be recovered. */
import { api, apiUrl, badge, bytes, esc, icon, pickPaths, progressBlock, reportError, short, statusBadge,
  toast, waitForJob, when } from '../core.js';

const S = {
  kind: 'drive', drive: '', folder: '', labId: '', evidenceId: '', path: '', deep: false,
  types: [], partial: false, sources: null, formats: [], job: null, history: [], bench: null, benchImage: '',
};
let root;

export async function show(el, params) {
  root = el;
  if (params.evidence) { S.kind = 'evidence'; S.evidenceId = params.evidence; }
  root.innerHTML = '<div class="empty">Loading…</div>';
  const [sources, formats, history] = await Promise.all([
    api('/api/recovery/sources').catch(() => ({ drives: [], labImages: [], evidence: [] })),
    api('/api/recovery/formats').catch(() => []), api('/api/jobs?kind=recovery').catch(() => []),
  ]);
  S.sources = sources;
  S.formats = formats;
  S.history = history;
  const imgs = sources.labImages || [];
  S.labId = S.labId || imgs.find(i => i.hasTruth)?.id || imgs[0]?.id || '';
  S.benchImage = S.benchImage || imgs.find(i => i.hasTruth)?.id || '';
  S.evidenceId = S.evidenceId || sources.evidence?.[0]?.id || '';
  if (!S.drive) S.drive = (sources.drives || []).find(d => d.removable)?.letter || '';
  if (!(sources.drives || []).length && S.kind === 'drive') S.kind = 'lab';
  render();
}

function render() {
  const running = S.job?.status === 'RUNNING';
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Recover deleted files</h1>
        <p class="page-desc">Find files that were deleted from a drive, USB stick or disk image and get them back. The source is only read, never changed.</p>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><span class="card-title">1 · Where should WipeX look?</span>
        <div class="seg">${[['drive', 'Drive / USB'], ['lab', 'Sample disk'], ['evidence', 'Case evidence'], ['path', 'Image file']].map(([k, l]) =>
          `<button data-kind="${k}" class="${S.kind === k ? 'on' : ''}">${l}</button>`).join('')}</div></div>
      <div class="card-body">${sourceBody()}</div>
      <div class="card-body" style="border-top:1px solid var(--border)">
        <div class="label" style="margin-bottom:8px">2 · How thorough?</div>
        <div class="choice-row">
          <label class="choice ${!S.deep ? 'on' : ''}"><input type="radio" name="rc-mode" value="quick" ${!S.deep ? 'checked' : ''}>
            <b>Quick scan</b><span>Reads the file system for recently deleted files. Seconds.</span></label>
          <label class="choice ${S.deep ? 'on' : ''}"><input type="radio" name="rc-mode" value="deep" ${S.deep ? 'checked' : ''}>
            <b>Deep scan</b><span>Also searches every block for photos, documents and archives, even after a format. ${estimate()}</span></label>
        </div>
      </div>
      <div class="card-foot"><button class="btn btn-primary btn-lg" id="rc-start" ${running ? 'disabled' : ''}>${icon('search', 16)} ${running ? 'Scanning…' : 'Scan for deleted files'}</button></div>
    </div>
    ${S.job ? resultsCard() : ''}
    ${advancedBlock()}`;
  bind();
}

function driveCard(d) {
  const tags = [d.removable ? badge('USB / removable', 'blue') : '', d.isSystem ? badge('System drive', 'warn') : '',
    d.mediaType === 'SSD' ? badge('SSD') : d.mediaType === 'HDD' ? badge('Hard disk') : ''].join('');
  return `<button class="pick ${S.drive === d.letter ? 'on' : ''}" data-drive="${d.letter}">
    <div class="pick-top"><span class="pick-title">${esc(d.letter)}: ${esc(d.label || 'Local disk')}</span><span class="pick-tags">${tags}</span></div>
    <div class="pick-meta"><span>${esc(d.fileSystem)}</span><b>${bytes(d.size)}</b></div>
  </button>`;
}

function sourceBody() {
  const src = S.sources || {};
  if (S.kind === 'drive') {
    const drives = src.drives || [];
    if (!drives.length) return `<div class="empty">${src.platform === 'Windows' ? 'No drives found.' : 'Scanning drives by letter is available on Windows. Use an image file instead.'}</div>`;
    const d = drives.find(x => x.letter === S.drive);
    const ssd = d && d.mediaType === 'SSD' && d.trim;
    return `
      ${src.elevated ? '' : `<div class="notice warn" style="margin-bottom:12px">${icon('alert', 16)}<div><strong>Administrator rights needed</strong>Reading a drive directly needs WipeX to run as Administrator. Sample disks and image files work without it.</div></div>`}
      <div class="pick-grid">${drives.map(driveCard).join('')}</div>
      ${d ? `<div class="field" style="margin-top:14px"><label for="rc-folder">Only look in this folder (optional)</label>
        <div class="row"><input class="input mono" id="rc-folder" value="${esc(S.folder)}" placeholder="${esc(d.letter)}:\\Users\\…\\Documents" style="flex:1">
        <button class="btn btn-secondary btn-sm" id="rc-browse">Browse</button></div>
        <span class="hint">Faster on large drives. Leave empty to scan the whole drive.</span></div>` : ''}
      ${ssd ? `<div class="notice" style="margin-top:12px">${icon('info', 16)}<div><strong>This is an SSD</strong>SSDs erase deleted data on their own within seconds (TRIM), so deleted files often cannot be brought back. A USB stick or hard disk shows recovery best.</div></div>` : ''}
      ${d?.sameAsWorkspace ? `<div class="muted small" style="margin-top:8px">Recovered files are saved in the WipeX folder on this same drive.</div>` : ''}`;
  }
  if (S.kind === 'lab') {
    const imgs = src.labImages || [];
    return imgs.length ? `<div class="field"><label for="rc-lab">Sample disk</label>
      <select class="select" id="rc-lab">${imgs.map(i => `<option value="${i.id}" ${i.id === S.labId ? 'selected' : ''}>${esc(i.model)} · ${esc(i.capacity)}</option>`).join('')}</select>
      <span class="hint">A disk image with ordinary, deleted and fragmented files, safe to experiment with.</span></div>`
      : '<div class="empty">No sample disks yet. Create one in Erase Drive.</div>';
  }
  if (S.kind === 'evidence') {
    const ev = src.evidence || [];
    return ev.length ? `<div class="field"><label for="rc-ev">Evidence item</label>
      <select class="select" id="rc-ev">${ev.map(e => `<option value="${e.id}" ${e.id === S.evidenceId ? 'selected' : ''}>${esc(e.id)} · ${esc(e.label)} (${esc(e.format)})</option>`).join('')}</select>
      <span class="hint">Scans the verified copy stored with the case; results are linked to the case.</span></div>`
      : '<div class="empty">No evidence yet. <a href="#/cases">Open a case and acquire a disk</a> first.</div>';
  }
  return `<div class="field"><label for="rc-path">Disk image file</label>
    <div class="row"><input class="input mono" id="rc-path" value="${esc(S.path)}" placeholder="Path to a .dd, .img or .E01 file" style="flex:1">
    <button class="btn btn-secondary btn-sm" id="rc-pick">Browse</button></div></div>`;
}

function estimate() {
  const d = (S.sources?.drives || []).find(x => x.letter === S.drive);
  if (S.kind !== 'drive' || !d || S.folder) return '';
  const min = Math.max(1, Math.round(d.size / (120 * 1e6) / 60));
  return `About ${min} min for this drive.`;
}

function bind() {
  root.querySelectorAll('[data-kind]').forEach(b => b.addEventListener('click', () => { S.kind = b.dataset.kind; render(); }));
  root.querySelectorAll('[data-drive]').forEach(b => b.addEventListener('click', () => { S.drive = b.dataset.drive; S.folder = ''; render(); }));
  root.querySelector('#rc-folder')?.addEventListener('input', e => { S.folder = e.target.value; });
  root.querySelector('#rc-browse')?.addEventListener('click', async () => {
    const p = await pickPaths({ title: 'Choose the folder to search', start: `${S.drive}:\\` });
    if (p?.[0]) { S.folder = p[0]; render(); }
  });
  root.querySelector('#rc-pick')?.addEventListener('click', async () => {
    const p = await pickPaths({ title: 'Choose a disk image file' });
    if (p?.[0]) { S.path = p[0]; render(); }
  });
  root.querySelector('#rc-lab')?.addEventListener('change', e => { S.labId = e.target.value; });
  root.querySelector('#rc-ev')?.addEventListener('change', e => { S.evidenceId = e.target.value; });
  root.querySelector('#rc-path')?.addEventListener('input', e => { S.path = e.target.value; });
  root.querySelectorAll('input[name=rc-mode]').forEach(r => r.addEventListener('change', e => { S.deep = e.target.value === 'deep'; render(); }));
  root.querySelector('#rc-start').addEventListener('click', start);
  root.querySelector('#rc-open')?.addEventListener('click', openFolder);
  root.querySelectorAll('[data-job]').forEach(r => r.addEventListener('click', () => loadJob(r.dataset.job)));
  root.querySelectorAll('[data-type]').forEach(b => b.addEventListener('click', () => {
    const all = S.formats.map(f => f.ext);
    let cur = S.types.length ? [...S.types] : [...all];
    cur = cur.includes(b.dataset.type) ? cur.filter(t => t !== b.dataset.type) : [...cur, b.dataset.type];
    S.types = cur.length === all.length || !cur.length ? [] : cur;
    render();
  }));
  root.querySelector('#rc-partial')?.addEventListener('change', e => { S.partial = e.target.checked; });
  root.querySelector('#bm-img')?.addEventListener('change', e => { S.benchImage = e.target.value; });
  root.querySelector('#bm-run')?.addEventListener('click', runBenchmark);
}

function currentSource() {
  if (S.kind === 'drive') return S.drive ? { type: 'drive', id: S.drive, folder: S.folder.trim() || null } : null;
  if (S.kind === 'lab') return S.labId ? { type: 'lab', id: S.labId } : null;
  if (S.kind === 'evidence') return S.evidenceId ? { type: 'evidence', id: S.evidenceId } : null;
  return S.path.trim() ? { type: 'path', path: S.path.trim() } : null;
}

async function start() {
  const source = currentSource();
  if (!source) { toast('Choose where to look first', 'bad'); return; }
  // Sample disks and image files are small: always search their blocks too
  const deep = S.deep || S.kind === 'lab' || S.kind === 'path' || S.kind === 'evidence';
  try {
    const { jobId } = await api('/api/recovery/scan', { method: 'POST', body: {
      source, useFs: true, useCarving: deep, types: S.types.length ? S.types : null, includePartial: S.partial } });
    S.job = { id: jobId, status: 'RUNNING', progress: 0, message: 'Starting' };
    render();
    const job = await waitForJob(jobId, j => { S.job = j; if (root.classList.contains('active')) render(); });
    S.job = job;
    S.history = await api('/api/jobs?kind=recovery').catch(() => S.history);
    render();
    if (job.status !== 'COMPLETED') toast(job.message, 'bad');
  } catch (e) { reportError(e); }
}

async function loadJob(id) {
  try {
    S.job = await api(`/api/jobs/${id}`);
    render();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (e) { reportError(e); }
}

async function openFolder() {
  try { await api(`/api/recovery/${S.job.id}/open`, { method: 'POST' }); } catch (e) { reportError(e); }
}

const isImg = (name) => /\.(jpe?g|png|gif|bmp)$/i.test(name || '');
const fileUrl = (p, dl) => apiUrl(`/api/recovery/file?path=${encodeURIComponent(p)}${dl ? '&download=true' : ''}`);
const CONDITION = {
  intact: ['Recovered intact', 'ok', ''],
  unverified: ['Recovered', 'ok', 'Plain file: content looks present but has no structure to check'],
  damaged: ['Partly damaged', 'warn', 'Some of its space was reused'],
  overwritten: ['Overwritten', 'bad', 'Its space now holds other data'],
  zeroed: ['Erased by the drive', 'bad', 'The drive already wiped these blocks (SSD TRIM)'],
  unreadable: ['Unreadable', 'bad', ''],
};

/** One simple list: deleted files from the file system, plus files found only by the deep scan. */
function foundFiles(r) {
  const fsDeleted = (r.filesystem?.entries || []).filter(e => e.deleted && !e.isDir).map(e => ({
    name: e.name, where: e.path.slice(0, -e.name.length) || '/', size: e.size, when: e.modified,
    condition: e.contentStatus || 'unreadable', detail: e.detail, file: e.recoveredPath, how: 'File system',
  }));
  const carvedFiles = (r.carving?.files || []).filter(f => !f.alsoFoundAs);
  const carved = carvedFiles.map(f => ({
    name: `${f.id}.${f.ext}`, size: f.size, when: null,
    where: f.fragments?.length > 1 ? `Name not known · rebuilt from ${f.fragments.length} pieces found in free space`
      : 'Name not known (found in free space)',
    condition: f.status === 'partial' ? 'damaged' : 'intact', file: f.path,
    how: f.fragments?.length > 1 ? `Deep scan · rebuilt from ${f.fragments.length} pieces` : 'Deep scan',
  }));
  for (const e of fsDeleted) {             // a damaged deleted file whose intact copy the deep scan rebuilt
    if (e.condition !== 'damaged' && e.condition !== 'overwritten') continue;
    const ext = (e.name.split('.').pop() || '').toLowerCase();
    const copy = carvedFiles.find(f => f.status !== 'partial' && f.size === e.size && (f.ext === ext || (ext === 'jpeg' && f.ext === 'jpg')));
    if (copy) e.note = `Intact copy rebuilt by the deep scan: ${copy.id}.${copy.ext}`;
  }
  return [...fsDeleted, ...carved];
}

function resultsCard() {
  const j = S.job;
  if (j.status === 'RUNNING') return `<div class="card card-pad"><div class="card-title" style="margin-bottom:10px">Scanning ${esc(j.params?.label || '')}</div>${progressBlock(j.progress, j.message)}</div>`;
  if (j.status === 'FAILED') return `<div class="verdict bad"><span class="verdict-icon">${icon('x', 22, 2.6)}</span><div><div class="verdict-title">Scan could not run</div><div class="verdict-text">${esc(j.message)}</div></div></div>`;
  const r = j.result;
  const files = foundFiles(r);
  const ok = files.filter(f => ['intact', 'unverified'].includes(f.condition) && f.file);
  const headline = files.length
    ? `${files.length} deleted file${files.length === 1 ? '' : 's'} found · ${ok.length} recovered`
    : 'No deleted files found';
  return `
    <div class="card">
      <div class="card-head">
        <div><div class="card-title">${esc(headline)}</div><div class="card-sub">${esc(r.sourceLabel || r.source)} · ${esc(when(j.finished_at))}</div></div>
        <div class="row">
          ${ok.length ? `<button class="btn btn-primary btn-sm" id="rc-open">${icon('folder', 14)} Open recovered files</button>` : ''}
          <a class="btn btn-secondary btn-sm" href="${apiUrl(`/api/recovery/${j.id}/report.pdf`)}" target="_blank" rel="noopener">${icon('download', 14)} Report</a>
        </div>
      </div>
      ${r.warning ? `<div class="card-body" style="padding-bottom:0"><div class="notice warn">${icon('alert', 16)}<div>${esc(r.warning)}</div></div></div>` : ''}
      ${files.length ? `<div class="table-wrap" style="max-height:560px;overflow:auto"><table class="table">
        <thead><tr><th></th><th>File</th><th class="num">Size</th><th>Condition</th><th></th></tr></thead><tbody>
        ${files.map(fileRow).join('')}</tbody></table></div>`
        : `<div class="empty">${esc(r.filesystem?.reason || 'Nothing deleted was found here. Try a deep scan, or a folder where files were deleted.')}</div>`}
      ${technicalDetails(r)}
    </div>`;
}

function fileRow(f) {
  const [label, tone, hint] = CONDITION[f.condition] || [f.condition, '', ''];
  const thumb = f.file && isImg(f.name) && tone === 'ok' ? `<img class="thumb" src="${fileUrl(f.file)}" alt="" loading="lazy">`
    : `<span class="thumb" style="display:grid;place-items:center;color:var(--text-3)">${icon('file', 16)}</span>`;
  const actions = f.file && tone !== 'bad' ? `<a class="btn btn-ghost btn-sm" href="${fileUrl(f.file)}" target="_blank" rel="noopener">Open</a>
    <a class="btn btn-ghost btn-sm" href="${fileUrl(f.file, true)}" title="Save a copy">${icon('download', 14)} Save</a>` : '';
  return `<tr><td>${thumb}</td>
    <td><div style="font-weight:600" class="trunc">${esc(f.name)}</div><div class="muted small trunc" title="${esc(f.where)}">${esc(f.where)}${f.when ? ` · deleted file last changed ${esc(when(f.when))}` : ''}</div></td>
    <td class="num">${bytes(f.size)}</td>
    <td>${badge(label, tone)}${f.note || hint ? `<div class="muted small">${esc(f.note || hint)}</div>` : ''}</td>
    <td class="nowrap">${actions}</td></tr>`;
}

function technicalDetails(r) {
  const fs = r.filesystem || {};
  const carved = r.carving?.files || [];
  const vols = (fs.volumes || []).map(v => v.fsType).join(', ') || 'none recognised';
  const rows = carved.map(f => `<tr><td class="mono">${esc(f.id)}</td><td>${esc(f.ext.toUpperCase())}</td><td class="num">${bytes(f.size)}</td>
    <td class="mono">${f.offset.toLocaleString()}</td><td>${esc(f.technique)}</td><td class="mono" title="${esc(f.sha256)}">${short(f.sha256, 12)}</td>
    <td class="small">${f.alsoFoundAs ? esc(f.alsoFoundAs) : '—'}</td></tr>`).join('');
  const del = (fs.entries || []).filter(e => e.deleted && !e.isDir).map(e => `<tr><td class="trunc">${esc(e.path)}</td>
    <td class="num mono">${e.inode ?? ''}</td><td>${esc(e.contentStatus || '')}</td><td class="mono" title="${esc(e.sha256 || '')}">${short(e.sha256, 12)}</td></tr>`).join('');
  return `<details class="more"><summary>Technical details</summary><div class="more-body">
    <dl class="kv"><dt>File system</dt><dd>${esc(vols)}</dd><dt>Entries listed</dt><dd>${(fs.entries || []).length}</dd>
      <dt>Blocks searched</dt><dd>${r.carving?.bytesScanned ? `${bytes(r.carving.bytesScanned)} at ${r.carving.throughputMBps} MB/s` : 'Quick scan (not searched)'}</dd>
      <dt>Scan time</dt><dd>${r.seconds}s</dd><dt>Job</dt><dd class="mono">${esc(S.job.id)}</dd></dl>
    ${del ? `<div class="label" style="margin:12px 0 6px">Deleted file-system entries</div><div class="table-wrap"><table class="table"><thead><tr><th>Path</th><th class="num">Record</th><th>Content check</th><th>SHA-256</th></tr></thead><tbody>${del}</tbody></table></div>` : ''}
    ${rows ? `<div class="label" style="margin:12px 0 6px">Files found by searching blocks (carving)</div><div class="table-wrap"><table class="table"><thead><tr><th>ID</th><th>Type</th><th class="num">Size</th><th class="num">Offset</th><th>Technique</th><th>SHA-256</th><th>Also in file system</th></tr></thead><tbody>${rows}</tbody></table></div>` : ''}
  </div></details>`;
}

function advancedBlock() {
  const hist = S.history.slice(0, 10).map(h => `<tr class="clickable ${S.job?.id === h.id ? 'selected' : ''}" data-job="${h.id}">
    <td class="small nowrap"><b>${esc(when(h.created_at))}</b></td><td class="muted small trunc">${esc(h.message || '')}</td>
    <td style="text-align:right">${statusBadge(h.status)}</td></tr>`).join('');
  return `
    ${hist ? `<details class="more card-like"><summary>Previous scans (${S.history.length})</summary><div class="more-body table-wrap"><table class="table"><tbody>${hist}</tbody></table></div></details>` : ''}
    <details class="more card-like"><summary>Advanced options</summary><div class="more-body stack" style="gap:12px">
      <div class="field"><span class="label">File types for the deep scan</span>
        <div class="row" style="gap:6px">${S.formats.map(f => `<button class="chip ${!S.types.length || S.types.includes(f.ext) ? 'on' : ''}" data-type="${f.ext}" title="${esc(f.name)}">${f.ext.toUpperCase()}</button>`).join('')}</div></div>
      <label class="check"><input type="checkbox" id="rc-partial" ${S.partial ? 'checked' : ''}><span>Keep partly recovered pictures<span class="hint">Save JPEG/PNG/GIF files whose end is missing, marked as damaged.</span></span></label>
    </div></details>
    <details class="more card-like"><summary>Accuracy benchmark</summary><div class="more-body">${benchBody()}</div></details>`;
}

function benchBody() {
  const imgs = (S.sources?.labImages || []).filter(i => i.hasTruth);
  const b = S.bench;
  let res = '';
  if (b?.status === 'RUNNING') res = progressBlock(b.progress, b.message);
  else if (b?.status === 'FAILED') res = `<div class="notice bad">${icon('alert', 16)}<div>${esc(b.message)}</div></div>`;
  else if (b?.result) {
    const r = b.result;
    const pct = (v) => v == null ? '—' : `${Math.round(v * 100)}%`;
    res = `<table class="table" style="margin-top:10px"><thead><tr><th>Technique</th><th class="num">Found</th><th class="num">Correct</th><th class="num">Time</th></tr></thead><tbody>
      <tr><td>File system</td><td class="num">${r.fileSystem.recovered}/${r.fileSystem.of}</td><td class="num">—</td><td class="num">${r.fileSystem.seconds}s</td></tr>
      <tr><td>Deep scan</td><td class="num">${r.carving.recovered}/${r.carving.of}</td><td class="num">${pct(r.carving.precision)}</td><td class="num">${r.carving.seconds}s</td></tr>
      <tr><td><b>Both together</b></td><td class="num"><b>${r.combined.recovered}/${r.combined.of}</b></td><td class="num"></td><td class="num">${r.carving.throughputMBps} MB/s</td></tr></tbody></table>
      <div class="muted small" style="margin-top:6px">Counted only when the recovered file is byte-for-byte identical to the original (SHA-256).</div>`;
  }
  return `<p class="small" style="color:var(--text-2);margin-bottom:10px">Measures how many planted files WipeX recovers from a sample disk whose contents are known exactly.</p>
    ${imgs.length ? `<div class="row"><select class="select" id="bm-img" style="flex:1">${imgs.map(i => `<option value="${i.id}" ${i.id === S.benchImage ? 'selected' : ''}>${esc(i.model)}</option>`).join('')}</select>
      <button class="btn btn-secondary" id="bm-run" ${b?.status === 'RUNNING' ? 'disabled' : ''}>Run benchmark</button></div>` : '<div class="muted small">Needs a sample disk.</div>'}
    ${res}`;
}

async function runBenchmark() {
  try {
    const { jobId } = await api('/api/benchmark', { method: 'POST', body: { imageId: S.benchImage } });
    S.bench = { status: 'RUNNING', progress: 0, message: 'Starting' };
    render();
    S.bench = await waitForJob(jobId, j => { S.bench = j; if (root.classList.contains('active')) render(); });
    render();
  } catch (e) { reportError(e); }
}
