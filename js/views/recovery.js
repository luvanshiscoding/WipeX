/** M3 — Carving & Recovery: pick a source, run file-system recovery + carving, review and export. */
import { api, apiUrl, badge, bytes, esc, getOperator, icon, progressBlock, reportError, short, statusBadge,
  toast, waitForJob, when } from '../core.js';

const S = {
  sourceType: 'lab', labId: '', evidenceId: '', path: '', useFs: true, useCarving: true, types: [], partial: false,
  images: [], evidence: [], formats: [], job: null, tab: 'deleted', history: [], bench: null, benchImage: '',
};
let root;

export async function show(el, params) {
  root = el;
  if (params.evidence) { S.sourceType = 'evidence'; S.evidenceId = params.evidence; }
  root.innerHTML = '<div class="empty">Loading…</div>';
  const [images, cases, formats, history] = await Promise.all([
    api('/api/lab/images').catch(() => []), api('/api/cases').catch(() => []),
    api('/api/recovery/formats').catch(() => []), api('/api/jobs?kind=recovery').catch(() => []),
  ]);
  S.images = images;
  S.formats = formats;
  S.history = history;
  S.labId = S.labId || images.find(i => i.hasTruth)?.id || images[0]?.id || '';
  S.benchImage = S.benchImage || images.find(i => i.hasTruth)?.id || '';
  const details = await Promise.all(cases.map(c => api(`/api/cases/${c.id}`).catch(() => null)));
  S.evidence = details.filter(Boolean).flatMap(c => c.evidence.map(e => ({ ...e, caseTitle: c.title })));
  if (!S.evidenceId && S.evidence.length) S.evidenceId = S.evidence[0].id;
  render();
}

function render() {
  const running = S.job?.status === 'RUNNING';
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Carving & Recovery <span class="code-tag">M3</span></h1>
        <p class="page-desc">Recover deleted files from disk images, acquired evidence or devices. The source is only ever read; recovered files are written to the WipeX workspace with their hashes.</p>
      </div>
    </div>
    <div class="grid cols-side">
      <div class="stack">
        <div class="card">
          <div class="card-head"><span class="card-title">1 · Source</span>
            <div class="seg">${[['lab', 'Lab image'], ['evidence', 'Case evidence'], ['path', 'Path or device']].map(([k, l]) =>
              `<button data-src="${k}" class="${S.sourceType === k ? 'on' : ''}">${l}</button>`).join('')}</div></div>
          <div class="card-body">${sourceBody()}</div>
        </div>
        ${S.job ? resultsCard() : ''}
        ${benchCard()}
      </div>
      <div class="stack">
        <div class="card">
          <div class="card-head"><span class="card-title">2 · Techniques</span></div>
          <div class="card-body stack" style="gap:12px">
            <label class="check"><input type="checkbox" id="rc-fs" ${S.useFs ? 'checked' : ''}><span>File-system analysis<span class="hint">The Sleuth Kit lists deleted directory entries (NTFS, FAT, exFAT, ext, HFS+, ISO) and reads their clusters.</span></span></label>
            <label class="check"><input type="checkbox" id="rc-carve" ${S.useCarving ? 'checked' : ''}><span>Signature + structure carving<span class="hint">Finds files without any file system — after formatting or directory damage. Reassembles fragmented PNG and ZIP files.</span></span></label>
            <div class="field"><span class="label">File types to carve</span>
              <div class="row" style="gap:6px">${S.formats.map(f => `<button class="chip ${!S.types.length || S.types.includes(f.ext) ? 'on' : ''}" data-type="${f.ext}" title="${esc(f.name)}">${f.ext.toUpperCase()}</button>`).join('')}</div>
              <span class="hint">All types when none are deselected.</span></div>
            <label class="check"><input type="checkbox" id="rc-partial" ${S.partial ? 'checked' : ''}><span>Keep partial images<span class="hint">Save truncated JPEG/PNG/GIF files, marked as partial.</span></span></label>
          </div>
          <div class="card-foot"><button class="btn btn-primary" id="rc-start" ${running ? 'disabled' : ''}>${icon('search', 16)} ${running ? 'Scanning…' : 'Start scan'}</button></div>
        </div>
        ${historyCard()}
      </div>
    </div>`;
  bind();
}

function sourceBody() {
  if (S.sourceType === 'lab') {
    return S.images.length ? `
      <div class="field"><label>Lab disk image</label>
        <select class="select" id="rc-lab">${S.images.map(i => `<option value="${i.id}" ${i.id === S.labId ? 'selected' : ''}>${esc(i.model)} — ${esc(i.capacity)}${i.hasTruth ? ' · has ground truth' : ''}</option>`).join('')}</select>
        <span class="hint">Lab images contain live, deleted, fragmented and orphaned files. Create more in Drive Eraser.</span></div>`
      : '<div class="empty"><strong>No lab images</strong><a href="#/drive">Create one in Drive Eraser</a>.</div>';
  }
  if (S.sourceType === 'evidence') {
    return S.evidence.length ? `
      <div class="field"><label>Acquired evidence</label>
        <select class="select" id="rc-ev">${S.evidence.map(e => `<option value="${e.id}" ${e.id === S.evidenceId ? 'selected' : ''}>${esc(e.id)} · ${esc(e.label)} (${esc(e.caseTitle)})</option>`).join('')}</select>
        <span class="hint">Scans the hashed working copy, never the original. Results are linked to the case.</span></div>`
      : '<div class="empty"><strong>No evidence acquired yet</strong><a href="#/cases">Open a case and acquire an image</a> to recover from it with chain of custody.</div>';
  }
  return `
    <div class="field"><label for="rc-path">Image file or device path</label>
      <input class="input mono" id="rc-path" value="${esc(S.path)}" placeholder="D:\\images\\usb.dd   or   \\\\.\\PhysicalDrive1   or   /dev/sdb">
      <span class="hint">Opened read-only. Physical devices need administrator rights. For evidential work, acquire the device into a case first.</span></div>`;
}

function bind() {
  root.querySelectorAll('[data-src]').forEach(b => b.addEventListener('click', () => { S.sourceType = b.dataset.src; render(); }));
  root.querySelector('#rc-lab')?.addEventListener('change', e => { S.labId = e.target.value; });
  root.querySelector('#rc-ev')?.addEventListener('change', e => { S.evidenceId = e.target.value; });
  root.querySelector('#rc-path')?.addEventListener('input', e => { S.path = e.target.value; });
  root.querySelector('#rc-fs').addEventListener('change', e => { S.useFs = e.target.checked; });
  root.querySelector('#rc-carve').addEventListener('change', e => { S.useCarving = e.target.checked; });
  root.querySelector('#rc-partial').addEventListener('change', e => { S.partial = e.target.checked; });
  root.querySelectorAll('[data-type]').forEach(b => b.addEventListener('click', () => {
    const all = S.formats.map(f => f.ext);
    let cur = S.types.length ? [...S.types] : [...all];
    cur = cur.includes(b.dataset.type) ? cur.filter(t => t !== b.dataset.type) : [...cur, b.dataset.type];
    S.types = cur.length === all.length || !cur.length ? [] : cur;
    render();
  }));
  root.querySelector('#rc-start').addEventListener('click', start);
  root.querySelectorAll('[data-tab]').forEach(b => b.addEventListener('click', () => { S.tab = b.dataset.tab; render(); }));
  root.querySelectorAll('[data-job]').forEach(r => r.addEventListener('click', () => loadJob(r.dataset.job)));
  root.querySelector('#bm-img')?.addEventListener('change', e => { S.benchImage = e.target.value; });
  root.querySelector('#bm-run')?.addEventListener('click', runBenchmark);
}

async function start() {
  if (!S.useFs && !S.useCarving) { toast('Choose at least one technique', 'bad'); return; }
  const source = S.sourceType === 'lab' ? { type: 'lab', id: S.labId }
    : S.sourceType === 'evidence' ? { type: 'evidence', id: S.evidenceId } : { type: 'path', path: S.path.trim() };
  if (!source.id && !source.path) { toast('Choose a source first', 'bad'); return; }
  try {
    const { jobId } = await api('/api/recovery/scan', { method: 'POST', body: {
      source, useFs: S.useFs, useCarving: S.useCarving, types: S.types.length ? S.types : null,
      includePartial: S.partial, actor: getOperator() || 'system' } });
    S.job = { id: jobId, status: 'RUNNING', progress: 0, message: 'Starting' };
    S.tab = 'deleted';
    render();
    const job = await waitForJob(jobId, j => { S.job = j; if (root.classList.contains('active')) render(); });
    S.job = job;
    S.history = await api('/api/jobs?kind=recovery').catch(() => S.history);
    render();
    if (job.status === 'COMPLETED') toast(job.result.summary, 'ok'); else toast(job.message, 'bad');
  } catch (e) { reportError(e); }
}

async function loadJob(id) {
  try {
    S.job = await api(`/api/jobs/${id}`);
    S.tab = 'deleted';
    render();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (e) { reportError(e); }
}

const isImg = (name) => /\.(jpe?g|png|gif|bmp)$/i.test(name || '');
const fileUrl = (p, dl) => apiUrl(`/api/recovery/file?path=${encodeURIComponent(p)}${dl ? '&download=true' : ''}`);
const CONTENT = { intact: ['Intact', 'ok'], damaged: ['Damaged', 'warn'], overwritten: ['Overwritten', 'bad'], unreadable: ['Unreadable', 'bad'], unverified: ['Unverified', ''] };

function resultsCard() {
  const j = S.job;
  if (j.status === 'RUNNING') return `<div class="card card-pad"><div class="card-title" style="margin-bottom:10px">Scanning ${esc(j.params?.label || '')}</div>${progressBlock(j.progress, j.message)}</div>`;
  if (j.status === 'FAILED') return `<div class="verdict bad"><span class="verdict-icon">${icon('x', 22, 2.6)}</span><div><div class="verdict-title">Scan failed</div><div class="verdict-text">${esc(j.message)}</div></div></div>`;
  const r = j.result;
  const fs = r.filesystem || {};
  const entries = fs.entries || [];
  const deleted = entries.filter(e => e.deleted && !e.isDir);
  const carved = r.carving?.files || [];
  const onlyCarved = carved.filter(f => !f.alsoFoundAs);
  const repaired = carved.filter(f => f.status === 'repaired');
  const tiles = [
    ['File systems', (fs.volumes || []).map(v => v.fsType).join(', ') || 'None found'],
    ['Deleted entries', deleted.length], ['Carved files', carved.length],
    ['Only found by carving', onlyCarved.length], ['Fragments reassembled', repaired.length],
  ];
  return `
    <div class="card">
      <div class="card-head">
        <div><div class="card-title">Results · ${esc(r.sourceLabel || r.source)}</div><div class="card-sub">${esc(j.id)} · ${when(j.finished_at)} · ${r.seconds}s</div></div>
        <a class="btn btn-primary btn-sm" href="${apiUrl(`/api/recovery/${j.id}/report.pdf`)}" target="_blank" rel="noopener">${icon('download', 14)} PDF report</a>
      </div>
      <div class="card-body" style="padding-bottom:0">
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px">
          ${tiles.map(([k, v]) => `<div class="stat"><div class="stat-label">${k}</div><div class="stat-value" style="font-size:${typeof v === 'number' ? 21 : 14}px">${esc(v)}</div></div>`).join('')}
        </div>
      </div>
      <div class="tabs" style="margin-top:14px;border-radius:0">
        <button class="tab ${S.tab === 'deleted' ? 'on' : ''}" data-tab="deleted">Deleted files<span class="count">${deleted.length}</span></button>
        <button class="tab ${S.tab === 'carved' ? 'on' : ''}" data-tab="carved">Carved files<span class="count">${carved.length}</span></button>
        <button class="tab ${S.tab === 'all' ? 'on' : ''}" data-tab="all">File system listing<span class="count">${entries.length}</span></button>
      </div>
      <div class="table-wrap" style="max-height:520px;overflow:auto">${S.tab === 'deleted' ? deletedTable(deleted, fs) : S.tab === 'carved' ? carvedTable(carved) : allTable(entries)}</div>
    </div>`;
}

function deletedTable(rows, fs) {
  if (!fs.available) return `<div class="empty">${esc(fs.reason || 'File-system analysis was not run.')}</div>`;
  if (!rows.length) return `<div class="empty"><strong>No deleted entries</strong>${esc(fs.reason || 'The file system has no deleted directory entries.')}</div>`;
  return `<table class="table"><thead><tr><th></th><th>Original path</th><th class="num">Size</th><th>Modified</th><th>Content</th><th>SHA-256</th><th></th></tr></thead><tbody>
    ${rows.map(e => {
      const [label, tone] = CONTENT[e.contentStatus] || ['—', ''];
      const thumb = e.recoveredPath && isImg(e.name) && e.contentStatus === 'intact' ? `<img class="thumb" src="${fileUrl(e.recoveredPath)}" alt="" loading="lazy">` : `<span class="thumb" style="display:grid;place-items:center;color:var(--text-3)">${icon('fileX', 16)}</span>`;
      return `<tr><td>${thumb}</td><td class="trunc" title="${esc(e.path)}">${esc(e.path)}${e.detail ? `<div class="muted small">${esc(e.detail)}</div>` : ''}</td>
        <td class="num">${bytes(e.size)}</td><td class="nowrap">${esc(when(e.modified))}</td><td>${badge(label, tone)}</td>
        <td class="mono" title="${esc(e.sha256 || '')}">${short(e.sha256, 10)}</td>
        <td class="nowrap">${e.recoveredPath ? `<a class="btn btn-ghost btn-sm" href="${fileUrl(e.recoveredPath)}" target="_blank" rel="noopener">Open</a><a class="btn btn-ghost btn-sm" href="${fileUrl(e.recoveredPath, true)}">${icon('download', 14)}</a>` : ''}</td></tr>`;
    }).join('')}</tbody></table>`;
}

const TECH = { 'signature + structure': 'Structure-validated', 'bifragment gap carving (CRC-validated)': 'Gap carving · PNG CRC',
  'bifragment gap carving (ZIP CRC-validated)': 'Gap carving · ZIP CRC', 'signature + structure (incomplete)': 'Incomplete structure' };

function carvedTable(rows) {
  if (!rows.length) return '<div class="empty"><strong>No files carved</strong>No valid file structures were found in the scanned data.</div>';
  const STATUS = { valid: ['Valid', 'ok'], repaired: ['Reassembled', 'blue'], partial: ['Partial', 'warn'] };
  return `<table class="table"><thead><tr><th></th><th>File</th><th class="num">Size</th><th>Status</th><th>How it was found</th><th></th></tr></thead><tbody>
    ${rows.map(f => {
      const [label, tone] = STATUS[f.status] || [f.status, ''];
      const thumb = isImg(f.path) ? `<img class="thumb" src="${fileUrl(f.path)}" alt="" loading="lazy">` : `<span class="thumb" style="display:grid;place-items:center;color:var(--text-3)">${icon('file', 16)}</span>`;
      const dims = f.info?.width ? ` · ${f.info.width}×${f.info.height}` : f.info?.pages ? ` · ${f.info.pages} page(s)` : '';
      return `<tr><td>${thumb}</td>
        <td><div class="row" style="gap:6px;flex-wrap:nowrap"><span class="mono">${esc(f.id)}</span>${badge(f.ext.toUpperCase())}</div>
          <div class="muted small">${esc(f.type)}${dims} · offset <span class="mono">${f.offset.toLocaleString()}</span></div></td>
        <td class="num">${bytes(f.size)}</td>
        <td>${badge(label, tone)}</td>
        <td class="small"><div>${esc(TECH[f.technique] || f.technique)}${f.fragments?.length > 1 ? ` · ${f.fragments.length} fragments` : ''}</div>
          <div class="muted trunc" style="max-width:240px" title="${esc(f.alsoFoundAs || '')}">${f.alsoFoundAs ? `Also in file system: ${esc(f.alsoFoundAs)}` : 'Not visible in the file system'}</div></td>
        <td class="nowrap"><a class="btn btn-ghost btn-sm" href="${fileUrl(f.path)}" target="_blank" rel="noopener">Open</a><a class="btn btn-ghost btn-sm" href="${fileUrl(f.path, true)}" title="Download">${icon('download', 14)}</a></td></tr>`;
    }).join('')}</tbody></table>`;
}

function allTable(rows) {
  if (!rows.length) return '<div class="empty">No file-system entries.</div>';
  return `<table class="table"><thead><tr><th>Path</th><th class="num">Size</th><th>Modified</th><th>Created</th><th class="num">Inode</th><th>State</th></tr></thead><tbody>
    ${rows.map(e => `<tr><td class="trunc">${icon(e.isDir ? 'folder' : e.deleted ? 'fileX' : 'file', 14)} ${esc(e.path)}</td><td class="num">${e.isDir ? '' : bytes(e.size)}</td>
      <td class="nowrap">${esc(when(e.modified))}</td><td class="nowrap">${esc(when(e.created))}</td><td class="num mono">${e.inode ?? ''}</td>
      <td>${e.deleted ? badge('Deleted', 'warn') : badge('Live')}</td></tr>`).join('')}</tbody></table>`;
}

function historyCard() {
  if (!S.history.length) return '';
  return `<div class="card"><div class="card-head"><span class="card-title">Previous scans</span></div>
    <div class="table-wrap" style="max-height:260px;overflow:auto"><table class="table"><tbody>
      ${S.history.slice(0, 12).map(h => `<tr class="clickable ${S.job?.id === h.id ? 'selected' : ''}" data-job="${h.id}">
        <td><div class="small"><b>${esc(when(h.created_at))}</b></div><div class="muted small trunc" style="max-width:190px">${esc(h.message || '')}</div></td>
        <td style="text-align:right">${statusBadge(h.status)}</td></tr>`).join('')}
    </tbody></table></div></div>`;
}

function benchCard() {
  const withTruth = S.images.filter(i => i.hasTruth);
  const b = S.bench;
  let res = '';
  if (b?.status === 'RUNNING') res = progressBlock(b.progress, b.message);
  else if (b?.status === 'FAILED') res = `<div class="notice bad">${icon('alert', 16)}<div>${esc(b.message)}</div></div>`;
  else if (b?.result) {
    const r = b.result;
    const pct = (v) => v == null ? '—' : `${Math.round(v * 100)}%`;
    res = `<table class="table" style="border:1px solid var(--border);border-radius:6px">
      <thead><tr><th>Technique</th><th class="num">Recall</th><th class="num">Precision</th><th class="num">Time</th></tr></thead><tbody>
      <tr><td>File system</td><td class="num">${pct(r.fileSystem.recall)} <span class="muted">(${r.fileSystem.recovered}/${r.fileSystem.of})</span></td><td class="num">—</td><td class="num">${r.fileSystem.seconds}s</td></tr>
      <tr><td>Carving</td><td class="num">${pct(r.carving.recall)} <span class="muted">(${r.carving.recovered}/${r.carving.of})</span></td><td class="num">${pct(r.carving.precision)}</td><td class="num">${r.carving.seconds}s</td></tr>
      <tr><td><b>Combined</b></td><td class="num"><b>${pct(r.combined.recall)}</b> <span class="muted">(${r.combined.recovered}/${r.combined.of})</span></td><td class="num"></td><td class="num">${r.carving.throughputMBps} MB/s</td></tr>
      </tbody></table>
      <div class="muted small" style="margin-top:6px">Byte-exact matches (SHA-256) against ground truth. ${r.carving.repairedFragments} fragmented file(s) reassembled.${r.missed.length ? ` Missed: ${esc(r.missed.join(', '))}` : ''}</div>
      <table class="table" style="border:1px solid var(--border);border-radius:6px;margin-top:10px">
        <thead><tr><th>Type</th><th class="num">In image</th><th class="num">Fragmented</th><th class="num">Carved</th><th class="num">File system</th></tr></thead>
        <tbody>${Object.entries(r.perType).map(([t, v]) => `<tr><td>${esc(t.toUpperCase())}</td><td class="num">${v.inTruth}</td><td class="num">${v.fragmented}</td><td class="num">${v.carved}</td><td class="num">${v.fsRecovered}</td></tr>`).join('')}</tbody></table>`;
  }
  return `<div class="card"><div class="card-head"><div><div class="card-title">${icon('chart', 15)} Benchmark</div><div class="card-sub">Recall and precision against known ground truth</div></div></div>
    <div class="card-body stack" style="gap:10px">
      ${withTruth.length ? `<div class="row"><select class="select" id="bm-img" style="flex:1">${withTruth.map(i => `<option value="${i.id}" ${i.id === S.benchImage ? 'selected' : ''}>${esc(i.model)}</option>`).join('')}</select>
        <button class="btn btn-secondary" id="bm-run" ${b?.status === 'RUNNING' ? 'disabled' : ''}>Run</button></div>` : '<div class="muted small">Needs a sample lab image (it carries a ground-truth file).</div>'}
      ${res}
    </div></div>`;
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
