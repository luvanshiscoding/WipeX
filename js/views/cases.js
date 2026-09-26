/** Cases: evidence acquisition with hashes, legal holds (evidence lock), chain of custody. */
import { ago, api, badge, bytes, esc, getOperator, icon, modal, pickPaths, progressBlock, reportError,
  requireOperator, short, statusBadge, toast, waitForJob, when } from '../core.js';
import { actionLabel } from './overview.js';

const S = { cases: [], current: null, detail: null, tab: 'evidence', acquiring: null, dual: false, images: [] };
let root;

export async function show(el) {
  root = el;
  await refresh();
}

async function refresh(keep = true) {
  try {
    const [cases, dual, images] = await Promise.all([api('/api/cases'), api('/api/settings/dual-approval'), api('/api/lab/images').catch(() => [])]);
    S.cases = cases;
    S.dual = dual.enabled;
    S.images = images;
    if (!keep || !S.cases.find(c => c.id === S.current)) S.current = S.cases[0]?.id || null;
    S.detail = S.current ? await api(`/api/cases/${S.current}`) : null;
  } catch (e) { reportError(e); }
  render();
}

function render() {
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Cases</h1>
        <p class="page-desc">Keep evidence, legal holds and custody records together. A device or folder under an active hold cannot be erased by any module.</p>
      </div>
      <button class="btn btn-primary" id="cs-new">${icon('plus', 16)} New case</button>
    </div>
    <div class="grid cols-list">
      <div class="stack">
        <div class="card">
          ${S.cases.length ? `<div class="table-wrap"><table class="table"><tbody>${S.cases.map(c => `
            <tr class="clickable ${c.id === S.current ? 'selected' : ''}" data-case="${c.id}">
              <td><div style="font-weight:600">${esc(c.title)}</div><div class="muted small">${esc(c.id)} · ${esc(c.investigator)}</div>
                <div class="row" style="gap:5px;margin-top:5px">${statusBadge(c.status)}${c.evidenceCount ? badge(`${c.evidenceCount} evidence`) : ''}${c.activeHolds ? badge(`${c.activeHolds} hold${c.activeHolds > 1 ? 's' : ''}`, 'bad') : ''}</div></td>
            </tr>`).join('')}</tbody></table></div>`
          : '<div class="empty"><strong>No cases yet</strong>Create a case to acquire evidence and place legal holds.</div>'}
        </div>
        <div class="card card-pad stack" style="gap:10px">
          <div class="card-title">Erasure authorization</div>
          <label class="check"><input type="checkbox" id="cs-dual" ${S.dual ? 'checked' : ''}>
            <span>Two-person rule<span class="hint">Every erasure (M1 and M2) must name an approver who is not the operator.</span></span></label>
        </div>
      </div>
      <div>${S.detail ? detailHtml(S.detail) : '<div class="card"><div class="empty">Select or create a case.</div></div>'}</div>
    </div>`;

  root.querySelector('#cs-new').addEventListener('click', newCase);
  root.querySelectorAll('[data-case]').forEach(r => r.addEventListener('click', async () => {
    S.current = r.dataset.case;
    S.detail = await api(`/api/cases/${S.current}`).catch(() => null);
    render();
  }));
  root.querySelector('#cs-dual').addEventListener('change', async (e) => {
    try {
      await api('/api/settings/dual-approval', { method: 'POST', body: { enabled: e.target.checked, actor: getOperator() || 'system' } });
      toast(`Two-person rule ${e.target.checked ? 'enabled' : 'disabled'}`, 'ok');
    } catch (err) { reportError(err); }
  });
  if (S.detail) bindDetail();
}

function detailHtml(c) {
  const tabs = [['evidence', 'Evidence', c.evidence.length], ['holds', 'Legal holds', c.holds.filter(h => h.active).length],
                ['custody', 'Custody log', c.custody.length], ['jobs', 'Jobs', (c.jobs || []).length]];
  return `
    <div class="card">
      <div class="card-head">
        <div><div class="card-title" style="font-size:17px">${esc(c.title)}</div>
          <div class="card-sub">${esc(c.id)} · Investigator ${esc(c.investigator)} · opened ${esc(when(c.created_at))}</div>
          ${c.description ? `<div class="small" style="margin-top:6px;color:var(--text-2)">${esc(c.description)}</div>` : ''}</div>
        <div class="row">${statusBadge(c.status)}<button class="btn btn-secondary btn-sm" id="cs-status">${c.status === 'OPEN' ? 'Close case' : 'Reopen'}</button></div>
      </div>
      <div class="tabs" style="border-radius:0">${tabs.map(([k, l, n]) => `<button class="tab ${S.tab === k ? 'on' : ''}" data-tab="${k}">${l}<span class="count">${n}</span></button>`).join('')}</div>
      <div>${({ evidence: evidenceTab, holds: holdsTab, custody: custodyTab, jobs: jobsTab })[S.tab](c)}</div>
    </div>`;
}

function evidenceTab(c) {
  return `
    <div class="card-body stack">
      <div class="row between"><span class="muted small">Images are copied into the case folder; SHA-256 and MD5 are computed during the copy and re-checked afterwards.</span>
        <button class="btn btn-primary btn-sm" id="ev-acquire" ${c.status !== 'OPEN' ? 'disabled' : ''}>${icon('plus', 14)} Acquire evidence</button></div>
      ${S.acquiring ? progressBlock(S.acquiring.progress, S.acquiring.message) : ''}
      ${c.evidence.length ? `<div class="table-wrap" style="border:1px solid var(--border);border-radius:6px"><table class="table">
        <thead><tr><th>Item</th><th class="num">Size</th><th>SHA-256</th><th>Acquired</th><th></th></tr></thead><tbody>
        ${c.evidence.map(e => `<tr>
          <td><b class="mono">${esc(e.id)}</b> · ${esc(e.label)}<div class="muted small mono trunc" style="max-width:260px" title="${esc(e.source_path)}">${esc(e.source_path)}</div></td>
          <td class="num">${bytes(e.size_bytes)}</td>
          <td class="mono" title="${esc(e.sha256)}">${short(e.sha256, 14)}</td>
          <td class="small nowrap">${esc(when(e.acquired_at))}<div class="muted">${esc(e.acquired_by)}</div></td>
          <td class="nowrap"><button class="btn btn-ghost btn-sm" data-verify="${e.id}">Verify hash</button>
            <a class="btn btn-ghost btn-sm" href="#/recovery?evidence=${e.id}">Recover</a></td></tr>`).join('')}
        </tbody></table></div>` : '<div class="empty">No evidence acquired for this case.</div>'}
    </div>`;
}

function holdsTab(c) {
  return `
    <div class="card-body stack">
      <div class="row between"><span class="muted small">While a hold is active, WipeX refuses to erase the matching device or any path inside the held folder.</span>
        <button class="btn btn-primary btn-sm" id="hd-add">${icon('hold', 14)} Place hold</button></div>
      ${c.holds.length ? `<div class="table-wrap" style="border:1px solid var(--border);border-radius:6px"><table class="table">
        <thead><tr><th>Hold</th><th>Target</th><th>Reason</th><th>Placed</th><th>Status</th><th></th></tr></thead><tbody>
        ${c.holds.map(h => `<tr><td class="mono">${esc(h.id)}</td>
          <td><div class="small muted">${esc({ device_serial: 'Device serial', device_path: 'Device / image path', path: 'Folder or file' }[h.target_kind])}</div><div class="mono small trunc" title="${esc(h.target)}">${esc(h.target)}</div></td>
          <td class="small">${esc(h.reason || '—')}</td><td class="small nowrap">${esc(when(h.created_at))}</td>
          <td>${h.active ? badge('Active', 'bad') : badge(`Released ${when(h.released_at)}`)}</td>
          <td>${h.active ? `<button class="btn btn-ghost btn-sm" data-release="${h.id}">Release</button>` : ''}</td></tr>`).join('')}
        </tbody></table></div>` : '<div class="empty">No legal holds on this case.</div>'}
    </div>`;
}

function custodyTab(c) {
  if (!c.custody.length) return '<div class="empty">No custody events yet.</div>';
  return `<div class="card-body"><div class="timeline">${c.custody.map(e => `
    <div class="tl-item"><span class="tl-dot"></span><div>
      <div class="tl-title">${esc(actionLabel(e.action))}</div>
      <div class="tl-meta">${esc(when(e.ts))} · ${esc(e.actor)} · entry #${e.seq} · <span class="mono">${short(e.hash, 16)}</span></div>
      ${e.target ? `<div class="small mono trunc" style="max-width:640px">${esc(e.target)}</div>` : ''}
    </div></div>`).join('')}</div></div>`;
}

function jobsTab(c) {
  const jobs = c.jobs || [];
  if (!jobs.length) return '<div class="empty">No jobs linked to this case.</div>';
  return `<div class="table-wrap"><table class="table"><thead><tr><th>Job</th><th>Kind</th><th>Status</th><th>Started</th><th></th></tr></thead><tbody>
    ${jobs.map(j => `<tr><td class="mono">${esc(j.id)}</td><td>${esc(j.kind)}</td><td>${statusBadge(j.status)}</td><td class="small">${esc(ago(j.created_at))}</td>
      <td>${j.kind === 'recovery' ? `<a class="btn btn-ghost btn-sm" href="#/recovery">View</a>` : ''}</td></tr>`).join('')}</tbody></table></div>`;
}

function bindDetail() {
  root.querySelectorAll('[data-tab]').forEach(b => b.addEventListener('click', () => { S.tab = b.dataset.tab; render(); }));
  root.querySelector('#cs-status')?.addEventListener('click', toggleStatus);
  root.querySelector('#ev-acquire')?.addEventListener('click', acquire);
  root.querySelector('#hd-add')?.addEventListener('click', addHold);
  root.querySelectorAll('[data-verify]').forEach(b => b.addEventListener('click', async () => {
    b.disabled = true; b.textContent = 'Hashing…';
    try {
      const r = await api(`/api/evidence/${b.dataset.verify}/verify`, { method: 'POST', body: { actor: getOperator() || 'system' } });
      toast(r.match ? 'Hash matches the acquisition record' : 'HASH MISMATCH — evidence has changed', r.match ? 'ok' : 'bad');
      await refresh();
    } catch (e) { reportError(e); }
  }));
  root.querySelectorAll('[data-release]').forEach(b => b.addEventListener('click', async () => {
    const actor = await requireOperator();
    if (!actor) return;
    try { await api(`/api/holds/${b.dataset.release}/release`, { method: 'POST', body: { actor } }); toast('Hold released', 'ok'); await refresh(); }
    catch (e) { reportError(e); }
  }));
}

async function newCase() {
  const res = await modal({
    title: 'New case',
    body: `
      <div class="field"><label>Title</label><input class="input" id="nc-title" placeholder="e.g. Seized laptop — FIR 118/2026"></div>
      <div class="field"><label>Investigator</label><input class="input" id="nc-inv" value="${esc(getOperator())}"></div>
      <div class="field"><label>Description</label><textarea class="textarea" id="nc-desc" placeholder="Optional"></textarea></div>`,
    actions: [{ label: 'Cancel', value: null }, { label: 'Create case', cls: 'btn-primary', onClick: bd => {
      const title = bd.querySelector('#nc-title').value.trim(), inv = bd.querySelector('#nc-inv').value.trim();
      if (!title || !inv) { toast('Title and investigator are required', 'bad'); return false; }
      return { title, investigator: inv, description: bd.querySelector('#nc-desc').value };
    } }],
  });
  if (!res) return;
  try {
    const c = await api('/api/cases', { method: 'POST', body: res });
    S.current = c.id;
    S.tab = 'evidence';
    await refresh();
    toast(`Case ${c.id} opened`, 'ok');
  } catch (e) { reportError(e); }
}

async function toggleStatus() {
  const actor = await requireOperator();
  if (!actor) return;
  try {
    await api(`/api/cases/${S.current}/status`, { method: 'POST', body: { status: S.detail.status === 'OPEN' ? 'CLOSED' : 'OPEN', actor } });
    await refresh();
  } catch (e) { reportError(e); }
}

async function acquire() {
  const actor = await requireOperator();
  if (!actor) return;
  const res = await modal({
    title: 'Acquire evidence',
    sub: 'The source is read once, copied into the case folder and hashed (SHA-256 + MD5). The copy is re-hashed to prove it is identical.',
    body: `
      <div class="field"><label>Source</label>
        <select class="select" id="aq-kind"><option value="lab">Lab disk image</option><option value="path">Image file or device path</option></select></div>
      <div class="field" id="aq-lab-f"><label>Lab image</label><select class="select" id="aq-lab">${S.images.map(i => `<option value="${i.id}">${esc(i.model)}</option>`).join('')}</select></div>
      <div class="field hidden" id="aq-path-f"><label>Path</label><div class="row"><input class="input mono" id="aq-path" placeholder="D:\\evidence\\usb.dd or \\\\.\\PhysicalDrive1" style="flex:1"><button class="btn btn-secondary btn-sm" id="aq-browse">Browse</button></div>
        <span class="hint">Physical devices need administrator rights.</span></div>
      <div class="field"><label>Label</label><input class="input" id="aq-label" placeholder="e.g. Suspect USB stick"></div>`,
    actions: [{ label: 'Cancel', value: null }, { label: 'Acquire', cls: 'btn-primary', onClick: bd => {
      const kind = bd.querySelector('#aq-kind').value;
      return kind === 'lab' ? { labImageId: bd.querySelector('#aq-lab').value, label: bd.querySelector('#aq-label').value }
        : { sourcePath: bd.querySelector('#aq-path').value.trim(), label: bd.querySelector('#aq-label').value };
    } }],
    onMount: (bd) => {
      const sync = () => { const lab = bd.querySelector('#aq-kind').value === 'lab'; bd.querySelector('#aq-lab-f').classList.toggle('hidden', !lab); bd.querySelector('#aq-path-f').classList.toggle('hidden', lab); };
      bd.querySelector('#aq-kind').addEventListener('change', sync);
      bd.querySelector('#aq-browse').addEventListener('click', async () => { const p = await pickPaths({ title: 'Choose an image file' }); if (p?.[0]) bd.querySelector('#aq-path').value = p[0]; });
    },
  });
  if (!res) return;
  try {
    const { jobId } = await api(`/api/cases/${S.current}/evidence`, { method: 'POST', body: { ...res, actor } });
    S.acquiring = { progress: 0, message: 'Starting' };
    render();
    const job = await waitForJob(jobId, j => { S.acquiring = j; if (root.classList.contains('active') && S.tab === 'evidence') render(); });
    S.acquiring = null;
    if (job.status === 'COMPLETED') toast(`Acquired ${job.result.id} · SHA-256 ${job.result.sha256.slice(0, 16)}…`, 'ok');
    else toast(job.message, 'bad');
    await refresh();
  } catch (e) { S.acquiring = null; reportError(e); render(); }
}

async function addHold() {
  const actor = await requireOperator();
  if (!actor) return;
  const devices = await api('/api/devices').catch(() => []);
  const res = await modal({
    title: 'Place legal hold',
    sub: 'Erasure of the held target will be refused until the hold is released.',
    body: `
      <div class="field"><label>Hold applies to</label><select class="select" id="hd-kind">
        <option value="device_serial">A storage device (by serial number)</option>
        <option value="path">A folder or file (and everything inside it)</option></select></div>
      <div class="field" id="hd-dev-f"><label>Device</label><select class="select" id="hd-dev">${devices.map(d => `<option value="${esc(d.serialNumber)}">${esc(d.model)} — ${esc(d.serialNumber)}</option>`).join('')}</select></div>
      <div class="field hidden" id="hd-path-f"><label>Path</label><div class="row"><input class="input mono" id="hd-path" style="flex:1"><button class="btn btn-secondary btn-sm" id="hd-browse">Browse</button></div></div>
      <div class="field"><label>Reason</label><input class="input" id="hd-reason" placeholder="e.g. Preserve for court proceedings"></div>`,
    actions: [{ label: 'Cancel', value: null }, { label: 'Place hold', cls: 'btn-danger', onClick: bd => {
      const kind = bd.querySelector('#hd-kind').value;
      const target = kind === 'path' ? bd.querySelector('#hd-path').value.trim() : bd.querySelector('#hd-dev').value;
      if (!target) { toast('Choose a target', 'bad'); return false; }
      return { targetKind: kind, target, reason: bd.querySelector('#hd-reason').value };
    } }],
    onMount: (bd) => {
      bd.querySelector('#hd-kind').addEventListener('change', e => {
        const p = e.target.value === 'path';
        bd.querySelector('#hd-dev-f').classList.toggle('hidden', p);
        bd.querySelector('#hd-path-f').classList.toggle('hidden', !p);
      });
      bd.querySelector('#hd-browse').addEventListener('click', async () => { const p = await pickPaths({ title: 'Choose the folder or file to hold' }); if (p?.[0]) bd.querySelector('#hd-path').value = p[0]; });
    },
  });
  if (!res) return;
  try {
    await api(`/api/cases/${S.current}/holds`, { method: 'POST', body: { ...res, actor } });
    S.tab = 'holds';
    toast('Legal hold placed', 'ok');
    await refresh();
  } catch (e) { reportError(e); }
}
