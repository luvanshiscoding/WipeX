/** Erase a whole drive (M1): device → method → erase & verify → certificate. Shown inside the Erase page. */
import qrcode from 'qrcode-generator';
import { api, apiUrl, badge, bytes, checksList, confirmDanger, demo, esc, getOperator, icon, modal, progressBlock,
  refreshDemo, reportError, sleep, statusBadge, toast, when } from '../core.js';

const S = { step: 1, devices: [], methods: [], selected: null, method: null, psid: '', wipeId: null, status: null, cert: null, loading: false, demo: undefined };
let root, appRef, pollToken = 0;
const visible = () => root?.isConnected && root.closest('.view')?.classList.contains('active');

export async function show(el, _params, app) {
  root = el;
  appRef = app;
  if (!S.methods.length) S.methods = await api('/api/methods').catch(() => []);
  if (S.step === 1 || S.demo !== demo.enabled) await loadDevices();
  render();
}

async function loadDevices(refresh = false) {
  S.loading = true;
  render();
  try {
    S.devices = await api(`/api/devices${refresh ? '?refresh=true' : ''}`);
    if (S.selected) S.selected = S.devices.find(d => d.id === S.selected.id) || null;
  } catch (e) { reportError(e); S.devices = []; }
  S.loading = false;
}

function render() {
  if (!root) return;
  if (S.demo !== demo.enabled) {             // demo mode switched: start over with the other set of drives
    if (S.demo !== undefined && S.step !== 3) { S.step = 1; S.selected = null; S.method = null; S.cert = null; }
    S.demo = demo.enabled;
  }
  if (S.shownStep !== S.step) {              // a new step starts at the top of the page
    if (S.shownStep !== undefined) window.scrollTo({ top: 0 });
    S.shownStep = S.step;
  }
  root.innerHTML = `
    ${stepper()}
    <div id="drive-body"></div>`;
  const body = root.querySelector('#drive-body');
  ({ 1: renderDevices, 2: renderMethods, 3: renderRun, 4: renderCert })[S.step](body);
}

function stepper() {
  const steps = ['Choose drive', 'Choose method', 'Erase and check', 'Certificate'];
  return `<div class="stepper">${steps.map((t, i) => {
    const n = i + 1;
    const cls = n === S.step ? 'on' : n < S.step ? 'done' : '';
    return `<div class="step ${cls}"><span class="step-num">${n < S.step ? icon('check', 13, 2.8) : n}</span><span class="step-text">${t}</span></div>`;
  }).join('')}</div>`;
}

// ── Step 1: device ─────────────────────────────────────────────────────────
function lockReason(d) {
  if (d.isBootDrive) return 'System disk — cannot be erased while the OS is running';
  if (d.legalHold) return `Under legal hold ${d.legalHold.id} (case ${d.legalHold.caseId})`;
  return '';
}

function deviceCard(d) {
  const locked = lockReason(d);
  const tags = [
    d.isImage ? badge('Sample disk', 'blue') : d.removable ? badge('USB', 'blue') : badge(d.interface || d.type || 'Disk'),
    d.isBootDrive ? badge('System disk', 'warn') : '',
    d.legalHold ? badge('Legal hold', 'bad') : '',
  ].join('');
  const files = d.isImage ? `${(d.currentFiles || []).length} files · ${(d.deletedRecoverableFiles || []).length} deleted` : (d.powerOnHours || '');
  return `
    <button class="pick ${S.selected?.id === d.id ? 'on' : ''} ${locked ? 'disabled' : ''}" data-id="${esc(d.id)}" ${locked ? 'aria-disabled="true"' : ''}>
      <div class="pick-top"><span class="pick-kind">${icon(d.isImage ? 'disk' : d.removable ? 'usb' : 'drive', 14)}${esc(d.type)}</span><span class="pick-tags">${tags}</span></div>
      <div class="pick-title">${esc(d.model)}</div>
      <div class="pick-meta"><span class="mono">${esc(d.maskedSerial || d.serialNumber || '')}</span><b>${esc(d.capacity || bytes(d.capacityBytes))}</b></div>
      <div class="pick-note ${locked ? (d.legalHold ? 'bad' : 'warn') : ''}">${esc(locked || files)}</div>
    </button>`;
}

function renderDevices(body) {
  const list = demo.enabled ? S.devices.filter(d => d.isImage)
    : S.devices.filter(d => !d.isImage).sort((x, y) => (y.removable ? 1 : 0) - (x.removable ? 1 : 0));
  if (S.selected && !list.some(x => x.id === S.selected.id)) S.selected = null;
  const d = S.selected;
  const usable = list.filter(x => !lockReason(x)).length;
  const empty = demo.enabled
    ? '<div class="empty"><strong>No sample disks</strong>Create one to practise safely.</div>'
    : `<div class="empty"><strong>Plug in a USB pendrive</strong>Then press Rescan. The system disk is always locked.
        <div class="row"><button class="btn btn-secondary btn-sm" id="dv-scan2">${icon('refresh', 14)} Rescan</button></div></div>`;
  body.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div><div class="card-title">${demo.enabled ? 'Sample disks' : 'Drives on this computer'}</div>
          <div class="card-sub">${demo.enabled ? 'Demo mode: file-backed disks that behave like real drives' : 'USB drives first · run WipeX as Administrator to erase'}</div></div>
        <div class="row">
          ${demo.enabled ? `<button class="btn btn-secondary btn-sm" id="dv-new">${icon('plus', 14)} New sample disk</button>` : ''}
          <button class="btn btn-secondary btn-sm" id="dv-scan">${icon('refresh', 14)} Rescan</button>
        </div>
      </div>
      <div class="card-body">
        ${S.loading ? '<div class="empty">Scanning devices…</div>' : list.length ? `<div class="pick-grid">${list.map(deviceCard).join('')}</div>` : empty}
        ${!S.loading && !demo.enabled && list.length && !usable ? '<div class="muted small" style="margin-top:10px">No USB drive found. Plug one in and press Rescan, or switch on <b>Demo mode</b> at the top to practise on a sample disk.</div>' : ''}
      </div>
    </div>
    ${d ? detailCard(d) : ''}
    <div class="row between" style="margin-top:16px">
      <span class="muted small">${d ? `Selected: <b>${esc(d.model)}</b>` : 'Select a drive to continue.'}</span>
      <button class="btn btn-primary btn-lg" id="dv-next" ${d && !lockReason(d) ? '' : 'disabled'}>Continue ${icon('arrow', 16)}</button>
    </div>`;

  body.querySelectorAll('.pick').forEach(b => b.addEventListener('click', () => {
    const dev = S.devices.find(x => x.id === b.dataset.id);
    if (lockReason(dev)) { toast(lockReason(dev), 'bad'); return; }
    S.selected = dev;
    render();
  }));
  const rescan = async () => { await loadDevices(true); render(); };
  body.querySelector('#dv-scan').addEventListener('click', rescan);
  body.querySelector('#dv-scan2')?.addEventListener('click', rescan);
  body.querySelector('#dv-new')?.addEventListener('click', newLabImage);
  body.querySelector('#dv-next').addEventListener('click', () => { S.step = 2; S.method = recommend(S.selected); render(); });
  body.querySelector('#dv-reset')?.addEventListener('click', resetImage);
  body.querySelector('#dv-del')?.addEventListener('click', deleteImage);
}

function detailCard(d) {
  const live = d.currentFiles || [], del = d.deletedRecoverableFiles || [];
  const rows = [...del.map(f => ({ ...f, del: true })), ...live].slice(0, 14);
  return `
    <div class="card" style="margin-top:16px">
      <div class="card-head">
        <div><div class="card-title">${esc(d.model)}</div><div class="card-sub mono">${esc(d.devicePath)}</div></div>
        ${d.isImage ? `<div class="row"><button class="btn btn-secondary btn-sm" id="dv-reset">${icon('refresh', 14)} Reset to sample data</button><button class="btn btn-danger-outline btn-sm" id="dv-del">${icon('trash', 14)} Delete image</button></div>` : ''}
      </div>
      <div class="card-body grid cols-2">
        <dl class="kv">
          <dt>Serial number</dt><dd class="mono">${esc(d.serialNumber)}</dd>
          <dt>Media</dt><dd>${esc(d.type)}${d.interface ? ` · ${esc(d.interface)}` : ''}</dd>
          <dt>Capacity</dt><dd>${esc(d.capacity)} (${Number(d.capacityBytes || 0).toLocaleString()} bytes)</dd>
          ${d.isImage ? '' : `<dt>Health</dt><dd>${esc(d.healthStatus || '—')}${d.reallocatedSectors ? ` · ${d.reallocatedSectors} reallocated sectors` : ''}</dd>
          <dt>Power-on</dt><dd>${esc(d.powerOnHours || '—')}</dd>`}
        </dl>
        <div>
          ${d.isImage ? `<div class="label" style="margin-bottom:6px">Contents found by The Sleuth Kit</div>
          ${rows.length ? `<div class="table-wrap" style="border:1px solid var(--border);border-radius:6px;max-height:230px;overflow:auto"><table class="table"><tbody>${rows.map(f => `
            <tr><td class="trunc">${icon(f.del ? 'fileX' : 'file', 14)} ${esc(f.name)}</td><td class="num">${esc(f.size)}</td><td>${f.del ? badge('Deleted', 'warn') : ''}</td></tr>`).join('')}
          </tbody></table></div>` : '<div class="muted small">No readable file system — the image is blank or already erased.</div>'}`
          : '<div class="notice warn">' + icon('alert', 16) + '<div><strong>Real drive</strong>Everything on it will be destroyed. Close any window that shows it before you start.</div></div>'}
          ${d.advice ? `<div class="rec-line">${icon('star', 14)} Recommended: <b>${esc(methodName(d.advice.recommended))}</b></div>` : ''}
        </div>
      </div>
    </div>`;
}

async function newLabImage() {
  const res = await modal({
    title: 'New lab disk image',
    sub: 'A file-backed disk that erasure and recovery treat exactly like a real device.',
    body: `
      <div class="field"><label>Name</label><input class="input" id="li-name" value="lab-disk-${Math.floor(Math.random() * 90 + 10)}"></div>
      <div class="field"><label>Contents</label><select class="select" id="li-kind">
        <option value="sample">FAT16 with sample files (live, deleted, fragmented, orphaned)</option>
        <option value="blank">Blank (zero-filled)</option></select></div>
      <div class="field"><label>Size (MB)</label><input class="input" id="li-size" type="number" min="16" max="1024" value="64"></div>`,
    actions: [{ label: 'Cancel', value: null }, { label: 'Create', cls: 'btn-primary', onClick: bd => ({
      name: bd.querySelector('#li-name').value, kind: bd.querySelector('#li-kind').value, sizeMb: +bd.querySelector('#li-size').value }) }],
  });
  if (!res) return;
  try {
    toast('Creating lab image…');
    const img = await api('/api/lab/images', { method: 'POST', body: res });
    await loadDevices();
    S.selected = S.devices.find(d => d.id === img.id) || null;
    render();
    toast(`Created ${img.model}`, 'ok');
  } catch (e) { reportError(e); }
}

async function resetImage() {
  try {
    await api(`/api/lab/images/${S.selected.id}/reset`, { method: 'POST' });
    await loadDevices();
    render();
    toast('Image rebuilt with sample files', 'ok');
  } catch (e) { reportError(e); }
}

async function deleteImage() {
  const ok = await modal({ title: 'Delete lab image?', sub: esc(S.selected.devicePath), actions: [{ label: 'Cancel', value: false }, { label: 'Delete', cls: 'btn-danger', value: true }] });
  if (!ok) return;
  try {
    await api(`/api/lab/images/${S.selected.id}`, { method: 'DELETE' });
    S.selected = null;
    await loadDevices();
    render();
  } catch (e) { reportError(e); }
}

// ── Step 2: method ─────────────────────────────────────────────────────────
/** Why a firmware method cannot run on this device from this OS ('' when it can). */
function methodBlock(m, d) {
  if (!m.hardware || m.id === 'destroy') return '';
  if (d.isImage) return 'Needs a physical NVMe/SATA device';
  const caps = d.hardwareMethods || {};
  if (caps[m.hardware]?.available) return '';
  if (m.hardware === 'crypto' && caps.opal?.available) return '';
  return caps[m.hardware]?.reason || 'Not available for this device on this operating system';
}

/** Opal drives without NVMe Sanitize are crypto-erased by PSID revert; the PSID is on the drive label. */
const needsPsid = (d) => S.method === 'crypto_erase' && !d.isImage && !d.hardwareMethods?.crypto?.available && d.hardwareMethods?.opal?.available;

function recommend(d) {
  const rec = d.advice?.recommended || d.recommendedMethod;
  const m = S.methods.find(x => x.id === rec);
  return m && rec !== 'destroy' && !methodBlock(m, d) ? rec : 'nist_800_88';
}

const methodName = (id) => S.methods.find(m => m.id === id)?.name || id;
const FIT = { best: ['Recommended', 'ok'], good: ['Suitable', 'info'], fair: ['Works, not needed', ''],
  avoid: ['Not advised', 'warn'], unavailable: ['Not available', ''] };
const FIT_ORDER = ['best', 'good', 'fair', 'avoid', 'unavailable'];

const METHOD_NOTES = {
  quick_used: 'Overwrites only what the file system uses or used, then checks the rest for old data. Seconds; not a NIST Clear.',
  nist_800_88: 'One pass of zeros over every addressable sector, then a full read-back. The NIST baseline for Clear.',
  single_pass: 'One pass of zeros. Same write as NIST Clear; kept for policies that name it separately.',
  random_pass: 'One pass of keyed random data. Verification regenerates the exact stream, so random is fully checkable.',
  dod_5220_22_m: 'Zeros, ones, then keyed random. Legacy DoD pattern still requested by some policies.',
  gutmann: '35 passes designed for 1990s magnetic encodings. No benefit on modern drives; very slow.',
  crypto_erase: 'Destroys the drive\'s media encryption key (NVMe Sanitize, or TCG Opal PSID revert). Seconds, covers spare blocks.',
  block_erase: 'NVMe Sanitize block erase: the controller erases every block, including spare and remapped areas.',
  ata_sanitize: 'Drive firmware erases all blocks including remapped and over-provisioned areas.',
};

function methodRow(m, d, advice) {
  const blocked = methodBlock(m, d);
  const fit = blocked ? 'unavailable' : (advice.fit || 'good');
  const [label, tone] = FIT[fit];
  const off = fit === 'unavailable';
  return `<label class="method-row ${S.method === m.id ? 'on' : ''} ${off ? 'disabled' : ''}">
    <input type="radio" name="mt" value="${m.id}" ${S.method === m.id ? 'checked' : ''} ${off ? 'disabled' : ''}>
    <div class="method-main">
      <div class="method-name">${esc(m.name)}</div>
      <div class="method-why">${esc(blocked || advice.reason || METHOD_NOTES[m.id] || '')}</div>
    </div>
    <div class="method-tags">${badge(label, tone)}<span class="muted small">${m.id === 'quick_used' ? 'Used space only · not a NIST Clear'
      : `${m.passes ? `${m.passes} pass${m.passes > 1 ? 'es' : ''}` : 'Firmware'} · NIST ${esc(m.category)}`}</span>
      ${advice.time && !off ? `<span class="method-time">${esc(advice.time)}</span>` : ''}</div>
  </label>`;
}

function renderMethods(body) {
  const d = S.selected;
  const dual = appRef.health?.dualApproval;
  const adv = d.advice || { methods: {}, why: [] };
  const rec = recommend(d);
  const fitOf = (m) => methodBlock(m, d) ? 'unavailable' : (adv.methods[m.id]?.fit || 'good');
  const methods = S.methods.filter(m => m.id !== 'destroy')
    .sort((x, y) => (x.id === rec ? -1 : y.id === rec ? 1 : 0) || FIT_ORDER.indexOf(fitOf(x)) - FIT_ORDER.indexOf(fitOf(y)));
  const usable = methods.filter(m => fitOf(m) !== 'unavailable');
  const unusable = methods.filter(m => fitOf(m) === 'unavailable');
  body.innerHTML = `
    <div class="grid cols-side">
      <div class="stack">
        <div class="card rec-card"><div class="card-body">
          <div class="rec-head">${icon('star', 18)}
            <div style="flex:1"><div class="label">Recommended for this ${esc((adv.mediaLabel || d.type || 'drive').toLowerCase())}</div>
              <div class="rec-name">${esc(methodName(rec))}</div></div>
            ${S.method !== rec ? '<button class="btn btn-secondary btn-sm" id="mt-use-rec">Use it</button>' : badge('Selected', 'ok')}</div>
          <ul class="rec-why">${(adv.why || []).map(w => `<li>${esc(w)}</li>`).join('')}</ul>
          ${adv.methods?.[rec]?.time ? `<div class="rec-time">${icon('info', 14)} Takes ${esc(adv.methods[rec].time)} for this drive. ${esc(adv.timeNote || '')}</div>` : ''}
          ${adv.fastest && adv.methods?.[adv.fastest] && S.method !== adv.fastest ? `<div class="quick-offer">
            <div><b>Need it in seconds?</b> Quick erase overwrites only what the file system uses or used and checks the rest for old data:
              ${esc(adv.methods[adv.fastest].time)}. It is not a NIST Clear; for disposal erase every block.</div>
            <button class="btn btn-secondary btn-sm" id="mt-use-quick">${icon('arrow', 14)} Use Quick erase</button></div>` : ''}
          ${adv.warning ? `<div class="notice bad" style="margin-top:10px">${icon('alert', 16)}<div>${esc(adv.warning)}</div></div>` : ''}
        </div></div>
        <div class="card">
          <div class="card-head"><span class="card-title">All methods for this drive</span><span class="card-sub">best first, each with the reason</span></div>
          <div class="method-list">${usable.map(m => methodRow(m, d, adv.methods[m.id] || {})).join('')}</div>
          ${unusable.length ? `<details class="more"><summary>Not available on this drive (${unusable.length})</summary>
            <div class="method-list">${unusable.map(m => methodRow(m, d, adv.methods[m.id] || {})).join('')}</div></details>` : ''}
        </div>
      </div>
      <div class="stack">
        <div class="card">
          <div class="card-head"><span class="card-title">Target</span>${dual ? badge('Two-person rule on', 'warn') : ''}</div>
          <div class="card-body"><dl class="kv">
            <dt>Drive</dt><dd>${esc(d.model)}</dd><dt>Serial</dt><dd class="mono">${esc(d.serialNumber)}</dd><dt>Capacity</dt><dd>${esc(d.capacity)}</dd>
            <dt>Operator</dt><dd>${esc(getOperator())}</dd><dt>Approver</dt><dd>${dual ? 'Required when you confirm' : 'Optional'}</dd>
          </dl>
          ${needsPsid(d) ? `<div class="field" style="margin-top:12px"><label for="mt-psid">Drive PSID (32 characters, printed on the label)</label>
            <input class="input mono" id="mt-psid" value="${esc(S.psid)}" autocomplete="off" spellcheck="false">
            <span class="hint">Used once for the TCG Opal PSID revert; never stored.</span></div>` : ''}
          </div>
        </div>
        <div class="muted small" style="padding:0 4px">After erasing, WipeX reads the drive back${d.isImage ? ', checks canary blocks' : ''} and tries to recover files from it. The job passes only if nothing is recoverable.</div>
      </div>
    </div>
    <div class="row between" style="margin-top:16px">
      <button class="btn btn-secondary" id="mt-back">${icon('back', 16)} Back</button>
      <button class="btn btn-danger btn-lg" id="mt-start" ${S.method ? '' : 'disabled'}>Start erasure</button>
    </div>`;

  body.querySelectorAll('input[name=mt]').forEach(r => r.addEventListener('change', () => { S.method = r.value; render(); }));
  body.querySelector('#mt-use-rec')?.addEventListener('click', () => { S.method = rec; render(); });
  body.querySelector('#mt-use-quick')?.addEventListener('click', () => { S.method = adv.fastest; render(); });
  body.querySelector('#mt-psid')?.addEventListener('input', e => { S.psid = e.target.value; });
  body.querySelector('#mt-back').addEventListener('click', () => { S.step = 1; render(); });
  body.querySelector('#mt-start').addEventListener('click', startErasure);
}

async function startErasure() {
  const d = S.selected;
  const operator = getOperator();
  const m = S.methods.find(x => x.id === S.method);
  if (needsPsid(d) && S.psid.replace(/[^A-Za-z0-9]/g, '').length !== 32) { toast('Enter the 32-character PSID from the drive label', 'bad'); return; }
  const ok = await confirmDanger({
    title: `Erase ${d.model}?`,
    sub: 'Every byte on this device will be overwritten. This cannot be undone.',
    rows: [['Device', esc(d.model)], ['Path', `<span class="mono">${esc(d.devicePath)}</span>`], ['Serial', `<span class="mono">${esc(d.serialNumber)}</span>`],
           ['Method', esc(m.name)], ['Operator', esc(operator)]],
    confirmLabel: 'Erase device',
    approval: appRef.health?.dualApproval ? 'required' : '',
  });
  if (!ok) return;
  try {
    const res = await api('/api/wipe/start', { method: 'POST', body: {
      deviceId: d.id, methodId: S.method, psid: needsPsid(d) ? S.psid : '', approver: ok.approver || '', approverPassword: ok.approverPassword || '' } });
    S.psid = '';
    S.wipeId = res.wipeId;
    S.status = null;
    S.cert = null;
    S.step = 3;
    render();
    poll();
  } catch (e) { reportError(e); }
}

// ── Step 3: run ────────────────────────────────────────────────────────────
async function poll() {
  const token = ++pollToken;
  while (token === pollToken) {
    try {
      S.status = await api(`/api/wipe/status/${S.wipeId}`);
    } catch (e) { reportError(e); return; }
    if (S.step === 3 && visible()) renderRun(root.querySelector('#drive-body'));
    if (S.status.status !== 'IN_PROGRESS') { refreshDemo(); return; }
    await sleep(700);
  }
}

function renderRun(body) {
  if (!body) return;
  const st = S.status;
  const running = !st || st.status === 'IN_PROGRESS';
  const v = st?.verification;
  const exe = st?.execution;
  let verdict = '';
  if (!running) {
    const pass = st.status === 'COMPLETED';
    verdict = `
      <div class="verdict ${pass ? '' : 'bad'}">
        <span class="verdict-icon">${icon(pass ? 'check' : 'x', 22, 2.6)}</span>
        <div><div class="verdict-title">${pass ? 'Erasure verified' : st.status === 'FAILED' ? 'Erasure failed' : 'Verification failed'}</div>
        <div class="verdict-text">${esc(v?.summary || st.command || '')}</div></div>
      </div>`;
  }
  body.innerHTML = `
    <div class="grid cols-side">
      <div class="stack">
        <div class="card"><div class="card-body stack">
          <div class="row between"><div><div class="card-title">${esc(S.selected?.model || '')}</div><div class="card-sub mono">${esc(S.wipeId)}</div></div>${st ? statusBadge(st.status) : ''}</div>
          <div class="stat-row">
            <div class="stat"><div class="stat-label">Progress</div><div class="stat-value">${st ? st.progress : 0}%</div></div>
            <div class="stat"><div class="stat-label">Throughput</div><div class="stat-value">${esc((st && st.speed && !['—', 'Starting'].includes(st.speed)) ? st.speed : '—')}</div></div>
            <div class="stat"><div class="stat-label">Passes done</div><div class="stat-value">${exe?.passes?.length ?? '—'}</div></div>
          </div>
          ${running ? progressBlock(st?.progress ?? null, st?.command || 'Starting…') : ''}
          ${verdict}
        </div></div>
        ${v?.checks ? `<div class="card"><div class="card-head"><span class="card-title">Verification evidence</span><span class="card-sub">Mean entropy of samples: ${v.meanEntropy ?? '—'} bits/byte (informational)</span></div><div class="card-body">${checksList(v.checks)}</div></div>` : ''}
      </div>
      <div class="stack">
        <div class="card"><div class="card-head"><span class="card-title">Passes</span></div>
          ${exe?.passes?.length ? `<div class="table-wrap"><table class="table"><thead><tr><th>#</th><th>Pattern</th><th class="num">Time</th></tr></thead><tbody>
            ${exe.passes.map(p => `<tr><td>${p.pass}</td><td>${esc(p.pattern)}</td><td class="num">${p.seconds}s</td></tr>`).join('')}</tbody></table></div>`
            : `<div class="empty">${running ? 'Writing…' : exe?.hardware ? esc(exe.hardware.message) : exe?.error ? esc(exe.error) : 'No passes recorded'}</div>`}
        </div>
        ${!running ? `<div class="card card-pad stack" style="gap:10px">
          <button class="btn btn-primary" id="run-cert">${icon('shield', 16)} ${st.status === 'COMPLETED' ? 'Issue certificate' : 'Issue failure report'}</button>
          <button class="btn btn-secondary" id="run-new">New job</button></div>` : ''}
        ${!running && st.status === 'COMPLETED' && S.selected && !S.selected.isImage ? `<div class="card card-pad stack" style="gap:8px">
          <div class="card-title">Use the drive again</div>
          <div class="muted small">The erased drive has no partition left, so the computer shows it as unformatted. Create one empty file system to reuse it; the certificate is not affected.</div>
          <div style="display:flex;gap:8px"><select class="select" id="run-fs">${['exFAT', 'FAT32', ...(appRef.health?.platform === 'Darwin' ? [] : ['NTFS'])].map(f => `<option>${f}</option>`).join('')}</select>
            <button class="btn btn-secondary" id="run-format">${icon('drive', 16)} Format for reuse</button></div>
          ${S.formatted ? `<div class="small">${esc(S.formatted)}</div>` : ''}</div>` : ''}
      </div>
    </div>`;
  body.querySelector('#run-cert')?.addEventListener('click', issueCertificate);
  body.querySelector('#run-format')?.addEventListener('click', async (e) => {
    const fs = body.querySelector('#run-fs').value;
    e.target.disabled = true;
    try {
      const r = await api(`/api/wipe/${encodeURIComponent(S.wipeId)}/format`, { method: 'POST', body: { fileSystem: fs } });
      S.formatted = `Formatted as ${r.fileSystem}${r.volume ? ` (${r.volume})` : ''}, label ${r.label}`;
      toast(S.formatted, 'ok');
      render();
    } catch (err) { reportError(err); e.target.disabled = false; }
  });
  body.querySelector('#run-new')?.addEventListener('click', resetFlow);
}

async function issueCertificate() {
  try {
    S.cert = await api('/api/certificates/generate', { method: 'POST', body: { wipeId: S.wipeId } });
    refreshDemo();
    S.step = 4;
    render();
  } catch (e) { reportError(e); }
}

function resetFlow() {
  S.step = 1; S.wipeId = null; S.status = null; S.cert = null; S.method = null; S.psid = ''; S.formatted = '';
  loadDevices().then(render);
}

// ── Step 4: certificate ────────────────────────────────────────────────────
export function qrSvg(text) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ cellSize: 3, margin: 0, scalable: true });
}

const sigBadge = (s) => s ? ` ${s.valid ? badge('signed', 'ok') : badge('signature invalid', 'bad')}` : '';

export function certificateHtml(c) {
  const ok = c.trustScore === 'GREEN';
  const verifyUrl = `${location.origin}${location.pathname}#/verify?q=${encodeURIComponent(c.certificateId)}`;
  return `
    <div class="cert ${ok ? '' : 'fail'}">
      <div class="cert-head">
        <div class="stack" style="gap:6px">
          <div class="cert-title">Certificate of Data Sanitization</div>
          <div class="cert-id">${esc(c.certificateId)}</div>
          <div class="muted small">Issued ${esc(when(c.issueDate))} · ${esc(c.signatureAlgorithm || 'ECDSA P-256')}</div>
          <div class="row" style="margin-top:4px">${ok ? badge('Sanitized and verified', 'ok') : badge(c.cleanedStatus || 'Not verified', 'bad')}
            ${c.isValid ? badge('Signature valid', 'ok') : badge('Signature INVALID', 'bad')}</div>
        </div>
        <div class="qr" title="Scan to verify">${qrSvg(verifyUrl)}</div>
      </div>
      <div class="grid cols-2" style="margin-top:18px">
        <dl class="kv">
          <dt>Device</dt><dd>${esc(c.deviceModel)}</dd><dt>Serial</dt><dd class="mono">${esc(c.serialNumber)}</dd>
          <dt>Media</dt><dd>${esc(c.storageType)}</dd><dt>Capacity</dt><dd>${Number(c.capacityBytes || 0).toLocaleString()} bytes</dd>
        </dl>
        <dl class="kv">
          <dt>Method</dt><dd>${esc(c.standard)}</dd><dt>NIST category</dt><dd>${esc(c.category)}</dd>
          <dt>Operator</dt><dd>${esc(c.operator || '—')}${sigBadge(c.issuerSignature)}</dd>
          <dt>Approver</dt><dd>${esc(c.approver || '—')}${sigBadge(c.approvalSignature)}</dd>
        </dl>
      </div>
      <div class="section-label">Verification</div>
      ${checksList(c.verification?.checks || [])}
      <div class="section-label">SHA-256 of signed content</div>
      <div class="digest">${esc(c.sha256Digest)}</div>
    </div>`;
}

function renderCert(body) {
  const c = S.cert;
  body.innerHTML = `
    <div class="grid cols-side">
      ${certificateHtml(c)}
      <div class="stack">
        <div class="card card-pad stack" style="gap:10px">
          <a class="btn btn-primary" href="${apiUrl(`/api/certificates/${encodeURIComponent(c.certificateId)}/pdf`)}" target="_blank" rel="noopener">${icon('download', 16)} Download PDF</a>
          <a class="btn btn-secondary" href="#/verify?q=${encodeURIComponent(c.certificateId)}">${icon('shield', 16)} Open in verifier</a>
          <button class="btn btn-secondary" id="ct-new">New job</button>
        </div>
        <div class="notice">${icon('info', 16)}<div><strong>How to verify</strong>Scan the QR code or enter the certificate ID in <i>Verify</i>. The PDF includes a draft annexure for BSA 2023 §63, to be signed by the responsible person.</div></div>
      </div>
    </div>`;
  body.querySelector('#ct-new').addEventListener('click', resetFlow);
}
