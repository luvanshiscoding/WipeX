/** M1 — Drive Eraser: device → method → erase & verify → certificate. */
import qrcode from 'qrcode-generator';
import { api, apiUrl, askOperator, badge, bytes, checksList, confirmDanger, esc, getOperator, icon, modal, progressBlock,
  reportError, requireOperator, sleep, statusBadge, toast, when } from '../core.js';

const S = { step: 1, devices: [], methods: [], selected: null, method: null, approver: '', wipeId: null, status: null, cert: null, loading: false };
let root, appRef, pollToken = 0;

export async function show(el, _params, app) {
  root = el;
  appRef = app;
  if (!S.methods.length) S.methods = await api('/api/methods').catch(() => []);
  if (S.step === 1) await loadDevices();
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
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Drive Eraser <span class="code-tag">M1</span></h1>
        <p class="page-desc">Sanitize an entire storage device following NIST SP 800-88, verify the result independently and issue a signed certificate.</p>
      </div>
    </div>
    ${stepper()}
    <div id="drive-body"></div>`;
  const body = root.querySelector('#drive-body');
  ({ 1: renderDevices, 2: renderMethods, 3: renderRun, 4: renderCert })[S.step](body);
}

function stepper() {
  const steps = ['Choose device', 'Choose method', 'Erase & verify', 'Certificate'];
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
    d.isImage ? badge('Lab image', 'blue') : badge(d.interface || d.type || 'Disk'),
    d.isBootDrive ? badge('System disk', 'warn') : '',
    d.legalHold ? badge('Legal hold', 'bad') : '',
  ].join('');
  const files = d.isImage ? `${(d.currentFiles || []).length} files · ${(d.deletedRecoverableFiles || []).length} deleted` : (d.powerOnHours || '');
  return `
    <button class="pick ${S.selected?.id === d.id ? 'on' : ''} ${locked ? 'disabled' : ''}" data-id="${esc(d.id)}" ${locked ? 'aria-disabled="true"' : ''}>
      <div class="pick-top"><span class="pick-kind">${icon(d.isImage ? 'disk' : 'drive', 14)}${esc(d.type)}</span><span class="pick-tags">${tags}</span></div>
      <div class="pick-title">${esc(d.model)}</div>
      <div class="pick-meta"><span class="mono">${esc(d.maskedSerial || d.serialNumber || '')}</span><b>${esc(d.capacity || bytes(d.capacityBytes))}</b></div>
      <div class="pick-note ${locked ? (d.legalHold ? 'bad' : 'warn') : ''}">${esc(locked || files)}</div>
    </button>`;
}

function renderDevices(body) {
  const physical = S.devices.filter(d => !d.isImage);
  const images = S.devices.filter(d => d.isImage);
  const d = S.selected;
  body.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div><div class="card-title">Storage targets</div><div class="card-sub">Physical disks detected on this workstation, plus lab disk images for safe, real erasure runs.</div></div>
        <div class="row">
          <button class="btn btn-secondary btn-sm" id="dv-new">${icon('plus', 14)} New lab image</button>
          <button class="btn btn-secondary btn-sm" id="dv-scan">${icon('refresh', 14)} Rescan</button>
        </div>
      </div>
      <div class="card-body">
        ${S.loading ? '<div class="empty">Scanning devices…</div>' : `
        <div class="section-label" style="margin-top:0">Physical devices</div>
        ${physical.length ? `<div class="pick-grid">${physical.map(deviceCard).join('')}</div>` : '<div class="muted small">No physical devices detected. Attach a USB drive and rescan (administrator rights are needed to erase it).</div>'}
        <div class="section-label">Lab disk images</div>
        ${images.length ? `<div class="pick-grid">${images.map(deviceCard).join('')}</div>` : '<div class="muted small">No lab images yet — create one to try a real erasure safely.</div>'}`}
      </div>
    </div>
    ${d ? detailCard(d) : ''}
    <div class="row between" style="margin-top:16px">
      <span class="muted small">${d ? `Selected: <b>${esc(d.model)}</b>` : 'Select a device to continue.'}</span>
      <button class="btn btn-primary btn-lg" id="dv-next" ${d && !lockReason(d) ? '' : 'disabled'}>Continue ${icon('arrow', 16)}</button>
    </div>`;

  body.querySelectorAll('.pick').forEach(b => b.addEventListener('click', () => {
    const dev = S.devices.find(x => x.id === b.dataset.id);
    if (lockReason(dev)) { toast(lockReason(dev), 'bad'); return; }
    S.selected = dev;
    render();
  }));
  body.querySelector('#dv-scan').addEventListener('click', async () => { await loadDevices(true); render(); });
  body.querySelector('#dv-new').addEventListener('click', newLabImage);
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
          : '<div class="notice warn">' + icon('alert', 16) + '<div><strong>Real device</strong>Erasure permanently destroys all data on this disk. The disk is taken offline during the job; run WipeX as administrator.</div></div>'}
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
function methodBlock(m, d) {
  const hwAvailable = appRef.health?.capabilities?.hardwarePurge;
  if (m.id === 'destroy') return '';
  if (m.hardware && d.isImage) return 'Needs a physical NVMe/SATA device';
  if (m.hardware && !hwAvailable) return 'Hardware sanitize commands run on Linux (nvme-cli / hdparm)';
  return '';
}

function recommend(d) {
  const hw = appRef.health?.capabilities?.hardwarePurge;
  if (!d.isImage && hw && /nvme/i.test(d.type)) return 'crypto_erase';
  if (!d.isImage && hw && /ssd/i.test(d.type)) return 'ata_sanitize';
  return 'nist_800_88';
}

const METHOD_NOTES = {
  nist_800_88: 'One pass of zeros over every addressable sector, then a full read-back. The NIST baseline for Clear.',
  single_pass: 'One pass of zeros. Same write as NIST Clear; kept for policies that name it separately.',
  random_pass: 'One pass of keyed random data. Verification regenerates the exact stream, so random is fully checkable.',
  dod_5220_22_m: 'Zeros, ones, then keyed random. Legacy DoD pattern still requested by some policies.',
  gutmann: '35 passes designed for 1990s magnetic encodings. No benefit on modern drives; very slow.',
  crypto_erase: 'Destroys the drive\'s media encryption key (NVMe Sanitize / TCG Opal). Seconds, covers spare blocks.',
  ata_sanitize: 'Drive firmware erases all blocks including remapped and over-provisioned areas.',
};

function renderMethods(body) {
  const d = S.selected;
  const dual = appRef.health?.dualApproval;
  const methods = S.methods.filter(m => m.id !== 'destroy');
  body.innerHTML = `
    <div class="grid cols-side">
      <div class="card">
        <div class="card-head"><div><div class="card-title">Sanitization method</div><div class="card-sub">Recommended for ${esc(d.type)}: <b>${esc(S.methods.find(m => m.id === recommend(d))?.name || '')}</b></div></div></div>
        <div class="card-body"><div class="pick-grid" style="grid-template-columns:repeat(auto-fill,minmax(300px,1fr))">
          ${methods.map(m => {
            const blocked = methodBlock(m, d);
            return `<button class="pick ${S.method === m.id ? 'on' : ''} ${blocked ? 'disabled' : ''}" data-id="${m.id}">
              <div class="pick-top"><span class="pick-title">${esc(m.name)}</span>${m.id === recommend(d) ? badge('Recommended', 'info') : ''}</div>
              <div class="small" style="color:var(--text-2)">${esc(METHOD_NOTES[m.id] || '')}</div>
              <div class="pick-tags">${badge(`NIST ${m.category}`, m.category === 'Purge' ? 'blue' : '')}${m.passes ? badge(`${m.passes} pass${m.passes > 1 ? 'es' : ''}`) : badge('Firmware command')}</div>
              ${blocked ? `<div class="pick-note warn">${esc(blocked)}</div>` : ''}
            </button>`;
          }).join('')}
        </div></div>
      </div>
      <div class="stack">
        <div class="card">
          <div class="card-head"><span class="card-title">Target</span></div>
          <div class="card-body"><dl class="kv">
            <dt>Device</dt><dd>${esc(d.model)}</dd><dt>Serial</dt><dd class="mono">${esc(d.serialNumber)}</dd><dt>Capacity</dt><dd>${esc(d.capacity)}</dd>
          </dl></div>
        </div>
        <div class="card">
          <div class="card-head"><span class="card-title">Authorization</span>${dual ? badge('Two-person rule on', 'warn') : ''}</div>
          <div class="card-body stack" style="gap:12px">
            <div class="field"><label>Operator</label><div class="row"><b>${esc(getOperator() || 'Not set')}</b><button class="btn btn-ghost btn-sm" id="mt-op">Change</button></div></div>
            <div class="field"><label for="mt-approver">Approver ${dual ? '(required)' : '(optional)'}</label>
              <input class="input" id="mt-approver" value="${esc(S.approver)}" placeholder="Second person confirming this erasure">
              <span class="hint">Recorded on the certificate and in the audit log.</span></div>
          </div>
        </div>
        <div class="notice">${icon('info', 16)}<div><strong>What happens next</strong>WipeX captures sample blocks${d.isImage ? ' and plants canary blocks' : ''}, runs the passes, reads the device back against the expected pattern, then tries to recover files from it with M3. The job only passes if nothing is recoverable.</div></div>
      </div>
    </div>
    <div class="row between" style="margin-top:16px">
      <button class="btn btn-secondary" id="mt-back">${icon('back', 16)} Back</button>
      <button class="btn btn-danger btn-lg" id="mt-start" ${S.method ? '' : 'disabled'}>Start erasure</button>
    </div>`;

  body.querySelectorAll('.pick').forEach(b => b.addEventListener('click', () => {
    const m = S.methods.find(x => x.id === b.dataset.id);
    const blocked = methodBlock(m, d);
    if (blocked) { toast(blocked, 'bad'); return; }
    S.method = m.id;
    S.approver = body.querySelector('#mt-approver').value;
    render();
  }));
  body.querySelector('#mt-approver').addEventListener('input', e => { S.approver = e.target.value; });
  body.querySelector('#mt-op').addEventListener('click', async () => { await askOperator(); render(); });
  body.querySelector('#mt-back').addEventListener('click', () => { S.step = 1; render(); });
  body.querySelector('#mt-start').addEventListener('click', startErasure);
}

async function startErasure() {
  const d = S.selected;
  const operator = await requireOperator();
  if (!operator) return;
  const m = S.methods.find(x => x.id === S.method);
  const ok = await confirmDanger({
    title: `Erase ${d.model}?`,
    sub: 'Every byte on this device will be overwritten. This cannot be undone.',
    rows: [['Device', esc(d.model)], ['Path', `<span class="mono">${esc(d.devicePath)}</span>`], ['Serial', `<span class="mono">${esc(d.serialNumber)}</span>`],
           ['Method', esc(m.name)], ['Operator', esc(operator)], ['Approver', esc(S.approver || '—')]],
    confirmLabel: 'Erase device',
  });
  if (!ok) return;
  try {
    const res = await api('/api/wipe/start', { method: 'POST', body: { deviceId: d.id, methodId: S.method, operator, approver: S.approver } });
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
    if (S.step === 3 && root?.classList.contains('active')) renderRun(root.querySelector('#drive-body'));
    if (S.status.status !== 'IN_PROGRESS') return;
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
      </div>
    </div>`;
  body.querySelector('#run-cert')?.addEventListener('click', issueCertificate);
  body.querySelector('#run-new')?.addEventListener('click', resetFlow);
}

async function issueCertificate() {
  try {
    S.cert = await api('/api/certificates/generate', { method: 'POST', body: { wipeId: S.wipeId, actor: getOperator() || 'system' } });
    S.step = 4;
    render();
  } catch (e) { reportError(e); }
}

function resetFlow() {
  S.step = 1; S.wipeId = null; S.status = null; S.cert = null; S.method = null; S.approver = '';
  loadDevices().then(render);
}

// ── Step 4: certificate ────────────────────────────────────────────────────
export function qrSvg(text) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ cellSize: 3, margin: 0, scalable: true });
}

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
          <dt>Operator</dt><dd>${esc(c.operator || '—')}</dd><dt>Approver</dt><dd>${esc(c.approver || '—')}</dd>
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
