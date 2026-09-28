/** Overview: status of every module, readiness checks and recent activity. */
import { ago, api, can, demo, esc, icon, nextDemoStep, refreshDemo, reportError, toast } from '../core.js';

const ACTIONS = {
  'erasure.started': 'Erasure started', 'erasure.finished': 'Erasure finished', 'erasure.blocked_by_hold': 'Erasure blocked by legal hold',
  'certificate.issued': 'Certificate issued', 'recovery.started': 'Recovery scan started', 'recovery.finished': 'Recovery scan finished',
  'file_erasure.started': 'File erasure started', 'file_erasure.finished': 'File erasure finished', 'file_erasure.sandbox_created': 'Sample files created',
  'case.created': 'Case opened', 'case.closed': 'Case closed', 'case.open': 'Case reopened',
  'evidence.acquisition_started': 'Evidence acquisition started', 'evidence.acquired': 'Evidence acquired', 'evidence.hash_verified': 'Evidence hash verified',
  'evidence.hash_mismatch': 'Evidence hash MISMATCH', 'hold.placed': 'Legal hold placed', 'hold.released': 'Legal hold released',
  'settings.dual_approval': 'Two-person rule changed', 'lab_image.created': 'Lab image created', 'lab_image.reset': 'Lab image reset',
  'history.cleared': 'History cleared', 'lab_image.formatted': 'Sample disk quick-formatted', 'settings.demo_mode': 'Demo mode switched', 'demo.reset': 'Sample data reset',
  'erasure.formatted_for_reuse': 'Drive formatted for reuse', 'user.login': 'Signed in', 'user.logout': 'Signed out',
  'user.login_failed': 'Sign-in failed', 'user.created': 'User created', 'user.updated': 'User updated',
  'user.password_changed': 'Password changed', 'audit.exported': 'Audit log exported',
  'erasure.android_started': 'Phone erasure started', 'erasure.android_finished': 'Phone erasure finished',
};
export const actionLabel = (a) => ACTIONS[a] || a.replace(/[._]/g, ' ');

const NOISE = new Set(['user.login', 'user.logout']);

const MODULES = [
  { id: 'recover', href: '#/recovery', ic: 'recover', perm: 'recovery.run', tint: 'teal', tag: 'M3 · Forensic recovery', name: 'Recover Files',
    desc: 'Bring back deleted files from a USB drive, disk or image, even after a format, each with a confidence score.' },
  { id: 'drive', href: '#/erase?mode=drive', ic: 'drive', perm: 'erasure.run', tint: 'rose', tag: 'M1 · Drive eraser', name: 'Erase a Drive',
    desc: 'Wipe a whole USB drive or disk to NIST SP 800-88, prove nothing is left, get a signed certificate.' },
  { id: 'files', href: '#/erase?mode=files', ic: 'folder', perm: 'files.erase', tint: 'amber', tag: 'M2 · File & folder eraser', name: 'Erase Files',
    desc: 'Pick files and folders in a file browser; their content, names and system traces are destroyed.' },
];

export async function show(el, _params, app) {
  el.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Overview</h1>
        <p class="page-desc">Recover, erase and prove it: every job is checked, signed and logged on this workstation.</p>
      </div>
    </div>
    <div id="ov-demo"></div>
    <div class="grid cols-3" id="ov-modules">${MODULES.map(m => moduleCard(m, null)).join('')}</div>
    <div class="grid cols-side" style="margin-top:16px">
      <div class="card tint tint-blue"><div class="card-head"><span class="card-title">${icon('audit', 16)} Recent activity</span><a class="btn btn-ghost btn-sm" href="#/audit">Audit log ${icon('arrow', 13)}</a></div><div id="ov-activity"><div class="empty">Loading…</div></div></div>
      <div class="card tint tint-violet"><div class="card-head"><span class="card-title">${icon('shield', 16)} Workstation</span></div><div class="card-body" id="ov-ready"></div></div>
    </div>`;

  renderDemo(el.querySelector('#ov-demo'));

  const devicesPromise = api('/api/devices').catch(() => []);   // slowest call (hardware probe): fill its row last
  const [sessions, jobs, log, chain] = await Promise.all([
    api('/api/wipe/sessions').catch(() => []), api('/api/jobs').catch(() => []),
    api('/api/audit/log?limit=30').catch(() => ({ entries: [], total: 0 })), api('/api/audit/verify').catch(() => null),
  ]);
  await refreshDemo();
  renderDemo(el.querySelector('#ov-demo'));

  const done = (list, ok) => list.filter(x => x.status === ok).length;
  const recoveries = jobs.filter(j => j.kind === 'recovery');
  const deletions = jobs.filter(j => j.kind === 'file_erasure');
  const failed = sessions.filter(s => ['FAILED', 'VERIFICATION_FAILED'].includes(s.status)).length;
  const stats = {
    recover: [[recoveries.length, 'scans'], [done(recoveries, 'COMPLETED'), 'completed']],
    drive: [[sessions.length, 'erasures'], [done(sessions, 'COMPLETED'), 'verified'], ...(failed ? [[failed, 'failed']] : [])],
    files: [[deletions.length, 'jobs'], [done(deletions, 'COMPLETED'), 'completed']],
  };
  el.querySelector('#ov-modules').innerHTML = MODULES.map(m => moduleCard(m, stats[m.id])).join('');

  const entries = log.entries.filter(e => !NOISE.has(e.action)).slice(0, 7);
  el.querySelector('#ov-activity').innerHTML = entries.length ? `
    <div class="activity">${entries.map(e => `
      <div class="act-row"><span class="act-dot ${/fail|mismatch|blocked/.test(e.action) ? 'bad' : ''}"></span>
        <span class="act-what"><b>${esc(actionLabel(e.action))}</b><span class="muted small trunc">${esc(e.target || e.case_id || '')}</span></span>
        <span class="muted small nowrap">${ago(e.ts)}</span></div>`).join('')}</div>`
    : '<div class="empty"><strong>No activity yet</strong>Actions appear here as they are logged.</div>';

  const h = app.health;
  const ready = [
    [!!h, 'Engine', h ? `${h.platform === 'Darwin' ? 'macOS' : h.platform}${h.elevated ? ' · Administrator' : ''}` : 'Start: python wipex.py'],
    [h?.elevated, 'Drive access', h?.elevated ? 'Read and erase drives' : 'Start with WipeX.cmd / WipeX.command', true],
    [null, 'Drives', 'Scanning…', true, 'ov-drives'],
    [chain?.valid, 'Audit chain', chain ? (chain.valid ? `${chain.entries} entries intact` : `Broken at entry ${chain.brokenAt}`) : '—'],
    [h?.capabilities?.signing, 'Signing key', 'ECDSA P-256'],
    [h?.capabilities?.sleuthKit, 'The Sleuth Kit', h?.capabilities?.sleuthKit ? 'File-system recovery' : 'Install pytsk3'],
    [true, 'Network', 'Not needed · local only'],
  ];
  el.querySelector('#ov-ready').innerHTML = `<div class="ready-list">${ready.map(readyRow).join('')}</div>`;

  devicesPromise.then(devices => {
    const usb = devices.filter(d => !d.isImage && d.removable).length;
    const physical = devices.filter(d => !d.isImage).length;
    const row = el.querySelector('#ov-drives');
    if (row) row.outerHTML = readyRow([usb > 0, 'Drives', `${physical} found · ${usb ? `${usb} USB` : 'no USB drive'}`, true, 'ov-drives']);
  });
}

function readyRow([ok, name, detail, optional, id]) {
  const state = ok ? '' : optional ? 'skip' : 'bad';
  return `<div class="ready-row" ${id ? `id="${id}"` : ''}><span class="check-ic ${state}">${icon(ok ? 'check' : optional ? 'minus' : 'x', 13, 2.6)}</span>
    <span class="ready-name">${esc(name)}</span><span class="muted small ready-detail">${esc(detail)}</span></div>`;
}

function moduleCard(m, stats) {
  const ok = can(m.perm);
  return `<a class="card module tint tint-${m.tint} ${ok ? '' : 'locked'}" ${ok ? `href="${m.href}"` : 'aria-disabled="true" title="Not available for this access profile"'}>
    <div class="module-top"><span class="module-icon">${icon(m.ic, 20)}</span>
      <div><div class="module-name">${m.name}</div><div class="module-tag">${m.tag}</div></div></div>
    <div class="module-desc">${m.desc}</div>
    <div class="module-foot">
      <span class="module-stats">${stats ? stats.map(([n, l]) => `<span><b>${n}</b> ${l}</span>`).join('') : '<span class="muted">…</span>'}</span>
      <span class="module-cta">${ok ? `Open ${icon('arrow', 14)}` : `${icon('lock', 13)} Not for this profile`}</span>
    </div>
  </a>`;
}

function renderDemo(el) {
  if (!el) return;
  if (!demo.enabled) { el.innerHTML = ''; return; }
  const next = nextDemoStep();
  el.innerHTML = `
    <div class="card demo-card tint tint-amber">
      <div class="card-head">
        <div><div class="card-title">${icon('play', 16)} Demo walkthrough</div><div class="card-sub">${demo.completed} of ${demo.total} steps done · sample disks and sample files only · each tick comes from the audit log</div></div>
        <button class="btn btn-secondary btn-sm" id="ov-demo-reset" title="Refill the sample disks with sample data and start the steps again">${icon('refresh', 14)} Reset sample data</button>
      </div>
      <ol class="demo-steps">${demo.steps.map((s, i) => `
        <li class="${s.done ? 'done' : ''} ${next && next.id === s.id ? 'next' : ''}">
          <span class="demo-num">${s.done ? icon('check', 13, 2.8) : i + 1}</span>
          <span class="demo-title">${esc(s.title)}</span>
          <a class="btn ${next && next.id === s.id ? 'btn-primary' : 'btn-ghost'} btn-sm" href="${s.href}">${s.done ? 'Again' : 'Go'} ${icon('arrow', 13)}</a>
        </li>`).join('')}</ol>
    </div>`;
  el.querySelector('#ov-demo-reset').addEventListener('click', async (e) => {
    e.target.disabled = true;
    try {
      await api('/api/demo/reset', { method: 'POST' });
      await refreshDemo();
      toast('Sample disks refilled; walkthrough restarted', 'ok');
      renderDemo(el);
    } catch (err) { reportError(err); e.target.disabled = false; }
  });
}
