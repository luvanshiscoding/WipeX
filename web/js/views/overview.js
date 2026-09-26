/** Overview: status of every module, readiness checks and recent activity. */
import { ago, api, badge, can, esc, icon, session } from '../core.js';

const ACTIONS = {
  'erasure.started': 'Erasure started', 'erasure.finished': 'Erasure finished', 'erasure.blocked_by_hold': 'Erasure blocked by legal hold',
  'certificate.issued': 'Certificate issued', 'recovery.started': 'Recovery scan started', 'recovery.finished': 'Recovery scan finished',
  'file_erasure.started': 'File erasure started', 'file_erasure.finished': 'File erasure finished', 'file_erasure.sandbox_created': 'Sample files created',
  'case.created': 'Case opened', 'case.closed': 'Case closed', 'case.open': 'Case reopened',
  'evidence.acquisition_started': 'Evidence acquisition started', 'evidence.acquired': 'Evidence acquired', 'evidence.hash_verified': 'Evidence hash verified',
  'evidence.hash_mismatch': 'Evidence hash MISMATCH', 'hold.placed': 'Legal hold placed', 'hold.released': 'Legal hold released',
  'settings.dual_approval': 'Two-person rule changed', 'lab_image.created': 'Lab image created', 'lab_image.reset': 'Lab image reset',
  'history.cleared': 'History cleared', 'user.login': 'Signed in', 'user.logout': 'Signed out',
  'user.login_failed': 'Sign-in failed', 'user.created': 'User created', 'user.updated': 'User updated',
  'user.password_changed': 'Password changed', 'audit.exported': 'Audit log exported',
  'erasure.android_started': 'Phone erasure started', 'erasure.android_finished': 'Phone erasure finished',
};
export const actionLabel = (a) => ACTIONS[a] || a.replace(/[._]/g, ' ');

export async function show(el, _params, app) {
  el.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Overview</h1>
        <p class="page-desc">Recover deleted files, or destroy files so they can never be recovered. Every action is checked, signed and logged.</p>
      </div>
      <div class="row">
        ${can('recovery.run') ? `<a class="btn btn-secondary" href="#/recovery">${icon('recover')} Recover files</a>` : ''}
        ${can('files.erase') ? `<a class="btn btn-primary" href="#/files">${icon('fileX')} Delete files permanently</a>` : ''}
      </div>
    </div>
    <div id="ov-operator"></div>
    <div class="grid cols-4" id="ov-kpis">${'<div class="card kpi"><div class="kpi-label">Loading…</div><div class="kpi-value">–</div></div>'.repeat(4)}</div>
    <div class="grid cols-3" style="margin-top:16px" id="ov-modules"></div>
    <div class="grid cols-side" style="margin-top:16px">
      <div class="card"><div class="card-head"><span class="card-title">Recent activity</span><a class="btn btn-ghost btn-sm" href="#/audit">Open audit log</a></div><div id="ov-activity"><div class="empty">Loading…</div></div></div>
      <div class="card"><div class="card-head"><span class="card-title">Workstation readiness</span></div><div class="card-body" id="ov-ready"></div></div>
    </div>`;

  renderModules(el.querySelector('#ov-modules'));
  const u = session.user;
  el.querySelector('#ov-operator').innerHTML = u ? `<div class="notice" style="margin-bottom:16px">${icon('user', 18)}
    <div><strong>Signed in as ${esc(u.displayName)} (${esc(u.roleLabel)})</strong>Your actions are recorded in the audit log and signed with your personal key ${esc(u.keyId)}.</div></div>` : '';

  const devicesPromise = api('/api/devices').catch(() => []);   // slowest call (hardware probe): fill its tile last
  const [sessions, jobs, cases, log, chain] = await Promise.all([
    api('/api/wipe/sessions').catch(() => []), api('/api/jobs').catch(() => []),
    api('/api/cases').catch(() => []), api('/api/audit/log?limit=10').catch(() => ({ entries: [], total: 0 })),
    api('/api/audit/verify').catch(() => null),
  ]);

  const done = sessions.filter(s => s.status === 'COMPLETED').length;
  const failed = sessions.filter(s => ['FAILED', 'VERIFICATION_FAILED'].includes(s.status)).length;
  const recoveries = jobs.filter(j => j.kind === 'recovery');
  const openCases = cases.filter(c => c.status === 'OPEN');
  const holds = cases.reduce((n, c) => n + (c.activeHolds || 0), 0);

  el.querySelector('#ov-kpis').innerHTML = [
    `<div class="card kpi" id="ov-dev-kpi"><div class="kpi-label">${icon('drive', 15)}Storage targets</div><div class="kpi-value">–</div><div class="kpi-foot">Scanning devices…</div></div>`,
    kpi('shield', 'Erasure jobs', sessions.length, failed ? `${done} verified · ${failed} failed` : `${done} verified`),
    kpi('recover', 'Recovery scans', recoveries.length, `${recoveries.filter(j => j.status === 'COMPLETED').length} completed`),
    kpi('cases', 'Open cases', openCases.length, holds ? `${holds} active legal hold${holds === 1 ? '' : 's'}` : 'No active legal holds'),
  ].join('');

  el.querySelector('#ov-activity').innerHTML = log.entries.length ? `
    <div class="table-wrap"><table class="table"><tbody>${log.entries.map(e => `
      <tr><td style="width:36%"><b>${esc(actionLabel(e.action))}</b></td>
          <td class="trunc muted">${esc(e.target || e.case_id || '')}</td>
          <td class="nowrap muted">${esc(e.actor)}</td>
          <td class="nowrap muted" style="text-align:right">${ago(e.ts)}</td></tr>`).join('')}
    </tbody></table></div>` : '<div class="empty"><strong>No activity yet</strong>Actions will appear here as they are logged.</div>';

  devicesPromise.then(devices => {
    const physical = devices.filter(d => !d.isImage).length;
    const images = devices.length - physical;
    const tile = el.querySelector('#ov-dev-kpi');
    if (tile) tile.outerHTML = kpi('drive', 'Storage targets', devices.length, `${physical} drive${physical === 1 ? '' : 's'} · ${images} sample disk${images === 1 ? '' : 's'}`);
  });

  const h = app.health;
  const ready = [
    [!!h, 'Engine running', h ? `${h.platform} · ${h.database}` : 'Start: python wipex.py'],
    [h?.capabilities?.signing, 'Signing key', h?.capabilities?.signing ? 'ECDSA P-256 certificates and audit entries' : 'Install the cryptography package'],
    [chain?.valid, 'Audit chain intact', chain ? (chain.valid ? `${chain.entries} entries verified` : `Broken at entry ${chain.brokenAt}`) : '—'],
    [h?.capabilities?.sleuthKit, 'The Sleuth Kit', h?.capabilities?.sleuthKit ? 'File-system recovery available' : 'Install pytsk3 for file-system recovery'],
    [h?.elevated, 'Administrator rights', h?.elevated ? 'Raw device access available' : 'Needed only for physical disks; lab images work without it', true],
    [!!h?.capabilities?.hardwarePurge, 'Firmware sanitize (Purge)', h?.capabilities?.hardwarePurge || 'Not available on this OS; use the Linux live USB', true],
    [h?.capabilities?.e01, 'E01 evidence images', 'Read and write Expert Witness (E01) images', true],
  ];
  el.querySelector('#ov-ready').innerHTML = `<div class="stack" style="gap:10px">${ready.map(([ok, name, detail, optional]) => `
    <div class="row" style="align-items:flex-start;flex-wrap:nowrap">
      <span class="check-ic ${ok ? '' : optional ? 'skip' : 'bad'}" style="margin-top:1px">${icon(ok ? 'check' : optional ? 'minus' : 'x', 13, 2.6)}</span>
      <div><div style="font-weight:600;font-size:13.5px">${esc(name)}</div><div class="muted small">${esc(detail)}</div></div>
    </div>`).join('')}</div>`;
}

function kpi(ic, label, value, foot) {
  return `<div class="card kpi"><div class="kpi-label">${icon(ic, 15)}${esc(label)}</div><div class="kpi-value">${esc(value)}</div><div class="kpi-foot">${esc(foot)}</div></div>`;
}

function renderModules(el) {
  const mods = [
    { href: '#/recovery', ic: 'recover', name: 'Recover deleted files', desc: 'Get back files deleted from a drive, USB stick or disk image, even after a format.',
      feats: ['Reads the drive without changing it', 'Finds deleted files by name and by content', 'Rebuilds split pictures and archives', 'Report with a fingerprint (SHA-256) of every file'] },
    { href: '#/files', ic: 'fileX', name: 'Permanently delete files', desc: 'Destroy chosen files so they cannot be recovered or traced.',
      feats: ['Overwrites the content before deleting', 'Removes names, hidden streams and Windows traces', 'Checks the drive afterwards to prove nothing is left', 'Honest warning on SSDs and flash drives'] },
    { href: '#/drive', ic: 'drive', name: 'Erase a whole drive', desc: 'Wipe an entire disk or USB drive and prove it with a certificate.',
      feats: ['NIST SP 800-88 methods, incl. drive firmware erase', 'Reads everything back after erasing', 'Tries to recover files as a final proof', 'Signed certificate with QR code and PDF'] },
  ];
  el.innerHTML = mods.map(m => `
    <a class="card module" href="${m.href}">
      <div class="module-top"><span class="module-icon">${icon(m.ic, 20)}</span>
        <div><div class="module-name">${m.name}</div><div class="module-desc">${m.desc}</div></div></div>
      <ul class="module-feats">${m.feats.map(f => `<li>${f}</li>`).join('')}</ul>
      <span class="module-cta">Open ${icon('arrow', 14)}</span>
    </a>`).join('');
}
