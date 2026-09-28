/** Settings (administrator): access profiles, roles, two-person rule, workstation key. */
import { api, badge, esc, icon, modal, reportError, restartElevated, session, toast, when } from '../core.js';

const S = { users: [], roles: [], dual: false, key: '', admin: null };
let root;

const ROLE_NOTES = {
  admin: 'Everything, including users and settings',
  investigator: 'Cases, evidence, recovery, legal holds; approves erasures',
  sanitizer: 'Drive and file erasure, certificates, lab images',
  auditor: 'Read-only: cases, audit log, reports',
};

export async function show(el) {
  root = el;
  await refresh();
}

async function refresh() {
  try {
    const [users, roles, dual, key, admin] = await Promise.all([
      api('/api/users'), api('/api/roles'), api('/api/settings/dual-approval'), api('/api/crypto/public-key'),
      api('/api/system/admin').catch(() => null)]);
    Object.assign(S, { users, roles, dual: dual.enabled, key: key.publicKeyPem, admin });
  } catch (e) { reportError(e); }
  render();
}

function userRow(u) {
  const me = u.username === session.user?.username;
  const action = me ? '<span class="muted small">current</span>' : '';
  return `<tr>
    <td><div style="font-weight:600">${esc(u.displayName)}</div><div class="muted small mono">${esc(u.username)}</div></td>
    <td>${badge(u.roleLabel, u.role === 'admin' ? 'blue' : '')}</td>
    <td>${u.active ? badge('Active', 'ok') : badge('Disabled', 'bad')}</td>
    <td class="mono small">${esc(u.keyId)}</td>
    <td class="small muted nowrap">${u.lastLogin ? esc(when(u.lastLogin)) : 'never'}</td>
    <td class="num nowrap">${action}</td>
  </tr>`;
}

function headHtml() {
  const desc = 'NTRO access profiles, erasure policy and the workstation key. Switch profile with "View as" at the top right.';
  return `<div class="page-head"><div><h1 class="page-title">Settings</h1>`
    + `<p class="page-desc">${desc}</p></div></div>`;
}

function usersCard() {
  const rows = S.users.filter(u => u.username.startsWith('ntro.')).map(userRow).join('');
  return `<div class="card"><div class="card-head"><span class="card-title">Access profiles</span>`
    + `<span class="card-sub">controlled access: opened only by the engine on this workstation</span></div>`
    + `<div class="table-wrap"><table class="table"><thead><tr><th>Profile</th><th>Role</th><th>Status</th>`
    + `<th>Signing key</th><th>Last opened</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function rolesCard() {
  const items = S.roles.map(r => `<dt>${esc(r.label)}</dt><dd>${esc(ROLE_NOTES[r.id] || '')}</dd>`).join('');
  return `<div class="card"><div class="card-head"><span class="card-title">Roles</span></div>`
    + `<div class="card-body"><dl class="kv">${items}</dl></div></div>`;
}

function policyCard() {
  const toggle = `<label class="toggle"><input type="checkbox" id="st-dual" ${S.dual ? 'checked' : ''}>`
    + `<span>Two-person rule<span class="hint">Every drive, file or phone erasure needs a second person with approval rights `
    + `(Forensic Investigator or Lab Administrator profile) to approve it.</span></span></label>`;
  return `<div class="card"><div class="card-head"><span class="card-title">Erasure policy</span></div>`
    + `<div class="card-body">${toggle}</div></div>`;
}

function adminCard() {
  const a = S.admin;
  if (!a) return '';
  const who = a.platform === 'Windows' ? 'Administrator' : 'root';
  const startsWhen = a.platform === 'Windows' ? 'every time you sign in to Windows' : 'when the computer starts';
  return `<div class="card"><div class="card-head"><span class="card-title">${who} rights</span>`
    + `${a.elevated ? badge('Running with them', 'ok') : badge('Not running with them', 'bad')}</div>`
    + `<div class="card-body stack" style="gap:12px">`
    + (a.elevated ? '' : `<button class="btn btn-danger btn-sm" id="st-elevate" style="align-self:flex-start">${icon('shield', 14)} Restart as ${who}</button>`)
    + `<label class="toggle"><input type="checkbox" id="st-auto" ${a.autostart ? 'checked' : ''} ${a.elevated ? '' : 'disabled'}>`
    + `<span>Start WipeX with ${who} rights automatically<span class="hint">WipeX then starts ${startsWhen} with no prompt, and you open it from the link `
    + `<span class="mono">${esc(location.origin)}/</span> (a desktop shortcut is added). ${a.elevated ? '' : `Needs WipeX running with ${who} rights to switch.`}</span></span></label>`
    + `</div></div>`;
}

function keyCard() {
  return `<div class="card"><div class="card-head"><span class="card-title">Workstation signing key</span>`
    + `<span class="card-sub">ECDSA P-256; verifies certificates and the audit log</span></div>`
    + `<div class="card-body"><div class="key-block">${esc(S.key || 'Unavailable')}</div></div></div>`;
}

function render() {
  root.innerHTML = headHtml()
    + `<div class="grid cols-side"><div class="stack">${usersCard()}</div>`
    + `<div class="stack">${adminCard()}${policyCard()}${rolesCard()}${keyCard()}</div></div>`;
  root.querySelector('#st-elevate')?.addEventListener('click', () => restartElevated());
  root.querySelector('#st-auto')?.addEventListener('change', async (e) => {
    try {
      const r = await api('/api/system/autostart', { method: 'POST', body: { enabled: e.target.checked } });
      toast(r.installed ? `WipeX ${r.how}. Open it at ${r.link}` : 'Automatic start removed', 'ok');
      S.admin.autostart = !!r.installed;
    } catch (err) { reportError(err); e.target.checked = !e.target.checked; }
  });
  root.querySelector('#st-dual').addEventListener('change', async (e) => {
    try {
      await api('/api/settings/dual-approval', { method: 'POST', body: { enabled: e.target.checked } });
      toast(e.target.checked ? 'Two-person rule enabled' : 'Two-person rule disabled', 'ok');
    } catch (err) { reportError(err); e.target.checked = !e.target.checked; }
  });
}
