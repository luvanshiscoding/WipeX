/** Users & Settings (administrator): accounts, roles, two-person rule, workstation key. */
import { api, badge, esc, icon, modal, reportError, session, toast, when } from '../core.js';

const S = { users: [], roles: [], dual: false, key: '' };
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
    const [users, roles, dual, key] = await Promise.all([
      api('/api/users'), api('/api/roles'), api('/api/settings/dual-approval'), api('/api/crypto/public-key')]);
    Object.assign(S, { users, roles, dual: dual.enabled, key: key.publicKeyPem });
  } catch (e) { reportError(e); }
  render();
}

function userRow(u) {
  const me = u.username === session.user?.username;
  const action = me ? '<span class="muted small">you</span>'
    : `<button class="btn btn-secondary btn-sm" data-edit="${esc(u.username)}">Edit</button>`;
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
  const desc = 'Accounts and roles for this workstation. Each user signs their own actions with a personal key.';
  return `<div class="page-head"><div><h1 class="page-title">Users &amp; Settings</h1>`
    + `<p class="page-desc">${desc}</p></div>`
    + `<button class="btn btn-primary" id="st-add">${icon('plus', 16)} Add user</button></div>`;
}

function usersCard() {
  const rows = S.users.map(userRow).join('');
  return `<div class="card"><div class="card-head"><span class="card-title">Users</span>`
    + `<span class="card-sub">${S.users.length} account(s)</span></div>`
    + `<div class="table-wrap"><table class="table"><thead><tr><th>User</th><th>Role</th><th>Status</th>`
    + `<th>Signing key</th><th>Last sign-in</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function rolesCard() {
  const items = S.roles.map(r => `<dt>${esc(r.label)}</dt><dd>${esc(ROLE_NOTES[r.id] || '')}</dd>`).join('');
  return `<div class="card"><div class="card-head"><span class="card-title">Roles</span></div>`
    + `<div class="card-body"><dl class="kv">${items}</dl></div></div>`;
}

function policyCard() {
  const toggle = `<label class="toggle"><input type="checkbox" id="st-dual" ${S.dual ? 'checked' : ''}>`
    + `<span>Two-person rule<span class="hint">Every drive, file or phone erasure needs a second user with approval rights `
    + `(investigator or administrator) to sign in and approve it.</span></span></label>`;
  return `<div class="card"><div class="card-head"><span class="card-title">Erasure policy</span></div>`
    + `<div class="card-body">${toggle}</div></div>`;
}

function keyCard() {
  return `<div class="card"><div class="card-head"><span class="card-title">Workstation signing key</span>`
    + `<span class="card-sub">ECDSA P-256; verifies certificates and the audit log</span></div>`
    + `<div class="card-body"><div class="key-block">${esc(S.key || 'Unavailable')}</div></div></div>`;
}

function render() {
  root.innerHTML = headHtml()
    + `<div class="grid cols-side"><div class="stack">${usersCard()}</div>`
    + `<div class="stack">${policyCard()}${rolesCard()}${keyCard()}</div></div>`;
  root.querySelector('#st-add').addEventListener('click', addUser);
  root.querySelectorAll('[data-edit]').forEach(b => b.addEventListener('click', () => editUser(b.dataset.edit)));
  root.querySelector('#st-dual').addEventListener('change', async (e) => {
    try {
      await api('/api/settings/dual-approval', { method: 'POST', body: { enabled: e.target.checked } });
      toast(e.target.checked ? 'Two-person rule enabled' : 'Two-person rule disabled', 'ok');
    } catch (err) { reportError(err); e.target.checked = !e.target.checked; }
  });
}

function roleOptions(selected) {
  return S.roles.map(r => `<option value="${r.id}" ${r.id === selected ? 'selected' : ''}>${esc(r.label)}</option>`).join('');
}

async function addUser() {
  const res = await modal({
    title: 'Add user',
    sub: 'A personal signing key is generated and protected with this password.',
    body: `<div class="field"><label for="nu-name">Full name</label><input class="input" id="nu-name"></div>`
      + `<div class="field"><label for="nu-user">Username</label><input class="input" id="nu-user" autocomplete="off"></div>`
      + `<div class="field"><label for="nu-role">Role</label><select class="select" id="nu-role">${roleOptions('sanitizer')}</select></div>`
      + `<div class="field"><label for="nu-pass">Initial password (8+ characters)</label>`
      + `<input class="input" id="nu-pass" type="password" autocomplete="new-password"></div>`,
    actions: [{ label: 'Cancel', value: null }, { label: 'Add user', cls: 'btn-primary', onClick: bd => ({
      displayName: bd.querySelector('#nu-name').value.trim(), username: bd.querySelector('#nu-user').value.trim(),
      role: bd.querySelector('#nu-role').value, password: bd.querySelector('#nu-pass').value }) }],
  });
  if (!res) return;
  try {
    await api('/api/users', { method: 'POST', body: res });
    toast(`User ${res.username} added`, 'ok');
    await refresh();
  } catch (e) { reportError(e); }
}

async function editUser(username) {
  const u = S.users.find(x => x.username === username);
  if (!u) return;
  const res = await modal({
    title: `Edit ${u.displayName}`,
    sub: 'Resetting the password issues a new signing key; signatures made with the old key stay verifiable.',
    body: `<div class="field"><label for="eu-role">Role</label><select class="select" id="eu-role">${roleOptions(u.role)}</select></div>`
      + `<label class="toggle"><input type="checkbox" id="eu-active" ${u.active ? 'checked' : ''}><span>Account active</span></label>`
      + `<div class="field" style="margin-top:12px"><label for="eu-pass">New password (leave empty to keep)</label>`
      + `<input class="input" id="eu-pass" type="password" autocomplete="new-password"></div>`,
    actions: [{ label: 'Cancel', value: null }, { label: 'Save', cls: 'btn-primary', onClick: bd => {
      const body = { role: bd.querySelector('#eu-role').value, active: bd.querySelector('#eu-active').checked };
      const pw = bd.querySelector('#eu-pass').value;
      if (pw) body.newPassword = pw;
      return body;
    } }],
  });
  if (!res) return;
  try {
    await api(`/api/users/${encodeURIComponent(username)}`, { method: 'PATCH', body: res });
    toast('User updated', 'ok');
    await refresh();
  } catch (e) { reportError(e); }
}
