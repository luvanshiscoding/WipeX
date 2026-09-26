/**
 * WipeX frontend entry: sign-in, top navigation (filtered by role), hash router, engine status.
 */
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import { api, askOperator, can, esc, icon, onSessionEnded, renderOperator, session, setSession } from './core.js';
import * as overview from './views/overview.js';
import * as drive from './views/drive.js';
import * as files from './views/files.js';
import * as recovery from './views/recovery.js';
import * as cases from './views/cases.js';
import * as audit from './views/audit.js';
import * as verify from './views/verify.js';
import * as settings from './views/settings.js';

const ROUTES = [
  { id: 'overview', label: 'Overview', icon: 'overview', view: overview },
  { id: 'recovery', label: 'Recover Files', icon: 'recover', view: recovery, perm: 'recovery.run' },
  { id: 'files', label: 'Delete Files', icon: 'fileX', view: files, perm: 'files.erase' },
  { id: 'drive', label: 'Erase Drive', icon: 'drive', view: drive, perm: 'erasure.run' },
  { id: 'cases', label: 'Cases', icon: 'cases', view: cases, perm: 'case.read' },
  { id: 'audit', label: 'Audit Log', icon: 'audit', view: audit, perm: 'audit.read' },
  { id: 'verify', label: 'Verify', icon: 'shield', view: verify },
  { id: 'settings', label: 'Settings', icon: 'user', view: settings, perm: 'users.manage' },
];

export const app = { health: null };
const allowed = () => ROUTES.filter(r => !r.perm || can(r.perm));

function parseHash() {
  const [path, query = ''] = (location.hash.replace(/^#\/?/, '') || 'overview').split('?');
  return { id: path || 'overview', params: Object.fromEntries(new URLSearchParams(query)) };
}

function renderNav(active) {
  document.getElementById('nav').innerHTML = allowed().map(r =>
    `<a href="#/${r.id}" class="${r.id === active ? 'active' : ''}">${icon(r.icon, 16)}<span>${r.label}</span></a>`).join('');
}

async function route() {
  if (!session.user) return showAuth();
  const { id, params } = parseHash();
  const r = allowed().find(x => x.id === id) || ROUTES[0];
  renderNav(r.id);
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${r.id}`));
  document.title = `${r.label} · WipeX`;
  window.scrollTo({ top: 0 });
  try {
    await r.view.show(document.getElementById(`view-${r.id}`), params, app);
  } catch (e) {
    console.error(e);
  }
}

// ── Sign-in / first-run setup ──────────────────────────────────────────────
async function showAuth() {
  const rootEl = document.getElementById('auth-root');
  document.body.classList.add('signed-out');
  document.getElementById('nav').innerHTML = '';                       // never show the previous user's menu
  document.querySelectorAll('.view').forEach(v => { v.innerHTML = ''; v.classList.remove('active'); });
  let setup = false;
  try { setup = (await api('/api/auth/state')).setupRequired; } catch { /* engine offline: show sign-in */ }
  rootEl.innerHTML = `
    <div class="auth-wrap">
      <form class="auth-card" autocomplete="on">
        <div class="brand auth-brand">
          <span class="brand-mark">${icon('shield', 18, 2.2)}</span>
          <span class="brand-name">WipeX</span>
        </div>
        <h1 class="auth-title">${setup ? 'Create the administrator account' : 'Sign in'}</h1>
        <p class="auth-sub">${setup
          ? 'First run on this workstation. The administrator adds investigator, sanitizer and auditor accounts afterwards.'
          : 'Secure erasure and forensic recovery workstation. Every action is signed with your personal key.'}</p>
        ${setup ? '<div class="field"><label for="au-display">Full name</label><input class="input" id="au-display" autocomplete="name"></div>' : ''}
        <div class="field"><label for="au-user">Username</label><input class="input" id="au-user" autocomplete="username" required></div>
        <div class="field"><label for="au-pass">Password${setup ? ' (8+ characters)' : ''}</label>
          <input class="input" id="au-pass" type="password" autocomplete="${setup ? 'new-password' : 'current-password'}" required></div>
        <div class="auth-error" id="au-err" role="alert"></div>
        <button class="btn btn-primary btn-lg" type="submit">${setup ? 'Create account and sign in' : 'Sign in'}</button>
        <div class="muted small auth-foot">Runs locally · no network connection required</div>
      </form>
    </div>`;
  const form = rootEl.querySelector('form');
  form.querySelector('#au-user').focus();
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const body = { username: form.querySelector('#au-user').value.trim(), password: form.querySelector('#au-pass').value };
    if (setup) body.displayName = form.querySelector('#au-display').value.trim();
    try {
      const res = await api(setup ? '/api/auth/setup' : '/api/auth/login', { method: 'POST', body });
      setSession(res.token, res.user);
      rootEl.innerHTML = '';
      document.body.classList.remove('signed-out');
      await refreshHealth();
      route();
    } catch (e) {
      form.querySelector('#au-err').textContent = e.message;
    }
  });
}

async function restoreSession() {
  if (!session.token) return;
  try {
    const st = await api('/api/auth/state');
    if (st.user) setSession(session.token, st.user);
    else setSession('', null);
  } catch { setSession('', null); }
}

async function refreshHealth() {
  const el = document.getElementById('engine-status');
  try {
    app.health = await api('/api/health');
    el.innerHTML = `<span class="dot ok"></span><span class="engine-text">Online</span>`;
    el.title = `WipeX engine running on ${app.health.platform}${app.health.elevated ? ' as Administrator (drives can be read directly)' : ' without Administrator rights (drives cannot be read directly)'}`;
  } catch {
    app.health = null;
    el.innerHTML = '<span class="dot bad"></span><span class="engine-text">Engine offline</span>';
    el.title = 'Start the backend: python wipex.py';
  }
}

document.getElementById('operator-chip').addEventListener('click', () => askOperator());
window.addEventListener('hashchange', route);
onSessionEnded(() => { showAuth(); });
renderOperator();
refreshHealth().then(restoreSession).then(route);
setInterval(refreshHealth, 20000);
