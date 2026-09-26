/**
 * WipeX frontend entry: sign-in, top navigation (filtered by role), hash router, engine status.
 */
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import { api, askOperator, can, esc, icon, loadProfiles, onSessionEnded, openProfile, profiles, renderOperator, session, setSession } from './core.js';
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
  if (!session.user) return;
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

// ── Access profile (no sign-in page in the prototype) ─────────────────────────
function showOffline() {
  const rootEl = document.getElementById('auth-root');
  document.body.classList.add('signed-out');
  document.getElementById('nav').innerHTML = '';
  rootEl.innerHTML = `
    <div class="auth-wrap"><div class="auth-card">
      <div class="brand auth-brand"><span class="brand-mark">${icon('shield', 18, 2.2)}</span><span class="brand-name">WipeX</span></div>
      <h1 class="auth-title">The WipeX engine is not running</h1>
      <p class="auth-sub">Start it on this workstation with <span class="mono">python wipex.py</span> (or double-click WipeX.cmd), then reload this page.</p>
      <button class="btn btn-primary btn-lg" id="au-retry">Try again</button>
    </div></div>`;
  rootEl.querySelector('#au-retry').addEventListener('click', () => boot());
}

async function openWorkstation() {
  if (!profiles.length) await loadProfiles();
  if (session.token) {
    try {
      const st = await api('/api/auth/state');
      if (st.user) { setSession(session.token, st.user); return; }
    } catch { /* token expired: open the profile again */ }
  }
  await openProfile();
}

async function boot() {
  await refreshHealth();
  try {
    await openWorkstation();
  } catch {
    return showOffline();
  }
  document.getElementById('auth-root').innerHTML = '';
  document.body.classList.remove('signed-out');
  route();
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
onSessionEnded((why) => { if (why === 'switched') route(); else boot(); });
renderOperator();
boot();
setInterval(refreshHealth, 20000);
