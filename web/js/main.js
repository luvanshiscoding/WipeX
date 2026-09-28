/**
 * WipeX frontend entry: access profile, sidebar navigation (filtered by role), demo mode,
 * hash router and engine status.
 */
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import { api, askOperator, can, demo, esc, icon, loadProfiles, nextDemoStep, onDemoChange, onSessionEnded, openProfile,
  profiles, refreshDemo, renderOperator, reportError, session, setDemo, setSession, toast } from './core.js';
import logoUrl from '../img/wipex-logo.svg';
import * as overview from './views/overview.js';
import * as erase from './views/erase.js';
import * as recovery from './views/recovery.js';
import * as cases from './views/cases.js';
import * as audit from './views/audit.js';
import * as verify from './views/verify.js';
import * as settings from './views/settings.js';

const ROUTES = [
  { id: 'overview', label: 'Overview', icon: 'overview', view: overview },
  { id: 'recovery', label: 'Recover Files', icon: 'recover', view: recovery, perm: 'recovery.run', group: 'Modules' },
  { id: 'erase', label: 'Erase', icon: 'eraser', view: erase, perm: ['erasure.run', 'files.erase'], group: 'Modules' },
  { id: 'cases', label: 'Cases', icon: 'cases', view: cases, perm: 'case.read', group: 'Records' },
  { id: 'audit', label: 'Audit Log', icon: 'audit', view: audit, perm: 'audit.read', group: 'Records' },
  { id: 'verify', label: 'Verify Certificate', icon: 'shield', view: verify, group: 'Records' },
  { id: 'settings', label: 'Settings', icon: 'user', view: settings, perm: 'users.manage', group: 'Admin' },
];

export const app = { health: null };
const allowed = () => ROUTES.filter(r => !r.perm || [].concat(r.perm).some(can));
// Earlier addresses of the two erase modules (bookmarks, certificate links, demo steps)
const ALIASES = { drive: '#/erase?mode=drive', files: '#/erase?mode=files' };

function parseHash() {
  const [path, query = ''] = (location.hash.replace(/^#\/?/, '') || 'overview').split('?');
  return { id: path || 'overview', params: Object.fromEntries(new URLSearchParams(query)) };
}

function renderNav(active) {
  let group = null;
  document.getElementById('nav').innerHTML = allowed().map(r => {
    const head = r.group && r.group !== group ? `<div class="nav-group">${r.group}</div>` : '';
    group = r.group || group;
    return `${head}<a href="#/${r.id}" class="${r.id === active ? 'active' : ''}">${icon(r.icon, 17)}<span>${r.label}</span></a>`;
  }).join('');
}

async function route() {
  if (!session.user) return;
  const { id, params } = parseHash();
  if (ALIASES[id]) { history.replaceState(null, '', ALIASES[id]); return route(); }
  const r = allowed().find(x => x.id === id) || ROUTES[0];
  renderNav(r.id);
  document.body.classList.remove('nav-open');
  document.getElementById('crumb').textContent = r.group ? `${r.group} / ${r.label}` : r.label;
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${r.id}`));
  document.title = `${r.label} · WipeX`;
  window.scrollTo({ top: 0 });
  refreshDemo();
  try {
    await r.view.show(document.getElementById(`view-${r.id}`), params, app);
  } catch (e) {
    console.error(e);
  }
}

// ── Demo mode ────────────────────────────────────────────────────────────────
function renderDemoBar() {
  const bar = document.getElementById('demo-bar');
  document.getElementById('demo-toggle').checked = demo.enabled;
  document.body.classList.toggle('demo-on', demo.enabled);
  if (!demo.enabled) { bar.hidden = true; return; }
  const next = nextDemoStep();
  bar.hidden = false;
  bar.innerHTML = `
    <span class="demo-pill">${icon('play', 14)} Demo mode</span>
    <span class="demo-text">Sample disks and sample files only · real drives are protected</span>
    <span class="spacer"></span>
    <span class="demo-count">${demo.completed}/${demo.total} steps</span>
    ${next ? `<a class="btn btn-sm demo-next" href="${next.href}">Next: ${esc(next.title)} ${icon('arrow', 13)}</a>`
      : `<span class="demo-done">${icon('check', 14, 2.6)} Walkthrough complete</span>`}`;
}

onDemoChange((_d, switched) => {
  renderDemoBar();
  if (switched) route();
});

document.getElementById('demo-toggle').addEventListener('change', async (e) => {
  try {
    await setDemo(e.target.checked);
    toast(demo.enabled ? 'Demo mode on: practise on sample disks and sample files' : 'Demo mode off: real drives can be used', 'ok');
  } catch (err) { reportError(err); e.target.checked = demo.enabled; }
});

// ── Access profile (no sign-in page in the prototype) ─────────────────────────
function showOffline() {
  const rootEl = document.getElementById('auth-root');
  document.body.classList.add('signed-out');
  document.getElementById('nav').innerHTML = '';
  rootEl.innerHTML = `
    <div class="auth-wrap"><div class="auth-card">
      <div class="brand auth-brand"><img class="brand-logo" src="${logoUrl}" alt=""><span class="brand-name">WipeX</span></div>
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
  await refreshDemo();
  route();
}

async function refreshHealth() {
  const el = document.getElementById('engine-status');
  try {
    app.health = await api('/api/health');
    el.innerHTML = `<span class="dot ok"></span><span class="engine-text">Engine online${app.health.elevated ? ' · Admin' : ''}</span>`;
    el.title = `WipeX engine running on ${app.health.platform}${app.health.elevated ? ' as Administrator (drives can be read directly)' : ' without Administrator rights (drives cannot be read directly)'}`;
  } catch {
    app.health = null;
    el.innerHTML = '<span class="dot bad"></span><span class="engine-text">Engine offline</span>';
    el.title = 'Start the backend: python wipex.py';
  }
}

document.getElementById('operator-chip').addEventListener('click', () => askOperator());
document.getElementById('menu-btn').addEventListener('click', () => document.body.classList.toggle('nav-open'));
document.getElementById('scrim').addEventListener('click', () => document.body.classList.remove('nav-open'));
window.addEventListener('hashchange', route);
onSessionEnded((why) => { if (why === 'switched') route(); else boot(); });
renderOperator();
boot();
setInterval(refreshHealth, 20000);
