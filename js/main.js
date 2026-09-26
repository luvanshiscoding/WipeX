/**
 * WipeX frontend entry: top navigation, hash router, engine status.
 */
import { api, askOperator, icon, renderOperator } from './core.js';
import * as overview from './views/overview.js';
import * as drive from './views/drive.js';
import * as files from './views/files.js';
import * as recovery from './views/recovery.js';
import * as cases from './views/cases.js';
import * as audit from './views/audit.js';
import * as verify from './views/verify.js';

const ROUTES = [
  { id: 'overview', label: 'Overview', icon: 'overview', view: overview },
  { id: 'drive', label: 'Drive Eraser', icon: 'drive', view: drive },
  { id: 'files', label: 'File Eraser', icon: 'fileX', view: files },
  { id: 'recovery', label: 'Recovery', icon: 'recover', view: recovery },
  { id: 'cases', label: 'Cases', icon: 'cases', view: cases },
  { id: 'audit', label: 'Audit Log', icon: 'audit', view: audit },
  { id: 'verify', label: 'Verify', icon: 'shield', view: verify },
];

export const app = { health: null };

function parseHash() {
  const [path, query = ''] = (location.hash.replace(/^#\/?/, '') || 'overview').split('?');
  return { id: path || 'overview', params: Object.fromEntries(new URLSearchParams(query)) };
}

function renderNav(active) {
  document.getElementById('nav').innerHTML = ROUTES.map(r =>
    `<a href="#/${r.id}" class="${r.id === active ? 'active' : ''}">${icon(r.icon, 16)}<span>${r.label}</span></a>`).join('');
}

async function route() {
  const { id, params } = parseHash();
  const r = ROUTES.find(x => x.id === id) || ROUTES[0];
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

async function refreshHealth() {
  const el = document.getElementById('engine-status');
  try {
    app.health = await api('/api/health');
    el.innerHTML = `<span class="dot ok"></span><span class="engine-text">Engine online${app.health.elevated ? ' · admin' : ''}</span>`;
    el.title = `Sleuth Kit: ${app.health.capabilities.sleuthKit ? 'yes' : 'no'} · Signing: ${app.health.capabilities.signing ? 'yes' : 'no'}`;
  } catch {
    app.health = null;
    el.innerHTML = '<span class="dot bad"></span><span class="engine-text">Engine offline</span>';
    el.title = 'Start the backend: python -m uvicorn main:app --port 8000';
  }
}

document.getElementById('operator-chip').addEventListener('click', () => askOperator());
window.addEventListener('hashchange', route);
renderOperator();
refreshHealth().then(route);
setInterval(refreshHealth, 20000);
