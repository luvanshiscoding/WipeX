/**
 * WipeX frontend core: API client, session, job polling, formatting, icons,
 * toasts, modals and the file picker.
 */

// ── API ────────────────────────────────────────────────────────────────────
// The backend serves the built UI itself and Vite proxies /api in development,
// so requests are same-origin; only a page opened from disk needs an absolute URL.
const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:8000' : '';

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ── Session ────────────────────────────────────────────────────────────────
const TOKEN_KEY = 'wipex_token';
export const session = { token: '', user: null };
try { session.token = sessionStorage.getItem(TOKEN_KEY) || ''; } catch { /* storage unavailable */ }
let onSignedOut = null;

export function setSession(token, user) {
  session.token = token || '';
  session.user = user || null;
  try {
    if (session.token) sessionStorage.setItem(TOKEN_KEY, session.token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* storage unavailable */ }
  renderOperator();
}

export function onSessionEnded(fn) { onSignedOut = fn; }

/** True when the signed-in user's role grants the permission (admin has '*'). */
export function can(perm) {
  const p = session.user?.permissions || [];
  return p.includes('*') || p.includes(perm);
}

export async function api(path, { method = 'GET', body, raw = false } = {}) {
  let res;
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (session.token) headers.Authorization = `Bearer ${session.token}`;
  try {
    res = await fetch(API_BASE + path, {
      method, headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: 'no-store',
    });
  } catch (e) {
    throw new ApiError(0, 'Cannot reach the WipeX engine. Start it with: python wipex.py');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = j.detail || detail; } catch { /* not json */ }
    if (res.status === 401 && session.token && !path.startsWith('/api/auth/')) {
      setSession('', null);
      onSignedOut && onSignedOut();
    }
    throw new ApiError(res.status, typeof detail === 'string' ? detail : JSON.stringify(detail));
  }
  return raw ? res : res.json();
}

// ── Demo mode (sample disks and sample files only, with a guided walkthrough) ──
export const demo = { enabled: false, steps: [], completed: 0, total: 0 };
const demoListeners = [];
export function onDemoChange(fn) { demoListeners.push(fn); }
const emitDemo = (switched) => demoListeners.forEach(fn => fn(demo, switched));

/** Re-read the walkthrough progress (cheap: a few audit-log rows). */
export async function refreshDemo() {
  try { Object.assign(demo, await api('/api/demo')); } catch { /* engine offline */ }
  emitDemo(false);
  return demo;
}

export async function setDemo(on) {
  Object.assign(demo, await api('/api/demo', { method: 'POST', body: { enabled: on } }));
  emitDemo(true);
  return demo;
}

export const nextDemoStep = () => demo.steps.find(s => !s.done) || null;

/** URL for links and images (downloads cannot send headers, so the token rides in the query). */
export function apiUrl(path) {
  if (!session.token || !path.startsWith('/api/')) return API_BASE + path;
  return `${API_BASE}${path}${path.includes('?') ? '&' : '?'}token=${encodeURIComponent(session.token)}`;
}

/** Poll a background job until it finishes; onUpdate receives each snapshot. */
export async function waitForJob(jobId, onUpdate, interval = 600) {
  for (;;) {
    const job = await api(`/api/jobs/${jobId}`);
    onUpdate && onUpdate(job);
    if (job.status !== 'RUNNING') return job;
    await sleep(interval);
  }
}

export const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ── Formatting ─────────────────────────────────────────────────────────────
export function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function bytes(n) {
  n = Number(n) || 0;
  if (n < 1000) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1000; i++; } while (n >= 1000 && i < u.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
}

export function when(ts) {
  if (!ts) return '—';
  const d = new Date(String(ts).replace(' UTC', 'Z').replace(' ', 'T'));
  return isNaN(d) ? String(ts) : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function ago(ts) {
  const d = new Date(String(ts).replace(' UTC', 'Z').replace(' ', 'T'));
  if (isNaN(d)) return '';
  const s = Math.round((Date.now() - d) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const short = (h, n = 12) => h ? `${h.slice(0, n)}…` : '—';

// ── Icons (inline SVG, stroke-based) ───────────────────────────────────────
const P = {
  overview: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  drive: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
  file: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/>',
  fileX: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M9.5 12.5l5 5M14.5 12.5l-5 5"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  recover: '<path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/><path d="M12 8v4l3 2"/>',
  cases: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M3 13h18"/>',
  audit: '<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4 6l1 1 2-2M4 12l1 1 2-2M4 18l1 1 2-2"/>',
  shield: '<path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6z"/><path d="M9 12l2 2 4-4"/>',
  check: '<path d="M5 12l5 5L20 7"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  minus: '<path d="M6 12h12"/>',
  alert: '<path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17.5v.01"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="1.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  back: '<path d="M19 12H5M11 18l-6-6 6-6"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5"/><path d="M5 20h14"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
  image: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M21 17l-5-5-9 8"/>',
  up: '<path d="M12 19V5M6 11l6-6 6 6"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>',
  disk: '<rect x="3" y="6" width="18" height="12" rx="2"/><path d="M7 14h.01M11 14h6"/>',
  hold: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14v3"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  usb: '<rect x="7" y="9" width="10" height="13" rx="2"/><path d="M9 9V3h6v6M11 5.5h.01M13 5.5h.01"/>',
  play: '<circle cx="12" cy="12" r="9"/><path d="M10 8.5l5 3.5-5 3.5z"/>',
  star: '<path d="M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z"/>',
  eraser: '<path d="M9 20h11"/><path d="M4.6 14.6l9.2-9.2a2 2 0 0 1 2.8 0l2.9 2.9a2 2 0 0 1 0 2.8L12 18.6a2 2 0 0 1-1.4.6H8.2a2 2 0 0 1-1.4-.6l-2.2-2.2a2 2 0 0 1 0-2.8z"/><path d="M9.2 10l5.4 5.4"/>',
  percent: '<path d="M19 5L5 19"/><circle cx="7" cy="7" r="2.5"/><circle cx="17" cy="17" r="2.5"/>',
};
export function icon(name, size = 16, sw = 1.9) {
  return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;
}

// ── Toasts ─────────────────────────────────────────────────────────────────
export function toast(message, tone = '') {
  const root = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${tone}`;
  el.innerHTML = `${icon(tone === 'bad' ? 'alert' : tone === 'ok' ? 'check' : 'info', 16)}<span>${esc(message)}</span>`;
  root.appendChild(el);
  setTimeout(() => el.remove(), tone === 'bad' ? 7000 : 4000);
}

export function reportError(e) {
  console.error(e);
  toast(e.message || String(e), 'bad');
}

// ── Modals ─────────────────────────────────────────────────────────────────
export function modal({ title, sub = '', body = '', actions = [], danger = false, wide = false, onMount }) {
  return new Promise(resolve => {
    const root = document.getElementById('modal-root');
    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    backdrop.innerHTML = `
      <div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true">
        <div class="modal-head ${danger ? 'danger' : ''}">
          <div class="modal-title">${esc(title)}</div>
          ${sub ? `<div class="modal-sub">${sub}</div>` : ''}
        </div>
        <div class="modal-body">${body}</div>
        <div class="modal-foot">${actions.map((a, i) => `<button class="btn ${a.cls || 'btn-secondary'}" data-i="${i}">${esc(a.label)}</button>`).join('')}</div>
      </div>`;
    const close = (val) => { backdrop.remove(); document.removeEventListener('keydown', onKey); resolve(val); };
    const onKey = (e) => { if (e.key === 'Escape') close(null); };
    document.addEventListener('keydown', onKey);
    backdrop.addEventListener('mousedown', e => { if (e.target === backdrop) close(null); });
    backdrop.querySelectorAll('.modal-foot button').forEach(btn => {
      btn.addEventListener('click', async () => {
        const a = actions[+btn.dataset.i];
        if (a.value === undefined && a.onClick) {
          const r = await a.onClick(backdrop);
          if (r !== false) close(r);
        } else close(a.value);
      });
    });
    root.appendChild(backdrop);
    onMount && onMount(backdrop, close);
    const first = backdrop.querySelector('input, select, textarea, .btn-primary, .btn-danger');
    first && first.focus();
  });
}

/** Destructive confirmation: the user must type the confirmation word. */
export function confirmDanger({ title, sub, rows = [], word = 'ERASE', confirmLabel = 'Erase', extra = '', approval = '' }) {
  return modal({
    title, sub, danger: true,
    body: `
      <dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>
      ${extra}
      ${approval ? `<div class="approval-box">
        <div class="label">Approver ${approval === 'required' ? '(two-person rule: required)' : '(optional)'}</div>
        <div class="hint">A second person with approval rights approves here. The approval is signed with their own key.</div>
        <select class="select" id="ap-user" style="margin-top:8px">
          <option value="">Choose the approving profile…</option>
          ${profiles.filter(p => ['admin', 'investigator'].includes(p.role) && p.username !== session.user?.username)
            .map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}
        </select></div>` : ''}
      <div class="field">
        <label for="confirm-word">Type <b>${word}</b> to confirm</label>
        <input class="input mono" id="confirm-word" autocomplete="off" spellcheck="false">
      </div>`,
    actions: [
      { label: 'Cancel', value: false },
      { label: confirmLabel, cls: 'btn-danger', onClick: (bd) => {
        if (bd.querySelector('#confirm-word').value.trim().toUpperCase() !== word) {
          bd.querySelector('#confirm-word').focus();
          toast(`Type ${word} to confirm`, 'bad');
          return false;
        }
        if (!approval) return true;
        const approver = bd.querySelector('#ap-user').value;
        if (approval === 'required' && !approver) {
          toast('The two-person rule is on: choose the approving profile', 'bad');
          return false;
        }
        return { approver, approverPassword: '' };
      } },
    ],
  });
}

// ── Access profile ("View as") ──────────────────────────────────────────────
const PROFILE_KEY = 'wipex_profile';
export const profiles = [];

export function getOperator() { return session.user?.username || ''; }

export async function loadProfiles() {
  const list = await api('/api/auth/profiles');
  profiles.splice(0, profiles.length, ...list);
  return profiles;
}

/** Open an NTRO access profile (no password in the prototype; the engine only serves this workstation). */
export async function openProfile(id) {
  let wanted = id;
  if (!wanted) { try { wanted = localStorage.getItem(PROFILE_KEY) || ''; } catch { /* storage unavailable */ } }
  const res = await api('/api/auth/profile', { method: 'POST', body: { profile: wanted || 'admin' } })
    .catch(() => api('/api/auth/profile', { method: 'POST', body: { profile: 'admin' } }));
  setSession(res.token, res.user);
  const current = profiles.find(p => p.username === res.user.username);
  try { if (current) localStorage.setItem(PROFILE_KEY, current.id); } catch { /* storage unavailable */ }
  return res.user;
}

export function renderOperator() {
  const u = session.user;
  const nameEl = document.getElementById('operator-name');
  const avatarEl = document.getElementById('operator-avatar');
  if (!nameEl || !avatarEl) return;
  nameEl.innerHTML = u ? `<span class="operator-view">View as</span>${esc(u.displayName)}` : 'Opening…';
  nameEl.parentElement.title = u ? `${u.displayName} (${u.roleLabel}). Switch the access profile` : '';
  avatarEl.textContent = u ? u.displayName.replace(/^NTRO\s+/, '').split(/\s+/).map(s => s[0]).join('').slice(0, 2).toUpperCase() : '·';
}

const PROFILE_NOTES = {
  admin: 'Every module, users and settings',
  investigator: 'Cases, evidence, recovery, legal holds; approves erasures',
  sanitizer: 'Drive and file erasure, certificates',
  auditor: 'Read-only: cases, audit log, reports, certificates',
};

/** "View as" menu: switch between the NTRO access profiles. */
export async function askOperator() {
  const u = session.user;
  const options = profiles.map(p => `
    <label class="choice ${u && p.username === u.username ? 'on' : ''}" style="margin-bottom:8px">
      <input type="radio" name="pf" value="${esc(p.id)}" ${u && p.username === u.username ? 'checked' : ''}>
      <b>${esc(p.name)}</b><span>${esc(PROFILE_NOTES[p.id] || p.roleLabel)}</span></label>`).join('');
  const choice = await modal({
    title: 'View WipeX as',
    sub: 'Controlled access for NTRO: profiles open only on this workstation, and every action is recorded and signed with the profile’s own key.',
    body: options,
    actions: [{ label: 'Cancel', value: null }, { label: 'Switch profile', cls: 'btn-primary',
      onClick: bd => bd.querySelector('input[name=pf]:checked')?.value || null }],
  });
  if (choice && (!u || profiles.find(p => p.id === choice)?.username !== u.username)) {
    try {
      await openProfile(choice);
      toast(`Now viewing as ${session.user.displayName}`, 'ok');
      onSignedOut && onSignedOut('switched');
    } catch (e) { reportError(e); }
  }
  return getOperator();
}

export async function requireOperator() { return getOperator(); }

// ── Administrator / root rights ─────────────────────────────────────────────
/** Restart the engine with Administrator / root rights; the page reloads when the new engine answers. */
export async function restartElevated() {
  let res;
  try { res = await api('/api/system/elevate', { method: 'POST' }); } catch (e) { reportError(e); return false; }
  if (!res.started) { toast(res.message, res.elevated ? 'ok' : 'bad'); return !!res.elevated; }
  const wait = modal({ title: 'Restarting WipeX with Administrator rights',
    sub: esc(res.message), body: '<div class="job-msg"><span class="spinner"></span><span>Waiting for the engine…</span></div>',
    actions: [{ label: 'Close', value: null }] });
  const deadline = Date.now() + 180000;
  while (Date.now() < deadline) {
    await sleep(1500);
    try {
      const h = await fetch(API_BASE + '/api/health', { cache: 'no-store' }).then(r => r.json());
      if (h.elevated) { location.reload(); return true; }
    } catch { /* the engine is switching over */ }
  }
  document.querySelector('.modal-backdrop')?.remove();
  await wait;
  toast('WipeX is still running without Administrator rights', 'bad');
  return false;
}

// ── File picker (the file browser in a dialog) ───────────────────────────────
/** pick: 'any' | 'folder' | 'file'. Resolves to an array of paths, or null when cancelled. */
export async function pickPaths({ title = 'Choose files or folders', start = '', pick = 'any', multi = false } = {}) {
  const { mountExplorer } = await import('./explorer.js');
  const selected = new Map();
  const what = pick === 'folder' ? 'a folder' : pick === 'file' ? 'a file' : 'an item';
  return modal({
    title, wide: true,
    sub: `Tick ${what}; double-click a folder to open it. Protected system locations show a lock.`,
    body: '<div class="xp-modal"></div>',
    actions: [{ label: 'Cancel', value: null }, { label: 'Choose', cls: 'btn-primary', onClick: () => {
      if (!selected.size) { toast(`Tick ${what} first`, 'bad'); return false; }
      return [...selected.keys()];
    } }],
    onMount: (bd) => mountExplorer(bd.querySelector('.xp-modal'), { multi, pick, start, selected }),
  });
}

// ── Small render helpers ───────────────────────────────────────────────────
export function badge(text, tone = '') { return `<span class="badge ${tone}">${esc(text)}</span>`; }

export function statusBadge(status) {
  const map = {
    COMPLETED: ['Completed', 'ok'], RUNNING: ['Running', 'info'], IN_PROGRESS: ['In progress', 'info'],
    FAILED: ['Failed', 'bad'], VERIFICATION_FAILED: ['Verification failed', 'bad'],
    PASS: ['Pass', 'ok'], FAIL: ['Fail', 'bad'], PARTIAL: ['Partial', 'warn'],
    OPEN: ['Open', 'info'], CLOSED: ['Closed', ''],
  };
  const [t, tone] = map[status] || [status || '—', ''];
  return badge(t, tone);
}

export function progressBlock(pct, message, running = true) {
  return `
    <div class="stack" style="gap:8px">
      <div class="progress ${pct == null ? 'indeterminate' : ''}"><div style="width:${pct || 0}%"></div></div>
      <div class="job-msg">${running ? '<span class="spinner"></span>' : ''}<span>${esc(message || '')}</span>${pct != null ? `<span class="spacer"></span><span class="mono">${pct}%</span>` : ''}</div>
    </div>`;
}

export function checksList(checks = []) {
  if (!checks.length) return '';
  return `<div class="checks">${checks.map(c => {
    const state = c.passed === true ? '' : c.passed === false ? 'bad' : 'skip';
    const ic = c.passed === true ? 'check' : c.passed === false ? 'x' : 'minus';
    return `<div class="check-row">
      <span class="check-ic ${state}">${icon(ic, 13, 2.6)}</span>
      <div><div class="check-name">${esc(c.name)}</div><div class="check-detail">${esc(describeCheck(c))}</div></div>
      <span>${c.passed === true ? badge('Pass', 'ok') : c.passed === false ? badge('Fail', 'bad') : badge('Skipped')}</span>
    </div>`;
  }).join('')}</div>`;
}

function describeCheck(c) {
  if (c.name === 'Pattern read-back') {
    return `Expected ${c.expected}; coverage ${c.coverage}; ${c.mismatchedRegions} mismatched region(s)` +
      (c.unchangedBlocks ? `; ${c.unchangedBlocks} block(s) still hold old content` : '') +
      (c.readErrors ? `; ${c.readErrors} read error(s)` : '');
  }
  if (c.name === 'Canary blocks') return `${c.planted} marker blocks planted before erasure; ${c.recovered} found afterwards`;
  if (c.name === 'Recovery attempt (M3)') return c.skipped ? c.reason : c.detail;
  if (c.detail) return c.detail;
  return Object.entries(c).filter(([k]) => !['name', 'passed'].includes(k)).map(([k, v]) => `${k}: ${v}`).join('; ');
}
