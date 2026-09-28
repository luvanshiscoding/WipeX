/**
 * File browser in the style of Windows Explorer and macOS Finder: a side panel with the user's
 * folders and drives, an address bar, and a sortable list of folders and files with check boxes.
 * Used on the Erase page (choose many items) and in the picker dialog (one folder or one file).
 * In demo mode it shows only the sample files WipeX created.
 */
import { api, bytes, esc, icon } from './core.js';

const TYPES = {
  txt: 'Text document', csv: 'CSV file', log: 'Log file', md: 'Markdown file', json: 'JSON file', xml: 'XML file', ini: 'Configuration file',
  jpg: 'JPEG image', jpeg: 'JPEG image', png: 'PNG image', gif: 'GIF image', bmp: 'Bitmap image', webp: 'WebP image', heic: 'HEIC image', svg: 'SVG image',
  pdf: 'PDF document', doc: 'Word document', docx: 'Word document', rtf: 'Rich text document', odt: 'Text document',
  xls: 'Excel workbook', xlsx: 'Excel workbook', ods: 'Spreadsheet', ppt: 'PowerPoint presentation', pptx: 'PowerPoint presentation',
  zip: 'ZIP archive', rar: 'RAR archive', '7z': '7-Zip archive', tar: 'TAR archive', gz: 'GZip archive',
  db: 'Database file', sqlite: 'SQLite database', mp4: 'MP4 video', mov: 'QuickTime video', avi: 'AVI video', mkv: 'MKV video',
  mp3: 'MP3 audio', wav: 'WAV audio', exe: 'Application', msi: 'Windows installer', dmg: 'Disk image', iso: 'Disc image',
  img: 'Disk image', dd: 'Disk image', e01: 'Forensic image (E01)', lnk: 'Shortcut', py: 'Python file', js: 'JavaScript file', html: 'HTML document',
};
const GROUP = {
  image: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'heic', 'svg'], pdf: ['pdf'], doc: ['doc', 'docx', 'rtf', 'odt', 'txt', 'md', 'log'],
  sheet: ['xls', 'xlsx', 'ods', 'csv'], slides: ['ppt', 'pptx'], archive: ['zip', 'rar', '7z', 'tar', 'gz'],
  media: ['mp4', 'mov', 'avi', 'mkv', 'mp3', 'wav'], disk: ['img', 'dd', 'e01', 'iso', 'dmg', 'db', 'sqlite'],
};
const COLOR = { image: '#1f9d6b', pdf: '#d64545', doc: '#2f6fd1', sheet: '#1e8a4c', slides: '#d9730d', archive: '#b7791f', media: '#7c4dde', disk: '#4b5d6b', other: '#8b98a5' };

const ext = (name) => (/\.([^.\\/]+)$/.exec(name || '') || [])[1]?.toLowerCase() || '';
const groupOf = (e) => Object.keys(GROUP).find(g => GROUP[g].includes(ext(e.name))) || 'other';

export function fileType(e) {
  if (e.isDir) return 'File folder';
  const x = ext(e.name);
  return TYPES[x] || (x ? `${x.toUpperCase()} file` : 'File');
}

function folderSvg(size = 20) {
  return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true"><path d="M2.5 6.2c0-1 .8-1.7 1.7-1.7h4.9l2 2.1h8.7c.9 0 1.7.8 1.7 1.7v1H2.5z" fill="#e0a526"/>
    <path d="M2.5 8.6h19v9.7c0 1-.8 1.7-1.7 1.7H4.2c-.9 0-1.7-.8-1.7-1.7z" fill="#f8c94b"/><path d="M2.5 8.6h19v1.1h-19z" fill="#fff" fill-opacity=".35"/></svg>`;
}

function fileSvg(e, size = 20) {
  const c = COLOR[groupOf(e)];
  return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true"><path d="M6 2.5h8.2l4.8 4.8v13a1.2 1.2 0 0 1-1.2 1.2H6a1.2 1.2 0 0 1-1.2-1.2V3.7A1.2 1.2 0 0 1 6 2.5z" fill="#fff" stroke="#b8c2cc" stroke-width="1"/>
    <path d="M14.2 2.5v3.6c0 .7.5 1.2 1.2 1.2H19" fill="#eef1f4" stroke="#b8c2cc" stroke-width="1"/><rect x="7" y="13.2" width="10" height="5.4" rx="1" fill="${c}"/></svg>`;
}

function driveSvg(e, size = 22) {
  if (e.removable) {
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true"><rect x="6.5" y="8" width="11" height="14" rx="2.2" fill="#2f6fd1"/>
      <rect x="8.5" y="2" width="7" height="6.5" rx=".8" fill="#c9d3dd" stroke="#8b98a5" stroke-width=".8"/><rect x="10" y="4" width="1.4" height="1.6" fill="#6b7a88"/><rect x="12.6" y="4" width="1.4" height="1.6" fill="#6b7a88"/>
      <circle cx="12" cy="17.5" r="1.2" fill="#9cc2ff"/></svg>`;
  }
  return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true"><rect x="2.5" y="6" width="19" height="12" rx="2" fill="#6b7a88"/>
    <rect x="2.5" y="6" width="19" height="7.5" rx="2" fill="#8b98a5"/><circle cx="17.6" cy="15.8" r="1" fill="#3fcf7f"/><rect x="5" y="15.3" width="7" height="1" rx=".5" fill="#c9d3dd"/></svg>`;
}

const entryIcon = (e, size) => (e.drive ? driveSvg(e, size) : e.isDir ? folderSvg(size) : fileSvg(e, size));
const fmtDate = (ts) => {
  const d = ts ? new Date(ts) : null;
  return d && !isNaN(d) ? d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : '';
};
const norm = (p) => String(p || '').replace(/[\\/]+$/, '').toLowerCase();

/**
 * Mount the browser in el. Options:
 *   multi   (true)  more than one item may be selected
 *   pick    ('any') 'folder' or 'file' limits what can be ticked
 *   demo    (false) show only the sample files WipeX created
 *   start   ('')    folder to open first ('' = This PC, or the sample files in demo mode)
 *   selected (Map)  path → entry, kept across folders
 *   onChange(map)   called when the selection changes
 *   actions         extra toolbar HTML, e.g. a "Create sample files" button
 */
export function mountExplorer(el, opts = {}) {
  const o = { multi: true, pick: 'any', demo: false, start: '', selected: new Map(), onChange: () => {}, actions: '', ...opts };
  const st = { path: null, entries: [], parent: '', back: [], fwd: [], sort: 'name', dir: 1, q: '', editing: false,
    loading: true, error: '', drives: [], places: [], sandbox: null, focus: -1 };

  const selectable = (e) => !e.protected && !(o.pick === 'folder' && !e.isDir) && !(o.pick === 'file' && e.isDir);
  const insideSandbox = (p) => (st.sandbox?.roots || []).some(r => norm(p).startsWith(norm(r)));
  const isSandboxRoot = (p) => (st.sandbox?.roots || []).some(r => norm(p) === norm(r));

  async function loadRoots() {
    if (o.demo) {
      st.sandbox = await api('/api/files/sandbox').catch(() => ({ roots: [], sets: [] }));
      return;
    }
    const r = await api('/api/fs/list?path=').catch(() => ({ entries: [], places: [] }));
    st.drives = r.entries || [];
    st.places = r.places || [];
  }

  async function load(path, remember = true) {
    if (remember && st.path !== null && st.path !== path) { st.back.push(st.path); st.fwd = []; }
    st.loading = true; st.error = ''; st.q = ''; st.focus = -1;
    render();
    try {
      if (o.demo && (!path || !insideSandbox(path) || isSandboxRoot(path))) {
        st.sandbox = await api('/api/files/sandbox');
        st.path = ''; st.parent = ''; st.entries = st.sandbox.sets.map(s => ({ ...s, name: `Sample set ${s.name}` }));
      } else if (!path && !o.demo) {
        await loadRoots();
        st.path = ''; st.parent = ''; st.entries = [];
      } else {
        const d = await api(`/api/fs/list?path=${encodeURIComponent(path)}`);
        st.path = d.path; st.entries = d.entries;
        st.parent = o.demo && isSandboxRoot(d.parent) ? '' : (d.parent || '');
      }
    } catch (e) {
      if (e.status === 404 && path) {            // the open folder was just erased: show where it was, like Explorer
        const up = st.parent && st.parent !== path ? st.parent : '';
        return load(up, false);
      }
      st.error = e.message; st.path = path; st.entries = [];
    }
    st.loading = false;
    render();
  }

  function toggle(e, force) {
    if (!selectable(e)) return;
    const on = force ?? !o.selected.has(e.path);
    if (!o.multi) o.selected.clear();
    if (on) o.selected.set(e.path, e); else o.selected.delete(e.path);
    o.onChange(o.selected);
    render();
  }

  function sorted() {
    const q = st.q.trim().toLowerCase();
    const list = st.entries.filter(e => !q || e.name.toLowerCase().includes(q));
    const key = { name: e => e.name.toLowerCase(), date: e => e.modified || '', size: e => e.size || 0, type: e => fileType(e) }[st.sort];
    return list.sort((a, b) => (b.isDir - a.isDir) || (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * st.dir);
  }

  function crumbs() {
    const rootLabel = o.demo ? 'Sample files' : 'This PC';
    const parts = [`<button class="xp-crumb" data-go="">${o.demo ? icon('play', 14) : icon('drive', 14)} ${rootLabel}</button>`];
    if (st.path) {
      const win = /^[A-Za-z]:/.test(st.path);
      let acc = '';
      st.path.split(/[\\/]/).filter(Boolean).forEach((s, i) => {
        acc = win ? (i === 0 ? `${s}\\` : `${acc.replace(/\\$/, '')}\\${s}`) : `${acc}/${s}`;
        if (o.demo && (!insideSandbox(acc) || isSandboxRoot(acc))) return;
        const drive = i === 0 && win ? st.drives.find(d => norm(d.path) === norm(acc)) : null;
        const label = drive ? `${drive.label} (${drive.drive})` : o.demo && isSandboxRoot(acc.replace(/[\\/][^\\/]+$/, '')) ? `Sample set ${s}` : s;
        parts.push(`<span class="xp-sep">›</span><button class="xp-crumb" data-go="${esc(acc)}">${esc(label)}</button>`);
      });
    }
    return parts.join('');
  }

  function side() {
    const item = (p, label, ic, on) => `<button class="xp-nav ${on ? 'on' : ''}" data-go="${esc(p)}" title="${esc(p || label)}">${ic}<span>${esc(label)}</span></button>`;
    if (o.demo) {
      return `<div class="xp-side-h">Demo mode</div>${item('', 'Sample files', folderSvg(18), !st.path)}
        ${(st.sandbox?.sets || []).slice(0, 8).map(s => item(s.path, `Sample set ${s.name}`, folderSvg(18), norm(st.path).startsWith(norm(s.path)))).join('')}`;
    }
    return `${st.places.length ? `<div class="xp-side-h">Quick access</div>${st.places.map(p => item(p.path, p.name, folderSvg(18), norm(st.path).startsWith(norm(p.path)))).join('')}` : ''}
      <div class="xp-side-h">${navigator.platform.startsWith('Mac') ? 'Locations' : 'This PC'}</div>${item('', navigator.platform.startsWith('Mac') ? 'Computer' : 'This PC', icon('drive', 17), !st.path)}
      ${st.drives.map(d => item(d.path, `${d.label || d.name} (${d.drive || d.path})`, driveSvg(d, 18), st.path && norm(st.path).startsWith(norm(d.path)))).join('')}`;
  }

  function tile(e, i) {
    const pct = e.size ? Math.round((1 - e.free / e.size) * 100) : 0;
    const can = selectable(e);
    return `<div class="xp-tile ${o.selected.has(e.path) ? 'sel' : ''}" data-i="${i}" tabindex="0" title="${esc(e.protected ? 'Open the drive to choose files; only a USB drive can be erased as a whole' : 'USB drive: tick to erase everything on it')}">
      ${can ? `<input type="checkbox" class="xp-tcb" ${o.selected.has(e.path) ? 'checked' : ''} aria-label="Select ${esc(e.label)}">` : ''}
      <span class="xp-tile-ic">${driveSvg(e, 36)}</span>
      <span class="xp-tile-main"><b>${esc(e.label)} (${esc(e.drive || e.path)})</b>
        ${e.size ? `<span class="xp-usage ${pct > 90 ? 'full' : ''}"><span style="width:${pct}%"></span></span><span class="xp-tile-sub">${bytes(e.free)} free of ${bytes(e.size)} · ${esc(e.fileSystem || '')}</span>` : `<span class="xp-tile-sub">${esc(e.fileSystem || '')}</span>`}
        ${e.removable ? '<span class="badge blue">USB</span>' : ''}</span></div>`;
  }

  function pcView() {
    const drives = [...st.drives].sort((a, b) => (b.removable ? 1 : 0) - (a.removable ? 1 : 0));
    st.view = drives;
    return `<div class="xp-pc">
      ${st.places.length ? `<div class="xp-sec">Folders</div><div class="xp-places">${st.places.map(p => `<button class="xp-place" data-go="${esc(p.path)}">${folderSvg(34)}<span>${esc(p.name)}</span></button>`).join('')}</div>` : ''}
      <div class="xp-sec">Devices and drives</div>
      ${drives.length ? `<div class="xp-tiles">${drives.map(tile).join('')}</div>` : '<div class="empty">No drives found.</div>'}
      <div class="muted small xp-note">${icon('info', 13)} Tick a USB drive to erase everything on it, or open any drive to choose files and folders.</div>
    </div>`;
  }

  function listView() {
    const rows = sorted();
    st.view = rows;
    const selHere = rows.filter(selectable);
    const allOn = selHere.length && selHere.every(e => o.selected.has(e.path));
    const th = (k, label, cls = '') => `<th class="${cls} sortable ${st.sort === k ? 'on' : ''}" data-sort="${k}">${label}${st.sort === k ? `<span class="xp-arrow">${st.dir > 0 ? '▲' : '▼'}</span>` : ''}</th>`;
    if (!rows.length) {
      return `<div class="empty">${st.q ? 'No item matches your search.' : o.demo && !st.path ? '<strong>No sample files yet</strong>Create a set of sample files to practise on.' : 'This folder is empty.'}</div>`;
    }
    return `<table class="xp-list"><thead><tr>
        <th class="xp-cb">${o.multi && selHere.length ? `<input type="checkbox" id="xp-all" ${allOn ? 'checked' : ''} aria-label="Select all in this folder">` : ''}</th>
        ${th('name', 'Name')}${th('date', 'Date modified', 'xp-c-date')}${th('type', 'Type', 'xp-c-type')}${th('size', 'Size', 'num xp-c-size')}<th class="xp-c-go"></th></tr></thead>
      <tbody>${rows.map((e, i) => {
        const can = selectable(e);
        const on = o.selected.has(e.path);
        return `<tr class="xp-row ${on ? 'sel' : ''} ${can ? '' : 'locked'} ${e.hidden ? 'dim' : ''} ${st.focus === i ? 'focus' : ''}" data-i="${i}" tabindex="0">
          <td class="xp-cb">${can ? `<input type="checkbox" ${on ? 'checked' : ''} aria-label="Select ${esc(e.name)}">` : `<span class="xp-lock" title="Protected location: cannot be erased">${icon('lock', 13)}</span>`}</td>
          <td class="xp-name"><span class="xp-ic">${entryIcon(e, 20)}</span><span class="xp-label" title="${esc(e.path)}">${esc(e.name)}</span></td>
          <td class="xp-c-date">${esc(fmtDate(e.modified))}</td>
          <td class="xp-c-type">${esc(fileType(e))}</td>
          <td class="num xp-c-size">${e.isDir ? '' : bytes(e.size)}</td>
          <td class="xp-c-go">${e.isDir ? `<button class="xp-open" data-open="${i}" title="Open folder">${icon('arrow', 14)}</button>` : ''}</td></tr>`;
      }).join('')}</tbody></table>`;
  }

  function status() {
    const n = o.selected.size;
    const files = [...o.selected.values()].filter(e => !e.isDir);
    const size = files.reduce((s, e) => s + (e.size || 0), 0);
    const count = st.path || o.demo ? `${st.entries.length} item${st.entries.length === 1 ? '' : 's'}` : `${st.drives.length} drive${st.drives.length === 1 ? '' : 's'}`;
    return `<span>${count}</span>${n ? `<span class="xp-sel-count">${n} selected${files.length && size ? ` · ${bytes(size)} in files` : ''}</span>` : ''}`;
  }

  function render() {
    el.innerHTML = `<div class="xp">
      <div class="xp-bar">
        <div class="xp-btns">
          <button class="xp-b" id="xp-back" title="Back" ${st.back.length ? '' : 'disabled'}>${icon('back', 16)}</button>
          <button class="xp-b" id="xp-fwd" title="Forward" ${st.fwd.length ? '' : 'disabled'}>${icon('arrow', 16)}</button>
          <button class="xp-b" id="xp-up" title="Up one level" ${st.path ? '' : 'disabled'}>${icon('up', 16)}</button>
          <button class="xp-b" id="xp-refresh" title="Refresh">${icon('refresh', 15)}</button>
        </div>
        <div class="xp-address" id="xp-address" title="Click to type a path">${st.editing
          ? `<input class="xp-addr-input mono" id="xp-addr" value="${esc(st.path)}" placeholder="Type a path and press Enter" spellcheck="false">`
          : `<div class="xp-crumbs">${crumbs()}</div>`}</div>
        <label class="xp-search">${icon('search', 14)}<input id="xp-q" placeholder="Search" value="${esc(st.q)}" ${st.path || o.demo ? '' : 'disabled'}></label>
        ${o.actions}
      </div>
      <div class="xp-main">
        <nav class="xp-side">${side()}</nav>
        <div class="xp-pane">${st.loading ? '<div class="empty"><span class="spinner"></span></div>' : st.error
          ? `<div class="empty"><strong>Cannot open this folder</strong>${esc(st.error)}</div>` : (!st.path && !o.demo ? pcView() : listView())}</div>
      </div>
      <div class="xp-status">${status()}</div>
    </div>`;
    bind();
  }

  function bind() {
    const q = (s) => el.querySelector(s);
    q('#xp-back').onclick = () => { st.fwd.push(st.path); load(st.back.pop(), false); };
    q('#xp-fwd').onclick = () => { st.back.push(st.path); load(st.fwd.pop(), false); };
    q('#xp-up').onclick = () => load(st.parent || '');
    q('#xp-refresh').onclick = () => load(st.path || '', false);
    q('#xp-address').onclick = (ev) => {
      if (st.editing || ev.target.closest('[data-go]') || o.demo) return;
      st.editing = true; render(); q('#xp-addr')?.focus(); q('#xp-addr')?.select();
    };
    const addr = q('#xp-addr');
    if (addr) {
      addr.onkeydown = (ev) => {
        if (ev.key === 'Enter') { st.editing = false; load(addr.value.trim()); }
        if (ev.key === 'Escape') { st.editing = false; render(); }
      };
      addr.onblur = () => { if (st.editing) { st.editing = false; render(); } };
    }
    const search = q('#xp-q');
    if (search) {
      search.oninput = () => {
        st.q = search.value;
        const pane = el.querySelector('.xp-pane');
        pane.innerHTML = listView();
        bindList();
      };
    }
    el.querySelectorAll('[data-go]').forEach(b => b.addEventListener('click', (ev) => { ev.stopPropagation(); load(b.dataset.go); }));
    bindList();
  }

  function bindList() {
    const view = st.view || [];
    el.querySelectorAll('[data-sort]').forEach(h => h.addEventListener('click', () => {
      st.dir = st.sort === h.dataset.sort ? -st.dir : 1; st.sort = h.dataset.sort; render();
    }));
    el.querySelector('#xp-all')?.addEventListener('change', (ev) => {
      view.filter(selectable).forEach(e => (ev.target.checked ? o.selected.set(e.path, e) : o.selected.delete(e.path)));
      o.onChange(o.selected); render();
    });
    el.querySelectorAll('.xp-row, .xp-tile').forEach(row => {
      const e = view[+row.dataset.i];
      const cb = row.querySelector('input[type=checkbox]');
      cb?.addEventListener('click', (ev) => { ev.stopPropagation(); toggle(e, cb.checked); });
      let pending = null;                // a click on a folder waits briefly: a double-click opens it instead
      row.addEventListener('click', (ev) => {
        if (ev.target.closest('[data-open]') || ev.detail > 1) return;
        if (row.classList.contains('xp-tile')) { if (e.protected || ev.target.closest('.xp-tile-main, .xp-tile-ic')) { load(e.path); return; } }
        if (!selectable(e)) { if (e.isDir) load(e.path); return; }
        if (!e.isDir) { toggle(e); return; }
        clearTimeout(pending);
        pending = setTimeout(() => toggle(e), 240);
      });
      row.addEventListener('dblclick', () => { clearTimeout(pending); if (e.isDir) load(e.path); });
      row.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' && e.isDir) load(e.path);
        if (ev.key === ' ') { ev.preventDefault(); toggle(e); }
        if (ev.key === 'Backspace' && st.path) load(st.parent || '');
      });
    });
    el.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click', (ev) => { ev.stopPropagation(); load(view[+b.dataset.open].path); }));
  }

  (async () => {
    await loadRoots();
    await load(o.start || '', false);
  })();

  return {
    go: (p) => load(p),
    refresh: () => load(st.path || '', false),
    get path() { return st.path; },
    render,
  };
}
