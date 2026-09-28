/** Erase: one page for both erasure modules, switched with a toggle: a whole drive (M1) or selected files and folders (M2). */
import { can, icon } from '../core.js';
import * as drive from './drive.js';
import * as files from './files.js';

const MODES = [
  { id: 'drive', perm: 'erasure.run', icon: 'drive', label: 'Whole drive', sub: 'USB drive or disk · NIST SP 800-88 · signed certificate', view: drive },
  { id: 'files', perm: 'files.erase', icon: 'folder', label: 'Selected files & folders', sub: 'Pick them in a file browser · names and traces removed', view: files },
];
let mode = 'drive';

export async function show(el, params, app) {
  const modes = MODES.filter(m => can(m.perm));
  if (params.mode && modes.some(m => m.id === params.mode)) mode = params.mode;
  if (!modes.some(m => m.id === mode)) mode = modes[0]?.id;
  el.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Erase</h1>
        <p class="page-desc">Wipe a whole drive, or only the files and folders you choose. WipeX then tries to recover them: the job passes only if nothing comes back.</p>
      </div>
    </div>
    <div class="mode-switch" role="tablist" aria-label="What to erase">${modes.map(m => `
      <button role="tab" class="mode-opt ${m.id === mode ? 'on' : ''}" data-mode="${m.id}" aria-selected="${m.id === mode}">
        <span class="mode-ic">${icon(m.icon, 20)}</span>
        <span class="mode-text"><b>${m.label}</b><span>${m.sub}</span></span>
        <span class="mode-radio"></span>
      </button>`).join('')}</div>
    <div id="erase-body"></div>`;
  el.querySelectorAll('[data-mode]').forEach(b => b.addEventListener('click', () => {
    if (b.dataset.mode === mode) return;
    mode = b.dataset.mode;
    history.replaceState(null, '', `#/erase?mode=${mode}`);
    show(el, { mode }, app);
  }));
  const m = modes.find(x => x.id === mode);
  if (m) await m.view.show(el.querySelector('#erase-body'), params, app);
}
