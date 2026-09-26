/** Audit log: hash-chained, signed entries with on-demand chain verification and export. */
import { api, apiUrl, esc, icon, reportError, short, when } from '../core.js';
import { actionLabel } from './overview.js';

const S = { entries: [], total: 0, chain: null, filter: '', open: new Set(), limit: 200 };
let root;

export async function show(el) {
  root = el;
  await load();
}

async function load() {
  try {
    const [log, chain] = await Promise.all([api(`/api/audit/log?limit=${S.limit}`), api('/api/audit/verify')]);
    S.entries = log.entries;
    S.total = log.total;
    S.chain = chain;
  } catch (e) { reportError(e); }
  render();
}

function render() {
  const c = S.chain;
  const q = S.filter.toLowerCase();
  const rows = S.entries.filter(e => !q || [e.action, actionLabel(e.action), e.actor, e.target, e.case_id, JSON.stringify(e.details)].join(' ').toLowerCase().includes(q));
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Audit Log</h1>
        <p class="page-desc">Every action is appended to a hash chain and signed with the workstation key. Editing, deleting or reordering any entry breaks the chain from that point.</p>
      </div>
      <div class="row">
        <button class="btn btn-secondary" id="au-verify">${icon('shield', 16)} Verify chain</button>
        <a class="btn btn-secondary" href="${apiUrl('/api/audit/export')}">${icon('download', 16)} Export JSON</a>
      </div>
    </div>
    ${c ? `<div class="verdict ${c.valid ? '' : 'bad'}" style="margin-bottom:16px">
      <span class="verdict-icon">${icon(c.valid ? 'check' : 'x', 22, 2.6)}</span>
      <div><div class="verdict-title">${c.valid ? `Chain intact — ${c.entries} entries verified` : `Chain broken at entry #${c.brokenAt}`}</div>
      <div class="verdict-text">${esc(c.reason)}${c.valid && c.headHash ? ` · head <span class="mono">${short(c.headHash, 20)}</span>` : ''}</div></div></div>` : ''}
    <div class="card">
      <div class="card-head"><span class="card-title">Entries <span class="muted" style="font-weight:400">(${S.total})</span></span>
        <input class="input" id="au-filter" placeholder="Filter by action, actor, target…" value="${esc(S.filter)}" style="max-width:320px"></div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th class="num">#</th><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Hash</th></tr></thead>
        <tbody>${rows.map(e => `
          <tr class="clickable" data-seq="${e.seq}">
            <td class="num mono">${e.seq}</td><td class="nowrap small">${esc(when(e.ts))}</td>
            <td><b>${esc(actionLabel(e.action))}</b>${e.case_id ? `<div class="muted small">${esc(e.case_id)}</div>` : ''}</td>
            <td class="nowrap">${esc(e.actor)}</td><td class="trunc mono small" title="${esc(e.target || '')}">${esc(e.target || '—')}</td>
            <td class="mono">${short(e.hash, 10)}</td></tr>
          ${S.open.has(e.seq) ? `<tr><td></td><td colspan="5"><div class="stack" style="gap:6px">
            <pre class="mono small" style="margin:0;white-space:pre-wrap;background:var(--surface-2);border:1px solid var(--border);border-radius:6px;padding:10px">${esc(JSON.stringify(e.details, null, 2))}</pre>
            <div class="digest">hash ${esc(e.hash)}<br>prev ${esc(e.prev_hash)}<br>sig  ${esc(e.signature.slice(0, 96))}…</div></div></td></tr>` : ''}`).join('')}
        </tbody></table></div>
      ${!rows.length ? '<div class="empty">No entries match.</div>' : ''}
      ${S.total > S.entries.length ? `<div class="card-foot"><button class="btn btn-secondary btn-sm" id="au-more">Load more</button></div>` : ''}
    </div>`;
  root.querySelector('#au-verify').addEventListener('click', load);
  const f = root.querySelector('#au-filter');
  f.addEventListener('input', e => { S.filter = e.target.value; render(); const n = root.querySelector('#au-filter'); n.focus(); n.setSelectionRange(n.value.length, n.value.length); });
  root.querySelectorAll('[data-seq]').forEach(r => r.addEventListener('click', () => {
    const s = +r.dataset.seq;
    S.open.has(s) ? S.open.delete(s) : S.open.add(s);
    render();
  }));
  root.querySelector('#au-more')?.addEventListener('click', () => { S.limit += 200; load(); });
}
