/** Verify a sanitization certificate: signature check plus comparison with the ledger record. */
import { ApiError, api, apiUrl, demo, esc, icon, refreshDemo, reportError, when } from '../core.js';
import { certificateHtml } from './drive.js';

let root;
let lastQuery = '';

export async function show(el, params) {
  root = el;
  if (params.q) lastQuery = params.q;
  // Demo mode lists only certificates of sample disks
  const recent = await api('/api/certificates').then(r => r.certificates
    .filter(c => !demo.enabled || c.storageType === 'Disk image' || /^Lab disk image/.test(c.deviceModel || '')).slice(0, 5)).catch(() => []);
  root.innerHTML = `
    <div class="page-head">
      <div>
        <h1 class="page-title">Verify certificate</h1>
        <p class="page-desc">Check that a certificate was issued here and not altered since. The QR code on a certificate opens this page.</p>
      </div>
    </div>
    <div class="grid cols-side">
      <div class="stack">
        <div class="card card-pad">
          <form class="row" id="vf-form" style="flex-wrap:nowrap">
            <input class="input mono" id="vf-q" value="${esc(lastQuery)}" placeholder="Certificate ID or device serial number" style="flex:1">
            <button class="btn btn-primary">${icon('search', 16)} Verify</button>
          </form>
        </div>
        <div id="vf-result"></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="card-title">Recently issued</span></div>
        ${recent.length ? `<div class="table-wrap"><table class="table"><tbody>${recent.map(c => `
          <tr class="clickable" data-id="${esc(c.certificateId)}"><td><div class="mono small">${esc(c.certificateId)}</div><div class="muted small">${esc(c.deviceModel)} · ${esc(when(c.issueDate))}</div></td></tr>`).join('')}
        </tbody></table></div>` : '<div class="empty">No certificates issued yet.</div>'}
      </div>
    </div>`;
  root.querySelector('#vf-form').addEventListener('submit', e => { e.preventDefault(); lastQuery = root.querySelector('#vf-q').value.trim(); lookup(); });
  root.querySelectorAll('[data-id]').forEach(r => r.addEventListener('click', () => { lastQuery = r.dataset.id; root.querySelector('#vf-q').value = lastQuery; lookup(); }));
  if (lastQuery) lookup();
}

async function lookup() {
  const out = root.querySelector('#vf-result');
  if (!lastQuery) { out.innerHTML = ''; return; }
  out.innerHTML = '<div class="card"><div class="empty">Checking signature…</div></div>';
  try {
    const c = await api(`/api/verify/${encodeURIComponent(lastQuery)}`);
    refreshDemo();
    out.innerHTML = `
      <div class="verdict ${c.isValid ? '' : 'bad'}" style="margin-bottom:16px">
        <span class="verdict-icon">${icon(c.isValid ? 'check' : 'x', 22, 2.6)}</span>
        <div><div class="verdict-title">${c.isValid ? 'Authentic certificate' : 'Certificate is NOT valid'}</div>
        <div class="verdict-text">${esc(c.verdict)}</div></div>
        <span class="spacer"></span>
        <a class="btn btn-secondary btn-sm" href="${apiUrl(`/api/certificates/${encodeURIComponent(c.certificateId)}/pdf`)}" target="_blank" rel="noopener">${icon('download', 14)} PDF</a>
      </div>
      ${certificateHtml(c)}`;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      out.innerHTML = `<div class="verdict bad"><span class="verdict-icon">${icon('x', 22, 2.6)}</span>
        <div><div class="verdict-title">No such certificate</div><div class="verdict-text">No certificate has the exact ID or serial number “${esc(lastQuery)}”. Partial IDs are not accepted.</div></div></div>`;
    } else { out.innerHTML = ''; reportError(e); }
  }
}
