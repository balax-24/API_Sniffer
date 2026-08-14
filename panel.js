/* =====================================================================
 * API Sniffer Pro v2.1 — single-file hardened build
 * If anything breaks, a RED banner appears at the top of the panel.
 * Click the banner to copy the error text.
 * ===================================================================== */

/* ---------- 1. on-screen diagnostics ---------- */
(function () {
  const banner = document.createElement('div');
  banner.id = 'errBanner';
  banner.style.cssText = 'display:none;position:sticky;top:0;z-index:99;background:#5c1a1a;color:#ffb4a8;padding:6px 10px;font:11px monospace;border-bottom:1px solid #f48771;white-space:pre-wrap;word-break:break-all;cursor:pointer';
  banner.title = 'Click to copy this error';
  document.body.prepend(banner);
  window.__showErr = function (msg, src, line) {
    const text = '⚠ ' + msg + (src ? '\n  at ' + src + (line ? ':' + line : '') : '');
    banner.textContent = text;
    banner.style.display = 'block';
    console.error(text);
  };
  window.addEventListener('error', e => window.__showErr(e.message, e.filename, e.lineno));
  window.addEventListener('unhandledrejection', e => window.__showErr(String(e.reason && e.reason.message || e.reason)));
})();

/* ---------- 2. state & settings ---------- */
'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const parseHost = u => { try { return new URL(u).host; } catch { return u; } };
const parsePath = u => { try { const x = new URL(u); return x.pathname + x.search; } catch { return u; } };
const nowIso = () => new Date().toISOString().replace(/[:.]/g, '-');
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));

const state = {
  entries: [], recording: true, seq: 0,
  sortKey: 'seq', sortDir: -1, page: 1, pageSize: 250,
  selected: new Set(), favs: new Set(), dedupeView: false,
  bodyCache: new Map(),
};

const SETTINGS_KEY = 'apiprox.settings.v2';
const SNAPSHOT_KEY = 'apiprox.snapshot.v2';
const FAVS_KEY = 'apiprox.favs.v2';
const DEFAULT_SETTINGS = {
  autoStart: true, maxEntries: 10000, dedupe: false, autoScroll: true,
  hostWhitelist: '', hostBlacklist: '',
  skipHeaders: 'accept-encoding,content-length,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,sec-fetch-user,priority',
  optHeaders: 'authorization,cookie,content-type,accept,accept-language,x-api-key,x-auth-token,x-csrf-token,referer,origin,user-agent,x-requested-with',
  insecure: false, singleLine: false, bodyCache: false, bodyCacheMax: 50000,
};
let settings = loadSettings();
function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    return raw ? { ...DEFAULT_SETTINGS, ...JSON.parse(raw) } : { ...DEFAULT_SETTINGS };
  } catch { return { ...DEFAULT_SETTINGS }; }
}
function saveSettings() { try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); } catch {} }
function syncSettingsToForm() {
  $('setAutoStart').checked = settings.autoStart;
  $('setMaxEntries').value = settings.maxEntries;
  $('setDedupe').checked = settings.dedupe;
  $('setAutoScroll').checked = settings.autoScroll;
  $('setHostWhitelist').value = settings.hostWhitelist;
  $('setHostBlacklist').value = settings.hostBlacklist;
  $('setSkipHeaders').value = settings.skipHeaders;
  $('setOptHeaders').value = settings.optHeaders;
  $('setInsecure').checked = settings.insecure;
  $('setSingleLine').checked = settings.singleLine;
  $('setBodyCache').checked = settings.bodyCache;
  $('setBodyCacheMax').value = settings.bodyCacheMax;
  $('optInsecure').checked = settings.insecure;
  $('optSingleLine').checked = settings.singleLine;
}

/* ---------- 3. helpers ---------- */
function fmtSize(b) {
  if (!b) return '-';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}
function fmtTime(ms) {
  if (ms == null || isNaN(ms)) return '-';
  if (ms < 1) return '<1 ms';
  if (ms < 1000) return ms.toFixed(0) + ' ms';
  return (ms / 1000).toFixed(2) + ' s';
}
function flash(msg, isErr = false) {
  const f = $('flash');
  if (!f) return;
  f.textContent = msg;
  f.className = isErr ? 'err' : '';
  clearTimeout(f._t);
  f._t = setTimeout(() => { f.textContent = ''; }, 1500);
}
function flashRow(tr) {
  tr.classList.remove('hit-flash');
  void tr.offsetWidth;
  tr.classList.add('hit-flash');
}
function downloadText(text, filename, mime = 'text/plain') {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
function copyText(text) {
  navigator.clipboard.writeText(text).then(
    () => flash('Copied!'),
    () => {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      flash('Copied!');
    }
  );
}

/* ---------- 4. capture pipeline ---------- */
function inferType(entry) {
  try {
    const ct = (entry.response.content.mimeType || '').toLowerCase();
    if (ct.includes('json')) return 'json';
    if (ct.includes('html')) return 'html';
    if (ct.includes('xml')) return 'xml';
    if (ct.includes('javascript')) return 'javascript';
    if (ct.includes('css')) return 'css';
    if (ct.includes('image')) return 'image';
    return 'other';
  } catch { return 'other'; }
}
function hostPasses(url) {
  const host = parseHost(url);
  if (settings.hostWhitelist) {
    try { if (!new RegExp(settings.hostWhitelist, 'i').test(host)) return false; } catch {}
  }
  if (settings.hostBlacklist) {
    try { if (new RegExp(settings.hostBlacklist, 'i').test(host)) return false; } catch {}
  }
  return true;
}
function dedupeKey(entry) {
  const body = entry.request.postData ? entry.request.postData.text || '' : '';
  return `${entry.request.method}\n${entry.request.url}\n${body}`;
}
function maybeCacheBody(rec) {
  rec.entry.getContent((content, encoding) => {
    if (content == null) return;
    const max = settings.bodyCacheMax;
    state.bodyCache.set(rec.seq, {
      text: encoding === 'base64' ? `[base64] ${content.slice(0, max)}` : content.slice(0, max),
      mime: rec.entry.response.content.mimeType || '',
      base64: encoding === 'base64',
    });
  });
}

chrome.devtools.network.onRequestFinished.addListener(entry => {
  try {
    if (!state.recording) return;
    const url = entry.request.url;
    if (!hostPasses(url)) return;

    if (settings.dedupe) {
      const k = dedupeKey(entry);
      const prev = state.entries.find(e => e._dk === k);
      if (prev) {
        prev.count = (prev.count || 1) + 1;
        prev.entry = entry; prev.status = entry.response.status;
        prev.size = entry.response.content.size || 0;
        prev.time = entry.time; prev.url = url;
        render(); return;
      }
    }

    const rec = {
      seq: ++state.seq, entry, url, method: entry.request.method,
      status: entry.response.status, type: inferType(entry),
      size: entry.response.content.size || 0, time: entry.time || 0,
      _dk: settings.dedupe ? dedupeKey(entry) : null,
      count: 1, ts: Date.now(),
    };
    state.entries.push(rec);
    if (state.entries.length > settings.maxEntries) {
      const drop = state.entries.splice(0, state.entries.length - settings.maxEntries);
      drop.forEach(r => { state.selected.delete(r.seq); state.bodyCache.delete(r.seq); });
    }
    if (settings.bodyCache && settings.bodyCacheMax > 0) maybeCacheBody(rec);
    render();
  } catch (err) { window.__showErr(String(err && err.stack || err)); }
});

/* ---------- 5. filtering ---------- */
function matchesFilters(rec) {
  const q = $('filter').value.trim();
  if (q) {
    let ok = false;
    try { ok = new RegExp(q, 'i').test(rec.url); } catch { ok = rec.url.toLowerCase().includes(q.toLowerCase()); }
    if (!ok) return false;
  }
  const m = $('methodFilter').value;
  if (m && rec.method !== m) return false;
  const s = $('statusFilter').value;
  if (s && String(rec.status).charAt(0) !== s) return false;
  const t = $('typeFilter').value;
  if (t && rec.type !== t) return false;
  if ($('favOnly').checked && !state.favs.has(rec.method + ' ' + rec.url)) return false;
  return true;
}
function favKey(rec) { return rec.method + ' ' + rec.url; }
function getFiltered() {
  let list = state.entries.filter(matchesFilters);
  if (state.dedupeView) {
    const seen = new Set();
    list = list.filter(r => {
      const k = r.method + ' ' + r.url;
      if (seen.has(k)) return false; seen.add(k); return true;
    });
  }
  return list;
}

/* ---------- 6. table rendering ---------- */
function buildRow(rec) {
  const tr = document.createElement('tr');
  const sel = state.selected.has(rec.seq);
  const col = rec.status >= 500 ? 'var(--bad)' : rec.status >= 400 ? 'var(--warn)' : rec.status >= 300 ? 'var(--warn)' : 'var(--good)';
  const fav = state.favs.has(favKey(rec));
  const extra = rec.count > 1 ? ` <span class="badge">×${rec.count}</span>` : '';
  tr.innerHTML = `
    <td class="cell-check"><input type="checkbox" data-seq="${rec.seq}" ${sel ? 'checked' : ''}></td>
    <td class="cell-seq">${rec.seq}</td>
    <td class="cell-method"><span class="method m-${rec.method.toLowerCase()}">${esc(rec.method)}</span></td>
    <td class="cell-status" style="color:${col}">${rec.status}${extra}</td>
    <td class="cell-type">${rec.type}</td>
    <td class="cell-host" title="${esc(rec.url)}">${esc(parseHost(rec.url))}</td>
    <td class="cell-path" title="${esc(rec.url)}">${esc(parsePath(rec.url))}</td>
    <td class="cell-size">${fmtSize(rec.size)}</td>
    <td class="cell-time ${rec.time > 1000 ? 'bad' : ''}">${fmtTime(rec.time)}</td>
    <td class="cell-actions">
      <button class="mini" data-act="curl" data-seq="${rec.seq}">cURL</button>
      <button class="mini" data-act="opt" data-seq="${rec.seq}">⚡</button>
      <button class="star-btn ${fav ? 'on' : ''}" data-act="fav" data-seq="${rec.seq}">${fav ? '★' : '☆'}</button>
    </td>`;
  tr.onclick = e => { if (e.target.closest('button, input')) return; showDetail(rec); };
  tr.querySelector('input[type=checkbox]').onchange = e => {
    e.stopPropagation();
    if (e.target.checked) state.selected.add(rec.seq); else state.selected.delete(rec.seq);
    updateBulkBar();
  };
  tr.querySelector('[data-act="curl"]').onclick = e => { e.stopPropagation(); copyText(toCurl(rec.entry, { optimized: false })); };
  tr.querySelector('[data-act="opt"]').onclick = e => { e.stopPropagation(); copyText(toCurl(rec.entry, { optimized: true })); };
  tr.querySelector('[data-act="fav"]').onclick = e => { e.stopPropagation(); toggleFav(rec); };
  return tr;
}

function emptyRow(msg, hint) {
  const tr = document.createElement('tr');
  tr.innerHTML = `<td colspan="10" style="text-align:center;padding:24px;color:var(--dim)">
    ${esc(msg)}<br><span style="font-size:11px">${esc(hint || '')}</span></td>`;
  return tr;
}

function render() {
  const list = getFiltered();
  const totalPages = Math.max(1, Math.ceil(list.length / state.pageSize));
  state.page = clamp(state.page, 1, totalPages);
  const start = (state.page - 1) * state.pageSize;
  const slice = [...list].sort(sortFn()).slice(start, start + state.pageSize);
  const body = $('logBody');
  body.innerHTML = '';

  if (!state.entries.length) {
    body.appendChild(emptyRow(
      state.recording ? '● Recording — waiting for requests…' : '■ Recording paused.',
      'Open DevTools BEFORE loading the page. The panel only sees requests while DevTools is open. Start with ● Start, then reload the page or click around the app.'
    ));
  } else if (!list.length) {
    body.appendChild(emptyRow(
      `${state.entries.length} captured, but filters hide them all.`,
      'Filter text: "' + $('filter').value + '" · Method: ' + $('methodFilter').value + ' · Status: ' + $('statusFilter').value + ' · Type: ' + $('typeFilter').value + ' — clear filters or press Ctrl+F and empty the box.'
    ));
  } else {
    const frag = document.createDocumentFragment();
    slice.forEach(r => frag.appendChild(buildRow(r)));
    body.appendChild(frag);
  }

  updateStats();
  updatePager(totalPages);
  updateBulkBar();
  if (settings.autoScroll && state.page === totalPages) {
    const wrap = $('logWrap'); wrap.scrollTop = wrap.scrollHeight;
  }
}

function sortFn() {
  const k = state.sortKey, d = state.sortDir;
  return (a, b) => {
    let av = a[k], bv = b[k];
    if (k === 'host') { av = parseHost(a.url); bv = parseHost(b.url); }
    if (k === 'path') { av = parsePath(a.url); bv = parsePath(b.url); }
    if (typeof av === 'string') return av.localeCompare(bv) * d;
    return ((av || 0) - (bv || 0)) * d;
  };
}
function updatePager(totalPages) {
  $('pageInfo').textContent = `Page ${state.page} / ${totalPages}`;
  $('btnPrev').disabled = state.page <= 1;
  $('btnNext').disabled = state.page >= totalPages;
  const b = $('liveBadge');
  b.textContent = state.recording ? '● RECORDING' : '■ PAUSED';
  b.style.color = state.recording ? 'var(--good)' : 'var(--bad)';
}
function updateStats() {
  const all = state.entries.length;
  const shown = getFiltered().length;
  const totalSize = state.entries.reduce((s, r) => s + (r.size || 0), 0);
  const avgTime = all ? state.entries.reduce((s, r) => s + (r.time || 0), 0) / all : 0;
  const errs = state.entries.filter(r => r.status >= 400).length;
  $('stats').innerHTML =
    `<span>Captured <b>${all}</b></span>` +
    `<span>Shown <b>${shown}</b></span>` +
    `<span>Size <b>${fmtSize(totalSize)}</b></span>` +
    `<span>Avg <b>${fmtTime(avgTime)}</b></span>` +
    `<span>4xx/5xx <b style="color:${errs ? 'var(--bad)' : 'var(--dim)'}">${errs}</b></span>` +
    `<span>Status <b style="color:${state.recording ? 'var(--good)' : 'var(--bad)'}">${state.recording ? 'ON' : 'OFF'}</b></span>`;
}
function updateBulkBar() {
  const n = state.selected.size;
  $('bulkBar').classList.toggle('hidden', n === 0);
  $('selCount').textContent = `${n} selected`;
  $('selAll').checked = getFiltered().length > 0 && getFiltered().every(r => state.selected.has(r.seq));
}
function toggleFav(rec) {
  const k = favKey(rec);
  if (state.favs.has(k)) state.favs.delete(k); else state.favs.add(k);
  try { localStorage.setItem(FAVS_KEY, JSON.stringify([...state.favs])); } catch {}
  render();
}

/* ---------- 7. cURL engines ---------- */
function getSkipSet() { return new Set(settings.skipHeaders.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)); }
function getOptSet() { return new Set(settings.optHeaders.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)); }
function sq(s) { return String(s ?? '').replace(/'/g, `'\\''`); }
function dq(s) { return String(s ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t').replace(/\$\{/g, '\\${'); }

function toCurl(entry, opts = {}) {
  const r = entry.request;
  const skip = getSkipSet(), keep = getOptSet();
  const optimized = !!opts.optimized;
  const insecure = opts.insecure ?? settings.insecure;
  const singleLine = opts.singleLine ?? settings.singleLine;
  const join = singleLine ? ' ' : ' \\\n';
  const lines = [];
  lines.push(optimized ? `curl -X ${r.method}` : `curl --url '${sq(r.url)}'`);
  const seen = new Set();
  const addHeader = (name, value) => {
    const n = name.toLowerCase();
    if (optimized && keep.size && !keep.has(n)) return;
    if (skip.has(n) || seen.has(n)) return;
    seen.add(n);
    lines.push(`  -H '${sq(name)}: ${sq(value)}'`);
  };
  (r.headers || []).forEach(h => addHeader(h.name, h.value));
  if (optimized && !seen.has('cookie') && r.cookies && r.cookies.length) {
    lines.push(`  -H 'Cookie: ${sq(r.cookies.map(c => `${c.name}=${c.value}`).join('; '))}'`);
  }
  const pd = r.postData;
  if (pd && (pd.text || (pd.params && pd.params.length))) {
    if (pd.text) {
      let body = pd.text;
      if (/json/i.test(pd.mimeType || '')) {
        try { body = JSON.stringify(JSON.parse(pd.text), null, optimized ? 2 : 0); } catch {}
      }
      lines.push(`  --data-raw '${sq(body)}'`);
    } else if (pd.params && pd.params.length) {
      pd.params.forEach(p => lines.push(`  --data-urlencode '${sq(p.name)}=${sq(p.value || '')}'`));
    }
  }
  if (optimized) {
    lines.push(`  --compressed`);
    if (insecure) lines.push(`  --insecure`);
    lines.push(`  --max-time 60`);
  } else if (opts.compressed ?? true) {
    lines.push(`  --compressed`);
  }
  return lines.join(join);
}
/* ---------- 8. detail view ---------- */
function getContentText(entry) {
  return new Promise(resolve => {
    entry.getContent((content, encoding) => resolve({ content, encoding }));
  });
}
function prettyJson(text) { try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return null; } }
function kvTable(rows) {
  if (!rows || !rows.length) return '<p style="color:var(--dim)">(none)</p>';
  return `<table class="kv"><tbody>` + rows.map(h =>
    `<tr><td>${esc(h.name)}</td><td>${esc(h.value)}</td></tr>`).join('') + `</tbody></table>`;
}
function timingTable(entry) {
  const t = entry.timings || {};
  const names = [['blocked','Blocked'],['dns','DNS'],['connect','Connect'],['ssl','SSL'],['send','Send'],['wait','Wait (TTFB)'],['receive','Receive']];
  return `<table class="kv"><tbody>` + names.map(([k,label]) =>
    `<tr><td>${label}</td><td>${t[k] == null || t[k] < 0 ? '-' : t[k].toFixed(1) + ' ms'}</td></tr>`).join('') + `</tbody></table>`;
}

let currentDetail = null;
let detailTab = 'overview';

async function showDetail(rec) {
  if (!rec.entry) {
    $('dTitle').textContent = `${rec.method} ${rec.status} — ${rec.url}`;
    $('dMeta').innerHTML = `<span style="color:var(--warn)">metadata-only record — no body stored</span>`;
    $('dContent').innerHTML = '';
    switchTab('detail');
    return;
  }
  currentDetail = rec;
  const e = rec.entry;
  $('dTitle').textContent = `${e.request.method} ${rec.status} — ${rec.url}`;
  $('dMeta').innerHTML =
    `<span>Host: <b>${esc(parseHost(rec.url))}</b></span>` +
    `<span>Type: <b>${rec.type}</b></span>` +
    `<span>Size: <b>${fmtSize(rec.size)}</b></span>` +
    `<span>Time: <b>${fmtTime(rec.time)}</b></span>` +
    `<span>Seq: <b>#${rec.seq}</b></span>` +
    (rec.count > 1 ? `<span>Dupes: <b>${rec.count}</b></span>` : '');
  switchTab('detail');
  renderDetailTab();
}

async function renderDetailTab() {
  const d = $('dContent');
  if (!currentDetail) { d.innerHTML = ''; return; }
  const rec = currentDetail, e = rec.entry;

  if (detailTab === 'overview') {
    let qp = []; try { qp = [...new URL(rec.url).searchParams.entries()]; } catch {}
    d.innerHTML =
      `<h4>Request line</h4><pre class="code">${esc(e.request.method)} ${esc(rec.url)}</pre>` +
      (qp.length ? `<h4>Query parameters (${qp.length})</h4>` + kvTable(qp.map(([k,v])=>({name:k,value:v}))) : '') +
      `<h4>Timing breakdown</h4>` + timingTable(e) +
      `<h4>Response info</h4><table class="kv"><tbody>` +
      `<tr><td>Status</td><td>${rec.status}</td></tr>` +
      `<tr><td>MIME</td><td>${esc(e.response.content.mimeType || '')}</td></tr>` +
      `<tr><td>Size</td><td>${fmtSize(rec.size)}</td></tr>` +
      `<tr><td>Server IP</td><td>${esc(e.serverIPAddress || '')}</td></tr>` +
      `<tr><td>HTTP version</td><td>${esc(e.response.httpVersion || '')}</td></tr>` +
      `</tbody></table>` +
      `<h4>Actions</h4>
      <button class="mini" id="dReplay">Replay (fetch)</button>
      <button class="mini" id="dOpenTab">Open URL</button>
      <button class="mini" id="dCopyAll">Copy raw</button>`;
    $('dReplay').onclick = () => replay(rec);
    $('dOpenTab').onclick = () => { window.open(rec.url, '_blank'); };
    $('dCopyAll').onclick = async () => {
      const { content } = await getContentText(e);
      copyText(`>>> ${e.request.method} ${rec.url} [${rec.status}]\n\n` +
        e.request.headers.map(h => `${h.name}: ${h.value}`).join('\n') + '\n\n' +
        (e.request.postData?.text ? '-- body --\n' + e.request.postData.text + '\n\n' : '') +
        '<<< response\n\n' + (content || '(no body)'));
    };
  }
  else if (detailTab === 'request') {
    const pd = e.request.postData;
    d.innerHTML = `<h4>Request headers</h4>` + kvTable(e.request.headers) +
      `<h4>Request cookies</h4>` + kvTable(e.request.cookies || []);
    if (pd) {
      const pretty = prettyJson(pd.text || '');
      d.innerHTML += `<h4>Request body (${esc(pd.mimeType || 'unknown')})</h4>` +
        `<pre class="code">${esc(pretty || pd.text || '(no body)')}</pre>` +
        (pretty ? `<p style="color:var(--dim)">(pretty-printed)</p>` : '');
    } else d.innerHTML += `<p style="color:var(--dim)">No request body.</p>`;
  }
  else if (detailTab === 'response') {
    d.innerHTML = `<p style="color:var(--dim)">Loading body…</p>`;
    const { content, encoding } = await getContentText(e);
    if (currentDetail !== rec) return;
    const mime = e.response.content.mimeType || '';
    let html = `<h4>Response headers</h4>` + kvTable(e.response.headers) +
      `<h4>Response cookies</h4>` + kvTable(e.response.cookies || []);
    if (content == null) html += `<p style="color:var(--dim)">No response body available.</p>`;
    else if (encoding === 'base64') {
      if (/^image\//i.test(mime)) html += `<h4>Image preview</h4><img class="resp-img" src="data:${mime};base64,${content}" alt="response image">`;
      else html += `<h4>Binary body (base64, ${content.length} chars)</h4><pre class="code">${esc(content.slice(0,2000))}</pre>`;
    } else {
      const pretty = prettyJson(content);
      const display = pretty || content;
      const MAX = 20000;
      html += `<h4>Response body (${esc(mime)})</h4>`;
      // naive JWT detection
      const jm = content.match(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/);
      if (jm) html += `<p style="color:var(--warn)">⚠ Looks like a JWT token was returned in this body.</p>`;
      html += `<pre class="code">${esc(display.length > MAX ? display.slice(0,MAX) + `\n… [truncated ${display.length - MAX} chars]` : display)}</pre>`;
    }
    d.innerHTML = html;
  }
  else if (detailTab === 'curl') {
    const std = toCurl(e, { optimized: false });
    const opt = toCurl(e, { optimized: true });
    d.innerHTML = `<h4>Standard cURL</h4><pre class="code">${esc(std)}</pre>
      <button class="mini" id="dCopyStd">Copy standard</button>
      <h4>Optimized cURL</h4><pre class="code">${esc(opt)}</pre>
      <button class="mini" id="dCopyOpt">Copy optimized</button>
      <h4>fetch()</h4><pre class="code">${esc(toFetch(e))}</pre>
      <button class="mini" id="dCopyFetch">Copy fetch</button>`;
    $('dCopyStd').onclick = () => copyText(std);
    $('dCopyOpt').onclick = () => copyText(opt);
    $('dCopyFetch').onclick = () => copyText(toFetch(e));
  }
  else if (detailTab === 'raw') {
    d.innerHTML = `<p style="color:var(--dim)">Loading…</p>`;
    const { content } = await getContentText(e);
    if (currentDetail !== rec) return;
    const rawReq = `${e.request.method} ${(()=>{try{const u=new URL(rec.url);return u.pathname+u.search;}catch{return rec.url;}})()} HTTP/1.1\n` +
      e.request.headers.map(h => `${h.name}: ${h.value}`).join('\n') +
      (e.request.postData?.text ? `\n\n${e.request.postData.text}` : '');
    const rawResp = `HTTP/1.1 ${rec.status}\n` +
      e.response.headers.map(h => `${h.name}: ${h.value}`).join('\n') +
      (content != null ? `\n\n${content.slice(0,20000)}` : '\n\n(no body)');
    d.innerHTML = `<h4>Raw request</h4><pre class="code raw">${esc(rawReq)}</pre>
      <h4>Raw response</h4><pre class="code raw">${esc(rawResp)}</pre>
      <button class="mini" id="dCopyRaw">Copy raw</button>`;
    $('dCopyRaw').onclick = () => copyText(rawReq + '\n\n' + rawResp);
  }
}

document.querySelectorAll('#dTabs button').forEach(b => {
  b.onclick = () => {
    detailTab = b.dataset.dtab;
    document.querySelectorAll('#dTabs button').forEach(x => x.classList.toggle('active', x === b));
    renderDetailTab();
  };
});

/* ---------- 9. replay ---------- */
async function replay(rec) {
  const e = rec.entry;
  const headers = {}, skip = getSkipSet();
  (e.request.headers || []).forEach(h => {
    const n = h.name.toLowerCase();
    if (skip.has(n) || n === 'host' || n === 'content-length') return;
    if (!(n in headers)) headers[h.name] = h.value;
  });
  const body = e.request.postData?.text;
  flash('Replaying…', true);
  try {
    const resp = await fetch(rec.url, { method: e.request.method, headers, body: body || undefined, credentials: 'include' });
    const text = await resp.text();
    $('dContent').innerHTML =
      `<h4>Replay result (${resp.status} ${resp.statusText})</h4>` +
      `<p style="color:var(--dim)">Note: browser CORS may strip headers for cross-origin replays. Use cURL for a faithful replay.</p>` +
      `<pre class="code">${esc((prettyJson(text) || text).slice(0,20000))}</pre>`;
    flash(`Replay: ${resp.status}`);
  } catch (err) {
    $('dContent').innerHTML = `<h4>Replay failed</h4><pre class="code">${esc(String(err))}</pre><p style="color:var(--warn)">CORS or network error — use the cURL export.</p>`;
    flash('Replay failed', true);
  }
}

/* ---------- 10. HAR 1.2 ---------- */
async function buildHar(recs) {
  const includeBodies = $('harBodies').checked;
  const includeBinary = $('harBinary').checked;
  const entries = [];
  for (const rec of recs) {
    if (!rec.entry) continue;
    const copy = JSON.parse(JSON.stringify(rec.entry));
    if (includeBodies) {
      const { content, encoding } = await getContentText(rec.entry);
      if (content != null && (encoding !== 'base64' || includeBinary)) {
        copy.response.content.text = content;
        if (encoding === 'base64') copy.response.content.encoding = 'base64';
      }
    }
    entries.push(copy);
  }
  return { log: { version: '1.2', creator: { name: 'API Sniffer Pro', version: '2.1' }, pages: [], entries } };
}
async function downloadHar(recs, name) {
  const list = recs || state.entries;
  flash(`Building HAR (${list.length} entries)…`, true);
  const har = await buildHar(list);
  downloadText(JSON.stringify(har, null, $('harPretty').checked ? 2 : 0), name || `capture_${nowIso()}.har`, 'application/json');
  flash(`HAR saved (${list.length} entries)`);
}
$('btnHarDownload').onclick = () => downloadHar();
$('btnHarDownloadFiltered').onclick = () => downloadHar(getFiltered(), `filtered_${nowIso()}.har`);
$('btnHarCopy').onclick = async () => copyText(JSON.stringify(await buildHar(state.entries), null, 2));

/* ---------- 11. snapshots & reports ---------- */
$('btnSaveJson').onclick = () => {
  try {
    localStorage.setItem(SNAPSHOT_KEY, JSON.stringify(state.entries.map(r => ({
      seq: r.seq, method: r.method, url: r.url, status: r.status, type: r.type,
      size: r.size, time: r.time, count: r.count, ts: r.ts }))));
    flash(`Snapshot saved (${state.entries.length} records)`);
  } catch { flash('Snapshot too large for localStorage', true); }
};
$('btnRestore').onclick = () => {
  try {
    const meta = JSON.parse(localStorage.getItem(SNAPSHOT_KEY));
    if (!meta) { flash('No snapshot found', true); return; }
    state.entries = meta.map(m => ({ ...m, entry: null, _dk: null }));
    state.seq = meta.length ? Math.max(...meta.map(m => m.seq)) : 0;
    state.selected.clear(); state.bodyCache.clear(); state.page = 1;
    render(); flash(`Restored ${meta.length} records (metadata only)`);
  } catch { flash('Restore failed', true); }
};
function toCsv(recs) {
  const escCell = v => { const s = String(v ?? ''); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const head = ['seq','method','url','status','type','size','time_ms','host','path','count'];
  return [head.join(','), ...recs.map(r => [r.seq, r.method, r.url, r.status, r.type, r.size, r.time, parseHost(r.url), parsePath(r.url), r.count].map(escCell).join(','))].join('\n');
}
function toMarkdown(recs) {
  const L = [];
  L.push('# API Sniffer Pro — capture report');
  L.push('', `- Generated: ${new Date().toISOString()}`, `- Entries: ${recs.length}`, `- 4xx/5xx: ${recs.filter(r => r.status >= 400).length}`, '');
  L.push('| # | Method | Status | Host | Path | Size | Time |', '|---|--------|--------|------|------|------|------|');
  recs.slice(0, 500).forEach(r => L.push(`| ${r.seq} | ${r.method} | ${r.status} | ${parseHost(r.url)} | ${parsePath(r.url).replace(/\|/g,'\\|').slice(0,120)} | ${fmtSize(r.size)} | ${fmtTime(r.time)} |`));
  if (recs.length > 500) L.push(`| … | | | | ${recs.length - 500} more | | |`);
  return L.join('\n');
}
$('btnSaveCsv').onclick = () => downloadText(toCsv(state.entries), `capture_${nowIso()}.csv`, 'text/csv');
$('btnSaveMd').onclick = () => downloadText(toMarkdown(state.entries), `report_${nowIso()}.md`, 'text/markdown');
$('btnCopyMd').onclick = () => copyText(toMarkdown(getFiltered()));

/* ---------- 12. stats dashboard ---------- */
function barList(el, pairs, type) {
  if (!pairs.length) { el.innerHTML = '<p style="color:var(--dim)">No data yet.</p>'; return; }
  const max = pairs[0][1];
  el.innerHTML = pairs.map(([k, v]) => {
    const cls = type === 'status' ? (' ' + (+k >= 400 ? 'bad' : +k >= 300 ? 'warn' : 'good')) : '';
    return `<div class="bar-row"><span class="lbl" title="${esc(k)}">${esc(k)}</span>` +
      `<div class="track"><div class="fill${cls}" style="width:${(v/max*100).toFixed(1)}%"></div></div>` +
      `<span class="cnt">${v}</span></div>`;
  }).join('');
}
function renderStats() {
  const recs = state.entries;
  const errs = recs.filter(r => r.status >= 400).length;
  const totalBytes = recs.reduce((s, r) => s + (r.size || 0), 0);
  const avgTime = recs.length ? recs.reduce((s, r) => s + (r.time || 0), 0) / recs.length : 0;
  const maxTime = recs.length ? Math.max(...recs.map(r => r.time || 0)) : 0;
  $('statsGrid').innerHTML =
    `<div class="stat-card"><div class="k">Requests</div><div class="v">${recs.length}</div></div>` +
    `<div class="stat-card"><div class="k">Unique hosts</div><div class="v">${new Set(recs.map(r => parseHost(r.url))).size}</div></div>` +
    `<div class="stat-card"><div class="k">Total bytes</div><div class="v">${fmtSize(totalBytes)}</div></div>` +
    `<div class="stat-card"><div class="k">Avg time</div><div class="v">${fmtTime(avgTime)}</div></div>` +
    `<div class="stat-card"><div class="k">Slowest</div><div class="v bad">${fmtTime(maxTime)}</div></div>` +
    `<div class="stat-card"><div class="k">4xx/5xx</div><div class="v ${errs ? 'bad' : 'good'}">${errs}</div></div>` +
    `<div class="stat-card"><div class="k">Error rate</div><div class="v ${errs ? 'bad' : 'good'}">${recs.length ? (errs/recs.length*100).toFixed(1) : 0}%</div></div>`;
  const methods = {}; recs.forEach(r => methods[r.method] = (methods[r.method] || 0) + 1);
  barList($('statMethods'), Object.entries(methods).sort((a, b) => b[1] - a[1]), 'method');
  const statuses = {}; recs.forEach(r => { const k = String(r.status); statuses[k] = (statuses[k] || 0) + 1; });
  barList($('statStatuses'), Object.entries(statuses).sort((a, b) => b[1] - a[1]), 'status');
  const hosts = {}; recs.forEach(r => { const h = parseHost(r.url); hosts[h] = (hosts[h] || 0) + 1; });
  barList($('statHosts'), Object.entries(hosts).sort((a, b) => b[1] - a[1]).slice(0, 15), 'host');
  const slow = [...recs].sort((a, b) => (b.time || 0) - (a.time || 0)).slice(0, 10);
  $('statSlow').innerHTML = slow.length ? slow.map((r, i) =>
    `<div class="bar-row"><span class="lbl" title="${esc(r.url)}">${i+1}. ${esc(parseHost(r.url))}</span>` +
    `<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dim)">${esc(parsePath(r.url).slice(0,80))}</span>` +
    `<span class="cnt" style="color:${r.time > 1000 ? 'var(--bad)' : 'var(--good)'}">${fmtTime(r.time)}</span></div>`).join('')
    : '<p style="color:var(--dim)">No data yet.</p>';
}

/* ---------- 13. cURL export tab ---------- */
let curlMode = 'std';
function currentRecs() {
  const src = $('curlSource').value;
  if (src === 'selected' && currentDetail) return [currentDetail];
  if (src === 'filtered') return getFiltered();
  return state.entries;
}
function renderCurlTab() {
  const recs = currentRecs();
  const opts = { optimized: curlMode === 'opt', insecure: $('optInsecure').checked, singleLine: $('optSingleLine').checked, compressed: $('optCompressed').checked };
  $('curlOutput').value = recs.map(r => r.entry ? toCurl(r.entry, opts) : '# metadata-only record (no entry)').join('\n\n');
  $('btnCurlMode').textContent = curlMode === 'opt' ? '⚡ cURL optimized' : 'cURL standard';
  $('btnCurlMode').classList.toggle('primary', curlMode === 'std');
}
$('btnCurlMode').onclick = () => { curlMode = curlMode === 'std' ? 'opt' : 'std'; renderCurlTab(); };
$('optInsecure').onchange = renderCurlTab;
$('optSingleLine').onchange = renderCurlTab;
$('optCompressed').onchange = renderCurlTab;
$('curlSource').onchange = renderCurlTab;
$('btnCopyCurl').onclick = () => copyText($('curlOutput').value);
$('btnCopyFetch').onclick = () => copyText(currentRecs().map(r => r.entry ? toFetch(r.entry) : '').join('\n\n'));
$('btnCopyPython').onclick = () => copyText(currentRecs().map(r => r.entry ? toPython(r.entry) : '').join('\n\n'));
$('btnCopyHttpie').onclick = () => copyText(currentRecs().map(r => r.entry ? toHttpie(r.entry) : '').join('\n\n'));
$('btnCopyPowershell').onclick = () => copyText(currentRecs().map(r => r.entry ? toPowershell(r.entry) : '').join('\n\n'));

/* language snippets (used by detail + cURL tab) */
function toFetch(entry) {
  const r = entry.request, headers = {}, skip = getSkipSet();
  (r.headers || []).forEach(h => { const n = h.name.toLowerCase(); if (!skip.has(n) && !(n in headers)) headers[h.name] = h.value; });
  const body = r.postData?.text;
  return `fetch(${JSON.stringify(r.url, null, 2)}, ${JSON.stringify({ method: r.method, headers, ...(body ? { body } : {}) }, null, 2)});`;
}
function toPython(entry) {
  const r = entry.request, hdrs = {}, skip = getSkipSet();
  (r.headers || []).forEach(h => { const n = h.name.toLowerCase(); if (!skip.has(n) && !(n in hdrs)) hdrs[h.name] = h.value; });
  const L = ['import requests', ''];
  const pd = r.postData;
  if (pd?.text && /json/i.test(pd.mimeType || '')) {
    let pl = pd.text; try { pl = JSON.stringify(JSON.parse(pd.text), null, 2); } catch {}
    L.push(`payload = ${pl}`, '', `r = requests.${r.method.toLowerCase()}(${JSON.stringify(r.url)},`, `    json=payload,`, `    headers=${JSON.stringify(hdrs, null, 2)})`);
  } else if (pd?.text) {
    L.push(`data = ${JSON.stringify(pd.text)}`, '', `r = requests.${r.method.toLowerCase()}(${JSON.stringify(r.url)},`, `    data=data,`, `    headers=${JSON.stringify(hdrs, null, 2)})`);
  } else {
    L.push(`r = requests.${r.method.toLowerCase()}(${JSON.stringify(r.url)},`, `    headers=${JSON.stringify(hdrs, null, 2)})`);
  }
  L.push('', 'print(r.status_code, r.text[:500])');
  return L.join('\n');
}
function toHttpie(entry) {
  const r = entry.request, skip = getSkipSet();
  const parts = [`http ${r.method === 'GET' ? '' : r.method} '${r.url}'`].filter(Boolean);
  (r.headers || []).forEach(h => { if (!skip.has(h.name.toLowerCase())) parts.push(`'${h.name}: ${h.value}'`); });
  if (r.postData?.text) {
    if (/json/i.test(r.postData.mimeType || '')) { try { parts.push(`json=${JSON.stringify(JSON.parse(r.postData.text))}`); } catch { parts.push(`'${r.postData.text}'`); } }
    else parts.push(`'${r.postData.text}'`);
  }
  return parts.join(' \\\n  ');
}
function toPowershell(entry) {
  const r = entry.request, skip = getSkipSet();
  const L = [];
  const body = r.postData?.text;
  if (body && /json/i.test(r.postData.mimeType || '')) {
    L.push(`$body = @'`);
    try { L.push(JSON.stringify(JSON.parse(body), null, 2)); } catch { L.push(body); }
    L.push(`'@`, '');
  }
  const hdrs = [];
  (r.headers || []).forEach(h => { if (!skip.has(h.name.toLowerCase())) hdrs.push(`        "${h.name}" = "${dq(h.value)}"`); });
  L.push(`$headers = @{`, hdrs.join('\n'), `}`, '');
  L.push(`Invoke-RestMethod -Uri "${dq(r.url)}" -Method ${r.method} -Headers $headers${body ? (body.includes('\n') ? ' -Body $body' : ` -Body "${dq(body)}"`) : ''}`);
  return L.join('\n');
}

/* ---------- 14. tabs, controls, keyboard, init ---------- */
function switchTab(name) {
  document.querySelectorAll('nav.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  document.querySelectorAll('section.tab').forEach(s => s.classList.toggle('hidden', s.id !== 'tab-' + name));
  if (name === 'stats') renderStats();
  if (name === 'curl') renderCurlTab();
}
document.querySelectorAll('nav.tabs button').forEach(b => b.onclick = () => switchTab(b.dataset.tab));

$('btnStart').onclick = () => { state.recording = true; render(); $('btnStart').textContent = '● Recording…'; $('btnStop').textContent = '■ Stop'; flash('Recording on'); };
$('btnStop').onclick = () => {
  state.recording = false; render(); $('btnStart').textContent = '● Start'; $('btnStop').textContent = '■ Stop'; flash('Recording off');
  if ($('harAuto').checked) downloadHar();
};
$('btnClear').onclick = () => { state.entries = []; state.seq = 0; state.selected.clear(); state.bodyCache.clear(); render(); $('dContent').innerHTML = ''; $('dTitle').textContent = 'Select a request'; flash('Cleared'); };
$('filter').oninput = () => { state.page = 1; render(); };
$('methodFilter').onchange = () => { state.page = 1; render(); };
$('statusFilter').onchange = () => { state.page = 1; render(); };
$('typeFilter').onchange = () => { state.page = 1; render(); };
$('favOnly').onchange = () => { state.page = 1; render(); };
$('pageSize').onchange = e => { state.pageSize = +e.target.value; state.page = 1; render(); };
$('btnPrev').onclick = () => { state.page--; render(); };
$('btnNext').onclick = () => { state.page++; render(); };
document.querySelectorAll('#log thead th[data-key]').forEach(th => {
  th.onclick = () => {
    const k = th.dataset.key;
    if (state.sortKey === k) state.sortDir *= -1;
    else { state.sortKey = k; state.sortDir = (k === 'method' || k === 'host') ? 1 : -1; }
    document.querySelectorAll('#log thead th .arrow').forEach(a => a.textContent = '');
    th.querySelector('.arrow').textContent = state.sortDir === 1 ? ' ▲' : ' ▼';
    state.page = 1; render();
  };
});
$('selAll').onchange = e => {
  const list = getFiltered();
  if (e.target.checked) list.forEach(r => state.selected.add(r.seq));
  else list.forEach(r => state.selected.delete(r.seq));
  updateBulkBar(); render();
};
$('btnCopySelCurl').onclick = () => copyText(getSelectedRecs().map(r => r.entry ? toCurl(r.entry, { optimized: false }) : '').join('\n\n'));
$('btnCopySelOpt').onclick = () => copyText(getSelectedRecs().map(r => r.entry ? toCurl(r.entry, { optimized: true }) : '').join('\n\n'));
$('btnCopySelHar').onclick = async () => copyText(JSON.stringify(await buildHar(getSelectedRecs()), null, 2));
$('btnDeleteSel').onclick = () => {
  const del = getSelectedRecs().map(r => r.seq);
  state.entries = state.entries.filter(r => !del.includes(r.seq));
  del.forEach(s => state.selected.delete(s));
  render(); flash(`Deleted ${del.length}`);
};
$('btnCollapseDup').onclick = () => { state.dedupeView = !state.dedupeView; $('btnCollapseDup').classList.toggle('primary', state.dedupeView); state.page = 1; render(); };
function getSelectedRecs() { return state.entries.filter(r => state.selected.has(r.seq)); }

/* deep search via 🔍 modal */
$('btnDeepSearch').onclick = () => { $('deepQuery').value = ''; $('deepResults').innerHTML = ''; $('searchModal').classList.remove('hidden'); setTimeout(() => $('deepQuery').focus(), 50); };
$('btnDeepClose').onclick = () => $('searchModal').classList.add('hidden');
$('searchModal').onclick = e => { if (e.target === $('searchModal')) $('searchModal').classList.add('hidden'); };
$('btnDeepRun').onclick = () => runDeepSearch();
$('deepQuery').onkeydown = e => { if (e.key === 'Enter') runDeepSearch(); };
function runDeepSearch() {
  const q = $('deepQuery').value.trim(), out = $('deepResults');
  if (!q) return;
  out.innerHTML = '<p style="color:var(--dim)">Scanning…</p>';
  let re; try { re = new RegExp(q, 'i'); } catch { re = null; }
  const results = [];
  state.entries.forEach(rec => {
    if (re ? re.test(rec.url) : rec.url.toLowerCase().includes(q.toLowerCase())) { results.push({ rec, where: 'url' }); return; }
    const cached = state.bodyCache.get(rec.seq);
    if (cached && (re ? re.test(cached.text) : cached.text.toLowerCase().includes(q.toLowerCase()))) results.push({ rec, where: 'body' });
  });
  if (!results.length) { out.innerHTML = '<p style="color:var(--dim)">No hits. Enable "cache response bodies" in Settings to search bodies.</p>'; return; }
  out.innerHTML = `<p style="color:var(--warn)">${results.length} hit(s). Click to jump:</p>`;
  results.slice(0, 200).forEach(({ rec, where }) => {
    const div = document.createElement('div');
    div.style.cssText = 'padding:4px 6px;border-bottom:1px solid var(--border);cursor:pointer';
    div.innerHTML = `<span class="method m-${rec.method.toLowerCase()}">${rec.method}</span> ` +
      `<span style="color:${rec.status >= 400 ? 'var(--bad)' : 'var(--good)'}">${rec.status}</span> ` +
      `<span style="color:var(--warn)">${esc(parseHost(rec.url))}</span> ` +
      `<span>${esc(parsePath(rec.url).slice(0,120))}</span>` +
      (where === 'body' ? ' <span class="badge green">body</span>' : '');
    div.onclick = () => { $('searchModal').classList.add('hidden'); showDetail(rec); };
    out.appendChild(div);
  });
}

/* settings */
$('btnSettings').onclick = () => switchTab('settings');
$('btnSaveSettings').onclick = () => {
  settings.autoStart = $('setAutoStart').checked;
  settings.maxEntries = clamp(+$('setMaxEntries').value || 10000, 100, 100000);
  settings.dedupe = $('setDedupe').checked;
  settings.autoScroll = $('setAutoScroll').checked;
  settings.hostWhitelist = $('setHostWhitelist').value.trim();
  settings.hostBlacklist = $('setHostBlacklist').value.trim();
  settings.skipHeaders = $('setSkipHeaders').value.trim();
  settings.optHeaders = $('setOptHeaders').value.trim();
  settings.insecure = $('setInsecure').checked;
  settings.singleLine = $('setSingleLine').checked;
  settings.bodyCache = $('setBodyCache').checked;
  settings.bodyCacheMax = clamp(+$('setBodyCacheMax').value || 50000, 1000, 1000000);
  saveSettings(); syncSettingsToForm();
  flash('Settings saved');
};
$('btnWipe').onclick = () => {
  if (!confirm('Wipe all settings, favorites and snapshots?')) return;
  localStorage.removeItem(SETTINGS_KEY); localStorage.removeItem(SNAPSHOT_KEY); localStorage.removeItem(FAVS_KEY);
  settings = { ...DEFAULT_SETTINGS }; state.favs.clear(); syncSettingsToForm(); flash('Wiped');
};

/* keyboard */
document.addEventListener('keydown', e => {
  const tag = document.activeElement?.tagName;
  const typing = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
  if (e.key === 'Escape') { $('searchModal').classList.add('hidden'); return; }
  if (typing) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') { e.preventDefault(); $('filter').focus(); $('filter').select(); }
  else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); state.recording ? $('btnStop').click() : $('btnStart').click(); }
  else if (/^[1-6]$/.test(e.key)) switchTab(['log','detail','curl','har','stats','settings'][+e.key - 1]);
  else if (e.key.toLowerCase() === 'd') $('btnCollapseDup').click();
});

/* ---------- init ---------- */
function init() {
  try { state.favs = new Set(JSON.parse(localStorage.getItem(FAVS_KEY) || '[]')); } catch {}
  state.recording = settings.autoStart;
  // add 🔍 button + set ⚙ to open settings tab
  const btnSearch = document.createElement('button');
  btnSearch.id = 'btnDeepSearch'; btnSearch.textContent = '🔍 Search';
  btnSearch.title = 'Deep search URLs + cached bodies';
  btnSearch.style.cssText = 'background:#4a3a10;';
  $('btnSettings').insertAdjacentElement('beforebegin', btnSearch);
  syncSettingsToForm();
  $('pageSize').value = state.pageSize;
  switchTab('log');
  render();
  console.log('[API Sniffer Pro v2.1] initialized — recording:', state.recording);
}
init();