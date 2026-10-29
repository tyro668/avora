// Avora mock SaaS chat page (shared by the Go, Node, Python, Java and Rust gateways).
// No build step. User and model text only ever reaches the DOM through
// textContent / createTextNode; only the constant icon markup is parsed as HTML.
'use strict';

// ---- pure helpers (also loaded by mock/web/test/chat.test.mjs under Node) ----
const AvoraChat = (() => {
  // parseMarkdown turns model output into a small block AST. It is tolerant of
  // half-streamed input: an unterminated ``` fence is an open code block.
  function parseMarkdown(src) {
    const lines = String(src || '').replace(/\r\n?/g, '\n').split('\n');
    const out = [];
    let para = null, list = null, quote = null;
    const flush = () => { para = null; list = null; quote = null; };
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];
      const fence = ln.match(/^\s*(`{3,}|~{3,})\s*([\w+#.-]*)/);
      if (fence) {
        flush();
        const close = new RegExp('^\\s*' + fence[1][0] + '{' + fence[1].length + ',}\\s*$');
        const body = []; let closed = false;
        for (i++; i < lines.length; i++) { if (close.test(lines[i])) { closed = true; break; } body.push(lines[i]); }
        if (!closed && body.length && !body[body.length - 1].trim()) body.pop();
        out.push({ t: 'code', lang: fence[2].toLowerCase(), text: body.join('\n'), closed });
        continue;
      }
      if (!ln.trim()) { flush(); continue; }
      let m;
      if ((m = ln.match(/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/))) { flush(); out.push({ t: 'h', level: m[1].length, inl: parseInline(m[2]) }); continue; }
      if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(ln)) { flush(); out.push({ t: 'hr' }); continue; }
      if ((m = ln.match(/^\s{0,3}>\s?(.*)$/))) {
        if (!quote) { flush(); quote = { t: 'quote', text: [] }; out.push(quote); }
        quote.text.push(m[1]); quote.inl = parseInline(quote.text.join('\n')); continue;
      }
      if ((m = ln.match(/^\s*([-*+]|(\d{1,9})[.)])\s+(.*)$/))) {
        const ordered = m[2] !== undefined;
        if (!list || list.ordered !== ordered) { para = null; quote = null; list = { t: 'list', ordered, start: ordered ? Number(m[2]) : 1, items: [] }; out.push(list); }
        list.items.push({ raw: m[3] }); continue;
      }
      if (list && /^\s+\S/.test(ln)) { const it = list.items[list.items.length - 1]; it.raw += '\n' + ln.trim(); continue; }
      if (quote) quote = null;
      list = null;
      if (!para) { para = { t: 'p', raw: [] }; out.push(para); }
      para.raw.push(ln);
    }
    for (const b of out) {
      if (b.t === 'p') { b.inl = parseInline(b.raw.join('\n')); delete b.raw; }
      if (b.t === 'list') for (const it of b.items) { it.inl = parseInline(it.raw); delete it.raw; }
      if (b.t === 'quote') delete b.text;
    }
    return out;
  }

  // parseInline: `code`, **bold**, *em* / _em_, [text](http(s) url). Anything
  // else, including HTML tags, stays literal text.
  function parseInline(s) {
    const out = [];
    const push = (n) => { const l = out[out.length - 1]; if (n.t === 'text' && l && l.t === 'text') l.v += n.v; else out.push(n); };
    let i = 0;
    while (i < s.length) {
      const c = s[i];
      if (c === '`') {
        const j = s.indexOf('`', i + 1);
        if (j > i) { push({ t: 'code', v: s.slice(i + 1, j) }); i = j + 1; continue; }
      }
      if ((c === '*' || c === '_') && s[i + 1] === c) {
        const j = s.indexOf(c + c, i + 2);
        if (j > i + 2) { out.push({ t: 'b', c: parseInline(s.slice(i + 2, j)) }); i = j + 2; continue; }
      }
      if ((c === '*' || c === '_') && s[i + 1] && s[i + 1] !== ' ' && (c === '*' || !/\w/.test(s[i - 1] || ''))) {
        const j = s.indexOf(c, i + 1);
        if (j > i + 1 && s[j - 1] !== ' ') { out.push({ t: 'i', c: parseInline(s.slice(i + 1, j)) }); i = j + 1; continue; }
      }
      if (c === '[') {
        const m = s.slice(i).match(/^\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/);
        if (m) { out.push({ t: 'a', href: m[2], c: parseInline(m[1]) }); i += m[0].length; continue; }
      }
      push({ t: 'text', v: c }); i++;
    }
    return out;
  }

  const KW = new Set(('func package import return if else for range go defer var const type struct interface map chan select case switch default break continue nil true false ' +
    'string int int64 uint8 byte rune error bool float64 any ' +
    'function let async await new class extends this null undefined typeof instanceof try catch finally throw yield export from of in ' +
    'def lambda pass None True False elif with as raise not and or is self print ' +
    'fn pub mut impl use mod match loop where crate trait enum struct ' +
    'public private protected static final void boolean long double char ' +
    'echo then fi do done esac local').split(' '));
  const HASH_COMMENT = new Set(['py', 'python', 'sh', 'bash', 'shell', 'zsh', 'yaml', 'yml', 'toml', 'ruby', 'rb', 'r', 'perl', 'dockerfile', 'makefile']);
  // highlight splits code into [{c, v}] tokens; c is 'k' keyword/key, 's' string, 'c' comment or ''.
  function highlight(code, lang) {
    const toks = [];
    const add = (c, v) => { const l = toks[toks.length - 1]; if (l && l.c === c) l.v += v; else toks.push({ c, v }); };
    const hash = HASH_COMMENT.has(lang);
    const json = lang === 'json' || lang === 'jsonc';
    let i = 0;
    while (i < code.length) {
      const ch = code[i], rest = code.slice(i);
      if ((!json && !hash && rest.startsWith('//')) || (hash && ch === '#')) { const e = code.indexOf('\n', i); const j = e < 0 ? code.length : e; add('c', code.slice(i, j)); i = j; continue; }
      if (!json && rest.startsWith('/*')) { const e = code.indexOf('*/', i + 2); const j = e < 0 ? code.length : e + 2; add('c', code.slice(i, j)); i = j; continue; }
      if (ch === '"' || ch === "'" || ch === '`') {
        let j = i + 1;
        while (j < code.length && code[j] !== ch && (ch === '`' || code[j] !== '\n')) j += code[j] === '\\' && ch !== '`' ? 2 : 1;
        const v = code.slice(i, Math.min(j + 1, code.length));
        // JSON object keys get the keyword colour, values the string colour.
        add(json && ch === '"' && /^\s*:/.test(code.slice(j + 1)) ? 'k' : 's', v); i = j + 1; continue;
      }
      const w = rest.match(/^[A-Za-z_][\w]*/);
      if (w) { add(!json && KW.has(w[0]) ? 'k' : '', w[0]); i += w[0].length; continue; }
      add('', ch); i++;
    }
    return toks;
  }

  // shortModel gives the label for a /v1/models entry: the advertised display
  // name, else the last path segment of "device/adapter/model".
  function shortModel(m) {
    if (!m) return '';
    if (typeof m === 'string') return m.split('/').pop() || m;
    return m.display_name || (m.id || '').split('/').pop() || m.id || '';
  }
  // shortId: "dev_844ecdd014750482971af079554161b9" → "dev_844ecdd0…554161b9".
  function shortId(id, head = 12, tail = 8) {
    id = String(id || '');
    return id.length > head + tail + 1 ? id.slice(0, head) + '…' + id.slice(-tail) : id;
  }
  const secs = (ms) => (ms / 1000).toFixed(2) + ' s';
  const secs1 = (ms) => (ms / 1000).toFixed(1);

  // mergeToolCalls folds streamed delta.tool_calls fragments (OpenAI shape) into
  // complete calls, keyed by index.
  function mergeToolCalls(acc, deltas) {
    for (const d of deltas || []) {
      const k = d.index ?? acc.length;
      const t = acc[k] || (acc[k] = { id: '', name: '', args: '' });
      if (d.id) t.id = d.id;
      if (d.function) { if (d.function.name) t.name += d.function.name; if (d.function.arguments) t.args += d.function.arguments; }
    }
    return acc;
  }
  const prettyArgs = (s) => { try { return JSON.stringify(JSON.parse(s), null, 0).replace(/^\{/, '{ ').replace(/\}$/, ' }').replace(/":/g, '": ').replace(/,"/g, ', "'); } catch { return s; } };

  // steps derives the timeline rows from what the browser saw of one answer.
  // Every row is backed by a real event: response headers (X-Task-Id), the first
  // content delta, finish_reason=tool_calls, the final finish/usage or an error.
  function steps(a) {
    const rows = [];
    if (a.dispatchedAt != null) rows.push({ k: 'dispatch', state: 'ok', at: a.dispatchedAt, device: a.device || '设备' });
    else if (a.state === 'live') rows.push({ k: 'dispatch', state: 'live', device: a.device || '设备' });
    if (a.firstAt != null) rows.push({ k: 'first', state: 'ok', at: a.firstAt, model: a.model, ttft: a.firstAt });
    else if (a.state === 'live' && a.dispatchedAt != null) rows.push({ k: 'first', state: 'live', model: a.model });
    if ((a.tools || []).length) rows.push({ k: 'tools', state: 'ok', at: a.toolsAt ?? a.endAt, finish: 'tool_calls', tools: a.tools });
    if (a.state === 'live' && a.firstAt != null && !(a.tools || []).length) rows.push({ k: 'gen', state: 'live' });
    if (a.state === 'done' && a.finish !== 'tool_calls') rows.push({ k: 'done', state: 'ok', at: a.endAt, finish: a.finish || 'stop' });
    if (a.state === 'stopped') rows.push({ k: 'stopped', state: 'bad', at: a.endAt });
    if (a.state === 'error') rows.push({ k: 'error', state: 'bad', at: a.endAt, code: a.error && a.error.code });
    return rows;
  }
  function summary(a) {
    const parts = [];
    const tasks = (a.taskIds || []).length;
    if (tasks) parts.push(tasks + ' 次任务');
    if ((a.tools || []).length) parts.push(a.tools.length + ' 次工具调用');
    if (a.endAt != null) parts.push('用时 ' + secs1(a.endAt) + ' 秒');
    return parts;
  }
  function metrics(a) {
    const p = [];
    if (a.firstAt != null) p.push('首字 ' + Math.round(a.firstAt) + ' ms');
    if (a.endAt != null) p.push('总耗时 ' + secs1(a.endAt) + ' s');
    const u = a.usage;
    if (u) {
      p.push((u.prompt_tokens ?? '-') + ' → ' + (u.completion_tokens ?? '-') + ' tokens');
      const gen = (a.endAt ?? 0) - (a.firstAt ?? 0);
      if (u.completion_tokens && a.firstAt != null && gen > 0) p.push((u.completion_tokens / (gen / 1000)).toFixed(1) + ' tok/s');
    }
    if (a.finish && a.finish !== 'stop') p.push('finish: ' + a.finish);
    return p;
  }

  // titleOf makes a history title from the first user message.
  const titleOf = (text) => { const t = String(text || '').replace(/\s+/g, ' ').trim(); return t.length > 30 ? t.slice(0, 30) + '…' : (t || '新对话'); };
  // groupByDay buckets chats (newest first) into 今天 / 昨天 / 更早.
  function groupByDay(chats, now = Date.now()) {
    const d0 = new Date(now); d0.setHours(0, 0, 0, 0);
    const today = d0.getTime(), yday = today - 864e5;
    const g = { 今天: [], 昨天: [], 更早: [] };
    for (const c of [...chats].sort((a, b) => b.updated - a.updated)) g[c.updated >= today ? '今天' : c.updated >= yday ? '昨天' : '更早'].push(c);
    return Object.entries(g).filter(([, v]) => v.length);
  }
  // stripImages replaces data: URIs in stored messages when storage is full.
  function stripImages(chat) {
    const c = JSON.parse(JSON.stringify(chat));
    for (const m of c.messages || []) if (Array.isArray(m.content)) m.content = m.content.map((p) => (p.type === 'image_url' ? { type: 'text', text: '[图片未保存]' } : p));
    for (const t of c.turns || []) delete t.img;
    return c;
  }
  // codeChars: the 8 visible characters of a pairing code such as "K7QF-3H9X".
  const codeChars = (v) => String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  const brandOf = (tenant) => { const t = String(tenant || '').trim(); return t ? t[0].toUpperCase() + t.slice(1) : ''; };

  return { parseMarkdown, parseInline, highlight, shortModel, shortId, secs, mergeToolCalls, prettyArgs, steps, summary, metrics, titleOf, groupByDay, stripImages, codeChars, brandOf };
})();
if (typeof module === 'object' && module.exports) module.exports = AvoraChat;

// ---- page ----
if (typeof document !== 'undefined') (function () {
  const L = AvoraChat;
  const $ = (id) => document.getElementById(id);
  const SS = window.sessionStorage, LS = window.localStorage;
  let auth = null;            // {tenant, user, key}
  let chats = [];             // stored conversations
  let cur = null;             // current conversation {id,title,updated,model,messages,turns}
  let models = [];            // /v1/models data
  let devices = [];           // /lmbp/v1/tenant/devices devices
  let attachment = null;      // {dataURL, name, size}
  let busy = null;            // AbortController of the running request
  let pairLink = '', issuer = '';
  let showRevoked = false;    // offline/revoked group expanded

  const ERR = {
    UNAUTHENTICATED: '认证失败：租户 API Key 无效或已失效',
    FORBIDDEN: '无权访问该资源',
    BAD_REQUEST: '请求格式或参数错误',
    DEVICE_OFFLINE: '设备离线：请确认电脑上的 Connector 正在运行',
    DEVICE_BUSY: '设备繁忙：已达并发上限，请稍后重试',
    MODEL_NOT_FOUND: '模型不存在：你的在线设备上没有这个模型',
    UPSTREAM_ERROR: '本机模型出错',
    TIMEOUT: '任务超时',
    CANCELLED: '任务已取消',
    RATE_LIMITED: '请求过于频繁，请稍后再试',
    INTERNAL: '网关内部错误',
    OUTCOME_UNKNOWN: '设备中途断开，结果未知（可能已执行）',
    FLOW_CONTROL: '流控违规，连接已断开',
    SLOW_CONSUMER: '读取过慢，任务被网关终止',
    CAPABILITY_UNSUPPORTED: '模型或设备不支持该能力（如图片、tools）',
    PAYLOAD_TOO_LARGE: '附件过大（单个 ≤ 20 MiB，单任务 ≤ 32 MiB）',
    IDEMPOTENCY_KEY_REUSED: 'Idempotency-Key 被用于不同的请求体',
    E2EE_DECRYPT_FAILED: '设备无法解密请求',
    CONSENT_DENIED: '配对未获同意：该配对码已被拒绝，需在设备上重新发起配对',
    VERSION_UNSUPPORTED: '协议版本不支持',
    BAD_SIGNATURE: '任务签名无效',
    NETWORK: '网络错误',
  };
  const describe = (code, msg) => (ERR[code] || '错误') + (msg ? '（' + msg + '）' : '');

  // ---- icons (constant markup only) ----
  const P = {
    pen: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>', chev: '<path d="m6 9 6 6 6-6"/>', chevr: '<path d="m9 6 6 6-6 6"/>', chevu: '<path d="m6 15 6-6 6 6"/>',
    check: '<path d="m5 12 5 5 9-10"/>', copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    img: '<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>', up: '<path d="M12 19V5M6 11l6-6 6 6"/>',
    laptop: '<rect x="4" y="5" width="16" height="11" rx="2"/><path d="M2 19h20"/>', mon: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    wrench: '<path d="M14.7 6.3a4 4 0 0 0 5 5L22 14l-8 8-3-3 8-8"/><path d="M14.7 6.3 12 3.6a4 4 0 0 0-5.4 5.4L2 13.6 5.4 17l4.6-4.6"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>', more: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>', side: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/>',
    term: '<path d="m4 17 6-5-6-5M12 19h8"/>', link: '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>', plus: '<path d="M12 5v14M5 12h14"/>', alert: '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5h.01"/>',
    square: '<rect x="6" y="6" width="12" height="12" rx="2"/>', trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  };
  function icon(k, c = 'currentColor', s = 16, w = 2) {
    const t = document.createElement('template');
    t.innerHTML = `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="${w}" stroke-linecap="round" stroke-linejoin="round">${P[k]}</svg>`;
    return t.content.firstChild;
  }
  let logoN = 0;
  function logo(s, r) {
    const id = 'lg' + (++logoN);
    const t = document.createElement('template');
    t.innerHTML = `<svg width="${s}" height="${s}" viewBox="0 0 32 32"><defs><linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#2bb8a6"/><stop offset="1" stop-color="#0f7a6e"/></linearGradient></defs><rect width="32" height="32" rx="${r}" fill="url(#${id})"/><path d="M9 21.5 14.6 9.5h2.8L23 21.5h-3l-1.1-2.6h-5.8L12 21.5z M14 16.4h3.9L16 11.9z" fill="#fff"/><circle cx="24.5" cy="8" r="2.2" fill="#ccfbf1"/></svg>`;
    return t.content.firstChild;
  }
  for (const e of document.querySelectorAll('[data-icon]')) e.prepend(icon(e.dataset.icon, e.dataset.c, Number(e.dataset.s), Number(e.dataset.w || 2)));
  for (const e of document.querySelectorAll('[data-logo]')) { const s = Number(e.dataset.logo); e.append(logo(s, Math.round(s * 0.3))); }

  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function toast(text, bad) {
    const d = el('div', bad ? 'bad' : '', text);
    $('toast').appendChild(d); setTimeout(() => d.remove(), 4000);
  }
  const copy = (t, what) => navigator.clipboard?.writeText(t).then(() => toast('已复制' + what), () => toast('复制失败', true));

  // ---- API ----
  class ApiError extends Error { constructor(status, code, msg) { super(msg); this.status = status; this.code = code; } }
  async function parseError(res) {
    let code = 'HTTP_' + res.status, msg = res.statusText;
    try {
      const b = await res.json();
      if (b.error && typeof b.error === 'object') { code = b.error.code || code; msg = b.error.message || msg; }
      else if (b.code) { code = b.code; msg = b.detail || b.title || msg; }
      else if (typeof b.error === 'string') { code = b.error; }
    } catch { /* not JSON */ }
    return new ApiError(res.status, code, msg);
  }
  const headers = (extra) => Object.assign({ Authorization: 'Bearer ' + auth.key, 'X-End-User': auth.user }, extra || {});
  async function api(method, path, body) {
    const res = await fetch(path, { method, headers: headers(body ? { 'Content-Type': 'application/json' } : {}), body: body ? JSON.stringify(body) : undefined });
    if (!res.ok) { const e = await parseError(res); if (e.status === 401) onUnauthorized(); throw e; }
    return res.json();
  }
  function onUnauthorized() { toast(ERR.UNAUTHENTICATED + '，请重新登录', true); logout(); }

  // ---- login ----
  const brand = () => L.brandOf(auth?.tenant);
  function showApp(on) {
    $('login').classList.toggle('hidden', on); $('app').classList.toggle('hidden', !on);
    if (!on) { closeModal('pairModal'); closeModal('devModal'); return; }
    const b = brand();
    $('brand').textContent = b + ' Chat'; document.title = b + ' Chat';
    $('who').textContent = auth.user; $('whoTenant').textContent = '租户 ' + auth.tenant;
    $('avatar').textContent = (auth.user || 'U').slice(0, 1).toUpperCase();
    $('pairSub').textContent = `让 ${b} Chat 使用你电脑上的模型`;
    $('foot').textContent = `消息经 ${b} 网关送到你的电脑上执行，回答由本机模型生成`;
  }
  async function login(a) {
    auth = a;
    try { await api('GET', '/lmbp/v1/tenant/devices'); } catch (e) { auth = null; throw e; }
    SS.setItem('lmbp.auth', JSON.stringify(a));
    showApp(true); loadChats(); openChat(null); await loadPairing(); await refresh();
  }
  function logout() { if (busy) busy.abort(); auth = null; SS.removeItem('lmbp.auth'); showApp(false); }
  $('loginForm').addEventListener('submit', async (ev) => {
    ev.preventDefault(); $('loginErr').textContent = '';
    try { await login({ tenant: $('tenant').value.trim(), user: $('user').value.trim(), key: $('key').value }); $('key').value = ''; }
    catch (e) { $('loginErr').textContent = e.status === 401 ? 'API Key 无效' : describe(e.code, e.message); }
  });
  $('logout').onclick = () => { $('meMenu').classList.add('hidden'); logout(); };
  $('meMore').onclick = (e) => { e.stopPropagation(); $('meMenu').classList.toggle('hidden'); };
  document.addEventListener('click', () => { $('meMenu').classList.add('hidden'); for (const m of document.querySelectorAll('.dc .menu')) m.remove(); });
  $('fold').onclick = () => { $('app').classList.add('folded'); $('unfold').classList.remove('hidden'); };
  $('unfold').onclick = () => { $('app').classList.remove('folded'); $('unfold').classList.add('hidden'); };

  // ---- modals ----
  const isOpen = (id) => !$(id).classList.contains('hidden');
  function closeModal(id) { $(id).classList.add('hidden'); }
  for (const id of ['pairModal', 'devModal']) $(id).addEventListener('mousedown', (e) => { if (e.target === $(id)) id === 'pairModal' ? closePairModal() : closeModal(id); });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (isOpen('pairModal')) closePairModal(); else if (isOpen('devModal')) closeModal('devModal');
  });

  // ---- pairing ----
  async function loadPairing() {
    try {
      const res = await fetch('/.well-known/lmbp?tenant=' + encodeURIComponent(auth.tenant));
      if (!res.ok) throw await parseError(res);
      issuer = (await res.json()).issuer;
    } catch (e) { issuer = location.origin; toast('读取网关元数据失败：' + describe(e.code, e.message), true); }
    pairLink = 'lmbp://pair?v=2&gateway=' + encodeURIComponent(issuer) + '&tenant=' + encodeURIComponent(auth.tenant) + '&remote=' + encodeURIComponent(location.origin);
    $('pairLink').textContent = pairLink; $('pairLink').title = pairLink;
    if ($('code').value.trim()) openPairModal(null);
  }
  const cmd = () => `avora connector -pair-link '${pairLink}' -adapter-id local -ollama-url http://127.0.0.1:11434 -models <模型名> -capabilities vision`;
  $('copyLink').onclick = () => copy(pairLink, '配对链接');
  $('copyCmd').onclick = () => copy(cmd(), ' CLI 命令');
  function pairMsg(text, bad) { const d = $('pairMsg'); d.className = 'ind ' + (bad ? 'msg-err' : 'msg-ok'); d.textContent = text; }
  function clearPairMsg() { $('pairMsg').className = 'ind'; $('pairMsg').textContent = ''; }

  function renderCode() {
    const box = $('codeBox'), v = L.codeChars($('code').value);
    for (const n of [...box.children]) if (n.id !== 'code') n.remove();
    const focusAt = Math.min(v.length, 7);
    for (let i = 0; i < 8; i++) {
      if (i === 4) box.insertBefore(el('em', '', '–'), $('code'));
      box.insertBefore(el('span', i === focusAt ? 'f' : '', v[i] || ''), $('code'));
    }
  }
  $('code').addEventListener('input', renderCode);
  $('code').addEventListener('focus', () => $('codeBox').classList.add('focus'));
  $('code').addEventListener('blur', () => $('codeBox').classList.remove('focus'));
  $('advToggle').onclick = () => { const open = $('advBody').classList.toggle('hidden'); $('advToggle').classList.toggle('open', !open); };

  // Pending pairings are never listed by the gateway (review 2026-10-29): the pairing dialog
  // opens only when the user asks for it, and the code typed here must be the one the
  // user's own desktop shows.
  function updatePairBadge() {
    const n = devices.filter((d) => d.status === 'active').length;
    $('pairBadge').className = 'badge off'; $('pairBadge').textContent = n ? `已配对 ${n} 台` : '未配对';
  }
  function openPairModal() {
    updatePairBadge(); renderCode();
    if (!isOpen('pairModal')) { closeModal('devModal'); $('pairModal').classList.remove('hidden'); setTimeout(() => $('code')?.focus(), 20); }
  }
  function closePairModal() { closeModal('pairModal'); }
  $('closePairModal').onclick = closePairModal;
  $('openPairModal').onclick = () => { clearPairMsg(); openPairModal(); };
  for (const id of ['code', 'jkt']) $(id).addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); decide(false); } });

  async function decide(deny) {
    const user_code = $('code').value.trim();
    if (!user_code) return pairMsg('请输入设备上显示的配对码', true);
    const body = { user_code }; const jkt = $('jkt').value.trim(); if (jkt) body.jkt = jkt; if (deny) body.deny = true;
    $('approve').disabled = $('deny').disabled = true;
    try {
      const r = await api('POST', '/lmbp/v1/tenant/devices/approvals', body);
      // device_name is reported by the device itself: shown as plain text and labelled as such.
      pairMsg(r.status === 'approved' ? `已批准（设备自报名称：${r.device_name || '未命名'}，设备 ID：${r.device_id}），等待设备上线…` : '已拒绝该配对请求，设备将收到 CONSENT_DENIED');
      $('code').value = ''; $('jkt').value = ''; renderCode();
      if (location.search) window.history.replaceState(null, '', location.pathname);
      if (r.status === 'approved') {
        toast(`已批准配对：${r.device_id}`);
        closeModal('pairModal');
      }
      refresh(); setTimeout(refresh, 1500);
    } catch (e) {
      const extra = { 404: '（配对码无效、已过期或已使用）', 409: '（jkt 与该配对请求的设备密钥不一致）', 429: '（失败次数过多，请一分钟后再试）' }[e.status] || '';
      pairMsg(describe(e.code, e.message) + extra, true);
    } finally { $('approve').disabled = $('deny').disabled = false; }
  }
  $('approve').onclick = () => decide(false);
  $('deny').onclick = () => decide(true);

  // ---- devices & models ----
  async function refresh() {
    if (!auth) return;
    try {
      const [d, m] = await Promise.all([api('GET', '/lmbp/v1/tenant/devices'), api('GET', '/v1/models')]);
      devices = d.devices || [];
      if (isOpen('pairModal')) updatePairBadge();
      renderDevices(devices); renderModels(m.data || []);
    } catch (e) { if (e.status !== 401) $('devSub').textContent = '加载失败：' + describe(e.code, e.message); }
  }
  const devIcon = (name) => (/mini|imac|studio|desktop|台式|pc|win/i.test(name || '') ? 'mon' : 'laptop');
  function deviceCard(d) {
    const revoked = d.status !== 'active';
    const card = el('div', 'dc' + (d.online && !revoked ? '' : ' dim'));
    const ic = el('span', 'dic'); ic.append(icon(devIcon(d.name), '#3a3a37', 18));
    const body = el('div'); body.style.cssText = 'flex:1;min-width:0';
    const nm = el('div', 'nm'); nm.title = '设备自报名称（由设备提供，仅供参考）';
    nm.append(document.createTextNode(d.name || '(未命名设备)'),
      el('span', 'badge ' + (revoked ? 'rv' : d.online ? 'on' : 'off'), revoked ? '已吊销' : d.online ? '在线' : '离线'), el('span', 'sp'));
    const more = el('button', 'more'); more.type = 'button'; more.title = '更多操作'; more.append(icon('more', '#a3a39f', 16));
    more.onclick = (e) => {
      e.stopPropagation();
      for (const m of document.querySelectorAll('.dc .menu')) m.remove();
      const menu = el('div', 'menu');
      const cp = el('button', '', '复制设备 ID'); cp.type = 'button'; cp.onclick = () => { menu.remove(); copy(d.device_id, '设备 ID'); };
      menu.append(cp);
      if (!revoked) {
        const rv = el('button', 'bad', '吊销设备'); rv.type = 'button';
        rv.onclick = async () => {
          menu.remove();
          if (!confirm(`吊销设备「${d.name}」？吊销后设备需要重新配对。`)) return;
          try { await api('POST', '/lmbp/v1/tenant/devices/' + encodeURIComponent(d.device_id) + '/revoke'); toast('已吊销'); refresh(); }
          catch (err) { toast(describe(err.code, err.message), true); }
        };
        menu.append(rv);
      }
      menu.onclick = (ev) => ev.stopPropagation();
      card.append(menu);
    };
    nm.append(more);
    const idl = el('div', 'idl', L.shortId(d.device_id)); idl.title = d.device_id;
    body.append(nm, idl);
    if ((d.models || []).length) {
      const ms = el('div', 'ms');
      for (const m of d.models) {
        const s = el('span', '', (d.model_names || {})[m] || m); s.title = m;
        for (const c of (d.model_capabilities || {})[m] || []) s.append(el('i', '', c));
        ms.append(s);
      }
      body.append(ms);
    }
    card.append(ic, body);
    return card;
  }
  function renderDevices(devs) {
    const active = devs.filter((d) => d.status === 'active');
    const online = active.filter((d) => d.online);
    const rest = devs.filter((d) => !(d.status === 'active' && d.online));
    $('devCount').textContent = `已配对 ${active.length} 台，在线 ${online.length} 台`;
    // rail indicator
    $('devDot').className = 'dot' + (online.length ? '' : ' off');
    $('devTitle').textContent = online.length ? `${online.length} 台设备在线` : active.length ? '设备离线' : '未连接设备';
    $('devSub').textContent = online.length ? online.map((d) => d.name).join(' · ') : active.length ? '请在电脑上启动 Avora' : '点此配对新设备';
    const box = $('devices'); box.textContent = '';
    if (!devs.length) box.append(el('div', 'none', '还没有配对的设备'));
    else if (!online.length) box.append(el('div', 'none', '当前没有在线设备'));
    for (const d of online) box.append(deviceCard(d));
    if (rest.length) {
      const grp = el('div', 'revoked-group');
      const btn = el('button', 'revoked-toggle' + (showRevoked ? ' open' : '')); btn.type = 'button';
      btn.append(icon('chevr', '#8a8a86', 14), document.createTextNode('离线和已吊销'), el('span', '', `(${rest.length})`), el('span', 'sp'),
        el('span', '', rest[0].name + (rest.length > 1 ? ' 等' : '')));
      btn.children[1].style.color = '#a3a39f'; btn.lastChild.style.cssText = 'font-size:12px;color:#a3a39f';
      const list = el('div', 'revoked-list' + (showRevoked ? '' : ' hidden'));
      for (const d of rest) list.append(deviceCard(d));
      btn.onclick = () => { showRevoked = !showRevoked; list.classList.toggle('hidden', !showRevoked); btn.classList.toggle('open', showRevoked); };
      grp.append(btn, list); box.append(grp);
    }
  }
  $('devInd').onclick = () => {
    if (!devices.some((d) => d.status === 'active')) { clearPairMsg(); openPairModal(); return; }
    $('devModal').classList.remove('hidden');
  };
  $('closeDevModal').onclick = $('doneDevModal').onclick = () => closeModal('devModal');

  function deviceName(modelId) {
    const m = models.find((x) => x.id === modelId);
    if (m && m.owned_by) return m.owned_by;
    const d = devices.find((x) => x.device_id === String(modelId || '').split('/')[0]);
    return d ? d.name : '';
  }
  function renderModels(list) {
    models = list;
    const sel = $('model'), prev = sel.value || (cur && cur.model) || ''; sel.textContent = '';
    if (!list.length) { const o = el('option', '', '（没有在线模型）'); o.value = ''; sel.append(o); }
    for (const m of list) { const o = el('option', '', L.shortModel(m) + (m.owned_by ? ' · ' + m.owned_by : '')); o.value = m.id; o.title = m.id; sel.append(o); }
    if (list.some((m) => m.id === prev)) sel.value = prev;
    else if (prev && busy === null && cur && cur.turns.length) {
      // Keep the conversation's model selectable so the user sees DEVICE_OFFLINE instead of a silent switch.
      const o = el('option', '', L.shortModel(prev) + '（已离线）'); o.value = prev; sel.prepend(o); sel.value = prev;
    }
    renderChip();
  }
  function renderChip() {
    const id = $('model').value, m = models.find((x) => x.id === id);
    $('chipDot').className = 'dot' + (m ? '' : ' off');
    $('chipName').textContent = id ? L.shortModel(m || id) : '没有在线模型';
    $('chipDev').textContent = id ? deviceName(id) : '';
    $('chip').title = id || '';
  }
  $('model').onchange = () => { renderChip(); if (cur) cur.model = $('model').value; };
  setInterval(refresh, 1500);

  // ---- attachments ----
  $('pick').onclick = () => $('file').click();
  $('file').onchange = () => {
    const f = $('file').files[0]; $('file').value = '';
    if (!f) return;
    if (f.size > 20 << 20) return toast(ERR.PAYLOAD_TOO_LARGE, true);
    const r = new FileReader();
    r.onload = () => { attachment = { dataURL: r.result, name: f.name, size: f.size }; renderAtt(); };
    r.readAsDataURL(f);
  };
  function renderAtt() {
    const a = $('attInfo'); a.textContent = '';
    if (!attachment) return;
    const img = new Image(); img.src = attachment.dataURL; img.alt = attachment.name;
    const x = el('button', '', '移除'); x.type = 'button'; x.onclick = () => { attachment = null; renderAtt(); };
    a.append(img, el('span', '', `${attachment.name}（${(attachment.size / 1024).toFixed(1)} KiB）`), x);
  }

  // ---- history (localStorage, per tenant + user) ----
  const storeKey = () => `avora.chats.${auth.tenant}.${auth.user}`;
  function loadChats() { try { chats = JSON.parse(LS.getItem(storeKey()) || '[]'); } catch { chats = []; } }
  function saveChats() {
    const keep = chats.filter((c) => c.turns.length);
    try { LS.setItem(storeKey(), JSON.stringify(keep)); }
    catch { try { LS.setItem(storeKey(), JSON.stringify(keep.map(L.stripImages))); } catch { toast('本地存储已满，历史对话未保存', true); } }
  }
  function renderHist() {
    const nav = $('hist'); nav.textContent = '';
    for (const [label, list] of L.groupByDay(chats.filter((c) => c.turns.length))) {
      nav.append(el('div', 'hl', label));
      for (const c of list) {
        const b = el('button', 'hi' + (cur && c.id === cur.id ? ' cur' : '')); b.type = 'button'; b.title = c.title;
        b.append(el('span', '', c.title));
        const del = el('span', 'del'); del.title = '删除'; del.append(icon('trash', '#8a8a86', 13));
        del.onclick = (e) => {
          e.stopPropagation();
          if (!confirm(`删除对话「${c.title}」？`)) return;
          chats = chats.filter((x) => x.id !== c.id); saveChats();
          if (cur && cur.id === c.id) openChat(null); else renderHist();
        };
        b.append(del);
        b.onclick = () => { if (!busy) openChat(c.id); };
        nav.append(b);
      }
    }
  }
  function openChat(id) {
    if (busy) busy.abort();
    cur = chats.find((c) => c.id === id) || { id: 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), title: '新对话', updated: Date.now(), model: '', messages: [], turns: [] };
    if (!chats.includes(cur)) chats.push(cur);
    chats = chats.filter((c) => c === cur || c.turns.length);
    $('title').textContent = cur.title;
    const chat = $('chat'); chat.textContent = '';
    if (!cur.turns.length) chat.append(emptyState());
    for (const t of cur.turns) t.role === 'user' ? userTurn(t) : renderAnswer(answerShell(t), t);
    if (cur.model && [...$('model').options].some((o) => o.value === cur.model)) { $('model').value = cur.model; renderChip(); }
    $('input').placeholder = cur.turns.length ? '继续提问…' : '给本机模型发送消息…';
    renderHist(); scrollEnd(true);
  }
  function emptyState() {
    const e = el('div', 'empty'); e.id = 'empty';
    const l = el('div'); l.style.display = 'inline-flex'; l.append(logo(44, 13));
    e.append(l, el('h2', '', '今天想聊点什么？'), el('p', '', '配对一台电脑后，就能用它上面的模型对话'));
    return e;
  }
  $('newChat').onclick = () => openChat(null);

  // ---- rendering ----
  let stick = true;
  $('scroll').addEventListener('scroll', () => { const s = $('scroll'); stick = s.scrollHeight - s.scrollTop - s.clientHeight < 40; });
  function scrollEnd(force) { const s = $('scroll'); if (force || stick) s.scrollTop = s.scrollHeight; }

  function userTurn(t) {
    $('empty')?.remove();
    const w = el('div', 'uq turn user'), b = el('div', 'bubble', t.text);
    if (t.img) { const i = new Image(); i.src = t.img; i.alt = '附件'; b.append(i); }
    w.append(b); $('chat').append(w); scrollEnd();
  }
  function inline(parent, nodes) {
    for (const n of nodes) {
      if (n.t === 'text') parent.append(document.createTextNode(n.v));
      else if (n.t === 'code') parent.append(el('code', 'i', n.v));
      else if (n.t === 'b') inline(parent.appendChild(el('strong')), n.c);
      else if (n.t === 'i') inline(parent.appendChild(el('em')), n.c);
      else if (n.t === 'a') { const a = el('a'); a.href = n.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; inline(a, n.c); parent.append(a); }
    }
  }
  function codeBlock(b) {
    const w = el('div', 'cb'), h = el('div', 'bh');
    const cp = el('button', 'cp'); cp.type = 'button'; cp.append(icon('copy', '#4a4a47', 13), document.createTextNode('复制'));
    cp.onclick = () => copy(b.text, '代码');
    h.append(document.createTextNode(b.lang || 'text'), el('span', 'sp'), cp);
    const pre = el('pre'), code = el('code');
    for (const t of L.highlight(b.text, b.lang)) code.append(t.c ? el('span', t.c, t.v) : document.createTextNode(t.v));
    pre.append(code); w.append(h, pre);
    return w;
  }
  function renderMarkdown(box, text) {
    box.textContent = '';
    for (const b of L.parseMarkdown(text)) {
      if (b.t === 'p') inline(box.appendChild(el('p')), b.inl);
      else if (b.t === 'h') inline(box.appendChild(el('h' + b.level)), b.inl);
      else if (b.t === 'hr') box.append(el('hr'));
      else if (b.t === 'quote') inline(box.appendChild(el('blockquote')), b.inl);
      else if (b.t === 'code') box.append(codeBlock(b));
      else if (b.t === 'list') {
        const l = el(b.ordered ? 'ol' : 'ul'); if (b.ordered && b.start !== 1) l.start = b.start;
        for (const it of b.items) inline(l.appendChild(el('li')), it.inl);
        box.append(l);
      }
    }
  }
  function addCursor(box) {
    let n = box.lastElementChild;
    if (n && n.classList.contains('cb')) n = n.querySelector('code');
    else while (n && n.lastElementChild && /^(OL|UL|LI|BLOCKQUOTE)$/.test(n.tagName)) n = n.lastElementChild;
    (n || box).append(el('span', 'cursor'));
  }

  function answerShell(a) {
    $('empty')?.remove();
    const w = el('div', 'ans turn assistant');
    const h = el('div', 'ah');
    const lg = el('span', 'logo-s'); lg.append(logo(24, 7));
    const who = el('span', 'who'); who.dataset.tip = a.modelId || '';
    who.append(el('b', '', L.shortModel(a.modelId)), el('span', 'on', a.device ? '· ' + a.device : ''));
    h.append(lg, who);
    const stepsBox = el('div'), body = el('div', 'md bubble'), tail = el('div');
    w.append(h, stepsBox, body, tail);
    $('chat').append(w);
    return { w, stepsBox, body, tail, foldSet: false, fold: true };
  }
  function stepRow(r, a) {
    const row = el('div', 'st');
    const n = el('span', 'n ' + r.state);
    if (r.state === 'ok') n.append(icon('check', '#fff', 10, 3.4));
    if (r.state === 'bad') n.append(icon('x', '#fff', 9, 3.4));
    const txt = el('span');
    const d = (s) => el('span', 'd', s);
    switch (r.k) {
      case 'dispatch': txt.append(document.createTextNode(r.state === 'live' ? '正在派发到 ' : '已派发到 '), el('b', '', r.device)); break;
      case 'first': txt.append(document.createTextNode(L.shortModel(a.modelId) + (r.state === 'live' ? ' 等待首字…' : ' 开始生成 '))); if (r.ttft != null) txt.append(d('· 首字 ' + Math.round(r.ttft) + ' ms')); break;
      case 'tools': txt.append(document.createTextNode('模型请求调用工具 '), d('· finish: tool_calls')); break;
      case 'gen': txt.append(document.createTextNode('正在生成…')); break;
      case 'done': txt.append(document.createTextNode('生成完成 '), d('· finish: ' + r.finish)); break;
      case 'stopped': txt.append(document.createTextNode('已手动停止，网关已向设备发送取消')); break;
      case 'error': txt.append(document.createTextNode('出错 '), d('· ' + (r.code || ''))); break;
    }
    row.append(n, txt);
    if (r.at != null) row.append(el('span', 'tm', L.secs(r.at)));
    return row;
  }
  function toolCard(t) {
    const card = el('div', 'tool');
    const h = el('button', 'th'); h.type = 'button';
    h.append(icon('wrench', '#5f5f5b', 14), el('span', 'fn', t.name || '(未命名工具)'), el('span', 'tag req', '模型请求'), el('span', 'sp'), el('span', 'cid', L.shortId(t.id, 8, 0).replace(/…$/, '') || ''), icon('chev', '#8a8a86', 13));
    h.lastChild.previousSibling.title = t.id || '';
    h.onclick = () => card.classList.toggle('fold');
    const pre = el('pre');
    for (const k of L.highlight(L.prettyArgs(t.args || ''), 'json')) pre.append(k.c ? el('span', k.c, k.v) : document.createTextNode(k.v));
    card.append(h, pre);
    return card;
  }
  // renderAnswer draws (or redraws) one assistant turn from its record.
  function renderAnswer(v, a) {
    const live = a.state === 'live';
    v.w.dataset.state = live ? '' : a.state;
    if (!live) v.w.dataset.state = a.state; else delete v.w.dataset.state;
    v.stepsBox.textContent = '';
    if (!v.foldSet) v.fold = !((a.tools || []).length || a.state === 'error');
    if (live && v.fold) {
      const pill = el('button', 'live-line'); pill.type = 'button';
      pill.append(el('span', 'spin'), document.createTextNode('正在生成'));
      if (a.dispatchedAt != null) pill.append(el('span', 'sep', '·'), document.createTextNode('已派发到 ' + (a.device || '设备')));
      if (a.firstAt != null) pill.append(el('span', 'sep', '·'), document.createTextNode('首字 ' + Math.round(a.firstAt) + ' ms'));
      pill.append(icon('chev', '#8a8a86', 13));
      pill.onclick = () => { v.fold = false; v.foldSet = true; renderAnswer(v, a); };
      v.stepsBox.append(pill);
    } else {
      const box = el('div', 'steps' + (v.fold ? ' fold' : ''));
      const sh = el('button', 'sh'); sh.type = 'button';
      if (live) sh.append(el('span', 'spin'), el('b', '', '正在生成'));
      else if (a.state === 'done') sh.append(icon('check', '#0f8f80', 15, 2.4), el('b', '', '已完成'));
      else if (a.state === 'stopped') sh.append(icon('square', '#8a8a86', 15), el('b', '', '已停止'));
      else sh.append(icon('alert', '#d64545', 15), el('b', '', '出错'));
      const sm = L.summary(a); if (sm.length) sh.append(el('span', 'm', '· ' + sm.join(' · ')));
      sh.append(el('span', 'sp'), icon(v.fold ? 'chev' : 'chevu', '#8a8a86', 15));
      sh.onclick = () => { v.fold = !v.fold; v.foldSet = true; renderAnswer(v, a); };
      const sb = el('div', 'sb');
      for (const r of L.steps(a)) {
        sb.append(stepRow(r, a));
        if (r.k === 'tools') for (const t of r.tools) sb.append(toolCard(t));
      }
      box.append(sh, sb); v.stepsBox.append(box);
    }
    if (a.text || live) { renderMarkdown(v.body, a.text); if (live) addCursor(v.body); }
    else v.body.textContent = a.state === 'stopped' ? '（已停止）' : (a.tools || []).length ? '' : '（无输出）';
    v.tail.textContent = '';
    if (a.error && a.state === 'error') { const e = el('div', 'err'); e.append(el('b', '', a.error.code), document.createTextNode(describe(a.error.code, a.error.message))); v.tail.append(e); }
    if (!live) {
      const act = el('div', 'act');
      const cp = el('button', 'ib'); cp.type = 'button'; cp.title = '复制回答'; cp.append(icon('copy', '#8a8a86', 15)); cp.onclick = () => copy(a.text || '', '回答');
      const mt = L.metrics(a);
      const info = el('button', 'ib'); info.type = 'button'; info.title = '显示/隐藏性能指标'; info.append(icon('info', '#5f5f5b', 15));
      const ml = el('span', 'mline');
      mt.forEach((p, i) => { if (i) ml.append(el('i', '', '·')); ml.append(document.createTextNode(p)); });
      for (const id of a.taskIds || []) { if (ml.childNodes.length) ml.append(el('i', '', '·')); const s = el('span', '', L.shortId(id, 13, 8)); s.title = id; ml.append(s); }
      info.onclick = () => ml.classList.toggle('hidden');
      act.append(cp, info); if (ml.childNodes.length) act.append(ml);
      v.tail.append(act);
    }
    scrollEnd();
  }

  // ---- chat ----
  function setBusy(ctrl) {
    busy = ctrl; $('send').classList.toggle('hidden', !!ctrl); $('stop').classList.toggle('hidden', !ctrl); $('input').disabled = !!ctrl;
  }
  $('stop').onclick = () => busy && busy.abort();
  const grow = () => { const t = $('input'); t.style.height = 'auto'; t.style.height = Math.min(t.scrollHeight, 200) + 'px'; };
  $('input').addEventListener('input', grow);
  $('input').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
  $('send').onclick = send;

  async function send() {
    const text = $('input').value.trim(), model = $('model').value;
    if (busy || (!text && !attachment)) return;
    if (!model) return toast('没有可用的模型：请先配对设备并确认它在线', true);
    const shown = text || '请描述这张图片。';
    const content = attachment ? [{ type: 'text', text: shown }, { type: 'image_url', image_url: { url: attachment.dataURL } }] : text;
    const userMsg = { role: 'user', content };
    const ut = { role: 'user', text: shown, img: attachment && attachment.dataURL };
    if (!cur.turns.length) { cur.title = L.titleOf(shown); $('title').textContent = cur.title; }
    cur.turns.push(ut); cur.model = model; cur.updated = Date.now();
    userTurn(ut);
    $('input').value = ''; grow(); attachment = null; renderAtt();
    $('input').placeholder = '继续提问…';
    const msgs = cur.messages.concat([userMsg]);
    const a = { role: 'assistant', modelId: model, model: L.shortModel(models.find((m) => m.id === model) || model), device: deviceName(model), state: 'live', text: '', tools: [], taskIds: [] };
    cur.turns.push(a); saveChats(); renderHist();
    const v = answerShell(a); stick = true; renderAnswer(v, a); scrollEnd(true);
    const ctrl = new AbortController(); setBusy(ctrl);
    const t0 = performance.now(), at = () => performance.now() - t0;
    let pending = false;
    const redraw = () => { if (pending) return; pending = true; requestAnimationFrame(() => { pending = false; if (a.state === 'live') renderAnswer(v, a); }); };
    let failed = null, rawTools = [];
    try {
      const res = await fetch('/v1/chat/completions', {
        method: 'POST', signal: ctrl.signal,
        headers: headers({ 'Content-Type': 'application/json' }), // no Idempotency-Key: 停止 must cancel at once (keyed tasks get a 30 s re-attach grace)
        body: JSON.stringify({ model, stream: true, messages: msgs }),
      });
      const tid = res.headers.get('X-Task-Id');
      if (tid) { a.taskIds.push(tid); a.dispatchedAt = at(); }
      if (!res.ok) { const e = await parseError(res); failed = e; if (e.status === 401) onUnauthorized(); }
      else {
        if (a.dispatchedAt == null) a.dispatchedAt = at();
        redraw();
        const rd = res.body.getReader(), dec = new TextDecoder(); let buf = '';
        for (;;) {
          const { value, done } = await rd.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const ev = buf.slice(0, i); buf = buf.slice(i + 2);
            const data = ev.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart()).join('\n');
            if (!data || data === '[DONE]') continue;
            let j; try { j = JSON.parse(data); } catch { continue; }
            if (j.error) { failed = new ApiError(0, j.error.code, j.error.message); continue; }
            const ch = (j.choices || [])[0] || {};
            const piece = ch.delta && ch.delta.content;
            if (piece) { if (a.firstAt == null) a.firstAt = at(); a.text += piece; redraw(); }
            if (ch.delta && ch.delta.tool_calls) { if (a.firstAt == null) a.firstAt = at(); L.mergeToolCalls(rawTools, ch.delta.tool_calls); a.tools = rawTools.filter(Boolean); redraw(); }
            if (ch.finish_reason) { a.finish = ch.finish_reason; if (ch.finish_reason === 'tool_calls') a.toolsAt = at(); }
            if (j.usage) a.usage = j.usage;
          }
        }
      }
    } catch (e) {
      if (e.name === 'AbortError') failed = { code: 'CANCELLED', message: '已手动停止', stopped: true };
      else failed = new ApiError(0, 'NETWORK', e.message);
    }
    a.endAt = at();
    a.state = failed ? (failed.stopped ? 'stopped' : 'error') : 'done';
    if (failed && !failed.stopped) a.error = { code: failed.code, message: failed.message };
    renderAnswer(v, a);
    // Keep the turn in history if anything was produced (a stopped partial answer counts).
    const reply = { role: 'assistant', content: a.text };
    if (a.tools.length) reply.tool_calls = a.tools.map((t) => ({ id: t.id, type: 'function', function: { name: t.name, arguments: t.args } }));
    if (a.text || a.tools.length || !failed) cur.messages = msgs.concat([reply]);
    cur.updated = Date.now(); saveChats(); renderHist();
    setBusy(null); $('input').focus();
  }

  // ---- boot ----
  const qs = new URLSearchParams(location.search);
  if (qs.get('user_code')) $('code').value = qs.get('user_code');
  if (qs.get('jkt')) { $('jkt').value = qs.get('jkt'); $('advBody').classList.remove('hidden'); $('advToggle').classList.add('open'); }
  if (qs.get('tenant')) $('tenant').value = qs.get('tenant');
  renderCode();
  const saved = SS.getItem('lmbp.auth');
  if (saved) login(JSON.parse(saved)).catch(() => logout());
})();
