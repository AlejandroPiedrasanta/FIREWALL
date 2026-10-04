'use strict';
/* MiniWall — lógica de la interfaz (sin dependencias externas). */

const TOKEN = new URLSearchParams(location.search).get('t') || '';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

async function api(path, body) {
  const r = await fetch('/api/' + path, {
    method: body ? 'POST' : 'GET',
    headers: { 'X-Token': TOKEN, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
  return r.json();
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function fmtBytes(b, dec) {
  b = Number(b) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  const d = dec ?? (i === 0 ? 0 : b < 10 ? 2 : b < 100 ? 1 : 0);
  return b.toFixed(d).replace('.', ',') + ' ' + u[i];
}
const fmtRate = b => fmtBytes(b) + '/s';
const pad = n => String(n).padStart(2, '0');
const MONTHS = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];
const DAYS = ['dom', 'lun', 'mar', 'mié', 'jue', 'vie', 'sáb'];

function fmtClock(t, secs) {
  const d = new Date(t * 1000);
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + (secs ? ':' + pad(d.getSeconds()) : '');
}
function fmtDate(t, time) {
  const d = new Date(t * 1000);
  return d.getDate() + ' ' + MONTHS[d.getMonth()] + (time ? ' ' + fmtClock(t) : '');
}
function ago(t) {
  if (!t) return '—';
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return 'ahora';
  if (s < 3600) return 'hace ' + Math.floor(s / 60) + ' min';
  if (s < 86400) return 'hace ' + Math.floor(s / 3600) + ' h';
  if (s < 86400 * 7) return 'hace ' + Math.floor(s / 86400) + ' d';
  return fmtDate(t);
}
const todayStr = () => { const d = new Date(); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); };
const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const letter = n => (String(n || '?').replace(/[^\p{L}\p{N}]/gu, '')[0] || '?').toUpperCase();
const countryName = cc => (window.WORLD && WORLD.labels[cc] && WORLD.labels[cc][2]) || cc || 'Desconocido';

function appIcon(path, name) {
  if (path) return `<img class="app-ico" src="/api/icon?t=${TOKEN}&p=${encodeURIComponent(path)}" data-letter="${esc(letter(name))}" alt="" draggable="false">`;
  return `<span class="app-ico letter">${esc(letter(name))}</span>`;
}
document.addEventListener('error', e => {
  const t = e.target;
  if (t.tagName === 'IMG' && t.classList.contains('app-ico')) {
    const s = document.createElement('span');
    s.className = 'app-ico letter';
    s.textContent = t.dataset.letter || '?';
    t.replaceWith(s);
  }
}, true);

function toast(title, text, level, actions, ms) {
  const el = document.createElement('div');
  el.className = 'toast ' + (level || 'info');
  el.innerHTML = `<div class="ttl">${esc(title)}</div><div class="txt">${esc(text)}</div>` + (actions ? `<div class="row" style="margin-top:8px">${actions}</div>` : '');
  $('#toasts').appendChild(el);
  const kill = () => el.remove();
  setTimeout(kill, ms || 6000);
  el.addEventListener('click', e => { if (!e.target.closest('button')) kill(); });
  while ($('#toasts').children.length > 3) $('#toasts').firstChild.remove();
}

/* Reutiliza filas por clave para que las listas no parpadeen al refrescar. */
function keyedRender(container, items, keyFn, html, after) {
  const old = new Map();
  for (const el of [...container.children]) if (el.dataset.k) old.set(el.dataset.k, el);
  let prev = null;
  const wrap = document.createElement(container.tagName === 'TBODY' ? 'tbody' : 'div');
  for (const it of items) {
    const k = keyFn(it);
    const h = html(it);
    let el = old.get(k);
    if (el) {
      old.delete(k);
      if (el._h !== h && !el.contains(document.activeElement)) { wrap.innerHTML = h; const n = wrap.firstElementChild; n.dataset.k = k; n._h = h; el.replaceWith(n); el = n; }
    } else {
      wrap.innerHTML = h;
      el = wrap.firstElementChild;
      el.dataset.k = k;
      el._h = h;
    }
    const want = prev ? prev.nextSibling : container.firstChild;
    if (el !== want) container.insertBefore(el, want);
    prev = el;
    if (after) after(el, it);
  }
  for (const el of old.values()) el.remove();
  [...container.children].forEach(el => { if (!el.dataset.k) el.remove(); });
}

/* ======================================================================
   Gráfico de áreas (tiempo real e historial)
   ====================================================================== */
class AreaChart {
  constructor(canvas, tip, opts = {}) {
    this.c = canvas; this.tip = tip; this.o = opts; this.pts = []; this.hover = -1;
    this.ctx = canvas.getContext('2d');
    new ResizeObserver(() => this.draw()).observe(canvas);
    if (tip) {
      canvas.addEventListener('mousemove', e => this.onMove(e));
      canvas.addEventListener('mouseleave', () => { this.hover = -1; this.tip.style.display = 'none'; this.draw(); });
      canvas.addEventListener('click', () => { if (this.hover >= 0 && this.o.onPick) this.o.onPick(this.pts[this.hover]); });
    }
  }
  set(pts, opts) { this.pts = pts || []; if (opts) Object.assign(this.o, opts); this.draw(); }
  layout() {
    const r = this.c.getBoundingClientRect();
    const minimal = this.o.minimal;
    return { w: r.width, h: r.height, l: minimal ? 0 : 62, r: minimal ? 0 : 10, t: minimal ? 22 : 10, b: minimal ? 0 : 24 };
  }
  scale(max) {
    if (this.o.fixedMax) return { max: this.o.fixedMax, step: this.o.fixedMax / 4 };
    if (max <= 0) max = 1024;
    const unit = this.o.percent ? 1 : Math.pow(1024, Math.max(0, Math.floor(Math.log(max) / Math.log(1024))));
    const v = max / unit;
    const raw = v / 4;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const step = ([1, 2, 2.5, 5, 10].find(m => m * mag >= raw) || 10) * mag * unit;
    return { max: Math.ceil(max / step) * step, step };
  }
  draw() {
    const { c, ctx } = this;
    const L = this.layout();
    const dpr = devicePixelRatio || 1;
    if (L.w < 10 || L.h < 10) return;
    c.width = Math.round(L.w * dpr); c.height = Math.round(L.h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, L.w, L.h);
    const pts = this.pts;
    const keys = this.o.keys || ['a', 'b'];
    const colors = this.o.colors || [cssVar('--down'), cssVar('--up')];
    let max = 0;
    for (const p of pts) for (const k of keys) max = Math.max(max, p[k] || 0);
    const sc = this.scale(max);
    const W = L.w - L.l - L.r, H = L.h - L.t - L.b;
    const t0 = this.o.from ?? (pts.length ? pts[0].t : 0);
    const t1 = this.o.to ?? (pts.length ? pts[pts.length - 1].t : 1);
    const X = t => L.l + (t1 > t0 ? (t - t0) / (t1 - t0) : 0) * W;
    const Y = v => L.t + H - (v / sc.max) * H;
    this.geo = { X, Y, L, t0, t1 };

    // cuadrícula y ejes
    ctx.font = '11px "Segoe UI", system-ui, sans-serif';
    ctx.fillStyle = cssVar('--faint'); ctx.strokeStyle = cssVar('--grid'); ctx.lineWidth = 1;
    if (!this.o.minimal) {
      ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
      for (let v = 0; v <= sc.max + 1e-9; v += sc.step) {
        const y = Math.round(Y(v)) + .5;
        ctx.beginPath(); ctx.moveTo(L.l, y); ctx.lineTo(L.w - L.r, y); ctx.stroke();
        ctx.fillText(this.o.percent ? Math.round(v) + ' %' : fmtBytes(v, v < 1024 ? 0 : undefined) + (this.o.amount ? '' : '/s'), L.l - 8, y);
      }
      ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      const span = t1 - t0, n = Math.max(2, Math.floor(W / 110));
      for (let i = 0; i <= n; i++) {
        const t = t0 + span * i / n;
        let s = span <= 600 ? fmtClock(t, true) : span <= 86400 * 1.01 ? fmtClock(t) : fmtDate(t, span <= 86400 * 3);
        const x = X(t);
        ctx.fillText(s, Math.min(Math.max(x, L.l + 24), L.w - L.r - 24), L.h - L.b + 6);
      }
    }
    if (!pts.length) {
      ctx.fillStyle = cssVar('--faint'); ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText(this.o.empty || 'Sin datos todavía', L.l + W / 2, L.t + H / 2);
      return;
    }
    // áreas
    keys.forEach((k, ki) => {
      const col = colors[ki];
      const g = ctx.createLinearGradient(0, L.t, 0, L.t + H);
      g.addColorStop(0, col + (ki ? '55' : '66')); g.addColorStop(1, col + '05');
      ctx.beginPath();
      ctx.moveTo(X(pts[0].t), Y(0));
      for (const p of pts) ctx.lineTo(X(p.t), Y(p[k] || 0));
      ctx.lineTo(X(pts[pts.length - 1].t), Y(0));
      ctx.closePath(); ctx.fillStyle = g; ctx.fill();
      ctx.beginPath();
      pts.forEach((p, i) => i ? ctx.lineTo(X(p.t), Y(p[k] || 0)) : ctx.moveTo(X(p.t), Y(p[k] || 0)));
      ctx.strokeStyle = col; ctx.lineWidth = 1.6; ctx.lineJoin = 'round'; ctx.stroke();
    });
    // marca de selección (máquina del tiempo)
    if (this.o.mark) {
      const x = X(this.o.mark.t), x2 = X(this.o.mark.t + this.o.mark.len);
      ctx.fillStyle = cssVar('--text') + '14';
      ctx.fillRect(x, L.t, Math.max(2, x2 - x), H);
    }
    if (this.hover >= 0 && pts[this.hover]) {
      const p = pts[this.hover], x = Math.round(X(p.t)) + .5;
      ctx.strokeStyle = cssVar('--muted'); ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x, L.t); ctx.lineTo(x, L.t + H); ctx.stroke(); ctx.setLineDash([]);
      keys.forEach((k, ki) => {
        ctx.beginPath(); ctx.arc(x, Y(p[k] || 0), 3.5, 0, Math.PI * 2);
        ctx.fillStyle = colors[ki]; ctx.fill(); ctx.strokeStyle = cssVar('--bg'); ctx.lineWidth = 1.5; ctx.stroke();
      });
    }
  }
  onMove(e) {
    if (!this.pts.length || !this.geo) return;
    const r = this.c.getBoundingClientRect();
    const mx = e.clientX - r.left;
    let best = 0, bd = 1e9;
    this.pts.forEach((p, i) => { const d = Math.abs(this.geo.X(p.t) - mx); if (d < bd) { bd = d; best = i; } });
    this.hover = best;
    this.draw();
    const p = this.pts[best];
    this.tip.innerHTML = this.o.tipFmt ? this.o.tipFmt(p) : '';
    this.tip.style.display = 'block';
    const tw = this.tip.offsetWidth;
    let x = this.geo.X(p.t) + 14;
    if (x + tw > r.width - 4) x = this.geo.X(p.t) - tw - 14;
    this.tip.style.left = x + 'px';
    this.tip.style.top = '14px';
    this.c.style.cursor = this.o.onPick ? 'pointer' : 'default';
  }
}

/* Gráfico de barras apiladas (uso por día). */
class BarChart {
  constructor(canvas, tip) {
    this.c = canvas; this.tip = tip; this.data = []; this.hover = -1; this.ctx = canvas.getContext('2d');
    new ResizeObserver(() => this.draw()).observe(canvas);
    canvas.addEventListener('mousemove', e => this.onMove(e));
    canvas.addEventListener('mouseleave', () => { this.hover = -1; tip.style.display = 'none'; this.draw(); });
  }
  set(data) { this.data = data; this.draw(); }
  draw() {
    const { c, ctx } = this, r = c.getBoundingClientRect(), dpr = devicePixelRatio || 1;
    if (r.width < 10) return;
    c.width = r.width * dpr; c.height = r.height * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, r.width, r.height);
    const L = { l: 62, r: 8, t: 8, b: 22 }, W = r.width - L.l - L.r, H = r.height - L.t - L.b;
    const max = Math.max(1024, ...this.data.map(d => d.rx + d.tx));
    const sc = AreaChart.prototype.scale.call({ o: {} }, max);
    ctx.font = '11px "Segoe UI", system-ui, sans-serif'; ctx.strokeStyle = cssVar('--grid'); ctx.fillStyle = cssVar('--faint');
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    for (let v = 0; v <= sc.max + 1e-9; v += sc.step) {
      const y = Math.round(L.t + H - v / sc.max * H) + .5;
      ctx.beginPath(); ctx.moveTo(L.l, y); ctx.lineTo(r.width - L.r, y); ctx.stroke();
      ctx.fillText(fmtBytes(v, v < 1024 ? 0 : undefined), L.l - 8, y);
    }
    const n = this.data.length || 1, bw = W / n, gap = Math.min(10, bw * .25);
    this.geo = { L, bw };
    const every = Math.ceil(n / Math.max(1, Math.floor(W / 46)));
    this.data.forEach((d, i) => {
      const x = L.l + i * bw + gap / 2, w = Math.max(1, bw - gap);
      const hr = d.rx / sc.max * H, ht = d.tx / sc.max * H;
      ctx.globalAlpha = this.hover === -1 || this.hover === i ? 1 : .55;
      ctx.fillStyle = cssVar('--down'); roundRect(ctx, x, L.t + H - hr, w, hr, 3);
      ctx.fillStyle = cssVar('--up'); roundRect(ctx, x, L.t + H - hr - ht, w, ht, 3);
      ctx.globalAlpha = 1;
      if (i % every === 0) { ctx.fillStyle = cssVar('--faint'); ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.fillText(d.label, x + w / 2, L.t + H + 6); }
    });
  }
  onMove(e) {
    if (!this.geo || !this.data.length) return;
    const r = this.c.getBoundingClientRect(), i = Math.floor((e.clientX - r.left - this.geo.L.l) / this.geo.bw);
    if (i < 0 || i >= this.data.length) { this.tip.style.display = 'none'; return; }
    if (i !== this.hover) { this.hover = i; this.draw(); }
    const d = this.data[i];
    this.tip.innerHTML = `<b>${esc(d.title)}</b><br><span class="down">↓ ${fmtBytes(d.rx)}</span> &nbsp; <span class="up">↑ ${fmtBytes(d.tx)}</span>`;
    this.tip.style.display = 'block';
    let x = this.geo.L.l + (i + 1) * this.geo.bw + 6;
    if (x + this.tip.offsetWidth > r.width) x = this.geo.L.l + i * this.geo.bw - this.tip.offsetWidth - 6;
    this.tip.style.left = x + 'px'; this.tip.style.top = '10px';
  }
}
function roundRect(ctx, x, y, w, h, rad) {
  if (h <= 0) return;
  rad = Math.min(rad, h / 2, w / 2);
  ctx.beginPath(); ctx.moveTo(x, y + h); ctx.lineTo(x, y + rad); ctx.quadraticCurveTo(x, y, x + rad, y);
  ctx.lineTo(x + w - rad, y); ctx.quadraticCurveTo(x + w, y, x + w, y + rad); ctx.lineTo(x + w, y + h); ctx.closePath(); ctx.fill();
}

/* ======================================================================
   Estado global
   ====================================================================== */
const S = {
  tab: 'grafico', range: 'live', tmDay: '', last: null, hist: null, mark: null,
  fwFilter: 'all', fwSearch: '', usePeriod: 'week', useOffset: 0, mapMode: 'now', mapCountry: '',
  alertKinds: '', lastAlertId: -1, cfg: null, conns: null, usageToday: null, mini: false,
};

const rateTip = p => `<div class="muted small">${p.label || fmtClock(p.t, true)}</div><span class="down">↓ ${fmtRate(p.a)}</span> &nbsp; <span class="up">↑ ${fmtRate(p.b)}</span>` + (p.total != null ? `<div class="muted small">Total: ${fmtBytes(p.total)}</div>` : '');

const mainChart = new AreaChart($('#mainChart'), $('#mainTip'), { tipFmt: rateTip });
const miniChart = new AreaChart($('#miniChart'), null, { minimal: true });
const useChart = new BarChart($('#useChart'), $('#useTip'));
const cpuChart = new AreaChart($('#cpuChart'), null, { percent: true, fixedMax: 100, keys: ['a'] });
const memChart = new AreaChart($('#memChart'), null, { percent: true, fixedMax: 100, keys: ['a'] });

/* ======================================================================
   Navegación
   ====================================================================== */
function showTab(tab) {
  S.tab = tab;
  $$('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  $$('section.view').forEach(s => s.classList.toggle('active', s.id === 'v-' + tab));
  refreshTab(true);
}
document.addEventListener('click', e => {
  const t = e.target.closest('[data-tab]');
  if (t) showTab(t.dataset.tab);
});

const refreshers = {
  grafico: () => { if (S.range !== 'live') loadHistory(); },
  firewall: () => renderFirewall(),
  uso: () => loadUsage(),
  mapa: () => loadConns(),
  red: () => loadLan(),
  seguridad: () => loadSecurity(),
  sistema: () => loadSystem(),
  alertas: () => loadAlerts(),
  ajustes: () => loadConfig(),
};
const intervals = { mapa: 3000, red: 5000, seguridad: 3000, sistema: 1000, uso: 30000, grafico: 60000 };
let tabTimer = null;
function refreshTab(now) {
  clearTimeout(tabTimer);
  const f = refreshers[S.tab];
  if (f && now) f();
  const iv = intervals[S.tab];
  if (iv) tabTimer = setTimeout(() => { if (refreshers[S.tab]) refreshers[S.tab](); refreshTab(false); }, iv);
}

/* ======================================================================
   Estado en vivo (cada segundo)
   ====================================================================== */
async function poll() {
  try {
    const s = await api('state');
    onState(s);
  } catch (e) { /* la ventana puede estar cerrándose */ }
  setTimeout(poll, 1000);
}

function onState(s) {
  const first = !S.last;
  S.last = s;
  if (first) $('#ver').textContent = s.version || '';
  document.documentElement.dataset.theme = s.theme || 'oscuro';
  const secs = s.secs || [];
  const cur = secs.length ? secs[secs.length - 1] : [0, 0, 0];
  $('#sbDown').textContent = fmtRate(cur[1]);
  $('#sbUp').textContent = fmtRate(cur[2]);
  $('#gDown').textContent = fmtRate(cur[1]);
  $('#gUp').textContent = fmtRate(cur[2]);
  $('#sbToday').textContent = '↓ ' + fmtBytes(s.todayRx) + '  ↑ ' + fmtBytes(s.todayTx);
  $('#sbConns').textContent = s.conns;
  $('#sbHosts').textContent = s.hosts;
  $('#sbProfile').textContent = s.profile;
  $$('#modeSeg button').forEach(b => { b.classList.toggle('on', b.dataset.mode === s.mode); b.classList.toggle('block', b.dataset.mode === 'bloquear'); });
  const warns = [];
  if (!s.etw) warns.push(`<span class="pill warn" title="${esc(s.etwErr || '')}">Tráfico por app no disponible</span>`);
  if (s.fwErr) warns.push(`<span class="pill danger" title="${esc(s.fwErr)}">Error del firewall</span>`);
  if (s.snoozed) warns.push(`<span class="pill">Alertas silenciadas</span>`);
  $('#sbWarn').innerHTML = warns.join(' ');
  const badge = $('#badge');
  badge.textContent = s.unread > 99 ? '99+' : s.unread;
  badge.classList.toggle('hidden', !s.unread);

  // datos del gráfico en vivo (últimos 5 minutos) y minigráfico
  const live = secs.slice(-300).map(x => ({ t: x[0], a: x[1], b: x[2] }));
  if (S.range === 'live' && S.tab === 'grafico') {
    const now = s.now;
    mainChart.set(live, { from: now - 299, to: now, mark: null, onPick: null, empty: 'Recopilando datos…' });
  }
  if (S.mini) {
    miniChart.set(secs.slice(-120).map(x => ({ t: x[0], a: x[1], b: x[2] })), { from: s.now - 119, to: s.now });
    $('#miniDown').textContent = '↓ ' + fmtRate(cur[1]);
    $('#miniUp').textContent = '↑ ' + fmtRate(cur[2]);
  }

  if (S.tab === 'grafico') renderGraphLists();
  if (S.tab === 'firewall') renderFirewall();

  // notificaciones dentro de la app
  if (s.latest) {
    if (first || S.lastAlertId < 0) S.lastAlertId = s.latest.id;
    else if (s.latest.id > S.lastAlertId) {
      S.lastAlertId = s.latest.id;
      const al = s.latest;
      const app = al.kind === 'ask' && s.apps.find(a => a.key === al.key && a.pending);
      toast(al.title, al.text.split('\n')[0], al.level,
        app ? `<button class="btn sm primary" data-act="ask-allow" data-key="${esc(al.key)}">Permitir</button><button class="btn sm danger" data-act="ask-block" data-key="${esc(al.key)}">Bloquear</button>` : '',
        app ? 20000 : 6000);
      if (S.tab === 'alertas') loadAlerts();
    }
  }
}

/* ======================================================================
   Pestaña Gráfico
   ====================================================================== */
function appRow(a, rx, tx, max, showRate) {
  const tot = rx + tx;
  const sub = showRate ? `<span class="down">↓ ${fmtRate(rx)}</span> · <span class="up">↑ ${fmtRate(tx)}</span>` : `${fmtBytes(tot)} · <span class="down">↓ ${fmtBytes(rx)}</span> <span class="up">↑ ${fmtBytes(tx)}</span>`;
  const wd = max ? (rx / max * 100) : 0, wu = max ? (tx / max * 100) : 0;
  return `<div class="item" title="${esc(a.path || a.key)}">${appIcon(a.path, a.name)}<div class="main"><div class="row"><span class="name grow">${esc(a.name)}</span>${a.blocked ? '<span class="tag danger">bloqueada</span>' : ''}</div><div class="sub">${sub}</div><div class="bar"><i class="d" style="width:${wd}%"></i><i class="u" style="width:${wu}%"></i></div></div></div>`;
}

function renderGraphLists() {
  const s = S.last;
  if (!s) return;
  const byKey = new Map(s.apps.map(a => [a.key, a]));
  if (S.range === 'live') {
    $('#appsTitle').textContent = 'Apps usando la red ahora';
    const act = s.apps.filter(a => a.rxRate + a.txRate > 0 || a.conns > 0).slice(0, 12);
    const max = Math.max(1, ...act.map(a => a.rxRate + a.txRate));
    $('#appsHint').textContent = act.length + ' activas';
    if (!act.length) $('#liveApps').innerHTML = '<div class="empty">Ninguna app está usando la red en este momento.</div>';
    else keyedRender($('#liveApps'), act, a => a.key, a => appRow(a, a.rxRate, a.txRate, max, true));
    $('#sideTitle').textContent = 'Más usadas hoy';
    const top = [...s.apps].filter(a => a.todayRx + a.todayTx > 0).sort((x, y) => (y.todayRx + y.todayTx) - (x.todayRx + x.todayTx)).slice(0, 10);
    const tmax = Math.max(1, ...top.map(a => a.todayRx + a.todayTx));
    if (!top.length) $('#sidePanel').innerHTML = `<div class="empty">${s.etw ? 'Aún no hay uso registrado hoy.' : 'El detalle por app requiere el monitor ETW (ejecuta MiniWall como administrador).'}</div>`;
    else keyedRender($('#sidePanel'), top, a => a.key, a => appRow(a, a.todayRx, a.todayTx, tmax, false));
  } else if (S.hist) {
    $('#appsTitle').textContent = S.tmDay ? 'Apps del ' + fmtDate(S.hist.from) : 'Apps en este periodo';
    const list = S.hist.apps || [];
    const max = Math.max(1, ...list.map(a => a.rx + a.tx));
    $('#appsHint').textContent = '';
    const items = list.slice(0, 12).map(u => Object.assign({}, byKey.get(u.key) || { key: u.key, name: u.name || u.key, path: u.key.includes('\\') ? u.key : '' }, { name: (byKey.get(u.key) || {}).name || u.name || u.key, _rx: u.rx, _tx: u.tx }));
    if (!items.length) $('#liveApps').innerHTML = '<div class="empty">Sin uso por app registrado en este periodo.</div>';
    else keyedRender($('#liveApps'), items, a => a.key, a => appRow(a, a._rx, a._tx, max, false));
  }
}

async function loadHistory() {
  const q = S.tmDay ? 'day=' + S.tmDay : 'range=' + S.range;
  try { S.hist = await api('history?' + q); } catch (e) { return; }
  const h = S.hist;
  const pts = (h.points || []).map(p => ({ t: p.t, a: p.rx / h.step, b: p.tx / h.step, total: p.rx + p.tx, label: h.step >= 3600 ? fmtDate(p.t, true) : (h.to - h.from > 86400 ? fmtDate(p.t, true) : fmtClock(p.t)) }));
  mainChart.set(pts, { from: h.from, to: h.to, mark: S.mark, onPick: pickHour, empty: 'No hay datos guardados en este periodo' });
  const stepTxt = h.step >= 3600 ? (h.step / 3600) + ' h' : (h.step / 60) + ' min';
  $('#chartInfo').textContent = (S.tmDay ? 'Máquina del tiempo · ' + S.tmDay : 'Historial') + ' · resolución ' + stepTxt + ' · clic para ver qué apps había en esa hora';
  renderGraphLists();
  if (!S.mark) {
    $('#sideTitle').textContent = 'Máquina del tiempo';
    $('#sidePanel').innerHTML = '<div class="empty">Haz clic en cualquier punto del gráfico para ver qué apps usaron la red en esa hora.</div>';
  }
}

async function pickHour(p) {
  const hr = Math.floor(p.t / 3600) * 3600;
  S.mark = { t: hr, len: 3600 };
  mainChart.set(mainChart.pts, { mark: S.mark });
  const apps = (await api('hour?t=' + hr).catch(() => null)) || [];
  const byKey = new Map((S.last?.apps || []).map(a => [a.key, a]));
  $('#sideTitle').textContent = `${fmtDate(hr)} · ${fmtClock(hr)}–${fmtClock(hr + 3600)}`;
  const max = Math.max(1, ...apps.map(a => a.rx + a.tx));
  $('#sidePanel').innerHTML = apps.length ? apps.map(u => {
    const a = byKey.get(u.key) || { key: u.key, name: u.name || u.key, path: u.key.includes('\\') ? u.key : '' };
    return appRow({ ...a, name: a.name || u.name }, u.rx, u.tx, max, false);
  }).join('') : '<div class="empty">No se registró uso por app en esa hora.</div>';
}

$('#rangeChips').addEventListener('click', e => {
  const b = e.target.closest('[data-range]');
  if (!b) return;
  S.range = b.dataset.range; S.tmDay = ''; S.mark = null; $('#tmDate').value = '';
  $$('#rangeChips .chip').forEach(c => c.classList.toggle('on', c === b));
  if (S.range === 'live') {
    $('#chartInfo').textContent = 'En vivo · 1 muestra por segundo';
    $('#liveApps').innerHTML = ''; $('#sidePanel').innerHTML = '';
    if (S.last) onState(S.last);
  } else loadHistory();
});
$('#tmDate').max = todayStr();
$('#tmDate').addEventListener('change', e => {
  S.tmDay = e.target.value; S.mark = null;
  if (!S.tmDay) { $('#rangeChips [data-range=live]').click(); return; }
  S.range = 'day';
  $$('#rangeChips .chip').forEach(c => c.classList.remove('on'));
  $('#liveApps').innerHTML = '';
  loadHistory();
});

/* ======================================================================
   Pestaña Firewall
   ====================================================================== */
function renderFirewall() {
  const s = S.last;
  if (!s) return;
  const sel = $('#profileSel');
  const opts = s.profiles.map(p => `<option${p === s.profile ? ' selected' : ''}>${esc(p)}</option>`).join('');
  if (sel._o !== opts) { sel.innerHTML = opts; sel._o = opts; }

  const pend = s.apps.filter(a => a.pending);
  keyedRender($('#askList'), pend, a => a.key, a => `<div class="ask">${appIcon(a.path, a.name)}<div class="grow" style="min-width:0"><div><b>${esc(a.name)}</b> quiere conectarse a Internet</div><div class="small muted ellipsis">${esc(a.path)}</div></div><button class="btn primary" data-act="ask-allow" data-key="${esc(a.key)}">Permitir</button><button class="btn danger" data-act="ask-block" data-key="${esc(a.key)}">Bloquear</button></div>`);

  const mc = {
    monitor: ['i-graph', 'ok', 'Modo Monitorizar', 'Todas las apps pueden conectarse salvo las que bloquees. Se te avisa cuando una app se conecta por primera vez.'],
    preguntar: ['i-shield', 'warn', 'Modo Preguntar antes de conectar', 'Las apps nuevas se bloquean al conectarse por primera vez hasta que decidas si permitirlas. Las apps de Windows se permiten automáticamente (configurable en Ajustes).'],
    bloquear: ['i-lock', 'danger', 'Modo Bloquear todo', 'El Firewall de Windows bloquea todo el tráfico saliente y entrante. Ninguna app puede conectarse a Internet.'],
  }[s.mode];
  const mh = `<div class="stat"><div class="ic ${mc[1]}"><svg><use href="#${mc[0]}"/></svg></div><div><div class="t">${mc[2]} · perfil «${esc(s.profile)}»</div><div class="d">${mc[3]}</div></div></div>`;
  if ($('#modeCard')._h !== mh) { $('#modeCard').innerHTML = mh; $('#modeCard')._h = mh; }

  const q = S.fwSearch.toLowerCase();
  let list = s.apps.filter(a => a.canFw || a.conns || a.rxRate || a.todayRx);
  if (S.fwFilter === 'active') list = list.filter(a => a.active);
  if (S.fwFilter === 'blocked') list = list.filter(a => a.blocked);
  if (q) list = list.filter(a => a.name.toLowerCase().includes(q) || (a.path || '').toLowerCase().includes(q));
  const body = $('#fwBody');
  if (!list.length) { body.innerHTML = `<tr><td colspan="7" class="empty">${q ? 'Ninguna app coincide con la búsqueda.' : 'Todavía no se ha detectado ninguna app con actividad de red.'}</td></tr>`; return; }
  keyedRender(body, list.slice(0, 250), a => a.key, a => `<tr>
    <td>${appIcon(a.path, a.name)}</td>
    <td style="max-width:420px"><div class="row" style="gap:6px"><b class="ellipsis">${esc(a.name)}</b>${a.system ? '<span class="tag">sistema</span>' : ''}${a.active ? '<span class="dot" title="Activa ahora"></span>' : ''}</div><div class="small faint ellipsis" title="${esc(a.path)}">${esc(a.path || 'Sin ejecutable propio')}</div></td>
    <td class="r num down">${a.rxRate ? fmtRate(a.rxRate) : '—'}</td>
    <td class="r num up">${a.txRate ? fmtRate(a.txRate) : '—'}</td>
    <td class="r num">${a.todayRx + a.todayTx ? fmtBytes(a.todayRx + a.todayTx) : '—'}</td>
    <td class="r num">${a.conns || '—'}</td>
    <td class="r">${a.canFw ? `<label class="row" style="justify-content:flex-end;gap:8px;cursor:pointer"><span class="small ${a.blocked ? 'danger' : 'muted'}">${a.blocked ? 'Bloqueada' : 'Permitida'}</span><span class="switch block"><input type="checkbox" data-act="toggle-block" data-key="${esc(a.key)}"${a.blocked ? ' checked' : ''}><span></span></span></label>` : '<span class="small faint">—</span>'}</td>
  </tr>`);
}
$('#fwFilter').addEventListener('click', e => {
  const b = e.target.closest('[data-f]'); if (!b) return;
  S.fwFilter = b.dataset.f; $$('#fwFilter .chip').forEach(c => c.classList.toggle('on', c === b)); renderFirewall();
});
$('#fwSearch').addEventListener('input', e => { S.fwSearch = e.target.value; renderFirewall(); });
$('#profileSel').addEventListener('change', e => act({ act: 'profile-switch', name: e.target.value }));

/* ======================================================================
   Pestaña Uso
   ====================================================================== */
function usageList(el, items, kind) {
  const max = Math.max(1, ...items.map(i => i.rx + i.tx));
  const byKey = new Map((S.last?.apps || []).map(a => [a.key, a]));
  el.innerHTML = items.length ? items.slice(0, 15).map(i => {
    let ico, name = i.name || i.key, sub = '';
    if (kind === 'app') { const a = byKey.get(i.key); name = a?.name || name; ico = appIcon(a?.path || (i.key.includes('\\') ? i.key : ''), name); }
    else if (kind === 'host') { ico = `<span class="cc">${esc(i.cc || '··')}</span>`; sub = i.name !== i.key ? i.key : ''; }
    else { ico = `<span class="cc">${esc(i.cc)}</span>`; name = countryName(i.cc); }
    return `<div class="item" title="${esc(i.key)}">${ico}<div class="main"><div class="row"><span class="name grow">${esc(name)}</span><span class="num small">${fmtBytes(i.rx + i.tx)}</span></div>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}<div class="bar"><i class="d" style="width:${i.rx / max * 100}%"></i><i class="u" style="width:${i.tx / max * 100}%"></i></div></div></div>`;
  }).join('') : '<div class="empty">Sin datos en este periodo.</div>';
}

async function loadUsage() {
  let u;
  try { u = await api(`usage?period=${S.usePeriod}&offset=${S.useOffset}`); } catch (e) { return; }
  const f = new Date(u.from + 'T00:00:00'), t = new Date(u.to + 'T00:00:00');
  const lbl = S.usePeriod === 'day' ? `${DAYS[f.getDay()]} ${f.getDate()} ${MONTHS[f.getMonth()]} ${f.getFullYear()}`
    : S.usePeriod === 'month' ? `${MONTHS[f.getMonth()]} ${f.getFullYear()}` : `${f.getDate()} ${MONTHS[f.getMonth()]} – ${t.getDate()} ${MONTHS[t.getMonth()]}`;
  $('#useLabel').textContent = lbl;
  $('#useRx').textContent = fmtBytes(u.rx);
  $('#useTx').textContent = fmtBytes(u.tx);
  $('#useTotal').textContent = fmtBytes(u.rx + u.tx);
  if (u.limitGB > 0) {
    const used = (u.periodRx + u.periodTx) / 1e9, pct = Math.min(100, used / u.limitGB * 100);
    $('#limitBody').innerHTML = `<div class="gauge"><span class="v num">${pct.toFixed(0)}%</span><span class="muted small">${used.toFixed(2).replace('.', ',')} de ${u.limitGB} GB</span></div><div class="meter"><i class="${pct >= 100 ? 'danger' : pct >= 80 ? 'warn' : ''}" style="width:${pct}%"></i></div><div class="small faint" style="margin-top:4px">El periodo termina el ${u.periodEnd}</div>`;
  } else $('#limitBody').innerHTML = '<div class="small muted" style="margin-top:6px">Sin límite. <a href="#" data-tab="ajustes" style="color:var(--accent)">Configurar</a></div>';

  if (S.usePeriod === 'day') {
    const h = await api('history?day=' + u.from).catch(() => null);
    const hours = Array.from({ length: 24 }, (_, i) => ({ rx: 0, tx: 0, label: pad(i), title: `${pad(i)}:00–${pad(i)}:59` }));
    for (const p of h?.points || []) { const hr = new Date(p.t * 1000).getHours(); hours[hr].rx += p.rx; hours[hr].tx += p.tx; }
    useChart.set(hours);
  } else {
    useChart.set(u.days.map(d => { const x = new Date(d.day + 'T00:00:00'); return { rx: d.rx, tx: d.tx, label: S.usePeriod === 'week' ? DAYS[x.getDay()] + ' ' + x.getDate() : String(x.getDate()), title: `${DAYS[x.getDay()]} ${x.getDate()} ${MONTHS[x.getMonth()]}` }; }));
  }
  usageList($('#useApps'), u.apps || [], 'app');
  usageList($('#useHosts'), u.hosts || [], 'host');
  usageList($('#useCountries'), u.countries || [], 'country');
}
$('#usePeriod').addEventListener('click', e => {
  const b = e.target.closest('[data-p]'); if (!b) return;
  S.usePeriod = b.dataset.p; S.useOffset = 0; $$('#usePeriod .chip').forEach(c => c.classList.toggle('on', c === b)); loadUsage();
});

/* ======================================================================
   Pestaña Mapa
   ====================================================================== */
let mapBuilt = false;
function buildMap() {
  if (mapBuilt || !window.WORLD) return;
  mapBuilt = true;
  const W = WORLD;
  let h = `<svg viewBox="0 0 ${W.w} ${W.h}" preserveAspectRatio="xMidYMid meet"><g id="mapLand">`;
  for (const cc in W.shapes) h += `<path class="c" data-cc="${cc}" d="${W.shapes[cc]}"/>`;
  h += '</g><g id="mapPts"></g></svg>';
  $('#mapWrap').innerHTML = h;
  const tip = $('#mapTip');
  $('#mapWrap').addEventListener('mousemove', e => {
    const el = e.target.closest('[data-cc]');
    if (!el) { tip.style.display = 'none'; return; }
    const cc = el.dataset.cc, d = S.mapData?.[cc];
    tip.innerHTML = `<b>${esc(countryName(cc))}</b>` + (d ? `<br>${d.hosts} hosts · ${d.conns} conexiones<br><span class="down">↓ ${fmtBytes(d.rx)}</span> <span class="up">↑ ${fmtBytes(d.tx)}</span>` : '<br><span class="muted">Sin conexiones</span>');
    const r = $('#mapWrap').parentElement.getBoundingClientRect();
    tip.style.display = 'block';
    tip.style.left = Math.min(e.clientX - r.left + 14, r.width - tip.offsetWidth - 6) + 'px';
    tip.style.top = (e.clientY - r.top + 14) + 'px';
  });
  $('#mapWrap').addEventListener('mouseleave', () => { tip.style.display = 'none'; });
  $('#mapWrap').addEventListener('click', e => {
    const el = e.target.closest('[data-cc]');
    S.mapCountry = el && S.mapCountry !== el.dataset.cc ? el.dataset.cc : '';
    renderMap();
  });
}

async function loadConns() {
  buildMap();
  try {
    S.conns = await api('conns');
    if (S.mapMode === 'today') S.usageToday = await api('usage?period=day&offset=0');
  } catch (e) { return; }
  renderMap();
}

function renderMap() {
  const c = S.conns;
  if (!c) return;
  const data = {};
  const hosts = (c.hosts || []).filter(h => S.mapMode === 'today' || h.conns > 0);
  if (S.mapMode === 'today' && S.usageToday) {
    for (const x of S.usageToday.countries || []) data[x.cc] = { rx: x.rx, tx: x.tx, conns: 0, hosts: 0 };
    for (const x of S.usageToday.hosts || []) if (x.cc && data[x.cc]) data[x.cc].hosts++;
  } else {
    for (const h of hosts) {
      if (!h.cc) continue;
      const d = data[h.cc] || (data[h.cc] = { rx: 0, tx: 0, conns: 0, hosts: 0 });
      d.rx += h.rx; d.tx += h.tx; d.conns += h.conns; d.hosts++;
    }
  }
  S.mapData = data;
  const metric = d => S.mapMode === 'today' ? d.rx + d.tx : d.conns + d.hosts;
  const max = Math.max(1, ...Object.values(data).map(metric));
  $$('#mapLand path').forEach(p => {
    const cc = p.dataset.cc, d = data[cc];
    p.classList.toggle('sel', cc === S.mapCountry);
    p.style.fill = d ? `color-mix(in srgb, var(--accent) ${Math.round(25 + 60 * Math.sqrt(metric(d) / max))}%, var(--land))` : '';
  });
  let pts = '';
  for (const cc in data) {
    const lb = WORLD.labels[cc];
    if (!lb) continue;
    const r = 2.2 + 4 * Math.sqrt(metric(data[cc]) / max);
    pts += `<circle class="pulse" cx="${lb[0]}" cy="${lb[1]}" r="${r}"/><circle class="pt" data-cc="${cc}" cx="${lb[0]}" cy="${lb[1]}" r="${r}"/>`;
  }
  $('#mapPts').innerHTML = pts;
  $('#mapSel').textContent = S.mapCountry ? 'Filtrando: ' + countryName(S.mapCountry) : Object.keys(data).length + ' países';
  $('[data-act="map-clear"]').classList.toggle('hidden', !S.mapCountry);

  let list;
  if (S.mapMode === 'today' && S.usageToday) list = (S.usageToday.hosts || []).map(h => ({ ip: h.key, name: h.name !== h.key ? h.name : '', cc: h.cc, rx: h.rx, tx: h.tx, apps: [] }));
  else list = hosts;
  if (S.mapCountry) list = list.filter(h => h.cc === S.mapCountry);
  $('#mapCount').textContent = list.length;
  keyedRender($('#mapHosts'), list.slice(0, 200), h => h.ip, h => `<div class="item"><span class="cc">${esc(h.cc || '··')}</span><div class="main"><div class="name">${esc(h.name || h.ip)}</div><div class="sub">${h.name ? esc(h.ip) + ' · ' : ''}${esc((h.apps || []).join(', ') || countryName(h.cc))}</div></div><div class="small num muted" style="text-align:right">${h.conns ? h.conns + ' conex.<br>' : ''}${fmtBytes(h.rx + h.tx)}</div></div>`);

  let conns = c.conns || [];
  if (S.mapCountry) conns = conns.filter(x => x.cc === S.mapCountry);
  $('#connBody').innerHTML = conns.length ? conns.slice(0, 400).map(x => `<tr><td><b>${esc(x.app)}</b></td><td><div>${esc(x.host || x.ip)}</div>${x.host ? `<div class="small faint mono">${esc(x.ip)}</div>` : ''}</td><td>${x.cc ? `<span class="cc">${esc(x.cc)}</span> <span class="small muted">${esc(countryName(x.cc))}</span>` : '<span class="faint small">Red local</span>'}</td><td class="num">${x.port}</td><td>${x.proto}</td><td class="small">${esc(x.state)}</td></tr>`).join('') : '<tr><td colspan="6" class="empty">Sin conexiones activas.</td></tr>';
}
$('#mapMode').addEventListener('click', e => {
  const b = e.target.closest('[data-m]'); if (!b) return;
  S.mapMode = b.dataset.m; $$('#mapMode .chip').forEach(c => c.classList.toggle('on', c === b)); loadConns();
});

/* ======================================================================
   Pestaña Red
   ====================================================================== */
async function loadLan() {
  let r;
  try { r = await api('lan'); } catch (e) { return; }
  const w = r.wifi, lvl = r.wifiLevel || 'info';
  const icCls = lvl === 'ok' ? 'ok' : lvl === 'danger' ? 'danger' : lvl === 'warn' ? 'warn' : '';
  $('#wifiCard').innerHTML = `<h3><svg width="16" height="16"><use href="#i-wifi"/></svg>Wi‑Fi y detección de gemelos malvados</h3>
    <div class="stat" style="margin-bottom:10px"><div class="ic ${icCls}"><svg><use href="#${lvl === 'ok' ? 'i-shield' : lvl === 'info' ? 'i-info' : 'i-alert'}"/></svg></div><div><div class="t">${w.connected ? esc(w.ssid) : 'Sin Wi‑Fi'}</div><div class="d">${esc(r.wifiStatus || r.wifiErr || 'Comprobando…')}</div></div></div>
    ${w.connected ? `<dl class="kv"><dt>Punto de acceso (BSSID)</dt><dd class="mono">${esc(w.bssid)}</dd><dt>Seguridad</dt><dd>${esc(w.auth)} ${w.cipher ? '· ' + esc(w.cipher) : ''}</dd><dt>Señal</dt><dd>${esc(w.signal)}</dd><dt>Canal</dt><dd>${esc(w.channel)} ${w.radio ? '· ' + esc(w.radio) : ''}</dd></dl>
    ${lvl === 'warn' || lvl === 'danger' ? '<div style="margin-top:10px"><button class="btn sm" data-act="wifi-trust">Confiar en este punto de acceso</button></div>' : ''}` : ''}`;
  $('#ifaceCard').innerHTML = `<h3><svg width="16" height="16"><use href="#i-plug"/></svg>Adaptadores</h3>` + ((r.ifaces || []).map(i => `<div class="item"><span class="dot ${i.up ? '' : 'off'}"></span><div class="main"><div class="name">${esc(i.name)} <span class="tag">${esc(i.type)}</span></div><div class="sub">${esc(i.desc)} ${i.mac ? '· ' + esc(i.mac) : ''}</div></div><div class="small muted num" style="text-align:right">${i.up && i.speed ? (i.speed >= 1e9 ? (i.speed / 1e9).toFixed(1) + ' Gbps' : Math.round(i.speed / 1e6) + ' Mbps') : 'Desconectado'}</div></div>`).join('') || '<div class="empty">Sin adaptadores.</div>');

  const devs = r.devices || [];
  $('#devCount').textContent = devs.filter(d => d.online).length + ' conectados ahora · ' + devs.length + ' conocidos';
  keyedRender($('#devBody'), devs, d => d.mac + (d.self ? 's' : ''), d => `<tr>
    <td><span class="dot ${d.online ? '' : 'off'}" title="${d.online ? 'En línea' : 'No visto ahora'}"></span></td>
    <td>${d.self ? '<b>Este equipo</b>' : `<input type="text" value="${esc(d.name)}" placeholder="${d.gateway ? 'Router' : 'Sin nombre'}" data-act="dev-name" data-mac="${esc(d.mac)}" style="width:160px;padding:3px 8px">`}
      ${d.gateway ? ' <span class="tag accent">router</span>' : ''}${d.random ? ' <span class="tag" title="Dirección MAC aleatoria (habitual en móviles)">MAC privada</span>' : ''}</td>
    <td class="mono">${esc(d.ip)}</td><td class="mono">${esc(d.mac)}</td><td class="small">${esc(d.host || '—')}</td>
    <td class="small muted">${d.firstSeen ? fmtDate(d.firstSeen, true) : '—'}</td><td class="small muted">${d.online ? 'ahora' : ago(d.lastSeen)}</td>
    <td class="r">${d.self ? '' : `<button class="btn sm" data-act="dev-forget" data-mac="${esc(d.mac)}" title="Olvidar dispositivo">Olvidar</button>`}</td></tr>`);
}
document.addEventListener('change', e => {
  const t = e.target;
  if (t.dataset.act === 'dev-name') api('device', { mac: t.dataset.mac, name: t.value }).then(() => toast('Nombre guardado', t.value || 'Sin nombre', 'info', '', 2500));
});

/* ======================================================================
   Pestaña Seguridad
   ====================================================================== */
function statCard(icon, cls, title, desc, extra) {
  return `<div class="card"><div class="stat"><div class="ic ${cls}"><svg><use href="#${icon}"/></svg></div><div class="grow"><div class="t">${title}</div><div class="d">${desc}</div>${extra ? `<div style="margin-top:10px">${extra}</div>` : ''}</div></div></div>`;
}
async function loadSecurity() {
  let r;
  try { r = await api('security'); } catch (e) { return; }
  const off = r.firewall.filter(p => !p.enabled);
  const fw = off.length
    ? statCard('i-alert', 'danger', 'Firewall de Windows desactivado', 'Perfiles sin protección: ' + off.map(p => p.name).join(', ') + '. Sin el firewall, MiniWall no puede bloquear apps.', '<button class="btn sm primary" data-act="fw-enable">Activar firewall</button>')
    : statCard('i-shield', 'ok', 'Firewall de Windows activo', 'Perfiles ' + r.firewall.map(p => p.name).join(', ') + ' protegidos.' + (r.firewall.some(p => p.blockOut) ? ' Tráfico saliente bloqueado por defecto.' : ''));
  const modeTxt = { monitor: 'Monitorizar', preguntar: 'Preguntar antes de conectar', bloquear: 'Bloquear todo' }[r.mode];
  const mode = statCard('i-fire', r.mode === 'bloquear' ? 'danger' : r.mode === 'preguntar' ? 'warn' : 'ok', 'Modo: ' + modeTxt, `${r.apps} apps conocidas · ${r.blocked} con reglas de bloqueo de MiniWall.` + (r.fwErr ? `<br><span class="danger">Último error: ${esc(r.fwErr)}</span>` : ''));
  const rdpDesc = (r.rdp.enabled ? `El Escritorio remoto está <b>habilitado</b> (puerto ${r.rdp.port}).` : 'El Escritorio remoto está deshabilitado en Windows.')
    + (r.rdpActive?.length ? `<br><span class="danger">Conexión activa desde: ${r.rdpActive.map(esc).join(', ')}</span>` : '<br>No hay conexiones RDP entrantes.');
  const rdp = statCard('i-monitor', r.rdpActive?.length ? 'danger' : r.rdp.enabled && !r.rdpBlocked ? 'warn' : 'ok', 'Detección de conexiones RDP', rdpDesc,
    `<label class="row" style="cursor:pointer"><span class="switch block"><input type="checkbox" data-act="rdp-block"${r.rdpBlocked ? ' checked' : ''}><span></span></span><span class="small">Bloquear RDP entrante con el firewall</span></label>`);
  const wl = r.wifiLevel || 'info';
  const wifi = statCard(wl === 'info' ? 'i-wifi' : wl === 'ok' ? 'i-wifi' : 'i-alert', wl === 'info' ? '' : wl, 'Gemelo malvado (Wi‑Fi)', esc(r.wifiStatus || 'Comprobando…'));
  const camOn = (r.privacy || []).filter(p => p.active);
  const priv = statCard(camOn.length ? 'i-cam' : 'i-lock', camOn.length ? 'warn' : 'ok', 'Protección de privacidad', camOn.length ? camOn.map(p => `${esc(p.app.split('\\').pop())} está usando la ${esc(p.device)}`).join('<br>') : 'Ninguna app está usando la cámara ni el micrófono ahora.');
  const etw = statCard('i-graph', r.etw ? 'ok' : 'warn', 'Monitor de tráfico por app', r.etw ? 'Activo (Event Tracing for Windows). Se mide cuánto usa cada app.' : 'No disponible: se muestran solo los totales del equipo. Ejecuta MiniWall como administrador.');
  $('#secCards').innerHTML = fw + mode + rdp + wifi + priv + etw;

  const pl = r.privacy || [];
  $('#privList').innerHTML = pl.length ? pl.map(p => { const nm = p.app.split('\\').pop(); return `<div class="item"><span class="app-ico letter"><svg width="14" height="14"><use href="#${p.device === 'cámara' ? 'i-cam' : 'i-mic'}"/></svg></span><div class="main"><div class="name">${esc(nm)}</div><div class="sub" title="${esc(p.path)}">${esc(p.device)} · ${esc(p.path || 'app de la Tienda')}</div></div>${p.active ? '<span class="tag warn">en uso ahora</span>' : `<span class="small muted">${ago(p.last)}</span>`}</div>`; }).join('') : '<div class="empty">Windows no ha registrado accesos a la cámara o al micrófono.</div>';
  const ls = r.listens || [];
  $('#listenBody').innerHTML = ls.length ? ls.map(l => `<tr><td>${esc(l.app)}</td><td>${l.proto}</td><td class="mono">${esc(l.addr)}</td><td class="r num">${l.port}</td></tr>`).join('') : '<tr><td colspan="4" class="empty">No hay puertos abiertos a la red.</td></tr>';
}

/* ======================================================================
   Pestaña Sistema
   ====================================================================== */
function fmtUptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return (d ? d + ' d ' : '') + h + ' h ' + m + ' min';
}
async function loadSystem() {
  let r;
  try { r = await api('system'); } catch (e) { return; }
  const now = Date.now() / 1000;
  const ser = arr => (arr || []).map((v, i, a) => ({ t: now - (a.length - 1 - i), a: v }));
  const cpu = r.cpu || [], mem = r.mem || [];
  cpuChart.set(ser(cpu), { from: now - 119, to: now, colors: [cssVar('--down')] });
  memChart.set(ser(mem), { from: now - 119, to: now, colors: [cssVar('--up')] });
  $('#cpuV').textContent = (cpu.length ? cpu[cpu.length - 1] : 0).toFixed(0) + '%';
  $('#memV').textContent = (mem.length ? mem[mem.length - 1] : 0).toFixed(0) + '%';
  $('#memD').textContent = `${fmtBytes(r.memUsed)} usados de ${fmtBytes(r.memTotal)}`;
  $('#sysInfo').textContent = `${r.host || ''} · encendido desde hace ${fmtUptime(r.uptime)}`;
  $('#diskList').innerHTML = (r.disks || []).map(d => { const used = d.total - d.free, p = d.total ? used / d.total * 100 : 0; return `<div style="margin-bottom:12px"><div class="row"><b>${esc(d.drive)}</b><span class="grow"></span><span class="small muted num">${fmtBytes(d.free)} libres de ${fmtBytes(d.total)}</span></div><div class="meter" style="margin-top:6px"><i class="${p > 92 ? 'danger' : p > 80 ? 'warn' : ''}" style="width:${p}%"></i></div></div>`; }).join('') || '<div class="empty">—</div>';
  $('#sysIfaces').innerHTML = (r.ifaces || []).map(i => `<div class="item"><span class="dot ${i.up ? '' : 'off'}"></span><div class="main"><div class="name">${esc(i.name)}</div><div class="sub">${esc(i.desc)}</div></div><div class="small num" style="text-align:right"><span class="down">↓ ${fmtBytes(i.rx)}</span><br><span class="up">↑ ${fmtBytes(i.tx)}</span></div></div>`).join('') || '<div class="empty">—</div>';
}

/* ======================================================================
   Pestaña Alertas
   ====================================================================== */
const alertIcon = { newapp: 'i-info', ask: 'i-shield', appchanged: 'i-info', device: 'i-wifi', rdp: 'i-monitor', privacy: 'i-cam', eviltwin: 'i-alert', limit: 'i-bars', system: 'i-info' };
async function loadAlerts() {
  let list;
  try { list = await api('alerts'); } catch (e) { return; }
  const kinds = S.alertKinds ? S.alertKinds.split(',') : null;
  if (kinds) list = list.filter(a => kinds.includes(a.kind));
  const pend = new Set((S.last?.apps || []).filter(a => a.pending).map(a => a.key));
  $('#alertList').innerHTML = list.length ? list.map(a => `<div class="alert${a.read ? '' : ' unread'}"><div class="ic ${a.level}"><svg><use href="#${alertIcon[a.kind] || 'i-info'}"/></svg></div><div class="grow" style="min-width:0"><div class="row"><span class="ttl grow">${esc(a.title)}</span><span class="small faint" title="${new Date(a.t * 1000).toLocaleString()}">${ago(a.t)}</span></div><div class="txt">${esc(a.text)}</div>${a.kind === 'ask' && pend.has(a.key) ? `<div class="row" style="margin-top:8px"><button class="btn sm primary" data-act="ask-allow" data-key="${esc(a.key)}">Permitir</button><button class="btn sm danger" data-act="ask-block" data-key="${esc(a.key)}">Bloquear</button></div>` : ''}</div></div>`).join('') : '<div class="empty">No hay alertas. Todo tranquilo.</div>';
}
$('#alertFilter').addEventListener('click', e => {
  const b = e.target.closest('[data-k]'); if (!b) return;
  S.alertKinds = b.dataset.k; $$('#alertFilter .chip').forEach(c => c.classList.toggle('on', c === b)); loadAlerts();
});
$('#snoozeSel').addEventListener('change', async e => {
  if (e.target.value === '') return;
  await api('snooze', { name: e.target.value });
  toast(e.target.value === '0' ? 'Alertas reactivadas' : 'Alertas silenciadas', e.target.value === '0' ? '' : 'Las notificaciones no se mostrarán durante ' + e.target.selectedOptions[0].text + '.', 'info', '', 3000);
  e.target.value = '';
});

/* ======================================================================
   Pestaña Ajustes
   ====================================================================== */
const THEMES = [
  ['oscuro', 'Oscuro', '#0e1318', '#151c24', '#2dd4bf'],
  ['claro', 'Claro', '#f3f5f8', '#ffffff', '#0d9488'],
  ['medianoche', 'Medianoche', '#0a0f1e', '#10182e', '#38bdf8'],
  ['grafito', 'Grafito', '#111111', '#191919', '#4ade80'],
  ['bosque', 'Bosque', '#0d1411', '#131d18', '#86efac'],
];
function settingRow(title, desc, control) {
  return `<div class="setting"><div class="main"><div>${title}</div>${desc ? `<div class="d">${desc}</div>` : ''}</div>${control}</div>`;
}
const sw = (path, on) => `<label class="switch"><input type="checkbox" data-cfg="${path}"${on ? ' checked' : ''}><span></span></label>`;
async function loadConfig() {
  let c;
  try { c = await api('config'); } catch (e) { return; }
  S.cfg = c;
  $('#themeList').innerHTML = THEMES.map(t => `<button class="theme-card${c.theme === t[0] ? ' on' : ''}" data-theme-set="${t[0]}"><div class="pv" style="background:${t[2]}"><i style="background:${t[3]};border:1px solid ${t[4]}55"></i><i style="background:linear-gradient(90deg, ${t[4]}88, ${t[4]}11);left:10px;right:40%;height:12px;bottom:17px"></i></div><div class="nm">${t[1]}</div></button>`).join('');
  const n = c.notify;
  $('#notifySettings').innerHTML =
    settingRow('Notificaciones de Windows', 'Muestra un aviso discreto junto al reloj. Las alertas siempre quedan en la pestaña Alertas.', sw('notify.balloons', n.balloons)) +
    settingRow('Apps nuevas', 'Cuando una app se conecta por primera vez.', sw('notify.newApp', n.newApp)) +
    settingRow('Apps modificadas', 'Cuando el ejecutable de una app cambia (actualizaciones o posibles manipulaciones).', sw('notify.appChanged', n.appChanged)) +
    settingRow('Dispositivos nuevos en la red', '', sw('notify.devices', n.devices)) +
    settingRow('Escritorio remoto (RDP)', '', sw('notify.rdp', n.rdp)) +
    settingRow('Cámara y micrófono', '', sw('notify.privacy', n.privacy)) +
    settingRow('Gemelo malvado Wi‑Fi', '', sw('notify.evilTwin', n.evilTwin)) +
    settingRow('Límite de datos', '', sw('notify.limit', n.limit));
  $('#generalSettings').innerHTML =
    settingRow('Límite de datos mensual', 'Avisa al llegar al 80 % y al 100 %. 0 = sin límite.', `<span class="row" style="gap:6px"><input type="number" min="0" step="1" value="${c.limitGB}" data-cfg="limitGB" style="width:90px"> GB</span>`) +
    settingRow('Día de inicio del periodo', 'Día del mes en que se reinicia tu tarifa.', `<input type="number" min="1" max="28" value="${c.billingDay}" data-cfg="billingDay" style="width:70px">`) +
    settingRow('Historial de gráficos', 'Cuánto tiempo guardar el detalle por app y por hora.', `<select data-cfg="retention">${[7, 30, 90, 180, 365].map(d => `<option value="${d}"${c.retention === d ? ' selected' : ''}>${d} días</option>`).join('')}</select>`) +
    settingRow('Cerrar a la bandeja', 'Al cerrar la ventana, MiniWall sigue protegiendo desde la bandeja del sistema.', sw('closeToTray', c.closeToTray)) +
    settingRow('Iniciar con Windows', 'Se abre minimizado al iniciar sesión.', sw('autostart', c.autostart)) +
    settingRow('Preguntar también por apps de Windows', 'En modo Preguntar, incluye los programas de C:\\Windows (puede cortar servicios del sistema).', sw('askSystem', c.askSystem)) +
    settingRow('Quitar todas las reglas de MiniWall', 'Elimina del Firewall de Windows todo lo que MiniWall ha bloqueado. Úsalo antes de desinstalar.', '<button class="btn sm danger" data-act="rules-clear">Quitar reglas</button>');
}
async function saveCfg(patch) {
  try {
    S.cfg = await api('config', { config: patch });
  } catch (e) { toast('No se pudo guardar', e.message, 'danger'); }
}
document.addEventListener('change', e => {
  const t = e.target, path = t.dataset.cfg;
  if (!path || !S.cfg) return;
  let v = t.type === 'checkbox' ? t.checked : t.type === 'number' || t.tagName === 'SELECT' ? Number(t.value) : t.value;
  if (path.startsWith('notify.')) saveCfg({ notify: { ...S.cfg.notify, [path.slice(7)]: v } });
  else saveCfg({ [path]: v });
});
document.addEventListener('click', e => {
  const t = e.target.closest('[data-theme-set]');
  if (!t) return;
  document.documentElement.dataset.theme = t.dataset.themeSet;
  saveCfg({ theme: t.dataset.themeSet }).then(loadConfig);
  setTimeout(() => { mainChart.draw(); miniChart.draw(); }, 50);
});

/* ======================================================================
   Acciones
   ====================================================================== */
async function act(d) {
  try {
    switch (d.act) {
      case 'toggle-block': {
        const r = await api('block', { key: d.key, block: d.checked });
        if (r !== 'ok') toast('No se pudo cambiar', r, 'warn');
        break;
      }
      case 'ask-allow': await api('ask', { key: d.key, allow: true }); toast('App permitida', 'Se ha eliminado el bloqueo.', 'info', '', 2500); break;
      case 'ask-block': await api('ask', { key: d.key, allow: false }); toast('App bloqueada', 'Seguirá bloqueada en este perfil.', 'warn', '', 2500); break;
      case 'profile-switch': await api('profile', { action: 'switch', name: d.name }); break;
      case 'profile-new': {
        const n = prompt('Nombre del nuevo perfil (copia las reglas del perfil actual):');
        if (n) await api('profile', { action: 'create', name: n });
        break;
      }
      case 'profile-rename': {
        const cur = S.last?.profile, n = prompt('Nuevo nombre para «' + cur + '»:', cur);
        if (n && n !== cur) await api('profile', { action: 'rename', name: cur, newName: n });
        break;
      }
      case 'profile-delete': {
        const cur = S.last?.profile;
        if (confirm('¿Eliminar el perfil «' + cur + '»? Sus reglas de bloqueo se quitarán.')) await api('profile', { action: 'delete', name: cur });
        break;
      }
      case 'use-prev': S.useOffset--; loadUsage(); break;
      case 'use-next': if (S.useOffset < 0) { S.useOffset++; loadUsage(); } break;
      case 'map-clear': S.mapCountry = ''; renderMap(); break;
      case 'wifi-trust': await api('wifi/trust', {}); loadLan(); break;
      case 'dev-forget': await api('device/forget', { mac: d.mac }); loadLan(); break;
      case 'rdp-block': await api('rdp', { on: d.checked }); setTimeout(loadSecurity, 800); break;
      case 'rules-clear':
        if (confirm('Se eliminarán todas las reglas de MiniWall del Firewall de Windows, se vaciarán los perfiles y se volverá al modo Monitorizar. ¿Continuar?')) { await api('rules/clear', {}); toast('Reglas eliminadas', 'MiniWall ya no bloquea ninguna app.', 'info', '', 4000); }
        break;
      case 'fw-enable': await api('firewall/enable', {}); setTimeout(loadSecurity, 1500); break;
      case 'alerts-read': await api('alerts/read', {}); loadAlerts(); break;
      case 'alerts-clear': if (confirm('¿Borrar todas las alertas?')) { await api('alerts/clear', {}); loadAlerts(); } break;
    }
  } catch (e) { toast('Error', e.message, 'danger'); }
  if (d.act.startsWith('ask') && S.tab === 'alertas') setTimeout(loadAlerts, 300);
}
document.addEventListener('click', e => {
  const t = e.target.closest('[data-act]');
  if (!t || t.type === 'checkbox' || t.dataset.act === 'dev-name') return;
  e.preventDefault();
  act({ act: t.dataset.act, key: t.dataset.key, mac: t.dataset.mac });
  const toastEl = t.closest('.toast');
  if (toastEl) toastEl.remove();
});
document.addEventListener('change', e => {
  const t = e.target;
  if (t.type === 'checkbox' && t.dataset.act) act({ act: t.dataset.act, key: t.dataset.key, checked: t.checked });
});

$('#modeSeg').addEventListener('click', async e => {
  const b = e.target.closest('[data-mode]');
  if (!b || b.classList.contains('on')) return;
  const m = b.dataset.mode;
  if (m === 'bloquear' && !confirm('«Bloquear todo» cortará el acceso a Internet de TODAS las apps hasta que cambies de modo. ¿Continuar?')) return;
  if (m === 'preguntar') toast('Preguntar antes de conectar', 'Las apps nuevas se bloquearán al conectarse hasta que las permitas.', 'info', '', 5000);
  await api('mode', { mode: m }).catch(err => toast('Error', err.message, 'danger'));
});

/* ======================================================================
   Minigráfico
   ====================================================================== */
function checkMini() {
  const m = innerWidth < 480 && innerHeight < 320;
  if (m !== S.mini) {
    S.mini = m;
    document.body.classList.toggle('mini', m);
    if (!m) { mainChart.draw(); }
  }
}
addEventListener('resize', checkMini);
$('#miniBtn').addEventListener('click', () => api('window', { action: 'mini' }));
$('#mini').addEventListener('dblclick', () => api('window', { action: 'normal' }));

/* ======================================================================
   Inicio
   ====================================================================== */
api('config').then(c => { S.cfg = c; document.documentElement.dataset.theme = c.theme; }).catch(() => {});
checkMini();
poll();
refreshTab(true);
