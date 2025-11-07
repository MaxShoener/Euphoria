// server.js
// Euphoria - Single-tab web proxy for Koyeb
// - No iframe, no puppeteer/playwright
// - Express + node-fetch
// - Injects floating oval topbar into proxied pages and keeps all navigation inside /proxy
// - Lightweight memory + disk caching, session cookie persistence
// - Rewrites anchors, forms, meta-refresh, src/srcset/css url(), window.open, pushState/replaceState
// - Careful about regexes to avoid syntax errors

import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cookie from "cookie";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// --- middleware ---
app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// --- sessions (in memory) ---
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24 hours
const SESSIONS = new Map();

function mkSid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
function now() { return Date.now(); }
function createSession() {
  const sid = mkSid();
  const data = { cookies: new Map(), last: now() };
  SESSIONS.set(sid, data);
  return { sid, data };
}
function getSession(req) {
  const hdr = req.headers.cookie || "";
  const parsed = cookie.parse(hdr || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const data = SESSIONS.get(sid);
  data.last = now();
  return { sid, data };
}
function persistSessionCookie(res, sid) {
  const sc = cookie.serialize(SESSION_NAME, sid, { httpOnly: true, path: "/", sameSite: "Lax", maxAge: 60 * 60 * 24 });
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", sc);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, sc]);
  else res.setHeader("Set-Cookie", [prev, sc]);
}
function storeSetCookieStrings(setCookies = [], sessionData) {
  for (const sc of setCookies) {
    try {
      const kv = sc.split(";")[0];
      const parsed = cookie.parse(kv || "");
      for (const k in parsed) if (k) sessionData.cookies.set(k, parsed[k]);
    } catch (e) { /* ignore */ }
  }
}
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) {
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

// --- caching (mem + disk) ---
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes

function cacheKey(k) { return Buffer.from(k).toString("base64url"); }
function cacheGet(k) {
  const m = MEM_CACHE.get(k);
  if (m && (now() - m.t) < CACHE_TTL) return m.val;
  const f = path.join(CACHE_DIR, cacheKey(k));
  if (fs.existsSync(f)) {
    try {
      const raw = fs.readFileSync(f, "utf8");
      const obj = JSON.parse(raw);
      if ((now() - obj.t) < CACHE_TTL) {
        MEM_CACHE.set(k, { val: obj.val, t: obj.t });
        return obj.val;
      } else try { fs.unlinkSync(f); } catch (e) { /* ignore */ }
    } catch (e) { /* ignore */ }
  }
  return null;
}
function cacheSet(k, v) {
  MEM_CACHE.set(k, { val: v, t: now() });
  try { fs.writeFileSync(path.join(CACHE_DIR, cacheKey(k)), JSON.stringify({ val: v, t: now() }), "utf8"); } catch (e) { /* ignore */ }
}

// --- utils ---
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function buildCookieHeader(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}
function extractUrl(req) {
  if (req.query && req.query.url) return req.query.url;
  const m = req.path.match(/^\/proxy\/(.+)$/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}
function isLikelySearch(input) {
  if (!input) return true;
  if (input.includes(" ")) return true;
  if (/^https?:\/\//i.test(input)) return false;
  if (/\./.test(input)) return false;
  return true;
}

// --- injected floating oval topbar + containment script ---
// Solid dark oval background, uniform icon sizes, embedded minimal CSS
const INJECT_TOPBAR_AND_CONTAINMENT = `
<!-- EUPHORIA FLOATING OVAL TOPBAR -->
<div id="euphoria-topbar" style="
  position:fixed;top:12px;left:50%;transform:translateX(-50%);
  width:76%;max-width:1100px;background:#0f1113;border-radius:32px;padding:6px 10px;
  display:flex;align-items:center;gap:8px;z-index:2147483647;box-shadow:0 10px 30px rgba(0,0,0,0.6);
  font-family:system-ui,Arial,sans-serif;">
  <div style="display:flex;align-items:center;gap:8px;margin-left:6px">
    <button id="eph-back" aria-label="Back" style="width:40px;height:40px;border-radius:10px;border:0;background:#17181a;color:#fff;cursor:pointer">◀</button>
    <button id="eph-forward" aria-label="Forward" style="width:40px;height:40px;border-radius:10px;border:0;background:#17181a;color:#fff;cursor:pointer">▶</button>
    <button id="eph-refresh" aria-label="Refresh" style="width:40px;height:40px;border-radius:10px;border:0;background:#17181a;color:#fff;cursor:pointer">⟳</button>
  </div>
  <input id="eph-input" aria-label="Address bar" placeholder="Enter URL or search..." style="flex:1;padding:10px 14px;border-radius:18px;border:0;background:#141516;color:#fff;outline:none;font-size:15px" />
  <div style="display:flex;align-items:center;gap:8px;margin-right:6px">
    <button id="eph-home" aria-label="Home" style="width:40px;height:40px;border-radius:10px;border:0;background:#17181a;color:#fff;cursor:pointer">🏠</button>
    <button id="eph-go" aria-label="Go" style="width:48px;height:40px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer;font-weight:700">Go</button>
    <button id="eph-full" aria-label="Fullscreen" style="width:40px;height:40px;border-radius:10px;border:0;background:#17181a;color:#fff;cursor:pointer">⛶</button>
  </div>
</div>
<style>body{padding-top:84px !important;background:transparent !important;}img,video{max-width:100%;height:auto;}</style>

<script>
(function(){
  // small containment script to keep navigation via /proxy
  const input = document.getElementById('eph-input');
  const btnGo = document.getElementById('eph-go');
  const btnBack = document.getElementById('eph-back');
  const btnForward = document.getElementById('eph-forward');
  const btnRefresh = document.getElementById('eph-refresh');
  const btnHome = document.getElementById('eph-home');
  const btnFull = document.getElementById('eph-full');

  // prefill input from ?url=
  try {
    const m = location.search.match(/[?&]url=([^&]+)/);
    if (m) input.value = decodeURIComponent(m[1]);
  } catch (e) {}

  function isLikelySearch(v){
    if(!v) return true;
    if(v.indexOf(' ') !== -1) return true;
    if(/^https?:\\/\\//i.test(v)) return false;
    if(/\\./.test(v)) return false;
    return true;
  }
  function normalize(v){
    v = (v||'').trim();
    if(!v) return 'https://www.google.com';
    if(isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
    if(/^https?:\\/\\//i.test(v)) return v;
    return 'https://' + v;
  }
  function toProxy(h){ return '/proxy?url=' + encodeURIComponent(h); }

  btnGo.addEventListener('click', ()=> {
    const v = input.value || '';
    if(!v) return;
    if(/\\/proxy\\?url=/.test(v)){ location.href = v; return; }
    location.href = toProxy(normalize(v));
  });
  input.addEventListener('keydown', (e)=>{ if(e.key === 'Enter') btnGo.click(); });

  btnBack.addEventListener('click', ()=> history.back());
  btnForward.addEventListener('click', ()=> history.forward());
  btnRefresh.addEventListener('click', ()=> location.reload());
  btnHome.addEventListener('click', ()=> location.href = '/proxy?url=' + encodeURIComponent('https://www.google.com'));
  btnFull.addEventListener('click', ()=> { if(!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); });

  // helpers for rewriting
  function absolute(h){ try { return new URL(h, document.baseURI).href } catch(e) { return h; } }
  function toProxyHref(h){ return '/proxy?url=' + encodeURIComponent(h); }

  function rewriteAnchor(a){
    try {
      if(!a || !a.getAttribute) return;
      const href = a.getAttribute('href'); if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(href.startsWith('/proxy?url=')) return;
      const abs = absolute(href);
      a.setAttribute('href', toProxyHref(abs));
      a.removeAttribute('target');
    } catch(e){}
  }

  function rewriteAsset(el, attr){
    try {
      if(!el || !el.getAttribute) return;
      const v = el.getAttribute(attr); if(!v) return;
      if(/^data:/i.test(v)) return;
      if(v.startsWith('/proxy?url=')) return;
      const abs = absolute(v);
      el.setAttribute(attr, toProxyHref(abs));
    } catch(e){}
  }

  function rewriteSrcset(el){
    try {
      const ss = el.getAttribute('srcset'); if(!ss) return;
      const parts = ss.split(',').map(p => {
        const [url, rest] = p.trim().split(/\\s+/,2);
        if(!url) return p;
        if(/^data:/i.test(url)) return p;
        return toProxyHref(absolute(url)) + (rest ? ' ' + rest : '');
      });
      el.setAttribute('srcset', parts.join(', '));
    } catch(e){}
  }

  function rewriteAll(){
    document.querySelectorAll('a[href]').forEach(rewriteAnchor);
    ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
      document.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
      document.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
    });
    document.querySelectorAll('[srcset]').forEach(rewriteSrcset);
  }

  rewriteAll();

  const mo = new MutationObserver((muts)=>{
    for(const mut of muts){
      if(mut.type === 'childList' && mut.addedNodes.length) rewriteAll();
    }
  });
  mo.observe(document.documentElement || document, { childList:true, subtree:true });

  // ensure clicks route through proxy in-page
  document.addEventListener('click', function(e){
    const a = e.target.closest && e.target.closest('a[href]');
    if(!a) return;
    const href = a.getAttribute('href') || '';
    if(!href) return;
    if(href.startsWith('/proxy?url=') || href.startsWith('/')) return;
    if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
    e.preventDefault();
    location.href = toProxyHref(absolute(href));
  }, true);

  // intercept forms
  document.addEventListener('submit', function(e){
    const f = e.target;
    if(!f) return;
    try {
      const a = f.getAttribute('action') || '';
      if(!a) return;
      if(a.startsWith('/proxy?url=')) return;
      if(/^(javascript:|#)/i.test(a)) return;
      const abs = absolute(a);
      f.setAttribute('action', '/proxy?url=' + encodeURIComponent(abs));
    } catch(e){}
  }, true);

  // patch history APIs so pushState/replaceState go through proxy
  (function(history){
    const push = history.pushState;
    history.pushState = function(s,t,u){
      try { if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = '/proxy?url=' + encodeURIComponent(absolute(u)); } catch(e){}
      return push.apply(history, arguments);
    };
    const rep = history.replaceState;
    history.replaceState = function(s,t,u){
      try { if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = '/proxy?url=' + encodeURIComponent(absolute(u)); } catch(e){}
      return rep.apply(history, arguments);
    };
  })(window.history);

  // patch window.open to use proxy in same tab
  (function(){
    try {
      const orig = window.open;
      window.open = function(u,...rest){
        try { if(!u) return orig.apply(window, arguments); location.href = '/proxy?url=' + encodeURIComponent(absolute(u)); return null; } catch(e) { return orig.apply(window, arguments); }
      };
    } catch(e){}
  })();

})();
</script>
`;

// --- proxy endpoint ---
app.get("/proxy", async (req, res) => {
  let raw = extractUrl(req) || req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize short inputs/searches
  if (!/^https?:\/\//i.test(raw)) {
    try {
      const maybe = decodeURIComponent(raw);
      if (isLikelySearch(maybe)) raw = "https://www.google.com/search?q=" + encodeURIComponent(maybe);
      else raw = "https://" + maybe;
    } catch (e) { raw = "https://" + raw; }
  }

  // session
  const session = getSession(req);
  persistSessionCookie(res, session.sid);

  const keyHtml = raw + "::html";
  const assetKey = raw + "::asset";

  // fastpath: return cached small asset if acceptable
  try {
    const cachedAsset = cacheGet(assetKey);
    if (cachedAsset && !req.headers.accept?.includes("text/html")) {
      const obj = typeof cachedAsset === "string" ? JSON.parse(cachedAsset) : cachedAsset;
      if (obj.headers) Object.entries(obj.headers).forEach(([k, v]) => res.setHeader(k, v));
      return res.send(Buffer.from(obj.body, "base64"));
    }
  } catch (e) { /* ignore */ }

  // build headers for upstream
  const cookieHeader = buildCookieHeader(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers["accept"] || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    // follow redirects server-side so we know final URL and can rewrite properly
    const upstream = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // store cookies returned upstream
    const setCookies = upstream.headers.raw ? (upstream.headers.raw()["set-cookie"] || []) : [];
    if (setCookies.length) storeSetCookieStrings(setCookies, session.data);

    const contentType = upstream.headers.get("content-type") || "";

    // binary or non-html -> pipe bytes back (and cache small assets)
    if (!contentType.includes("text/html")) {
      const arr = await upstream.arrayBuffer();
      const buf = Buffer.from(arr);

      if (buf.length < 100 * 1024) {
        try { cacheSet(assetKey, JSON.stringify({ headers: { "Content-Type": contentType }, body: buf.toString("base64") })); } catch (e) { /* ignore */ }
      }

      res.setHeader("Content-Type", contentType);
      const cacheControl = upstream.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      persistSessionCookie(res, session.sid);
      return res.send(buf);
    }

    // HTML path: read full HTML and rewrite carefully
    let html = await upstream.text();

    // remove CSP meta tags (prevent our injection from being blocked)
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // remove integrity/crossorigin that would break proxied assets
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    const finalUrl = upstream.url || raw;

    // ensure <base> exists so relative resolution in page JS still works
    if (/<head/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // rewrite anchors to /proxy
    html = html.replace(/<a\b([^>]*?)href=(["'])([^"']*)\2/gi, (m, pre, q, val) => {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // rewrite src/href/srcset for common asset tags
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?(?:src|href|srcset)=)(["'])([^"']*)\2/gi, (m, prefix, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // rewrite CSS url()
    html = html.replace(/url\\((['"]?)(.*?)\\1\\)/gi, (m, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      if (abs.startsWith("/proxy?url=")) return m;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // rewrite form actions
    html = html.replace(/(<\\s*form[^>]*action=)(["'])([^"']*)(["'])/gi, (m, pre, q1, val, q2) => {
      if (!val) return m;
      if (/^(javascript:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q1}/proxy?url=${encodeURIComponent(abs)}${q2}`;
    });

    // meta-refresh rewrite
    html = html.replace(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*>/gi, (m) => {
      const match = m.match(/content\\s*=\\s*"(.*?)"/i);
      if (!match) return m;
      const parts = match[1].split(";");
      if (parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";");
      const uMatch = urlPart.match(/url=(.*)/i);
      if (!uMatch) return m;
      const dest = uMatch[1].replace(/['"]/g, "").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // remove obvious analytics/static trackers (best-effort)
    html = html.replace(/<script[^>]*src=(["'])[^\\"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\\1[^>]*><\\/script>/gi, "");

    // inject the floating oval topbar and containment script after <body>
    if (/<body/i.test(html)) {
      html = html.replace(/<body([^>]*)>/i, (m) => m + INJECT_TOPBAR_AND_CONTAINMENT);
    } else {
      html = INJECT_TOPBAR_AND_CONTAINMENT + html;
    }

    // cache successful HTML
    if (upstream.status === 200) {
      try { cacheSet(keyHtml, html); } catch (e) { /* ignore */ }
    }

    // finalize headers and send
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    return res.send(html);

  } catch (err) {
    console.error("Euphoria proxy error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    res.status(500).send(`<div style="padding:1.5rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// --- fallback serve index.html for SPA root ---
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    const idx = path.join(__dirname, "public", "index.html");
    if (fs.existsSync(idx)) return res.sendFile(idx);
  }
  next();
});

app.listen(PORT, () => console.log(\`Euphoria proxy running on port \${PORT}\`));