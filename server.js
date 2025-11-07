// server.js — Euphoria (rewritten)
// Node 20+ native fetch, Express, safe regex usage, injection + containment
import express from "express";
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

// Middleware
app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
// Serve the launcher/static files from ./public (index.html will be used for SPA fallback)
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---- Simple session cookie store (in-memory) ----
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24h
const SESSIONS = new Map();
function mkSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
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
    } catch (e) { /* ignore malformed set-cookie */ }
  }
}
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
}, 1000 * 60 * 10);

// ---- Lightweight cache (memory + disk) ----
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 5;
function cacheKey(k) { return Buffer.from(k).toString("base64url"); }
function cacheGet(k) {
  const m = MEM_CACHE.get(k);
  if (m && (now() - m.t) < CACHE_TTL) return m.val;
  const f = path.join(CACHE_DIR, cacheKey(k));
  if (fs.existsSync(f)) {
    try {
      const raw = fs.readFileSync(f, "utf8");
      const obj = JSON.parse(raw);
      if ((now() - obj.t) < CACHE_TTL) { MEM_CACHE.set(k, { val: obj.val, t: obj.t }); return obj.val; }
      else try { fs.unlinkSync(f) } catch (e) { /* ignore */ }
    } catch (e) { /* ignore */ }
  }
  return null;
}
function cacheSet(k, v) {
  MEM_CACHE.set(k, { val: v, t: now() });
  try { fs.writeFileSync(path.join(CACHE_DIR, cacheKey(k)), JSON.stringify({ val: v, t: now() }), "utf8"); } catch (e) { /* ignore */ }
}

// ---- Helpers ----
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
function normalizeInputToURL(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// ---- Injected UI & containment script (solid dark oval topbar) ----
const INJECT_TOPBAR_AND_CONTAINMENT = `
<!-- EUPHORIA TOPBAR (injected) -->
<div id="euphoria-topbar" style="position:fixed;top:12px;left:50%;transform:translateX(-50%);width:78%;max-width:1200px;background:#111;border-radius:28px;padding:8px 12px;display:flex;align-items:center;gap:8px;z-index:2147483647;box-shadow:0 6px 20px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
  <button id="eph-back" aria-label="Back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" aria-label="Forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" aria-label="Refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" aria-label="Home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" aria-label="Address" style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" placeholder="Enter URL or search..." />
  <button id="eph-go" aria-label="Go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" aria-label="Fullscreen" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
</div>
<style>body{padding-top:76px !important;background:transparent !important;}</style>

<script>
/* containment script — keeps navigation inside /proxy and rewrites dynamic links */
(function(){
  try {
    const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);
    const absolute = (h) => { try { return new URL(h, document.baseURI).href } catch(e){ return h } };

    const input = document.getElementById('eph-input');
    const go = document.getElementById('eph-go');
    const back = document.getElementById('eph-back');
    const forward = document.getElementById('eph-forward');
    const refresh = document.getElementById('eph-refresh');
    const home = document.getElementById('eph-home');
    const full = document.getElementById('eph-full');

    try {
      const m = location.search.match(/[?&]url=([^&]+)/);
      if(m) input.value = decodeURIComponent(m[1]);
    } catch(e){}

    function isLikelySearch(v){
      if(!v) return true;
      if(v.includes(' ')) return true;
      if(/^https?:\\/\\//i.test(v)) return false;
      if(/\\./.test(v)) return false;
      return true;
    }
    function normalize(v){
      v=(v||'').trim();
      if(!v) return 'https://www.google.com';
      if (isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
      try{ new URL(v); return v } catch(e) {}
      return 'https://' + v;
    }

    go.onclick = () => {
      const val = input.value;
      if (/\\/proxy\\?url=/i.test(val)) { location.href = val; return; }
      const u = normalize(val);
      location.href = toProxy(u);
    };
    input.onkeydown = e => { if (e.key === 'Enter') go.onclick(); };
    back.onclick = () => history.back();
    forward.onclick = () => history.forward();
    refresh.onclick = () => location.reload();
    home.onclick = () => location.href = '/';
    full.onclick = () => { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

    // rewrite helpers
    function rewriteAnchor(a){
      try {
        if (!a || !a.getAttribute) return;
        const href = a.getAttribute('href');
        if (!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if (href.startsWith('/proxy?url=')) return;
        const abs = absolute(href);
        a.setAttribute('href', toProxy(abs));
        a.removeAttribute('target');
      } catch(e){}
    }
    function rewriteAsset(el, attr){
      try {
        if (!el || !el.getAttribute) return;
        const v = el.getAttribute(attr);
        if (!v) return;
        if (/^data:/i.test(v)) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(v)) return;
        if (v.startsWith('/proxy?url=')) return;
        const abs = absolute(v);
        el.setAttribute(attr, toProxy(abs));
      } catch(e){}
    }

    function rewriteAll(){
      try {
        document.querySelectorAll('a[href]').forEach(rewriteAnchor);
        ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
          document.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
          document.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
        });
        document.querySelectorAll('[srcset]').forEach(el=>{
          try{
            const ss = el.getAttribute('srcset');
            if(!ss) return;
            const parts = ss.split(',').map(p=>{
              const [url, rest] = p.trim().split(/\\s+/,2);
              if(!url) return p;
              if(/^data:/i.test(url)) return p;
              return toProxy(absolute(url)) + (rest ? ' ' + rest : '');
            });
            el.setAttribute('srcset', parts.join(', '));
          }catch(e){}
        });
      } catch(e){}
    }

    rewriteAll();
    const mo = new MutationObserver(muts=>{
      for(const mut of muts){
        if(mut.type === 'childList'){
          mut.addedNodes.forEach(n=>{
            if(n.nodeType !== 1) return;
            if(n.matches && n.matches('a[href]')) rewriteAnchor(n);
            n.querySelectorAll && n.querySelectorAll('a[href]').forEach(rewriteAnchor);
            ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
              if(n.matches && n.matches(tag + '[src]')) rewriteAsset(n,'src');
              n.querySelectorAll && n.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
              if(n.matches && n.matches(tag + '[href]')) rewriteAsset(n,'href');
              n.querySelectorAll && n.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
            });
            if(n.querySelectorAll && n.querySelectorAll('[srcset]').length){
              n.querySelectorAll('[srcset]').forEach(el=>{
                const ss = el.getAttribute('srcset');
                if(!ss) return;
                const parts = ss.split(',').map(p=>{
                  const [url, rest] = p.trim().split(/\\s+/,2);
                  if(!url) return p;
                  if(/^data:/i.test(url)) return p;
                  return toProxy(absolute(url)) + (rest ? ' ' + rest : '');
                });
                el.setAttribute('srcset', parts.join(', '));
              });
            }
          });
        }
      }
    });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });

    // intercept click navigation to force /proxy
    document.addEventListener('click', function(e){
      const a = e.target.closest && e.target.closest('a[href]');
      if(!a) return;
      try {
        const href = a.getAttribute('href') || '';
        if(!href) return;
        if (href.startsWith('/proxy?url=') || href.startsWith('/')) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = absolute(href);
        location.href = toProxy(abs);
      } catch(e){}
    }, true);

    // intercept forms
    document.addEventListener('submit', function(e){
      const f = e.target;
      if(!f) return;
      try{
        const a = f.getAttribute('action') || '';
        if(!a) return;
        if(a.startsWith('/proxy?url=')) return;
        if(/^(javascript:|#)/i.test(a)) return;
        const abs = absolute(a);
        f.setAttribute('action', '/proxy?url=' + encodeURIComponent(abs));
      }catch(e){}
    }, true);

    // patch history API to keep pushes inside proxy
    (function(history){ const push = history.pushState; history.pushState = function(s,t,u){
      try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(absolute(u)); }catch(e){}
      return push.apply(history, arguments);
    }; const rep = history.replaceState; history.replaceState = function(s,t,u){
      try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(absolute(u)); }catch(e){}
      return rep.apply(history, arguments);
    }; })(window.history);

    // patch window.open to open inside proxy (same tab)
    (function(){
      try{
        const orig = window.open;
        window.open = function(u, ...rest){
          try{ if(!u) return orig.apply(window, arguments); const abs = absolute(u); location.href = toProxy(abs); return null; }catch(e){ return orig.apply(window, arguments); }
        };
      }catch(e){}
    })();

    // meta refresh rewrite
    function rewriteMetaRefresh(){
      document.querySelectorAll('meta[http-equiv]').forEach(m=>{
        try{
          if(m.getAttribute('http-equiv').toLowerCase() !== 'refresh') return;
          const c = m.getAttribute('content') || '';
          const parts = c.split(';');
          if(parts.length < 2) return;
          const urlpart = parts.slice(1).join(';').match(/url=(.*)/i);
          if(!urlpart) return;
          const dest = urlpart[1].replace(/['"]/g,'').trim();
          const abs = absolute(dest);
          m.setAttribute('content', parts[0] + ';url=' + toProxy(abs));
        }catch(e){}
      });
    }
    rewriteMetaRefresh();
    setTimeout(()=>{ rewriteAll(); rewriteMetaRefresh(); }, 500);
  }catch(e){}
})();
</script>
`;

// ---- /proxy endpoint ----
app.get("/proxy", async (req, res) => {
  try {
    let raw = extractUrl(req);
    if (!raw) raw = req.query.url;
    if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

    // normalize input -> if user supplied something like "xbox" or "google search", handle it
    if (!/^https?:\/\//i.test(raw)) {
      try {
        const maybe = decodeURIComponent(raw);
        if (isLikelySearch(maybe)) raw = "https://www.google.com/search?q=" + encodeURIComponent(maybe);
        else raw = "https://" + maybe;
      } catch (e) { raw = "https://" + raw; }
    }

    const session = getSession(req);
    persistSessionCookie(res, session.sid);

    const keyHtml = raw + "::html";
    const assetKey = raw + "::asset";

    // quick-serve small cached assets if not HTML
    try {
      const cachedAsset = cacheGet(assetKey);
      if (cachedAsset && !req.headers.accept?.includes("text/html")) {
        const obj = typeof cachedAsset === "string" ? JSON.parse(cachedAsset) : cachedAsset;
        if (obj.headers) Object.entries(obj.headers).forEach(([k, v]) => res.setHeader(k, v));
        persistSessionCookie(res, session.sid);
        return res.send(Buffer.from(obj.body, "base64"));
      }
    } catch (e) { /* ignore cache errors */ }

    // Prepare headers for origin request
    const cookieHeader = buildCookieHeader(session.data.cookies);
    const headers = {
      "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
      "Accept": req.headers["accept"] || "*/*",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    };
    if (cookieHeader) headers["Cookie"] = cookieHeader;
    if (req.headers.referer) headers["Referer"] = req.headers.referer;

    // fetch origin (server follows redirects)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // collect set-cookie for session
    const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if (setCookies.length) storeSetCookieStrings(setCookies, session.data);

    const contentType = originRes.headers.get("content-type") || "";

    // Non-HTML -> stream bytes (and small-asset cache)
    if (!contentType.includes("text/html")) {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if (buf.length < 100 * 1024) {
        try { cacheSet(assetKey, JSON.stringify({ headers: { "Content-Type": contentType }, body: buf.toString("base64") })); } catch (e) { /* ignore */ }
      }
      res.setHeader("Content-Type", contentType);
      const cacheControl = originRes.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      persistSessionCookie(res, session.sid);
      return res.send(buf);
    }

    // HTML path
    const html = await originRes.text();

    // Transformations — use RegExp safely (avoid invalid literal escapes)
    // Remove CSP meta tags
    out = html.replace(new RegExp('<meta[^>]*http-equiv=["\']?content-security-policy["\']?[^>]*>', 'gi'), '');

    // Remove integrity and crossorigin attributes (break proxied assets)
    out = out.replace(new RegExp('\\sintegrity=(["\'])(.*?)\\1', 'gi'), '');
    out = out.replace(new RegExp('\\scrossorigin=(["\'])(.*?)\\1', 'gi'), '');

    // Inject <base href="finalUrl"> to help relative resolution before we rewrite
    const finalUrl = originRes.url || raw;
    if (/<head/i.test(out)) {
      out = out.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      out = `<base href="${finalUrl}">` + out;
    }

    // Rewrite anchors (<a href="...">) to /proxy?url=abs
    out = out.replace(/<a\b([^>]*?)href=(["'])(.*?)\2/gi, (m, pre, q, val) => {
      try {
        if (!val) return m;
        if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
        if (val.startsWith('/proxy?url=')) return m;
        const abs = toAbsolute(val, finalUrl) || val;
        return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
      } catch (e) { return m; }
    });

    // Rewrite asset tags (src/href/srcset) to /proxy?url=abs
    out = out.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?(?:src|href|srcset)=)(["'])(.*?)\2/gi, (m, prefix, q, val) => {
      try {
        if (!val) return m;
        if (/^data:/i.test(val)) return m;
        if (val.startsWith('/proxy?url=')) return m;
        const abs = toAbsolute(val, finalUrl) || val;
        return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
      } catch (e) { return m; }
    });

    // CSS url(...) -> /proxy?url=abs
    out = out.replace(new RegExp('url\\((["\']?)(.*?)\\1\\)', 'gi'), (m, q, val) => {
      try {
        if (!val) return m;
        if (/^data:/i.test(val)) return m;
        const abs = toAbsolute(val, finalUrl) || val;
        if (abs.startsWith('/proxy?url=')) return m;
        return `url("/proxy?url=${encodeURIComponent(abs)}")`;
      } catch (e) { return m; }
    });

    // form actions -> /proxy?url=abs
    out = out.replace(/(<\s*form[^>]*action=)(["'])(.*?)\2/gi, (m, pre, q, val) => {
      try {
        if (!val) return m;
        if (/^(javascript:|#)/i.test(val)) return m;
        if (val.startsWith('/proxy?url=')) return m;
        const abs = toAbsolute(val, finalUrl) || val;
        return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
      } catch (e) { return m; }
    });

    // meta refresh rewriting (safe)
    out = out.replace(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*>/gi, (m) => {
      try {
        const match = m.match(/content\s*=\s*"(.*?)"/i);
        if (!match) return m;
        const parts = match[1].split(";");
        if (parts.length < 2) return m;
        const urlPart = parts.slice(1).join(";");
        const uMatch = urlPart.match(/url=(.*)/i);
        if (!uMatch) return m;
        const dest = uMatch[1].replace(/['"]/g, "").trim();
        const abs = toAbsolute(dest, finalUrl) || dest;
        return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
      } catch (e) { return m; }
    });

    // remove some known analytics script tags (best-effort) — use RegExp via constructor to avoid literal escape issues
    const analyticsPattern = new RegExp('<script[^>]*src=(["\'])(?:[^"\']*)(analytics|gtag|googletagmanager|doubleclick|googlesyndication)(?:[^"\']*)\\1[^>]*><\\/script>', 'gi');
    out = out.replace(analyticsPattern, '');

    // inject the topbar + containment script just after <body>
    if (/<body/i.test(out)) {
      out = out.replace(/<body([^>]*)>/i, (m) => m + INJECT_TOPBAR_AND_CONTAINMENT);
    } else {
      out = INJECT_TOPBAR_AND_CONTAINMENT + out;
    }

    // cache successful HTML
    if (originRes.status === 200) cacheSet(keyHtml, out);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    return res.send(out);

  } catch (err) {
    console.error("Euphoria proxy error:", err && err.message ? err.message : err);
    // try to recover session header if available
    res.status(500).send(`<div style="padding:1.2rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// Fallback: serve index.html for SPA / launcher routes
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));
