// server.js
// EUPHORIA — interception-style proxy (no iframe, no headless browser)
// - Serves static frontend from ./public/index.html
// - /proxy?url=... fetches origin, rewrites HTML to keep navigation inside Euphoria
// - Lightweight LRU cache and small-disk persistence
// - Session cookie store per client (via cookie) to maintain logins
// - Injects floating oval topbar + containment script to handle clicks/forms/history

import express from "express";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import cookie from "cookie";
import compression from "compression";
import morgan from "morgan";
import pkg from "scramjet"; // scramjet is CommonJS — import default then destructure
import LRU from "lru-cache";

const { StringStream } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Middleware ----
app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---- Simple session cookie store (in-memory) ----
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24; // 24h
const SESSIONS = new Map();

function mkSid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
function now() {
  return Date.now();
}
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
  const sc = cookie.serialize(SESSION_NAME, sid, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    maxAge: 60 * 60 * 24,
  });
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
    } catch (e) {
      // ignore
    }
  }
}
// cleanup old sessions periodically
setInterval(() => {
  const cutoff = now() - SESSION_TTL_MS;
  for (const [sid, data] of SESSIONS.entries())
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
}, 1000 * 60 * 30);

// ---- Cache: LRU (memory) + optional disk persistence for small HTML entries ----
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

const cache = new LRU({
  max: 200, // number of entries
  ttl: 1000 * 60 * 5, // 5 minutes
  sizeCalculation: (v, key) => (typeof v === "string" ? Buffer.byteLength(v, "utf8") : 1),
});

function diskCachePath(key) {
  return path.join(CACHE_DIR, Buffer.from(key).toString("base64url"));
}
function cacheGetDisk(key) {
  try {
    const p = diskCachePath(key);
    if (!fs.existsSync(p)) return null;
    const raw = fs.readFileSync(p, "utf8");
    const obj = JSON.parse(raw);
    if (Date.now() - obj.t > 1000 * 60 * 10) {
      try { fs.unlinkSync(p); } catch (e) {}
      return null;
    }
    return obj.val;
  } catch (e) {
    return null;
  }
}
function cacheSetDisk(key, val) {
  try {
    fs.writeFileSync(diskCachePath(key), JSON.stringify({ t: Date.now(), val }), "utf8");
  } catch (e) {
    // ignore
  }
}
function cacheGet(key) {
  const m = cache.get(key);
  if (m) return m;
  const d = cacheGetDisk(key);
  if (d) {
    cache.set(key, d);
    return d;
  }
  return null;
}
function cacheSet(key, val, persist = false) {
  cache.set(key, val);
  if (persist) cacheSetDisk(key, val);
}

// ---- Helpers ----
function toAbsolute(href, base) {
  try {
    return new URL(href, base).href;
  } catch (e) {
    return null;
  }
}
function buildCookieHeader(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}
function extractUrlFromReq(req) {
  if (req.query && req.query.url) return req.query.url;
  const m = req.path.match(/^\/proxy\/(.+)$/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}
function looksLikeSearch(input) {
  if (!input) return true;
  if (input.includes(" ")) return true;
  if (/^https?:\/\//i.test(input)) return false;
  if (/\./.test(input)) return false;
  return true;
}
function normalizeInputToUrl(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (looksLikeSearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// ---- Injected TOPBAR + containment script (floating dark oval) ----
const TOPBAR_INJECT = `
<!-- EUPHORIA TOPBAR (injected) -->
<div id="euphoria-topbar" style="position:fixed;top:12px;left:50%;transform:translateX(-50%);width:84%;max-width:1200px;background:#0f1113;border-radius:28px;padding:8px 12px;display:flex;align-items:center;gap:8px;z-index:2147483647;box-shadow:0 8px 30px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
  <button id="eph-back" aria-label="Back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#1b1d1f;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" aria-label="Forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#1b1d1f;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" aria-label="Refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#1b1d1f;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" aria-label="Home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#1b1d1f;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" aria-label="Address" style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#161718;color:#fff;outline:none" placeholder="Enter URL or search..." />
  <button id="eph-go" aria-label="Go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" aria-label="Fullscreen" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#1b1d1f;color:#fff;cursor:pointer">⛶</button>
</div>
<style>html,body{background:transparent !important;}body{padding-top:76px !important;margin:0 !important}</style>

<script>
/* EUPHORIA containment script */
(function(){
  try{
    const absolute = (h) => { try{ return new URL(h, document.baseURI).href } catch(e){ return h; } };
    const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);
    const input = document.getElementById('eph-input');
    const goBtn = document.getElementById('eph-go');
    const backBtn = document.getElementById('eph-back');
    const forwardBtn = document.getElementById('eph-forward');
    const refreshBtn = document.getElementById('eph-refresh');
    const homeBtn = document.getElementById('eph-home');
    const fullBtn = document.getElementById('eph-full');

    // Prefill input from location url param
    try {
      const m = location.search.match(/[?&]url=([^&]+)/);
      if(m) input.value = decodeURIComponent(m[1]);
    } catch(e){}

    function isLikelySearch(v){
      if(!v) return true;
      if(v.indexOf(' ') !== -1) return true;
      if(/^https?:\\/\\//i.test(v)) return false;
      if(/\\./.test(v)) return false;
      return true;
    }
    function normalize(v){
      v=(v||'').trim();
      if(!v) return 'https://www.google.com';
      if(isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
      if(/^https?:\\/\\//i.test(v)) return v;
      return 'https://' + v;
    }

    goBtn.onclick = () => {
      const raw = input.value || '';
      if(/\\/proxy\\?url=/i.test(raw)) { location.href = raw; return; }
      const u = normalize(raw);
      location.href = toProxy(u);
    };
    input.addEventListener('keydown', e => { if(e.key === 'Enter') goBtn.click(); });

    backBtn.onclick = () => history.back();
    forwardBtn.onclick = () => history.forward();
    refreshBtn.onclick = () => location.reload();
    homeBtn.onclick = () => location.href = toProxy('https://www.google.com');
    fullBtn.onclick = () => { if(!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

    // Rewrite anchors/assets inside proxied HTML (for dynamic DOM)
    function rewriteAnchor(el){
      try{
        if(!el || !el.getAttribute) return;
        const href = el.getAttribute('href');
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(href.startsWith('/proxy?url=')) { el.removeAttribute('target'); return; }
        const abs = absolute(href);
        el.setAttribute('href', toProxy(abs));
        el.removeAttribute('target');
      }catch(e){}
    }
    function rewriteAsset(el, attr){
      try{
        if(!el || !el.getAttribute) return;
        const v = el.getAttribute(attr);
        if(!v) return;
        if(/^data:/i.test(v)) return;
        if(v.startsWith('/proxy?url=')) return;
        const abs = absolute(v);
        el.setAttribute(attr, '/proxy?url=' + encodeURIComponent(abs));
      }catch(e){}
    }

    function rewriteAll(){
      document.querySelectorAll('a[href]').forEach(rewriteAnchor);
      ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
        document.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
        document.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
      });
      document.querySelectorAll('[srcset]').forEach(el=>{
        try{
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [url, rest] = p.trim().split(/\\s+/,2);
            if(!url) return p;
            if(/^data:/i.test(url)) return p;
            return '/proxy?url=' + encodeURIComponent(absolute(url)) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }catch(e){}
      });
    }
    rewriteAll();

    // Observe DOM changes and rewrite dynamically inserted nodes
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
                try{
                  const ss = el.getAttribute('srcset') || '';
                  const parts = ss.split(',').map(p=>{
                    const [url, rest] = p.trim().split(/\\s+/,2);
                    if(!url) return p;
                    if(/^data:/i.test(url)) return p;
                    return '/proxy?url=' + encodeURIComponent(absolute(url)) + (rest ? ' ' + rest : '');
                  });
                  el.setAttribute('srcset', parts.join(', '));
                }catch(e){}
              });
            }
          });
        }
      }
    });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });

    // Intercept clicks on anchors (ensure stay in proxy)
    document.addEventListener('click', function(e){
      const a = e.target.closest && e.target.closest('a[href]');
      if(!a) return;
      try{
        const href = a.getAttribute('href') || '';
        if(!href) return;
        if(href.startsWith('/proxy?url=') || href.startsWith('/')) return; // local
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = absolute(href);
        location.href = '/proxy?url=' + encodeURIComponent(abs);
      }catch(e){}
    }, true);

    // Intercept form submissions
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

    // Patch history APIs and window.open to stay inside proxy
    (function(h){ const push = h.pushState; h.pushState = function(s,t,u){ try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = '/proxy?url=' + encodeURIComponent(absolute(u)); }catch(e){} return push.apply(h, arguments); }; const rep = h.replaceState; h.replaceState = function(s,t,u){ try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = '/proxy?url=' + encodeURIComponent(absolute(u)); }catch(e){} return rep.apply(h, arguments); }; })(window.history);

    (function(){ const orig = window.open; window.open = function(u, ...rest){ try{ if(!u) return orig.apply(window, arguments); const abs = absolute(u); location.href = '/proxy?url=' + encodeURIComponent(abs); return null; }catch(e){ return orig.apply(window, arguments); } }; })();

    // Rewrite meta refresh tags
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
          m.setAttribute('content', parts[0] + ';url=' + '/proxy?url=' + encodeURIComponent(abs));
        }catch(e){}
      });
    }
    rewriteMetaRefresh();

    // initial post-load rewrite
    setTimeout(()=>{ rewriteAll(); rewriteMetaRefresh(); }, 500);
  }catch(e){}
})();
</script>
`;

// ---- /proxy endpoint ----
app.get("/proxy", async (req, res) => {
  try {
    let raw = extractUrlFromReq(req);
    if (!raw) raw = req.query.url;
    if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

    // Normalize user-friendly inputs
    if (!/^https?:\/\//i.test(raw)) {
      try {
        const maybe = decodeURIComponent(raw);
        if (looksLikeSearch(maybe)) raw = "https://www.google.com/search?q=" + encodeURIComponent(maybe);
        else raw = "https://" + maybe;
      } catch (e) {
        raw = "https://" + raw;
      }
    }

    // session
    const sess = getSession(req);
    persistSessionCookie(res, sess.sid);

    // cache key for HTML
    const keyHtml = raw + "::html";

    // Quick cache hit
    const cached = cacheGet(keyHtml);
    if (cached) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      persistSessionCookie(res, sess.sid);
      return res.send(cached);
    }

    // Build headers (pass through some client headers)
    const cookieHeader = buildCookieHeader(sess.data.cookies);
    const headers = {
      "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
      "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
      "Referer": req.headers.referer || undefined,
    };
    if (cookieHeader) headers["Cookie"] = cookieHeader;

    // Fetch origin (follow server-side redirects for simplicity)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // store set-cookie values in session
    const rawSetCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if (rawSetCookies.length) storeSetCookieStrings(rawSetCookies, sess.data);

    const contentType = originRes.headers.get("content-type") || "";

    // Non-HTML asset -> stream binary (cache small ones)
    if (!contentType.includes("text/html")) {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      // attempt small caching
      if (buf.length < 100 * 1024) {
        try {
          cacheSet(raw + "::asset", { headers: { "Content-Type": contentType }, body: buf.toString("base64") }, true);
        } catch (e) { }
      }
      // forward
      res.setHeader("Content-Type", contentType);
      const cacheControl = originRes.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      persistSessionCookie(res, sess.sid);
      return res.send(buf);
    }

    // HTML: get full string for rewriting
    let html = await originRes.text();

    // Defensive cleaning to avoid blocking our injected scripts
    // remove meta CSP tags
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // remove integrity / crossorigin attributes that break proxied assets
    html = html.replace(/\s(integrity|crossorigin)=["'][^"']*["']/gi, "");
    // remove <noscript> tags (sometimes contain fallback JS that confuses)
    html = html.replace(/<noscript[\s\S]*?<\/noscript>/gi, "");

    // inject base tag pointing to final origin to help relative resolution
    const finalUrl = originRes.url || raw;
    if (/<head\b/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // rewrite anchors -> /proxy?url=abs
    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, (m, pre, q, val) => {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // rewrite form actions
    html = html.replace(/(<\s*form[^>]*?\baction=)(["'])([^"']*)\2/gi, (m, pre, q, val) => {
      if (!val) return m;
      if (/^(javascript:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // rewrite src/href/srcset for common asset tags (img, script, link, source, video, audio)
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?\b(?:src|href|srcset)=)(["'])([^"']*)\2/gi, (m, prefix, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // rewrite CSS url(...) usage
    html = html.replace(/url\\((['"]?)(.*?)\\1\\)/gi, (m, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // rewrite meta refresh tags to proxy
    html = html.replace(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*>/gi, (m) => {
      const match = m.match(/content\\s*=\\s*["']([^"']*)["']/i);
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

    // remove known analytics scripts that degrade speed (best-effort)
    try {
      html = html.replace(/<script[^>]+src=(["'])[^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\\1[^>]*>[\\s\\S]*?<\\/script>/gi, "");
      html = html.replace(/<script[^>]*>(?:[^<]|<(?!\\/script>))*?(analytics|gtag|googlesyndication|googletagmanager)[\\s\\S]*?<\\/script>/gi, "");
    } catch (e) {
      // fallback - don't crash on regex issues
    }

    // insert protective CSS for images/videos to fit container and transparent backgrounds
    if (/<head/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m, g) => `${m}<style>img,video{max-width:100%;height:auto;display:block;max-height:100vh;}body{margin:0;background:transparent}</style>`);
    } else {
      html = `<style>img,video{max-width:100%;height:auto;display:block;max-height:100vh;}body{margin:0;background:transparent}</style>` + html;
    }

    // inject topbar + containment script right after <body>
    if (/<body\b/i.test(html)) {
      html = html.replace(/<body([^>]*)>/i, (m) => m + TOPBAR_INJECT);
    } else {
      html = TOPBAR_INJECT + html;
    }

    // Cache final HTML
    if (originRes.status === 200) {
      try { cacheSet(keyHtml, html, true); } catch (e) {}
    }

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, sess.sid);
    return res.send(html);

  } catch (err) {
    console.error("EUPHORIA proxy error:", err && err.message ? err.message : err);
    return res.status(500).send(`<div style="padding:1rem;background:#111;color:#fff;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// Serve index.html for root and SPA paths
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Fallback static
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// Start
app.listen(PORT, () => {
  console.log(`EUPHORIA proxy running on port ${PORT}`);
});
