// server.js — Euphoria single-endpoint proxy (no iframe, no puppeteer)
// - Serves both HTML and assets via /proxy?url=...
// - Injects the oval UI and containment script into HTML responses
// - Keeps navigation inside /proxy by rewriting links, forms, meta-refresh and intercepting runtime nav
import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import cookie from "cookie";
import morgan from "morgan";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---- Simple session cookie store (in-memory) ----
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24h
const SESSIONS = new Map();
function mkSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function now(){ return Date.now(); }
function createSession(){ const sid = mkSid(); const data = { cookies: new Map(), last: now() }; SESSIONS.set(sid, data); return { sid, data }; }
function getSession(req){
  const hdr = req.headers.cookie || "";
  const parsed = cookie.parse(hdr || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const data = SESSIONS.get(sid);
  data.last = now();
  return { sid, data };
}
function persistSessionCookie(res, sid){
  const sc = cookie.serialize(SESSION_NAME, sid, { httpOnly: true, path: "/", sameSite: "Lax", maxAge: 60*60*24 });
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", sc);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, sc]);
  else res.setHeader("Set-Cookie", [prev, sc]);
}
function storeSetCookieStrings(setCookies=[], sessionData){
  for(const sc of setCookies){
    try{
      const kv = sc.split(";")[0];
      const parsed = cookie.parse(kv || "");
      for(const k in parsed) if(k) sessionData.cookies.set(k, parsed[k]);
    }catch(e){}
  }
}
setInterval(()=>{ const cutoff = now() - SESSION_TTL; for(const [sid,data] of SESSIONS.entries()) if((data.last||0) < cutoff) SESSIONS.delete(sid); }, 1000*60*10);

// ---- Lightweight cache (memory + disk) ----
const CACHE_DIR = path.join(__dirname, "cache");
if(!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 5;

function cacheKey(k){ return Buffer.from(k).toString("base64url"); }
function cacheGet(k){
  const m = MEM_CACHE.get(k);
  if(m && (now()-m.t) < CACHE_TTL) return m.val;
  const f = path.join(CACHE_DIR, cacheKey(k));
  if(fs.existsSync(f)){
    try{
      const raw = fs.readFileSync(f, "utf8");
      const obj = JSON.parse(raw);
      if((now()-obj.t) < CACHE_TTL){ MEM_CACHE.set(k, { val: obj.val, t: obj.t }); return obj.val; }
      else try{ fs.unlinkSync(f) }catch(e){}
    }catch(e){}
  }
  return null;
}
function cacheSet(k,v){
  MEM_CACHE.set(k, { val: v, t: now() });
  try{ fs.writeFileSync(path.join(CACHE_DIR, cacheKey(k)), JSON.stringify({ val: v, t: now() }), "utf8"); }catch(e){}
}

// ---- Helpers ----
function toAbsolute(href, base){
  try{ return new URL(href, base).href; }catch(e){ return null; }
}
function buildCookieHeader(map){
  const parts = [];
  for(const [k,v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}
function extractUrl(req){
  if(req.query && req.query.url) return req.query.url;
  const m = req.path.match(/^\/proxy\/(.+)$/);
  if(m) return decodeURIComponent(m[1]);
  return null;
}
function isLikelySearch(input){
  if(!input) return true;
  if(input.includes(" ")) return true;
  if(/^https?:\/\//i.test(input)) return false;
  if(/\./.test(input)) return false;
  return true;
}
function normalizeInputToURL(input){
  const v = (input||"").trim();
  if(!v) return "https://www.google.com";
  if(isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if(/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// Injected UI (solid dark oval) + containment script (ensures navigation stays /proxy)
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
/* EUPHORIA containment script - keeps navigation inside /proxy and rewrites dynamic links */
(function(){
  try {
    // Helpers
    const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);
    const toLoad = toProxy; // same endpoint for HTML
    const absolute = (h) => { try { return new URL(h, document.baseURI).href } catch(e){ return h } };

    // UI wiring
    const input = document.getElementById('eph-input');
    const go = document.getElementById('eph-go');
    const back = document.getElementById('eph-back');
    const forward = document.getElementById('eph-forward');
    const refresh = document.getElementById('eph-refresh');
    const home = document.getElementById('eph-home');
    const full = document.getElementById('eph-full');

    // prefill input with proxied URL parameter if present
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
      // avoid double-wrapping if user pasted a /proxy?url= link
      if (/\\/proxy\\?url=/i.test(val)) { location.href = val; return; }
      const u = normalize(val);
      location.href = toLoad(u);
    };
    input.onkeydown = e => { if (e.key === 'Enter') go.onclick(); };
    back.onclick = () => history.back();
    forward.onclick = () => history.forward();
    refresh.onclick = () => location.reload();
    home.onclick = () => location.href = '/';
    full.onclick = () => { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

    // Rewrite existing anchors and assets in DOM
    function rewriteAnchor(a){
      try {
        if (!a || !a.getAttribute) return;
        const href = a.getAttribute('href');
        if (!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        // if already proxied, keep it
        if (href.startsWith('/proxy?url=')) return;
        const abs = absolute(href);
        a.setAttribute('href', toLoad(abs));
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
    }

    rewriteAll();

    // Watch for mutations to rewrite new nodes
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

    // Intercept clicks to ensure we navigate via /proxy
    document.addEventListener('click', function(e){
      const a = e.target.closest && e.target.closest('a[href]');
      if(!a) return;
      try {
        const href = a.getAttribute('href') || '';
        if(!href) return;
        if (href.startsWith('/proxy?url=') || href.startsWith('/')) return; // already proxied or local
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = absolute(href);
        location.href = toLoad(abs);
      } catch(e){}
    }, true);

    // Intercept form submits and rewrite action -> /proxy?url=abs
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

    // Patch history APIs to keep internal SPA navigation proxied if scripts call pushState/replaceState
    (function(history){ const push = history.pushState; history.pushState = function(s,t,u){
      try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toLoad(absolute(u)); }catch(e){}
      return push.apply(history, arguments);
    }; const rep = history.replaceState; history.replaceState = function(s,t,u){
      try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toLoad(absolute(u)); }catch(e){}
      return rep.apply(history, arguments);
    }; })(window.history);

    // Patch window.open to navigate the same tab via /proxy
    (function(){
      try{
        const orig = window.open;
        window.open = function(u, ...rest){
          try{ if(!u) return orig.apply(window, arguments); const abs = absolute(u); location.href = toLoad(abs); return null; }catch(e){ return orig.apply(window, arguments); }
        };
      }catch(e){}
    })();

    // Rewrite meta refresh tags dynamically
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
          m.setAttribute('content', parts[0] + ';url=' + toLoad(abs));
        }catch(e){}
      });
    }
    rewriteMetaRefresh();

    // run initial small delay rewrite for pages that mutate on load
    setTimeout(()=>{ rewriteAll(); rewriteMetaRefresh(); }, 500);
  }catch(e){}
})();
</script>
`;

// ---- /proxy endpoint ----
app.get("/proxy", async (req, res) => {
  let raw = extractUrl(req);
  if (!raw) raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  // normalize search / hostname inputs (if user typed plain host)
  if (!/^https?:\/\//i.test(raw)) {
    // if looks like a search query (no dot or contains space) -> google search
    try {
      const maybe = decodeURIComponent(raw);
      if (isLikelySearch(maybe)) raw = "https://www.google.com/search?q=" + encodeURIComponent(maybe);
      else raw = "https://" + maybe;
    } catch(e){ raw = "https://" + raw; }
  }

  // session
  const session = getSession(req);
  persistSessionCookie(res, session.sid);

  // caching key
  const keyHtml = raw + "::html";
  const assetKey = raw + "::asset";

  // If asset cached small
  try {
    const cachedAsset = cacheGet(assetKey);
    if (cachedAsset && !req.headers.accept?.includes("text/html")) {
      const obj = typeof cachedAsset === "string" ? JSON.parse(cachedAsset) : cachedAsset;
      if (obj.headers) Object.entries(obj.headers).forEach(([k,v])=>res.setHeader(k,v));
      return res.send(Buffer.from(obj.body, "base64"));
    }
  } catch(e){}

  // fetch origin, follow redirects server-side
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
    const timeout = setTimeout(()=>controller.abort(), 20000);
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // save set-cookie values to session
    const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if (setCookies.length) storeSetCookieStrings(setCookies, session.data);

    const contentType = originRes.headers.get("content-type") || "";

    // If non-HTML binary -> pipe bytes
    if (!contentType.includes("text/html")) {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      // cache small assets
      if (buf.length < 100*1024) {
        try { cacheSet(assetKey, JSON.stringify({ headers: { "Content-Type": contentType }, body: buf.toString("base64") })); } catch(e){}
      }
      // forward common headers
      res.setHeader("Content-Type", contentType);
      const cacheControl = originRes.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      persistSessionCookie(res, session.sid);
      return res.send(buf);
    }

    // HTML path
    const html = await originRes.text();

    // remove meta CSP tags which block our injected scripts/resources
    let out = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // remove integrity/crossorigin that will break proxied assets
    out = out.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    out = out.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // Inject base tag referencing origin's final URL (so relative resolution in JS still works when we absolute-ify links)
    const finalUrl = originRes.url || raw;
    if (/\<head/i.test(out)) {
      out = out.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      out = `<base href="${finalUrl}">` + out;
    }

    // Rewrite anchors, assets, forms, meta refresh, window.open occurrences in HTML source (best-effort)
    // Note: we avoid rewriting things already pointing to our /proxy to prevent loops.
    // anchors
    out = out.replace(/<a\b([^>]*?)href=(["'])([^"']*)\2/gi, (m, pre, q, val) => {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // asset tags: src/href/srcset -> /proxy
    out = out.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?(?:src|href|srcset)=)(["'])([^"']*)\2/gi, (m, prefix, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      if (val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // CSS url(...) -> /proxy
    out = out.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,val)=>{
      if(!val) return m;
      if(/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      if (abs.startsWith('/proxy?url=')) return m;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // form actions -> /proxy
    out = out.replace(/(<\s*form[^>]*action=)(["'])([^"']*)(["'])/gi, (m, pre, q1, val, q2) => {
      if(!val) return m;
      if(/^(javascript:|#)/i.test(val)) return m;
      if(val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q1}/proxy?url=${encodeURIComponent(abs)}${q2}`;
    });

    // meta refresh -> /proxy
    out = out.replace(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*>/gi, (m)=>{
      const match = m.match(/content\\s*=\\s*"(.*?)"/i);
      if(!match) return m;
      const parts = match[1].split(";");
      if(parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";");
      const uMatch = urlPart.match(/url=(.*)/i);
      if(!uMatch) return m;
      const dest = uMatch[1].replace(/['"]/g,"").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // remove some known analytics scripts (best-effort) to speed pages
    out = out.replace(/<script[^>]*src=(["'])[^\"]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^>]*\\1[^>]*><\\/script>/gi, "");

    // inject the topbar + containment script right after <body>
    if (/<body/i.test(out)) {
      out = out.replace(/<body([^>]*)>/i, (m)=> m + INJECT_TOPBAR_AND_CONTAINMENT);
    } else {
      // fallback - prepend
      out = INJECT_TOPBAR_AND_CONTAINMENT + out;
    }

    // Cache final HTML (successful 200)
    if (originRes.status === 200) cacheSet(keyHtml, out);

    // set content type and send
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    return res.send(out);

  } catch (err) {
    console.error("Euphoria proxy error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    res.status(500).send(`<div style="padding:1.5rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// Fallback: serve index.html for SPA paths
app.use((req,res,next)=>{
  if(req.method === "GET" && req.accepts("html")) return res.sendFile(path.join(__dirname,"public","index.html"));
  next();
});

app.listen(PORT, ()=> console.log(`Euphoria proxy running on port ${PORT}`));
