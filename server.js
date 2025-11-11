// server.js — Euphoria proxy (no iframe, scramjet streaming + websocket)
// Save as server.js (ESM)
import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import scramjetPkg from "scramjet"; // default import (scramjet is CommonJS under-the-hood)
const { StringStream, DataStream } = scramjetPkg;
import { WebSocketServer } from "ws";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

// middleware
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// serve single-file frontend
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// --- sessions (simple in-memory cookie store to persist set-cookie across proxied requests) ---
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24 hours
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function now(){ return Date.now(); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now() }; SESSIONS.set(sid, payload); return { sid, payload }; }
function getSessionFromReq(req){
  const cookieHeader = req.headers.cookie || "";
  const parsed = {};
  cookieHeader.split(";").forEach(p => {
    const [k,v] = p.split("=").map(s => (s||"").trim());
    if(k && v) parsed[k] = v;
  });
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid);
  payload.last = now();
  return { sid, payload };
}
function setSessionCookieHeader(res, sid){
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie", cookieStr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function storeSetCookieToSession(setCookies, sessionPayload){
  for(const sc of setCookies || []){
    try {
      const kv = sc.split(";")[0];
      const idx = kv.indexOf("=");
      if(idx === -1) continue;
      const k = kv.slice(0, idx).trim();
      const v = kv.slice(idx+1).trim();
      if(k) sessionPayload.cookies.set(k, v);
    } catch(e){}
  }
}

// --- simple memory + disk cache ---
const CACHE_DIR = path.join(__dirname, "cache");
if(!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes

function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const m = MEM_CACHE.get(key);
  if(m && (now() - m.t) < CACHE_TTL) return m.v;
  const file = path.join(CACHE_DIR, cacheKey(key));
  if(fs.existsSync(file)){
    try {
      const raw = fs.readFileSync(file, "utf8");
      const obj = JSON.parse(raw);
      if((now() - obj.t) < CACHE_TTL){ MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
      try { fs.unlinkSync(file); } catch(e){}
    } catch(e){}
  }
  return null;
}
function cacheSet(key, val){
  MEM_CACHE.set(key, { v: val, t: now() });
  try { fs.writeFileSync(path.join(CACHE_DIR, cacheKey(key)), JSON.stringify({ v: val, t: now() }), "utf8"); } catch(e){}
}

// helpers
function toAbsolute(href, base){
  try { return new URL(href, base).href; } catch(e) { return null; }
}
function buildCookieHeader(map){
  const parts = [];
  for(const [k,v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}
function extractProxyUrl(req){
  if(req.query && req.query.url) return req.query.url;
  // support /proxy/<encoded>
  const m = req.path.match(/^\/proxy\/(.+)/);
  if(m) return decodeURIComponent(m[1]);
  return null;
}
function looksLikeSearch(input){
  if(!input) return true;
  if(input.includes(" ")) return true;
  if(/^https?:\/\//i.test(input)) return false;
  if(/\./.test(input)) return false;
  return true;
}
function normalizeToUrl(input){
  const v = (input || "").trim();
  if(!v) return "https://www.google.com";
  if(looksLikeSearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if(/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// The HTML topbar + containment script that we'll inject into proxied pages.
// It's a fairly compact script that rewrites anchors/assets/forms/dynamic pushes to keep navigation going through /proxy?url=...
const INJECT = `
<!-- EUPHORIA TOPBAR INJECTION -->
<div id="euphoria-topbar" style="position:fixed;top:14px;left:50%;transform:translateX(-50%);width:min(1100px,86%);background:#111;border-radius:28px;padding:8px 10px;display:flex;gap:8px;align-items:center;z-index:2147483647;box-shadow:0 6px 20px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
  <button id="eph-back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" placeholder="Enter URL or search..." style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" />
  <button id="eph-go" style="min-width:48px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
</div>
<style>body{padding-top:86px !important;background:transparent !important;}</style>
<script>
(function(){
  try {
    const getAbs = (h) => { try { return new URL(h, document.baseURI).href } catch(e) { return h; } };
    const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);
    const input = document.getElementById('eph-input');
    const go = document.getElementById('eph-go');
    const back = document.getElementById('eph-back');
    const forward = document.getElementById('eph-forward');
    const refresh = document.getElementById('eph-refresh');
    const home = document.getElementById('eph-home');
    const full = document.getElementById('eph-full');
    // preload input from ?url= query
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
      if(isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
      try{ new URL(v); return v; }catch(e){}
      return 'https://' + v;
    }
    go.onclick = ()=> {
      const val = input.value;
      if(/\\/proxy\\?url=/i.test(val)){ location.href = val; return; }
      const u = normalize(val);
      location.href = toProxy(u);
    };
    input.onkeydown = e => { if(e.key === 'Enter') go.onclick(); };
    back.onclick = ()=> history.back();
    forward.onclick = ()=> history.forward();
    refresh.onclick = ()=> location.reload();
    home.onclick = ()=> location.href = '/';
    full.onclick = ()=> { if(!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

    function rewriteAnchor(a){
      try {
        if(!a || !a.getAttribute) return;
        const href = a.getAttribute('href');
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(href.startsWith('/proxy?url=')) { a.removeAttribute('target'); return; }
        const abs = getAbs(href);
        a.setAttribute('href', toProxy(abs));
        a.removeAttribute('target');
      } catch(e){}
    }
    function rewriteAsset(el, attr){
      try {
        if(!el || !el.getAttribute) return;
        const v = el.getAttribute(attr);
        if(!v) return;
        if(/^data:/i.test(v)) return;
        if(v.startsWith('/proxy?url=')) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(v)) return;
        const abs = getAbs(v);
        el.setAttribute(attr, '/proxy?url=' + encodeURIComponent(abs));
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
            return '/proxy?url=' + encodeURIComponent(getAbs(url)) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }catch(e){}
      });
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
                const ss = el.getAttribute('srcset'); if(!ss) return;
                const parts = ss.split(',').map(p=>{
                  const [url, rest] = p.trim().split(/\\s+/,2);
                  if(!url) return p;
                  if(/^data:/i.test(url)) return p;
                  return '/proxy?url=' + encodeURIComponent(getAbs(url)) + (rest ? ' ' + rest : '');
                });
                el.setAttribute('srcset', parts.join(', '));
              });
            }
          });
        }
      }
    });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });
    document.addEventListener('click', function(e){
      const a = e.target.closest && e.target.closest('a[href]');
      if(!a) return;
      try {
        const href = a.getAttribute('href') || '';
        if(!href) return;
        if(href.startsWith('/proxy?url=')||href.startsWith('/')) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = getAbs(href);
        location.href = toProxy(abs);
      } catch(e){}
    }, true);
    document.addEventListener('submit', function(e){
      const f = e.target;
      if(!f) return;
      try{
        const a = f.getAttribute('action') || '';
        if(!a) return;
        if(a.startsWith('/proxy?url=')) return;
        if(/^(javascript:|#)/i.test(a)) return;
        const abs = getAbs(a);
        f.setAttribute('action', '/proxy?url=' + encodeURIComponent(abs));
      }catch(e){}
    }, true);
    (function(history){
      const push = history.pushState;
      history.pushState = function(s,t,u){
        try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(getAbs(u)); }catch(e){}
        return push.apply(history, arguments);
      };
      const rep = history.replaceState;
      history.replaceState = function(s,t,u){
        try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(getAbs(u)); }catch(e){}
        return rep.apply(history, arguments);
      };
    })(window.history);
    (function(){ try{ const orig = window.open; window.open = function(u,...rest){ try{ if(!u) return orig.apply(window, arguments); const abs = getAbs(u); location.href = '/proxy?url=' + encodeURIComponent(abs); return null; }catch(e){ return orig.apply(window, arguments); } }; }catch(e){} })();
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
          const abs = getAbs(dest);
          m.setAttribute('content', parts[0] + ';url=' + '/proxy?url=' + encodeURIComponent(abs));
        }catch(e){}
      });
    }
    rewriteMetaRefresh();
    setTimeout(()=>{ rewriteAll(); rewriteMetaRefresh(); }, 500);
  } catch(e) { /* swallow */ }
})();
</script>
`;

// --- WebSocket server for telemetry / streaming notifications ---
const server = app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", (raw) => {
    try {
      const parsed = JSON.parse(raw.toString());
      // echo-ish or do small commands
      if(parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch(e){}
  });
});

// --- main proxy endpoint ---
app.get("/proxy", async (req, res) => {
  let raw = extractProxyUrl(req) || req.query.url;
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // Allow human typed hostnames or searches (if user clicked from file:// frontend)
  if(!/^https?:\/\//i.test(raw)){
    try {
      const maybe = decodeURIComponent(raw);
      if(looksLikeSearch(maybe)) raw = "https://www.google.com/search?q=" + encodeURIComponent(maybe);
      else raw = "https://" + maybe;
    } catch(e){
      raw = "https://" + raw;
    }
  }

  const session = getSessionFromReq(req);
  setSessionCookieHeader(res, session.sid);

  // caching keys
  const cacheKeyHtml = raw + "::html";
  const cacheKeyAsset = raw + "::asset";

  // small asset cache quick return (only for non-HTML acceptance)
  try {
    const accept = req.headers.accept || "";
    if(!accept.includes("text/html")){
      const cached = cacheGet(cacheKeyAsset);
      if(cached){
        if(cached.headers) Object.entries(cached.headers).forEach(([k,v]) => res.setHeader(k,v));
        return res.send(Buffer.from(cached.body, "base64"));
      }
    }
  } catch(e){}

  // prefer cached HTML for fast response
  const cachedHtml = cacheGet(cacheKeyHtml);
  if(cachedHtml && req.headers.accept && req.headers.accept.includes("text/html")){
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    setSessionCookieHeader(res, session.sid);
    return res.send(cachedHtml);
  }

  // Prepare fetch headers (pass through user agent, accept-language, use session cookies)
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) headers["Cookie"] = cookieHdr;
  if(req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    const controller = new AbortController();
    const to = setTimeout(()=> controller.abort(), 20000);
    // follow redirects server-side to get final URL
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(to);

    // capture set-cookie headers
    const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    const contentType = (originRes.headers.get("content-type") || "").toLowerCase();

    // If non-html, return raw buffer (images, js, css, etc.)
    if(!contentType.includes("text/html")){
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      // cache small assets
      if(buf.length < 128 * 1024){
        try {
          cacheSet(cacheKeyAsset, { headers: { "Content-Type": contentType }, body: buf.toString("base64") });
        } catch(e){}
      }
      // forward common headers
      res.setHeader("Content-Type", contentType);
      const cacheControl = originRes.headers.get("cache-control");
      if(cacheControl) res.setHeader("Cache-Control", cacheControl);
      setSessionCookieHeader(res, session.sid);
      return res.send(buf);
    }

    // HTML path
    let html = await originRes.text();

    // remove problematic meta CSP tags and strict CSP which block our injected scripts/resources
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // remove integrity / crossorigin attributes that will break proxied assets
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

    // Inject base tag so relative resolves still work for scripts that build relative URLs
    const finalUrl = originRes.url || raw;
    if(/<head[\s>]/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, function(_, g){ return `<head${g}><base href="${finalUrl}">`; });
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // Rewrite: anchors -> /proxy?url=abs
    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function(m, pre, q, val){
      if(!val) return m;
      if(/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if(val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // Rewrite asset tags (img/script/link/source/video/audio/iframe) src/href/srcset
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|srcset)=)(["'])([^"']*)\3/gi, function(m, prefix, attr, q, val){
      if(!val) return m;
      if(/^data:/i.test(val)) return m;
      if(val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      // srcset needs special handling elsewhere; but this will catch many
      return `${prefix}${attr}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // CSS url(...) -> proxied
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, function(m, q, val){
      if(!val) return m;
      if(/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Form actions -> proxy
    html = html.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function(m, pre, q, val){
      if(!val) return m;
      if(/^(javascript:|#)/i.test(val)) return m;
      if(val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // Meta refresh rewrite
    html = html.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi, function(m){
      const match = m.match(/content\s*=\s*["']([^"']*)["']/i);
      if(!match) return m;
      const parts = match[1].split(";");
      if(parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
      if(!urlPart) return m;
      const dest = urlPart[1].replace(/['"]/g,"").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // Remove/strip some heavy analytics scripts (best effort) to speed loads (do NOT try to remove every script)
    try {
      // remove <script src="...analytics..."></script> (simple)
      html = html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi, "");
      // remove inline known trackers by pattern (light)
      html = html.replace(/<script[^>]*>\s*window\.ga=\s*.*?<\/script>/gi, "");
    } catch(e){}

    // Inject the topbar and containment script directly after <body>
    if(/<body[^>]*>/i.test(html)){
      html = html.replace(/<body([^>]*)>/i, function(m,g){ return `<body${g}>` + INJECT; });
    } else {
      html = INJECT + html;
    }

    // Cache HTML if status 200
    if(originRes.status === 200){
      try { cacheSet(cacheKeyHtml, html); } catch(e){}
    }

    // stream to client progressively using scramjet StringStream
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    setSessionCookieHeader(res, session.sid);

    // small progressive streaming: pipe string chunks with a short delay to improve time-to-first-paint on client
    // We'll send in 32KB chunks (or full HTML if smaller). Using StringStream helps memory usage.
    try {
      const stream = StringStream.from(html);
      stream.pipe(res);
      stream.on("end", ()=> {
        try { res.end(); } catch(e){}
      });
      stream.on("error", ()=> { try { res.end(); } catch(e){} });
    } catch(e){
      // fallback: send full body
      res.send(html);
    }
  } catch(err){
    console.error("Euphoria proxy error:", err && err.message ? err.message : err);
    setSessionCookieHeader(res, session.sid);
    res.status(500).send(`<div style="padding:1rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// fallback to serve public/index.html for root and other HTML accept paths
app.use((req, res, next) => {
  if(req.method === "GET" && req.accepts && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});
