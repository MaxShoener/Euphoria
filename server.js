// server.js — fixed: prevents /proxy recursion, safer streaming, no headers-after-send
import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fsPromises from "fs/promises";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import scramjetPkg from "scramjet";
const { StringStream } = scramjetPkg;
import { WebSocketServer } from "ws";
import { pipeline } from "stream";
import { promisify } from "util";
import { EventEmitter } from "events";

EventEmitter.defaultMaxListeners = 50;
const pipe = promisify(pipeline);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

// Basic config
const CACHE_TTL = 1000 * 60 * 6;
const ASSET_CACHE_MAX_SIZE = 128 * 1024;
const FETCH_TIMEOUT_MS = 25000;
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");
if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// simple in-memory cache + async disk writes
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheGet(k) { const e = MEM_CACHE.get(k); if (!e) return null; if ((now() - e.t) > CACHE_TTL) { MEM_CACHE.delete(k); return null; } return e.v; }
function cacheSet(k, v) { MEM_CACHE.set(k, { v, t: now() }); if (ENABLE_DISK_CACHE) { const fname = path.join(CACHE_DIR, encodeURIComponent(Buffer.from(k).toString("base64"))); (async () => { try { await fsPromises.writeFile(fname, JSON.stringify({ t: now(), v }), "utf8"); } catch (e) {} })(); } }

// sessions
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now() }; SESSIONS.set(sid, payload); return { sid, payload }; }
function getSessionFromReq(req){
  const cookieHeader = req.headers.cookie || "";
  const parsed = {};
  cookieHeader.split(";").forEach(p => {
    const [k,v] = (p||"").split("=").map(s => (s||"").trim());
    if(k && v) parsed[k] = v;
  });
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid); payload.last = now(); return { sid, payload };
}
function setSessionCookieHeaderIfSafe(res, sid){
  // set cookie only if headers not sent
  if (res.headersSent) return;
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie", cookieStr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function setSessionCookieHeader(res, sid){
  // use this before streaming begins
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie", cookieStr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function storeSetCookieToSession(setCookies, sessionPayload){
  for(const sc of setCookies||[]){
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
function buildCookieHeader(map){
  return [...map.entries()].map(([k,v])=>`${k}=${v}`).join("; ");
}

// helpers
function toAbsolute(href, base){
  try { return new URL(href, base).href; } catch(e) { return null; }
}
function looksLikeSearch(input){
  if(!input) return true;
  if(input.includes(" ")) return true;
  if(/^https?:\/\//i.test(input)) return false;
  if(/\./.test(input)) return false;
  return true;
}
function normalizeToUrl(input){
  const v = (input||"").trim();
  if(!v) return "https://www.google.com";
  if(looksLikeSearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if(/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}
function isAlreadyProxiedHref(href, ourHost){
  if(!href) return false;
  try{
    if(href.includes("/proxy?url=")) return true;
    // if it's a full URL and points back to our host + path starting with /proxy -> considered proxied
    const u = new URL(href, `https://${ourHost}`);
    if(u.host === ourHost && u.pathname.startsWith("/proxy")) return true;
  } catch(e){}
  return false;
}

// Injection (topbar + rewrite). The client rewrite script now *explicitly skips* any href that already contains '/proxy?url=' or that resolves to our host /proxy path.
const INJECT_TOPBAR_HTML = `
<style>
#euphoria-topbar{position:fixed;top:12px;left:50%;transform:translateX(-50%);width:min(1100px,86%);background:rgba(255,255,255,0.92);border-radius:28px;padding:8px 10px;display:flex;gap:8px;align-items:center;z-index:2147483647;box-shadow:0 6px 20px rgba(0,0,0,0.12);backdrop-filter:blur(6px);color:#000;font-family:system-ui,Arial;}
#euphoria-topbar button{min-width:44px;padding:8px;border-radius:10px;border:0;background:#eee;cursor:pointer}
#euphoria-topbar input{flex:1;padding:8px 12px;border-radius:12px;border:0;background:#fff}
#euphoria-loading{position:fixed;top:0;left:0;width:0%;height:3px;background:#2e7d32;transition:width .18s;z-index:2147483648}
</style>
<div id="euphoria-topbar" aria-hidden="false">
  <button id="eph-back">◀</button>
  <button id="eph-forward">▶</button>
  <button id="eph-refresh">⟳</button>
  <button id="eph-home">🏠</button>
  <input id="eph-input" placeholder="Enter URL or search" />
  <button id="eph-go">Go</button>
  <button id="eph-full">⛶</button>
</div>
<div id="euphoria-loading" aria-hidden="true"></div>
<script>
(function(){
  const i=document.getElementById('eph-input'), g=document.getElementById('eph-go'), b=document.getElementById('eph-back'), f=document.getElementById('eph-forward'), r=document.getElementById('eph-refresh'), h=document.getElementById('eph-home'), full=document.getElementById('eph-full'), loading=document.getElementById('euphoria-loading');
  function normalize(v){v=(v||'').trim(); if(!v) return 'https://www.google.com'; if(v.includes(' ')||!/\\./.test(v)) return 'https://www.google.com/search?q='+encodeURIComponent(v); if(/^https?:\\/\\//i.test(v)) return v; return 'https://'+v;}
  g.onclick=()=>{ const u=normalize(i.value); location.href='/proxy?url='+encodeURIComponent(u); };
  i.onkeydown=e=>{ if(e.key==='Enter') g.onclick(); };
  b.onclick=()=>history.back(); f.onclick=()=>history.forward(); r.onclick=()=>location.reload(); h.onclick=()=>location.href='/proxy?url='+encodeURIComponent('https://www.google.com');
  full.onclick=()=>{ if(!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };
  window.addEventListener('beforeunload', ()=> loading.style.width='10%');
  window.addEventListener('load', ()=> { loading.style.width='100%'; setTimeout(()=>loading.style.width='0%',300);});
  try{ const m=location.search.match(/[?&]url=([^&]+)/); if(m) i.value=decodeURIComponent(m[1]); } catch(e){}
})();
</script>
`;

// Minimal but robust client-side rewrite — skip hrefs that already point to our /proxy or contain /proxy?url=
const INJECT_REWRITE_SCRIPT = `
<script>
(function(){
  function proxify(u){
    try{
      // Do not wrap already proxied links or links that point to our own /proxy
      if(!u) return u;
      if(u.includes('/proxy?url=')) return u;
      const abs = new URL(u, document.baseURI).href;
      // if the abs already resolves to our host+ /proxy path, don't wrap
      try { const me = location.host; if(abs.includes(me) && (abs.indexOf('/proxy')!==-1)) return abs; } catch(e) {}
      return '/proxy?url=' + encodeURIComponent(abs);
    } catch(e){ return u; }
  }
  // anchors
  document.querySelectorAll('a[href]').forEach(a=>{
    try{
      const h=a.getAttribute('href'); if(!h) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return;
      if(h.includes('/proxy?url=')) return;
      a.setAttribute('href', proxify(h));
      a.removeAttribute('target');
    }catch(e){}
  });
  // forms
  document.querySelectorAll('form[action]').forEach(f=>{
    try{ const a=f.getAttribute('action'); if(!a) return; if(a.includes('/proxy?url=')) return; f.setAttribute('action', proxify(a)); }catch(e){}
  });
  // assets & srcset
  const tags=['img','script','link','iframe','source','video','audio'];
  tags.forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      try{
        ['src','href'].forEach(attr=>{
          const v = el.getAttribute && el.getAttribute(attr); if(!v) return;
          if(/^data:/i.test(v)) return;
          if(v.includes('/proxy?url=')) return;
          el.setAttribute(attr, proxify(v));
        });
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset')||'';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }
      }catch(e){}
    });
  });
  // css url(...) in style tags
  try {
    document.querySelectorAll('style').forEach(s=>{
      try{
        let t=s.textContent; if(!t) return;
        t = t.replace(/url\$begin:math:text$(['"]?)(.*?)\\\\1\\$end:math:text$/g, function(full,q,u){
          if(!u) return full; if(/^data:/i.test(u) || u.includes('/proxy?url=')) return full;
          try { const abs=new URL(u, document.baseURI).href; return 'url(\"/proxy?url=' + encodeURIComponent(abs) + '\")'; } catch(e){ return full; }
        });
        s.textContent = t;
      }catch(e){}
    });
  } catch(e){}
  // intercept fetch
  try{
    const orig = window.fetch;
    window.fetch = function(resource, init){
      try{
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')){
          resource = '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request){
          if(!resource.url.includes('/proxy?url=')) resource = new Request('/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      }catch(e){}
      return orig(resource, init);
    };
  }catch(e){}
})();
</script>
`;

// websocket for telemetry
const server = app.listen(PORT, () => console.log('Euphoria proxy running on port', PORT));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try { const p = JSON.parse(raw.toString()); if(p.cmd==='ping') ws.send(JSON.stringify({ msg:'pong', ts: Date.now() })); } catch(e){}
  });
});

// main proxy endpoint
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if(!raw) return res.status(400).send("Missing url");

  // normalize simple inputs
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);

  // check accepts
  const accept = (req.headers.accept || "").toLowerCase();

  // asset cache quick-return
  const assetCacheKey = raw + "::asset";
  if(!accept.includes("text/html")) {
    const cached = cacheGet(assetCacheKey);
    if(cached){
      if(cached.headers) Object.entries(cached.headers).forEach(([k,v]) => res.setHeader(k,v));
      // set cookie before sending
      setSessionCookieHeader(res, session.sid);
      try { return res.send(Buffer.from(cached.body,'base64')); } catch(e) {}
    }
  }

  // HTML cache
  const htmlCacheKey = raw + "::html";
  if(accept.includes("text/html")) {
    const ch = cacheGet(htmlCacheKey);
    if(ch){
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      setSessionCookieHeader(res, session.sid);
      return res.send(ch);
    }
  }

  // prepare origin headers
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) headers["Cookie"] = cookieHdr;
  if(req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    const controller = new AbortController();
    const tm = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(tm);

    // capture set-cookie
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    const contentType = (originRes.headers.get("content-type") || "").toLowerCase();

    // non-HTML: stream with header forwarding
    if(!contentType.includes("text/html")){
      // prepare headers BEFORE streaming
      const cencoding = originRes.headers.get("content-encoding");
      const clen = originRes.headers.get("content-length");
      const cacheControl = originRes.headers.get("cache-control");
      const ct = originRes.headers.get("content-type");

      if(ct) res.setHeader("Content-Type", ct);
      if(cencoding) res.setHeader("Content-Encoding", cencoding);
      if(clen) res.setHeader("Content-Length", clen);
      if(cacheControl) res.setHeader("Cache-Control", cacheControl);
      res.setHeader("Vary", "Accept-Encoding");
      res.setHeader("Access-Control-Allow-Origin", "*");

      // set cookie header BEFORE streaming begins
      setSessionCookieHeader(res, session.sid);

      // cache small assets
      const contentLengthNumber = clen ? parseInt(clen, 10) : NaN;
      if(!isNaN(contentLengthNumber) && contentLengthNumber <= ASSET_CACHE_MAX_SIZE){
        try {
          const arr = await originRes.arrayBuffer();
          const buf = Buffer.from(arr);
          cacheSet(assetCacheKey, { headers: { "Content-Type": ct }, body: buf.toString("base64") });
          return res.send(buf);
        } catch(e){
          // fallthrough to streaming
        }
      }

      // stream using pipeline (preserves encoding)
      if(originRes.body && typeof originRes.body.pipe === "function"){
        try {
          await pipe(originRes.body, res);
          return;
        } catch(pipeErr){
          // log and attempt graceful fallback — but do NOT set headers after send
          console.warn("Asset pipeline error:", pipeErr && pipeErr.message);
          try { res.end(); } catch(e){}
          return;
        }
      } else {
        // fallback
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        return res.send(buf);
      }
    }

    // HTML path
    let html = await originRes.text();

    // strip CSP meta tags
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // strip integrity/crossorigin
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

    const finalUrl = originRes.url || raw;

    // inject base
    if(/<head[\s>]/i.test(html)) html = html.replace(/<head([^>]*)>/i, (m,g)=>`<head${g}><base href="${finalUrl}">`);
    else html = `<base href="${finalUrl}">` + html;

    // server-side rewrite — avoid double-proxying:
    const ourHost = req.headers.host || "localhost";

    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function(m, pre, q, val){
      if(!val) return m;
      if(/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if(isAlreadyProxiedHref(val, ourHost)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|srcset)=)(["'])([^"']*)\3/gi,
      function(m, prefix, attr, q, val){
        if(!val) return m;
        if(isAlreadyProxiedHref(val, ourHost) || /^data:/i.test(val)) return m;
        const abs = toAbsolute(val, finalUrl) || val;
        if(attr.toLowerCase().startsWith("srcset")){
          const parts = val.split(",").map(p=>{
            const [u, rest] = p.trim().split(/\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            const a = toAbsolute(u, finalUrl) || u;
            return `/proxy?url=${encodeURIComponent(a)}` + (rest? " " + rest : "");
          });
          return `${prefix}${attr}${q}${parts.join(", ")}${q}`;
        }
        return `${prefix}${attr}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
      });

    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, function(m, q, val){
      if(!val) return m;
      if(/^data:/i.test(val)) return m;
      if(isAlreadyProxiedHref(val, ourHost)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    html = html.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function(m, pre, q, val){
      if(!val) return m;
      if(isAlreadyProxiedHref(val, ourHost) || /^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

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

    // remove trackers (best-effort)
    html = html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi, "");
    html = html.replace(/<script[^>]*>\s*window\.ga=.*?<\/script>/gi, "");

    // inject topbar + rewrite script only if topbar absent
    if(!/id=(["'])?euphoria-topbar\1?/i.test(html)){
      if(/<body[^>]*>/i.test(html)) html = html.replace(/<body([^>]*)>/i, (m,g)=>`<body${g}>` + INJECT_TOPBAR_HTML + INJECT_REWRITE_SCRIPT);
      else html = INJECT_TOPBAR_HTML + INJECT_REWRITE_SCRIPT + html;
    } else {
      if(/<body[^>]*>/i.test(html)) html = html.replace(/<body([^>]*)>/i, (m,g)=>`<body${g}>` + INJECT_REWRITE_SCRIPT);
      else html = INJECT_REWRITE_SCRIPT + html;
    }

    // cache html
    try { cacheSet(htmlCacheKey, html); } catch(e){}

    // set headers BEFORE streaming
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Access-Control-Allow-Origin", "*");
    setSessionCookieHeader(res, session.sid);

    // stream via StringStream -> pipe to res
    const stream = StringStream.from(html);
    try {
      await pipe(stream, res);
    } catch(pipeErr){
      console.error("HTML stream pipe error:", pipeErr && pipeErr.message);
      try { if(!res.headersSent) res.status(502).end("Stream error"); else res.end(); } catch(e){}
    }
    return;

  } catch(err){
    console.error("Proxy error:", err && err.message ? err.message : err);
    // only set cookie if headers not sent
    try { setSessionCookieHeaderIfSafe(res, session.sid); } catch(e){}
    if(!res.headersSent) return res.status(502).send(`<div style="padding:1rem;background:#fee;color:#900;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
    try { res.end(); } catch(e){}
    return;
  }
});

// serve index.html fallback
app.use((req,res,next)=>{
  if(req.method === "GET" && req.accepts && req.accepts("html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

console.log("Euphoria proxy (fixed) ready on port", PORT);