// server.js — Euphoria proxy (fixed for deployment domain, single-inject, robust streaming + proxy-all)
//
// Important:
// - package.json must set "type": "module"
// - dependencies: express, node-fetch, scramjet, ws, compression, morgan, cors
//
// Behavior fixes in this file:
// - Prevent nested /proxy recursion by rewriting to hard-coded deployment origin
// - Inject topbar only once using a marker comment <!--EUPHORIA-UI-INJECTED-->
// - Preserve site CSS/scripts; do not force dark themes
// - Rewrite many asset attributes (src, href, data-src, poster, srcset, data-srcset) to proxy through deployment
// - Stream binary assets with pipeline and forward Content-Encoding and relevant headers
// - Set session cookie & other headers before starting to stream
// - Avoid setting headers after res.headersSent
// - Increase EventEmitter default listeners to avoid warnings
//
// Replace DEPLOYMENT_ORIGIN with your deployment domain (no trailing slash).
const DEPLOYMENT_ORIGIN = "https://useful-karil-maxshoener-6cb890d9.koyeb.app";

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

// -------- configuration --------
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX_SIZE = 128 * 1024; // 128 KB
const FETCH_TIMEOUT_MS = 25000;
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");

// ensure cache dir exists (async)
if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// -------- middleware --------
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -------- simple memory cache (non-blocking disk writes optional) --------
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheGet(key) {
  const e = MEM_CACHE.get(key);
  if (!e) return null;
  if ((now() - e.t) > CACHE_TTL) { MEM_CACHE.delete(key); return null; }
  return e.v;
}
function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, encodeURIComponent(Buffer.from(key).toString("base64")));
    (async () => {
      try { await fsPromises.writeFile(fname, JSON.stringify({ t: now(), v: val }), "utf8"); } catch (e) {}
    })();
  }
}

// -------- sessions/cookies --------
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
  const payload = SESSIONS.get(sid);
  payload.last = now();
  return { sid, payload };
}
function setSessionCookieHeader(res, sid){
  // Always set cookie BEFORE streaming begins
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie", cookieStr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function setSessionCookieHeaderIfSafe(res, sid){
  if(res.headersSent) return;
  setSessionCookieHeader(res, sid);
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
function buildCookieHeader(map){
  return [...map.entries()].map(([k,v]) => `${k}=${v}`).join("; ");
}

// -------- helpers --------
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
  const v = (input || "").trim();
  if(!v) return "https://www.google.com";
  if(looksLikeSearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if(/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// consider something proxied if it already contains /proxy?url= or points back to our deployment origin /proxy path
function isAlreadyProxiedHref(href){
  if(!href) return false;
  try {
    if(href.includes("/proxy?url=")) return true;
    // If the href resolves to our DEPLOYMENT_ORIGIN and has /proxy path, treat as proxied
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if(resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch(e){}
  return false;
}

// produce proxied absolute URL pointing explicitly at our deployment origin
function proxyizeAbsoluteUrl(absUrl){
  // ensure encoded and absolute
  try {
    const u = new URL(absUrl);
    return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch(e) {
    // fallback: try to prefix https
    try {
      const u2 = new URL("https://" + absUrl);
      return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`;
    } catch(e2) {
      return absUrl;
    }
  }
}

// coerce a possibly relative link into deployment-proxied absolute link
function toDeploymentProxyLink(href, base){
  if(!href) return href;
  if(isAlreadyProxiedHref(href)) {
    // if already proxied but relative to another host (e.g., google.com/proxy), ensure it points to our deployment
    try {
      const maybe = new URL(href, base);
      if(maybe.pathname.startsWith("/proxy")) {
        // extract original target from url param if present, else leave as-is
        const urlParam = maybe.searchParams.get("url");
        if(urlParam) return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(urlParam)}`;
      }
    } catch(e){}
    return href;
  }
  // absolute-ify then proxyize
  const abs = toAbsolute(href, base) || href;
  return proxyizeAbsoluteUrl(abs);
}

// -------- injection content --------
// marker ensures topbar is injected only once
const INJECT_MARKER = "<!--EUPHORIA-UI-INJECTED-->";

// translucent topbar HTML (light look) and loading bar
const INJECT_TOPBAR_HTML = `
${INJECT_MARKER}
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
  g.onclick=()=>{ const u=normalize(i.value); location.href='${DEPLOYMENT_ORIGIN}/proxy?url='+encodeURIComponent(u); };
  i.onkeydown=e=>{ if(e.key==='Enter') g.onclick(); };
  b.onclick=()=>history.back(); f.onclick=()=>history.forward(); r.onclick=()=>location.reload(); h.onclick=()=>location.href='${DEPLOYMENT_ORIGIN}/proxy?url='+encodeURIComponent('https://www.google.com');
  full.onclick=()=>{ if(!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };
  window.addEventListener('beforeunload', ()=> loading.style.width='10%');
  window.addEventListener('load', ()=> { loading.style.width='100%'; setTimeout(()=>loading.style.width='0%',300);});
  try{ const m=location.search.match(/[?&]url=([^&]+)/); if(m) i.value=decodeURIComponent(m[1]); } catch(e){}
})();
</script>
`;

// rewrite script (client-side) — ensures links/assets are proxied to our deployment origin instead of relative /proxy on target domains
const INJECT_REWRITE_SCRIPT = `
<script>
(function(){
  function proxyize(u){
    try {
      if(!u) return u;
      if(u.includes('/proxy?url=')) return u;
      const abs = new URL(u, document.baseURI).href;
      // If this already points to our deployment origin's /proxy, return it
      try { if(abs.startsWith('${DEPLOYMENT_ORIGIN}/proxy')) return abs; } catch(e){}
      return '${DEPLOYMENT_ORIGIN}/proxy?url=' + encodeURIComponent(abs);
    } catch(e) { return u; }
  }

  // rewrite anchors
  document.querySelectorAll('a[href]').forEach(a=>{
    try {
      const h = a.getAttribute('href'); if(!h) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return;
      if(h.includes('/proxy?url=')) return;
      a.setAttribute('href', proxyize(h));
      a.removeAttribute('target');
    } catch(e){}
  });

  // rewrite forms
  document.querySelectorAll('form[action]').forEach(f=>{
    try { const a=f.getAttribute('action'); if(!a) return; if(a.includes('/proxy?url=')) return; f.setAttribute('action', proxyize(a)); } catch(e){}
  });

  // rewrite many asset attributes and srcset/data-src/data-srcset/poster
  const attrs = ['src','href','poster','data-src','data-href'];
  const tags = ['img','script','link','iframe','source','video','audio'];
  tags.forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      try{
        attrs.forEach(attr=>{
          if(el.hasAttribute && el.hasAttribute(attr)){
            const v = el.getAttribute(attr);
            if(!v) return;
            if(/^data:/i.test(v)) return;
            if(v.includes('/proxy?url=')) return;
            el.setAttribute(attr, proxyize(v));
          }
        });
        // srcset and data-srcset
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return '${DEPLOYMENT_ORIGIN}/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }
        if(el.hasAttribute && el.hasAttribute('data-srcset')){
          const ss = el.getAttribute('data-srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return '${DEPLOYMENT_ORIGIN}/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('data-srcset', parts.join(', '));
        }
      }catch(e){}
    });
  });

  // rewrite CSS url(...) inside style tags (best-effort)
  try {
    document.querySelectorAll('style').forEach(s=>{
      try{
        let t = s.textContent;
        if(!t) return;
        t = t.replace(/url\$begin:math:text$(['"]?)(.*?)\\\\1\\$end:math:text$/g, function(full,q,u){
          if(!u) return full;
          if(/^data:/i.test(u) || u.includes('/proxy?url=')) return full;
          try { const abs = new URL(u, document.baseURI).href; return 'url("${DEPLOYMENT_ORIGIN}/proxy?url=' + encodeURIComponent(abs) + '")'; } catch(e){ return full; }
        });
        s.textContent = t;
      } catch(e){}
    });
  } catch(e){}

  // intercept fetch/XHR to proxy automatically
  try {
    const orig = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')){
          resource = '${DEPLOYMENT_ORIGIN}/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request){
          if(!resource.url.includes('/proxy?url=')) resource = new Request('${DEPLOYMENT_ORIGIN}/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      } catch(e){}
      return orig(resource, init);
    };
  } catch(e){}
})();
</script>
`;

// -------- WebSocket telemetry --------
const server = app.listen(PORT, () => console.log(`Euphoria proxy ready on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try {
      const p = JSON.parse(raw.toString());
      if(p.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch(e){}
  });
});

// -------- main proxy endpoint --------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize human input like "google.com"
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  const accept = (req.headers.accept || "").toLowerCase();

  // asset quick cache
  const assetCacheKey = raw + "::asset";
  if(!accept.includes("text/html")) {
    const cached = cacheGet(assetCacheKey);
    if(cached){
      if(cached.headers) Object.entries(cached.headers).forEach(([k,v]) => res.setHeader(k, v));
      // set cookie BEFORE sending
      setSessionCookieHeader(res, session.sid);
      try { return res.send(Buffer.from(cached.body, "base64")); } catch(e) {}
    }
  }

  // html cache
  const htmlCacheKey = raw + "::html";
  if(accept.includes("text/html")){
    const cachedHtml = cacheGet(htmlCacheKey);
    if(cachedHtml){
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      setSessionCookieHeader(res, session.sid);
      return res.send(cachedHtml);
    }
  }

  // build origin request headers (allow compressed responses)
  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if(req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    const originRes = await fetch(raw, { headers: originHeaders, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // capture set-cookie into session
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    const contentType = (originRes.headers.get("content-type") || "").toLowerCase();

    // Non-HTML: stream binary (images, js, css, fonts, etc.)
    if(!contentType.includes("text/html")) {
      // set response headers BEFORE streaming
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

      // set session cookie BEFORE streaming
      setSessionCookieHeader(res, session.sid);

      // small asset cache: buffer small assets
      const contentLengthNumber = clen ? parseInt(clen, 10) : NaN;
      if(!isNaN(contentLengthNumber) && contentLengthNumber <= ASSET_CACHE_MAX_SIZE){
        try {
          const arr = await originRes.arrayBuffer();
          const buf = Buffer.from(arr);
          cacheSet(assetCacheKey, { headers: { "Content-Type": ct }, body: buf.toString("base64") });
          return res.send(buf);
        } catch(e) {
          // fallback to streaming
        }
      }

      // stream origin response directly
      if(originRes.body && typeof originRes.body.pipe === "function") {
        try {
          await pipe(originRes.body, res);
          return;
        } catch(pipeErr){
          // log and attempt to end safely
          console.warn("Asset pipeline error:", pipeErr && pipeErr.message);
          try { if(!res.headersSent) res.status(502).end("Asset stream error"); else res.end(); } catch(e){}
          return;
        }
      } else {
        // fallback: buffer & send
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        return res.send(buf);
      }
    }

    // HTML path: fetch as text and transform
    let html = await originRes.text();

    // remove CSP meta tags and integrity/crossorigin to allow proxied assets to run
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

    const finalUrl = originRes.url || raw;

    // inject base href so relative assets resolve
    if(/<head[\s>]/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // Server-side rewrites (avoid double-proxying; point rewrites to DEPLOYMENT_ORIGIN)
    // anchors
    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function(m, pre, q, val){
      if(!val) return m;
      if(/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if(isAlreadyProxiedHref(val)) {
        // If it resolves to other host's /proxy?url=..., make it point to our deployment proxy instead
        try {
          const resolved = new URL(val, finalUrl);
          if(resolved.pathname.startsWith("/proxy")) {
            const urlParam = resolved.searchParams.get("url");
            if(urlParam) return `<a${pre}href="${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(urlParam)}"`;
          }
        } catch(e){}
        return m;
      }
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // asset tags, srcset, poster, data-src, data-srcset etc.
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|poster|data-src|data-href|srcset|data-srcset)=)(["'])([^"']*)\3/gi,
      function(m, prefix, attr, q, val) {
        if(!val) return m;
        if(/^data:/i.test(val)) return m;
        if(isAlreadyProxiedHref(val)) {
          // if it's another host's /proxy url, rewrite to our deployment proxy with original target if possible
          try {
            const resolved = new URL(val, finalUrl);
            if(resolved.pathname.startsWith("/proxy")) {
              const urlParam = resolved.searchParams.get("url");
              if(urlParam) return `${prefix}${attr}${q}${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(urlParam)}${q}`;
            }
          } catch(e){}
          return m;
        }
        const abs = toAbsolute(val, finalUrl) || val;
        if(attr.toLowerCase().startsWith("srcset") || attr.toLowerCase().startsWith("data-srcset")){
          // convert each candidate in srcset
          const parts = val.split(",").map(p=>{
            const [u, rest] = p.trim().split(/\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            const a = toAbsolute(u, finalUrl) || u;
            return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(a)}` + (rest ? " " + rest : "");
          });
          return `${prefix}${attr}${q}${parts.join(", ")}${q}`;
        }
        return `${prefix}${attr}${q}${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}${q}`;
      });

    // CSS url(...)
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, function(m, q, val){
      if(!val) return m;
      if(/^data:/i.test(val) || isAlreadyProxiedHref(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // form action
    html = html.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function(m, pre, q, val){
      if(!val) return m;
      if(isAlreadyProxiedHref(val) || /^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // meta refresh
    html = html.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi, function(m){
      const match = m.match(/content\s*=\s*["']([^"']*)["']/i);
      if(!match) return m;
      const parts = match[1].split(";");
      if(parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
      if(!urlPart) return m;
      const dest = urlPart[1].replace(/['"]/g,"").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // remove trackers (best-effort)
    html = html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi, "");
    html = html.replace(/<script[^>]*>\s*window\.ga=.*?<\/script>/gi, "");

    // inject one-time topbar and rewrite script if not already injected
    if(!html.includes(INJECT_MARKER)) {
      if(/<body[^>]*>/i.test(html)) html = html.replace(/<body([^>]*)>/i, (m,g)=>`<body${g}>` + INJECT_TOPBAR_HTML + INJECT_REWRITE_SCRIPT);
      else html = INJECT_TOPBAR_HTML + INJECT_REWRITE_SCRIPT + html;
    } else {
      // only inject rewrite script (if marker exists but rewrite not present)
      if(!html.includes(INJECT_REWRITE_SCRIPT.trim())) {
        if(/<body[^>]*>/i.test(html)) html = html.replace(/<body([^>]*)>/i, (m,g)=>`<body${g}>` + INJECT_REWRITE_SCRIPT);
        else html = INJECT_REWRITE_SCRIPT + html;
      }
    }

    // cache transformed HTML
    try { cacheSet(htmlCacheKey, html); } catch(e){}

    // set headers BEFORE streaming
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Access-Control-Allow-Origin", "*");
    setSessionCookieHeader(res, session.sid);

    // stream using scramjet StringStream
    const stream = StringStream.from(html);
    try {
      await pipe(stream, res);
    } catch (streamErr) {
      console.error("HTML stream error:", streamErr && streamErr.message);
      try { if(!res.headersSent) res.status(502).end("Stream error"); else res.end(); } catch(e){}
    }

    return;

  } catch (err) {
    console.error("Proxy fetch error:", err && err.message ? err.message : err);
    setSessionCookieHeaderIfSafe(res, session.sid);
    if(!res.headersSent) return res.status(502).send(`<div style="padding:1rem;background:#fee;color:#900;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
    try { res.end(); } catch(e){}
    return;
  }
});

// fallback to serve public/index.html for root and other HTML accept paths
app.use((req, res, next) => {
  if(req.method === "GET" && req.accepts && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// periodic cleanup of sessions and cache
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 24); // 24 hours
  for(const [sid, payload] of SESSIONS.entries()){
    if((payload.last || 0) < cutoff) SESSIONS.delete(sid);
  }
  for(const [k,v] of MEM_CACHE.entries()){
    if((now() - v.t) > CACHE_TTL) MEM_CACHE.delete(k);
  }
}, 1000 * 60 * 30);

console.log("Euphoria proxy (deployment-aware) listening on port", PORT);