// server.js — Full-featured Euphoria proxy (robust, fixed, proxy-all)
// Save as ESM (package.json must contain: "type": "module")
//
// Features:
//  - scramjet streaming for progressive HTML (StringStream)
//  - streaming non-HTML assets via pipeline (preserve encodings)
//  - in-memory cache + async disk cache (non-blocking)
//  - sessions/cookie persistence across proxied requests
//  - injection of translucent topbar + loading bar (only if page lacks euphoria-topbar)
//  - rewriting: anchors, assets, forms, srcset, CSS url(...), meta-refresh
//  - remove CSP/integrity attributes where needed
//  - analytics/script trimming (best-effort)
//  - WebSocket telemetry at /_euph_ws
//  - careful header handling to avoid "Cannot set headers after they are sent" errors
//  - prevention of nested /proxy rewriting
//  - EventEmitter listener limit increased to avoid warnings
//
// Note: tweak constants (CACHE_TTL, ASSET_CACHE_MAX_SIZE, FETCH_TIMEOUT_MS) for your environment.

import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fsPromises from "fs/promises";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import scramjetPkg from "scramjet"; // CommonJS -> default import then destructure
const { StringStream } = scramjetPkg;
import { WebSocketServer } from "ws";
import { pipeline } from "stream";
import { promisify } from "util";
import { EventEmitter } from "events";

const pipe = promisify(pipeline);
EventEmitter.defaultMaxListeners = 50; // increase global default to avoid warning

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

// ----------------- Config -----------------
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX_SIZE = 128 * 1024; // 128 KB
const FETCH_TIMEOUT_MS = 25000; // 25s
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");
const ORIGIN_HOST_ALLOWLIST = []; // optional list of hosts you might want to bypass proxy (empty -> proxy-all)

// Ensure cache dir exists (async, non-blocking)
if (ENABLE_DISK_CACHE) {
  fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// ----------------- Middleware -----------------
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ----------------- In-memory cache -----------------
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
    // async write
    const fname = path.join(CACHE_DIR, encodeURIComponent(Buffer.from(key).toString("base64")));
    (async () => {
      try { await fsPromises.writeFile(fname, JSON.stringify({ t: now(), v: val }), "utf8"); } catch (e) { /* ignore */ }
    })();
  }
}

// ----------------- Session & cookie helpers -----------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: now() }; SESSIONS.set(sid, payload); return { sid, payload }; }
function getSessionFromReq(req) {
  const cookieHeader = req.headers.cookie || "";
  const parsed = {};
  cookieHeader.split(";").forEach(p => {
    const [k, v] = (p || "").split("=").map(s => (s || "").trim());
    if (k && v) parsed[k] = v;
  });
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid);
  payload.last = now();
  return { sid, payload };
}
function setSessionCookieHeader(res, sid) {
  // Set cookie header once, BEFORE streaming starts
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function storeSetCookieToSession(setCookies, sessionPayload) {
  for (const sc of setCookies || []) {
    try {
      const kv = sc.split(";")[0];
      const idx = kv.indexOf("=");
      if (idx === -1) continue;
      const k = kv.slice(0, idx).trim();
      const v = kv.slice(idx + 1).trim();
      if (k) sessionPayload.cookies.set(k, v);
    } catch (e) { /* ignore */ }
  }
}
function buildCookieHeader(map) { return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; "); }

// ----------------- Utility helpers -----------------
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function looksLikeSearch(input) {
  if (!input) return true;
  if (input.includes(" ")) return true;
  if (/^https?:\/\//i.test(input)) return false;
  if (/\./.test(input)) return false;
  return true;
}
function normalizeToUrl(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (looksLikeSearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

function isAlreadyProxiedHref(href, ourHost) {
  if (!href) return false;
  try {
    // If it already contains /proxy?url= or points to our deployment host's /proxy path, treat as proxied
    if (href.includes("/proxy?url=")) return true;
    const u = new URL(href, `https://${ourHost}`);
    // If host equals our host and path starts with /proxy, treat as proxied
    if (u.host === ourHost && u.pathname.startsWith("/proxy")) return true;
  } catch (e) {}
  return false;
}

// ----------------- Injection: topbar + minimal rewrite script -----------------
// This is the UI we inject into proxied pages if they don't already contain '#euphoria-topbar'.
const INJECT_TOPBAR_HTML = `
<!-- EUPHORIA: injected topbar -->
<style>
#euphoria-topbar { position: fixed; top: 12px; left: 50%; transform: translateX(-50%); width: min(1100px,86%); background: rgba(255,255,255,0.85); border-radius:28px; padding:8px 10px; display:flex; gap:8px; align-items:center; z-index:2147483647; box-shadow:0 6px 20px rgba(0,0,0,0.12); backdrop-filter: blur(6px); color:#000; font-family:system-ui,Arial,sans-serif; }
#euphoria-topbar button { min-width:44px; padding:8px; border-radius:10px; border:0; background:#eee; cursor:pointer; }
#euphoria-topbar input { flex:1; padding:8px 12px; border-radius:12px; border:0; background:#fff; }
#euphoria-loading { position: fixed; top: 0; left: 0; width: 0%; height: 3px; background: #2e7d32; transition: width 0.2s; z-index:2147483648; }
</style>
<div id="euphoria-topbar" aria-hidden="false">
  <button id="eph-back">◀</button>
  <button id="eph-forward">▶</button>
  <button id="eph-refresh">⟳</button>
  <button id="eph-home">🏠</button>
  <input id="eph-input" placeholder="Enter URL or search">
  <button id="eph-go">Go</button>
  <button id="eph-full">⛶</button>
</div>
<div id="euphoria-loading" aria-hidden="true"></div>
<script>
(function(){
  const topbar = document.getElementById('euphoria-topbar');
  const input = document.getElementById('eph-input');
  const go = document.getElementById('eph-go');
  const back = document.getElementById('eph-back');
  const forward = document.getElementById('eph-forward');
  const refresh = document.getElementById('eph-refresh');
  const home = document.getElementById('eph-home');
  const full = document.getElementById('eph-full');
  const loading = document.getElementById('euphoria-loading');

  function normalize(v){
    v=(v||'').trim();
    if(!v) return 'https://www.google.com';
    if(v.includes(' ') || !/\\./.test(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
    if(/^https?:\\/\\//i.test(v)) return v;
    return 'https://' + v;
  }

  go.onclick = ()=> { const u = normalize(input.value); location.href = '/proxy?url=' + encodeURIComponent(u); };
  input.onkeydown = e => { if(e.key === 'Enter') go.onclick(); };
  back.onclick = ()=> history.back();
  forward.onclick = ()=> history.forward();
  refresh.onclick = ()=> location.reload();
  home.onclick = ()=> location.href = '/proxy?url=' + encodeURIComponent('https://www.google.com');
  full.onclick = ()=> { if(!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

  // update loading bar on navigation events
  window.addEventListener('beforeunload', ()=> { loading.style.width='10%'; });
  window.addEventListener('load', ()=> { loading.style.width='100%'; setTimeout(()=>loading.style.width='0%', 300); });
  // try to prefill input from query param url
  try {
    const m = location.search.match(/[?&]url=([^&]+)/);
    if(m) input.value = decodeURIComponent(m[1]);
  } catch(e){}
})();
</script>
`;

// minimal dynamic rewrite script (no topbar) — rewrites anchors/assets/forms/srcset and intercepts fetch
const INJECT_REWRITE_SCRIPT = `
<script>
(function(){
  function proxify(u){
    try { const abs = new URL(u, document.baseURI).href; if(abs.includes('/proxy?url=')) return abs; return '/proxy?url=' + encodeURIComponent(abs); } catch(e) { return u; }
  }
  // anchors
  document.querySelectorAll('a[href]').forEach(a=>{
    try{
      const h = a.getAttribute('href');
      if(!h) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return;
      if(h.startsWith('/proxy?url=')) return;
      a.setAttribute('href', proxify(h));
      a.removeAttribute('target');
    }catch(e){}
  });
  // forms
  document.querySelectorAll('form[action]').forEach(f=>{
    try{
      const a = f.getAttribute('action'); if(!a) return;
      if(a.startsWith('/proxy?url=')) return;
      f.setAttribute('action', proxify(a));
    }catch(e){}
  });
  // assets + srcset
  const tags=['img','script','link','iframe','source','video','audio'];
  tags.forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      try{
        ['src','href'].forEach(attr=>{
          const v = el.getAttribute && el.getAttribute(attr);
          if(!v) return;
          if(/^data:/i.test(v)) return;
          if(v.startsWith('/proxy?url=')) return;
          el.setAttribute(attr, proxify(v));
        });
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
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
        let t = s.textContent;
        if(!t) return;
        t = t.replace(/url\\((['"]?)(.*?)\\1\\)/g, function(full,q,u){
          if(!u) return full;
          if(/^data:/i.test(u)) return full;
          try { const abs = new URL(u, document.baseURI).href; return 'url(\"/proxy?url=' + encodeURIComponent(abs) + '\")'; } catch(e) { return full; }
        });
        s.textContent = t;
      }catch(e){}
    });
  } catch(e){}
  // intercept fetch/XHR to route through proxy automatically
  try {
    const origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.startsWith('/proxy?url=')){
          resource = '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request){
          resource = new Request('/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      } catch(e){}
      return origFetch(resource, init);
    };
  } catch(e){}
})();
</script>
`;

// ----------------- WebSocket telemetry -----------------
const server = app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try {
      const parsed = JSON.parse(raw.toString());
      if (parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch (e) {}
  });
});

// ----------------- Main proxy endpoint -----------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // Normalize simple hostnames (allow human input like "google.com")
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session
  const session = getSessionFromReq(req);

  // If Accept header doesn't include HTML, we might be serving an asset
  const accept = (req.headers.accept || "").toLowerCase();

  // quick asset cache check for non-HTML
  const assetCacheKey = raw + "::asset";
  if (!accept.includes("text/html")) {
    const cachedAsset = cacheGet(assetCacheKey);
    if (cachedAsset) {
      if (cachedAsset.headers) Object.entries(cachedAsset.headers).forEach(([k, v]) => res.setHeader(k, v));
      setSessionCookieHeader(res, session.sid); // set cookie header BEFORE sending body
      try {
        const buf = Buffer.from(cachedAsset.body, "base64");
        return res.send(buf);
      } catch (e) { /* fallthrough to network fetch */ }
    }
  }

  // HTML cache check
  const htmlCacheKey = raw + "::html";
  if (accept.includes("text/html")) {
    const cachedHtml = cacheGet(htmlCacheKey);
    if (cachedHtml) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      setSessionCookieHeader(res, session.sid);
      return res.send(cachedHtml);
    }
  }

  // Build origin request headers
  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if (req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  try {
    // fetch with timeout
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const originRes = await fetch(raw, { headers: originHeaders, redirect: "follow", signal: controller.signal });

    clearTimeout(timer);

    // capture set-cookie
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    const contentType = (originRes.headers.get("content-type") || "").toLowerCase();

    // If this is NOT HTML -> stream binary/asset with header forwarding
    if (!contentType.includes("text/html")) {
      // Prepare headers BEFORE sending body
      const cencoding = originRes.headers.get("content-encoding");
      const clen = originRes.headers.get("content-length");
      const cacheControl = originRes.headers.get("cache-control");
      const ct = originRes.headers.get("content-type");

      if (ct) res.setHeader("Content-Type", ct);
      if (cencoding) res.setHeader("Content-Encoding", cencoding);
      if (clen) res.setHeader("Content-Length", clen);
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      res.setHeader("Vary", "Accept-Encoding");
      res.setHeader("Access-Control-Allow-Origin", "*"); // allow usage in proxied contexts

      // set session cookie header now (before streaming)
      setSessionCookieHeader(res, session.sid);

      // Try to cache small assets (non-blocking). If small, buffer and send; else stream.
      const contentLengthNumber = clen ? parseInt(clen, 10) : NaN;
      if (!isNaN(contentLengthNumber) && contentLengthNumber <= ASSET_CACHE_MAX_SIZE) {
        // buffer into memory (awaiting arrayBuffer)
        try {
          const arr = await originRes.arrayBuffer();
          const buf = Buffer.from(arr);
          // cache small assets
          cacheSet(assetCacheKey, { headers: { "Content-Type": ct }, body: buf.toString("base64") });
          return res.send(buf);
        } catch (e) {
          // fallback to streaming if buffering fails
        }
      }

      // Stream the origin body to client, preserving encoding
      if (originRes.body && typeof originRes.body.pipe === "function") {
        try {
          // pipeline will end the res when done or error
          await pipe(originRes.body, res);
          return;
        } catch (pipeErr) {
          // If the pipeline failed (premature close etc.), just try a safe fallback
          console.warn("Pipeline error for asset:", pipeErr && pipeErr.message);
          try {
            // If body readable, attempt to read arrayBuffer fallback
            const arr = await originRes.arrayBuffer();
            const buf = Buffer.from(arr);
            return res.send(buf);
          } catch (finalErr) {
            console.error("Final asset fallback failed:", finalErr && finalErr.message);
            // cannot send more headers or body reliably
            return;
          }
        }
      } else {
        // Fallback buffer -> send
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        return res.send(buf);
      }
    }

    // ----- HTML handling -----
    // Read origin HTML fully (we will stream transformed HTML progressively)
    let html = await originRes.text();

    // strip CSP meta tags to allow our injection and proxied scripts/styles to run
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // remove integrity/crossorigin attributes which would break proxied assets
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

    const finalUrl = originRes.url || raw;

    // ensure base tag exists to help relative resolution
    if (/<head[\s>]/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // server-side rewrites: anchors, assets, srcset, css url(...), form actions, meta refresh
    // IMPORTANT: avoid re-proxying links that already point to /proxy?url= or point to our host's /proxy path
    const ourHost = req.headers.host || "localhost";

    // anchors
    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function (m, pre, q, val) {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (isAlreadyProxiedHref(val, ourHost)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // asset tags (img/script/link/source/video/audio/iframe) including srcset
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|srcset)=)(["'])([^"']*)\3/gi,
      function (m, prefix, attr, q, val) {
        if (!val) return m;
        if (isAlreadyProxiedHref(val, ourHost) || /^data:/i.test(val)) return m;
        const abs = toAbsolute(val, finalUrl) || val;
        // handle srcset candidates
        if (attr.toLowerCase().startsWith("srcset")) {
          const parts = val.split(",").map(p => {
            const [u, rest] = p.trim().split(/\s+/, 2);
            if (!u) return p;
            if (/^data:/i.test(u)) return p;
            const a = toAbsolute(u, finalUrl) || u;
            return `/proxy?url=${encodeURIComponent(a)}` + (rest ? " " + rest : "");
          });
          return `${prefix}${attr}${q}${parts.join(", ")}${q}`;
        }
        return `${prefix}${attr}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
      });

    // css url(...) rewriting
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, function (m, q, val) {
      if (!val) return m;
      if (/^data:/i.test(val) || isAlreadyProxiedHref(val, ourHost)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // form action rewriting
    html = html.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function (m, pre, q, val) {
      if (!val) return m;
      if (isAlreadyProxiedHref(val, ourHost) || /^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // meta refresh rewrite
    html = html.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi, function (m) {
      const match = m.match(/content\s*=\s*["']([^"']*)["']/i);
      if (!match) return m;
      const parts = match[1].split(";");
      if (parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
      if (!urlPart) return m;
      const dest = urlPart[1].replace(/['"]/g, "").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // Trim common analytics/tracker scripts (best-effort)
    html = html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi, "");
    html = html.replace(/<script[^>]*>\s*window\.ga=.*?<\/script>/gi, "");

    // Inject rewrite script + topbar only if topbar not present
    if (!/id=(["'])?euphoria-topbar\1?/i.test(html)) {
      // inject both topbar HTML and rewrite script (topbar includes loading bar)
      if (/<body[^>]*>/i.test(html)) {
        html = html.replace(/<body([^>]*)>/i, (m, g) => `<body${g}>` + INJECT_TOPBAR_HTML + INJECT_REWRITE_SCRIPT);
      } else {
        html = INJECT_TOPBAR_HTML + INJECT_REWRITE_SCRIPT + html;
      }
    } else {
      // only inject rewrite script (topbar already present)
      if (/<body[^>]*>/i.test(html)) {
        html = html.replace(/<body([^>]*)>/i, (m, g) => `<body${g}>` + INJECT_REWRITE_SCRIPT);
      } else {
        html = INJECT_REWRITE_SCRIPT + html;
      }
    }

    // Cache HTML in memory
    try { cacheSet(htmlCacheKey, html); } catch (e) { /* ignore cache errors */ }

    // Prepare response headers BEFORE streaming
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Access-Control-Allow-Origin", "*");
    setSessionCookieHeader(res, session.sid);

    // Stream HTML progressively using scramjet StringStream
    const stream = StringStream.from(html);
    try {
      await pipe(stream, res);
    } catch (streamErr) {
      // If a stream error occurs, we can't set headers — log and end
      console.error("HTML stream error:", streamErr && streamErr.message);
      try { res.end(); } catch (e) {}
    }
    return;
  } catch (err) {
    // Top-level fetch error
    console.error("Proxy error:", err && err.message ? err.message : err);
    try { setSessionCookieHeader(res, session.sid); } catch (e) {}
    if (!res.headersSent) {
      return res.status(502).send(`<div style="padding:1rem;background:#fee;color:#900;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
    } else {
      try { res.end(); } catch (e) {}
      return;
    }
  }
});

// ----------------- Fallback to frontend index.html for HTML accept -----------------
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ----------------- Periodic cleanup -----------------
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 24); // delete sessions unused >24h
  for (const [sid, payload] of SESSIONS.entries()) {
    if ((payload.last || 0) < cutoff) SESSIONS.delete(sid);
  }
  // prune cache older than TTL
  for (const [k, v] of MEM_CACHE.entries()) {
    if ((now() - v.t) > CACHE_TTL) MEM_CACHE.delete(k);
  }
}, 1000 * 60 * 30); // every 30 minutes

// ----------------- Done -----------------
console.log("Euphoria proxy (robust) ready on port", PORT);
