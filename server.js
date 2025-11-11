/**
 * Euphoria Proxy Server (feature-packed)
 * - No iframes, no puppeteer
 * - Uses scramjet for streaming where applicable
 * - Rewrites proxied HTML so navigation stays under /proxy?url=...
 * - Injects a floating oval topbar & containment script into proxied HTML
 * - Lightweight memory+disk cache with LRU-ish eviction
 * - Session cookie store (in-memory)
 * - Small admin endpoints (cache clear, stats)
 * - Optional Wisp-style WebSocket endpoint at /wisp
 *
 * NOTE:
 * - scramjet is imported as default then destructured to avoid CJS/ESM named export issues.
 * - This file aims to be robust against many of the issues you reported (CSP, integrity, redirects, srcset, meta refresh).
 */

import express from "express";
import http from "http";
import { WebSocketServer } from "ws";
import path from "path";
import fs from "fs";
import os from "os";
import { fileURLToPath } from "url";
import morgan from "morgan";
import compression from "compression";
import cors from "cors";
import fetch from "node-fetch";
import scramjetPkg from "scramjet"; // import default to avoid named export errors
const { StringStream, DataStream } = scramjetPkg; // destructure what we need
// If scramjet import causes problem in your environment, change to require style or use lighter streaming (we stuck with this to meet your "use scramjet" constraint)

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// --- Middlewares ---
app.use(morgan("tiny"));
app.use(cors());
app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

// Serve frontend (index.html) and assets from public/ (client UI)
const PUBLIC_DIR = path.join(__dirname, "public");
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
app.use(express.static(PUBLIC_DIR, { index: false }));

// --- Basic in-memory session store (for cookies recorded from origin servers) ---
const SESSION_COOKIE_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24 hours
const SESSIONS = new Map();
function mkSid() {
  return (
    Math.random().toString(36).slice(2) + "-" + Date.now().toString(36).slice(2)
  );
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
function getSessionFromRequest(req) {
  const cookieHeader = req.headers.cookie || "";
  const kvs = cookieHeader.split(";").map((x) => x.trim());
  let sid = null;
  for (const kv of kvs) {
    const [k, v] = kv.split("=");
    if (k === SESSION_COOKIE_NAME) {
      sid = v;
      break;
    }
  }
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const data = SESSIONS.get(sid);
  data.last = now();
  return { sid, data };
}
function persistSessionCookie(res, sid) {
  const cookieStr = `${SESSION_COOKIE_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) {
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 30);

// --- Lightweight cache: memory + disk (LRU-ish) ---
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const MEM_CACHE_MAX = 500; // entries
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes

function cacheKey(k) {
  try {
    return Buffer.from(k).toString("base64url");
  } catch (e) {
    return Buffer.from(String(k)).toString("base64");
  }
}
function pruneMemCacheIfNeeded() {
  if (MEM_CACHE.size <= MEM_CACHE_MAX) return;
  // remove oldest inserted entries (simple)
  const keys = MEM_CACHE.keys();
  while (MEM_CACHE.size > MEM_CACHE_MAX) {
    const k = keys.next().value;
    MEM_CACHE.delete(k);
  }
}
function cacheSet(key, value) {
  const k = cacheKey(key);
  const payload = { t: now(), v: value };
  MEM_CACHE.set(k, payload);
  pruneMemCacheIfNeeded();
  try {
    fs.writeFileSync(path.join(CACHE_DIR, k), JSON.stringify(payload), "utf8");
  } catch (e) {}
}
function cacheGet(key) {
  const k = cacheKey(key);
  const mem = MEM_CACHE.get(k);
  if (mem && now() - mem.t < CACHE_TTL) return mem.v;
  // check disk
  const p = path.join(CACHE_DIR, k);
  if (fs.existsSync(p)) {
    try {
      const raw = fs.readFileSync(p, "utf8");
      const obj = JSON.parse(raw);
      if (now() - obj.t < CACHE_TTL) {
        MEM_CACHE.set(k, { t: obj.t, v: obj.v });
        pruneMemCacheIfNeeded();
        return obj.v;
      } else {
        try { fs.unlinkSync(p); } catch (e) {}
      }
    } catch (e) {}
  }
  return null;
}
function cacheDel(key) {
  const k = cacheKey(key);
  MEM_CACHE.delete(k);
  try { fs.unlinkSync(path.join(CACHE_DIR, k)); } catch (e) {}
}

// --- Helper utilities ---
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
function sanitizeHeaderName(h) {
  if (!h) return h;
  return String(h)
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "");
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

// --- Topbar injection (solid dark oval) and containment script ---
// NOTE: content is minimized to keep length okay, but contains all behavior: address bar, back/forward/refresh/home/fullscreen, interception of links/forms/history/window.open
const TOPBAR_INJECTION = `
<!-- EUPHORIA INJECTED TOPBAR -->
<div id="euphoria-topbar" style="position:fixed;top:12px;left:50%;transform:translateX(-50%);width:86%;max-width:1200px;background:#0f1113;border-radius:999px;padding:8px 14px;display:flex;align-items:center;gap:8px;z-index:2147483647;box-shadow:0 8px 30px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
  <button id="eph-back" aria-label="Back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#191b1e;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" aria-label="Forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#191b1e;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" aria-label="Refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#191b1e;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" aria-label="Home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#191b1e;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" aria-label="Address" style="flex:1;padding:8px 12px;border-radius:14px;border:0;background:#141618;color:#fff;outline:none" placeholder="Enter URL or search..." />
  <button id="eph-go" aria-label="Go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" aria-label="Fullscreen" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#191b1e;color:#fff;cursor:pointer">⛶</button>
</div>
<style>html,body{padding-top:86px !important;background:transparent !important}</style>

<script>
(function(){
  // containment script keeps navigation inside /proxy?url=...
  const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);
  const absolute = (h) => { try { return new URL(h, document.baseURI).href } catch(e) { return h } };

  const input = document.getElementById('eph-input');
  const go = document.getElementById('eph-go');
  const back = document.getElementById('eph-back');
  const forward = document.getElementById('eph-forward');
  const refresh = document.getElementById('eph-refresh');
  const home = document.getElementById('eph-home');
  const full = document.getElementById('eph-full');

  try {
    const urlParam = new URLSearchParams(location.search).get('url');
    if (urlParam) input.value = decodeURIComponent(urlParam);
  } catch(e) {}

  function isLikelySearch(v){
    if(!v) return true;
    if(v.includes(' ')) return true;
    if(/^https?:\\/\\//i.test(v)) return false;
    if(/\\./.test(v)) return false;
    return true;
  }
  function normalize(v){
    v = (v||'').trim();
    if(!v) return 'https://www.google.com';
    if (isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
    try { new URL(v); return v; } catch(e) {}
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
  home.onclick = () => location.href = '/proxy?url=' + encodeURIComponent('https://www.google.com');
  full.onclick = () => {
    if (!document.fullscreenElement) document.documentElement.requestFullscreen().catch(()=>{});
    else document.exitFullscreen().catch(()=>{});
  };

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
      if (v.startsWith('/proxy?url=')) return;
      const abs = absolute(v);
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
          return '/proxy?url=' + encodeURIComponent(absolute(url)) + (rest ? ' ' + rest : '');
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
              const ss = el.getAttribute('srcset');
              if(!ss) return;
              const parts = ss.split(',').map(p=>{
                const [url, rest] = p.trim().split(/\\s+/,2);
                if(!url) return p;
                if(/^data:/i.test(url)) return p;
                return '/proxy?url=' + encodeURIComponent(absolute(url)) + (rest ? ' ' + rest : '');
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
      if (href.startsWith('/proxy?url=') || href.startsWith('/')) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      e.preventDefault();
      const abs = absolute(href);
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
      const abs = absolute(a);
      f.setAttribute('action', '/proxy?url=' + encodeURIComponent(abs));
    }catch(e){}
  }, true);

  // history patching
  try {
    (function(history){ 
      const push = history.pushState;
      history.pushState = function(s,t,u){
        try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(absolute(u)); }catch(e){}
        return push.apply(history, arguments);
      };
      const rep = history.replaceState;
      history.replaceState = function(s,t,u){
        try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(absolute(u)); }catch(e){}
        return rep.apply(history, arguments);
      };
    })(window.history);
  } catch(e){}
  
  // patch window.open
  try {
    const origOpen = window.open;
    window.open = function(u, ...rest){
      try {
        if(!u) return origOpen.apply(window, arguments);
        const abs = absolute(u);
        location.href = toProxy(abs);
        return null;
      } catch(e) { return origOpen.apply(window, arguments); }
    };
  } catch(e){}
})();
</script>
`;

// --- Utility to rewrite HTML source safely (avoid invalid regex flags) ---
// We'll do multiple explicit replacements, careful with regex escapes

function rewriteHtmlSource(html, finalUrl) {
  let out = html;

  // Remove meta CSP tags
  out = out.replace(/<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");

  // Remove integrity/crossorigin attributes
  out = out.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
  out = out.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

  // Inject base if head exists
  if (/<head[\s>]/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
  } else {
    out = `<base href="${finalUrl}">` + out;
  }

  // anchors: <a ... href="...">
  out = out.replace(/<a\b([^>]*?)\bhref\s*=\s*(["'])(.*?)\2/gi, (m, pre, quote, val) => {
    if (!val) return m;
    if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
    if (val.startsWith("/proxy?url=")) return m;
    const abs = toAbsolute(val, finalUrl) || val;
    return `<a${pre}href="${"/proxy?url=" + encodeURIComponent(abs)}"`;
  });

  // forms: action
  out = out.replace(/<form\b([^>]*?)\baction\s*=\s*(["'])(.*?)\2/gi, (m, pre, q, val) => {
    if (!val) return m;
    if (/^(javascript:|#)/i.test(val)) return m;
    if (val.startsWith("/proxy?url=")) return m;
    const abs = toAbsolute(val, finalUrl) || val;
    return `<form${pre}action="${"/proxy?url=" + encodeURIComponent(abs)}"`;
  });

  // src/href/srcset attributes on many tags
  out = out.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?\b(?:src|href|srcset)\s*=\s*)(["'])([^"']*)\2/gi, (m, prefix, q, val) => {
    if (!val) return m;
    if (/^data:/i.test(val)) return m;
    if (val.startsWith("/proxy?url=")) return m;
    const abs = toAbsolute(val, finalUrl) || val;
    return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
  });

  // srcset handling separately (more robust)
  out = out.replace(/\bsrcset\s*=\s*(["'])(.*?)\1/gi, (m, q, val) => {
    if (!val) return m;
    try {
      const parts = val.split(",").map(p => {
        const [url, rest] = p.trim().split(/\s+/, 2);
        if (!url) return p;
        if (/^data:/i.test(url)) return p;
        const abs = toAbsolute(url, finalUrl) || url;
        return `/proxy?url=${encodeURIComponent(abs)}` + (rest ? " " + rest : "");
      });
      return `srcset=${q}${parts.join(", ")}${q}`;
    } catch (e) {
      return m;
    }
  });

  // CSS url(...) rewrite
  out = out.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
    if (!val) return m;
    if (/^data:/i.test(val)) return m;
    const abs = toAbsolute(val, finalUrl) || val;
    return `url("/proxy?url=${encodeURIComponent(abs)}")`;
  });

  // meta refresh rewrite
  out = out.replace(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/gi, (match) => {
    const contentMatch = match.match(/content\s*=\s*(["'])(.*?)\1/i);
    if (!contentMatch) return match;
    const contentVal = contentMatch[2];
    const parts = contentVal.split(";");
    if (parts.length < 2) return match;
    const urlPart = parts.slice(1).join(";");
    const urlMatch = urlPart.match(/url\s*=\s*(.*)/i);
    if (!urlMatch) return match;
    const dest = urlMatch[1].replace(/['"]/g, "").trim();
    const abs = toAbsolute(dest, finalUrl) || dest;
    return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
  });

  // Remove or reduce known analytics script elements (best-effort); keep inline scripts untouched
  try {
    // remove script tags where src includes analytics keywords
    out = out.replace(/<script[^>]+src=(["'])[^"']*(analytics|gtag|googlesyndication|googletagmanager|doubleclick)[^"']*\1[^>]*><\/script>/gi, "");
  } catch (e) {
    // fallback: ignore failure and continue
  }

  // inject topbar & containment script after opening body (or at top)
  if (/<body[^>]*>/i.test(out)) {
    out = out.replace(/<body([^>]*)>/i, (m, g) => `<body${g}>` + TOPBAR_INJECTION);
  } else {
    out = TOPBAR_INJECTION + out;
  }

  return out;
}

// --- Admin endpoints (cache, stats) ---
app.get("/admin/cache/keys", (req, res) => {
  const keys = [];
  for (const k of MEM_CACHE.keys()) keys.push(k);
  res.json({ keys, memCount: MEM_CACHE.size });
});
app.post("/admin/cache/clear", (req, res) => {
  MEM_CACHE.clear();
  // clear disk
  try {
    for (const f of fs.readdirSync(CACHE_DIR)) {
      try { fs.unlinkSync(path.join(CACHE_DIR, f)); } catch (e) {}
    }
  } catch (e) {}
  res.json({ ok: true });
});

// --- healthcheck ---
app.get("/healthz", (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// --- Main proxy endpoint (/proxy?url=...) ---
app.get("/proxy", async (req, res) => {
  let raw = req.query.url || "";
  if (!raw) return res.status(400).send("Missing url, use /proxy?url=https://example.com");

  // Accept raw that might be encoded or plain host
  try { raw = decodeURIComponent(raw); } catch (e) {}

  // normalize: if no scheme and looks like search, map to google search
  if (!/^https?:\/\//i.test(raw)) {
    // If looks like "google.com" or "xbox.com" (contain dot) assume https, else treat as search
    if (isLikelySearch(raw)) {
      raw = "https://www.google.com/search?q=" + encodeURIComponent(raw);
    } else {
      raw = "https://" + raw;
    }
  }

  // session & cookie handling
  const session = getSessionFromRequest(req);
  persistSessionCookie(res, session.sid);

  // caching keys
  const cacheKeyHtml = raw + "::html";
  const cacheKeyAsset = raw + "::asset";

  // If client requests only assets (Accept doesn't include text/html), we can return cached assets
  try {
    const cachedAsset = cacheGet(cacheKeyAsset);
    if (cachedAsset && !(req.headers.accept || "").includes("text/html")) {
      if (cachedAsset.headers) Object.entries(cachedAsset.headers).forEach(([k, v]) => res.setHeader(k, v));
      persistSessionCookie(res, session.sid);
      return res.send(Buffer.from(cachedAsset.body, "base64"));
    }
  } catch (e) {}

  // Serve cached HTML if available
  const cachedHtml = cacheGet(cacheKeyHtml);
  if (cachedHtml) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    return res.send(cachedHtml);
  }

  // Prepare headers for fetch to origin
  const cookieHeader = buildCookieHeader(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers["accept"] || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    // Use node-fetch to fetch origin (follow redirects)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25_000);

    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // capture set-cookie into session store
    const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if (setCookies.length) {
      for (const sc of setCookies) {
        try {
          // parse simple cookie key=value
          const kv = sc.split(";")[0] || "";
          const [k, v] = kv.split("=");
          if (k && v) session.data.cookies.set(k.trim(), v.trim());
        } catch (e) {}
      }
    }

    const contentType = originRes.headers.get("content-type") || "";

    // Non-HTML: stream bytes back, caching small assets
    if (!contentType.includes("text/html")) {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      // forward headers
      res.setHeader("Content-Type", contentType);
      const cacheControl = originRes.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      persistSessionCookie(res, session.sid);

      // small asset caching
      if (buf.length < 100 * 1024) {
        try {
          cacheSet(cacheKeyAsset, { headers: { "Content-Type": contentType }, body: buf.toString("base64") });
        } catch (e) {}
      }
      return res.send(buf);
    }

    // HTML: read full text so we can safely replace and inject
    const text = await originRes.text();
    let finalUrl = originRes.url || raw;

    // rewrite HTML (function above)
    const rewritten = rewriteHtmlSource(text, finalUrl);

    // cache HTML
    if (originRes.status === 200) {
      try { cacheSet(cacheKeyHtml, rewritten); } catch (e) {}
    }

    // stream HTML progressively using scramjet StringStream
    try {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      persistSessionCookie(res, session.sid);
      // Use streaming so client begins rendering fast
      await StringStream.from(rewritten).pipe(res);
      // ensure response ends
      if (!res.writableEnded) res.end();
      return;
    } catch (e) {
      // If streaming fails, fallback to send
      if (!res.headersSent) res.setHeader("Content-Type", "text/html; charset=utf-8");
      persistSessionCookie(res, session.sid);
      return res.send(rewritten);
    }
  } catch (err) {
    console.error("Proxy fetch error:", err && err.message ? err.message : String(err));
    persistSessionCookie(res, session.sid);
    return res.status(500).send(`<div style="padding:1.5rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// --- WebSocket (Wisp-style optional) ---
// A simple WebSocket endpoint that accepts JSON messages { url: "https://..." } and returns fetched data.
// This is optional but handy for local downloadable frontends that prefer ws.
const wss = new WebSocketServer({ noServer: true });
server.on("upgrade", (req, socket, head) => {
  if (req.url && req.url.startsWith("/wisp")) {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  } else {
    socket.destroy();
  }
});
wss.on("connection", (ws, req) => {
  ws.on("message", async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (!msg || !msg.url) return ws.send(JSON.stringify({ error: "Missing url" }));
      // small safety: only allow http/https
      if (!/^https?:\/\//i.test(msg.url)) return ws.send(JSON.stringify({ error: "Invalid url scheme" }));
      // perform fetch
      const response = await fetch(msg.url, { redirect: "follow", headers: { "User-Agent": "Euphoria-Wisp/1.0" } });
      const ct = response.headers.get("content-type") || "";
      if (ct.includes("application/json")) {
        const json = await response.json();
        ws.send(JSON.stringify({ url: msg.url, contentType: ct, body: json }));
      } else {
        const txt = await response.text();
        ws.send(JSON.stringify({ url: msg.url, contentType: ct, body: txt }));
      }
    } catch (e) {
      ws.send(JSON.stringify({ error: e && e.message ? e.message : String(e) }));
    }
  });
});

// --- SPA fallback: serve index.html for all other GET requests that accept html ---
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts && req.accepts("html")) {
    const idx = path.join(PUBLIC_DIR, "index.html");
    if (fs.existsSync(idx)) return res.sendFile(idx);
  }
  next();
});

// --- Graceful shutdown ---
function graceful() {
  console.log("Shutting down gracefully...");
  server.close(() => {
    console.log("Closed HTTP server.");
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
}
process.on("SIGINT", graceful);
process.on("SIGTERM", graceful);

// --- Start server ---
server.listen(PORT, () => {
  console.log(`Euphoria proxy listening on ${PORT}`);
});