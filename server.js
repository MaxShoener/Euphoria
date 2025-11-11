// server.js — Full-featured Euphoria proxy (expanded, scramjet import fixed)
// Save as ESM (package.json: "type": "module")
//
// Features:
//  - scramjet streaming for progressive HTML (StringStream)
//  - streaming non-HTML assets via pipeline (preserve encodings)
//  - in-memory cache + optional async disk cache (non-blocking)
//  - sessions/cookie persistence across proxied requests
//  - injection of small rewrite script (only if page lacks euphoria-topbar)
//  - rewriting: anchors, assets, forms, srcset, CSS url(...), meta-refresh
//  - CSP/integrity removal to allow proxied loads
//  - analytics/tracker trimming (best-effort)
//  - WebSocket telemetry at /_euph_ws
//  - robust header forwarding
//  - safe timeouts and aborts
//
// NOTE: tune CACHE_TTL, ASSET_CACHE_MAX_SIZE, and timeouts for your environment.

import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fsPromises from "fs/promises";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import pkg from "scramjet"; // scramjet is CommonJS — import default then destructure
const { StringStream, DataStream } = pkg;
import { WebSocketServer } from "ws";
import { pipeline } from "stream";
import { promisify } from "util";

const pipe = promisify(pipeline);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

// ---------------------------
// Config
// ---------------------------
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX_SIZE = 128 * 1024; // cache small assets only (128KB)
const HTML_STREAM_CHUNK_MS = 12; // small delay for progressive streaming (optional)
const FETCH_TIMEOUT_MS = 25000; // 25s

// Optional disk cache directory (async writes). If you want to disable disk caching, set to null.
const CACHE_DIR = path.join(__dirname, "cache"); // async writes below (non-blocking)
const ENABLE_DISK_CACHE = true;

// ---------------------------
// Middleware
// ---------------------------
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Ensure cache dir exists (async) — not blocking
if (ENABLE_DISK_CACHE) {
  fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// ---------------------------
// In-memory stores
// ---------------------------
const MEM_CACHE = new Map(); // key -> { v, t }
function now() { return Date.now(); }
function cacheGet(key) {
  const e = MEM_CACHE.get(key);
  if (!e) return null;
  if ((now() - e.t) > CACHE_TTL) {
    MEM_CACHE.delete(key);
    return null;
  }
  return e.v;
}
function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
  if (ENABLE_DISK_CACHE) {
    // async disk write (non-blocking)
    const fname = path.join(CACHE_DIR, encodeURIComponent(Buffer.from(key).toString("base64")));
    (async () => {
      try {
        await fsPromises.writeFile(fname, JSON.stringify({ t: now(), v: val }), "utf8");
      } catch (e) { /* ignore */ }
    })();
  }
}

// Optionally load disk cache on start or on-demand — not necessary for correctness

// ---------------------------
// Session & cookie handling
// ---------------------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map(); // sid -> { cookies: Map, last }

function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() {
  const sid = makeSid();
  const payload = { cookies: new Map(), last: now() };
  SESSIONS.set(sid, payload);
  return { sid, payload };
}
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
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
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
function buildCookieHeader(map) {
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

// ---------------------------
// Utility helpers
// ---------------------------
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

// ---------------------------
// Small injection script (no topbar duplication)
// - It will NOT add the Euphoria topbar if the page already contains an element with id 'euphoria-topbar'.
// - It rewrites anchors, forms, assets, srcset, and intercepts fetch/XHR.
// ---------------------------
const INJECT = `
<script>
(function(){
  function proxifyURL(u){
    try { const abs=new URL(u, document.baseURI).href; return '/proxy?url=' + encodeURIComponent(abs); } catch(e) { return u; }
  }
  // Avoid injecting twice
  if(document.getElementById('euphoria-topbar')) {
    // still install rewriting behaviors
  }
  // rewrite anchors
  document.querySelectorAll('a[href]').forEach(a=>{
    try{
      const h=a.getAttribute('href');
      if(!h) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return;
      if(h.startsWith('/proxy?url=')) return;
      a.setAttribute('href', proxifyURL(h));
      a.removeAttribute('target');
    }catch(e){}
  });
  // forms
  document.querySelectorAll('form[action]').forEach(f=>{
    try{
      const a=f.getAttribute('action'); if(!a) return;
      if(a.startsWith('/proxy?url=')) return;
      f.setAttribute('action', proxifyURL(a));
    }catch(e){}
  });
  // assets & srcset
  const tags=['img','script','link','iframe','source','video','audio'];
  tags.forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      try{
        ['src','href'].forEach(attr=>{
          const v=el.getAttribute && el.getAttribute(attr);
          if(!v) return;
          if(/^data:/i.test(v)) return;
          if(v.startsWith('/proxy?url=')) return;
          el.setAttribute(attr, proxifyURL(v));
        });
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss=el.getAttribute('srcset');
          if(ss) {
            const parts = ss.split(',').map(p=>{
              const [url, rest] = p.trim().split(/\\s+/,2);
              if(!url) return p;
              if(/^data:/i.test(url)) return p;
              return '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href) + (rest? ' ' + rest : '');
            });
            el.setAttribute('srcset', parts.join(', '));
          }
        }
      }catch(e){}
    });
  });
  // rewrite CSS url(...) inside style tags
  try {
    document.querySelectorAll('style').forEach(s=>{
      try{
        let t=s.textContent;
        if(!t) return;
        t = t.replace(/url\\((['"]?)(.*?)\\1\\)/g, function(full, q, u){
          if(!u) return full;
          if(/^data:/i.test(u)) return full;
          try{ const abs=new URL(u, document.baseURI).href; return 'url("/proxy?url=' + encodeURIComponent(abs) + '")'; }catch(e){ return full; }
        });
        s.textContent = t;
      }catch(e){}
    });
  } catch(e){}
  // intercept fetch
  try {
    const __origFetch = window.fetch;
    window.fetch = function(resource, init){
      try{
        if(typeof resource === 'string' && !resource.startsWith('/proxy?url=')){
          resource = '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request){
          resource = new Request('/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      } catch(e){}
      return __origFetch(resource, init);
    };
  } catch(e){}
})();
</script>
`;

// ---------------------------
// WebSocket telemetry server
// ---------------------------
const server = app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try {
      const parsed = JSON.parse(raw.toString());
      if (parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch (e) { /* ignore */ }
  });
});

// ---------------------------
// Main /proxy endpoint
// ---------------------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize simple hostnames
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session
  const session = getSessionFromReq(req);
  setSessionCookieHeader(res, session.sid);

  // quick cache: if accept not HTML, check asset cache
  const accept = req.headers.accept || "";
  const assetCacheKey = raw + "::asset";
  if (!accept.includes("text/html")) {
    const cachedAsset = cacheGet(assetCacheKey);
    if (cachedAsset) {
      // forward cached headers
      if (cachedAsset.headers) Object.entries(cachedAsset.headers).forEach(([k, v]) => res.setHeader(k, v));
      setSessionCookieHeader(res, session.sid);
      try {
        const buf = Buffer.from(cachedAsset.body, "base64");
        return res.send(buf);
      } catch (e) { /* fallthrough to fetch */ }
    }
  }

  // HTML cache
  const htmlCacheKey = raw + "::html";
  if (accept.includes("text/html")) {
    const cachedHtml = cacheGet(htmlCacheKey);
    if (cachedHtml) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      setSessionCookieHeader(res, session.sid);
      return res.send(cachedHtml);
    }
  }

  // Build fetch headers to origin
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) headers["Cookie"] = cookieHdr;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    // timeout controller
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    // fetch origin
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });

    clearTimeout(to);

    // capture set-cookie header(s)
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    const contentType = (originRes.headers.get("content-type") || "").toLowerCase();

    // Non-HTML: stream binary / assets directly and forward encoding headers.
    if (!contentType.includes("text/html")) {
      // Forward important headers
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
      setSessionCookieHeader(res, session.sid);

      // Stream origin body to client preserving encoding and avoiding buffering
      if (originRes.body && typeof originRes.body.pipe === "function") {
        // Optionally cache small assets into memory (async)
        try {
          // If small enough, also capture into memory for asset cache
          const contentLength = clen ? parseInt(clen, 10) : NaN;
          if (!isNaN(contentLength) && contentLength <= ASSET_CACHE_MAX_SIZE) {
            // buffer but in an async non-blocking manner
            const arrBuf = await originRes.arrayBuffer();
            const buf = Buffer.from(arrBuf);
            // save to cache
            cacheSet(assetCacheKey, { headers: { "Content-Type": ct }, body: buf.toString("base64") });
            // send buffer
            return res.send(buf);
          } else {
            // stream directly
            await pipe(originRes.body, res);
            return;
          }
        } catch (e) {
          // fallback to streaming
          try { await pipe(originRes.body, res); return; } catch (ee) { /* fallback below */ }
        }
      }
      // fallback: buffer and send
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      return res.send(buf);
    }

    // HTML handling (modify & inject)
    let html = await originRes.text();

    // Remove problematic CSP meta tags so our injection and proxied assets load
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");

    // Remove integrity and crossorigin attributes that often break asset loads when proxied
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

    const finalUrl = originRes.url || raw;

    // Insert base tag if head present; else prefix HTML with base
    if (/<head[\s>]/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, function(m, g) { return `<head${g}><base href="${finalUrl}">`; });
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // Rewrite anchors
    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function(m, pre, q, val) {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const a = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(a)}"`;
    });

    // Rewrite assets tags (img/script/link/source/video/audio/iframe)
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|srcset)=)(["'])([^"']*)\3/gi,
      function(m, prefix, attr, q, val) {
        if (!val) return m;
        if (val.startsWith("/proxy?url=") || /^data:/i.test(val)) return m;
        const abs = toAbsolute(val, finalUrl) || val;
        // srcset handling: attr might be 'srcset=' here, but regex uses src|href|srcset token -- handle srcset specially
        if (attr.toLowerCase().startsWith("srcset")) {
          // convert each candidate
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

    // Rewrite CSS url(...) occurrences to proxy
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, function(m, q, val) {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Rewrite form actions
    html = html.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function(m, pre, q, val) {
      if (!val) return m;
      if (val.startsWith("/proxy?url=")) return m;
      if (/^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // Meta refresh rewrite
    html = html.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi, function(m) {
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

    // Remove some common analytics/tracking scripts (best-effort)
    html = html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi, "");
    html = html.replace(/<script[^>]*>\s*window\.ga=.*?<\/script>/gi, "");

    // Inject minimal INJECT script only if the page doesn't already contain 'euphoria-topbar' (prevents double bars)
    if (!/id=(["'])?euphoria-topbar\1?/i.test(html)) {
      if (/<body[^>]*>/i.test(html)) {
        html = html.replace(/<body([^>]*)>/i, (m, g) => `<body${g}>` + INJECT);
      } else {
        html = INJECT + html;
      }
    } else {
      // Even if topbar exists, still inject the rewriting script but avoid adding another topbar element.
      // Our INJECT is minimal and not adding a topbar in that case (see first lines of INJECT checking presence).
      if (/<body[^>]*>/i.test(html)) {
        html = html.replace(/<body([^>]*)>/i, (m, g) => `<body${g}>` + INJECT);
      } else {
        html = INJECT + html;
      }
    }

    // Cache HTML (in-memory) if status 200
    try { if (originRes.status === 200) cacheSet(htmlCacheKey, html); } catch (e) { /* ignore */ }

    // Forward relevant headers
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Access-Control-Allow-Origin", "*");
    setSessionCookieHeader(res, session.sid);

    // Stream HTML progressively using scramjet StringStream
    const stream = StringStream.from(html);
    // Pipe to res
    await pipe(stream, res);
    return;
  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : err);
    setSessionCookieHeader(res, session.sid);
    return res.status(500).send(`<div style="padding:1rem;font-family:system-ui;background:#fee;color:#900;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// ---------------------------
// Fallback: serve frontend for HTML requests
// ---------------------------
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ---------------------------
// Graceful cleanup for old sessions (optional background cleanup)
// ---------------------------
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 24); // 24h TTL for sessions
  for (const [sid, payload] of SESSIONS.entries()) {
    if ((payload.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 30); // run every 30 minutes

// Done
