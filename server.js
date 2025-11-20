// server.js
// Express + Scramjet hybrid Euphoria proxy (deployment-aware, single-inject logic, robust streaming)
// - Import style works with scramjet CommonJS default export (Node 20+ ESM loader)
// - Streams binary assets; transforms HTML safely and progressively
// - Rewrites all proxied links to DEPLOYMENT_ORIGIN/proxy?url=...
// - Does NOT inject the topbar into proxied pages (prevents double topbar)
// - Injects only a lightweight rewrite script into proxied HTML
// - Handles srcset, data-src, poster, data-srcset, CSS url(...), meta-refresh, form actions
// - Preserves Content-Encoding, Content-Type, Cache-Control for assets
// - Sets headers BEFORE streaming and avoids setting headers after res.headersSent
//
// Replace DEPLOYMENT_ORIGIN with your Koyeb deployment origin (no trailing slash).
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

// -------------------- Configuration --------------------
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX_SIZE = 128 * 1024; // 128KB
const FETCH_TIMEOUT_MS = 25000;
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");

// Asset extensions that are performance-sensitive; we will stream them directly and avoid HTML-style rewriting.
// They are still proxied through the backend (proxy-all), but treated as binary streaming paths (no transforms).
const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg",
  ".ico", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map", ".mp4", ".webm"
];
// Also treat service worker scripts specially
const SPECIAL_PATH_SEGMENTS = ["service-worker.js", "sw.js", "worker.js"];

// Ensure cache dir exists (async)
if (ENABLE_DISK_CACHE) {
  fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// -------------------- Middleware --------------------
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -------------------- In-memory cache (non-blocking disk writes) --------------------
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheGet(key) {
  const ent = MEM_CACHE.get(key);
  if (!ent) return null;
  if ((now() - ent.t) > CACHE_TTL) { MEM_CACHE.delete(key); return null; }
  return ent.v;
}
function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, encodeURIComponent(Buffer.from(key).toString("base64")));
    (async () => {
      try { await fsPromises.writeFile(fname, JSON.stringify({ t: now(), v: val }), "utf8"); } catch (e) { /* ignore */ }
    })();
  }
}

// -------------------- Sessions and Cookies --------------------
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
  // MUST be set before streaming begins
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function setSessionCookieHeaderIfSafe(res, sid) {
  if (res.headersSent) return;
  setSessionCookieHeader(res, sid);
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

// -------------------- Helpers --------------------
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

// If an href already contains /proxy?url= OR resolves to our DEPLOYMENT_ORIGIN /proxy path, treat as proxied
function isAlreadyProxiedHref(href) {
  if (!href) return false;
  try {
    if (href.includes("/proxy?url=")) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if (resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch (e) {}
  return false;
}

// Convert possibly-relative url to a proxied URL on our deployment origin
function toDeploymentProxyLink(href, base) {
  if (!href) return href;
  if (isAlreadyProxiedHref(href)) {
    // If it points to another host's /proxy?url=..., extract original 'url' param and re-map to our deployment
    try {
      const resolved = new URL(href, base || DEPLOYMENT_ORIGIN);
      if (resolved.pathname.startsWith("/proxy")) {
        const original = resolved.searchParams.get("url");
        if (original) return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(original)}`;
      }
    } catch (e) {}
    return href;
  }
  const abs = toAbsolute(href, base) || href;
  try {
    const u = new URL(abs);
    return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch (e) { return href; }
}

// Quick check: does a path look like an asset (by extension or path fragment)
function looksLikeAssetPath(urlStr) {
  if (!urlStr) return false;
  try {
    const url = new URL(urlStr, DEPLOYMENT_ORIGIN);
    const p = url.pathname.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (p.endsWith(ext)) return true;
    for (const seg of SPECIAL_PATH_SEGMENTS) if (p.endsWith(seg)) return true;
    return false;
  } catch (e) {
    // fallback by substring
    const p = urlStr.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (p.endsWith(ext)) return true;
    for (const seg of SPECIAL_PATH_SEGMENTS) if (p.endsWith(seg)) return true;
    return false;
  }
}

// -------------------- Minimal rewrite script to inject into proxied HTML pages
// NOTE: This script ONLY rewrites links/assets to point to DEPLOYMENT_ORIGIN/proxy?url=...
// It does NOT inject the UI topbar. The topbar UI is expected to be in public/index.html (client).
const INJECT_REWRITE_SCRIPT = `
<script>
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u){
    try{
      if(!u) return u;
      if(u.includes('/proxy?url=')) return u;
      const abs = new URL(u, document.baseURI).href;
      if(abs.startsWith(DEPLOY + '/proxy')) return abs;
      return DEPLOY + '/proxy?url=' + encodeURIComponent(abs);
    } catch(e){ return u; }
  }
  // anchors
  document.querySelectorAll('a[href]').forEach(a=>{
    try {
      const h = a.getAttribute('href'); if(!h) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return;
      if(h.includes('/proxy?url=')) return;
      a.setAttribute('href', prox(h));
      a.removeAttribute('target');
    } catch(e){}
  });
  // forms
  document.querySelectorAll('form[action]').forEach(f=>{
    try {
      const act = f.getAttribute('action'); if(!act) return;
      if(act.includes('/proxy?url=')) return;
      f.setAttribute('action', prox(act));
    } catch(e){}
  });
  // attributes and srcset
  const attrs = ['src','href','poster','data-src','data-href'];
  ['img','script','link','iframe','source','video','audio'].forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      try {
        attrs.forEach(attr=>{
          if(el.hasAttribute && el.hasAttribute(attr)){
            const v = el.getAttribute(attr);
            if(!v) return;
            if(/^data:/i.test(v)) return;
            if(v.includes('/proxy?url=')) return;
            el.setAttribute(attr, prox(v));
          }
        });
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }
        if(el.hasAttribute && el.hasAttribute('data-srcset')){
          const ss = el.getAttribute('data-srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('data-srcset', parts.join(', '));
        }
      } catch(e){}
    });
  });
  // style tag url(...) rewrite (best-effort)
  try {
    document.querySelectorAll('style').forEach(s => {
      try {
        let t = s.textContent;
        if(!t) return;
        t = t.replace(/url\$begin:math:text$\(\[\'\"\]\?\)\(\.\*\?\)\\\\1\\$end:math:text$/g, function(full,q,u){
          if(!u) return full;
          if(/^data:/i.test(u) || u.includes('/proxy?url=')) return full;
          try { const abs = new URL(u, document.baseURI).href; return 'url("' + DEPLOY + '/proxy?url=' + encodeURIComponent(abs) + '")'; } catch(e) { return full; }
        });
        s.textContent = t;
      } catch(e){}
    });
  } catch(e){}
  // intercept fetch to route through proxy
  try {
    const orig = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')){
          resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request){
          if(!resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      } catch(e){}
      return orig(resource, init);
    };
  } catch(e){}
})();
</script>
`;

// -------------------- WebSocket telemetry --------------------
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

// -------------------- Main /proxy handler --------------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // Normalize "google.com" style inputs
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  const accept = (req.headers.accept || "").toLowerCase();

  // Quick cached asset return for non-HTML accept
  const assetCacheKey = raw + "::asset";
  if (!accept.includes("text/html")) {
    const cachedAsset = cacheGet(assetCacheKey);
    if (cachedAsset) {
      if (cachedAsset.headers) Object.entries(cachedAsset.headers).forEach(([k, v]) => res.setHeader(k, v));
      // set cookie before sending
      setSessionCookieHeader(res, session.sid);
      try { return res.send(Buffer.from(cachedAsset.body, "base64")); } catch (e) { /* fallback to network */ }
    }
  }

  // Cached HTML
  const htmlCacheKey = raw + "::html";
  if (accept.includes("text/html")) {
    const ch = cacheGet(htmlCacheKey);
    if (ch) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      setSessionCookieHeader(res, session.sid);
      return res.send(ch);
    }
  }

  // Origin request headers (forward user agent, accept, accept-language, accept-encoding)
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
    // If the target looks like an asset or a special path, treat it as binary streaming path (no HTML transforms)
    const treatAsAsset = looksLikeAssetPath(raw);

    // fetch origin with timeout
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const originRes = await fetch(raw, { headers: originHeaders, redirect: "follow", signal: controller.signal });
    clearTimeout(to);

    // store Set-Cookie headers into session store
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    const contentType = (originRes.headers.get("content-type") || "").toLowerCase();

    // If non-HTML OR treatAsAsset => stream directly (images, js, css, wasm, service worker etc.)
    if (treatAsAsset || !contentType.includes("text/html")) {
      // Prepare headers before streaming
      const cencoding = originRes.headers.get("content-encoding");
      const clen = originRes.headers.get("content-length");
      const cacheControl = originRes.headers.get("cache-control");
      const ct = originRes.headers.get("content-type");
      const vary = originRes.headers.get("vary");

      if (ct) res.setHeader("Content-Type", ct);
      if (cencoding) res.setHeader("Content-Encoding", cencoding);
      if (clen) res.setHeader("Content-Length", clen);
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      if (vary) res.setHeader("Vary", vary);
      res.setHeader("Access-Control-Allow-Origin", "*");

      // set session cookie header before streaming begins
      setSessionCookieHeader(res, session.sid);

      // small-asset cache: if content-length known and small, buffer, cache and send
      const contentLengthNumber = clen ? parseInt(clen, 10) : NaN;
      if (!isNaN(contentLengthNumber) && contentLengthNumber <= ASSET_CACHE_MAX_SIZE) {
        try {
          const arr = await originRes.arrayBuffer();
          const buf = Buffer.from(arr);
          cacheSet(assetCacheKey, { headers: { "Content-Type": ct }, body: buf.toString("base64") });
          return res.send(buf);
        } catch (e) {
          // fallback to streaming below
        }
      }

      // stream using pipeline; pipeline will close res automatically
      if (originRes.body && typeof originRes.body.pipe === "function") {
        try {
          await pipe(originRes.body, res);
          return;
        } catch (pipeErr) {
          // streaming failed (premature close etc.) -> safe fallback: try buffering then send if possible
          console.warn("Asset pipeline failed:", pipeErr && pipeErr.message);
          try {
            const fallbackBufArr = await originRes.arrayBuffer();
            const buf = Buffer.from(fallbackBufArr);
            if (!res.headersSent) {
              // headers already set; send buffer
              return res.send(buf);
            } else {
              try { res.end(); } catch (e) {}
              return;
            }
          } catch (finalErr) {
            console.error("Asset fallback failed:", finalErr && finalErr.message);
            try { if (!res.headersSent) res.status(502).end("Asset stream error"); else res.end(); } catch (e) {}
            return;
          }
        }
      } else {
        // fallback: buffer & send
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        return res.send(buf);
      }
    }

    // ---------- HTML path ----------
    let html = await originRes.text();

    // remove CSP meta tags (they block our injection) and integrity/crossorigin attributes that break proxied asset loads
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

    const finalUrl = originRes.url || raw;

    // ensure <base href> so relative URLs resolve
    if (/<head[\s>]/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // Server-side rewrites: anchors -> DEPLOYMENT_ORIGIN/proxy?url=abs
    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function (m, pre, q, val) {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (isAlreadyProxiedHref(val)) {
        // If the href resolves to another host's /proxy?url=..., map it back to our deployment proxy
        try {
          const resolved = new URL(val, finalUrl);
          if (resolved.pathname.startsWith("/proxy")) {
            const orig = resolved.searchParams.get("url");
            if (orig) return `<a${pre}href="${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(orig)}"`;
          }
        } catch (e) { /* ignore */ }
        return m;
      }
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // Rewrite asset tags (img/script/link/source/video/audio/iframe) for src/href/srcset/poster/data-src/data-srcset
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|poster|data-src|data-href|srcset|data-srcset)=)(["'])([^"']*)\3/gi,
      function (m, prefix, attr, q, val) {
        if (!val) return m;
        if (/^data:/i.test(val)) return m; // keep data URLs
        if (isAlreadyProxiedHref(val)) {
          // rewrite other-host's /proxy?url= to our deployment proxy
          try {
            const resolved = new URL(val, finalUrl);
            if (resolved.pathname.startsWith("/proxy")) {
              const orig = resolved.searchParams.get("url");
              if (orig) return `${prefix}${attr}${q}${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(orig)}${q}`;
            }
          } catch (e) {}
          return m;
        }
        const abs = toAbsolute(val, finalUrl) || val;
        if (attr.toLowerCase().startsWith("srcset") || attr.toLowerCase().startsWith("data-srcset")) {
          const parts = val.split(",").map(p => {
            const [u, rest] = p.trim().split(/\s+/, 2);
            if (!u) return p;
            if (/^data:/i.test(u)) return p;
            const a = toAbsolute(u, finalUrl) || u;
            return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(a)}` + (rest ? " " + rest : "");
          });
          return `${prefix}${attr}${q}${parts.join(", ")}${q}`;
        }
        return `${prefix}${attr}${q}${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}${q}`;
      });

    // Rewrite CSS url(...)
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, function (m, q, val) {
      if (!val) return m;
      if (/^data:/i.test(val) || isAlreadyProxiedHref(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Rewrite form actions to proxy
    html = html.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function (m, pre, q, val) {
      if (!val) return m;
      if (isAlreadyProxiedHref(val) || /^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // Meta refresh rewrite
    html = html.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi, function (m) {
      const match = m.match(/content\s*=\s*["']([^"']*)["']/i);
      if (!match) return m;
      const parts = match[1].split(";");
      if (parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
      if (!urlPart) return m;
      const dest = urlPart[1].replace(/['"]/g, "").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // Remove some tracking scripts (best-effort)
    html = html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi, "");
    html = html.replace(/<script[^>]*>\s*window\.ga=.*?<\/script>/gi, "");

    // Inject only the rewrite script (do NOT inject topbar). To prevent double injection across navigations, we check a marker.
    const marker = "<!--EUPHORIA-REWRITE-INJECTED-->";
    if (!html.includes(marker)) {
      if (/<body[^>]*>/i.test(html)) {
        html = html.replace(/<body([^>]*)>/i, (m, g) => `<body${g}>` + marker + INJECT_REWRITE_SCRIPT);
      } else {
        html = marker + INJECT_REWRITE_SCRIPT + html;
      }
    }

    // Cache transformed HTML
    try { cacheSet(htmlCacheKey, html); } catch (e) { /* ignore */ }

    // Set headers BEFORE streaming
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Access-Control-Allow-Origin", "*");
    setSessionCookieHeader(res, session.sid);

    // Stream via scramjet StringStream (progressive)
    const stream = StringStream.from(html);
    try {
      await pipe(stream, res);
    } catch (streamErr) {
      console.error("HTML stream error:", streamErr && streamErr.message);
      try { if (!res.headersSent) res.status(502).end("Stream error"); else res.end(); } catch (e) {}
    }

    return;

  } catch (err) {
    console.error("Proxy fetch error:", err && err.message ? err.message : err);
    setSessionCookieHeaderIfSafe(res, session.sid);
    if (!res.headersSent) return res.status(502).send(`<div style="padding:1rem;background:#fee;color:#900;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
    try { res.end(); } catch (e) {}
    return;
  }
});

// -------------------- Serve index.html fallback --------------------
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// -------------------- Periodic cleanup --------------------
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 24); // 24 hours
  for (const [sid, payload] of SESSIONS.entries()) {
    if ((payload.last || 0) < cutoff) SESSIONS.delete(sid);
  }
  for (const [k, v] of MEM_CACHE.entries()) {
    if ((now() - v.t) > CACHE_TTL) MEM_CACHE.delete(k);
  }
}, 1000 * 60 * 30); // every 30 minutes

console.log("Euphoria proxy (Express + Scramjet) listening on port", PORT);