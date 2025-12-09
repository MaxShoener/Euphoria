// server.js
// EUPHORIA v2 — Proxy (no iframe) with per-origin rewrites (Option A)
// - Rewrites HTML so subresources are routed through /proxy?url=ABS
// - Rewrites Location: headers to route redirects through /proxy
// - Fallback: any unknown path requested on host will be proxied to origin derived from Referer
// - Strips CSP/integrity/crossorigin attributes that would break proxied pages
// - Small in-memory + optional disk cache, cookie session persistence
// - Streams binary assets, text/html is transformed
//
// Requirements: Node 18+ (global fetch available). If running older Node, install node-fetch
//
// Notes:
//  - This file is intentionally long and commented to be explicit and robust.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { EventEmitter } from "events";

EventEmitter.defaultMaxListeners = 200; // avoid MaxListenersExceededWarning

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ------------- CONFIG -------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX = 256 * 1024; // 256 KB threshold to cache
const FETCH_TIMEOUT_MS = 30000; // 30s

const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif",
  ".svg", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3"
];
const SPECIAL_ASSET_NAMES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// Headers to drop from proxied responses: they interfere with injection or block resources
const DROP_HEADERS_LOWER = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// ------------- EXPRESS SETUP -------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// serve static public files (index.html, css, assets for UI)
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ------------- SIMPLE CACHE (memory + optional disk) -------------
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheKey(s) { return Buffer.from(s).toString("base64url"); }
function cacheGet(key) {
  const entry = MEM_CACHE.get(key);
  if (entry && (now() - entry.t) < CACHE_TTL) return entry.v;
  if (ENABLE_DISK_CACHE) {
    try {
      const fname = path.join(CACHE_DIR, cacheKey(key));
      if (fs.existsSync(fname)) {
        const raw = fs.readFileSync(fname, "utf8");
        const obj = JSON.parse(raw);
        if ((now() - obj.t) < CACHE_TTL) { MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
        try { fs.unlinkSync(fname); } catch (e) {}
      }
    } catch (e) {}
  }
  return null;
}
function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(() => {});
  }
}

// ------------- SESSION / COOKIE STORE -------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();

function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: now() }; SESSIONS.set(sid, payload); return { sid, payload }; }

function parseCookies(cookieHeader = "") {
  const out = {};
  cookieHeader.split(";").forEach(p => {
    const [k, v] = (p || "").split("=").map(s => (s || "").trim());
    if (k && v) out[k] = v;
  });
  return out;
}

function getSessionFromReq(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  let sid = cookies[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid); payload.last = now(); return { sid, payload };
}

function setSessionCookieHeader(res, sid) {
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}

function storeSetCookieToSession(setCookies = [], sessionPayload) {
  for (const sc of setCookies) {
    try {
      const kv = sc.split(";")[0];
      const idx = kv.indexOf("=");
      if (idx === -1) continue;
      const k = kv.slice(0, idx).trim();
      const v = kv.slice(idx + 1).trim();
      if (k) sessionPayload.cookies.set(k, v);
    } catch (e) {}
  }
}
function buildCookieHeader(map) {
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

// cleanup stale sessions occasionally
setInterval(() => {
  const cutoff = Date.now() - (1000 * 60 * 30); // 30 minutes
  for (const [sid, payload] of SESSIONS.entries()) if (payload.last < cutoff) SESSIONS.delete(sid);
}, 1000 * 60 * 5);

// ------------- HELPERS -------------
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function isAlreadyProxiedHref(href) {
  if (!href) return false;
  try {
    if (href.includes("/proxy?url=")) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if (resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch (e) {}
  return false;
}
function proxyizeAbsoluteUrl(absUrl) {
  try { const u = new URL(absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; }
  catch (e) { try { const u2 = new URL("https://" + absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch (e2) { return absUrl; } }
}
function looksLikeAssetPath(urlStr) {
  if (!urlStr) return false;
  try {
    const p = new URL(urlStr, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (p.endsWith(ext)) return true;
    for (const seg of SPECIAL_ASSET_NAMES) if (p.endsWith(seg)) return true;
    return false;
  } catch (e) {
    const lower = urlStr.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (lower.endsWith(ext)) return true;
    for (const seg of SPECIAL_ASSET_NAMES) if (lower.endsWith(seg)) return true;
    return false;
  }
}

// sanitize HTML: remove CSP meta, integrity, crossorigin
function sanitizeHtmlStr(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch (e) {}
  return html;
}

// conservative replacements to proxyize href/src/srcset/form actions/css url()
function transformHtmlToProxy(html, baseUrl) {
  if (!html) return html;
  let out = html;

  // add base tag if none (helps scripts that use relative resolution)
  try {
    if (/<head[^>]*>/i.test(out) && !/<base\s/i.test(out)) {
      out = out.replace(/<head([^>]*)>/i, function (m, g) {
        return `<head${g}><base href="${baseUrl}">`;
      });
    }
  } catch (e) {}

  // anchor hrefs
  out = out.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function (m, pre, q, val) {
    if (!val) return m;
    if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
    if (isAlreadyProxiedHref(val)) return m;
    const abs = toAbsolute(val, baseUrl) || val;
    return `<a${pre}href="${proxyizeAbsoluteUrl(abs)}"`;
  });

  // form actions
  out = out.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function (m, pre, q, val) {
    if (!val) return m;
    if (/^(javascript:|#)/i.test(val)) return m;
    if (isAlreadyProxiedHref(val)) return m;
    const abs = toAbsolute(val, baseUrl) || val;
    return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}`;
  });

  // src/href on common tags
  out = out.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?\b(?:src|href)=)(["'])([^"']*)\2/gi, function (m, pre, q, val) {
    if (!val) return m;
    if (/^data:/i.test(val)) return m;
    if (isAlreadyProxiedHref(val)) return m;
    const abs = toAbsolute(val, baseUrl) || val;
    return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}`;
  });

  // srcset attribute
  out = out.replace(/(<[^>]+\s)srcset=(["'])([^"']*)\2/gi, function (m, pre, q, val) {
    try {
      const parts = val.split(',').map(p => {
        const [u, rest] = p.trim().split(/\s+/, 2);
        if (!u) return p;
        if (/^data:/i.test(u)) return p;
        if (isAlreadyProxiedHref(u)) return p;
        const abs = toAbsolute(u, baseUrl) || u;
        return proxyizeAbsoluteUrl(abs) + (rest ? ' ' + rest : '');
      });
      return pre + 'srcset=' + q + parts.join(', ') + q;
    } catch (e) { return m; }
  });

  // CSS url(...) references
  out = out.replace(/url\((['"]?)(.*?)\1\)/gi, function (m, q, val) {
    if (!val) return m;
    if (/^data:/i.test(val)) return m;
    try {
      if (isAlreadyProxiedHref(val)) return `url(${val})`;
      const abs = toAbsolute(val, baseUrl) || val;
      return `url("${proxyizeAbsoluteUrl(abs)}")`;
    } catch (e) { return m; }
  });

  // inline JS navigation assignments (best-effort)
  out = out.replace(/(window\.location(?:\.href|\.assign|\.replace)?\s*=\s*['"])([^'"]+)(['"])/gi, function (m, p1, p2, p3) {
    try {
      if (isAlreadyProxiedHref(p2)) return m;
      const abs = toAbsolute(p2, baseUrl) || p2;
      return p1 + proxyizeAbsoluteUrl(abs) + p3;
    } catch (e) { return m; }
  });

  // meta refresh
  out = out.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi, function (m) {
    const match = m.match(/content\s*=\s*["']([^"']*)["']/i);
    if (!match) return m;
    const parts = match[1].split(";");
    if (parts.length < 2) return m;
    const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
    if (!urlPart) return m;
    const dest = urlPart[1].replace(/['"]/g, "").trim();
    const abs = toAbsolute(dest, baseUrl) || dest;
    return `<meta http-equiv="refresh" content="${parts[0]};url=${proxyizeAbsoluteUrl(abs)}">`;
  });

  return out;
}

// ------------- INJECT CLIENT REWRITE SNIPPET (small) -------------
// This is placed in HTML so runtime-created nodes (via JS) will be proxied clientside too.
// It is intentionally tiny.
const CLIENT_REWRITE_SNIPPET = `
<!-- EUPHORIA_REWRITE_SNIPPET -->
<script>
(function(){
  try {
    const DEPLOY = "${DEPLOYMENT_ORIGIN}";
    function prox(u){
      try {
        if(!u) return u;
        if(u.includes('/proxy?url=')) return u;
        if(/^data:/i.test(u)) return u;
        const abs = new URL(u, document.baseURI).href;
        return DEPLOY + '/proxy?url=' + encodeURIComponent(abs);
      } catch(e){ return u; }
    }
    function rewriteRoot(root){
      try {
        root.querySelectorAll('a[href]').forEach(a=>{
          try { const h=a.getAttribute('href'); if(!h) return; if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return; if(h.includes('/proxy?url=')) return; a.setAttribute('href', prox(h)); a.removeAttribute('target'); }catch(e){}
        });
        root.querySelectorAll('form[action]').forEach(f=>{
          try { const a=f.getAttribute('action'); if(!a) return; if(a.includes('/proxy?url=')) return; f.setAttribute('action', prox(a)); }catch(e){}
        });
        ['img','script','link','iframe','source','video','audio'].forEach(tag=>{
          root.querySelectorAll(tag+'[src]').forEach(el=>{
            try { const v=el.getAttribute('src'); if(!v) return; if(/^data:/i.test(v)) return; if(v.includes('/proxy?url=')) return; el.setAttribute('src', prox(v)); }catch(e){}
          });
          root.querySelectorAll(tag+'[href]').forEach(el=>{
            try { const v=el.getAttribute('href'); if(!v) return; if(/^data:/i.test(v)) return; if(v.includes('/proxy?url=')) return; el.setAttribute('href', prox(v)); }catch(e){}
          });
        });
        root.querySelectorAll('[srcset]').forEach(el=>{
          try {
            const ss = el.getAttribute('srcset') || '';
            const parts = ss.split(',').map(p=>{
              const [u, rest] = p.trim().split(/\\s+/,2);
              if(!u) return p;
              if(/^data:/i.test(u)) return p;
              return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
            });
            el.setAttribute('srcset', parts.join(', '));
          } catch(e){}
        });
      } catch(e){}
    }
    rewriteRoot(document);
    new MutationObserver(muts=>{ for(const m of muts) m.addedNodes && Array.from(m.addedNodes).forEach(n=>{ if(n.nodeType!==1) return; rewriteRoot(n); }); }).observe(document.documentElement||document, { childList:true, subtree:true });
    // intercept fetch
    const orig = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        else if(resource instanceof Request) { if(!resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource); }
      } catch(e){}
      return orig(resource, init);
    };
  } catch(e){}
})();
</script>
`;

// ------------- WEBSOCKET TELEMETRY -------------
const server = app.listen(PORT, () => console.log(`Euphoria v2 starting on port ${PORT}`));
import { WebSocketServer } from "ws";
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try {
      const parsed = JSON.parse(raw.toString());
      if (parsed && parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch (e) {}
  });
});

// ------------- CORE /proxy HANDLER -------------
app.get("/proxy", async (req, res) => {
  // support /proxy?url=... and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize schemeless hosts (bare example.com -> https://example.com)
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session + cookie header must be established before streaming
  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch(e){}

  // Attempt quick cache for non-html asset requests (client may request via Accept header)
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers["x-euphoria-client"] === "v2";
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  if (!wantHtml) {
    const cached = cacheGet(assetKey);
    if (cached) {
      if (cached.headers) Object.entries(cached.headers).forEach(([k, v]) => { try { res.setHeader(k, v); } catch(e){} });
      return res.send(Buffer.from(cached.body, "base64"));
    }
  } else {
    const cachedHtml = cacheGet(htmlKey);
    if (cachedHtml) { res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // build headers to send upstream
  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/2.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if (req.headers.referer) originHeaders["Referer"] = req.headers.referer;
  // additionally spoof origin/referer to the target origin to help origin-sensitive sites
  try { originHeaders["Origin"] = new URL(raw).origin; originHeaders["Referer"] = raw; } catch(e){}

  // fetch the origin (manual redirect handling so we can rewrite Location)
  let originRes;
  try {
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(to);
  } catch (err) {
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // capture upstream Set-Cookie and persist to session store
  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch (e) {}

  // Handle redirects server-side by rewriting Location to our /proxy endpoint
  const status = originRes.status || 200;
  if ([301, 302, 303, 307, 308].includes(status)) {
    const loc = originRes.headers.get("location");
    if (loc) {
      let abs;
      try { abs = new URL(loc, raw).href; } catch(e) { abs = loc; }
      const proxied = proxyizeAbsoluteUrl(abs);
      try { res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); } catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  // Content type check
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = looksLikeAssetPath(raw) || !isHtml;

  // If this is clearly a binary asset: stream/send as buffer
  if (treatAsAsset) {
    // forward safe headers
    try { originRes.headers.forEach((v, k) => { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v); } catch(e){} }); } catch(e){}
    try { setSessionCookieHeader(res, session.sid); } catch(e){}

    try {
      const array = await originRes.arrayBuffer();
      const buf = Buffer.from(array);
      if (buf.length < ASSET_CACHE_MAX) {
        try { cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch(e){}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if (originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch (err) {
      // fallback streaming
      try { originRes.body.pipe(res); return; } catch (e) { return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // HTML path: read text, sanitize and transform
  let html;
  try { html = await originRes.text(); } catch (e) { console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }

  // sanitize
  html = sanitizeHtmlStr(html);

  // inject client-side rewrite snippet and transform links/assets to be proxied via /proxy?url=ABS
  try {
    const finalUrl = originRes.url || raw;
    // perform conservative transform
    const transformed = transformHtmlToProxy(html, finalUrl);
    // ensure client snippet is present (so runtime-dynamically-added assets are proxied)
    let finalHtml = transformed;
    if (!finalHtml.includes("EUPHORIA_REWRITE_SNIPPET")) finalHtml = finalHtml.replace(/<\/body>/i, CLIENT_REWRITE_SNIPPET + "</body>");
    // forward safe headers (except dropped headers)
    try { originRes.headers.forEach((v, k) => { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v); } catch(e){} }); } catch(e){}
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    try { setSessionCookieHeader(res, session.sid); } catch(e){}

    // cache small HTML
    try { if (finalHtml && finalHtml.length < 512 * 1024) cacheSet(htmlKey, finalHtml); } catch(e){}

    return res.send(finalHtml);
  } catch (err) {
    console.error("html transform error", err);
    try { setSessionCookieHeader(res, session.sid); } catch(e){}
    return res.status(500).send("Euphoria: failed to transform HTML");
  }
});

// ------------- FALLBACK: proxy requests that look like subresource paths on our host -------------
// This is the key to solve requests like: browser requests /xjs/... after loading proxied google HTML
// We use the Referer header to figure out which proxied origin this request belongs to, then proxy the full path.
//
// Example: Browser requests GET https://useful-karil.../xjs/_/js/..., referer: https://useful-karil.../proxy?url=https%3A%2F%2Fwww.google.com%2F
// We will resolve absolute = new URL(req.originalUrl, originalOrigin).href -> https://www.google.com/xjs/...
// Then fetch that absolute and stream it back.
app.use(async (req, res, next) => {
  // Allow static files (public) and /proxy itself to go through earlier handlers
  const p = req.path || "/";
  // If path clearly targets our own API endpoints, skip
  if (p.startsWith("/proxy") || p.startsWith("/_euph_ws") || p.startsWith("/static") || p.startsWith("/public")) return next();

  // if request has a referer that contains /proxy?url=..., use it
  const referer = req.headers.referer || req.headers.referrer || "";
  const m = referer.match(/[?&]url=([^&]+)/);
  if (!m) return next();

  let orig;
  try { orig = decodeURIComponent(m[1]); } catch(e) { orig = null; }
  if (!orig) return next();

  // build absolute URL for this path relative to the original origin
  let baseOrigin;
  try { baseOrigin = new URL(orig).origin; } catch(e){ return next(); }
  const attempted = new URL(req.originalUrl, baseOrigin).href;

  // proxy this attempted URL (no HTML transform unless it's text/html)
  console.log("Fallback proxy for subresource:", attempted, "referer->", orig);
  // reuse proxy logic: fetch attempted and return
  try {
    const session = getSessionFromReq(req);
    setSessionCookieHeader(res, session.sid);
    const originHeaders = {
      "User-Agent": req.headers["user-agent"] || "Euphoria/2.0",
      "Accept": req.headers.accept || "*/*",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
    };
    const cookieHdr = buildCookieHeader(session.payload.cookies);
    if (cookieHdr) originHeaders["Cookie"] = cookieHdr;
    const controller = new AbortController();
    const to = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    const originRes = await fetch(attempted, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(to);

    // redirect handling
    if ([301,302,303,307,308].includes(originRes.status)) {
      const loc = originRes.headers.get("location");
      if (loc) {
        let abs;
        try { abs = new URL(loc, attempted).href; } catch(e) { abs = loc; }
        return res.redirect(proxyizeAbsoluteUrl(abs));
      }
    }

    // handle non-html assets
    const ct = (originRes.headers.get("content-type") || "").toLowerCase();
    const isHtml = ct.includes("text/html");
    if (!isHtml) {
      originRes.headers.forEach((v,k)=> { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v);}catch(e){} });
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      res.setHeader("Content-Type", ct || "application/octet-stream");
      if (originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    }

    // if HTML, perform transform (rare for fallback)
    let html = await originRes.text();
    html = sanitizeHtmlStr(html);
    const transformed = transformHtmlToProxy(html, originRes.url || attempted);
    let finalHtml = transformed;
    if(!finalHtml.includes("EUPHORIA_REWRITE_SNIPPET")) finalHtml = finalHtml.replace(/<\/body>/i, CLIENT_REWRITE_SNIPPET + "</body>");
    originRes.headers.forEach((v,k)=> { if(!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v);}catch(e){} });
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(finalHtml);
  } catch (err) {
    console.error("fallback proxy error", err);
    return next();
  }
});

// ------------- SPA / Client fallback (serve index.html for HTML accept) -------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ------------- ERR HANDLERS -------------
process.on("unhandledRejection", (r) => console.error("unhandledRejection", r));
process.on("uncaughtException", (err) => console.error("uncaughtException", err));

console.log("Euphoria v2 running on port", PORT);