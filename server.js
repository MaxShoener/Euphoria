// server.js — EUPHORIA v2 (complete, corrected)
// No iframe. Progressive HTML streaming. Session cookie persistence.
// Rewrites anchors/assets/fetch/XHR to route through DEPLOYMENT_ORIGIN/proxy?url=...

import express from "express";
import fetch from "node-fetch";
import scramjetPkg from "scramjet";
const { StringStream } = scramjetPkg;
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { EventEmitter } from "events";
import { WebSocketServer } from "ws";

EventEmitter.defaultMaxListeners = 200;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- CONFIG ----------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_TTL = 1000 * 60 * 6;
const ASSET_CACHE_MAX = 256 * 1024;
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");
const FETCH_TIMEOUT_MS = 30000;

if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// heuristics
const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif",
  ".svg", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3"
];
const SPECIAL_ASSET_NAMES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

const DROP_HEADERS_LOWER = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// ---------------- APP ----------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// serve public/
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---------------- SESSIONS ----------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();

function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: Date.now() }; SESSIONS.set(sid, payload); return { sid, payload }; }

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
  const payload = SESSIONS.get(sid);
  payload.last = Date.now();
  return { sid, payload };
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

setInterval(() => {
  const cutoff = Date.now() - (1000 * 60 * 30);
  for (const [sid, payload] of SESSIONS.entries()) {
    if (payload.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 5);

// ---------------- CACHE ----------------
const MEM_CACHE = new Map();
function cacheKey(s) { return Buffer.from(s).toString("base64url"); }
function now() { return Date.now(); }

function cacheGet(key) {
  const entry = MEM_CACHE.get(key);
  if (entry && (now() - entry.t) < CACHE_TTL) return entry.v;
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if (fs.existsSync(fname)) {
      try {
        const raw = fs.readFileSync(fname, "utf8");
        const obj = JSON.parse(raw);
        if ((now() - obj.t) < CACHE_TTL) {
          MEM_CACHE.set(key, { v: obj.v, t: obj.t });
          return obj.v;
        } else {
          try { fs.unlinkSync(fname); } catch (e) {}
        }
      } catch (e) {}
    }
  }
  return null;
}

function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(()=>{});
  }
}

// ---------------- HELPERS ----------------
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
  try {
    const u = new URL(absUrl);
    return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch (e) {
    try { const u2 = new URL("https://" + absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; }
    catch (e2) { return absUrl; }
  }
}
function toDeploymentProxyLink(href, base) {
  if (!href) return href;
  if (isAlreadyProxiedHref(href)) {
    try {
      const resolved = new URL(href, base || DEPLOYMENT_ORIGIN);
      if (resolved.pathname.startsWith("/proxy")) {
        const orig = resolved.searchParams.get("url");
        if (orig) return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(orig)}`;
      }
    } catch (e) {}
    return href;
  }
  const abs = toAbsolute(href, base) || href;
  return proxyizeAbsoluteUrl(abs);
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

// ---------------- INJECT SCRIPT ----------------
// Small rewrite shim only (no topbar injection)
const INJECT_REWRITE_SCRIPT = `
<script>
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; const abs=new URL(u, document.baseURI).href; return DEPLOY + '/proxy?url=' + encodeURIComponent(abs);}catch(e){return u;} }
  // anchors
  document.querySelectorAll('a[href]').forEach(a=>{ try{ const h=a.getAttribute('href'); if(!h) return; if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return; if(h.includes('/proxy?url=')) return; a.setAttribute('href', prox(h)); a.removeAttribute('target'); }catch(e){} });
  // forms
  document.querySelectorAll('form[action]').forEach(f=>{ try{ const act = f.getAttribute('action'); if(!act) return; if(act.includes('/proxy?url=')) return; f.setAttribute('action', prox(act)); }catch(e){} });
  // assets + srcset
  const attrs = ['src','href','poster','data-src','data-href'];
  ['img','script','link','iframe','source','video','audio'].forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      try{
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
            const [u,rest] = p.trim().split(/\\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }
      }catch(e){}
    });
  });
  // fetch interception
  try {
    const origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        else if(resource instanceof Request) {
          if(!resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      } catch(e){}
      return origFetch(resource, init);
    };
  } catch(e){}
  // XHR interception
  try {
    const OrigXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new OrigXHR();
      const origOpen = xhr.open;
      xhr.open = function(method, url, ...rest){
        try {
          if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)){
            url = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href);
          }
        } catch(e){}
        return origOpen.call(this, method, url, ...rest);
      };
      return xhr;
    };
  } catch(e){}
})();
</script>
`;

// ---------------- WEBSOCKET ----------------
const server = app.listen(PORT, () => console.log(`Euphoria v2 running on port ${PORT}`));
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

// ---------------- /proxy ----------------
app.get("/proxy", async (req, res) => {
  // support ?url= and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize shorthand hostnames
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch (e) {}

  // If client explicitly marked as Euphoria client, or Accept includes text/html, treat as HTML
  const accept = (req.headers.accept || "").toLowerCase();
  const forcedHtml = !!req.headers["x-euphoria-client"];
  const wantHtml = forcedHtml || accept.includes("text/html");

  // caching keys
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // asset quick-return if not asking for HTML
  if (!wantHtml) {
    const cachedAsset = cacheGet(assetKey);
    if (cachedAsset) {
      try { Object.entries(cachedAsset.headers || {}).forEach(([k,v]) => res.setHeader(k,v)); } catch(e){}
      return res.send(Buffer.from(cachedAsset.body,"base64"));
    }
  }

  if (wantHtml) {
    const cachedHtml = cacheGet(htmlKey);
    if (cachedHtml) { res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // prepare origin headers
  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/2.0",
    "Accept": wantHtml ? "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" : (req.headers.accept || "*/*"),
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if (req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  let originRes;
  try {
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "follow", signal: controller.signal });
    clearTimeout(to);
  } catch (err) {
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // persist set-cookie headers to session
  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch (e) {}

  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = looksLikeAssetPath(raw) || !isHtml;

  // Asset streaming path
  if (!wantHtml || treatAsAsset) {
    // forward safe headers
    try {
      originRes.headers.forEach((v,k) => { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v); } catch(e){} });
    } catch(e){}
    try { setSessionCookieHeader(res, session.sid); } catch(e){}
    // try to read ArrayBuffer (for caching small assets), else fallback to streaming
    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if (buf.length < ASSET_CACHE_MAX) {
        try { cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch(e){}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if (originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch (err) {
      // fallback streaming
      try {
        if (originRes.body && originRes.body.pipe) {
          // forward minimal headers then pipe
          try { res.setHeader("Content-Type", contentType || "application/octet-stream"); } catch(e){}
          originRes.body.pipe(res);
          return;
        } else {
          return res.status(502).send("Euphoria: asset stream failed");
        }
      } catch (e) {
        return res.status(502).send("Euphoria: asset stream failed");
      }
    }
  }

  // HTML transform path (wantHtml && isHtml)
  // forward headers except dangerous ones
  try { originRes.headers.forEach((v, k) => { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v); } catch(e){} }); } catch(e){}

  try { res.setHeader("Content-Type", "text/html; charset=utf-8"); } catch(e){}

  try {
    const s = StringStream.from(originRes.body);
    let injected = false;
    const parts = [];

    await s
      .map(chunk => chunk.toString())
      .map(chunk => {
        // sanitize integrity/crossorigin
        let str = chunk.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
        // inject base / rewrite script early if possible
        if (!injected) {
          if (/<head[^>]*>/i.test(str)) {
            const finalUrl = originRes.url || raw;
            str = str.replace(/<head([^>]*)>/i, `<head$1><base href="${finalUrl}">`);
          }
          if (str.toLowerCase().includes("</body>")) {
            str = str.replace(/<\/body>/i, INJECT_REWRITE_SCRIPT + "</body>");
            injected = true;
          } else if (/<\/head>/i.test(str) && !injected) {
            str = str.replace(/<\/head>/i, INJECT_REWRITE_SCRIPT + "</head>");
            injected = true;
          }
        }
        // conservative rewriting for anchors/assets
        str = str.replace(/(<\s*a\b[^>]*?\bhref=)(["'])([^"']*)\2/gi, function(m, pre, q, val) {
          try {
            if (!val) return m;
            if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
            if (isAlreadyProxiedHref(val)) return m;
            const abs = toAbsolute(val, originRes.url || raw) || val;
            return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}`;
          } catch (e) { return m; }
        });
        str = str.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?\b(?:src|href)=)(["'])([^"']*)\2/gi, function(m, pre, q, val) {
          try {
            if (!val) return m;
            if (/^data:/i.test(val)) return m;
            if (isAlreadyProxiedHref(val)) return m;
            const abs = toAbsolute(val, originRes.url || raw) || val;
            return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}`;
          } catch (e) { return m; }
        });
        return str;
      })
      .each(async transformedChunk => {
        try {
          if (!res.headersSent) {
            try { setSessionCookieHeader(res, session.sid); } catch (e) {}
          }
          parts.push(transformedChunk);
          res.write(transformedChunk);
        } catch (e) {
          // ignore write errors (client disconnect)
        }
      });

    try { res.end(); } catch (e) {}
    try {
      const finalHtml = parts.join("");
      if (finalHtml.length > 0 && finalHtml.length < 512 * 1024) cacheSet(htmlKey, finalHtml);
    } catch (e) {}
    return;
  } catch (err) {
    console.error("html transform error", err && err.message ? err.message : err);
    if (!res.headersSent) return res.status(500).send("Euphoria: failed to process HTML");
    try { res.end(); } catch (e) {}
    return;
  }
});

// ---------------- fallback root ----------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), err => {
    if (err) res.status(500).send("Failed to serve index.html");
  });
});
app.get("*", (req, res, next) => {
  if (req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ---------------- error handlers ----------------
process.on("unhandledRejection", err => console.error("unhandledRejection", err));
process.on("uncaughtException", err => console.error("uncaughtException", err));