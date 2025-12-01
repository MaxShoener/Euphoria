// server.js — EUPHORIA v2 (Google + Xbox fix applied)
// Features:
//  - No iframe anywhere.
//  - Proxy-all: HTML, JS, CSS, images, fonts, WASM, video, JSON, etc.
//  - Session cookie persistence (memory store).
//  - Deployment-aware rewrites.
//  - Injects a compact rewrite shim into proxied HTML (no topbar injection).
//  - Streams binary assets; progressive HTML handling via scramjet StringStream.
//  - Small in-memory + optional disk caching for assets and HTML.
//  - WebSocket telemetry endpoint at /_euph_ws.
//  - Robust header handling (no headers-after-send), increased listeners limit.

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
import { pipeline } from "stream";
import { promisify } from "util";
import { EventEmitter } from "events";
import { WebSocketServer } from "ws";

EventEmitter.defaultMaxListeners = 200;
const pipe = promisify(pipeline);
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

// ---------------- EXPRESS ----------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---------------- SESSION ----------------
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
      const v = kv.slice(idx+1).trim();
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

// ---------------- INJECTED REWRITE SCRIPT (NEW FETCH/XHR FIX) ----------------
const INJECT_REWRITE_SCRIPT = `
<script>
(function() {
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u) {
    try {
      if(!u) return u;
      if(u.includes('/proxy?url=')) return u;
      if(/^(data:|blob:|javascript:)/i.test(u)) return u;
      const abs = new URL(u, document.baseURI).href;
      return DEPLOY + '/proxy?url=' + encodeURIComponent(abs);
    } catch(e) { return u; }
  }

  // FETCH
  const origFetch = window.fetch;
  window.fetch = function(resource, init) {
    try {
      if (resource instanceof Request) {
        const newUrl = prox(resource.url);
        resource = new Request(newUrl, resource);
      } else if (typeof resource === "string") {
        resource = prox(resource);
      }
    } catch(e) {}
    return origFetch(resource, init);
  };

  // XHR
  const OrigXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    const xhr = new OrigXHR();
    const openOrig = xhr.open;
    xhr.open = function(method, url, ...rest) {
      try { url = prox(url); } catch(e) {}
      return openOrig.call(this, method, url, ...rest);
    };
    return xhr;
  };
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
    } catch(e){}
  });
});

// ---------------- /proxy ----------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url || (req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//,"")) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch(e){}

  const accept = (req.headers.accept || "").toLowerCase();
  const assetKey = raw+"::asset";
  if(!accept.includes("text/html")) {
    const cachedAsset = cacheGet(assetKey);
    if(cachedAsset) {
      if(cachedAsset.headers) Object.entries(cachedAsset.headers).forEach(([k,v])=>res.setHeader(k,v));
      return res.send(Buffer.from(cachedAsset.body,"base64"));
    }
  }

  const htmlKey = raw+"::html";
  if(accept.includes("text/html")) {
    const cachedHtml = cacheGet(htmlKey);
    if(cachedHtml) { res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/2.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if(req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  let originRes;
  try {
    const controller = new AbortController();
    const t = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect:"follow", signal:controller.signal });
    clearTimeout(t);
  } catch(err) {
    return res.status(502).send("Euphoria: failed to fetch target: "+String(err));
  }

  try { const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"]||[] : []; if(setCookies.length) storeSetCookieToSession(setCookies, session.payload); } catch(e){}

  const contentType = (originRes.headers.get("content-type")||"").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = looksLikeAssetPath(raw) || !isHtml;

  if(treatAsAsset){
    originRes.headers.forEach((v,k)=>{if(!DROP_HEADERS_LOWER.has(k.toLowerCase())) try{res.setHeader(k,v);}catch(e){}});
    try{ setSessionCookieHeader(res, session.sid); } catch(e){}
    try{
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if(buf.length < ASSET_CACHE_MAX) try{ cacheSet(assetKey,{headers:Object.fromEntries(originRes.headers.entries()),body:buf.toString("base64")}); } catch(e){}
      res.setHeader("Content-Type", contentType||"application/octet-stream");
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch(err){
      try{ originRes.body.pipe(res); return; } catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  try { originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS_LOWER.has(k.toLowerCase())) try{res.setHeader(k,v);}catch(e){} }); } catch(e){}

  res.setHeader("Content-Type","text/html; charset=utf-8");

  try {
    const s = StringStream.from(originRes.body);
    let injected = false;
    const parts = [];
    await s.map(chunk=>chunk.toString())
      .map(chunk=>{
        let str = chunk.replace(/\s+integrity=(["'])(.*?)\1/gi,"").replace(/\s+crossorigin=(["'])(.*?)\1/gi,"");
        if(!injected){
          if(/<head[^>]*>/i.test(str)){ str = str.replace(/<head([^>]*)>/i, `<head$1><base href="${originRes.url||raw}">`); }
          if(str.toLowerCase().includes("</body>")){ str = str.replace(/<\/body>/i, INJECT_REWRITE_SCRIPT+"</body>"); injected=true; }
          else if(/<\/head>/i.test(str) && !injected){ str = str.replace(/<\/head>/i, INJECT_REWRITE_SCRIPT+"</head>"); injected=true; }
        }
        str = str.replace(/(<\s*a\b[^>]*?\bhref=)(["'])([^"']*)\2/gi,(m,pre,q,val)=>{ try{ if(!val) return m; if(/^(javascript:|mailto:|tel:|#)/i.test(val)) return m; if(isAlreadyProxiedHref(val)) return m; const abs=toAbsolute(val,originRes.url||raw)||val; return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}` } catch(e){return m;} });
        str = str.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?\b(?:src|href)=)(["'])([^"']*)\2/gi,(m,pre,q,val)=>{ try{ if(!val) return m; if(/^data:/i.test(val)) return m; if(isAlreadyProxiedHref(val)) return m; const abs=toAbsolute(val,originRes.url||raw)||val; return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}` } catch(e){return m;} });
        return str;
      })
      .each(async chunk=>{ parts.push(chunk); try{ if(!res.headersSent) try{ setSessionCookieHeader(res, session.sid);} catch(e){} res.write(chunk);} catch(e){} });
    try{ res.end(); } catch(e){}
    try{ if(parts.join("").length<512*1024) cacheSet(htmlKey, parts.join("")); } catch(e){}
    return;
  } catch(err){ if(!res.headersSent) res.status(500).send("Euphoria: failed to process HTML"); else try{res.end();}catch(e){} return; }
});

// ---------------- ROOT ----------------
app.get("/", (req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.get("*",(req,res,next)=>{ if(req.method==="GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname,"public","index.html")); next(); });

process.on("unhandledRejection",err=>console.error("unhandledRejection",err));