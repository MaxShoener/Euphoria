// server.js — EUPHORIA v2 with jsdom HTML rewrite (no iframe)
// Drop into project root. Requires dependencies: express, node-fetch, scramjet, jsdom, compression, morgan, cors, ws

import express from "express";
import fetch from "node-fetch";
import scramjetPkg from "scramjet";
const { StringStream } = scramjetPkg;
import { JSDOM } from "jsdom";
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
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX = 256 * 1024; // bytes
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");
const FETCH_TIMEOUT_MS = 30000;

if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// asset heuristics
const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif",
  ".svg", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3"
];
const SPECIAL_ASSET_NAMES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

// headers to drop (prevent CSP / embed restrictions)
const DROP_HEADERS_LOWER = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// ---------------- EXPRESS SETUP ----------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
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

// cleanup stale sessions
setInterval(() => {
  const cutoff = Date.now() - (1000 * 60 * 30); // 30 min
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

// ---------------- INJECTED REWRITE SCRIPT (small shim inserted into proxied HTML) ----------------
const INJECT_REWRITE_MARKER = "<!--EUPHORIA-REWRITE-INJECTED-->";
const INJECT_REWRITE_SCRIPT = `
<!-- EUPHORIA REWRITE SHIM -->
${INJECT_REWRITE_MARKER}
<script>
(function(){
  const DEPLOY="${DEPLOYMENT_ORIGIN}";
  function prox(u){ try { if(!u) return u; if(u.includes('/proxy?url=')) return u; if(/^(data:|blob:|javascript:)/i.test(u)) return u; return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href); } catch(e) { return u; } }
  // rewrite anchors/forms/assets on dynamic changes
  function rewriteOnce(root){
    try{
      root.querySelectorAll('a[href]').forEach(a=>{
        try{
          const h=a.getAttribute('href'); if(!h) return;
          if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return;
          if(h.includes('/proxy?url=')) return;
          a.setAttribute('href', prox(h));
          a.removeAttribute('target');
        }catch(e){}
      });
      ['img','script','link','iframe','source','video','audio'].forEach(tag=>{
        root.querySelectorAll(tag+'[src]').forEach(el=>{
          try{ const v=el.getAttribute('src'); if(!v) return; if(/^data:/i.test(v)) return; if(v.includes('/proxy?url=')) return; el.setAttribute('src', prox(v)); }catch(e){}
        });
        root.querySelectorAll(tag+'[href]').forEach(el=>{
          try{ const v=el.getAttribute('href'); if(!v) return; if(/^data:/i.test(v)) return; if(v.includes('/proxy?url=')) return; el.setAttribute('href', prox(v)); }catch(e){}
        });
      });
      root.querySelectorAll('[srcset]').forEach(el=>{
        try{
          const ss=el.getAttribute('srcset')||'';
          const parts=ss.split(',').map(p=>{
            const [u,rest]=p.trim().split(/\\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return prox(u) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }catch(e){}
      });
    }catch(e){}
  }
  // initial rewrite
  rewriteOnce(document);
  // observe
  try{
    const mo=new MutationObserver(muts=>{
      muts.forEach(m=>{
        m.addedNodes && Array.from(m.addedNodes).forEach(n=>{
          if(n.nodeType!==1) return;
          rewriteOnce(n);
        });
      });
    });
    mo.observe(document.documentElement||document,{childList:true,subtree:true});
  }catch(e){}
  // intercept fetch/XHR to route through proxy
  try{
    const origFetch=window.fetch;
    window.fetch=function(resource,init){
      try{
        if(typeof resource==='string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        else if(resource instanceof Request) {
          if(!resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      }catch(e){}
      return origFetch(resource, init);
    };
  }catch(e){}
  try{
    const OrigXHR=window.XMLHttpRequest;
    window.XMLHttpRequest=function(){
      const xhr=new OrigXHR();
      const origOpen=xhr.open;
      xhr.open=function(method,url,...rest){
        try{ if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)) url = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href); }catch(e){}
        return origOpen.call(this, method, url, ...rest);
      };
      return xhr;
    };
  }catch(e){}
})();
</script>
`;

// ---------------- HTML REWRITE using jsdom ----------------
async function rewriteHtml(rawHtml, baseUrl) {
  try {
    const dom = new JSDOM(rawHtml, { url: baseUrl || undefined });
    const doc = dom.window.document;

    // Helper: rewrite attribute if present
    function rewriteAttr(el, attr) {
      try {
        if (!el.hasAttribute(attr)) return;
        const val = el.getAttribute(attr);
        if (!val) return;
        if (isAlreadyProxiedHref(val)) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return;
        if (/^(data:|blob:|about:)/i.test(val)) return;
        const abs = toAbsolute(val, baseUrl) || val;
        el.setAttribute(attr, proxyizeAbsoluteUrl(abs));
      } catch (e) {}
    }

    // tags and attributes to rewrite
    const mapping = [
      ["a", "href"],
      ["link", "href"],
      ["script", "src"],
      ["img", "src"],
      ["iframe", "src"],
      ["source", "src"],
      ["video", "src"],
      ["audio", "src"],
      ["form", "action"]
    ];
    mapping.forEach(([tag, attr]) => {
      const nodes = Array.from(doc.getElementsByTagName(tag));
      nodes.forEach(el => rewriteAttr(el, attr));
    });

    // srcset
    Array.from(doc.querySelectorAll("[srcset]")).forEach(el => {
      try {
        const ss = el.getAttribute("srcset") || "";
        const parts = ss.split(",").map(p => {
          const [u, rest] = p.trim().split(/\s+/, 2);
          if (!u) return p;
          if (isAlreadyProxiedHref(u)) return p;
          if (/^data:/i.test(u)) return p;
          const abs = toAbsolute(u, baseUrl) || u;
          return proxyizeAbsoluteUrl(abs) + (rest ? " " + rest : "");
        });
        el.setAttribute("srcset", parts.join(", "));
      } catch (e) {}
    });

    // inline styles url(...)
    Array.from(doc.querySelectorAll("[style]")).forEach(el => {
      try {
        const s = el.getAttribute("style") || "";
        const rewritten = s.replace(/url\(([^)]+)\)/g, (_, raw) => {
          const clean = raw.replace(/['"]/g, "").trim();
          if (!clean) return `url(${clean})`;
          if (isAlreadyProxiedHref(clean)) return `url(${clean})`;
          if (/^data:/i.test(clean)) return `url(${clean})`;
          const abs = toAbsolute(clean, baseUrl) || clean;
          return `url(${proxyizeAbsoluteUrl(abs)})`;
        });
        el.setAttribute("style", rewritten);
      } catch (e) {}
    });

    // meta refresh rewrite
    Array.from(doc.querySelectorAll('meta[http-equiv]')).forEach(m => {
      try {
        if (m.getAttribute("http-equiv").toLowerCase() !== "refresh") return;
        const c = m.getAttribute("content") || "";
        const parts = c.split(";");
        if (parts.length < 2) return;
        const urlpart = parts.slice(1).join(";").match(/url=(.*)/i);
        if (!urlpart) return;
        const dest = urlpart[1].replace(/['"]/g, "").trim();
        const abs = toAbsolute(dest, baseUrl) || dest;
        m.setAttribute("content", parts[0] + ";url=" + proxyizeAbsoluteUrl(abs));
      } catch (e) {}
    });

    // Inject our rewrite script marker if not present
    const body = doc.body || doc.getElementsByTagName("body")[0];
    if (body && !rawHtml.includes(INJECT_REWRITE_MARKER)) {
      const scriptFragment = JSDOM.fragment(INJECT_REWRITE_SCRIPT);
      body.appendChild(scriptFragment);
    }

    // return serialized HTML
    return dom.serialize();
  } catch (err) {
    console.error("rewriteHtml error", err);
    return rawHtml;
  }
}

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

// ---------------- /proxy handler ----------------
app.get("/proxy", async (req, res) => {
  // Accept both ?url= and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // Normalize non-absolute
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch (e) {}

  const accept = (req.headers.accept || "").toLowerCase();
  const forcedHtml = !!req.headers["x-euphoria-client"];
  const wantHtml = forcedHtml || accept.includes("text/html");

  // cache keys
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // asset quick-return (when client is not asking for HTML)
  if (!wantHtml) {
    const cachedAsset = cacheGet(assetKey);
    if (cachedAsset) {
      try { Object.entries(cachedAsset.headers || {}).forEach(([k,v]) => res.setHeader(k,v)); } catch(e){}
      return res.send(Buffer.from(cachedAsset.body, "base64"));
    }
  }

  // html cache
  if (wantHtml) {
    const cachedHtml = cacheGet(htmlKey);
    if (cachedHtml) { res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // prepare origin headers (pass-through UA/Accept-Language)
  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/2.0",
    "Accept": wantHtml ? "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" : (req.headers.accept || "*/*"),
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if (req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  // fetch origin
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

  // persist set-cookie headers into session store
  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch (e) {}

  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = looksLikeAssetPath(raw) || !isHtml;

  // ---------------- ASSET PATH ----------------
  if (!wantHtml || treatAsAsset) {
    // forward safe headers
    try { originRes.headers.forEach((v, k) => { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v); } catch (e) {} }); } catch(e){}
    try { setSessionCookieHeader(res, session.sid); } catch (e) {}
    // try to buffer small assets for caching
    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if (buf.length < ASSET_CACHE_MAX) {
        try { cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch (e) {}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if (originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch (err) {
      // fallback to streaming
      try { originRes.body.pipe(res); return; } catch (e) { return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // ---------------- HTML PATH ----------------
  // forward safe headers except CSP-like ones
  try { originRes.headers.forEach((v, k) => { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) try { res.setHeader(k, v); } catch (e) {} }); } catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  // read full HTML body (we need it for jsdom rewrite)
  let rawHtml;
  try {
    rawHtml = await originRes.text();
  } catch (err) {
    console.error("failed to read html body", err);
    return res.status(502).send("Euphoria: failed to read HTML body");
  }

  // run rewriteHtml
  let finalHtml = rawHtml;
  try {
    finalHtml = await rewriteHtml(rawHtml, originRes.url || raw);
  } catch (err) {
    console.error("rewriteHtml failed", err);
    // fallback: use rawHtml
    finalHtml = rawHtml;
  }

  // ensure session cookie header set before sending
  try { setSessionCookieHeader(res, session.sid); } catch (e) {}

  // cache (if small) and send
  try {
    if (finalHtml && finalHtml.length < 512 * 1024) cacheSet(htmlKey, finalHtml);
  } catch (e) {}
  return res.send(finalHtml);
});

// ---------------- FALLBACK ROUTES ----------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.get("*", (req, res, next) => {
  if (req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ---------------- ERRORS ----------------
process.on("unhandledRejection", err => console.error("unhandledRejection", err));
process.on("uncaughtException", err => console.error("uncaughtException", err));