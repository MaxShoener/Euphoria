// server.js
// Euphoria v3 (Euphoria + Scramjet) — robust hybrid proxy for Node 20+
// Sections only. No placeholders. Single-file backend.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import http from "http";
import https from "https";
import { WebSocketServer, WebSocket } from "ws";
import { Agent, ProxyAgent, setGlobalDispatcher } from "undici";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =============================================================================
// CONFIG
// =============================================================================
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = (process.env.ENABLE_DISK_CACHE ?? "1") === "1";
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS || String(1000 * 60 * 8), 10);
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "35000", 10);
const MAX_BODY_BYTES = parseInt(process.env.MAX_BODY_BYTES || String(1024 * 1024 * 8), 10); // 8MB
const MAX_ASSET_CACHE_BYTES = parseInt(process.env.MAX_ASSET_CACHE_BYTES || String(1024 * 1024 * 2), 10); // 2MB
const MEM_CACHE_MAX_BYTES = parseInt(process.env.MEM_CACHE_MAX_BYTES || String(64 * 1024 * 1024), 10); // 64MB
const USER_AGENT_DEFAULT =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";

const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
const FORCE_PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || ""; // e.g. https://your-app.koyeb.app

const PER_HOST_CACHE_CONTROLS = Object.create(null); // { "example.com": { disable:true, ttl: 1234 } }

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// =============================================================================
// GLOBAL DISPATCHER (undici keepalive)
// =============================================================================
const keepAliveAgent = new Agent({
  keepAliveTimeout: 30_000,
  keepAliveMaxTimeout: 60_000,
  connections: 128,
  pipelining: 1
});
setGlobalDispatcher(keepAliveAgent);

// =============================================================================
// CONSTANTS
// =============================================================================
const DROP_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
]);

const ASSET_EXTS = [
  ".png",".jpg",".jpeg",".gif",".webp",".avif",".svg",".ico",
  ".css",".js",".mjs",".map",".json",".wasm",
  ".ttf",".otf",".woff",".woff2",".eot",
  ".mp4",".webm",".mp3",".m4a",".wav",".ogg",
  ".pdf",".zip",".rar",".7z",".bin"
];

const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// =============================================================================
// UTILS
// =============================================================================
function now() { return Date.now(); }

function cacheKey(s) {
  return Buffer.from(s).toString("base64url");
}

function safeJsonSize(v) {
  try { return Buffer.byteLength(JSON.stringify(v), "utf8"); } catch { return 1024; }
}

function isProbablyAssetByPath(urlStr) {
  try {
    const u = new URL(urlStr);
    const p = (u.pathname || "").toLowerCase();
    for (const x of SPECIAL_FILES) if (p.endsWith(x)) return true;
    for (const e of ASSET_EXTS) if (p.endsWith(e)) return true;
    return false;
  } catch {
    const p = (urlStr || "").toLowerCase();
    for (const x of SPECIAL_FILES) if (p.endsWith(x)) return true;
    for (const e of ASSET_EXTS) if (p.endsWith(e)) return true;
    return false;
  }
}

function isHtmlContentType(ct = "") {
  ct = (ct || "").toLowerCase();
  return ct.includes("text/html") || ct.includes("application/xhtml") || ct.includes("text/xml");
}

function isTextLike(ct = "") {
  ct = (ct || "").toLowerCase();
  return (
    ct.startsWith("text/") ||
    ct.includes("javascript") ||
    ct.includes("json") ||
    ct.includes("xml") ||
    ct.includes("x-www-form-urlencoded")
  );
}

function getReqOrigin(req) {
  if (FORCE_PUBLIC_ORIGIN) return FORCE_PUBLIC_ORIGIN.replace(/\/+$/,"");
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0].trim();
  const xfHost = (req.headers["x-forwarded-host"] || "").toString().split(",")[0].trim();
  const host = xfHost || req.headers.host || "localhost";
  const proto = xfProto || (req.socket.encrypted ? "https" : "http");
  return `${proto}://${host}`.replace(/\/+$/,"");
}

function clampStr(s, n) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) : s;
}

function parseCookies(header = "") {
  const out = Object.create(null);
  header.split(";").forEach(part => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  });
  return out;
}

function buildCookieHeader(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

function stripHtmlDanger(html) {
  // remove CSP meta, integrity, crossorigin (helps scripts/assets work through proxy)
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
    return html;
  } catch {
    return html;
  }
}

function normalizeInputToUrl(input) {
  input = (input || "").trim();
  if (!input) return "";
  // already url
  if (/^https?:\/\//i.test(input)) return input;
  // treat as query if contains spaces
  if (/\s/.test(input)) return `https://www.google.com/search?q=${encodeURIComponent(input)}`;
  // if looks like domain
  if (input.includes(".") || input.includes(":")) return `https://${input}`;
  // otherwise google it
  return `https://www.google.com/search?q=${encodeURIComponent(input)}`;
}

function isAlreadyProxied(u, publicOrigin) {
  try {
    if (!u) return false;
    if (u.includes("/proxy?url=")) return true;
    const x = new URL(u, publicOrigin);
    return x.origin === publicOrigin && (x.pathname === "/proxy" || x.pathname.startsWith("/proxy/"));
  } catch {
    return false;
  }
}

function toAbsolute(u, base) {
  try { return new URL(u, base).href; } catch { return null; }
}

function proxifyAbs(absUrl, publicOrigin) {
  try {
    const u = new URL(absUrl);
    return `${publicOrigin}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch {
    return `${publicOrigin}/proxy?url=${encodeURIComponent(absUrl)}`;
  }
}

function rewriteCssUrls(cssText, baseUrl, publicOrigin) {
  try {
    return cssText.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, raw) => {
      const u = (raw || "").trim();
      if (!u) return m;
      if (/^data:/i.test(u)) return m;
      if (/^blob:/i.test(u)) return m;
      if (isAlreadyProxied(u, publicOrigin)) return m;
      const abs = toAbsolute(u, baseUrl) || u;
      return `url("${proxifyAbs(abs, publicOrigin)}")`;
    });
  } catch {
    return cssText;
  }
}

function rewriteSrcset(srcset, baseUrl, publicOrigin) {
  try {
    const parts = (srcset || "").split(",").map(p => p.trim()).filter(Boolean);
    const out = parts.map(piece => {
      const [u, rest] = piece.split(/\s+/, 2);
      if (!u) return piece;
      if (/^data:/i.test(u) || /^blob:/i.test(u) || isAlreadyProxied(u, publicOrigin)) return piece;
      const abs = toAbsolute(u, baseUrl) || u;
      return proxifyAbs(abs, publicOrigin) + (rest ? " " + rest : "");
    });
    return out.join(", ");
  } catch {
    return srcset;
  }
}

function sanitizeUpstreamHeadersToClient(upHeaders) {
  const out = Object.create(null);
  for (const [k, v] of upHeaders.entries()) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (DROP_RESPONSE_HEADERS.has(lk)) continue;
    // Avoid upstream setting cookies for its own domain directly; we handle cookies in-session
    if (lk === "set-cookie") continue;
    out[k] = v;
  }
  return out;
}

function getSetCookies(upHeaders) {
  // undici fetch does not expose raw() like node-fetch; getSetCookie() exists in undici Headers
  // Fallback: try reading "set-cookie" header (may be a single combined string in some environments)
  try {
    if (typeof upHeaders.getSetCookie === "function") {
      return upHeaders.getSetCookie() || [];
    }
  } catch {}
  const sc = upHeaders.get("set-cookie");
  if (!sc) return [];
  // best-effort split (not perfect for all cookies, but better than nothing)
  return sc.split(/,(?=[^;]+=[^;]+)/g).map(s => s.trim()).filter(Boolean);
}

function storeSetCookiesToSession(setCookies, session) {
  for (const sc of setCookies || []) {
    try {
      const first = sc.split(";")[0];
      const idx = first.indexOf("=");
      if (idx === -1) continue;
      const k = first.slice(0, idx).trim();
      const v = first.slice(idx + 1).trim();
      if (k) session.cookies.set(k, v);
    } catch {}
  }
}

// =============================================================================
// SESSIONS (cookie jar per user session)
// =============================================================================
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();

function makeSid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function getOrCreateSession(req) {
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  sid = (sid || "").toString();
  if (!sid || !SESSIONS.has(sid)) {
    sid = makeSid();
    const payload = {
      created: now(),
      last: now(),
      ip: req.ip || req.socket.remoteAddress || null,
      ua: USER_AGENT_DEFAULT,
      cookies: new Map()
    };
    SESSIONS.set(sid, payload);
    return { sid, payload, isNew: true };
  }
  const payload = SESSIONS.get(sid);
  payload.last = now();
  payload.ip = payload.ip || req.ip || null;
  return { sid, payload, isNew: false };
}

function setSessionCookie(res, sid) {
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}

// cleanup
setInterval(() => {
  const cutoff = now() - 1000 * 60 * 60 * 24;
  for (const [sid, s] of SESSIONS.entries()) {
    if (s.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 20);

// =============================================================================
// CACHE (memory + disk)
// =============================================================================
const MEM_CACHE = new LRUCache({
  maxSize: MEM_CACHE_MAX_BYTES,
  ttl: CACHE_TTL_MS,
  sizeCalculation: (val) => {
    if (typeof val === "string") return Buffer.byteLength(val, "utf8");
    if (Buffer.isBuffer(val)) return val.length;
    return safeJsonSize(val);
  }
});

async function diskGet(key) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname, "utf8");
    const obj = JSON.parse(raw);
    if ((now() - obj.t) < (obj.ttl || CACHE_TTL_MS)) return obj.v;
    try { await fsPromises.unlink(fname); } catch {}
  } catch {}
  return null;
}

async function diskSet(key, val, ttl = CACHE_TTL_MS) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now(), ttl }), "utf8").catch(() => {});
  } catch {}
}

// =============================================================================
// SCRAMJET (optional, defensive integration)
// =============================================================================
let scramjetReady = false;
let scramjetMiddleware = null;

async function initScramjet() {
  try {
    const pkg = await import("@mercuryworkshop/scramjet");
    const mod = pkg?.default || pkg;
    const create =
      mod?.createScramjetServer ||
      mod?.createServer ||
      mod?.default?.createScramjetServer ||
      mod?.default?.createServer;

    if (typeof create !== "function") {
      console.warn("[scramjet] create server function not found, skipping");
      return;
    }

    // Many scramjet builds expose a (req,res,next) middleware or a handler object.
    const instance = await create({
      prefix: "/scramjet/",
      codec: "plain"
    });

    // Try common shapes
    if (typeof instance === "function") {
      scramjetMiddleware = instance;
      scramjetReady = true;
      console.log("[scramjet] middleware mounted");
      return;
    }
    if (instance && typeof instance.middleware === "function") {
      scramjetMiddleware = instance.middleware.bind(instance);
      scramjetReady = true;
      console.log("[scramjet] instance.middleware mounted");
      return;
    }
    if (instance && typeof instance.handle === "function") {
      scramjetMiddleware = (req, res, next) => instance.handle(req, res, next);
      scramjetReady = true;
      console.log("[scramjet] instance.handle mounted");
      return;
    }

    console.warn("[scramjet] unknown server shape, skipping");
  } catch (e) {
    console.warn("[scramjet] not available:", e?.message || e);
  }
}
await initScramjet();

// =============================================================================
// EXPRESS APP
// =============================================================================
const app = express();
app.set("trust proxy", true);

app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));

// rate limit
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_GLOBAL || "900", 10),
    standardHeaders: true,
    legacyHeaders: false
  })
);

// static
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// =============================================================================
// CLIENT INJECT (navigation + fetch/xhr/ws/eventsource/beacon)
// =============================================================================
function clientInjectScript(publicOrigin) {
  // NOTE: no iframe tricks; runs inside proxied doc context.
  return `
<script>
/* EUPHORIA_CLIENT */
(function(){
  const ORIGIN=${JSON.stringify(publicOrigin)};
  function abs(u, base){
    try { return new URL(u, base || document.baseURI).href; } catch(e) { return u; }
  }
  function prox(u){
    try{
      if(!u) return u;
      if(/^data:|^blob:|^about:|^javascript:/i.test(u)) return u;
      if(String(u).includes("/proxy?url=")) return u;
      const a = abs(u, document.baseURI);
      return ORIGIN + "/proxy?url=" + encodeURIComponent(a);
    }catch(e){ return u; }
  }

  // Intercept clicks (anchors/buttons with navigation)
  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
      if(!a) return;
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(mailto:|tel:|javascript:|#)/i.test(href)) return;
      // If target _blank, force same tab to avoid escaping
      a.removeAttribute("target");
      a.href = prox(href);
    }catch(e){}
  }, true);

  // Patch history + location assignments (SPA)
  try{
    const origPush = history.pushState;
    history.pushState = function(state, title, url){
      try{
        if(typeof url === "string") url = prox(url);
      }catch(e){}
      return origPush.call(this, state, title, url);
    };
    const origReplace = history.replaceState;
    history.replaceState = function(state, title, url){
      try{
        if(typeof url === "string") url = prox(url);
      }catch(e){}
      return origReplace.call(this, state, title, url);
    };
  }catch(e){}

  // Patch fetch
  try{
    const ofetch = window.fetch;
    window.fetch = function(resource, init){
      try{
        if(typeof resource === "string") resource = prox(resource);
        else if(resource && resource.url && typeof resource.url === "string" && !String(resource.url).includes("/proxy?url=")){
          resource = new Request(prox(resource.url), resource);
        }
      }catch(e){}
      return ofetch.call(this, resource, init);
    };
  }catch(e){}

  // Patch XHR
  try{
    const OXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const x = new OXHR();
      const open = x.open;
      x.open = function(method, url){
        try{
          if(typeof url === "string") url = prox(url);
        }catch(e){}
        return open.apply(this, arguments.length >= 2 ? [method, url, ...[].slice.call(arguments,2)] : arguments);
      };
      return x;
    };
  }catch(e){}

  // Patch WebSocket
  try{
    const OWS = window.WebSocket;
    window.WebSocket = function(url, protocols){
      try{
        const absUrl = abs(url, document.baseURI);
        const wsUrl = absUrl.replace(/^http/i,"ws");
        const p = ORIGIN + "/_wsproxy?url=" + encodeURIComponent(wsUrl);
        return new OWS(p, protocols);
      }catch(e){
        return new OWS(url, protocols);
      }
    };
    window.WebSocket.prototype = OWS.prototype;
  }catch(e){}

  // Patch EventSource
  try{
    const OES = window.EventSource;
    window.EventSource = function(url, cfg){
      try{
        return new OES(prox(url), cfg);
      }catch(e){
        return new OES(url, cfg);
      }
    };
    window.EventSource.prototype = OES.prototype;
  }catch(e){}

  // Patch sendBeacon
  try{
    const sb = navigator.sendBeacon;
    navigator.sendBeacon = function(url, data){
      try{ url = prox(url); }catch(e){}
      return sb.call(this, url, data);
    };
  }catch(e){}

})();
</script>`;
}

// =============================================================================
// JSDOM REWRITE (DOM + CSS + srcset + meta refresh + forms)
// =============================================================================
function jsdomTransform(html, baseUrl, publicOrigin) {
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;

    // ensure base
    if (!document.querySelector("base")) {
      const head = document.querySelector("head");
      if (head) {
        const b = document.createElement("base");
        b.setAttribute("href", baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }

    // anchors
    for (const a of Array.from(document.querySelectorAll("a[href]"))) {
      try {
        const href = a.getAttribute("href");
        if (!href) continue;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) continue;
        if (isAlreadyProxied(href, publicOrigin)) continue;
        const abs = toAbsolute(href, baseUrl) || href;
        a.setAttribute("href", proxifyAbs(abs, publicOrigin));
        a.removeAttribute("target");
        a.removeAttribute("rel");
      } catch {}
    }

    // forms
    for (const f of Array.from(document.querySelectorAll("form[action]"))) {
      try {
        const act = f.getAttribute("action") || "";
        if (!act) continue;
        if (isAlreadyProxied(act, publicOrigin)) continue;
        const abs = toAbsolute(act, baseUrl) || act;
        f.setAttribute("action", proxifyAbs(abs, publicOrigin));
      } catch {}
    }

    // src/href assets
    const tags = ["img","script","link","iframe","source","video","audio","track"];
    for (const t of tags) {
      for (const el of Array.from(document.getElementsByTagName(t))) {
        try {
          const attr = el.getAttribute("src") ? "src" : (el.getAttribute("href") ? "href" : null);
          if (!attr) continue;
          const v = el.getAttribute(attr);
          if (!v) continue;
          if (/^data:/i.test(v) || /^blob:/i.test(v)) continue;
          if (isAlreadyProxied(v, publicOrigin)) continue;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(attr, proxifyAbs(abs, publicOrigin));
        } catch {}
      }
    }

    // srcset
    for (const el of Array.from(document.querySelectorAll("[srcset]"))) {
      try {
        const ss = el.getAttribute("srcset") || "";
        el.setAttribute("srcset", rewriteSrcset(ss, baseUrl, publicOrigin));
      } catch {}
    }

    // inline <style>
    for (const st of Array.from(document.querySelectorAll("style"))) {
      try {
        const txt = st.textContent || "";
        st.textContent = rewriteCssUrls(txt, baseUrl, publicOrigin);
      } catch {}
    }

    // inline style attrs
    for (const el of Array.from(document.querySelectorAll("[style]"))) {
      try {
        const s = el.getAttribute("style") || "";
        el.setAttribute("style", rewriteCssUrls(s, baseUrl, publicOrigin));
      } catch {}
    }

    // meta refresh
    for (const m of Array.from(document.querySelectorAll('meta[http-equiv="refresh"], meta[http-equiv="Refresh"]'))) {
      try {
        const content = m.getAttribute("content") || "";
        const parts = content.split(";");
        if (parts.length < 2) continue;
        const match = parts.slice(1).join(";").match(/url=(.*)/i);
        if (!match) continue;
        const dest = match[1].replace(/['"]/g,"").trim();
        const abs = toAbsolute(dest, baseUrl) || dest;
        m.setAttribute("content", parts[0] + ";url=" + proxifyAbs(abs, publicOrigin));
      } catch {}
    }

    // remove noscript (reduces layout issues on some SPAs)
    for (const n of Array.from(document.getElementsByTagName("noscript"))) {
      try { n.remove(); } catch {}
    }

    // inject client patch (end of body)
    const inject = clientInjectScript(publicOrigin);
    const out = dom.serialize().replace(/<\/body>/i, inject + "</body>");
    return out;
  } catch (e) {
    return html;
  }
}

// =============================================================================
// UPSTREAM FETCH
// =============================================================================
function buildUpstreamHeaders(req, targetUrl, sessionPayload) {
  const headers = new Headers();

  // UA
  headers.set("user-agent", sessionPayload.ua || USER_AGENT_DEFAULT);

  // Accept defaults: let browser choose, but avoid forcing text/html
  if (req.headers.accept) headers.set("accept", String(req.headers.accept));
  else headers.set("accept", "*/*");

  if (req.headers["accept-language"]) headers.set("accept-language", String(req.headers["accept-language"]));

  // DO NOT pass accept-encoding explicitly; undici handles it; passing can confuse downstream caching
  // cookies from session jar
  const cookieHdr = buildCookieHeader(sessionPayload.cookies);
  if (cookieHdr) headers.set("cookie", cookieHdr);

  // referer/origin
  try {
    const t = new URL(targetUrl);
    headers.set("origin", t.origin);
  } catch {}

  if (req.headers.referer) headers.set("referer", String(req.headers.referer));
  if (req.headers["sec-fetch-site"]) headers.set("sec-fetch-site", String(req.headers["sec-fetch-site"]));
  if (req.headers["sec-fetch-mode"]) headers.set("sec-fetch-mode", String(req.headers["sec-fetch-mode"]));
  if (req.headers["sec-fetch-dest"]) headers.set("sec-fetch-dest", String(req.headers["sec-fetch-dest"]));
  if (req.headers["sec-fetch-user"]) headers.set("sec-fetch-user", String(req.headers["sec-fetch-user"]));

  // forward some auth headers if present
  const pass = ["authorization", "x-requested-with"];
  for (const k of pass) {
    if (req.headers[k]) headers.set(k, String(req.headers[k]));
  }

  // content headers for POST/PUT
  if (req.headers["content-type"]) headers.set("content-type", String(req.headers["content-type"]));

  return headers;
}

async function upstreamFetch(url, { method = "GET", headers, body } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      method,
      headers,
      body,
      redirect: "manual",
      signal: controller.signal
    });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

// =============================================================================
// TARGET URL PARSING (supports /proxy?url=, /proxy/<host>/<path>, and plain search)
// =============================================================================
function resolveTargetFromReq(req) {
  const qUrl = (req.query.url || "").toString();
  const qQ = (req.query.q || "").toString();

  // /proxy?url=...
  if (qUrl) return normalizeInputToUrl(qUrl);

  // /proxy?q=search
  if (!qUrl && qQ) return normalizeInputToUrl(qQ);

  // /proxy/<host>/<path>
  // Express route can provide req.params, but we also handle raw path here:
  const p = req.path || "";
  if (p.startsWith("/proxy/")) {
    const rest = p.slice("/proxy/".length);
    // if rest looks like encoded full url
    const decoded = decodeURIComponent(rest);
    if (/^https?:\/\//i.test(decoded)) return decoded;

    // treat as host/path
    const parts = rest.split("/");
    const host = parts.shift();
    if (host && host.includes(".")) {
      const tail = parts.join("/");
      const scheme = (req.query.s || "https").toString().toLowerCase() === "http" ? "http" : "https";
      const full = `${scheme}://${host}/${tail}`;
      return full.replace(/\/+$/,"") + (req.url.includes("?") ? "" : "");
    }
  }

  return "";
}

// =============================================================================
// PROXY CORE
// =============================================================================
async function handleProxy(req, res) {
  const publicOrigin = getReqOrigin(req);
  const { sid, payload } = getOrCreateSession(req);
  setSessionCookie(res, sid);

  let target = resolveTargetFromReq(req);

  // Friendly: allow visiting /proxy with no url -> Google
  if (!target) {
    // if user typed something like /proxy with POST body? (rare)
    if (req.query && req.query.input) target = normalizeInputToUrl(String(req.query.input));
  }
  if (!target) {
    // default to google home
    target = "https://www.google.com/";
  }

  // cache key
  const method = (req.method || "GET").toUpperCase();
  const isCacheableMethod = method === "GET" || method === "HEAD";

  let host = "";
  try { host = new URL(target).hostname; } catch {}
  const hostCfg = PER_HOST_CACHE_CONTROLS[host] || {};
  const ttl = typeof hostCfg.ttl === "number" ? hostCfg.ttl : CACHE_TTL_MS;
  const cacheDisabled = hostCfg.disable === true;

  // Read request body for non-GET
  let reqBody = undefined;
  if (!isCacheableMethod) {
    const chunks = [];
    let total = 0;
    await new Promise((resolve, reject) => {
      req.on("data", (c) => {
        total += c.length;
        if (total > MAX_BODY_BYTES) {
          reject(new Error("Body too large"));
          return;
        }
        chunks.push(c);
      });
      req.on("end", resolve);
      req.on("error", reject);
    }).catch((e) => {
      res.status(413).send("Request body too large");
    });
    if (res.headersSent) return;
    reqBody = Buffer.concat(chunks);
  }

  const cacheKeyBase = `${method}:${target}`;

  // Serve cache for GET assets/text (only when safe)
  if (isCacheableMethod && !cacheDisabled) {
    const mem = MEM_CACHE.get(cacheKeyBase);
    if (mem) {
      try {
        for (const [k, v] of Object.entries(mem.headers || {})) res.setHeader(k, v);
        res.status(mem.status || 200);
        return res.end(mem.body);
      } catch {}
    }
    const disk = await diskGet(cacheKeyBase);
    if (disk) {
      try {
        for (const [k, v] of Object.entries(disk.headers || {})) res.setHeader(k, v);
        res.status(disk.status || 200);
        return res.end(Buffer.from(disk.body, "base64"));
      } catch {}
    }
  }

  // Fetch upstream
  let upstream;
  try {
    const upHeaders = buildUpstreamHeaders(req, target, payload);
    upstream = await upstreamFetch(target, {
      method,
      headers: upHeaders,
      body: reqBody
    });
  } catch (e) {
    const msg = e?.name === "AbortError" ? "Upstream timeout" : (e?.message || String(e));
    return res.status(502).send("Euphoria: failed to fetch upstream: " + msg);
  }

  // store cookies
  try {
    const setCookies = getSetCookies(upstream.headers);
    if (setCookies.length) storeSetCookiesToSession(setCookies, payload);
  } catch {}

  const status = upstream.status || 200;

  // Redirect rewriting (never escape site)
  if ([301,302,303,307,308].includes(status)) {
    const loc = upstream.headers.get("location");
    if (loc) {
      let abs;
      try { abs = new URL(loc, target).href; } catch { abs = loc; }
      const prox = proxifyAbs(abs, publicOrigin);
      res.status(status);
      res.setHeader("Location", prox);
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.end("Redirecting to " + prox);
    }
  }

  // Determine handling by content-type
  const ct = (upstream.headers.get("content-type") || "").toLowerCase();
  const looksHtml = isHtmlContentType(ct);

  // Copy sanitized headers to client
  const safeHeaders = sanitizeUpstreamHeadersToClient(upstream.headers);
  for (const [k, v] of Object.entries(safeHeaders)) {
    try { res.setHeader(k, v); } catch {}
  }

  // Always allow framing inside our own UI page
  try { res.setHeader("x-frame-options", "SAMEORIGIN"); } catch {}
  try { res.setHeader("access-control-allow-origin", "*"); } catch {}

  // Read upstream body (buffer)
  let buf;
  try {
    const arr = await upstream.arrayBuffer();
    buf = Buffer.from(arr);
  } catch (e) {
    // fallback stream
    try {
      res.status(status);
      return upstream.body.pipe(res);
    } catch {
      return res.status(502).send("Euphoria: upstream body stream failed");
    }
  }

  // If not html: send as-is (this fixes complex images/fonts/media)
  if (!looksHtml) {
    // Ensure correct content type stays
    if (ct) res.setHeader("Content-Type", ct);
    res.status(status);
    // Cache small assets
    if ((isCacheableMethod && !cacheDisabled) && buf.length <= MAX_ASSET_CACHE_BYTES) {
      const payloadToCache = {
        status,
        headers: Object.fromEntries(Object.entries(safeHeaders)),
        body: buf
      };
      MEM_CACHE.set(cacheKeyBase, payloadToCache, { ttl });
      diskSet(cacheKeyBase, {
        status,
        headers: payloadToCache.headers,
        body: buf.toString("base64")
      }, ttl).catch(() => {});
    }
    return res.end(buf);
  }

  // HTML transform
  let html = buf.toString("utf8");

  // remove CSP-like blockers
  html = stripHtmlDanger(html);

  // rewrite
  const transformed = jsdomTransform(html, upstream.url || target, publicOrigin);

  res.status(status);
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  // cache html (bounded)
  if (isCacheableMethod && !cacheDisabled) {
    const b = Buffer.byteLength(transformed, "utf8");
    if (b <= 1024 * 1024 * 2) {
      MEM_CACHE.set(cacheKeyBase, { status, headers: Object.fromEntries(Object.entries(safeHeaders)), body: Buffer.from(transformed, "utf8") }, { ttl });
      diskSet(cacheKeyBase, { status, headers: Object.fromEntries(Object.entries(safeHeaders)), body: Buffer.from(transformed, "utf8").toString("base64") }, ttl).catch(() => {});
    }
  }

  return res.end(transformed);
}

// =============================================================================
// ROUTES
// =============================================================================
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// scramjet mount (optional)
if (scramjetReady && scramjetMiddleware) {
  app.use("/scramjet", (req, res, next) => {
    try { return scramjetMiddleware(req, res, next); } catch (e) { return next(); }
  });
}

// primary proxy
app.all("/proxy", (req, res) => handleProxy(req, res));
app.all("/proxy/*", (req, res) => handleProxy(req, res));

// helper: allow /go?q=...
app.get("/go", (req, res) => {
  const publicOrigin = getReqOrigin(req);
  const q = (req.query.q || req.query.url || "").toString();
  const target = normalizeInputToUrl(q || "https://www.google.com/");
  res.redirect(`${publicOrigin}/proxy?url=${encodeURIComponent(target)}`);
});

// =============================================================================
// ADMIN
// =============================================================================
function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  // allow local only when no token
  if (!ADMIN_TOKEN) {
    const ip = req.ip || "";
    if (ip === "127.0.0.1" || ip === "::1") return next();
  }
  res.status(403).json({ error: "forbidden" });
}

app.get("/_euph_debug/ping", (req, res) => res.json({ ok: true, ts: now() }));
app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, s] of SESSIONS.entries()) {
    out[sid] = { created: s.created, last: s.last, ip: s.ip, cookies: s.cookies.size };
  }
  res.json({ count: SESSIONS.size, sessions: out });
});
app.get("/_euph_debug/cache", requireAdmin, (req, res) => {
  res.json({ size: MEM_CACHE.size, calculatedSize: MEM_CACHE.calculatedSize, keys: MEM_CACHE.size });
});
app.post("/_euph_debug/clear_cache", requireAdmin, async (req, res) => {
  MEM_CACHE.clear();
  if (ENABLE_DISK_CACHE) {
    try {
      const files = await fsPromises.readdir(CACHE_DIR);
      for (const f of files) await fsPromises.unlink(path.join(CACHE_DIR, f)).catch(() => {});
    } catch {}
  }
  res.json({ ok: true });
});

// =============================================================================
// WEBSOCKET PROXY (/ _wsproxy?url=ws://...)
// =============================================================================
function setupWsProxy(server) {
  const wss = new WebSocketServer({ noServer: true, clientTracking: false });

  server.on("upgrade", (request, socket, head) => {
    try {
      const url = new URL(request.url, `http://${request.headers.host}`);
      if (url.pathname !== "/_wsproxy") return;
      const target = url.searchParams.get("url");
      if (!target) {
        socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
        socket.destroy();
        return;
      }

      wss.handleUpgrade(request, socket, head, (wsIn) => {
        let wsOut;
        try {
          wsOut = new WebSocket(target, {
            headers: {
              "user-agent": USER_AGENT_DEFAULT,
              "origin": request.headers.origin || request.headers.host || ""
            }
          });
        } catch {
          try { wsIn.close(); } catch {}
          return;
        }

        const closeBoth = () => {
          try { wsIn.close(); } catch {}
          try { wsOut.close(); } catch {}
        };

        wsOut.on("open", () => {
          wsIn.on("message", (m) => { try { wsOut.send(m); } catch {} });
          wsOut.on("message", (m) => { try { wsIn.send(m); } catch {} });
          wsIn.on("close", closeBoth);
          wsOut.on("close", closeBoth);
        });

        wsOut.on("error", closeBoth);
        wsIn.on("error", closeBoth);
      });
    } catch {
      try { socket.destroy(); } catch {}
    }
  });

  return wss;
}

// =============================================================================
// SERVER START
// =============================================================================
const server = http.createServer(app);
setupWsProxy(server);

server.listen(PORT, () => {
  console.log(`Euphoria v3 listening on :${PORT}`);
});

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================
function shutdown() {
  try { server.close(); } catch {}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.on("unhandledRejection", (e) => console.error("unhandledRejection", e?.stack || e));
process.on("uncaughtException", (e) => console.error("uncaughtException", e?.stack || e));