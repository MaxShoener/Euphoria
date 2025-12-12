// server.js
// Euphoria v3 — production hybrid proxy + Wisp-friendly routes
// Focus: image reliability, real redirects, in-site nav/buttons, search-from-bar, caching + speed.
// Node 20+ (ESM). Minimal comments: section headers only.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import { WebSocketServer, WebSocket } from "ws";
import cookie from "cookie";
import { EventEmitter } from "events";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import http from "http";
import https from "https";
import crypto from "crypto";

EventEmitter.defaultMaxListeners = 400;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================== CONFIG ==============================

const PORT = parseInt(process.env.PORT || "3000", 10);

// If set, this is used for all absolute proxy links.
// If not set, we compute from request (X-Forwarded-Proto/Host) so it never becomes localhost on Koyeb.
const DEPLOYMENT_ORIGIN_ENV = (process.env.DEPLOYMENT_ORIGIN || "").trim();

// Cache
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = (process.env.ENABLE_DISK_CACHE ?? "1") !== "0";

// TTLs
const CACHE_TTL_HTML_MS = parseInt(process.env.CACHE_TTL_HTML_MS || String(1000 * 60 * 4), 10); // 4 min
const CACHE_TTL_ASSET_MS = parseInt(process.env.CACHE_TTL_ASSET_MS || String(1000 * 60 * 15), 10); // 15 min

// Memory cache sizes (bytes)
const MEM_CACHE_MAX_BYTES = parseInt(process.env.MEM_CACHE_MAX_BYTES || String(256 * 1024 * 1024), 10); // 256MB total-ish
const MEM_CACHE_MAX_ITEM_BYTES = parseInt(process.env.MEM_CACHE_MAX_ITEM_BYTES || String(16 * 1024 * 1024), 10); // 16MB per item

// Disk cache threshold for assets (bytes) — keep disk cache smaller items only
const DISK_CACHE_MAX_ASSET_BYTES = parseInt(process.env.DISK_CACHE_MAX_ASSET_BYTES || String(8 * 1024 * 1024), 10); // 8MB
const DISK_CACHE_MAX_HTML_BYTES = parseInt(process.env.DISK_CACHE_MAX_HTML_BYTES || String(2 * 1024 * 1024), 10); // 2MB

// Fetch/network
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "35000", 10);
const USER_AGENT_DEFAULT =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

// Controls
const PER_HOST_CACHE_CONTROLS = {}; // { "example.com": { disable:true, ttlHtmlMs:..., ttlAssetMs:... } }

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// ============================== CONSTANTS ==============================

const DROP_REQ_HEADERS = new Set([
  "host",
  "content-length",
  "connection",
  "transfer-encoding",
  "upgrade",
  "proxy-connection",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
]);

const DROP_RES_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy",
  "report-to",
  "nel",
]);

const PASS_RES_HEADERS_DENYLIST_ON_REWRITE = new Set([
  "content-length",
  "content-encoding",
]);

const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
  ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3", ".m4a", ".wav", ".ogg",
  ".avif", ".bmp", ".apng"
];

const SPECIAL_FILES = [
  "service-worker.js", "sw.js", "worker.js", "manifest.json",
  "robots.txt", "favicon.ico"
];

const HTML_MIME_HINTS = ["text/html", "application/xhtml+xml"];

const SESSION_NAME = "euphoria_sid";
const ADMIN_TOKEN = (process.env.EUPH_ADMIN_TOKEN || "").trim();

// ============================== APP ==============================

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "1mb" }));

app.use(express.static(path.join(__dirname, "public"), { index: false, maxAge: "10m" }));

// ============================== RATE LIMIT ==============================

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || "900", 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down.",
});
app.use(globalLimiter);

// ============================== MEMORY CACHE ==============================

const MEM_CACHE = new LRUCache({
  maxSize: MEM_CACHE_MAX_BYTES,
  ttlAutopurge: true,
  sizeCalculation: (val) => {
    try {
      if (!val) return 1;
      if (typeof val === "string") return Buffer.byteLength(val, "utf8");
      if (Buffer.isBuffer(val)) return val.length;
      if (val && typeof val === "object") {
        if (val.__b64 && typeof val.__b64 === "string") return Math.min(Buffer.byteLength(val.__b64, "utf8"), MEM_CACHE_MAX_ITEM_BYTES);
        return Math.min(Buffer.byteLength(JSON.stringify(val), "utf8"), MEM_CACHE_MAX_ITEM_BYTES);
      }
      return 64;
    } catch {
      return 256;
    }
  },
});

// ============================== DISK CACHE ==============================

function now() { return Date.now(); }

function cacheKey(s) {
  // url-safe hash, shorter than base64(url)
  return crypto.createHash("sha256").update(s).digest("base64url");
}

function diskPath(key) {
  return path.join(CACHE_DIR, cacheKey(key) + ".json");
}

async function diskGet(key, ttlMs) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const fp = diskPath(key);
    if (!fs.existsSync(fp)) return null;
    const raw = await fsPromises.readFile(fp, "utf8");
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    if ((now() - obj.t) < ttlMs) return obj.v;
    fsPromises.unlink(fp).catch(() => {});
  } catch {}
  return null;
}

async function diskSet(key, val) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const fp = diskPath(key);
    await fsPromises.writeFile(fp, JSON.stringify({ t: now(), v: val }), "utf8").catch(() => {});
  } catch {}
}

// ============================== SESSIONS ==============================

const SESSIONS = new Map();

function makeSid() {
  return crypto.randomBytes(16).toString("hex") + "-" + Date.now().toString(36);
}

function createSession(req) {
  const sid = makeSid();
  const payload = {
    cookies: new Map(),
    last: now(),
    ua: USER_AGENT_DEFAULT,
    ip: req?.ip || req?.socket?.remoteAddress || null,
  };
  SESSIONS.set(sid, payload);
  return { sid, payload };
}

function parseCookies(header = "") {
  try {
    return cookie.parse(header || "");
  } catch {
    const out = {};
    (header || "").split(";").forEach((p) => {
      const [k, v] = (p || "").split("=").map((s) => (s || "").trim());
      if (k && v) out[k] = v;
    });
    return out;
  }
}

function getSessionFromReq(req) {
  const parsed = parseCookies(req.headers.cookie || "");
  const sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession(req);
  const payload = SESSIONS.get(sid);
  payload.last = now();
  payload.ip = req.ip || payload.ip;
  return { sid, payload };
}

function setSessionCookieHeader(req, res, sid) {
  const secure = (req.headers["x-forwarded-proto"] || req.protocol || "").toString().toLowerCase() === "https";
  const cookieStr =
    `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}` +
    (secure ? "; Secure" : "");
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
    } catch {}
  }
}

function buildCookieHeader(map) {
  try {
    return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  } catch {
    return "";
  }
}

// Cleanup stale sessions
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 24);
  for (const [sid, p] of SESSIONS.entries()) {
    if (p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 20);

// ============================== ORIGIN / URL HELPERS ==============================

function getPublicOrigin(req) {
  if (DEPLOYMENT_ORIGIN_ENV) return DEPLOYMENT_ORIGIN_ENV.replace(/\/+$/, "");
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0].trim() || req.protocol || "http";
  const xfHost = (req.headers["x-forwarded-host"] || "").toString().split(",")[0].trim();
  const host = xfHost || req.headers.host || `localhost:${PORT}`;
  return `${xfProto}://${host}`.replace(/\/+$/, "");
}

function safeUrl(str, base) {
  try { return new URL(str, base); } catch { return null; }
}

function isLikelySearchQuery(input) {
  const s = (input || "").trim();
  if (!s) return false;
  if (/\s/.test(s)) return true; // spaces -> search
  if (!/[.]/.test(s) && !/^https?:\/\//i.test(s)) return true; // no dot and no scheme -> search
  return false;
}

function toGoogleSearchUrl(q) {
  const query = (q || "").trim();
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

function normalizeTarget(raw) {
  let s = (raw || "").trim();
  if (!s) return null;

  // Allow /proxy?q=term or user typing "term"
  if (isLikelySearchQuery(s)) return toGoogleSearchUrl(s);

  // If missing scheme, add https
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  return s;
}

function proxyUrlFor(req, abs) {
  const origin = getPublicOrigin(req);
  return `${origin}/proxy?url=${encodeURIComponent(abs)}`;
}

function alreadyProxied(href) {
  return typeof href === "string" && href.includes("/proxy?url=");
}

function looksLikeAsset(urlStr) {
  if (!urlStr) return false;
  try {
    const u = new URL(urlStr, "https://x.invalid");
    const p = (u.pathname || "").toLowerCase();
    if (SPECIAL_FILES.some((f) => p.endsWith("/" + f) || p.endsWith(f))) return true;
    return ASSET_EXTENSIONS.some((ext) => p.endsWith(ext));
  } catch {
    const lower = urlStr.toLowerCase();
    if (SPECIAL_FILES.some((f) => lower.endsWith("/" + f) || lower.endsWith(f))) return true;
    return ASSET_EXTENSIONS.some((ext) => lower.endsWith(ext));
  }
}

function sanitizeHtml(html) {
  try {
    // Strip CSP metas + integrity/crossorigin that often break on rewritten resources
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch {}
  return html;
}

// ============================== UPSTREAM FETCH ==============================

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

async function upstreamFetch(url, opts = {}) {
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  const fetchOpts = {
    ...opts,
    signal: controller.signal,
  };

  // Node fetch (undici) accepts agent as dispatcher in some environments; in Node 20 it supports "agent".
  fetchOpts.agent = isHttps ? httpsAgent : httpAgent;

  try {
    const res = await fetch(url, fetchOpts);
    clearTimeout(timeout);
    return res;
  } catch (e) {
    clearTimeout(timeout);
    throw e;
  }
}

// ============================== HEADER BUILDING ==============================

function buildUpstreamHeaders(req, sessionPayload, targetUrl) {
  const headers = {};

  // Copy most request headers through (important for modern sites + images)
  for (const [kRaw, vRaw] of Object.entries(req.headers || {})) {
    const k = (kRaw || "").toLowerCase();
    if (!k || DROP_REQ_HEADERS.has(k)) continue;
    if (k === "cookie") continue; // we manage cookies
    if (k === "referer") continue; // we set below
    headers[k] = vRaw;
  }

  // UA / accept defaults
  headers["user-agent"] = sessionPayload.ua || req.headers["user-agent"] || USER_AGENT_DEFAULT;
  headers["accept"] = req.headers["accept"] || "*/*";

  // Avoid lying about encoding; Node fetch can decompress.
  // If we forward accept-encoding, some CDNs behave differently; we keep it unless you want to disable.
  if (!headers["accept-encoding"] && req.headers["accept-encoding"]) {
    headers["accept-encoding"] = req.headers["accept-encoding"];
  }

  // Cookies (session store)
  const cookieHdr = buildCookieHeader(sessionPayload.cookies);
  if (cookieHdr) headers["cookie"] = cookieHdr;

  // Origin + referer are important
  try {
    headers["origin"] = new URL(targetUrl).origin;
  } catch {}

  // Referrer: use upstream url as ref by default if present
  if (req.headers.referer) {
    // Many sites validate referer; keep original
    headers["referer"] = req.headers.referer;
  } else {
    try { headers["referer"] = new URL(targetUrl).origin + "/"; } catch {}
  }

  return headers;
}

// ============================== RESPONSE HEADER APPLY ==============================

function applyUpstreamHeaders(res, upstreamHeaders, { rewriting = false } = {}) {
  try {
    upstreamHeaders.forEach((v, k) => {
      const lk = k.toLowerCase();
      if (DROP_RES_HEADERS.has(lk)) return;
      if (rewriting && PASS_RES_HEADERS_DENYLIST_ON_REWRITE.has(lk)) return;
      try { res.setHeader(k, v); } catch {}
    });
  } catch {}
}

// ============================== HTML REWRITE (JSDOM) ==============================

function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

function proxyize(req, abs) {
  return proxyUrlFor(req, abs);
}

function jsdomTransform(req, html, baseUrl) {
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;

    if (!document.querySelector("base")) {
      const head = document.querySelector("head");
      if (head) {
        const b = document.createElement("base");
        b.setAttribute("href", baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }

    // Links
    for (const a of Array.from(document.querySelectorAll("a[href]"))) {
      try {
        const href = a.getAttribute("href");
        if (!href) continue;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) continue;
        if (alreadyProxied(href)) continue;
        const abs = toAbsolute(href, baseUrl) || href;
        a.setAttribute("href", proxyize(req, abs));
        // Many modern sites use target _blank; keep same-tab to preserve session
        a.removeAttribute("target");
        a.setAttribute("rel", "noreferrer");
      } catch {}
    }

    // Forms
    for (const f of Array.from(document.querySelectorAll("form[action]"))) {
      try {
        const act = f.getAttribute("action") || "";
        if (!act) continue;
        if (alreadyProxied(act)) continue;
        const abs = toAbsolute(act, baseUrl) || act;
        f.setAttribute("action", proxyize(req, abs));
      } catch {}
    }

    // Assets: src/href on common elements
    const assetTags = ["img", "script", "link", "iframe", "source", "video", "audio", "track"];
    for (const tag of assetTags) {
      const nodes = Array.from(document.getElementsByTagName(tag));
      for (const el of nodes) {
        try {
          const attr = el.getAttribute("src") ? "src" : (el.getAttribute("href") ? "href" : null);
          if (!attr) continue;
          const v = el.getAttribute(attr);
          if (!v) continue;
          if (/^data:/i.test(v)) continue;
          if (alreadyProxied(v)) continue;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(attr, proxyize(req, abs));
        } catch {}
      }
    }

    // srcset
    for (const el of Array.from(document.querySelectorAll("[srcset]"))) {
      try {
        const ss = el.getAttribute("srcset") || "";
        const parts = ss.split(",").map((p) => {
          const trimmed = p.trim();
          if (!trimmed) return p;
          const [u, rest] = trimmed.split(/\s+/, 2);
          if (!u) return p;
          if (/^data:/i.test(u)) return p;
          if (alreadyProxied(u)) return p;
          const abs = toAbsolute(u, baseUrl) || u;
          return proxyize(req, abs) + (rest ? " " + rest : "");
        });
        el.setAttribute("srcset", parts.join(", "));
      } catch {}
    }

    // style tags url(...)
    for (const st of Array.from(document.querySelectorAll("style"))) {
      try {
        let txt = st.textContent || "";
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
          if (!u) return m;
          if (/^data:/i.test(u)) return m;
          if (alreadyProxied(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyize(req, abs)}")`;
        });
        st.textContent = txt;
      } catch {}
    }

    // inline styles url(...)
    for (const el of Array.from(document.querySelectorAll("[style]"))) {
      try {
        const s = el.getAttribute("style") || "";
        const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
          if (!u) return m;
          if (/^data:/i.test(u)) return m;
          if (alreadyProxied(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyize(req, abs)}")`;
        });
        el.setAttribute("style", out);
      } catch {}
    }

    // meta refresh
    for (const m of Array.from(document.querySelectorAll('meta[http-equiv="refresh" i]'))) {
      try {
        const c = m.getAttribute("content") || "";
        const parts = c.split(";");
        if (parts.length < 2) continue;
        const urlPartMatch = parts.slice(1).join(";").match(/url=(.*)/i);
        if (!urlPartMatch) continue;
        const dest = urlPartMatch[1].replace(/['"]/g, "").trim();
        const abs = toAbsolute(dest, baseUrl) || dest;
        m.setAttribute("content", parts[0] + ";url=" + proxyize(req, abs));
      } catch {}
    }

    // remove noscript blocks (often contains broken fallbacks)
    for (const n of Array.from(document.getElementsByTagName("noscript"))) {
      try { n.parentNode && n.parentNode.removeChild(n); } catch {}
    }

    return dom.serialize();
  } catch {
    return html;
  }
}

// ============================== CLIENT RUNTIME PATCH ==============================

function clientRuntimePatch(req) {
  const ORIGIN = getPublicOrigin(req);
  const marker = "/* EUPHORIA_RUNTIME_PATCH_V3 */";
  return `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(ORIGIN)};
  function prox(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(u.includes("/proxy?url=")) return u;
      if(/^data:|^blob:|^about:|^javascript:/i.test(u)) return u;
      const abs = new URL(u, document.baseURI).href;
      return ORIGIN + "/proxy?url=" + encodeURIComponent(abs);
    }catch(e){ return u; }
  }

  // Patch location-style navigations
  try{
    const _assign = window.location.assign.bind(window.location);
    const _replace = window.location.replace.bind(window.location);
    window.location.assign = function(u){ return _assign(prox(u)); };
    window.location.replace = function(u){ return _replace(prox(u)); };
  }catch(e){}

  // Patch history
  try{
    const _ps = history.pushState.bind(history);
    const _rs = history.replaceState.bind(history);
    history.pushState = function(st, title, url){
      if(typeof url === "string") url = prox(url);
      return _ps(st, title, url);
    };
    history.replaceState = function(st, title, url){
      if(typeof url === "string") url = prox(url);
      return _rs(st, title, url);
    };
  }catch(e){}

  // Intercept clicks for in-site buttons that use JS navigation
  document.addEventListener("click", function(e){
    try{
      const a = e.target && e.target.closest ? e.target.closest("a[href]") : null;
      if(!a) return;
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(href.includes("/proxy?url=")) return;
      const p = prox(href);
      a.setAttribute("href", p);
    }catch(_){}
  }, true);

  // Patch fetch
  try{
    const _fetch = window.fetch;
    window.fetch = function(resource, init){
      try{
        if(typeof resource === "string") resource = prox(resource);
        else if(resource && resource.url) resource = new Request(prox(resource.url), resource);
      }catch(e){}
      return _fetch(resource, init);
    };
  }catch(e){}

  // Patch XHR
  try{
    const X = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new X();
      const open = xhr.open;
      xhr.open = function(method, url, ...rest){
        try{
          if(typeof url === "string") url = prox(url);
        }catch(e){}
        return open.call(this, method, url, ...rest);
      };
      return xhr;
    };
  }catch(e){}

  // Patch WebSocket and EventSource for apps (best-effort; many sites still block)
  try{
    const _WS = window.WebSocket;
    window.WebSocket = function(url, protocols){
      try{
        if(typeof url === "string" && !url.includes("/_wsproxy?url=")){
          const abs = new URL(url, document.baseURI).href;
          const wsUrl = ORIGIN + "/_wsproxy?url=" + encodeURIComponent(abs);
          return protocols ? new _WS(wsUrl, protocols) : new _WS(wsUrl);
        }
      }catch(e){}
      return protocols ? new _WS(url, protocols) : new _WS(url);
    };
    window.WebSocket.prototype = _WS.prototype;
  }catch(e){}

  try{
    const _ES = window.EventSource;
    window.EventSource = function(url, cfg){
      try{
        if(typeof url === "string") url = prox(url);
      }catch(e){}
      return new _ES(url, cfg);
    };
    window.EventSource.prototype = _ES.prototype;
  }catch(e){}

})();
</script>
`;
}

// ============================== BODY DETECTION ==============================

function requestWantsHtml(req) {
  const accept = (req.headers.accept || "").toString().toLowerCase();
  return HTML_MIME_HINTS.some((h) => accept.includes(h)) || req.query.force_html === "1";
}

// ============================== MAIN PROXY ROUTES ==============================

// Shortcut: /proxy?q=hello -> google search
// Normal: /proxy?url=https://example.com
app.get("/proxy", async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  if (q) {
    const abs = toGoogleSearchUrl(q);
    return handleProxy(req, res, abs);
  }

  const raw = (req.query.url || "").toString().trim();
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com or /proxy?q=search)");

  const abs = normalizeTarget(raw);
  if (!abs) return res.status(400).send("Invalid target");
  return handleProxy(req, res, abs);
});

// Friendly route: /proxy/:host/* -> https://:host/*
app.get("/proxy/:host/*", async (req, res) => {
  const host = (req.params.host || "").trim();
  const rest = (req.params[0] || "").toString();
  if (!host) return res.status(400).send("Missing host");
  const abs = `https://${host}/${rest}`.replace(/\/{2,}/g, "/").replace("https:/", "https://");
  return handleProxy(req, res, abs);
});

// Smart input route: /go/<anything> (good for UI url bar if you want)
app.get("/go/*", (req, res) => {
  const raw = (req.params[0] || "").toString();
  const abs = normalizeTarget(raw);
  if (!abs) return res.redirect("/");
  return res.redirect(`/proxy?url=${encodeURIComponent(abs)}`);
});

// ============================== CORE PROXY HANDLER ==============================

async function handleProxy(req, res, absoluteUrl) {
  const session = getSessionFromReq(req);
  setSessionCookieHeader(req, res, session.sid);

  // Resolve per-host cache config
  let host = "";
  try { host = new URL(absoluteUrl).hostname; } catch {}
  const hostCfg = PER_HOST_CACHE_CONTROLS[host] || {};
  const ttlHtml = hostCfg.ttlHtmlMs ?? CACHE_TTL_HTML_MS;
  const ttlAsset = hostCfg.ttlAssetMs ?? CACHE_TTL_ASSET_MS;

  // Decide HTML vs asset
  const wantsHtml = requestWantsHtml(req);

  // Keys
  const htmlKey = `html::${absoluteUrl}`;
  const assetKey = `asset::${absoluteUrl}::${req.headers["range"] ? "range" : "full"}`;

  // Cache read
  if (wantsHtml) {
    const mem = MEM_CACHE.get(htmlKey);
    if (typeof mem === "string") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("X-Euphoria-Cache", "mem");
      return res.status(200).send(mem);
    }
    const disk = await diskGet(htmlKey, ttlHtml);
    if (typeof disk === "string") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("X-Euphoria-Cache", "disk");
      MEM_CACHE.set(htmlKey, disk, { ttl: ttlHtml });
      return res.status(200).send(disk);
    }
  } else {
    const mem = MEM_CACHE.get(assetKey);
    if (mem && mem.__b64 && mem.headers) {
      res.setHeader("X-Euphoria-Cache", "mem");
      for (const [k, v] of Object.entries(mem.headers)) {
        if (!DROP_RES_HEADERS.has(k.toLowerCase())) {
          try { res.setHeader(k, v); } catch {}
        }
      }
      const buf = Buffer.from(mem.__b64, "base64");
      return res.status(200).send(buf);
    }
    const disk = await diskGet(assetKey, ttlAsset);
    if (disk && disk.__b64 && disk.headers) {
      res.setHeader("X-Euphoria-Cache", "disk");
      for (const [k, v] of Object.entries(disk.headers)) {
        if (!DROP_RES_HEADERS.has(k.toLowerCase())) {
          try { res.setHeader(k, v); } catch {}
        }
      }
      const buf = Buffer.from(disk.__b64, "base64");
      MEM_CACHE.set(assetKey, disk, { ttl: ttlAsset });
      return res.status(200).send(buf);
    }
  }

  // Upstream request
  const upstreamHeaders = buildUpstreamHeaders(req, session.payload, absoluteUrl);

  // Important for images/media: forward Range
  if (req.headers.range) upstreamHeaders["range"] = req.headers.range;

  // Avoid broken host routing
  delete upstreamHeaders["host"];

  let upstreamRes;
  try {
    upstreamRes = await upstreamFetch(absoluteUrl, {
      method: req.method,
      headers: upstreamHeaders,
      redirect: "manual",
    });
  } catch (err) {
    const msg = (err && err.name === "AbortError") ? "timeout" : (err && err.message ? err.message : String(err));
    return res.status(502).send("Euphoria: Failed to fetch upstream: " + msg);
  }

  // Store upstream cookies (best-effort; Node fetch doesn’t expose raw set-cookie always)
  try {
    const sc = upstreamRes.headers.get("set-cookie");
    if (sc) storeSetCookieToSession([sc], session.payload);
  } catch {}

  // Handle redirects (always rewrite to our public origin)
  const status = upstreamRes.status;
  if ([301, 302, 303, 307, 308].includes(status)) {
    const loc = upstreamRes.headers.get("location");
    if (loc) {
      let abs;
      try { abs = new URL(loc, absoluteUrl).href; } catch { abs = loc; }
      const proxied = proxyUrlFor(req, abs);
      res.setHeader("Location", proxied);
      res.setHeader("X-Euphoria-Redirect", "1");
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  const contentType = (upstreamRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = HTML_MIME_HINTS.some((h) => contentType.includes(h));
  const treatAsHtml = wantsHtml || isHtml;

  // Asset passthrough (streaming)
  if (!treatAsHtml) {
    applyUpstreamHeaders(res, upstreamRes.headers, { rewriting: false });

    // Ensure content-type exists
    if (!res.getHeader("Content-Type")) {
      res.setHeader("Content-Type", contentType || "application/octet-stream");
    }

    // Performance + “complex image” reliability:
    // - stream response
    // - preserve status & range responses
    res.status(upstreamRes.status);

    // Cache small assets (buffer only if below thresholds)
    const cacheableByHost = hostCfg.disable !== true;
    const canMemCache = cacheableByHost;
    const canDiskCache = cacheableByHost && ENABLE_DISK_CACHE;

    const clen = parseInt(upstreamRes.headers.get("content-length") || "0", 10) || 0;
    const range = !!req.headers.range;
    const cacheableSize = clen > 0 ? clen : 0;

    // If it's a range request, don't cache (can explode cache keys)
    if (range || cacheableSize > MEM_CACHE_MAX_ITEM_BYTES || cacheableSize > DISK_CACHE_MAX_ASSET_BYTES) {
      try {
        if (upstreamRes.body) {
          upstreamRes.body.pipe(res);
          return;
        }
      } catch {}
      // fallback buffer
      const ab = await upstreamRes.arrayBuffer();
      return res.send(Buffer.from(ab));
    }

    // Buffer for caching
    try {
      const ab = await upstreamRes.arrayBuffer();
      const buf = Buffer.from(ab);

      // send
      res.send(buf);

      // cache
      const headersObj = Object.fromEntries(upstreamRes.headers.entries());
      const entry = { headers: headersObj, __b64: buf.toString("base64") };

      if (canMemCache && buf.length <= MEM_CACHE_MAX_ITEM_BYTES) {
        MEM_CACHE.set(assetKey, entry, { ttl: ttlAsset });
      }
      if (canDiskCache && buf.length <= DISK_CACHE_MAX_ASSET_BYTES) {
        diskSet(assetKey, entry).catch(() => {});
      }
      return;
    } catch {
      try {
        if (upstreamRes.body) {
          upstreamRes.body.pipe(res);
          return;
        }
      } catch {}
      return res.status(502).send("Euphoria: asset stream failed");
    }
  }

  // HTML rewrite path
  let htmlText = "";
  try {
    htmlText = await upstreamRes.text();
  } catch {
    return res.status(502).send("Euphoria: failed reading HTML");
  }

  htmlText = sanitizeHtml(htmlText);

  // JSDOM transform
  let transformed = jsdomTransform(req, htmlText, upstreamRes.url || absoluteUrl);

  // Inject runtime patch
  if (!transformed.includes("EUPHORIA_RUNTIME_PATCH_V3")) {
    transformed = transformed.replace(/<\/body>/i, clientRuntimePatch(req) + "</body>");
  }

  // Apply headers with rewrite-safe denylist
  applyUpstreamHeaders(res, upstreamRes.headers, { rewriting: true });
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  // Avoid caching giant HTML
  const size = Buffer.byteLength(transformed, "utf8");
  const cacheableByHost = hostCfg.disable !== true;

  if (cacheableByHost && size <= DISK_CACHE_MAX_HTML_BYTES) {
    MEM_CACHE.set(htmlKey, transformed, { ttl: ttlHtml });
    diskSet(htmlKey, transformed).catch(() => {});
  } else if (cacheableByHost && size <= MEM_CACHE_MAX_ITEM_BYTES) {
    MEM_CACHE.set(htmlKey, transformed, { ttl: ttlHtml });
  }

  res.setHeader("X-Euphoria-Cache", "miss");
  return res.status(200).send(transformed);
}

// ============================== FALLBACK RELATIVE REQUESTS ==============================

app.use(async (req, res, next) => {
  const p = req.path || "/";
  if (
    p.startsWith("/proxy") ||
    p.startsWith("/_wsproxy") ||
    p.startsWith("/_euph_ws") ||
    p.startsWith("/_euph_debug") ||
    p.startsWith("/public") ||
    p.startsWith("/static")
  ) return next();

  // If user is already in proxied page, relative asset calls might hit root. We attempt to rebuild using referer.
  const referer = (req.headers.referer || req.headers.referrer || "").toString();
  const m = referer.match(/[?&]url=([^&]+)/);
  if (!m) return next();

  let orig;
  try { orig = decodeURIComponent(m[1]); } catch { return next(); }
  if (!orig) return next();

  let baseOrigin;
  try { baseOrigin = new URL(orig).origin; } catch { return next(); }

  const attempted = new URL(req.originalUrl, baseOrigin).href;
  const abs = attempted;

  // Route through core
  return handleProxy(req, res, abs);
});

// ============================== WEBSOCKET PROXY ==============================

function setupWsProxy(httpServer) {
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });

  httpServer.on("upgrade", (request, socket, head) => {
    try {
      const u = new URL(request.url, `http://${request.headers.host}`);
      if (u.pathname !== "/_wsproxy") return;
      const target = u.searchParams.get("url");
      if (!target) {
        socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
        socket.destroy();
        return;
      }

      wssProxy.handleUpgrade(request, socket, head, (wsIn) => {
        let wsOut;
        try {
          // Preserve protocol conversion if user passed http(s) url
          let t = target;
          if (/^https?:\/\//i.test(t)) {
            t = t.replace(/^http:/i, "ws:").replace(/^https:/i, "wss:");
          }
          wsOut = new WebSocket(t, {
            headers: {
              "user-agent": request.headers["user-agent"] || USER_AGENT_DEFAULT,
              "origin": request.headers["origin"] || "",
            },
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
          wsIn.on("message", (msg) => { try { wsOut.send(msg); } catch {} });
          wsOut.on("message", (msg) => { try { wsIn.send(msg); } catch {} });
          wsIn.on("close", closeBoth);
          wsOut.on("close", closeBoth);
          wsIn.on("error", closeBoth);
          wsOut.on("error", closeBoth);
        });

        wsOut.on("error", closeBoth);
      });
    } catch {
      try { socket.destroy(); } catch {}
    }
  });

  return wssProxy;
}

// ============================== TELEMETRY WS ==============================

function setupTelemetryWs(httpServer) {
  const wssTelemetry = new WebSocketServer({ server: httpServer, path: "/_euph_ws" });
  wssTelemetry.on("connection", (ws) => {
    ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
    ws.on("message", (raw) => {
      try {
        const parsed = JSON.parse(raw.toString());
        if (parsed && parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
      } catch {}
    });
  });
  return wssTelemetry;
}

// ============================== ADMIN ==============================

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  res.status(403).json({ error: "forbidden" });
}

app.get("/_euph_debug/ping", (req, res) => res.json({ msg: "pong", ts: Date.now() }));

app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, payload] of SESSIONS.entries()) {
    out[sid] = {
      last: new Date(payload.last).toISOString(),
      ua: payload.ua,
      ip: payload.ip,
      cookies: Object.fromEntries(payload.cookies.entries()),
    };
  }
  res.json({ sessions: out, count: SESSIONS.size });
});

app.get("/_euph_debug/cache", requireAdmin, (req, res) => {
  res.json({
    memCount: MEM_CACHE.size,
    memMaxBytes: MEM_CACHE_MAX_BYTES,
    memCalc: "lru-cache maxSize bytes",
  });
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

// ============================== SPA FALLBACK ==============================

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && (req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ============================== SERVER START ==============================

const server = http.createServer(app);
setupWsProxy(server);
setupTelemetryWs(server);

server.listen(PORT, () => {
  console.log(`Euphoria v3 running on port ${PORT}`);
});

// ============================== PROCESS HANDLERS ==============================

process.on("unhandledRejection", (err) => {
  console.error("unhandledRejection", err && err.stack ? err.stack : err);
});
process.on("uncaughtException", (err) => {
  console.error("uncaughtException", err && err.stack ? err.stack : err);
});
process.on("warning", (w) => {
  console.warn("warning", w && w.stack ? w.stack : w);
});

async function shutdown() {
  try { server.close(); } catch {}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
