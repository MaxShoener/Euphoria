// server.js
// Euphoria v4 — hybrid proxy focused on: logins, heavy SPAs, media/images, redirects, POST bodies, cookie jar.
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
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import http from "http";
import https from "https";
import crypto from "crypto";
import setCookieParser from "set-cookie-parser";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================== CONFIG ==============================

const PORT = parseInt(process.env.PORT || "3000", 10);

// If set, hard overrides absolute proxy URL generation.
// If NOT set, proxy will auto-detect from request headers (fixes Koyeb localhost redirect issue).
const DEPLOYMENT_ORIGIN_ENV = (process.env.DEPLOYMENT_ORIGIN || "").trim().replace(/\/+$/, "");

// Cache
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = (process.env.ENABLE_DISK_CACHE ?? "1") !== "0";

// TTLs
const CACHE_TTL_HTML_MS = parseInt(process.env.CACHE_TTL_HTML_MS || String(1000 * 60 * 3), 10); // 3 min
const CACHE_TTL_ASSET_MS = parseInt(process.env.CACHE_TTL_ASSET_MS || String(1000 * 60 * 12), 10); // 12 min

// Memory cache sizing (bytes)
const MEM_CACHE_MAX_BYTES = parseInt(process.env.MEM_CACHE_MAX_BYTES || String(384 * 1024 * 1024), 10); // 384MB
const MEM_CACHE_MAX_ITEM_BYTES = parseInt(process.env.MEM_CACHE_MAX_ITEM_BYTES || String(24 * 1024 * 1024), 10); // 24MB per item

// Disk cache thresholds (bytes)
const DISK_CACHE_MAX_ASSET_BYTES = parseInt(process.env.DISK_CACHE_MAX_ASSET_BYTES || String(12 * 1024 * 1024), 10); // 12MB
const DISK_CACHE_MAX_HTML_BYTES = parseInt(process.env.DISK_CACHE_MAX_HTML_BYTES || String(2 * 1024 * 1024), 10); // 2MB

// Request body limit (for login POSTs)
const MAX_BODY_BYTES = parseInt(process.env.MAX_BODY_BYTES || String(10 * 1024 * 1024), 10); // 10MB

// Network
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "40000", 10);
const USER_AGENT_DEFAULT =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

// Admin
const ADMIN_TOKEN = (process.env.EUPH_ADMIN_TOKEN || "").trim();

// Per-host toggles (optional)
const PER_HOST = {
  // Example:
  // "accounts.google.com": { disableRewrite: true, disableCache: true },
};

// Init disk cache dir
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

const REWRITE_STRIP_HEADERS = new Set([
  "content-length",
  "content-encoding",
]);

const HTML_MIME_HINTS = ["text/html", "application/xhtml+xml"];

// ============================== APP ==============================

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.static(path.join(__dirname, "public"), { index: false, maxAge: "10m" }));

// ============================== RATE LIMIT ==============================

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_GLOBAL || "1200", 10),
    standardHeaders: true,
    legacyHeaders: false,
    message: "Too many requests, slow down.",
  })
);

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
        if (val.__b64) return Math.min(Buffer.byteLength(val.__b64, "utf8"), MEM_CACHE_MAX_ITEM_BYTES);
        return Math.min(Buffer.byteLength(JSON.stringify(val), "utf8"), MEM_CACHE_MAX_ITEM_BYTES);
      }
      return 256;
    } catch {
      return 512;
    }
  },
});

function now() {
  return Date.now();
}

// ============================== DISK CACHE ==============================

function cacheKey(s) {
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
    await fsPromises.writeFile(diskPath(key), JSON.stringify({ t: now(), v: val }), "utf8").catch(() => {});
  } catch {}
}

// ============================== SESSIONS + COOKIE JAR ==============================

const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();

// Cookie jar format per session:
// jar: Map<domain, Map<cookieName, { value, domain, path, expiresAt, secure, httpOnly, sameSite }>>
function makeSid() {
  return crypto.randomBytes(16).toString("hex") + "-" + Date.now().toString(36);
}
function createSession(req) {
  const sid = makeSid();
  const payload = {
    last: now(),
    ua: USER_AGENT_DEFAULT,
    ip: req?.ip || req?.socket?.remoteAddress || null,
    jar: new Map(),
  };
  SESSIONS.set(sid, payload);
  return { sid, payload };
}
function parseCookiesHeader(header = "") {
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
  const parsed = parseCookiesHeader(req.headers.cookie || "");
  const sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession(req);
  const payload = SESSIONS.get(sid);
  payload.last = now();
  payload.ip = req.ip || payload.ip;
  return { sid, payload };
}
function setSessionCookieHeader(req, res, sid) {
  const secure = ((req.headers["x-forwarded-proto"] || req.protocol || "") + "").toLowerCase().includes("https");
  const c = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}` + (secure ? "; Secure" : "");
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", c);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, c]);
  else res.setHeader("Set-Cookie", [prev, c]);
}
function cleanupExpiredCookies(sessionPayload) {
  const t = now();
  for (const [domain, cmap] of sessionPayload.jar.entries()) {
    for (const [name, c] of cmap.entries()) {
      if (c.expiresAt && c.expiresAt <= t) cmap.delete(name);
    }
    if (cmap.size === 0) sessionPayload.jar.delete(domain);
  }
}
function domainMatches(cookieDomain, host) {
  if (!cookieDomain || !host) return false;
  const cd = cookieDomain.replace(/^\./, "").toLowerCase();
  const h = host.toLowerCase();
  if (h === cd) return true;
  return h.endsWith("." + cd);
}
function pathMatches(cookiePath, reqPath) {
  const cp = cookiePath || "/";
  const rp = reqPath || "/";
  if (cp === "/") return true;
  return rp.startsWith(cp);
}
function cookieStringFor(sessionPayload, urlObj) {
  cleanupExpiredCookies(sessionPayload);
  const host = urlObj.hostname;
  const reqPath = urlObj.pathname || "/";
  const pairs = [];
  for (const [domain, cmap] of sessionPayload.jar.entries()) {
    if (!domainMatches(domain, host)) continue;
    for (const [name, c] of cmap.entries()) {
      if (!pathMatches(c.path, reqPath)) continue;
      if (!name) continue;
      pairs.push(`${name}=${c.value}`);
    }
  }
  return pairs.join("; ");
}
function storeSetCookies(sessionPayload, setCookieHeaders, originUrl) {
  if (!setCookieHeaders || !setCookieHeaders.length) return;
  let originHost = "";
  try { originHost = new URL(originUrl).hostname; } catch {}

  const parsed = setCookieParser.parse(setCookieHeaders, { map: false });
  for (const sc of parsed) {
    try {
      const name = sc.name;
      const value = sc.value ?? "";
      if (!name) continue;

      // Domain defaults to origin host
      const domain = (sc.domain || originHost || "").toLowerCase();
      const pathV = sc.path || "/";

      let expiresAt = 0;
      if (sc.expires) expiresAt = new Date(sc.expires).getTime();
      if (typeof sc.maxAge === "number") expiresAt = now() + sc.maxAge * 1000;

      const entry = {
        value,
        domain,
        path: pathV,
        expiresAt: expiresAt || 0,
        secure: !!sc.secure,
        httpOnly: !!sc.httpOnly,
        sameSite: (sc.sameSite || "").toString(),
      };

      if (!sessionPayload.jar.has(domain)) sessionPayload.jar.set(domain, new Map());
      sessionPayload.jar.get(domain).set(name, entry);
    } catch {}
  }
}

// cleanup stale sessions
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 24);
  for (const [sid, p] of SESSIONS.entries()) {
    if (p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 20);

// ============================== ORIGIN + URL HELPERS ==============================

function getPublicOrigin(req) {
  if (DEPLOYMENT_ORIGIN_ENV) return DEPLOYMENT_ORIGIN_ENV;
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0].trim() || req.protocol || "http";
  const xfHost = (req.headers["x-forwarded-host"] || "").toString().split(",")[0].trim();
  const host = xfHost || (req.headers.host || `localhost:${PORT}`);
  return `${xfProto}://${host}`.replace(/\/+$/, "");
}

function proxyUrlFor(req, absoluteUrl) {
  return `${getPublicOrigin(req)}/proxy?url=${encodeURIComponent(absoluteUrl)}`;
}

function toGoogleSearchUrl(q) {
  const query = (q || "").trim();
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

function isLikelySearchQuery(input) {
  const s = (input || "").trim();
  if (!s) return false;
  if (/\s/.test(s)) return true;
  if (!/[.]/.test(s) && !/^https?:\/\//i.test(s)) return true;
  return false;
}

function normalizeTarget(raw) {
  let s = (raw || "").trim();
  if (!s) return null;
  if (isLikelySearchQuery(s)) return toGoogleSearchUrl(s);
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  return s;
}

function requestWantsHtml(req) {
  const accept = (req.headers.accept || "").toString().toLowerCase();
  return HTML_MIME_HINTS.some((h) => accept.includes(h)) || req.query.force_html === "1";
}

function sanitizeHtml(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch {}
  return html;
}

function alreadyProxied(href) {
  return typeof href === "string" && href.includes("/proxy?url=");
}

function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

// ============================== BODY COLLECT ==============================

async function collectBody(req) {
  // For GET/HEAD no body
  const m = (req.method || "GET").toUpperCase();
  if (m === "GET" || m === "HEAD") return null;

  // If express hasn't parsed it, we read raw
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on("data", (d) => {
      total += d.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("body_too_large"));
        try { req.destroy(); } catch {}
        return;
      }
      chunks.push(d);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ============================== UPSTREAM FETCH ==============================

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 160 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 160 });

async function upstreamFetch(url, opts = {}) {
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  const fetchOpts = { ...opts, signal: controller.signal };
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

  for (const [kRaw, vRaw] of Object.entries(req.headers || {})) {
    const k = (kRaw || "").toLowerCase();
    if (!k || DROP_REQ_HEADERS.has(k)) continue;
    if (k === "cookie") continue;
    headers[k] = vRaw;
  }

  headers["user-agent"] = sessionPayload.ua || req.headers["user-agent"] || USER_AGENT_DEFAULT;
  headers["accept"] = req.headers["accept"] || "*/*";

  // These help with some SPAs that do UA client-hints checks
  if (!headers["sec-fetch-site"] && req.headers["sec-fetch-site"]) headers["sec-fetch-site"] = req.headers["sec-fetch-site"];
  if (!headers["sec-fetch-mode"] && req.headers["sec-fetch-mode"]) headers["sec-fetch-mode"] = req.headers["sec-fetch-mode"];
  if (!headers["sec-fetch-dest"] && req.headers["sec-fetch-dest"]) headers["sec-fetch-dest"] = req.headers["sec-fetch-dest"];
  if (!headers["sec-fetch-user"] && req.headers["sec-fetch-user"]) headers["sec-fetch-user"] = req.headers["sec-fetch-user"];
  if (!headers["sec-ch-ua"] && req.headers["sec-ch-ua"]) headers["sec-ch-ua"] = req.headers["sec-ch-ua"];
  if (!headers["sec-ch-ua-mobile"] && req.headers["sec-ch-ua-mobile"]) headers["sec-ch-ua-mobile"] = req.headers["sec-ch-ua-mobile"];
  if (!headers["sec-ch-ua-platform"] && req.headers["sec-ch-ua-platform"]) headers["sec-ch-ua-platform"] = req.headers["sec-ch-ua-platform"];

  // Cookies from our server-side jar
  try {
    const u = new URL(targetUrl);
    const cstr = cookieStringFor(sessionPayload, u);
    if (cstr) headers["cookie"] = cstr;
  } catch {}

  // Origin/referrer help login and SPA routing
  try {
    headers["origin"] = new URL(targetUrl).origin;
  } catch {}
  if (req.headers.referer) headers["referer"] = req.headers.referer;

  return headers;
}

function applyUpstreamHeaders(res, upstreamHeaders, { rewriting = false } = {}) {
  try {
    upstreamHeaders.forEach((v, k) => {
      const lk = (k || "").toLowerCase();
      if (DROP_RES_HEADERS.has(lk)) return;
      if (rewriting && REWRITE_STRIP_HEADERS.has(lk)) return;
      try { res.setHeader(k, v); } catch {}
    });
  } catch {}
}

// ============================== HTML REWRITE ==============================

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
        a.setAttribute("href", proxyUrlFor(req, abs));
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
        f.setAttribute("action", proxyUrlFor(req, abs));
      } catch {}
    }

    // Assets src/href
    const tags = ["img", "script", "link", "iframe", "source", "video", "audio", "track"];
    for (const tag of tags) {
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
          el.setAttribute(attr, proxyUrlFor(req, abs));
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
          return proxyUrlFor(req, abs) + (rest ? " " + rest : "");
        });
        el.setAttribute("srcset", parts.join(", "));
      } catch {}
    }

    // style url(...)
    for (const st of Array.from(document.querySelectorAll("style"))) {
      try {
        let txt = st.textContent || "";
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
          if (!u) return m;
          if (/^data:/i.test(u)) return m;
          if (alreadyProxied(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyUrlFor(req, abs)}")`;
        });
        st.textContent = txt;
      } catch {}
    }

    // inline style url(...)
    for (const el of Array.from(document.querySelectorAll("[style]"))) {
      try {
        const s = el.getAttribute("style") || "";
        const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
          if (!u) return m;
          if (/^data:/i.test(u)) return m;
          if (alreadyProxied(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyUrlFor(req, abs)}")`;
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
        const match = parts.slice(1).join(";").match(/url=(.*)/i);
        if (!match) continue;
        const dest = match[1].replace(/['"]/g, "").trim();
        const abs = toAbsolute(dest, baseUrl) || dest;
        m.setAttribute("content", parts[0] + ";url=" + proxyUrlFor(req, abs));
      } catch {}
    }

    // noscript
    for (const n of Array.from(document.getElementsByTagName("noscript"))) {
      try { n.parentNode && n.parentNode.removeChild(n); } catch {}
    }

    return dom.serialize();
  } catch {
    return html;
  }
}

// ============================== RUNTIME PATCH ==============================

function runtimePatch(req, upstreamBaseUrl) {
  const ORIGIN = getPublicOrigin(req);
  const marker = "/* EUPHORIA_RUNTIME_PATCH_V4 */";
  return `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(ORIGIN)};
  const UPSTREAM_BASE = ${JSON.stringify(upstreamBaseUrl || "")};

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

  // Best-effort document.cookie bridge (helps some UI/auth code)
  // Reads cookies from server jar for current upstream base URL.
  async function fetchCookieString(){
    try{
      const u = new URL(location.href);
      const raw = u.searchParams.get("url");
      const base = raw ? decodeURIComponent(raw) : (UPSTREAM_BASE || document.baseURI);
      const r = await fetch(ORIGIN + "/__euph/cookie?url=" + encodeURIComponent(base), { credentials:"include" });
      if(!r.ok) return "";
      return await r.text();
    }catch(e){ return ""; }
  }
  async function pushSetCookie(cookieLine){
    try{
      const u = new URL(location.href);
      const raw = u.searchParams.get("url");
      const base = raw ? decodeURIComponent(raw) : (UPSTREAM_BASE || document.baseURI);
      await fetch(ORIGIN + "/__euph/cookie?url=" + encodeURIComponent(base), {
        method:"POST",
        headers:{ "content-type":"text/plain" },
        body: cookieLine || ""
      });
    }catch(e){}
  }

  // Patch cookie getter/setter if possible
  try{
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    if(!desc || desc.configurable){
      Object.defineProperty(document, "cookie", {
        configurable: true,
        get: function(){ return this.__euph_cookie_str || ""; },
        set: function(v){ pushSetCookie(String(v||"")); }
      });
      fetchCookieString().then(s => { document.__euph_cookie_str = s || ""; }).catch(()=>{});
      setInterval(() => { fetchCookieString().then(s => { document.__euph_cookie_str = s || ""; }).catch(()=>{}); }, 2500);
    }
  }catch(e){}

  // Location navigation
  try{
    const _assign = window.location.assign.bind(window.location);
    const _replace = window.location.replace.bind(window.location);
    window.location.assign = function(u){ return _assign(prox(u)); };
    window.location.replace = function(u){ return _replace(prox(u)); };
  }catch(e){}

  // history
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

  // fetch
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

  // xhr
  try{
    const X = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new X();
      const open = xhr.open;
      xhr.open = function(method, url, ...rest){
        try{ if(typeof url === "string") url = prox(url); }catch(e){}
        return open.call(this, method, url, ...rest);
      };
      return xhr;
    };
  }catch(e){}

  // click rewrite
  document.addEventListener("click", function(e){
    try{
      const a = e.target && e.target.closest ? e.target.closest("a[href]") : null;
      if(!a) return;
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(href.includes("/proxy?url=")) return;
      a.setAttribute("href", prox(href));
    }catch(_){}
  }, true);

  // WebSocket -> our /_wsproxy (best-effort)
  try{
    const _WS = window.WebSocket;
    window.WebSocket = function(url, protocols){
      try{
        let u = url;
        if(typeof u === "string"){
          const abs = new URL(u, document.baseURI).href
            .replace(/^http:/i, "ws:")
            .replace(/^https:/i, "wss:");
          const wsUrl = ORIGIN + "/_wsproxy?url=" + encodeURIComponent(abs);
          return protocols ? new _WS(wsUrl, protocols) : new _WS(wsUrl);
        }
      }catch(e){}
      return protocols ? new _WS(url, protocols) : new _WS(url);
    };
    window.WebSocket.prototype = _WS.prototype;
  }catch(e){}

})();
</script>
`;
}

// ============================== CORE PROXY HANDLER ==============================

async function handleProxy(req, res, absoluteUrl) {
  const session = getSessionFromReq(req);
  setSessionCookieHeader(req, res, session.sid);

  let host = "";
  try { host = new URL(absoluteUrl).hostname; } catch {}
  const hostCfg = PER_HOST[host] || {};
  const disableCache = hostCfg.disableCache === true;
  const disableRewrite = hostCfg.disableRewrite === true;

  const wantsHtml = requestWantsHtml(req);

  const htmlKey = `html::${absoluteUrl}`;
  const assetKey = `asset::${absoluteUrl}::${req.headers.range ? "range" : "full"}`;

  // Cache hit
  if (!disableCache && wantsHtml) {
    const mem = MEM_CACHE.get(htmlKey);
    if (typeof mem === "string") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("X-Euphoria-Cache", "mem");
      return res.status(200).send(mem);
    }
    const disk = await diskGet(htmlKey, CACHE_TTL_HTML_MS);
    if (typeof disk === "string") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("X-Euphoria-Cache", "disk");
      MEM_CACHE.set(htmlKey, disk, { ttl: CACHE_TTL_HTML_MS });
      return res.status(200).send(disk);
    }
  }

  if (!disableCache && !wantsHtml) {
    const mem = MEM_CACHE.get(assetKey);
    if (mem && mem.__b64 && mem.headers) {
      res.setHeader("X-Euphoria-Cache", "mem");
      for (const [k, v] of Object.entries(mem.headers)) {
        if (!DROP_RES_HEADERS.has(k.toLowerCase())) {
          try { res.setHeader(k, v); } catch {}
        }
      }
      return res.status(200).send(Buffer.from(mem.__b64, "base64"));
    }
    const disk = await diskGet(assetKey, CACHE_TTL_ASSET_MS);
    if (disk && disk.__b64 && disk.headers) {
      res.setHeader("X-Euphoria-Cache", "disk");
      for (const [k, v] of Object.entries(disk.headers)) {
        if (!DROP_RES_HEADERS.has(k.toLowerCase())) {
          try { res.setHeader(k, v); } catch {}
        }
      }
      MEM_CACHE.set(assetKey, disk, { ttl: CACHE_TTL_ASSET_MS });
      return res.status(200).send(Buffer.from(disk.__b64, "base64"));
    }
  }

  // Upstream fetch
  let bodyBuf = null;
  try {
    bodyBuf = await collectBody(req);
  } catch (e) {
    return res.status(413).send("Euphoria: request body too large");
  }

  const upstreamHeaders = buildUpstreamHeaders(req, session.payload, absoluteUrl);

  // Forward content-type for POST
  if (bodyBuf && req.headers["content-type"]) upstreamHeaders["content-type"] = req.headers["content-type"];
  if (bodyBuf) upstreamHeaders["content-length"] = String(bodyBuf.length);

  // Range for media/images
  if (req.headers.range) upstreamHeaders["range"] = req.headers.range;

  let upstreamRes;
  try {
    upstreamRes = await upstreamFetch(absoluteUrl, {
      method: req.method,
      headers: upstreamHeaders,
      redirect: "manual",
      body: bodyBuf || undefined,
    });
  } catch (err) {
    const msg = (err && err.name === "AbortError") ? "timeout" : (err && err.message ? err.message : String(err));
    return res.status(502).send("Euphoria: Failed to fetch upstream: " + msg);
  }

  // Capture Set-Cookie reliably (Node/undici supports getSetCookie())
  try {
    const sc = upstreamRes.headers.getSetCookie ? upstreamRes.headers.getSetCookie() : [];
    if (Array.isArray(sc) && sc.length) storeSetCookies(session.payload, sc, upstreamRes.url || absoluteUrl);
    else {
      const single = upstreamRes.headers.get("set-cookie");
      if (single) storeSetCookies(session.payload, [single], upstreamRes.url || absoluteUrl);
    }
  } catch {}

  // Redirect rewrite
  const status = upstreamRes.status || 200;
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

  // Decide HTML vs asset
  const contentType = (upstreamRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = HTML_MIME_HINTS.some((h) => contentType.includes(h));
  const treatAsHtml = wantsHtml || isHtml;

  // ASSET: stream with correct headers (fixes complex images + range)
  if (!treatAsHtml) {
    applyUpstreamHeaders(res, upstreamRes.headers, { rewriting: false });
    res.status(status);

    if (!res.getHeader("Content-Type")) {
      res.setHeader("Content-Type", contentType || "application/octet-stream");
    }

    // Don’t cache range responses
    const isRange = !!req.headers.range;

    const clen = parseInt(upstreamRes.headers.get("content-length") || "0", 10) || 0;
    const canBufferForCache = !disableCache && !isRange && clen > 0 && clen <= DISK_CACHE_MAX_ASSET_BYTES && clen <= MEM_CACHE_MAX_ITEM_BYTES;

    if (!canBufferForCache) {
      try {
        if (upstreamRes.body) {
          upstreamRes.body.pipe(res);
          return;
        }
      } catch {}
      const ab = await upstreamRes.arrayBuffer();
      return res.send(Buffer.from(ab));
    }

    // Buffer for caching
    const ab = await upstreamRes.arrayBuffer();
    const buf = Buffer.from(ab);
    res.send(buf);

    if (!disableCache && buf.length <= MEM_CACHE_MAX_ITEM_BYTES) {
      const entry = { headers: Object.fromEntries(upstreamRes.headers.entries()), __b64: buf.toString("base64") };
      MEM_CACHE.set(assetKey, entry, { ttl: CACHE_TTL_ASSET_MS });
      if (buf.length <= DISK_CACHE_MAX_ASSET_BYTES) diskSet(assetKey, entry).catch(() => {});
    }
    return;
  }

  // HTML: read, sanitize, rewrite, inject runtime patch
  let htmlText = "";
  try {
    htmlText = await upstreamRes.text();
  } catch {
    return res.status(502).send("Euphoria: failed reading HTML");
  }

  htmlText = sanitizeHtml(htmlText);

  let transformed = htmlText;

  if (!disableRewrite) {
    transformed = jsdomTransform(req, transformed, upstreamRes.url || absoluteUrl);
    if (!transformed.includes("EUPHORIA_RUNTIME_PATCH_V4")) {
      const baseForCookies = upstreamRes.url || absoluteUrl;
      transformed = transformed.replace(/<\/body>/i, runtimePatch(req, baseForCookies) + "</body>");
    }
  }

  applyUpstreamHeaders(res, upstreamRes.headers, { rewriting: true });
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(status);

  // Cache HTML if reasonable
  const size = Buffer.byteLength(transformed, "utf8");
  if (!disableCache && size <= DISK_CACHE_MAX_HTML_BYTES) {
    MEM_CACHE.set(htmlKey, transformed, { ttl: CACHE_TTL_HTML_MS });
    diskSet(htmlKey, transformed).catch(() => {});
  } else if (!disableCache && size <= MEM_CACHE_MAX_ITEM_BYTES) {
    MEM_CACHE.set(htmlKey, transformed, { ttl: CACHE_TTL_HTML_MS });
  }

  return res.send(transformed);
}

// ============================== ROUTES ==============================

// Main proxy endpoint supports any method (fixes POST login submissions)
app.all("/proxy", async (req, res) => {
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

// /proxy/:host/* -> https://host/*
app.all("/proxy/:host/*", async (req, res) => {
  const host = (req.params.host || "").trim();
  const rest = (req.params[0] || "").toString();
  if (!host) return res.status(400).send("Missing host");
  const abs = `https://${host}/${rest}`.replace(/\/{2,}/g, "/").replace("https:/", "https://");
  return handleProxy(req, res, abs);
});

// /go/<something> convenience
app.get("/go/*", (req, res) => {
  const raw = (req.params[0] || "").toString();
  const abs = normalizeTarget(raw);
  if (!abs) return res.redirect("/");
  return res.redirect(`/proxy?url=${encodeURIComponent(abs)}`);
});

// Cookie bridge used by injected runtime patch (best-effort)
app.get("/__euph/cookie", (req, res) => {
  const u = (req.query.url || "").toString();
  const abs = normalizeTarget(u) || u;
  if (!abs) return res.status(400).send("");
  const session = getSessionFromReq(req);
  setSessionCookieHeader(req, res, session.sid);
  try {
    const urlObj = new URL(abs);
    const c = cookieStringFor(session.payload, urlObj);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(c || "");
  } catch {
    return res.status(200).send("");
  }
});

app.post("/__euph/cookie", async (req, res) => {
  const u = (req.query.url || "").toString();
  const abs = normalizeTarget(u) || u;
  const session = getSessionFromReq(req);
  setSessionCookieHeader(req, res, session.sid);

  let body = "";
  try {
    const buf = await collectBody(req);
    body = buf ? buf.toString("utf8") : "";
  } catch {}

  if (!abs) return res.status(200).json({ ok: true });
  if (!body.trim()) return res.status(200).json({ ok: true });

  // Accept simple "name=value" or full Set-Cookie-like line
  try {
    storeSetCookies(session.payload, [body.trim()], abs);
  } catch {}

  return res.status(200).json({ ok: true });
});

// Fallback for relative asset fetches when site tries to request /path on proxy origin
app.use(async (req, res, next) => {
  const p = req.path || "/";
  if (
    p.startsWith("/proxy") ||
    p.startsWith("/_wsproxy") ||
    p.startsWith("/_euph_ws") ||
    p.startsWith("/_euph_debug") ||
    p.startsWith("/__euph/") ||
    p.startsWith("/public") ||
    p.startsWith("/static")
  ) return next();

  const referer = (req.headers.referer || req.headers.referrer || "").toString();
  const m = referer.match(/[?&]url=([^&]+)/);
  if (!m) return next();

  let orig = "";
  try { orig = decodeURIComponent(m[1]); } catch { return next(); }
  if (!orig) return next();

  let baseOrigin = "";
  try { baseOrigin = new URL(orig).origin; } catch { return next(); }

  const attempted = new URL(req.originalUrl, baseOrigin).href;
  return handleProxy(req, res, attempted);
});

// SPA
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && (req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ============================== WS PROXY ==============================

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
          let t = target;
          if (/^https?:\/\//i.test(t)) t = t.replace(/^http:/i, "ws:").replace(/^https:/i, "wss:");
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

app.get("/_euph_debug/ping", (req, res) => res.json({ msg: "pong", ts: Date.now(), origin: getPublicOrigin(req) }));

app.get("/_euph_debug/cache", requireAdmin, (req, res) => {
  res.json({
    memCount: MEM_CACHE.size,
    memMaxBytes: MEM_CACHE_MAX_BYTES,
    memMaxItemBytes: MEM_CACHE_MAX_ITEM_BYTES,
    diskEnabled: ENABLE_DISK_CACHE,
  });
});

app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, p] of SESSIONS.entries()) {
    out[sid] = {
      last: new Date(p.last).toISOString(),
      ua: p.ua,
      ip: p.ip,
      cookieDomains: [...p.jar.keys()],
    };
  }
  res.json({ sessions: out, count: SESSIONS.size });
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

// ============================== SERVER START ==============================

const server = http.createServer(app);
setupWsProxy(server);
setupTelemetryWs(server);

server.listen(PORT, () => {
  console.log(`Euphoria v4 running on port ${PORT}`);
});

// ============================== PROCESS ==============================

process.on("unhandledRejection", (err) => console.error("unhandledRejection", err && err.stack ? err.stack : err));
process.on("uncaughtException", (err) => console.error("uncaughtException", err && err.stack ? err.stack : err));
process.on("warning", (w) => console.warn("warning", w && w.stack ? w.stack : w));

async function shutdown() {
  try { server.close(); } catch {}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
