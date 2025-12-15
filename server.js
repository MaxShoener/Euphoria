// server.js
// Euphoria v3.5 - production-grade hybrid proxy (streaming assets + HTML rewrite + session cookie jar + ws tunnel)
// Node 20+ (ESM). Designed for small cloud instances (Koyeb free) while maximizing site compatibility.
//
// Sections only (minimal comments).

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import rateLimit from "express-rate-limit";
import path from "path";
import fs from "fs";
import fsPromises from "fs/promises";
import http from "http";
import https from "https";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { EventEmitter } from "events";
import { JSDOM } from "jsdom";
import { WebSocketServer, WebSocket } from "ws";
import { LRUCache } from "lru-cache";
import { Readable } from "stream";

// ===============================
// Process / globals
// ===============================
EventEmitter.defaultMaxListeners = 500;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===============================
// Config
// ===============================
const PORT = parseInt(process.env.PORT || "3000", 10);
const TRUST_PROXY = (process.env.TRUST_PROXY || "1") === "1";
const LOG_LEVEL = (process.env.LOG_LEVEL || "info").toLowerCase(); // debug|info|warn|error

const DEPLOYMENT_ORIGIN_FALLBACK = process.env.DEPLOYMENT_ORIGIN || `http://localhost:${PORT}`;

const ENABLE_DISK_CACHE = (process.env.ENABLE_DISK_CACHE || "1") === "1";
const CACHE_DIR = path.join(__dirname, "cache");
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS || String(1000 * 60 * 8), 10); // 8m
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "45000", 10);

const MEM_ASSET_MAX_BYTES = parseInt(process.env.MEM_ASSET_MAX_BYTES || String(160 * 1024 * 1024), 10); // 160MB
const MEM_HTML_MAX_BYTES = parseInt(process.env.MEM_HTML_MAX_BYTES || String(64 * 1024 * 1024), 10); // 64MB
const MEM_ENTRY_MAX_BYTES = parseInt(process.env.MEM_ENTRY_MAX_BYTES || String(8 * 1024 * 1024), 10); // 8MB

const ASSET_CACHE_THRESHOLD_BYTES = parseInt(process.env.ASSET_CACHE_THRESHOLD_BYTES || String(8 * 1024 * 1024), 10); // 8MB cache
const HTML_CACHE_THRESHOLD_BYTES = parseInt(process.env.HTML_CACHE_THRESHOLD_BYTES || String(2 * 1024 * 1024), 10); // 2MB cache

const USER_AGENT_DEFAULT =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122 Safari/537.36";

const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || String(15 * 60 * 1000), 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || "900", 10);

const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
const SESSION_NAME = process.env.SESSION_NAME || "euphoria_sid";

const DISABLE_REWRITE = (process.env.DISABLE_REWRITE || "0") === "1";
const DISABLE_CLIENT_HOOK = (process.env.DISABLE_CLIENT_HOOK || "0") === "1";

const ALLOWLIST_HOSTS = (process.env.ALLOWLIST_HOSTS || "").trim(); // comma-separated, optional
const BLOCKLIST_HOSTS = (process.env.BLOCKLIST_HOSTS || "").trim(); // comma-separated, optional

const ALLOWLIST = new Set(ALLOWLIST_HOSTS ? ALLOWLIST_HOSTS.split(",").map(s => s.trim()).filter(Boolean) : []);
const BLOCKLIST = new Set(BLOCKLIST_HOSTS ? BLOCKLIST_HOSTS.split(",").map(s => s.trim()).filter(Boolean) : []);

// Optional per-host rules (runtime configurable via admin endpoint in this file)
const PER_HOST = new Map();

// ===============================
// Init disk cache dir
// ===============================
if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// ===============================
// App + middleware
// ===============================
const app = express();
app.set("trust proxy", TRUST_PROXY);
app.disable("x-powered-by");

app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "2mb" }));

app.use(
  rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max: RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Too many requests, slow down."
  })
);

app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ===============================
// Logging
// ===============================
function logDebug(...args) {
  if (LOG_LEVEL === "debug") console.log("[debug]", ...args);
}
function logInfo(...args) {
  if (LOG_LEVEL === "debug" || LOG_LEVEL === "info") console.log("[info]", ...args);
}
function logWarn(...args) {
  if (LOG_LEVEL === "debug" || LOG_LEVEL === "info" || LOG_LEVEL === "warn") console.warn("[warn]", ...args);
}
function logError(...args) {
  console.error("[error]", ...args);
}

// ===============================
// Helpers: origin inference (fixes localhost redirect bug)
// ===============================
function getPublicOrigin(req) {
  const xfProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const xfHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const host = xfHost || req.headers.host || "";
  const proto = xfProto || (req.socket && req.socket.encrypted ? "https" : "http");
  if (!host) return DEPLOYMENT_ORIGIN_FALLBACK;
  return `${proto}://${host}`;
}

// ===============================
// Helpers: url parsing
// ===============================
function isProbablyUrl(input) {
  if (!input) return false;
  const s = String(input).trim();
  if (/^https?:\/\//i.test(s)) return true;
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/:?#]|$)/i.test(s)) return true;
  return false;
}

function normalizeTarget(raw) {
  let s = String(raw || "").trim();
  if (!s) return null;

  // If it isn't a URL-ish string, treat as Google search
  if (!isProbablyUrl(s) && (s.includes(" ") || s.length > 1)) {
    return `https://www.google.com/search?q=${encodeURIComponent(s)}`;
  }

  if (!/^https?:\/\//i.test(s)) s = `https://${s}`;
  try {
    return new URL(s).href;
  } catch {
    return `https://www.google.com/search?q=${encodeURIComponent(s)}`;
  }
}

function makeProxyUrl(publicOrigin, absUrl) {
  // Use RELATIVE by default to avoid origin leaks; but include absolute if needed
  // Here we use absolute URL in querystring, but proxy path is relative.
  return `${publicOrigin}/proxy?url=${encodeURIComponent(absUrl)}`;
}

function makeProxyUrlRelative(absUrl) {
  return `/proxy?url=${encodeURIComponent(absUrl)}`;
}

function safeB64u(s) {
  return Buffer.from(String(s)).toString("base64url");
}

function now() {
  return Date.now();
}

// ===============================
// Headers management
// ===============================
const DROP_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy",
  "strict-transport-security"
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

function shouldDropHeader(k) {
  const lk = String(k || "").toLowerCase();
  if (DROP_HEADERS.has(lk)) return true;
  if (HOP_BY_HOP.has(lk)) return true;
  if (lk === "content-length") return true;
  if (lk === "content-encoding") return true; // because fetch usually decompresses
  return false;
}

function copyHeaders(res, headers) {
  try {
    headers.forEach((v, k) => {
      if (shouldDropHeader(k)) return;
      try { res.setHeader(k, v); } catch {}
    });
  } catch {}
}

// ===============================
// Agents
// ===============================
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

// ===============================
// Timeout fetch wrapper (global fetch, Node 20)
// ===============================
async function upstreamFetch(url, opts = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort("timeout"), FETCH_TIMEOUT_MS);
  try {
    const u = new URL(url);
    const isHttps = u.protocol === "https:";
    const agent = isHttps ? httpsAgent : httpAgent;
    const res = await fetch(url, { ...opts, signal: controller.signal, agent });
    return res;
  } finally {
    clearTimeout(t);
  }
}

// ===============================
// Memory caches (byte-sized LRU)
// ===============================
function sizeof(val) {
  try {
    if (val == null) return 1;
    if (Buffer.isBuffer(val)) return val.length;
    if (typeof val === "string") return Buffer.byteLength(val, "utf8");
    return Buffer.byteLength(JSON.stringify(val), "utf8");
  } catch {
    return 1024;
  }
}

const MEM_ASSET = new LRUCache({
  maxSize: MEM_ASSET_MAX_BYTES,
  maxEntrySize: MEM_ENTRY_MAX_BYTES,
  ttl: CACHE_TTL_MS,
  sizeCalculation: (v) => sizeof(v)
});

const MEM_HTML = new LRUCache({
  maxSize: MEM_HTML_MAX_BYTES,
  maxEntrySize: MEM_ENTRY_MAX_BYTES,
  ttl: CACHE_TTL_MS,
  sizeCalculation: (v) => sizeof(v)
});

// ===============================
// Disk cache
// ===============================
function diskPathFor(key) {
  return path.join(CACHE_DIR, safeB64u(key));
}

async function diskGet(key) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const p = diskPathFor(key);
    if (!fs.existsSync(p)) return null;
    const raw = await fsPromises.readFile(p, "utf8");
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    if ((now() - obj.t) > CACHE_TTL_MS) {
      try { await fsPromises.unlink(p); } catch {}
      return null;
    }
    return obj.v;
  } catch {
    return null;
  }
}

async function diskSet(key, val) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const p = diskPathFor(key);
    await fsPromises.writeFile(p, JSON.stringify({ t: now(), v: val }), "utf8");
  } catch {}
}

async function diskClearAll() {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const files = await fsPromises.readdir(CACHE_DIR);
    for (const f of files) {
      try { await fsPromises.unlink(path.join(CACHE_DIR, f)); } catch {}
    }
  } catch {}
}

// ===============================
// Session cookie jar
// ===============================
const SESSIONS = new Map();

function makeSid() {
  return crypto.randomBytes(18).toString("base64url") + "-" + Date.now().toString(36);
}

function getOrCreateSession(req) {
  const cookies = parseCookieHeader(String(req.headers.cookie || ""));
  const sid = cookies[SESSION_NAME] || String(req.headers["x-euphoria-session"] || "");
  if (!sid || !SESSIONS.has(sid)) {
    const ns = {
      sid: makeSid(),
      createdAt: now(),
      lastAt: now(),
      ip: req.ip || req.socket?.remoteAddress || null,
      ua: USER_AGENT_DEFAULT,
      jar: createCookieJar()
    };
    SESSIONS.set(ns.sid, ns);
    return ns;
  }
  const s = SESSIONS.get(sid);
  s.lastAt = now();
  if (!s.ip) s.ip = req.ip || req.socket?.remoteAddress || null;
  return s;
}

function setSessionCookie(res, sid) {
  const parts = [
    `${SESSION_NAME}=${sid}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${60 * 60 * 24 * 2}`
  ];
  const xfProto = String(res.req?.headers?.["x-forwarded-proto"] || "").split(",")[0].trim();
  const secure = xfProto === "https";
  if (secure) parts.push("Secure");
  const cookieStr = parts.join("; ");
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}

function parseCookieHeader(header) {
  const out = {};
  const s = String(header || "");
  if (!s) return out;
  const parts = s.split(";");
  for (const p of parts) {
    const idx = p.indexOf("=");
    if (idx === -1) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function createCookieJar() {
  // Store by domain -> path -> name
  return {
    // domainKey: Map(pathKey -> Map(name -> {value, attrs}))
    store: new Map()
  };
}

function jarSetFromSetCookie(jar, setCookieStr, reqUrl) {
  try {
    const u = new URL(reqUrl);
    const parts = String(setCookieStr || "").split(";").map(x => x.trim()).filter(Boolean);
    if (!parts.length) return;
    const [nv, ...attrs] = parts;
    const eq = nv.indexOf("=");
    if (eq === -1) return;
    const name = nv.slice(0, eq).trim();
    const value = nv.slice(eq + 1).trim();
    if (!name) return;

    const meta = {};
    for (const a of attrs) {
      const i = a.indexOf("=");
      if (i === -1) meta[a.toLowerCase()] = true;
      else meta[a.slice(0, i).toLowerCase()] = a.slice(i + 1);
    }

    const domain = (meta.domain ? String(meta.domain).replace(/^\./, "") : u.hostname).toLowerCase();
    const pathV = (meta.path ? String(meta.path) : "/") || "/";
    const domainKey = domain;

    if (!jar.store.has(domainKey)) jar.store.set(domainKey, new Map());
    const paths = jar.store.get(domainKey);
    if (!paths.has(pathV)) paths.set(pathV, new Map());
    const names = paths.get(pathV);

    if (meta["max-age"] === "0" || String(meta.expires || "").toLowerCase() === "thu, 01 jan 1970 00:00:00 gmt") {
      names.delete(name);
      return;
    }

    names.set(name, { value, meta, setAt: now() });
  } catch {}
}

function domainMatches(cookieDomain, hostname) {
  const cd = String(cookieDomain || "").toLowerCase();
  const h = String(hostname || "").toLowerCase();
  if (!cd || !h) return false;
  if (h === cd) return true;
  return h.endsWith("." + cd);
}

function pathMatches(cookiePath, reqPath) {
  const cp = String(cookiePath || "/");
  const rp = String(reqPath || "/");
  if (rp === cp) return true;
  if (rp.startsWith(cp)) return true;
  return false;
}

function jarBuildCookieHeader(jar, reqUrl) {
  try {
    const u = new URL(reqUrl);
    const host = u.hostname.toLowerCase();
    const reqPath = u.pathname || "/";

    const pairs = [];

    for (const [domainKey, paths] of jar.store.entries()) {
      if (!domainMatches(domainKey, host)) continue;
      for (const [pathKey, names] of paths.entries()) {
        if (!pathMatches(pathKey, reqPath)) continue;
        for (const [name, obj] of names.entries()) {
          if (!name) continue;
          if (obj && typeof obj.value === "string") {
            pairs.push(`${name}=${obj.value}`);
          }
        }
      }
    }
    return pairs.join("; ");
  } catch {
    return "";
  }
}

// ===============================
// Session cleanup
// ===============================
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 8); // 8h idle
  for (const [sid, s] of SESSIONS.entries()) {
    if (!s || s.lastAt < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

// ===============================
// HTML sanitization + rewriting
// ===============================
function sanitizeHtml(html) {
  let out = String(html || "");
  out = out.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
  out = out.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
  out = out.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  return out;
}

function isAlreadyProxied(href) {
  if (!href) return false;
  const s = String(href);
  if (s.includes("/proxy?url=")) return true;
  if (s.startsWith("/proxy/")) return true;
  return false;
}

function absUrlMaybe(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

function proxyizeHref(href, baseUrl) {
  if (!href) return href;
  const h = String(href);
  if (/^(javascript:|mailto:|tel:|#)/i.test(h)) return h;
  if (isAlreadyProxied(h)) return h;
  const abs = absUrlMaybe(h, baseUrl) || h;
  return makeProxyUrlRelative(abs);
}

function rewriteCssUrls(cssText, baseUrl) {
  let t = String(cssText || "");
  // url(...)
  t = t.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
    if (!u) return m;
    if (/^data:/i.test(u)) return m;
    if (isAlreadyProxied(u)) return m;
    const abs = absUrlMaybe(u, baseUrl) || u;
    return `url("${makeProxyUrlRelative(abs)}")`;
  });
  return t;
}

function jsdomRewrite(html, baseUrl) {
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

    const aTags = Array.from(document.querySelectorAll("a[href]"));
    for (const a of aTags) {
      try {
        const href = a.getAttribute("href");
        if (!href) continue;
        a.setAttribute("href", proxyizeHref(href, baseUrl));
        a.removeAttribute("target");
        a.removeAttribute("rel");
      } catch {}
    }

    const forms = Array.from(document.querySelectorAll("form[action]"));
    for (const f of forms) {
      try {
        const act = f.getAttribute("action");
        if (!act) continue;
        f.setAttribute("action", proxyizeHref(act, baseUrl));
      } catch {}
    }

    const assets = ["img", "script", "link", "iframe", "source", "video", "audio", "track"];
    for (const tag of assets) {
      const nodes = Array.from(document.getElementsByTagName(tag));
      for (const el of nodes) {
        try {
          const attr = el.getAttribute("src") != null ? "src" : (el.getAttribute("href") != null ? "href" : null);
          if (!attr) continue;
          const v = el.getAttribute(attr);
          if (!v) continue;
          if (/^data:/i.test(v)) continue;
          el.setAttribute(attr, proxyizeHref(v, baseUrl));
        } catch {}
      }
    }

    const srcsets = Array.from(document.querySelectorAll("[srcset]"));
    for (const el of srcsets) {
      try {
        const ss = el.getAttribute("srcset") || "";
        const parts = ss.split(",").map(p => {
          const trimmed = p.trim();
          if (!trimmed) return trimmed;
          const seg = trimmed.split(/\s+/, 2);
          const u = seg[0];
          const rest = seg[1] ? " " + seg[1] : "";
          if (!u) return trimmed;
          if (/^data:/i.test(u)) return trimmed;
          const abs = absUrlMaybe(u, baseUrl) || u;
          return makeProxyUrlRelative(abs) + rest;
        });
        el.setAttribute("srcset", parts.join(", "));
      } catch {}
    }

    const styles = Array.from(document.querySelectorAll("style"));
    for (const st of styles) {
      try {
        st.textContent = rewriteCssUrls(st.textContent || "", baseUrl);
      } catch {}
    }

    const inlineStyleEls = Array.from(document.querySelectorAll("[style]"));
    for (const el of inlineStyleEls) {
      try {
        const s = el.getAttribute("style") || "";
        el.setAttribute("style", rewriteCssUrls(s, baseUrl));
      } catch {}
    }

    const metas = Array.from(document.querySelectorAll('meta[http-equiv="refresh"], meta[http-equiv="Refresh"]'));
    for (const m of metas) {
      try {
        const c = m.getAttribute("content") || "";
        const parts = c.split(";");
        if (parts.length < 2) continue;
        const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
        if (!urlPart) continue;
        const dest = String(urlPart[1] || "").replace(/['"]/g, "").trim();
        if (!dest) continue;
        const abs = absUrlMaybe(dest, baseUrl) || dest;
        m.setAttribute("content", parts[0] + ";url=" + makeProxyUrlRelative(abs));
      } catch {}
    }

    const noscripts = Array.from(document.getElementsByTagName("noscript"));
    for (const n of noscripts) {
      try { n.parentNode && n.parentNode.removeChild(n); } catch {}
    }

    return dom.serialize();
  } catch (e) {
    logWarn("jsdomRewrite failed:", e?.message || e);
    return html;
  }
}

function quickStringRewrite(html, baseUrl) {
  // fallback for very large pages or JSDOM failures.
  let out = String(html || "");
  const base = baseUrl;

  // href="..."
  out = out.replace(/\shref=(["'])(.*?)\1/gi, (m, q, u) => {
    if (!u) return m;
    if (/^(javascript:|mailto:|tel:|#)/i.test(u)) return m;
    if (isAlreadyProxied(u)) return m;
    const abs = absUrlMaybe(u, base) || u;
    return ` href=${q}${makeProxyUrlRelative(abs)}${q}`;
  });

  // src="..."
  out = out.replace(/\ssrc=(["'])(.*?)\1/gi, (m, q, u) => {
    if (!u) return m;
    if (/^data:/i.test(u)) return m;
    if (isAlreadyProxied(u)) return m;
    const abs = absUrlMaybe(u, base) || u;
    return ` src=${q}${makeProxyUrlRelative(abs)}${q}`;
  });

  // action="..."
  out = out.replace(/\saction=(["'])(.*?)\1/gi, (m, q, u) => {
    if (!u) return m;
    if (isAlreadyProxied(u)) return m;
    const abs = absUrlMaybe(u, base) || u;
    return ` action=${q}${makeProxyUrlRelative(abs)}${q}`;
  });

  // url(...) inside style blocks (best-effort)
  out = out.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
    if (!u) return m;
    if (/^data:/i.test(u)) return m;
    if (isAlreadyProxied(u)) return m;
    const abs = absUrlMaybe(u, base) || u;
    return `url("${makeProxyUrlRelative(abs)}")`;
  });

  return out;
}

function makeClientHookSnippet(publicOrigin) {
  // Hard "stay on site": intercept clicks, forms, fetch, xhr, navigation, location changes.
  const marker = "/*__EUPHORIA_CLIENT_HOOK__*/";
  return `
<script>${marker}
(() => {
  const PROXY = "${publicOrigin}";
  const PROXY_PATH = "/proxy?url=";

  function abs(u) {
    try { return new URL(u, document.baseURI).href; } catch { return u; }
  }
  function prox(u) {
    try {
      if (!u) return u;
      if (typeof u !== "string") return u;
      if (u.startsWith(PROXY_PATH) || u.includes("/proxy?url=")) return u;
      if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u)) return u;
      return PROXY_PATH + encodeURIComponent(abs(u));
    } catch { return u; }
  }
  function rewriteElAttr(el, attr) {
    try {
      const v = el.getAttribute(attr);
      if (!v) return;
      el.setAttribute(attr, prox(v));
    } catch {}
  }

  // clicks
  document.addEventListener("click", (ev) => {
    try {
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
      if (!a) return;
      const href = a.getAttribute("href");
      if (!href) return;
      if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      a.setAttribute("href", prox(href));
      a.removeAttribute("target");
    } catch {}
  }, true);

  // forms
  document.addEventListener("submit", (ev) => {
    try {
      const f = ev.target;
      if (!f || !f.action) return;
      f.action = prox(f.action);
    } catch {}
  }, true);

  // Mutation observer for dynamic DOM updates
  const mo = new MutationObserver((muts) => {
    for (const m of muts) {
      for (const n of (m.addedNodes || [])) {
        try {
          if (!n || !n.querySelectorAll) continue;
          n.querySelectorAll("a[href]").forEach(a => rewriteElAttr(a, "href"));
          n.querySelectorAll("img[src],script[src],iframe[src],source[src],video[src],audio[src],track[src]").forEach(el => rewriteElAttr(el, "src"));
          n.querySelectorAll("link[href]").forEach(el => rewriteElAttr(el, "href"));
          n.querySelectorAll("form[action]").forEach(el => rewriteElAttr(el, "action"));
        } catch {}
      }
    }
  });
  try { mo.observe(document.documentElement, { childList: true, subtree: true }); } catch {}

  // fetch/XHR
  const origFetch = window.fetch;
  window.fetch = function(resource, init) {
    try {
      if (typeof resource === "string") resource = prox(resource);
      else if (resource && resource.url) resource = new Request(prox(resource.url), resource);
    } catch {}
    return origFetch(resource, init);
  };

  const OrigXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    const xhr = new OrigXHR();
    const open = xhr.open;
    xhr.open = function(method, url, ...rest) {
      try { url = prox(url); } catch {}
      return open.call(this, method, url, ...rest);
    };
    return xhr;
  };

  // history + location
  const origPush = history.pushState;
  history.pushState = function(state, title, url) {
    try { if (typeof url === "string") url = prox(url); } catch {}
    return origPush.call(this, state, title, url);
  };
  const origReplace = history.replaceState;
  history.replaceState = function(state, title, url) {
    try { if (typeof url === "string") url = prox(url); } catch {}
    return origReplace.call(this, state, title, url);
  };

})();
</script>`;
}

// ===============================
// Policy: allow/block hosts
// ===============================
function isHostAllowed(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (!h) return false;
  if (BLOCKLIST.size && (BLOCKLIST.has(h) || [...BLOCKLIST].some(d => h === d || h.endsWith("." + d)))) return false;
  if (ALLOWLIST.size) return (ALLOWLIST.has(h) || [...ALLOWLIST].some(d => h === d || h.endsWith("." + d)));
  return true;
}

// ===============================
// Response helpers
// ===============================
function sendText(res, status, text, contentType = "text/plain; charset=utf-8") {
  res.status(status);
  res.setHeader("Content-Type", contentType);
  res.send(text);
}

function b2b(stream) {
  // Convert web stream to Node stream if needed.
  try {
    if (!stream) return null;
    if (typeof stream.getReader === "function") return Readable.fromWeb(stream);
    return stream;
  } catch {
    return null;
  }
}

// ===============================
// WebSocket tunnel endpoint
// ===============================
function setupWsTunnel(server) {
  const wss = new WebSocketServer({ noServer: true, clientTracking: false });

  server.on("upgrade", (req, socket, head) => {
    try {
      const u = new URL(req.url, `http://${req.headers.host}`);
      if (u.pathname !== "/_wsproxy") return;
      const target = u.searchParams.get("url");
      if (!target) {
        socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        const outbound = new WebSocket(target, {
          headers: {
            "User-Agent": USER_AGENT_DEFAULT,
            "Origin": req.headers.origin || "",
            "Sec-WebSocket-Protocol": req.headers["sec-websocket-protocol"] || ""
          }
        });

        const safeClose = () => {
          try { ws.close(); } catch {}
          try { outbound.close(); } catch {}
        };

        outbound.on("open", () => {
          ws.on("message", (msg) => { try { outbound.send(msg); } catch {} });
          outbound.on("message", (msg) => { try { ws.send(msg); } catch {} });
          ws.on("close", safeClose);
          outbound.on("close", safeClose);
        });

        outbound.on("error", safeClose);
        ws.on("error", safeClose);
      });
    } catch {
      try { socket.destroy(); } catch {}
    }
  });

  return wss;
}

// ===============================
// Admin guard
// ===============================
function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

// ===============================
// Basic endpoints
// ===============================
app.get("/_euph_debug/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, s] of SESSIONS.entries()) {
    out[sid] = {
      createdAt: new Date(s.createdAt).toISOString(),
      lastAt: new Date(s.lastAt).toISOString(),
      ip: s.ip,
      ua: s.ua,
      domains: [...(s.jar?.store?.keys?.() || [])]
    };
  }
  res.json({ count: SESSIONS.size, sessions: out });
});

app.get("/_euph_debug/cache", requireAdmin, (req, res) => {
  res.json({
    mem: {
      html: { size: MEM_HTML.size, calculatedSize: MEM_HTML.calculatedSize },
      asset: { size: MEM_ASSET.size, calculatedSize: MEM_ASSET.calculatedSize }
    },
    disk: { enabled: ENABLE_DISK_CACHE }
  });
});

app.post("/_euph_debug/clear_cache", requireAdmin, async (req, res) => {
  MEM_HTML.clear();
  MEM_ASSET.clear();
  await diskClearAll();
  res.json({ ok: true });
});

app.post("/_euph_debug/host_rules", requireAdmin, (req, res) => {
  const { host, rules } = req.body || {};
  if (!host || typeof host !== "string") return res.status(400).json({ error: "missing host" });
  if (rules == null) { PER_HOST.delete(host.toLowerCase()); return res.json({ ok: true, deleted: true }); }
  PER_HOST.set(host.toLowerCase(), rules);
  return res.json({ ok: true });
});

// ===============================
// Proxy entrypoints
// ===============================

// Home SPA fallback to public/index.html if present
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// Support /proxy/:host/* style
app.get("/proxy/:host/*", (req, res, next) => {
  const host = req.params.host;
  const rest = req.params[0] || "";
  let abs = `https://${host}/${rest}`;
  if (req.originalUrl.includes("?")) {
    const q = req.originalUrl.split("?").slice(1).join("?");
    if (q) abs += "?" + q;
  }
  req.query.url = abs;
  return proxyHandler(req, res).catch(next);
});

// Main /proxy
app.all("/proxy", (req, res, next) => {
  proxyHandler(req, res).catch(next);
});

// Optional shorthand /go?q=...
app.get("/go", (req, res) => {
  const publicOrigin = getPublicOrigin(req);
  const target = normalizeTarget(req.query.q || "");
  if (!target) return sendText(res, 400, "Missing q");
  res.redirect(302, makeProxyUrlRelative(target));
});

// ===============================
// Core proxy handler
// ===============================
async function proxyHandler(req, res) {
  const publicOrigin = getPublicOrigin(req);

  // url input
  let raw = req.query.url;
  if (!raw && req.path && req.path.startsWith("/proxy/")) {
    try {
      raw = decodeURIComponent(req.path.replace(/^\/proxy\//, ""));
    } catch {}
  }

  const target = normalizeTarget(raw || "");
  if (!target) {
    return sendText(res, 400, "Missing url (use /proxy?url=https://example.com, /proxy/:host/*, or /go?q=search)");
  }

  const u = new URL(target);
  if (!isHostAllowed(u.hostname)) return sendText(res, 403, "Host blocked by policy");

  // session
  const session = getOrCreateSession(req);
  setSessionCookie(res, session.sid);

  // cache keys
  const method = String(req.method || "GET").toUpperCase();
  const isGet = method === "GET" || method === "HEAD";
  const accept = String(req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.query.force_html === "1";

  const cacheKey = `${method}:${target}:${wantHtml ? "html" : "asset"}`;

  // per-host rules
  const hostRules = PER_HOST.get(u.hostname.toLowerCase()) || {};
  const cacheDisabled = hostRules?.cache === false;
  const rewriteDisabled = (hostRules?.rewrite === false) || DISABLE_REWRITE;

  // fast cache for GET/HEAD only
  if (isGet && !cacheDisabled) {
    if (wantHtml) {
      const mem = MEM_HTML.get(cacheKey);
      if (mem) {
        res.status(200);
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.send(mem);
      }
      const disk = await diskGet(cacheKey);
      if (disk && typeof disk === "string") {
        res.status(200);
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        MEM_HTML.set(cacheKey, disk);
        return res.send(disk);
      }
    } else {
      const mem = MEM_ASSET.get(cacheKey);
      if (mem && mem.body && mem.headers) {
        res.status(mem.status || 200);
        for (const [k, v] of Object.entries(mem.headers)) {
          try { res.setHeader(k, v); } catch {}
        }
        return res.send(Buffer.from(mem.body, "base64"));
      }
      const disk = await diskGet(cacheKey);
      if (disk && disk.body && disk.headers) {
        res.status(disk.status || 200);
        for (const [k, v] of Object.entries(disk.headers)) {
          try { res.setHeader(k, v); } catch {}
        }
        MEM_ASSET.set(cacheKey, disk);
        return res.send(Buffer.from(disk.body, "base64"));
      }
    }
  }

  // build upstream headers (compat: images, video, fetch, same-origin-ish)
  const upstreamHeaders = buildUpstreamHeaders(req, session, target);

  // body passthrough for non-GET
  let body = undefined;
  if (method !== "GET" && method !== "HEAD") {
    body = await readIncomingBody(req);
  }

  let upstreamRes;
  try {
    upstreamRes = await upstreamFetch(target, {
      method,
      headers: upstreamHeaders,
      redirect: "manual",
      body
    });
  } catch (e) {
    logWarn("fetch failed", e?.message || e);
    return sendText(res, 502, "Euphoria: failed to fetch target: " + String(e?.message || e));
  }

  // store set-cookie into session jar
  const setCookieList = getSetCookieHeaders(upstreamRes.headers);
  if (setCookieList.length) {
    for (const sc of setCookieList) jarSetFromSetCookie(session.jar, sc, target);
  }

  // handle redirects (stay on site!)
  const status = upstreamRes.status || 200;
  if ([301, 302, 303, 307, 308].includes(status)) {
    const loc = upstreamRes.headers.get("location");
    if (loc) {
      let abs;
      try { abs = new URL(loc, target).href; } catch { abs = loc; }
      // rewrite to relative proxy
      const prox = makeProxyUrlRelative(abs);
      res.status(status);
      res.setHeader("Location", prox);
      // keep body minimal
      return res.send(`Redirecting to ${prox}`);
    }
  }

  // content type routing
  const contentType = String(upstreamRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html") || wantHtml;

  if (!isHtml) {
    return await pipeAsset(req, res, upstreamRes, cacheKey, isGet && !cacheDisabled);
  } else {
    return await pipeHtml(req, res, upstreamRes, target, publicOrigin, cacheKey, isGet && !cacheDisabled, rewriteDisabled);
  }
}

// ===============================
// Upstream headers builder
// ===============================
function buildUpstreamHeaders(req, session, targetUrl) {
  const t = new URL(targetUrl);
  const headers = {};

  // forward many headers for compatibility (but not hop-by-hop)
  const pass = [
    "accept",
    "accept-language",
    "accept-encoding",
    "cache-control",
    "pragma",
    "range",
    "if-none-match",
    "if-modified-since",
    "dnt",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "upgrade-insecure-requests",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform"
  ];
  for (const k of pass) {
    const v = req.headers[k];
    if (v != null) headers[k] = v;
  }

  // user agent
  headers["user-agent"] = session.ua || req.headers["user-agent"] || USER_AGENT_DEFAULT;

  // origin & referer (best effort)
  try {
    headers["origin"] = t.origin;
  } catch {}
  if (req.headers.referer) headers["referer"] = req.headers.referer;

  // cookies
  const cookieHeader = jarBuildCookieHeader(session.jar, targetUrl);
  if (cookieHeader) headers["cookie"] = cookieHeader;

  // avoid br encoding issues: fetch in Node generally handles gzip/deflate; br depends on build.
  // Let the upstream pick based on accept-encoding; if absent, prefer gzip.
  if (!headers["accept-encoding"]) headers["accept-encoding"] = "gzip, deflate";

  // realistic accept
  if (!headers["accept"]) headers["accept"] = "*/*";

  return headers;
}

// ===============================
// Incoming request body reader
// ===============================
async function readIncomingBody(req) {
  return await new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (c) => {
      chunks.push(c);
      total += c.length;
      if (total > 10 * 1024 * 1024) {
        try { req.destroy(); } catch {}
        reject(new Error("body too large"));
      }
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ===============================
// Set-Cookie extraction (undici/WHATWG headers)
// ===============================
function getSetCookieHeaders(headers) {
  const list = [];
  try {
    // Node fetch doesn't always expose raw(), but modern undici supports getSetCookie() in some contexts.
    if (typeof headers.getSetCookie === "function") {
      const arr = headers.getSetCookie();
      if (Array.isArray(arr)) return arr;
    }
  } catch {}
  // fallback: cannot reliably get multiple Set-Cookie via standard Headers. Try common patterns:
  try {
    const sc = headers.get("set-cookie");
    if (sc) list.push(sc);
  } catch {}
  return list;
}

// ===============================
// Asset piping (binary-safe, range-friendly)
// ===============================
async function pipeAsset(req, res, upstreamRes, cacheKey, allowCache) {
  const status = upstreamRes.status || 200;

  // copy headers (drop security headers)
  copyHeaders(res, upstreamRes.headers);

  // ensure content-type
  const ct = upstreamRes.headers.get("content-type");
  if (ct) res.setHeader("Content-Type", ct);

  // handle CORS-ish for embedded resources
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");

  res.status(status);

  // Try streaming
  const bodyStream = b2b(upstreamRes.body);

  // if caching, we buffer up to threshold (still stream to client)
  const doBuffer = allowCache && (status === 200 || status === 206);
  const chunks = [];
  let buffered = 0;
  const max = ASSET_CACHE_THRESHOLD_BYTES;

  if (!bodyStream) {
    const ab = await upstreamRes.arrayBuffer().catch(() => null);
    if (!ab) return res.end();
    const buf = Buffer.from(ab);
    if (doBuffer && buf.length <= max) {
      const headersObj = {};
      upstreamRes.headers.forEach((v, k) => { if (!shouldDropHeader(k)) headersObj[k] = v; });
      const payload = { status, headers: headersObj, body: buf.toString("base64") };
      MEM_ASSET.set(cacheKey, payload);
      diskSet(cacheKey, payload).catch(() => {});
    }
    return res.send(buf);
  }

  return await new Promise((resolve) => {
    bodyStream.on("data", (chunk) => {
      try { res.write(chunk); } catch {}
      if (doBuffer && buffered <= max) {
        buffered += chunk.length;
        if (buffered <= max) chunks.push(Buffer.from(chunk));
      }
    });
    bodyStream.on("end", () => {
      try { res.end(); } catch {}
      if (doBuffer && buffered > 0 && buffered <= max) {
        const buf = Buffer.concat(chunks);
        const headersObj = {};
        upstreamRes.headers.forEach((v, k) => { if (!shouldDropHeader(k)) headersObj[k] = v; });
        const payload = { status, headers: headersObj, body: buf.toString("base64") };
        try { MEM_ASSET.set(cacheKey, payload); } catch {}
        diskSet(cacheKey, payload).catch(() => {});
      }
      resolve();
    });
    bodyStream.on("error", () => {
      try { res.end(); } catch {}
      resolve();
    });
  });
}

// ===============================
// HTML piping + rewrite + client hook
// ===============================
async function pipeHtml(req, res, upstreamRes, targetUrl, publicOrigin, cacheKey, allowCache, rewriteDisabled) {
  const status = upstreamRes.status || 200;

  // Read text
  let html = "";
  try {
    html = await upstreamRes.text();
  } catch (e) {
    logWarn("html read failed:", e?.message || e);
    res.status(502);
    return res.send("Euphoria: failed to read HTML");
  }

  html = sanitizeHtml(html);

  // rewrite (JSDOM + fallback)
  let out = html;
  if (!rewriteDisabled) {
    const baseUrl = upstreamRes.url || targetUrl;
    if (Buffer.byteLength(out, "utf8") > 900_000) out = quickStringRewrite(out, baseUrl);
    else out = jsdomRewrite(out, baseUrl);
  }

  // inject client hook (keeps redirects inside proxy)
  if (!DISABLE_CLIENT_HOOK && !out.includes("/*__EUPHORIA_CLIENT_HOOK__*/")) {
    const snippet = makeClientHookSnippet(publicOrigin);
    out = out.replace(/<\/body>/i, snippet + "</body>");
  }

  // response headers
  copyHeaders(res, upstreamRes.headers);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(status);

  // cache (only if small enough)
  const bytes = Buffer.byteLength(out, "utf8");
  if (allowCache && bytes <= HTML_CACHE_THRESHOLD_BYTES && (status === 200)) {
    try { MEM_HTML.set(cacheKey, out); } catch {}
    diskSet(cacheKey, out).catch(() => {});
  }

  return res.send(out);
}

// ===============================
// Startup server + ws
// ===============================
const server = http.createServer(app);
setupWsTunnel(server);

server.listen(PORT, () => {
  logInfo(`Euphoria v3.5 listening on ${PORT}`);
});

// ===============================
// Error handling
// ===============================
process.on("unhandledRejection", (err) => logError("unhandledRejection", err?.stack || err));
process.on("uncaughtException", (err) => logError("uncaughtException", err?.stack || err));

async function shutdown() {
  try { server.close(); } catch {}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// ===============================
// Padding utilities (v3.5)
// Many sites require extra quirks; these utilities support future toggles and extensions.
// ===============================

function noop() {}

function clamp(n, a, b) {
  const x = Number(n);
  if (Number.isNaN(x)) return a;
  return Math.max(a, Math.min(b, x));
}

function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj && obj[k] != null) out[k] = obj[k];
  return out;
}

function shallowClone(obj) {
  try { return { ...(obj || {}) }; } catch { return {}; }
}

function parseJsonSafe(s, fallback = null) {
  try { return JSON.parse(s); } catch { return fallback; }
}

function toLowerKeys(obj) {
  const out = {};
  try {
    for (const [k, v] of Object.entries(obj || {})) out[String(k).toLowerCase()] = v;
  } catch {}
  return out;
}

function hashShort(s) {
  try {
    return crypto.createHash("sha1").update(String(s)).digest("base64url").slice(0, 12);
  } catch {
    return safeB64u(String(s)).slice(0, 12);
  }
}

function withTimeout(p, ms, name = "timeout") {
  let t;
  const timeout = new Promise((_, rej) => {
    t = setTimeout(() => rej(new Error(name)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

function isTextLike(contentType) {
  const ct = String(contentType || "").toLowerCase();
  return ct.includes("text/") || ct.includes("json") || ct.includes("xml") || ct.includes("javascript");
}

function looksBinary(contentType) {
  const ct = String(contentType || "").toLowerCase();
  if (!ct) return true;
  return !(isTextLike(ct));
}

function normalizeHeaderValue(v) {
  if (Array.isArray(v)) return v.join(", ");
  return String(v);
}

function parseQueryString(qs) {
  const out = {};
  const s = String(qs || "").replace(/^\?/, "");
  if (!s) return out;
  for (const p of s.split("&")) {
    if (!p) continue;
    const [k, v] = p.split("=");
    if (!k) continue;
    try { out[decodeURIComponent(k)] = decodeURIComponent(v || ""); } catch { out[k] = v || ""; }
  }
  return out;
}

function stringifyQuery(obj) {
  const parts = [];
  for (const [k, v] of Object.entries(obj || {})) {
    parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(String(v)));
  }
  return parts.join("&");
}

function ensureLeadingSlash(p) {
  const s = String(p || "");
  if (!s.startsWith("/")) return "/" + s;
  return s;
}

function trimSlashes(s) {
  return String(s || "").replace(/^\/+|\/+$/g, "");
}

function safeUrlJoin(a, b) {
  try {
    return new URL(b, a).href;
  } catch {
    return String(a || "") + "/" + String(b || "");
  }
}

function parseHostPort(h) {
  const s = String(h || "");
  const idx = s.lastIndexOf(":");
  if (idx === -1) return { host: s, port: "" };
  const host = s.slice(0, idx);
  const port = s.slice(idx + 1);
  if (!/^\d+$/.test(port)) return { host: s, port: "" };
  return { host, port };
}

function redactUrl(u) {
  try {
    const url = new URL(u);
    url.search = "";
    return url.href;
  } catch {
    return String(u || "");
  }
}

function median(arr) {
  const a = (arr || []).slice().map(Number).filter(x => !Number.isNaN(x)).sort((x, y) => x - y);
  if (!a.length) return 0;
  const mid = Math.floor(a.length / 2);
  return a.length % 2 ? a[mid] : (a[mid - 1] + a[mid]) / 2;
}

function movingAverage(arr, w = 10) {
  const out = [];
  const a = (arr || []).slice().map(Number).filter(x => !Number.isNaN(x));
  for (let i = 0; i < a.length; i++) {
    const start = Math.max(0, i - w + 1);
    const slice = a.slice(start, i + 1);
    const sum = slice.reduce((p, c) => p + c, 0);
    out.push(sum / slice.length);
  }
  return out;
}

function urlLooksLikeAsset(u) {
  const s = String(u || "").toLowerCase();
  return /\.(png|jpe?g|webp|gif|svg|ico|css|js|mjs|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|wasm)(\?|#|$)/i.test(s);
}

function shouldAttemptHtmlRewrite(req, contentType) {
  const accept = String(req.headers.accept || "").toLowerCase();
  const ct = String(contentType || "").toLowerCase();
  if (ct.includes("text/html")) return true;
  if (accept.includes("text/html")) return true;
  if (req.query.force_html === "1") return true;
  return false;
}

function safeHeaderSet(res, k, v) {
  try { res.setHeader(k, v); } catch {}
}

function normalizeStatus(s) {
  const n = parseInt(String(s || ""), 10);
  if (!n || n < 100 || n > 999) return 200;
  return n;
}

function isRedirectStatus(s) {
  return [301, 302, 303, 307, 308].includes(normalizeStatus(s));
}

function normalizeMethod(m) {
  return String(m || "GET").toUpperCase();
}

function isSafeMethod(m) {
  const mm = normalizeMethod(m);
  return mm === "GET" || mm === "HEAD" || mm === "OPTIONS";
}

function normalizeLang(h) {
  const s = String(h || "").split(",")[0].trim();
  return s || "en-US";
}

function makeNonce() {
  return crypto.randomBytes(12).toString("base64url");
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function safeJson(res, obj, status = 200) {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

// end of file (chunked padding continues in later internal versions)
