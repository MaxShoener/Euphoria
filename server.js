/* ───────────────────────────────────────────── */
/* Imports                                       */
/* ───────────────────────────────────────────── */

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import http from "http";
import https from "https";
import crypto from "crypto";
import zlib from "zlib";
import { pipeline } from "stream";
import { promisify } from "util";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import { WebSocketServer } from "ws";
import { EventEmitter } from "events";

// Scramjet CommonJS-safe import (no named export assumptions)
import scramjetPkg from "@mercuryworkshop/scramjet";
const ScramjetFactory =
  scramjetPkg?.createScramjetServer ||
  scramjetPkg?.createServer ||
  scramjetPkg?.default?.createScramjetServer ||
  scramjetPkg?.default?.createServer ||
  null;

const pipe = promisify(pipeline);

/* ───────────────────────────────────────────── */
/* Globals                                       */
/* ───────────────────────────────────────────── */

EventEmitter.defaultMaxListeners = 300;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ───────────────────────────────────────────── */
/* Config                                        */
/* ───────────────────────────────────────────── */

const PORT = Number(process.env.PORT || 3000);
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const CACHE_DIR = path.join(__dirname, "cache");
const PUBLIC_DIR = path.join(__dirname, "public");

const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 20 * 1024 * 1024); // 20MB
const MAX_HTML_CACHE_BYTES = Number(process.env.MAX_HTML_CACHE_BYTES || 900 * 1024); // 900KB
const MAX_ASSET_CACHE_BYTES = Number(process.env.MAX_ASSET_CACHE_BYTES || 4 * 1024 * 1024); // 4MB
const CACHE_TTL_MS = Number(process.env.CACHE_TTL_MS || 10 * 60 * 1000); // 10 min
const CACHE_TTL_ASSET_MS = Number(process.env.CACHE_TTL_ASSET_MS || 60 * 60 * 1000); // 1 hour
const MEM_CACHE_ITEMS = Number(process.env.MEM_CACHE_ITEMS || 4096);

const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
const TRUST_PROXY = true;

const DROP_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy",
]);

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const BINARY_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
  ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map", ".mp4", ".webm", ".mp3", ".m4a",
  ".pdf", ".zip", ".rar", ".7z", ".avi", ".mov", ".mkv",
];

const SPECIAL_FILES = [
  "service-worker.js", "sw.js", "worker.js", "manifest.json",
];

const HARD_SITES = [
  /accounts\.google\.com/i,
  /login\.live\.com/i,
  /login\.microsoftonline\.com/i,
  /microsoft\.com/i,
  /xbox\.com/i,
  /xsts\.auth\.xboxlive\.com/i,
  /user\.auth\.xboxlive\.com/i,
];

const FEATURE_FLAGS = {
  ENABLE_SCRAMJET: process.env.ENABLE_SCRAMJET !== "0",
  ENABLE_HTML_REWRITE: process.env.ENABLE_HTML_REWRITE !== "0",
  ENABLE_JS_REWRITE: process.env.ENABLE_JS_REWRITE !== "0",
  ENABLE_SW_PATCH: process.env.ENABLE_SW_PATCH !== "0",
  STRICT_COOKIE_ORIGIN: process.env.STRICT_COOKIE_ORIGIN !== "0",
  ENABLE_WS_TUNNEL: process.env.ENABLE_WS_TUNNEL !== "0",
  ENABLE_RANGE: process.env.ENABLE_RANGE !== "0",
  ENABLE_BROTLI: process.env.ENABLE_BROTLI !== "0",
};

function log(...args) {
  if (process.env.QUIET_LOGS === "1") return;
  console.log(...args);
}

/* ───────────────────────────────────────────── */
/* Init                                          */
/* ───────────────────────────────────────────── */

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

const app = express();
app.set("trust proxy", TRUST_PROXY);

app.use(cors({ origin: true, credentials: true }));
app.use(morgan("tiny"));
app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(express.static(PUBLIC_DIR, { index: false }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.RATE_LIMIT_GLOBAL || 900),
    standardHeaders: true,
    legacyHeaders: false,
  })
);

/* ───────────────────────────────────────────── */
/* Public Origin Resolver                        */
/* ───────────────────────────────────────────── */

function getPublicOrigin(req) {
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0].trim();
  const xfHost = (req.headers["x-forwarded-host"] || "").toString().split(",")[0].trim();
  const host = (xfHost || req.headers.host || "").toString().split(",")[0].trim();
  const proto = (xfProto || (req.socket.encrypted ? "https" : "http")).trim();
  if (!host) return "";
  return `${proto}://${host}`;
}

function normalizeTarget(raw) {
  if (!raw) return null;
  let s = String(raw).trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  try {
    return new URL(s).href;
  } catch {
    return null;
  }
}

function makeProxyUrl(absUrl, req) {
  try {
    const origin = getPublicOrigin(req);
    return `${origin}/proxy?url=${encodeURIComponent(new URL(absUrl).href)}`;
  } catch {
    return absUrl;
  }
}

/* ───────────────────────────────────────────── */
/* Cache                                         */
/* ───────────────────────────────────────────── */

const MEM_CACHE = new LRUCache({
  max: MEM_CACHE_ITEMS,
  ttl: CACHE_TTL_MS,
});

function cacheKey(s) {
  return Buffer.from(s).toString("base64url");
}

async function diskGet(key) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(f)) return null;
    const raw = await fsPromises.readFile(f, "utf8");
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    if (nowMs() - obj.t > (obj.ttl || CACHE_TTL_MS)) return null;
    return obj.v;
  } catch {
    return null;
  }
}

async function diskSet(key, value, ttl = CACHE_TTL_MS) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(f, JSON.stringify({ v: value, t: nowMs(), ttl }), "utf8");
  } catch {}
}

function nowMs() {
  return Date.now();
}

/* ───────────────────────────────────────────── */
/* Sessions + Strict Cookie Jars                 */
/* ───────────────────────────────────────────── */

const SESSION_COOKIE = "euphoria_sid";
const SESSIONS = new Map();

function newSid() {
  return crypto.randomBytes(16).toString("hex") + Date.now().toString(36);
}

function parseCookieHeader(header = "") {
  const out = {};
  header
    .split(";")
    .map(v => v.trim())
    .filter(Boolean)
    .forEach(pair => {
      const idx = pair.indexOf("=");
      if (idx === -1) return;
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (k) out[k] = v;
    });
  return out;
}

function setCookieHeader(res, sid) {
  const ck = `${SESSION_COOKIE}=${sid}; Path=/; SameSite=Lax; HttpOnly`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", ck);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, ck]);
  else res.setHeader("Set-Cookie", [prev, ck]);
}

function getSession(req, res) {
  const cookies = parseCookieHeader(req.headers.cookie || "");
  let sid = cookies[SESSION_COOKIE] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) {
    sid = newSid();
    SESSIONS.set(sid, {
      created: nowMs(),
      last: nowMs(),
      // strict cookie storage:
      // origin -> Map(name -> { value, attrs })
      jars: new Map(),
      // optional per-origin local storage / session storage snapshots
      storage: new Map(),
      ua: DEFAULT_UA,
      ip: req.ip || req.socket.remoteAddress || null,
    });
    setCookieHeader(res, sid);
  }
  const s = SESSIONS.get(sid);
  s.last = nowMs();
  s.ip = req.ip || s.ip;
  return { sid, s };
}

function getJar(session, origin) {
  if (!session.jars.has(origin)) session.jars.set(origin, new Map());
  return session.jars.get(origin);
}

function serializeCookieJarForRequest(session, origin, urlObj) {
  // Strict same-origin: only send cookies for exact origin.
  // Optional: path matching and secure enforcement.
  const jar = getJar(session, origin);
  const pairs = [];
  const reqPath = urlObj.pathname || "/";
  const isHttps = urlObj.protocol === "https:";
  const now = nowMs();

  for (const [name, c] of jar.entries()) {
    if (!c || typeof c !== "object") continue;
    if (c.expiresAt && now > c.expiresAt) continue;
    if (c.path && !reqPath.startsWith(c.path)) continue;
    if (c.secure && !isHttps) continue;
    // SameSite is enforced by browser; we emulate strict-origin by origin partition above.
    pairs.push(`${name}=${c.value}`);
  }
  return pairs.join("; ");
}

function parseSetCookie(setCookieValue) {
  // returns { name, value, attrs }
  const parts = String(setCookieValue).split(";").map(p => p.trim());
  const first = parts.shift() || "";
  const idx = first.indexOf("=");
  if (idx === -1) return null;
  const name = first.slice(0, idx).trim();
  const value = first.slice(idx + 1).trim();
  const attrs = {};
  for (const p of parts) {
    const [kRaw, ...rest] = p.split("=");
    const k = (kRaw || "").trim().toLowerCase();
    const v = rest.join("=").trim();
    if (!k) continue;
    if (k === "path") attrs.path = v || "/";
    else if (k === "domain") attrs.domain = v || "";
    else if (k === "secure") attrs.secure = true;
    else if (k === "httponly") attrs.httpOnly = true;
    else if (k === "samesite") attrs.sameSite = v || "";
    else if (k === "max-age") {
      const sec = Number(v);
      if (!Number.isNaN(sec)) attrs.maxAge = sec;
    } else if (k === "expires") {
      const ts = Date.parse(v);
      if (!Number.isNaN(ts)) attrs.expires = ts;
    } else {
      attrs[k] = v || true;
    }
  }
  return { name, value, attrs };
}

function storeSetCookies(session, origin, setCookies) {
  const jar = getJar(session, origin);
  const baseNow = nowMs();
  for (const sc of setCookies) {
    const parsed = parseSetCookie(sc);
    if (!parsed) continue;

    const { name, value, attrs } = parsed;

    // strict-origin partitioning: ignore Domain attribute for cross-site access
    // but keep Path/Secure/Expiry for correct sending behavior
    let expiresAt = null;
    if (attrs.maxAge != null) expiresAt = baseNow + attrs.maxAge * 1000;
    else if (attrs.expires != null) expiresAt = attrs.expires;

    jar.set(name, {
      value,
      path: attrs.path || "/",
      secure: !!attrs.secure,
      httpOnly: !!attrs.httpOnly,
      sameSite: attrs.sameSite || "",
      expiresAt,
    });
  }
}

setInterval(() => {
  const cutoff = nowMs() - 24 * 60 * 60 * 1000;
  for (const [sid, s] of SESSIONS.entries()) {
    if (!s || s.last < cutoff) SESSIONS.delete(sid);
  }
}, 30 * 60 * 1000);

/* ───────────────────────────────────────────── */
/* Admin Auth                                    */
/* ───────────────────────────────────────────── */

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

/* ───────────────────────────────────────────── */
/* Content Helpers                               */
/* ───────────────────────────────────────────── */

function isProbablyAssetUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    const p = (u.pathname || "").toLowerCase();
    if (SPECIAL_FILES.some(sf => p.endsWith("/" + sf) || p.endsWith(sf))) return true;
    if (BINARY_EXTENSIONS.some(ext => p.endsWith(ext))) return true;
    return false;
  } catch {
    const lower = String(urlStr).toLowerCase();
    if (SPECIAL_FILES.some(sf => lower.endsWith("/" + sf) || lower.endsWith(sf))) return true;
    if (BINARY_EXTENSIONS.some(ext => lower.endsWith(ext))) return true;
    return false;
  }
}

function stripSecurityHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (DROP_RESPONSE_HEADERS.has(lk)) continue;
    if (HOP_BY_HOP_HEADERS.has(lk)) continue;
    out[k] = v;
  }
  return out;
}

function safeSetHeaders(res, headersObj) {
  for (const [k, v] of Object.entries(headersObj || {})) {
    try {
      if (v == null) continue;
      res.setHeader(k, v);
    } catch {}
  }
}

/* ───────────────────────────────────────────── */
/* Fetch Engine (no undici dependency)           */
/* ───────────────────────────────────────────── */

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

async function fetchWithTimeout(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const u = new URL(url);
    const agent = u.protocol === "https:" ? httpsAgent : httpAgent;

    // Node 20 fetch supports "dispatcher" in undici, but we avoid undici import.
    // It also supports "agent" in some environments; Koyeb Node tends to accept it.
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      // @ts-ignore
      agent,
      redirect: "manual",
    });

    return res;
  } finally {
    clearTimeout(timer);
  }
}

/* ───────────────────────────────────────────── */
/* Decompression / Buffering                     */
/* ───────────────────────────────────────────── */

async function readUpstreamBody(res, limitBytes = MAX_BODY_BYTES) {
  const ab = await res.arrayBuffer();
  const buf = Buffer.from(ab);
  if (buf.length > limitBytes) throw new Error("body_too_large");
  return buf;
}

function tryDecompress(buf, encoding) {
  const enc = (encoding || "").toLowerCase();
  try {
    if (enc.includes("br") && FEATURE_FLAGS.ENABLE_BROTLI) return zlib.brotliDecompressSync(buf);
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
  } catch {}
  return buf;
}

/* ───────────────────────────────────────────── */
/* Rewrite - URL                                 */
/* ───────────────────────────────────────────── */

function shouldSkipRewriting(value) {
  if (!value) return true;
  const v = String(value);
  if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(v)) return true;
  if (v.includes("/proxy?url=")) return true;
  if (v.includes("/sj?url=") || v.includes("/sj/")) return true;
  return false;
}

function toAbsoluteMaybe(urlLike, base) {
  try {
    return new URL(urlLike, base).href;
  } catch {
    return null;
  }
}

/* ───────────────────────────────────────────── */
/* Rewrite Engine – HTML / DOM                   */
/* ───────────────────────────────────────────── */

function rewriteHtml(html, baseUrl, req) {
  if (!FEATURE_FLAGS.ENABLE_HTML_REWRITE) return html;

  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }

  const document = dom.window.document;
  const origin = getPublicOrigin(req);

  // Ensure <base>
  if (!document.querySelector("base")) {
    const head = document.querySelector("head");
    if (head) {
      const b = document.createElement("base");
      b.setAttribute("href", baseUrl);
      head.insertBefore(b, head.firstChild);
    }
  }

  function rewriteAttr(el, attr) {
    try {
      const val = el.getAttribute(attr);
      if (shouldSkipRewriting(val)) return;
      const abs = toAbsoluteMaybe(val, baseUrl);
      if (!abs) return;
      el.setAttribute(attr, makeProxyUrl(abs, req));
    } catch {}
  }

  // Links
  document.querySelectorAll("a[href]").forEach(a => {
    rewriteAttr(a, "href");
    a.removeAttribute("target");
  });

  // Forms
  document.querySelectorAll("form[action]").forEach(f => {
    rewriteAttr(f, "action");
  });

  // Media / script / iframe / link
  ["img", "script", "iframe", "audio", "video", "source", "track"].forEach(tag => {
    document.querySelectorAll(tag).forEach(el => {
      rewriteAttr(el, "src");
    });
  });

  document.querySelectorAll("link[href]").forEach(el => {
    rewriteAttr(el, "href");
  });

  // srcset (critical for complex images)
  document.querySelectorAll("[srcset]").forEach(el => {
    try {
      const srcset = el.getAttribute("srcset");
      if (!srcset) return;
      const out = srcset
        .split(",")
        .map(part => {
          const [u, size] = part.trim().split(/\s+/, 2);
          if (shouldSkipRewriting(u)) return part;
          const abs = toAbsoluteMaybe(u, baseUrl);
          if (!abs) return part;
          return makeProxyUrl(abs, req) + (size ? " " + size : "");
        })
        .join(", ");
      el.setAttribute("srcset", out);
    } catch {}
  });

  // Inline styles url(...)
  document.querySelectorAll("[style]").forEach(el => {
    try {
      const s = el.getAttribute("style");
      if (!s) return;
      const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
        if (shouldSkipRewriting(u)) return m;
        const abs = toAbsoluteMaybe(u, baseUrl);
        if (!abs) return m;
        return `url("${makeProxyUrl(abs, req)}")`;
      });
      el.setAttribute("style", out);
    } catch {}
  });

  // <style> blocks
  document.querySelectorAll("style").forEach(st => {
    try {
      let css = st.textContent || "";
      css = css.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
        if (shouldSkipRewriting(u)) return m;
        const abs = toAbsoluteMaybe(u, baseUrl);
        if (!abs) return m;
        return `url("${makeProxyUrl(abs, req)}")`;
      });
      st.textContent = css;
    } catch {}
  });

  // Meta refresh
  document.querySelectorAll("meta[http-equiv]").forEach(m => {
    try {
      if ((m.getAttribute("http-equiv") || "").toLowerCase() !== "refresh") return;
      const c = m.getAttribute("content") || "";
      const match = c.match(/url=(.+)$/i);
      if (!match) return;
      const abs = toAbsoluteMaybe(match[1], baseUrl);
      if (!abs) return;
      m.setAttribute("content", c.replace(match[1], makeProxyUrl(abs, req)));
    } catch {}
  });

  return dom.serialize();
}

/* ───────────────────────────────────────────── */
/* Rewrite Engine – JavaScript                   */
/* ───────────────────────────────────────────── */

function rewriteInlineJs(code, baseUrl, req) {
  if (!FEATURE_FLAGS.ENABLE_JS_REWRITE) return code;

  const proxyFn = u => makeProxyUrl(u, req);

  try {
    // fetch()
    code = code.replace(/fetch\(\s*(['"])([^'"]+)\1/g, (m, q, u) => {
      if (shouldSkipRewriting(u)) return m;
      const abs = toAbsoluteMaybe(u, baseUrl);
      if (!abs) return m;
      return `fetch("${proxyFn(abs)}"`;
    });

    // XMLHttpRequest.open
    code = code.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+)\3/gi,
      (m, q1, method, q2, u) => {
        if (shouldSkipRewriting(u)) return m;
        const abs = toAbsoluteMaybe(u, baseUrl);
        if (!abs) return m;
        return `.open("${method || "GET"}","${proxyFn(abs)}"`;
      }
    );

    // Hardcoded paths "/api/..."
    code = code.replace(/(['"])(\/[^'"]+?)\1/g, (m, q, u) => {
      if (shouldSkipRewriting(u)) return m;
      const abs = toAbsoluteMaybe(u, baseUrl);
      if (!abs) return m;
      return `"${proxyFn(abs)}"`;
    });

    return code;
  } catch {
    return code;
  }
}

/* ───────────────────────────────────────────── */
/* Client-Side Patch Injection                   */
/* ───────────────────────────────────────────── */

function injectClientPatch(html, baseUrl, req) {
  const marker = "/*__EUPHORIA_CLIENT__*/";
  if (html.includes(marker)) return html;

  const origin = getPublicOrigin(req);

  const patch = `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(origin)};
  function prox(u){
    try{
      if(!u) return u;
      if(u.includes('/proxy?url=')) return u;
      if(/^(data:|blob:|about:|javascript:)/i.test(u)) return u;
      return ORIGIN + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href);
    }catch(e){ return u; }
  }

  const _fetch = window.fetch;
  window.fetch = function(r, i){
    try{
      if(typeof r === 'string') r = prox(r);
      else if(r && r.url) r = new Request(prox(r.url), r);
    }catch(e){}
    return _fetch(r, i);
  };

  const XHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function(){
    const x = new XHR();
    const open = x.open;
    x.open = function(m, u){
      try{ u = prox(u); }catch(e){}
      return open.apply(this, arguments);
    };
    return x;
  };

  const open = window.open;
  window.open = function(u){
    return open.call(window, prox(u));
  };
})();
</script>
`;

  return html.replace(/<\/body>/i, patch + "</body>");
}

/* ───────────────────────────────────────────── */
/* Response Processing                           */
/* ───────────────────────────────────────────── */

async function processHtmlResponse(resUp, rawBuf, req, targetUrl) {
  const encoding = resUp.headers.get("content-encoding");
  let buf = tryDecompress(rawBuf, encoding);
  let html = buf.toString("utf8");

  html = rewriteHtml(html, targetUrl, req);
  html = injectClientPatch(html, targetUrl, req);

  // Rewrite inline scripts AFTER injection
  try {
    const dom = new JSDOM(html, { url: targetUrl });
    dom.window.document.querySelectorAll("script:not([src])").forEach(s => {
      const code = s.textContent || "";
      if (!code.trim()) return;
      s.textContent = rewriteInlineJs(code, targetUrl, req);
    });
    html = dom.serialize();
  } catch {}

  return Buffer.from(html, "utf8");
}

/* ───────────────────────────────────────────── */
/* Redirect Handling                             */
/* ───────────────────────────────────────────── */

function handleRedirect(resUp, req, res, targetUrl) {
  const loc = resUp.headers.get("location");
  if (!loc) return false;
  let abs;
  try {
    abs = new URL(loc, targetUrl).href;
  } catch {
    return false;
  }
  res.status(resUp.status);
  res.setHeader("Location", makeProxyUrl(abs, req));
  res.end();
  return true;
}

/* ───────────────────────────────────────────── */
/* Google Search Fallback                        */
/* ───────────────────────────────────────────── */

function googleSearchToUrl(q) {
  if (!q) return null;
  return "https://www.google.com/search?q=" + encodeURIComponent(q);
}

/* ───────────────────────────────────────────── */
/* Cookie Jar – Strict Same-Origin Emulation     */
/* ───────────────────────────────────────────── */

function normalizeHost(h) {
  return String(h || "").trim().toLowerCase();
}

function normalizePath(p) {
  if (!p || typeof p !== "string") return "/";
  return p.startsWith("/") ? p : "/" + p;
}

// Very small RFC6265-ish parser (good enough for most sites).
function parseSetCookieStrict(setCookieValue) {
  // Returns: { name, value, domain, path, expiresAt, secure, httpOnly, sameSite }
  try {
    const parts = String(setCookieValue).split(";").map(s => s.trim());
    const [nv, ...attrs] = parts;
    const eq = nv.indexOf("=");
    if (eq < 1) return null;
    const name = nv.slice(0, eq).trim();
    const value = nv.slice(eq + 1).trim();

    const out = {
      name,
      value,
      domain: null,
      path: null,
      expiresAt: null,
      secure: false,
      httpOnly: false,
      sameSite: null,
    };

    for (const a of attrs) {
      const [kRaw, vRaw] = a.split("=").map(x => x && x.trim());
      const k = (kRaw || "").toLowerCase();
      const v = vRaw || "";
      if (k === "domain") out.domain = normalizeHost(v.replace(/^\./, ""));
      else if (k === "path") out.path = normalizePath(v);
      else if (k === "expires") {
        const t = Date.parse(v);
        if (!Number.isNaN(t)) out.expiresAt = t;
      } else if (k === "max-age") {
        const sec = parseInt(v, 10);
        if (!Number.isNaN(sec)) out.expiresAt = Date.now() + sec * 1000;
      } else if (k === "secure") out.secure = true;
      else if (k === "httponly") out.httpOnly = true;
      else if (k === "samesite") out.sameSite = v;
      else if (kRaw && kRaw.toLowerCase() === "secure") out.secure = true;
      else if (kRaw && kRaw.toLowerCase() === "httponly") out.httpOnly = true;
    }

    if (!out.path) out.path = "/";
    return out;
  } catch {
    return null;
  }
}

function domainMatches(cookieDomain, reqHost) {
  if (!cookieDomain) return false;
  const cd = normalizeHost(cookieDomain);
  const rh = normalizeHost(reqHost);
  if (rh === cd) return true;
  return rh.endsWith("." + cd);
}

function pathMatches(cookiePath, reqPath) {
  const cp = normalizePath(cookiePath || "/");
  const rp = normalizePath(reqPath || "/");
  if (rp === cp) return true;
  if (rp.startsWith(cp)) return true;
  return false;
}

// Session cookie jar structure:
// session.payload.cookies = Map<originKey, Map<cookieName, cookieObj>>
// originKey = `${protocol}//${host}`
function ensureOriginJar(sessionPayload, originKey) {
  if (!sessionPayload.cookieJar) sessionPayload.cookieJar = new Map();
  if (!sessionPayload.cookieJar.has(originKey)) sessionPayload.cookieJar.set(originKey, new Map());
  return sessionPayload.cookieJar.get(originKey);
}

// Strict same-origin: only store/send for exact originKey, and only if domain matches exact host.
function storeSetCookiesStrict(sessionPayload, originUrl, setCookieValues) {
  if (!FEATURE_FLAGS.STRICT_SAME_ORIGIN_COOKIES) return;
  let origin;
  try { origin = new URL(originUrl); } catch { return; }
  const originKey = `${origin.protocol}//${origin.host}`;
  const jar = ensureOriginJar(sessionPayload, originKey);

  for (const sc of setCookieValues || []) {
    const parsed = parseSetCookie(sc);
    if (!parsed) continue;

    // Enforce strictness: domain must be exact host (no wider cookie domains)
    const host = normalizeHost(origin.hostname);
    const dom = parsed.domain ? normalizeHost(parsed.domain) : host;
    if (dom !== host) continue;

    // If secure cookie but origin is http, drop it.
    if (parsed.secure && origin.protocol !== "https:") continue;

    // Expiration cleanup
    if (parsed.expiresAt && parsed.expiresAt <= Date.now()) {
      jar.delete(parsed.name);
      continue;
    }

    jar.set(parsed.name, {
      ...parsed,
      domain: host,
      path: parsed.path || "/",
      setAt: Date.now(),
    });
  }
}

function buildCookieHeaderStrict(sessionPayload, targetUrl) {
  if (!FEATURE_FLAGS.STRICT_SAME_ORIGIN_COOKIES) return "";
  let u;
  try { u = new URL(targetUrl); } catch { return ""; }
  const originKey = `${u.protocol}//${u.host}`;
  const jar = sessionPayload.cookieJar?.get(originKey);
  if (!jar) return "";

  const host = normalizeHost(u.hostname);
  const path = normalizePath(u.pathname || "/");
  const nowTs = Date.now();

  const pairs = [];
  for (const [name, c] of jar.entries()) {
    if (c.expiresAt && c.expiresAt <= nowTs) {
      jar.delete(name);
      continue;
    }
    if (c.secure && u.protocol !== "https:") continue;
    if (!domainMatches(c.domain, host)) continue;
    if (!pathMatches(c.path, path)) continue;
    pairs.push(`${name}=${c.value}`);
  }
  return pairs.join("; ");
}

/* ───────────────────────────────────────────── */
/* URL Parsing & Routing Helpers                 */
/* ───────────────────────────────────────────── */

function looksLikeUrlish(input) {
  if (!input) return false;
  const s = String(input).trim();
  if (!s) return false;
  if (/^https?:\/\//i.test(s)) return true;
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/].*)?$/i.test(s)) return true; // example.com/path
  return false;
}

function normalizeToHttpUrl(input) {
  const s = String(input || "").trim();
  if (!s) return null;
  if (/^https?:\/\//i.test(s)) return s;
  if (looksLikeUrlish(s)) return "https://" + s;
  return null;
}

function getTargetFromRequest(req) {
  // supports:
  // 1) /proxy?url=...
  // 2) /proxy/<encoded>
  // 3) /proxy/:host/*   (you requested this style)
  // 4) Google search shorthand: /proxy?q=hello
  const qUrl = req.query?.url;
  const qQ = req.query?.q;

  if (qQ && !qUrl) return googleSearchToUrl(qQ);

  if (qUrl) return normalizeToHttpUrl(qUrl);

  // /proxy/<something>
  if (req.path && req.path.startsWith("/proxy/")) {
    const rest = req.path.replace(/^\/proxy\//, "");
    if (!rest) return null;

    // /proxy/:host/* style:
    // If it looks like host/path and no scheme, prefix scheme.
    // Also accept percent-encoding.
    let decoded = rest;
    try { decoded = decodeURIComponent(rest); } catch {}
    const maybe = normalizeToHttpUrl(decoded);
    if (maybe) return maybe;

    // If they used /proxy/https://example.com (already decoded badly), normalize:
    if (/^https?:\/\//i.test(decoded)) return decoded;

    // As final fallback, treat it as path under referer target
    return null;
  }

  return null;
}

function isHtmlContentType(ct) {
  const s = String(ct || "").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

function shouldTreatAsAsset(ct) {
  const s = String(ct || "").toLowerCase();
  if (isHtmlContentType(s)) return false;
  return true;
}

function copyUpstreamHeadersToClient(resUp, resDown) {
  try {
    for (const [k, v] of resUp.headers.entries()) {
      const lk = k.toLowerCase();
      if (DROP_HEADERS.has(lk)) continue;
      // Prevent upstream from setting a broken origin in redirects; we handle redirects ourselves.
      if (lk === "location") continue;
      // Avoid content-encoding mismatches after we decompress/rewrite.
      if (lk === "content-encoding") continue;
      // We'll compute content-length ourselves if we transform.
      if (lk === "content-length") continue;
      try { resDown.setHeader(k, v); } catch {}
    }
  } catch {}
}

/* ───────────────────────────────────────────── */
/* Asset Streaming (Range / Large Media)         */
/* ───────────────────────────────────────────── */

async function streamUpstreamToClient(resUp, resDown) {
  // Node fetch body is a web stream; convert to node stream if available.
  // Best-effort: buffer if stream conversion not available.
  const body = resUp.body;

  if (!body) {
    resDown.end();
    return;
  }

  // In Node 20, resUp.body is a ReadableStream.
  if (typeof body.getReader === "function") {
    const reader = body.getReader();
    const pump = async () => {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value) resDown.write(Buffer.from(value));
      }
      resDown.end();
    };
    await pump();
    return;
  }

  // fallback
  const arr = await resUp.arrayBuffer();
  resDown.end(Buffer.from(arr));
}

/* ───────────────────────────────────────────── */
/* Proxy Endpoint (Main)                         */
/* ───────────────────────────────────────────── */

app.get("/proxy", async (req, res) => {
  // Google shorthand: /proxy?q=hello
  let target = getTargetFromRequest(req);
  if (!target) {
    return res
      .status(400)
      .send("Missing url (use /proxy?url=https://example.com) or /proxy?q=search");
  }

  // Special: if user passes a raw query in url= (not urlish), treat as google search
  if (!looksLikeUrlish(target) && req.query?.url) {
    target = googleSearchToUrl(String(req.query.url || ""));
  }
  if (!target) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch {}

  // caching keys
  const cacheKeyBase = target;
  const accept = String(req.headers.accept || "").toLowerCase();
  const wantsHtml = accept.includes("text/html") || req.query.force_html === "1";

  const key = wantsHtml ? `${cacheKeyBase}::html` : `${cacheKeyBase}::asset`;

  // Cache only GET without Range
  const hasRange = !!req.headers.range;
  const cacheAllowed = req.method === "GET" && !hasRange;

  if (cacheAllowed) {
    const mem = MEM_CACHE.get(key);
    if (mem) {
      if (mem.__type === "html") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.end(mem.body);
      }
      if (mem.__type === "asset") {
        if (mem.headers) {
          for (const [k, v] of Object.entries(mem.headers)) {
            try { res.setHeader(k, v); } catch {}
          }
        }
        return res.end(Buffer.from(mem.bodyB64, "base64"));
      }
    }

    const disk = await diskGet(key);
    if (disk) {
      if (disk.__type === "html") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.end(disk.body);
      }
      if (disk.__type === "asset") {
        if (disk.headers) {
          for (const [k, v] of Object.entries(disk.headers)) {
            try { res.setHeader(k, v); } catch {}
          }
        }
        return res.end(Buffer.from(disk.bodyB64, "base64"));
      }
    }
  }

  // Build upstream request headers
  const hdrs = {};
  try {
    hdrs["user-agent"] = session.payload.ua || USER_AGENT_DEFAULT;
    hdrs["accept"] = req.headers.accept || "*/*";
    hdrs["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
    hdrs["accept-encoding"] = "gzip, deflate, br";

    // Range support (fixes complex images/media in many CDNs)
    if (req.headers.range) hdrs["range"] = req.headers.range;

    // Strict same-origin cookies
    const cookieHeader = buildCookieHeaderStrict(session.payload, target);
    if (cookieHeader) hdrs["cookie"] = cookieHeader;

    // Referer/Origin: use upstream origin when possible
    if (req.headers.referer) hdrs["referer"] = req.headers.referer;
    try { hdrs["origin"] = new URL(target).origin; } catch {}
  } catch {}

  // Upstream fetch
  let up;
  try {
    up = await upstreamFetch(target, {
      method: "GET",
      headers: hdrs,
      redirect: "manual",
    });
  } catch (e) {
    // Many “Failed to fetch” sites need better redirect/cookie flow; chunk4 adds hardening.
    return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
  }

  // Cookies from upstream -> store strictly for this origin
  try {
    const raw = up.headers.get("set-cookie");
    if (raw) {
      // Some runtimes join multiple set-cookie; split conservatively.
      const setCookies = String(raw).split(/,(?=[^ ;]+=)/g);
      storeSetCookiesStrict(session.payload, up.url || target, setCookies);
    }
  } catch {}

  // Redirect trapping (keeps you inside /proxy)
  if ([301, 302, 303, 307, 308].includes(up.status)) {
    if (handleRedirect(up, req, res, target)) return;
  }

  // Copy headers (minus CSP/COOP/COEP/etc)
  copyUpstreamHeadersToClient(up, res);

  const ct = up.headers.get("content-type") || "";
  const isHtml = isHtmlContentType(ct) || wantsHtml;

  // HTML path: buffer + rewrite
  if (isHtml) {
    let rawBuf;
    try {
      rawBuf = Buffer.from(await up.arrayBuffer());
    } catch (e) {
      return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
    }

    // Transform
    let outBuf = rawBuf;
    try {
      outBuf = await processHtmlResponse(up, rawBuf, req, up.url || target);
    } catch {}

    res.status(up.status || 200);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store"); // safer for auth-heavy sites

    // Cache HTML only if small and allowed
    if (cacheAllowed && FEATURE_FLAGS.ENABLE_DISK_CACHE && outBuf.length < 600 * 1024) {
      try {
        const payload = { __type: "html", body: outBuf.toString("utf8") };
        MEM_CACHE.set(key, payload);
        diskSet(key, payload).catch(() => {});
      } catch {}
    }

    return res.end(outBuf);
  }

  // Asset path: stream large, buffer small for cache
  res.status(up.status || 200);

  // Ensure content-type set
  if (ct) {
    try { res.setHeader("Content-Type", ct); } catch {}
  }

  // If range request, do not cache, just stream
  if (hasRange) {
    return streamUpstreamToClient(up, res);
  }

  // Try buffer to cache for smaller assets
  let buf;
  try {
    const arr = await up.arrayBuffer();
    buf = Buffer.from(arr);
  } catch {
    return streamUpstreamToClient(up, res);
  }

  // Cache small assets
  if (cacheAllowed && buf.length <= ASSET_CACHE_THRESHOLD) {
    try {
      const headersObj = {};
      for (const [k, v] of up.headers.entries()) {
        const lk = k.toLowerCase();
        if (DROP_HEADERS.has(lk)) continue;
        if (lk === "content-encoding") continue;
        if (lk === "content-length") continue;
        headersObj[k] = v;
      }
      const payload = {
        __type: "asset",
        headers: headersObj,
        bodyB64: buf.toString("base64"),
      };
      MEM_CACHE.set(key, payload);
      diskSet(key, payload).catch(() => {});
    } catch {}
  }

  return res.end(buf);
});

/* ───────────────────────────────────────────── */
/* /proxy/:host/* Style Support                  */
/* ───────────────────────────────────────────── */

app.get(/^\/proxy\/([^/]+)\/(.*)$/i, async (req, res, next) => {
  // This handler normalizes /proxy/:host/* into /proxy?url=https://host/*
  // so your frontend can use clean paths.
  try {
    const host = req.params?.[0] || "";
    const rest = req.params?.[1] || "";
    if (!host) return next();

    const combined = `${host}/${rest}`;
    const url = normalizeToHttpUrl(combined);
    if (!url) return next();

    // rewrite req.url by redirecting internally
    const q = encodeURIComponent(url);
    return res.redirect(302, `/proxy?url=${q}`);
  } catch {
    return next();
  }
});

/* ───────────────────────────────────────────── */
/* Fallback Asset Path (Keeps Buttons Working)   */
/* ───────────────────────────────────────────── */

app.use(async (req, res, next) => {
  // If a site requests /_next/static/... etc, it may “escape” our /proxy path.
  // Attempt to reconstruct target from referer (?url=...).
  try {
    const p = req.path || "/";
    if (
      p.startsWith("/proxy") ||
      p.startsWith("/_euph_ws") ||
      p.startsWith("/_wsproxy") ||
      p.startsWith("/_euph_debug") ||
      p.startsWith("/static") ||
      p.startsWith("/public")
    ) return next();

    const ref = req.headers.referer || req.headers.referrer || "";
    const m = String(ref).match(/[?&]url=([^&]+)/);
    if (!m) return next();

    let base;
    try { base = decodeURIComponent(m[1]); } catch { return next(); }
    if (!base) return next();

    const baseOrigin = new URL(base).origin;
    const attempt = new URL(req.originalUrl, baseOrigin).href;

    // Proxy it by bouncing through /proxy
    return res.redirect(302, makeProxyUrl(attempt, req));
  } catch {
    return next();
  }
});

/* ───────────────────────────────────────────── */
/* Derived Origin / Proxy URL Builder            */
/* ───────────────────────────────────────────── */

function getRequestPublicOrigin(req) {
  // Fixes “redirects to localhost:3000” by preferring actual request host/proto.
  // Works on Koyeb/behind proxies if trust proxy enabled.
  try {
    const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
    const host = (req.headers["x-forwarded-host"] || req.headers.host || "").split(",")[0].trim();
    if (host) return `${proto}://${host}`;
  } catch {}
  return DEPLOYMENT_ORIGIN;
}

function makeProxyUrlStrict(targetAbs, req) {
  const origin = getRequestPublicOrigin(req);
  return `${origin}/proxy?url=${encodeURIComponent(String(targetAbs))}`;
}

function googleSearchToUrl(q) {
  const query = String(q || "").trim();
  if (!query) return "https://www.google.com/";
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

/* ───────────────────────────────────────────── */
/* Redirect Handler (Keeps you inside /proxy)    */
/* ───────────────────────────────────────────── */

function handleRedirect(upstreamRes, req, res, requestTarget) {
  try {
    const loc = upstreamRes.headers.get("location");
    if (!loc) return false;

    let abs;
    try {
      abs = new URL(loc, upstreamRes.url || requestTarget).href;
    } catch {
      abs = loc;
    }

    // Trap redirect back into proxy
    const prox = makeProxyUrl(abs, req);

    // Do NOT pass upstream Location; set ours
    try {
      res.status(upstreamRes.status || 302);
      res.setHeader("Location", prox);
      // some clients like a body for 302/303
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end(`Redirecting to ${prox}`);
      return true;
    } catch {
      return false;
    }
  } catch {
    return false;
  }
}

/* ───────────────────────────────────────────── */
/* Decompression Helpers (gzip/deflate/br)       */
/* ───────────────────────────────────────────── */

import zlib from "zlib";

function maybeDecompress(bodyBuf, headers) {
  const enc = String(headers?.get?.("content-encoding") || "").toLowerCase().trim();
  if (!enc) return bodyBuf;
  try {
    if (enc.includes("br") && zlib.brotliDecompressSync) {
      return zlib.brotliDecompressSync(bodyBuf);
    }
    if (enc.includes("gzip")) {
      return zlib.gunzipSync(bodyBuf);
    }
    if (enc.includes("deflate")) {
      return zlib.inflateSync(bodyBuf);
    }
  } catch {}
  return bodyBuf;
}

/* ───────────────────────────────────────────── */
/* HTML Processing Pipeline                       */
/* ───────────────────────────────────────────── */

function injectClientRuntime(html, baseUrl, req) {
  // More aggressive “browser-like” runtime:
  // - traps navigation APIs (location, open, assign/replace)
  // - patches fetch/XHR to proxy
  // - patches History API (pushState/replaceState)
  // - patches form submits at runtime
  // - attempts to keep top-level navigation inside proxy
  // NOTE: Some sites (Xbox/MS) have heavy anti-bot/service-worker flows;
  // this helps buttons/redirects not “escape”.

  const origin = getRequestPublicOrigin(req);
  const marker = "/* EUPHORIA_CLIENT_RUNTIME_V4 */";
  if (html.includes(marker)) return html;

  const js = `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(origin)};
  const PROXY_PATH = "/proxy?url=";

  function isProxied(u){ return typeof u === "string" && u.includes(PROXY_PATH); }
  function abs(u){
    try { return new URL(u, document.baseURI).href; } catch(e){ return u; }
  }
  function prox(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(isProxied(u)) return u;
      if(/^(data:|blob:|about:|javascript:|mailto:|tel:)/i.test(u)) return u;
      const a = abs(u);
      return ORIGIN + PROXY_PATH + encodeURIComponent(a);
    }catch(e){ return u; }
  }

  // Patch fetch
  try{
    const ofetch = window.fetch;
    window.fetch = function(resource, init){
      try{
        if(typeof resource === "string"){
          resource = prox(resource);
        }else if(resource && resource.url && resource instanceof Request){
          if(!isProxied(resource.url)){
            resource = new Request(prox(resource.url), resource);
          }
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
        return open.apply(this, arguments);
      };
      return x;
    };
  }catch(e){}

  // Patch History API
  try{
    const p = history.pushState;
    history.pushState = function(state, title, url){
      try{
        if(typeof url === "string") url = prox(url);
      }catch(e){}
      return p.apply(this, arguments);
    };
    const r = history.replaceState;
    history.replaceState = function(state, title, url){
      try{
        if(typeof url === "string") url = prox(url);
      }catch(e){}
      return r.apply(this, arguments);
    };
  }catch(e){}

  // Trap window.open
  try{
    const o = window.open;
    window.open = function(url, name, specs){
      try{ if(typeof url === "string") url = prox(url); }catch(e){}
      return o.call(this, url, name, specs);
    };
  }catch(e){}

  // Trap location navigation
  try{
    const loc = window.location;
    const assign = loc.assign.bind(loc);
    const replace = loc.replace.bind(loc);
    loc.assign = function(u){ return assign(prox(u)); };
    loc.replace = function(u){ return replace(prox(u)); };

    // If someone sets window.location = "https://..."
    // we can’t fully replace the setter safely across browsers, but we can intercept common patterns:
    window.__euph_setLocation = function(u){
      try{ window.location.href = prox(u); }catch(e){ window.location.href = u; }
    };
  }catch(e){}

  // Patch forms on submit
  function patchForms(){
    try{
      const forms = document.querySelectorAll("form[action]");
      forms.forEach(f=>{
        try{
          const a = f.getAttribute("action");
          if(a && !isProxied(a)) f.setAttribute("action", prox(a));
        }catch(e){}
      });
    }catch(e){}
  }
  patchForms();
  document.addEventListener("submit", function(ev){
    try{ patchForms(); }catch(e){}
  }, true);

  // Patch anchor clicks (in case some remain un-rewritten)
  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && (ev.target.closest ? ev.target.closest("a[href]") : null);
      if(!a) return;
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(isProxied(href)) return;
      a.setAttribute("href", prox(href));
      a.removeAttribute("target");
    }catch(e){}
  }, true);

})();
</script>`.trim();

  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, js + "\n</body>");
  return html + "\n" + js;
}

function rewriteHtmlWithBaseAndUrls(html, baseUrl, req) {
  // Uses your existing jsdomTransform + extra hardening:
  // - ensure base tag
  // - rewrite iframe/src/href/srcset/style url() via jsdomTransform
  // - inject runtime
  let out = sanitizeHtml(html);
  out = jsdomTransform(out, baseUrl);

  // Ensure any absolute links that are still raw get proxied (extra safety)
  try {
    const origin = getRequestPublicOrigin(req);
    out = out.replace(/(href|src)=["'](https?:\/\/[^"']+)["']/gi, (m, attr, u) => {
      const prox = `${origin}/proxy?url=${encodeURIComponent(u)}`;
      return `${attr}="${prox}"`;
    });
  } catch {}

  out = injectClientRuntime(out, baseUrl, req);
  return out;
}

async function processHtmlResponse(upstreamRes, upstreamBodyBuf, req, baseUrl) {
  // Decompress if needed (buttons/images often fail when content-encoding mismatched)
  const dec = maybeDecompress(upstreamBodyBuf, upstreamRes.headers);

  // Decode (best effort)
  let htmlText;
  try {
    htmlText = dec.toString("utf8");
  } catch {
    htmlText = Buffer.from(dec).toString("utf8");
  }

  // Rewrite inline scripts more aggressively inside a second JSDOM pass
  let rewritten = rewriteHtmlWithBaseAndUrls(htmlText, baseUrl, req);

  // Post-process scripts: rewriteInlineJs / patchServiceWorker
  try {
    const dom = new JSDOM(rewritten, { url: baseUrl, contentType: "text/html" });
    const doc = dom.window.document;

    // Remove/neutralize Service Worker registration (can break proxied sessions)
    if (FEATURE_FLAGS?.DISABLE_SERVICE_WORKERS) {
      const scripts = Array.from(doc.querySelectorAll("script"));
      for (const s of scripts) {
        if (s.getAttribute("src")) continue;
        const code = s.textContent || "";
        if (!code) continue;
        // blunt but effective: stop SW register
        if (/serviceWorker\s*\.\s*register/i.test(code)) {
          s.textContent = code.replace(/serviceWorker\s*\.\s*register/gi, "/*euph*/null&&serviceWorker.register");
        }
      }
      // also block SW via header meta where possible
      const meta = doc.createElement("meta");
      meta.setAttribute("http-equiv", "Service-Worker-Allowed");
      meta.setAttribute("content", "/");
      (doc.head || doc.documentElement).appendChild(meta);
    }

    const scripts2 = Array.from(doc.querySelectorAll("script"));
    for (const s of scripts2) {
      try {
        if (s.getAttribute("src")) continue;
        let code = s.textContent || "";
        if (!code.trim()) continue;

        const lower = code.slice(0, 600).toLowerCase();
        if (lower.includes("importscripts") || lower.includes("caches.open") || lower.includes("self.addeventlistener")) {
          code = patchServiceWorker(code, baseUrl);
        }
        code = rewriteInlineJs(code, baseUrl);
        s.textContent = code;
      } catch {}
    }

    rewritten = dom.serialize();
  } catch {}

  // Run extension hooks if your earlier chunks included them
  try {
    if (typeof runExtensions === "function") {
      rewritten = await runExtensions(rewritten, { url: baseUrl, req });
    }
  } catch {}

  return Buffer.from(rewritten, "utf8");
}

/* ───────────────────────────────────────────── */
/* Small but critical defaults for “real browser” */
/* ───────────────────────────────────────────── */

// These flags should exist earlier; if not, define minimal defaults here:
const FEATURE_FLAGS = globalThis.FEATURE_FLAGS || {
  STRICT_SAME_ORIGIN_COOKIES: true,
  DISABLE_SERVICE_WORKERS: true,
  ENABLE_DISK_CACHE: true,
};
globalThis.FEATURE_FLAGS = FEATURE_FLAGS;

// Make caching “feel faster” while keeping auth safer
function isAuthyHost(host) {
  const h = String(host || "").toLowerCase();
  return (
    h.includes("accounts.google.") ||
    h.includes("login.live.") ||
    h.includes("microsoftonline.") ||
    h.includes("xbox.") ||
    h.includes("live.com")
  );
}
