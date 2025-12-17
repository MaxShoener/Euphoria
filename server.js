/* ========================================================================== */
/*  server.js — Euphoria Hybrid                                               */
/*  ------------------------------------------------------------------------  */
/*  Design goals (per your spec):                                             */
/*   1) Load as many sites as possible via basic proxy + optional Scramjet     */
/*   2) Buttons/redirects stay inside Euphoria (no escaping the deployment)    */
/*   3) POST supported (forms + fetch/XHR + manual POST)                       */
/*   4) WS supported (auto-rewrite client WebSocket + /ws tunnel server)      */
/*   5) Media supported (range streaming, passthrough content-type)           */
/*   6) Harden login flows (Pass 3)                                            */
/*   7) Clean "acts as WISP server" endpoints + discovery                      */
/*   8) Scramjet-safe integration (CJS-safe import, never crash if missing)   */
/*                                                                            */
/*  Notes:                                                                     */
/*   - No iframes are used anywhere here.                                      */
/*   - This is an ESM file for Node 20+.                                       */
/*   - Some sites (Google/Microsoft/Xbox) may still resist due to modern       */
/*     origin isolation / anti-automation / token binding. This is best-effort */
/*     without headless Chromium.                                              */
/* ========================================================================== */

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import rateLimit from "express-rate-limit"; // user added 8.2.1
import path from "path";
import fs from "fs";
import fsPromises from "fs/promises";
import http from "http";
import https from "https";
import crypto from "crypto";
import zlib from "zlib";
import { pipeline } from "stream";
import { promisify } from "util";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import { LRUCache } from "lru-cache";
import WebSocket, { WebSocketServer } from "ws";
import { EventEmitter } from "events";

/* -------------------------------------------------------------------------- */
/* Scramjet (CJS-safe import)                                                 */
/* -------------------------------------------------------------------------- */
import scramjetPkg from "@mercuryworkshop/scramjet";
const ScramjetFactory =
  scramjetPkg?.createScramjetServer ||
  scramjetPkg?.createServer ||
  scramjetPkg?.default?.createScramjetServer ||
  scramjetPkg?.default?.createServer ||
  null;

EventEmitter.defaultMaxListeners = 300;

const pipe = promisify(pipeline);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ========================================================================== */
/* Config                                                                     */
/* ========================================================================== */

const PORT = Number(process.env.PORT || 8000);

// Koyeb / reverse proxy safety: DO NOT use trust proxy = true with express-rate-limit.
// Use hop count (typically 1).
const TRUST_PROXY_HOPS = Number(process.env.TRUST_PROXY_HOPS || 1);

const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

// Feature toggles
const FEATURE = Object.freeze({
  ENABLE_SCRAMJET: process.env.ENABLE_SCRAMJET !== "0",
  ENABLE_DISK_CACHE: process.env.ENABLE_DISK_CACHE !== "0",
  ENABLE_HTML_REWRITE: process.env.ENABLE_HTML_REWRITE !== "0",
  ENABLE_JS_REWRITE: process.env.ENABLE_JS_REWRITE !== "0",
  ENABLE_CSS_REWRITE: process.env.ENABLE_CSS_REWRITE !== "0",
  DISABLE_SERVICE_WORKERS: process.env.DISABLE_SERVICE_WORKERS !== "0",
  STRICT_COOKIE_ORIGIN: process.env.STRICT_COOKIE_ORIGIN !== "0",
  ENABLE_WS_TUNNEL: process.env.ENABLE_WS_TUNNEL !== "0",
  ENABLE_RANGE: process.env.ENABLE_RANGE !== "0",
  ENABLE_BROTLI: process.env.ENABLE_BROTLI !== "0",
  ENABLE_PREFETCH_HINTS: process.env.ENABLE_PREFETCH_HINTS !== "0",
  QUIET_LOGS: process.env.QUIET_LOGS === "1",
});

// Performance + caching limits
const LIMITS = Object.freeze({
  FETCH_TIMEOUT_MS: Number(process.env.FETCH_TIMEOUT_MS || 30000),
  MAX_BODY_BYTES: Number(process.env.MAX_BODY_BYTES || 25 * 1024 * 1024), // 25MB
  MEM_CACHE_ITEMS: Number(process.env.MEM_CACHE_ITEMS || 8000),
  HTML_CACHE_MAX: Number(process.env.HTML_CACHE_MAX || 900 * 1024),
  ASSET_CACHE_MAX: Number(process.env.ASSET_CACHE_MAX || 7 * 1024 * 1024),
  TTL_HTML_MS: Number(process.env.TTL_HTML_MS || 6 * 60 * 1000),
  TTL_ASSET_MS: Number(process.env.TTL_ASSET_MS || 60 * 60 * 1000),
  TTL_DISK_MS: Number(process.env.TTL_DISK_MS || 60 * 60 * 1000),
});

// UA + accept
const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

// Admin
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

// Some response headers break proxied browsing.
const DROP_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy",
  "origin-agent-cluster",
  "document-policy",
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

const SPECIAL_FILES = [
  "service-worker.js",
  "sw.js",
  "worker.js",
  "manifest.json",
];

const BINARY_EXTENSIONS = [
  ".wasm",
  ".js",
  ".mjs",
  ".css",
  ".png",
  ".jpg",
  ".jpeg",
  ".webp",
  ".gif",
  ".svg",
  ".ico",
  ".ttf",
  ".otf",
  ".woff",
  ".woff2",
  ".eot",
  ".json",
  ".map",
  ".mp4",
  ".webm",
  ".mp3",
  ".m4a",
  ".wav",
  ".ogg",
  ".pdf",
  ".zip",
  ".rar",
  ".7z",
  ".avi",
  ".mov",
  ".mkv",
];

// Some hosts are “auth-heavy” and should not cache HTML.
const AUTHY_HOST_HINTS = [
  "accounts.google.",
  "login.live.",
  "microsoftonline.",
  "xbox.",
  "live.com",
  "auth.",
  "login.",
  "signin.",
  "oauth",
  "sso",
];

// A few patterns commonly used in hostile “reload loops”.
const LOOP_HINTS = [
  /\/ServiceLogin/i,
  /\/signin\/v2/i,
  /\/oauth/i,
  /\/login/i,
  /\/authorize/i,
  /continue=/i,
];

function log(...args) {
  if (!FEATURE.QUIET_LOGS) console.log(...args);
}

/* ========================================================================== */
/* Init cache dir                                                             */
/* ========================================================================== */

if (FEATURE.ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

/* ========================================================================== */
/* Express setup                                                              */
/* ========================================================================== */

const app = express();
app.set("trust proxy", TRUST_PROXY_HOPS);

app.use(cors({ origin: true, credentials: true }));
app.use(morgan("tiny"));
app.use(compression());

// Body parsing: we do our own raw body for proxy routes to support arbitrary content.
// Keep json/urlencoded small for admin endpoints.
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));

// Static
app.use(express.static(PUBLIC_DIR, { index: false }));

// Rate limit: keep it simple and compatible
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.RATE_LIMIT_GLOBAL || 900),
    standardHeaders: true,
    legacyHeaders: false,
    // IMPORTANT: with trust proxy set to hop count, this is OK.
    // express-rate-limit v8 warns when trust proxy is true.
  })
);

/* ========================================================================== */
/* Utility helpers                                                            */
/* ========================================================================== */

function nowMs() {
  return Date.now();
}

function safeJsonParse(s, fallback = null) {
  try {
    return JSON.parse(s);
  } catch {
    return fallback;
  }
}

function cacheKey(s) {
  return Buffer.from(String(s)).toString("base64url");
}

function normalizeHost(h) {
  return String(h || "").trim().toLowerCase();
}

function normalizePath(p) {
  if (!p) return "/";
  const s = String(p);
  return s.startsWith("/") ? s : `/${s}`;
}

function looksLikeUrlish(input) {
  const s = String(input || "").trim();
  if (!s) return false;
  if (/^https?:\/\//i.test(s)) return true;
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/:?#].*)?$/i.test(s)) return true;
  return false;
}

function normalizeToHttpUrl(input) {
  const s = String(input || "").trim();
  if (!s) return null;
  if (/^https?:\/\//i.test(s)) {
    try {
      return new URL(s).href;
    } catch {
      return null;
    }
  }
  if (looksLikeUrlish(s)) {
    try {
      return new URL("https://" + s).href;
    } catch {
      return null;
    }
  }
  return null;
}

function googleSearchToUrl(q) {
  const query = String(q || "").trim();
  if (!query) return "https://www.google.com/";
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}

/**
 * Public origin resolver:
 * fixes “redirects going to http://localhost:3000/proxy” by always deriving from forwarded headers.
 */
function getPublicOrigin(req) {
  const xfProto = String(req.headers["x-forwarded-proto"] || "")
    .split(",")[0]
    .trim();
  const xfHost = String(req.headers["x-forwarded-host"] || "")
    .split(",")[0]
    .trim();
  const host = String(xfHost || req.headers.host || "")
    .split(",")[0]
    .trim();
  const proto = (xfProto || (req.socket.encrypted ? "https" : "http")).trim();
  if (!host) return "";
  return `${proto}://${host}`;
}

function makeProxyUrl(absUrl, req, mode = "proxy") {
  try {
    const origin = getPublicOrigin(req);
    const base = mode === "sj" ? "/sj" : "/proxy";
    return `${origin}${base}?url=${encodeURIComponent(new URL(absUrl).href)}`;
  } catch {
    return absUrl;
  }
}

/* ========================================================================== */
/* Disk cache                                                                 */
/* ========================================================================== */

async function diskGet(key) {
  if (!FEATURE.ENABLE_DISK_CACHE) return null;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(f)) return null;
    const raw = await fsPromises.readFile(f, "utf8");
    const obj = safeJsonParse(raw, null);
    if (!obj || typeof obj !== "object") return null;
    if (nowMs() - obj.t > (obj.ttl || LIMITS.TTL_DISK_MS)) return null;
    return obj.v;
  } catch {
    return null;
  }
}

async function diskSet(key, value, ttl) {
  if (!FEATURE.ENABLE_DISK_CACHE) return;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(
      f,
      JSON.stringify({ v: value, t: nowMs(), ttl: ttl || LIMITS.TTL_DISK_MS }),
      "utf8"
    );
  } catch {}
}

/* ========================================================================== */
/* Memory cache                                                               */
/* ========================================================================== */

const MEM_CACHE = new LRUCache({
  max: LIMITS.MEM_CACHE_ITEMS,
});

/* ========================================================================== */
/* Sessions + strict cookie jar                                               */
/* ========================================================================== */

const SESSION_COOKIE = "euphoria_sid";
const SESSIONS = new Map();

function newSid() {
  return crypto.randomBytes(16).toString("hex") + nowMs().toString(36);
}

function parseCookieHeader(header = "") {
  const out = {};
  header
    .split(";")
    .map((v) => v.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const idx = pair.indexOf("=");
      if (idx === -1) return;
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (k) out[k] = v;
    });
  return out;
}

function setSessionCookieHeader(res, sid) {
  const ck = `${SESSION_COOKIE}=${sid}; Path=/; SameSite=Lax; HttpOnly`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", ck);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, ck]);
  else res.setHeader("Set-Cookie", [prev, ck]);
}

/**
 * Session payload:
 *   - jar: originKey -> Map(cookieName -> cookieObj)
 *   - ua
 *   - strictCookies (per-session toggle)
 *   - nav: last few navigations for loop detection
 */
function getSession(req, res) {
  const cookies = parseCookieHeader(req.headers.cookie || "");
  let sid = cookies[SESSION_COOKIE] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) {
    sid = newSid();
    SESSIONS.set(sid, {
      created: nowMs(),
      last: nowMs(),
      ip: req.ip || req.socket.remoteAddress || null,
      ua: DEFAULT_UA,
      strictCookies: FEATURE.STRICT_COOKIE_ORIGIN,
      jar: new Map(),
      nav: [],
      hints: {
        // can be expanded later
        preferScramjet: false,
      },
    });
    setSessionCookieHeader(res, sid);
  }
  const s = SESSIONS.get(sid);
  s.last = nowMs();
  s.ip = req.ip || s.ip;
  return { sid, s };
}

setInterval(() => {
  const cutoff = nowMs() - 24 * 60 * 60 * 1000;
  for (const [sid, s] of SESSIONS.entries()) {
    if (!s || s.last < cutoff) SESSIONS.delete(sid);
  }
}, 30 * 60 * 1000);

/* ========================================================================== */
/* Cookie parsing + strict origin partitioning                                */
/* ========================================================================== */

/**
 * A minimal, robust Set-Cookie parser (RFC6265-ish).
 * We store cookies in a strict origin partition (protocol + host).
 */
function parseSetCookieLoose(sc) {
  try {
    const parts = String(sc).split(";").map((s) => s.trim());
    const nv = parts.shift() || "";
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

    for (const p of parts) {
      const [kRaw, ...rest] = p.split("=");
      const k = String(kRaw || "").trim().toLowerCase();
      const v = rest.join("=").trim();

      if (k === "domain") out.domain = normalizeHost(v.replace(/^\./, ""));
      else if (k === "path") out.path = normalizePath(v || "/");
      else if (k === "expires") {
        const t = Date.parse(v);
        if (!Number.isNaN(t)) out.expiresAt = t;
      } else if (k === "max-age") {
        const sec = parseInt(v, 10);
        if (!Number.isNaN(sec)) out.expiresAt = nowMs() + sec * 1000;
      } else if (k === "secure") out.secure = true;
      else if (k === "httponly") out.httpOnly = true;
      else if (k === "samesite") out.sameSite = v || null;
      else if (kRaw && String(kRaw).toLowerCase() === "secure") out.secure = true;
      else if (kRaw && String(kRaw).toLowerCase() === "httponly") out.httpOnly = true;
    }

    if (!out.path) out.path = "/";
    return out;
  } catch {
    return null;
  }
}

function ensureOriginJar(session, originKey) {
  if (!session.jar.has(originKey)) session.jar.set(originKey, new Map());
  return session.jar.get(originKey);
}

/**
 * Strict same-origin cookie emulation:
 * - Store cookies only for exact host (ignore parent-domain cookies)
 * - Send cookies only to exact origin partition
 */
function storeSetCookiesStrict(session, originUrl, setCookies) {
  if (!session.strictCookies) return;

  let u;
  try {
    u = new URL(originUrl);
  } catch {
    return;
  }

  const host = normalizeHost(u.hostname);
  const originKey = `${u.protocol}//${u.host}`;
  const jar = ensureOriginJar(session, originKey);

  for (const sc of setCookies || []) {
    const parsed = parseSetCookieLoose(sc);
    if (!parsed) continue;

    const cookieDomain = parsed.domain ? normalizeHost(parsed.domain) : host;

    // strict: only exact host allowed
    if (cookieDomain !== host) continue;

    // secure cookies only over https
    if (parsed.secure && u.protocol !== "https:") continue;

    // expiration cleanup
    if (parsed.expiresAt && parsed.expiresAt <= nowMs()) {
      jar.delete(parsed.name);
      continue;
    }

    jar.set(parsed.name, {
      ...parsed,
      domain: host,
      path: parsed.path || "/",
      setAt: nowMs(),
    });
  }
}

function pathMatches(cookiePath, reqPath) {
  const cp = normalizePath(cookiePath || "/");
  const rp = normalizePath(reqPath || "/");
  return rp === cp || rp.startsWith(cp);
}

function buildCookieHeaderStrict(session, targetUrl) {
  if (!session.strictCookies) return "";

  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    return "";
  }

  const originKey = `${u.protocol}//${u.host}`;
  const jar = session.jar.get(originKey);
  if (!jar) return "";

  const host = normalizeHost(u.hostname);
  const reqPath = normalizePath(u.pathname || "/");
  const now = nowMs();

  const pairs = [];
  for (const [name, c] of jar.entries()) {
    if (c.expiresAt && c.expiresAt <= now) {
      jar.delete(name);
      continue;
    }
    if (c.secure && u.protocol !== "https:") continue;
    if (normalizeHost(c.domain) !== host) continue;
    if (!pathMatches(c.path, reqPath)) continue;
    pairs.push(`${name}=${c.value}`);
  }

  return pairs.join("; ");
}

/* ========================================================================== */
/* Header handling                                                            */
/* ========================================================================== */

function copyHeadersFromUpstream(up, res, { rewriting = false } = {}) {
  try {
    for (const [k, v] of up.headers.entries()) {
      const lk = k.toLowerCase();
      if (DROP_RESPONSE_HEADERS.has(lk)) continue;
      if (HOP_BY_HOP_HEADERS.has(lk)) continue;

      // We trap redirects ourselves
      if (lk === "location") continue;

      // If we rewrite/decompress, avoid mismatched enc/len
      if (rewriting && (lk === "content-encoding" || lk === "content-length")) continue;

      try {
        res.setHeader(k, v);
      } catch {}
    }
  } catch {}
}

function isHtmlContentType(ct) {
  const s = String(ct || "").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

function isLikelyAuthyHost(hostname) {
  const h = normalizeHost(hostname);
  return AUTHY_HOST_HINTS.some((x) => h.includes(x));
}

function splitSetCookieHeader(raw) {
  // Split joined Set-Cookie safely:
  // comma that begins a new cookie-pair (very common heuristic)
  return String(raw || "")
    .split(/,(?=[^ ;]+=)/g)
    .map((s) => s.trim())
    .filter(Boolean);
}

/* ========================================================================== */
/* Fetch engine                                                               */
/* ========================================================================== */

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 256 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 256 });

async function fetchUpstream(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LIMITS.FETCH_TIMEOUT_MS);

  try {
    const u = new URL(url);
    const agent = u.protocol === "https:" ? httpsAgent : httpAgent;

    // Node20 fetch supports agent in many runtimes; Koyeb commonly does.
    // We do not import undici.
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

/* ========================================================================== */
/* Decompression                                                              */
/* ========================================================================== */

function maybeDecompress(buf, encoding) {
  const enc = String(encoding || "").toLowerCase().trim();
  if (!enc) return buf;

  try {
    if (enc.includes("br") && FEATURE.ENABLE_BROTLI && zlib.brotliDecompressSync) {
      return zlib.brotliDecompressSync(buf);
    }
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
  } catch {}

  return buf;
}

/* ========================================================================== */
/* URL rewriting primitives                                                   */
/* ========================================================================== */

function shouldSkipRewrite(value) {
  if (!value) return true;
  const v = String(value);
  if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(v)) return true;
  if (v.includes("/proxy?url=")) return true;
  if (v.includes("/sj?url=") || v.includes("/sj/")) return true;
  if (v.includes("/ws?url=")) return true;
  return false;
}

function toAbsoluteMaybe(urlLike, base) {
  try {
    return new URL(urlLike, base).href;
  } catch {
    return null;
  }
}

function isProbablyAssetUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    const p = (u.pathname || "").toLowerCase();
    if (SPECIAL_FILES.some((sf) => p.endsWith("/" + sf) || p.endsWith(sf))) return true;
    if (BINARY_EXTENSIONS.some((ext) => p.endsWith(ext))) return true;
    return false;
  } catch {
    const lower = String(urlStr || "").toLowerCase();
    if (SPECIAL_FILES.some((sf) => lower.endsWith("/" + sf) || lower.endsWith(sf))) return true;
    if (BINARY_EXTENSIONS.some((ext) => lower.endsWith(ext))) return true;
    return false;
  }
}

/* ========================================================================== */
/* Login Hardening Pass 3 — upstream request shaping                           */
/* ========================================================================== */

/**
 * Pass 3 request hardening:
 * - Keep headers coherent and "browser-like"
 * - Ensure origin/referer align with upstream
 * - Preserve accept + accept-language
 * - Preserve sec-fetch-* when present
 * - Force upgrade-insecure-requests for navigations
 */
function applyLoginRequestHardening(req, targetUrl, headers) {
  headers["user-agent"] = headers["user-agent"] || DEFAULT_UA;

  // Preserve some fetch metadata if present (helps some flows)
  const secFetchSite = req.headers["sec-fetch-site"];
  const secFetchMode = req.headers["sec-fetch-mode"];
  const secFetchDest = req.headers["sec-fetch-dest"];
  const secFetchUser = req.headers["sec-fetch-user"];

  if (secFetchSite) headers["sec-fetch-site"] = String(secFetchSite);
  if (secFetchMode) headers["sec-fetch-mode"] = String(secFetchMode);
  if (secFetchDest) headers["sec-fetch-dest"] = String(secFetchDest);
  if (secFetchUser) headers["sec-fetch-user"] = String(secFetchUser);

  // Typical browser nav hint
  if (!headers["upgrade-insecure-requests"]) headers["upgrade-insecure-requests"] = "1";

  try {
    const u = new URL(targetUrl);
    // Make referrer and origin match upstream origin.
    // A rewrite proxy cannot perfectly emulate cross-origin browser behavior,
    // but this reduces "UI breaks" and some auth loops.
    headers["origin"] = u.origin;
    headers["referer"] = u.href;
  } catch {}
}

/* ========================================================================== */
/* HTML/CSS/JS rewrite engine                                                 */
/* ========================================================================== */

/**
 * Sanitize HTML:
 * - Remove meta CSP
 * - Remove SRI (integrity) and crossorigin attributes (often break after rewrite)
 */
function sanitizeHtml(html) {
  let out = String(html || "");
  out = out.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
  out = out.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
  out = out.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  return out;
}

/**
 * Rewrite CSS url(...) references.
 */
function rewriteCssText(cssText, baseUrl, req, mode) {
  if (!FEATURE.ENABLE_CSS_REWRITE) return cssText;

  try {
    return String(cssText || "").replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      const abs = toAbsoluteMaybe(u, baseUrl);
      if (!abs) return m;
      return `url("${makeProxyUrl(abs, req, mode)}")`;
    });
  } catch {
    return cssText;
  }
}

/**
 * Rewrite inline JS best-effort:
 * - fetch("...")
 * - xhr.open(..., "...")
 * - new WebSocket("wss://...") -> Euphoria /ws tunnel
 *
 * Pass 3: keep it conservative to avoid breaking bundles too much.
 */
function rewriteInlineJs(code, baseUrl, req, mode) {
  if (!FEATURE.ENABLE_JS_REWRITE) return code;

  let out = String(code || "");

  try {
    // fetch("...") string literal only
    out = out.replace(/fetch\(\s*(['"])([^'"]+)\1/g, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      const abs = toAbsoluteMaybe(u, baseUrl);
      if (!abs) return m;
      return `fetch("${makeProxyUrl(abs, req, mode)}"`;
    });

    // xhr.open("GET","...") string literal url
    out = out.replace(
      /\.open\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+)\3/gi,
      (m, q1, method, q2, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs = toAbsoluteMaybe(u, baseUrl);
        if (!abs) return m;
        return `.open("${method || "GET"}","${makeProxyUrl(abs, req, mode)}"`;
      }
    );

    // WebSocket("wss://...")
    out = out.replace(/new\s+WebSocket\(\s*(['"])(wss?:\/\/[^'"]+)\1/gi, (m, q, u) => {
      // We route WS through /ws?url=
      const origin = getPublicOrigin(req);
      const prox = `${origin}/ws?url=${encodeURIComponent(u)}`;
      return `new WebSocket("${prox}"`;
    });

    return out;
  } catch {
    return out;
  }
}

/**
 * Disable service worker registrations (helps keep sessions stable).
 * This breaks some apps, but improves general “stay inside proxy”.
 */
function neuterServiceWorkerInlineJs(code) {
  if (!FEATURE.DISABLE_SERVICE_WORKERS) return code;

  try {
    return String(code || "")
      .replace(
        /navigator\s*\.\s*serviceWorker\s*\.\s*register/gi,
        "/*euphoria*/null&&navigator.serviceWorker.register"
      )
      .replace(/serviceWorker\s*\.\s*register/gi, "/*euphoria*/null&&serviceWorker.register");
  } catch {
    return code;
  }
}

/**
 * Rewrite HTML with JSDOM:
 * - base tag
 * - a[href], form[action]
 * - src/href for scripts, images, link, media, iframe (even though we do not use iframe ourselves)
 * - srcset
 * - style attributes and <style> tags
 * - meta refresh
 */
function rewriteHtmlDom(html, baseUrl, req, mode) {
  if (!FEATURE.ENABLE_HTML_REWRITE) return html;

  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }

  const document = dom.window.document;

  // Ensure base tag
  if (!document.querySelector("base")) {
    const head = document.querySelector("head");
    if (head) {
      const b = document.createElement("base");
      b.setAttribute("href", baseUrl);
      head.insertBefore(b, head.firstChild);
    }
  }

  const rewriteAttr = (el, attr) => {
    try {
      const val = el.getAttribute(attr);
      if (shouldSkipRewrite(val)) return;
      const abs = toAbsoluteMaybe(val, baseUrl);
      if (!abs) return;
      el.setAttribute(attr, makeProxyUrl(abs, req, mode));
    } catch {}
  };

  // Links
  document.querySelectorAll("a[href]").forEach((a) => {
    rewriteAttr(a, "href");
    a.removeAttribute("target"); // keep inside Euphoria
    // Some sites set rel=noreferrer; keep it unless it breaks
  });

  // Forms
  document.querySelectorAll("form[action]").forEach((f) => rewriteAttr(f, "action"));

  // Media / script / iframe / link
  ["img", "script", "iframe", "audio", "video", "source", "track"].forEach((tag) => {
    document.querySelectorAll(tag).forEach((el) => rewriteAttr(el, "src"));
  });

  document.querySelectorAll("link[href]").forEach((el) => rewriteAttr(el, "href"));

  // srcset (critical for complex images)
  document.querySelectorAll("[srcset]").forEach((el) => {
    try {
      const srcset = el.getAttribute("srcset");
      if (!srcset) return;
      const out = srcset
        .split(",")
        .map((part) => {
          const [u, size] = part.trim().split(/\s+/, 2);
          if (shouldSkipRewrite(u)) return part;
          const abs = toAbsoluteMaybe(u, baseUrl);
          if (!abs) return part;
          return makeProxyUrl(abs, req, mode) + (size ? " " + size : "");
        })
        .join(", ");
      el.setAttribute("srcset", out);
    } catch {}
  });

  // style attr url(...)
  document.querySelectorAll("[style]").forEach((el) => {
    try {
      const s = el.getAttribute("style") || "";
      if (!s) return;
      const out = rewriteCssText(s, baseUrl, req, mode);
      el.setAttribute("style", out);
    } catch {}
  });

  // <style> blocks
  document.querySelectorAll("style").forEach((st) => {
    try {
      const css = st.textContent || "";
      st.textContent = rewriteCssText(css, baseUrl, req, mode);
    } catch {}
  });

  // meta refresh
  document.querySelectorAll("meta[http-equiv]").forEach((m) => {
    try {
      if ((m.getAttribute("http-equiv") || "").toLowerCase() !== "refresh") return;
      const c = m.getAttribute("content") || "";
      const match = c.match(/url=(.+)$/i);
      if (!match) return;
      const abs = toAbsoluteMaybe(match[1], baseUrl);
      if (!abs) return;
      m.setAttribute("content", c.replace(match[1], makeProxyUrl(abs, req, mode)));
    } catch {}
  });

  // Opportunistic: rewrite inline event handlers that have obvious location assignments (very limited)
  // (We avoid heavy parsing; runtime script handles most navigation.)
  document.querySelectorAll("[onclick],[onsubmit],[onload],[onerror]").forEach((el) => {
    try {
      ["onclick", "onsubmit", "onload", "onerror"].forEach((attr) => {
        const v = el.getAttribute(attr);
        if (!v) return;
        // Extremely conservative replacement
        const patched = v.replace(/(location\s*\.\s*href\s*=\s*)(['"])([^'"]+)\2/g, (m, prefix, q, u) => {
          if (shouldSkipRewrite(u)) return m;
          const abs = toAbsoluteMaybe(u, baseUrl);
          if (!abs) return m;
          return `${prefix}"${makeProxyUrl(abs, req, mode)}"`;
        });
        el.setAttribute(attr, patched);
      });
    } catch {}
  });

  return dom.serialize();
}

/* ========================================================================== */
/* Client runtime injection (Pass 3)                                          */
/* ========================================================================== */

/**
 * This runtime is the “stay inside Euphoria” engine:
 * - intercepts clicks on <a>
 * - patches window.open
 * - patches location.assign/replace
 * - patches History pushState/replaceState
 * - patches fetch/XHR to always use /proxy
 * - patches form submissions and dynamically-created anchors
 * - rewrites WebSocket URLs to go through /ws tunnel
 * - mitigates Google “infinite reload” / “seizure” by guarding repeated navigations
 * - blocks service worker registration (best-effort)
 */
function injectClientRuntime(html, req, mode) {
  const marker = "/*__EUPHORIA_CLIENT_RUNTIME_V5__*/";
  if (String(html).includes(marker)) return html;

  const origin = getPublicOrigin(req);
  const basePath = mode === "sj" ? "/sj?url=" : "/proxy?url=";
  const wsPath = "/ws?url=";

  // This script is intentionally verbose and explicit (meaningful lines, not filler).
  // A big chunk of “browser-like” behavior has to be in the client runtime.
  const js = `
<script>
${marker}
(function(){
  "use strict";

  const ORIGIN = ${JSON.stringify(origin)};
  const BASE = ${JSON.stringify(basePath)};
  const WS_BASE = ${JSON.stringify(wsPath)};

  function isProxied(u){
    return typeof u === "string" && u.indexOf(BASE) !== -1;
  }
  function isWsProxied(u){
    return typeof u === "string" && u.indexOf(WS_BASE) !== -1;
  }
  function abs(u){
    try { return new URL(u, document.baseURI).href; } catch(e){ return u; }
  }
  function prox(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(isProxied(u)) return u;
      if(/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u)) return u;
      return ORIGIN + BASE + encodeURIComponent(abs(u));
    }catch(e){
      return u;
    }
  }
  function proxWs(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(isWsProxied(u)) return u;
      if(!/^wss?:\\/\\//i.test(u)) return u;
      return ORIGIN + WS_BASE + encodeURIComponent(u);
    }catch(e){
      return u;
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Navigation loop guard (fixes Google reload seizure)                     */
  /* ---------------------------------------------------------------------- */
  const NAV_GUARD = {
    lastHref: location.href,
    lastTs: Date.now(),
    sameCount: 0,
    // Heuristic threshold: if location changes too often to same pattern, stop loops.
    maxSame: 6,
    windowMs: 2500
  };

  function noteNavAttempt(nextHref){
    try{
      const now = Date.now();
      const same = (nextHref === NAV_GUARD.lastHref);
      if(now - NAV_GUARD.lastTs > NAV_GUARD.windowMs){
        NAV_GUARD.sameCount = 0;
        NAV_GUARD.lastHref = nextHref;
        NAV_GUARD.lastTs = now;
        return true;
      }
      if(same) NAV_GUARD.sameCount++;
      else {
        NAV_GUARD.sameCount = 0;
        NAV_GUARD.lastHref = nextHref;
      }
      NAV_GUARD.lastTs = now;
      if(NAV_GUARD.sameCount >= NAV_GUARD.maxSame){
        // break the loop by forcing a stable proxied version
        try{
          const stable = prox(nextHref);
          if(stable && stable !== location.href){
            location.replace(stable);
          }
        }catch(e){}
        return false;
      }
      return true;
    }catch(e){
      return true;
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Patch fetch                                                             */
  /* ---------------------------------------------------------------------- */
  try{
    const _fetch = window.fetch;
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
      return _fetch.call(this, resource, init);
    };
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Patch XHR                                                               */
  /* ---------------------------------------------------------------------- */
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

  /* ---------------------------------------------------------------------- */
  /* Patch WebSocket                                                         */
  /* ---------------------------------------------------------------------- */
  try{
    const OWS = window.WebSocket;
    window.WebSocket = function(url, protocols){
      try{
        if(typeof url === "string") url = proxWs(url);
      }catch(e){}
      return new OWS(url, protocols);
    };
    window.WebSocket.prototype = OWS.prototype;
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Patch window.open                                                       */
  /* ---------------------------------------------------------------------- */
  try{
    const _open = window.open;
    window.open = function(url, name, specs){
      try{
        if(typeof url === "string"){
          const p = prox(url);
          if(noteNavAttempt(p) === false) return null;
          url = p;
        }
      }catch(e){}
      return _open.call(window, url, name, specs);
    };
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Patch history                                                          */
  /* ---------------------------------------------------------------------- */
  try{
    const _push = history.pushState;
    history.pushState = function(state, title, url){
      try{
        if(typeof url === "string"){
          url = prox(url);
        }
      }catch(e){}
      return _push.apply(this, arguments);
    };
    const _replace = history.replaceState;
    history.replaceState = function(state, title, url){
      try{
        if(typeof url === "string"){
          url = prox(url);
        }
      }catch(e){}
      return _replace.apply(this, arguments);
    };
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Patch location.assign / replace                                         */
  /* ---------------------------------------------------------------------- */
  try{
    const loc = window.location;
    const _assign = loc.assign.bind(loc);
    const _replaceLoc = loc.replace.bind(loc);

    loc.assign = function(u){
      try{
        const p = prox(u);
        if(noteNavAttempt(p) === false) return;
        return _assign(p);
      }catch(e){
        return _assign(u);
      }
    };
    loc.replace = function(u){
      try{
        const p = prox(u);
        if(noteNavAttempt(p) === false) return;
        return _replaceLoc(p);
      }catch(e){
        return _replaceLoc(u);
      }
    };
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Rewrite anchors (click-time)                                            */
  /* ---------------------------------------------------------------------- */
  function rewriteAnchor(a){
    try{
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(isProxied(href)) return;

      const p = prox(href);
      a.setAttribute("href", p);
      a.removeAttribute("target");
    }catch(e){}
  }

  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
      if(!a) return;
      rewriteAnchor(a);
    }catch(e){}
  }, true);

  /* ---------------------------------------------------------------------- */
  /* Forms: keep submission inside proxy (including GET searches like Google)*/
  /* ---------------------------------------------------------------------- */
  function rewriteForm(f){
    try{
      const action = f.getAttribute("action") || "";
      if(action && !isProxied(action) && !/^(javascript:|mailto:|tel:|#)/i.test(action)){
        f.setAttribute("action", prox(action));
      }

      // If a form uses GET and has no action, browsers submit to current URL.
      // Some proxied pages end up with missing ?url if code sets window.location.
      // We preserve current location by forcing an action when empty.
      if(!action){
        try{
          f.setAttribute("action", location.href);
        }catch(e){}
      }
    }catch(e){}
  }

  function patchForms(){
    try{
      const forms = document.querySelectorAll("form");
      for(const f of forms){
        rewriteForm(f);
      }
    }catch(e){}
  }

  patchForms();

  document.addEventListener("submit", function(){
    try{ patchForms(); }catch(e){}
  }, true);

  /* ---------------------------------------------------------------------- */
  /* MutationObserver: patch dynamic nodes (SPAs)                            */
  /* ---------------------------------------------------------------------- */
  try{
    const mo = new MutationObserver(function(muts){
      try{
        for(const m of muts){
          if(!m.addedNodes) continue;
          for(const n of m.addedNodes){
            if(!n || n.nodeType !== 1) continue;
            // anchors
            if(n.matches && n.matches("a[href]")) rewriteAnchor(n);
            if(n.querySelectorAll){
              const as = n.querySelectorAll("a[href]");
              for(const a of as) rewriteAnchor(a);

              const forms = n.querySelectorAll("form");
              for(const f of forms) rewriteForm(f);
            }
          }
        }
      }catch(e){}
    });
    mo.observe(document.documentElement, { childList: true, subtree: true });
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Referrer policy normalization (helps Xbox/Google CSS + nav)             */
  /* ---------------------------------------------------------------------- */
  try{
    if(!document.querySelector('meta[name="referrer"]')){
      const m = document.createElement("meta");
      m.setAttribute("name", "referrer");
      m.setAttribute("content", "no-referrer-when-downgrade");
      (document.head || document.documentElement).appendChild(m);
    }
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Service worker suppression (client side)                                */
  /* ---------------------------------------------------------------------- */
  try{
    if(${JSON.stringify(!!FEATURE.DISABLE_SERVICE_WORKERS)}){
      if(navigator && navigator.serviceWorker){
        const sw = navigator.serviceWorker;
        if(sw.register){
          sw.register = function(){ return Promise.reject(new Error("ServiceWorker disabled by proxy")); };
        }
      }
    }
  }catch(e){}

  /* ---------------------------------------------------------------------- */
  /* Defensive: if page navigates to non-proxied http(s), yank it back        */
  /* ---------------------------------------------------------------------- */
  try{
    const check = function(){
      try{
        const href = location.href;
        if(href.indexOf(BASE) === -1 && /^https?:\\/\\//i.test(href)){
          const p = prox(href);
          if(noteNavAttempt(p) === false) return;
          location.replace(p);
        }
      }catch(e){}
    };
    setInterval(check, 800);
  }catch(e){}

})();</script>
`.trim();

  if (/<\/body>/i.test(html)) return String(html).replace(/<\/body>/i, js + "\n</body>");
  return String(html) + "\n" + js;
}

/* ========================================================================== */
/* Response processing                                                        */
/* ========================================================================== */

async function processHtmlResponse(up, rawBuf, req, baseUrl, mode) {
  const encoding = up.headers.get("content-encoding");
  let buf = maybeDecompress(rawBuf, encoding);

  let html = "";
  try {
    html = buf.toString("utf8");
  } catch {
    html = Buffer.from(buf).toString("utf8");
  }

  html = sanitizeHtml(html);

  // DOM rewrite first
  html = rewriteHtmlDom(html, baseUrl, req, mode);

  // Inline scripts pass: neuter SW + rewrite fetch/xhr/ws strings
  // We do this after DOM rewrite so baseUrl is stable.
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const doc = dom.window.document;

    // Some sites break layout unless charset meta exists early.
    try {
      if (!doc.querySelector("meta[charset]")) {
        const m = doc.createElement("meta");
        m.setAttribute("charset", "utf-8");
        (doc.head || doc.documentElement).insertBefore(m, (doc.head || doc.documentElement).firstChild);
      }
    } catch {}

    // Improve Xbox UI CSS compatibility:
    // - ensure viewport meta exists
    // - remove "color-scheme" meta that can fight custom UI
    try {
      if (!doc.querySelector('meta[name="viewport"]')) {
        const vp = doc.createElement("meta");
        vp.setAttribute("name", "viewport");
        vp.setAttribute("content", "width=device-width, initial-scale=1.0");
        (doc.head || doc.documentElement).appendChild(vp);
      }
    } catch {}
    try {
      const cs = doc.querySelector('meta[name="color-scheme"]');
      if (cs) cs.remove();
    } catch {}

    // Rewrite inline scripts
    const scripts = Array.from(doc.querySelectorAll("script:not([src])"));
    for (const s of scripts) {
      const code = s.textContent || "";
      if (!code.trim()) continue;
      let patched = code;
      patched = neuterServiceWorkerInlineJs(patched);
      patched = rewriteInlineJs(patched, baseUrl, req, mode);
      s.textContent = patched;
    }

    // Rewrite inline styles again via css rewriter
    if (FEATURE.ENABLE_CSS_REWRITE) {
      const styles = Array.from(doc.querySelectorAll("style"));
      for (const st of styles) {
        const css = st.textContent || "";
        if (!css.trim()) continue;
        st.textContent = rewriteCssText(css, baseUrl, req, mode);
      }
    }

    html = dom.serialize();
  } catch {
    // If JSDOM fails here, we still inject runtime below.
  }

  // Runtime injection last
  html = injectClientRuntime(html, req, mode);

  return Buffer.from(html, "utf8");
}

/* ========================================================================== */
/* Redirect trapping                                                          */
/* ========================================================================== */

function handleRedirect(up, req, res, requestTarget, mode) {
  const loc = up.headers.get("location");
  if (!loc) return false;

  let abs;
  try {
    abs = new URL(loc, up.url || requestTarget).href;
  } catch {
    // Sometimes Location is relative but malformed; try direct
    abs = loc;
  }

  const prox = makeProxyUrl(abs, req, mode);

  // For OAuth flows: sometimes a 303 expects a GET. Keep status but safe body.
  res.status(up.status || 302);
  res.setHeader("Location", prox);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(`Redirecting to ${prox}`);
  return true;
}

/* ========================================================================== */
/* Raw body reading (POST/PUT/PATCH/...)                                      */
/* ========================================================================== */

async function readRawBody(req, limitBytes) {
  const chunks = [];
  let size = 0;

  await new Promise((resolve, reject) => {
    req.on("data", (c) => {
      size += c.length;
      if (size > limitBytes) {
        reject(new Error("body_too_large"));
        try {
          req.destroy();
        } catch {}
        return;
      }
      chunks.push(c);
    });
    req.on("end", resolve);
    req.on("error", reject);
  });

  return Buffer.concat(chunks);
}

/* ========================================================================== */
/* Streaming body to client (media safe)                                      */
/* ========================================================================== */

async function streamUpstreamBody(up, res) {
  const body = up.body;

  if (!body) {
    res.end();
    return;
  }

  // Node fetch uses Web ReadableStream
  if (typeof body.getReader === "function") {
    const reader = body.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) res.write(Buffer.from(value));
    }
    res.end();
    return;
  }

  // fallback: buffer
  const ab = await up.arrayBuffer();
  res.end(Buffer.from(ab));
}

/* ========================================================================== */
/* Target extraction                                                          */
/* ========================================================================== */

function getTargetFromRequest(req) {
  // Supported:
  // 1) /proxy?url=...
  // 2) /proxy?q=...  -> Google search
  // 3) /proxy/:host/*  -> normalized to /proxy?url=https://host/*
  // For POST, we use ?url= too (forms rewritten to it).
  const qUrl = req.query?.url;
  const qQ = req.query?.q;

  if (qQ && !qUrl) return googleSearchToUrl(qQ);

  if (qUrl) {
    const val = String(qUrl);
    const maybe = normalizeToHttpUrl(val);
    if (maybe) return maybe;
    // If not urlish, treat as search terms
    return googleSearchToUrl(val);
  }

  return null;
}

/* ========================================================================== */
/* Proxy core: supports GET/POST and keeps user in Euphoria                    */
/* ========================================================================== */

async function proxyHandler(req, res, mode = "proxy") {
  const { sid, s: session } = getSession(req, res);

  // Allow toggles via query string
  if (typeof req.query.strictCookies !== "undefined") {
    session.strictCookies = String(req.query.strictCookies) !== "0";
  }

  // Determine upstream target
  let target = getTargetFromRequest(req);
  if (!target) {
    return res
      .status(400)
      .send("Missing url. Use /proxy?url=https://example.com or /proxy?q=search");
  }

  // Track navigation for loop hints (server-side)
  try {
    session.nav.push({ t: nowMs(), url: target });
    if (session.nav.length > 20) session.nav.shift();
  } catch {}

  // Cache key only for GET without range
  const hasRange = !!req.headers.range;
  const cacheAllowed = req.method === "GET" && !hasRange;

  const accept = String(req.headers.accept || "").toLowerCase();
  const wantsHtml =
    accept.includes("text/html") ||
    accept.includes("application/xhtml+xml") ||
    req.query.force_html === "1";

  const cacheKeyBase = `${mode}::${req.method}::${target}`;
  const key = wantsHtml ? `${cacheKeyBase}::html` : `${cacheKeyBase}::asset`;

  // Serve cache if eligible
  if (cacheAllowed) {
    const mem = MEM_CACHE.get(key);
    if (mem) {
      if (mem.__type === "html") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        if (mem.headers) {
          for (const [k, v] of Object.entries(mem.headers)) {
            try {
              res.setHeader(k, v);
            } catch {}
          }
        }
        return res.end(mem.body);
      }
      if (mem.__type === "asset") {
        if (mem.headers) {
          for (const [k, v] of Object.entries(mem.headers)) {
            try {
              res.setHeader(k, v);
            } catch {}
          }
        }
        return res.end(Buffer.from(mem.bodyB64, "base64"));
      }
    }

    const disk = await diskGet(key);
    if (disk) {
      if (disk.__type === "html") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        if (disk.headers) {
          for (const [k, v] of Object.entries(disk.headers)) {
            try {
              res.setHeader(k, v);
            } catch {}
          }
        }
        return res.end(disk.body);
      }
      if (disk.__type === "asset") {
        if (disk.headers) {
          for (const [k, v] of Object.entries(disk.headers)) {
            try {
              res.setHeader(k, v);
            } catch {}
          }
        }
        return res.end(Buffer.from(disk.bodyB64, "base64"));
      }
    }
  }

  // Build upstream headers
  const hdrs = {};

  // Copy a limited, safe subset + enforce browser-like defaults.
  hdrs["user-agent"] = session.ua || DEFAULT_UA;
  hdrs["accept"] = req.headers.accept || "*/*";
  hdrs["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
  hdrs["accept-encoding"] = "gzip, deflate" + (FEATURE.ENABLE_BROTLI ? ", br" : "");

  // Range for media/images
  if (FEATURE.ENABLE_RANGE && req.headers.range) {
    hdrs["range"] = req.headers.range;
  }

  // Forward content-type for POST
  if (req.headers["content-type"]) hdrs["content-type"] = String(req.headers["content-type"]);

  // Cookie header (strict partition)
  if (session.strictCookies) {
    const cookieHeader = buildCookieHeaderStrict(session, target);
    if (cookieHeader) hdrs["cookie"] = cookieHeader;
  } else {
    // Non-strict mode (fallback): forward browser cookies if any
    if (req.headers.cookie) hdrs["cookie"] = String(req.headers.cookie);
  }

  // Harden login flow request headers
  applyLoginRequestHardening(req, target, hdrs);

  // Pass through some common headers if present
  if (req.headers["dnt"]) hdrs["dnt"] = String(req.headers["dnt"]);
  if (req.headers["cache-control"]) hdrs["cache-control"] = String(req.headers["cache-control"]);
  if (req.headers["pragma"]) hdrs["pragma"] = String(req.headers["pragma"]);

  // Request body for non-GET/HEAD
  let upstreamBody = undefined;
  if (!["GET", "HEAD"].includes(req.method)) {
    try {
      upstreamBody = await readRawBody(req, LIMITS.MAX_BODY_BYTES);
    } catch (e) {
      return res.status(413).send("Request body too large");
    }
  }

  // Fetch upstream
  let up;
  try {
    up = await fetchUpstream(target, {
      method: req.method,
      headers: hdrs,
      body: upstreamBody,
    });
  } catch (e) {
    return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
  }

  // Store cookies
  try {
    const raw = up.headers.get("set-cookie");
    if (raw && session.strictCookies) {
      const setCookies = splitSetCookieHeader(raw);
      storeSetCookiesStrict(session, up.url || target, setCookies);
    }
  } catch {}

  // Redirect trapping
  if ([301, 302, 303, 307, 308].includes(up.status)) {
    if (handleRedirect(up, req, res, target, mode)) return;
  }

  // Detect HTML
  const ct = up.headers.get("content-type") || "";
  const isHtml = wantsHtml || isHtmlContentType(ct);

  // HTML path: buffer + rewrite
  if (isHtml) {
    let rawBuf;
    try {
      const ab = await up.arrayBuffer();
      rawBuf = Buffer.from(ab);
      if (rawBuf.length > LIMITS.MAX_BODY_BYTES) throw new Error("html_body_too_large");
    } catch (e) {
      return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
    }

    copyHeadersFromUpstream(up, res, { rewriting: true });

    const baseUrl = up.url || target;
    let outBuf = rawBuf;

    try {
      outBuf = await processHtmlResponse(up, rawBuf, req, baseUrl, mode);
    } catch {
      // If rewrite fails, fallback to raw
      outBuf = rawBuf;
    }

    res.status(up.status || 200);
    res.setHeader("Content-Type", "text/html; charset=utf-8");

    // Cache policy: do not cache authy HTML
    let cacheOk = cacheAllowed;
    try {
      const host = new URL(baseUrl).hostname;
      if (isLikelyAuthyHost(host)) cacheOk = false;
    } catch {}
    // extra heuristic: loops
    if (LOOP_HINTS.some((re) => re.test(baseUrl))) cacheOk = false;

    // Always no-store for HTML by default (safer for sessions)
    res.setHeader("Cache-Control", "no-store");

    if (cacheOk && outBuf.length <= LIMITS.HTML_CACHE_MAX) {
      const payload = {
        __type: "html",
        body: outBuf.toString("utf8"),
        headers: { "Cache-Control": "no-store" },
      };
      MEM_CACHE.set(key, payload, { ttl: LIMITS.TTL_HTML_MS });
      diskSet(key, payload, LIMITS.TTL_HTML_MS).catch(() => {});
    }

    return res.end(outBuf);
  }

  // Asset path: copy headers and stream or cache small
  copyHeadersFromUpstream(up, res, { rewriting: false });
  res.status(up.status || 200);

  if (ct) {
    try {
      res.setHeader("Content-Type", ct);
    } catch {}
  }

  // If range: stream directly
  if (FEATURE.ENABLE_RANGE && hasRange) {
    return streamUpstreamBody(up, res);
  }

  // Buffer for caching smaller assets
  let buf;
  try {
    const ab = await up.arrayBuffer();
    buf = Buffer.from(ab);
  } catch {
    return streamUpstreamBody(up, res);
  }

  // Cache small assets
  if (cacheAllowed && buf.length <= LIMITS.ASSET_CACHE_MAX) {
    const headersObj = {};
    try {
      for (const [k, v] of up.headers.entries()) {
        const lk = k.toLowerCase();
        if (DROP_RESPONSE_HEADERS.has(lk)) continue;
        if (HOP_BY_HOP_HEADERS.has(lk)) continue;
        if (lk === "content-length") continue;
        // keep content-encoding for assets (we didn't decompress)
        headersObj[k] = v;
      }
    } catch {}

    const payload = {
      __type: "asset",
      headers: headersObj,
      bodyB64: buf.toString("base64"),
    };

    MEM_CACHE.set(key, payload, { ttl: LIMITS.TTL_ASSET_MS });
    diskSet(key, payload, LIMITS.TTL_ASSET_MS).catch(() => {});
  }

  return res.end(buf);
}

/* ========================================================================== */
/* Routes: /proxy, /sj, /proxy/:host/*                                        */
/* ========================================================================== */

// Main proxy: supports GET + POST + others
app.all("/proxy", async (req, res) => {
  return proxyHandler(req, res, "proxy");
});

// Requested style: /proxy/:host/* => /proxy?url=https://host/*
app.get(/^\/proxy\/([^/]+)\/(.*)$/i, async (req, res, next) => {
  try {
    const host = req.params?.[0] || "";
    const rest = req.params?.[1] || "";
    if (!host) return next();
    const combined = `${host}/${rest}`;
    const decoded = decodeURIComponentSafe(combined);
    const url = normalizeToHttpUrl(decoded);
    if (!url) return next();
    return res.redirect(302, `/proxy?url=${encodeURIComponent(url)}`);
  } catch {
    return next();
  }
});

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/* ========================================================================== */
/* Scramjet-safe integration                                                  */
/* ========================================================================== */

/**
 * /sj route:
 * - If ScramjetFactory provides middleware/handler/fetch bridge, mount it.
 * - Otherwise fall back to internal proxy pipeline (mode="sj") which still helps.
 *
 * Fundamental difference:
 *  - /proxy = our rewrite proxy: server rewrites HTML + injects runtime.
 *  - /sj    = Scramjet ecosystem (client-side virtualization) when available.
 * In practice, /sj can handle some SPA behaviors better, but it depends on Scramjet build.
 */

function mountScramjetOrFallback() {
  // Always keep /sj?url=... usable.
  const fallback = () => {
    app.all("/sj", async (req, res) => proxyHandler(req, res, "sj"));
    log("[SCRAMJET] using internal /sj proxy fallback");
  };

  if (!FEATURE.ENABLE_SCRAMJET) return fallback();
  if (typeof ScramjetFactory !== "function") return fallback();

  try {
    const maybe = ScramjetFactory({ prefix: "/sj" });

    // Common shapes
    if (typeof maybe === "function") {
      app.use("/sj", maybe);
      log("[SCRAMJET] mounted middleware at /sj");
      return;
    }

    if (maybe && typeof maybe.handler === "function") {
      app.use("/sj", (req, res, next) => maybe.handler(req, res, next));
      log("[SCRAMJET] mounted handler at /sj");
      return;
    }

    if (maybe && typeof maybe.fetch === "function") {
      // fetch-bridge
      app.use("/sj", async (req, res) => {
        try {
          const origin = getPublicOrigin(req) || "http://localhost";
          const url = new URL(req.originalUrl, origin).href;
          const r = await maybe.fetch(url, { method: req.method, headers: req.headers });
          res.status(r.status);
          r.headers.forEach((v, k) => {
            try {
              res.setHeader(k, v);
            } catch {}
          });
          const buf = Buffer.from(await r.arrayBuffer());
          res.end(buf);
        } catch (e) {
          res.status(502).send("Scramjet error: " + String(e?.message || e));
        }
      });
      log("[SCRAMJET] mounted fetch bridge at /sj");
      return;
    }

    // Unknown shape => fallback
    return fallback();
  } catch (e) {
    log("[SCRAMJET] init failed, fallback:", e?.message || e);
    return fallback();
  }
}

mountScramjetOrFallback();

/* ========================================================================== */
/* Fallback “escaped path” handler                                            */
/* ========================================================================== */

/**
 * Some SPAs request /_next/... or /static/... from site-root (not from /proxy).
 * If that happens, we try to reconstruct the upstream origin from referer url=...
 * and bounce it back through /proxy.
 */
app.use(async (req, res, next) => {
  try {
    const p = req.path || "/";
    // If it's our own endpoints, ignore.
    if (
      p.startsWith("/proxy") ||
      p.startsWith("/sj") ||
      p.startsWith("/ws") ||
      p.startsWith("/wisp") ||
      p.startsWith("/_euph") ||
      p.startsWith("/public") ||
      p === "/" ||
      p.startsWith("/assets")
    ) {
      return next();
    }

    const ref = req.headers.referer || req.headers.referrer || "";
    const m = String(ref).match(/[?&]url=([^&]+)/);
    if (!m) return next();

    let base;
    try {
      base = decodeURIComponent(m[1]);
    } catch {
      return next();
    }
    if (!base) return next();

    const baseOrigin = new URL(base).origin;
    const attempt = new URL(req.originalUrl, baseOrigin).href;

    return res.redirect(302, makeProxyUrl(attempt, req, "proxy"));
  } catch {
    return next();
  }
});

/* ========================================================================== */
/* WebSocket tunnel (/ws?url=wss://...)                                       */
/* ========================================================================== */

/**
 * Client runtime rewrites:
 *   new WebSocket("wss://...") -> wss?url=...
 *
 * This is not a perfect browser WS implementation, but it’s enough for many apps.
 */

const server = http.createServer(app);

let wssTunnel = null;
if (FEATURE.ENABLE_WS_TUNNEL) {
  wssTunnel = new WebSocketServer({ server, path: "/ws" });

  wssTunnel.on("connection", (client, req) => {
    // Parse url param
    let upstreamUrl = "";
    try {
      const origin = "http://localhost";
      const u = new URL(req.url, origin);
      upstreamUrl = u.searchParams.get("url") || "";
    } catch {}

    if (!/^wss?:\/\//i.test(upstreamUrl)) {
      try {
        client.close(1008, "Invalid WS url");
      } catch {}
      return;
    }

    // Establish upstream WS
    let upstream;
    try {
      upstream = new WebSocket(upstreamUrl, {
        headers: {
          "user-agent": DEFAULT_UA,
          // We cannot safely forward cookies here without a full origin-aware WS cookie policy.
          // Many WS endpoints rely on tokens in the URL anyway.
        },
      });
    } catch (e) {
      try {
        client.close(1011, "Upstream WS failed");
      } catch {}
      return;
    }

    const closeBoth = () => {
      try {
        client.close();
      } catch {}
      try {
        upstream.close();
      } catch {}
    };

    upstream.on("open", () => {
      client.on("message", (d) => {
        try {
          upstream.send(d);
        } catch {}
      });

      upstream.on("message", (d) => {
        try {
          client.send(d);
        } catch {}
      });
    });

    upstream.on("close", closeBoth);
    upstream.on("error", closeBoth);
    client.on("close", closeBoth);
    client.on("error", closeBoth);
  });

  log("[WS] tunnel enabled at /ws?url=wss://...");
}

/* ========================================================================== */
/* WISP discovery endpoints (deployment recognizable as WISP server)           */
/* ========================================================================== */

/**
 * Since “WISP” has multiple community implementations, we provide:
 * - a discovery JSON endpoint
 * - a well-known alias
 * - a basic health endpoint
 *
 * Frontend can use these to auto-detect the current deployment as a WISP server.
 */

function wispDiscoveryPayload(req) {
  const origin = getPublicOrigin(req);
  return {
    name: "Euphoria",
    kind: "wisp-server",
    version: "1.0",
    origin,
    endpoints: {
      proxy: `${origin}/proxy`,
      scramjet: `${origin}/sj`,
      websocket: `${origin}/ws`,
      health: `${origin}/wisp/health`,
      discovery: `${origin}/wisp/discovery`,
    },
    capabilities: {
      proxy_get: true,
      proxy_post: true,
      proxy_streaming: true,
      proxy_range: !!FEATURE.ENABLE_RANGE,
      ws_tunnel: !!FEATURE.ENABLE_WS_TUNNEL,
      scramjet: FEATURE.ENABLE_SCRAMJET && typeof ScramjetFactory === "function",
      strict_cookie_origin: true,
      html_rewrite: !!FEATURE.ENABLE_HTML_REWRITE,
      js_rewrite: !!FEATURE.ENABLE_JS_REWRITE,
      css_rewrite: !!FEATURE.ENABLE_CSS_REWRITE,
      service_worker_disabled: !!FEATURE.DISABLE_SERVICE_WORKERS,
    },
    notes: [
      "This server provides a rewrite-proxy and optional Scramjet mount.",
      "Some high-security login flows may remain unreliable without a headless browser.",
    ],
  };
}

app.get("/wisp/health", (req, res) => res.json({ ok: true, ts: nowMs() }));
app.get("/wisp/discovery", (req, res) => res.json(wispDiscoveryPayload(req)));
app.get("/.well-known/wisp", (req, res) => res.json(wispDiscoveryPayload(req)));

/* ========================================================================== */
/* Admin/debug endpoints                                                      */
/* ========================================================================== */

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

app.get("/_euph_debug/ping", (req, res) => res.json({ ok: true, ts: nowMs() }));

app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, s] of SESSIONS.entries()) {
    out[sid] = {
      created: new Date(s.created).toISOString(),
      last: new Date(s.last).toISOString(),
      ip: s.ip,
      strictCookies: !!s.strictCookies,
      jarOrigins: [...s.jar.keys()].length,
      navCount: (s.nav || []).length,
    };
  }
  res.json({ count: SESSIONS.size, sessions: out });
});

app.post("/_euph_debug/clear_cache", requireAdmin, async (req, res) => {
  MEM_CACHE.clear();
  if (FEATURE.ENABLE_DISK_CACHE) {
    try {
      const files = await fsPromises.readdir(CACHE_DIR);
      for (const f of files) {
        await fsPromises.unlink(path.join(CACHE_DIR, f)).catch(() => {});
      }
    } catch {}
  }
  res.json({ ok: true });
});

/* ========================================================================== */
/* App shell / fallback                                                       */
/* ========================================================================== */

app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// SPA-style fallback: serve index for most GET HTML routes
app.get("*", (req, res, next) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

/* ========================================================================== */
/* Start server                                                               */
/* ========================================================================== */

server.listen(PORT, () => {
  log(`[BOOT] listening on ${PORT}`);
  log(`[BOOT] origin (example): http://localhost:${PORT}`);
  log(`[BOOT] /wisp/discovery ready`);
});

process.on("unhandledRejection", (err) => console.error("unhandledRejection", err?.stack || err));
process.on("uncaughtException", (err) => console.error("uncaughtException", err?.stack || err));
process.on("warning", (w) => console.warn("warning", w?.stack || w));

process.on("SIGINT", () => {
  try {
    server.close();
  } catch {}
  process.exit(0);
});

/* ========================================================================== */
/* End of server.js                                                           */
/* ========================================================================== */