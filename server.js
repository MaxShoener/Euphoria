// server.js — Euphoria Hybrid v4.0
// Production-grade hybrid proxy: (1) Basic “rewrite proxy” path (/proxy) + (2) Optional Scramjet mount (/sj)
// Node 20+, ESM. No iframes. Strong redirect trapping, range/media streaming, strict same-origin cookie emulation,
// tiered rewriting (fast/dom/strict), per-session settings, WS tunnel, caching, and stability guards.
//
// IMPORTANT REALITY NOTE (not fluff):
// A single backend cannot perfectly emulate a full browser for every modern site (esp. high-security login flows).
// This file gives the strongest “best shot” without headless Chromium, while staying deployable + stable.
//
// ──────────────────────────────────────────────────────────────────────────────
// Imports
// ──────────────────────────────────────────────────────────────────────────────

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
import { fileURLToPath } from "url";
import { EventEmitter } from "events";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import { JSDOM } from "jsdom";
import WebSocket, { WebSocketServer } from "ws";

// Scramjet: CommonJS-safe import (do not assume named exports)
import scramjetPkg from "@mercuryworkshop/scramjet";
const ScramjetFactory =
  scramjetPkg?.createScramjetServer ||
  scramjetPkg?.createServer ||
  scramjetPkg?.default?.createScramjetServer ||
  scramjetPkg?.default?.createServer ||
  null;

EventEmitter.defaultMaxListeners = 300;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ──────────────────────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────────────────────

const PORT = Number(process.env.PORT || 8000);
const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

const QUIET_LOGS = process.env.QUIET_LOGS === "1";
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const ENABLE_SCRAMJET = process.env.ENABLE_SCRAMJET !== "0";

// Avoid express-rate-limit “permissive trust proxy” validation error.
// Do NOT set trust proxy=true; use a hop-count (Koyeb commonly uses 1).
const TRUST_PROXY_HOPS = Number(process.env.TRUST_PROXY_HOPS || 1);

// Global Rate Limit
const RATE_LIMIT_GLOBAL = Number(process.env.RATE_LIMIT_GLOBAL || 900);

// Fetch / upstream
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 25 * 1024 * 1024);

// Rewriting CPU guards
const MAX_HTML_REWRITE_BYTES = Number(process.env.MAX_HTML_REWRITE_BYTES || 2 * 1024 * 1024); // beyond this, skip JSDOM
const MAX_DOM_REWRITE_BYTES = Number(process.env.MAX_DOM_REWRITE_BYTES || 900 * 1024); // prefer fast rewrite above this

// Cache sizes
const MEM_CACHE_ITEMS = Number(process.env.MEM_CACHE_ITEMS || 6000);
const HTML_CACHE_MAX = Number(process.env.HTML_CACHE_MAX || 700 * 1024);
const ASSET_CACHE_MAX = Number(process.env.ASSET_CACHE_MAX || 5 * 1024 * 1024);

const CACHE_TTL_HTML_MS = Number(process.env.CACHE_TTL_HTML_MS || 6 * 60 * 1000);
const CACHE_TTL_ASSET_MS = Number(process.env.CACHE_TTL_ASSET_MS || 60 * 60 * 1000);

const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

// Session / cookie behavior
const STRICT_COOKIES_DEFAULT = process.env.STRICT_COOKIES_DEFAULT !== "0";
const DISABLE_SERVICE_WORKERS = process.env.DISABLE_SERVICE_WORKERS !== "0";
const DEFAULT_REWRITE_MODE = process.env.DEFAULT_REWRITE_MODE || "auto"; // auto|fast|dom|strict

// Admin
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

// Header stripping
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

// Media / asset hints
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

const SPECIAL_FILES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

// ──────────────────────────────────────────────────────────────────────────────
// Logging
// ──────────────────────────────────────────────────────────────────────────────

function log(...args) {
  if (!QUIET_LOGS) console.log(...args);
}
function warn(...args) {
  if (!QUIET_LOGS) console.warn(...args);
}
function errlog(...args) {
  console.error(...args);
}
function nowMs() {
  return Date.now();
}

// ──────────────────────────────────────────────────────────────────────────────
// Disk Cache Init
// ──────────────────────────────────────────────────────────────────────────────

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// ──────────────────────────────────────────────────────────────────────────────
// Express App + Middleware
// ──────────────────────────────────────────────────────────────────────────────

const app = express();
app.set("trust proxy", TRUST_PROXY_HOPS);

app.use(cors({ origin: true, credentials: true }));
app.use(morgan("tiny"));
app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR, { index: false }));

// rate-limit guard: if proxy is trusted, enforce hop-count and keep default keyGenerator.
// In newer express-rate-limit versions, passing validate.trustProxy=false also works, but
// we avoid relying on that minor-version behavior.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: RATE_LIMIT_GLOBAL,
    standardHeaders: true,
    legacyHeaders: false,
    // safer: explicit key generator
    keyGenerator: (req) => {
      // trust proxy hop-count ensures req.ip is derived from x-forwarded-for correctly
      // but still avoid weird blank IP
      return req.ip || req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || "unknown";
    },
  })
);

// ──────────────────────────────────────────────────────────────────────────────
// Admin auth
// ──────────────────────────────────────────────────────────────────────────────

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

// ──────────────────────────────────────────────────────────────────────────────
// Public origin helper (fixes “redirects to localhost”)
// ──────────────────────────────────────────────────────────────────────────────

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

// ──────────────────────────────────────────────────────────────────────────────
// Cache (memory + disk)
// ──────────────────────────────────────────────────────────────────────────────

const MEM_CACHE = new LRUCache({ max: MEM_CACHE_ITEMS });

function cacheKey(s) {
  return Buffer.from(String(s)).toString("base64url");
}

async function diskGet(key) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(f)) return null;
    const raw = await fsPromises.readFile(f, "utf8");
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    if (nowMs() - obj.t > (obj.ttl || CACHE_TTL_HTML_MS)) return null;
    return obj.v;
  } catch {
    return null;
  }
}

async function diskSet(key, value, ttl) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(f, JSON.stringify({ v: value, t: nowMs(), ttl }), "utf8");
  } catch {}
}

// ──────────────────────────────────────────────────────────────────────────────
// Sessions + Strict same-origin cookie jar
// ──────────────────────────────────────────────────────────────────────────────
//
// Design: session.cookieJar is partitioned by originKey = `${protocol}//${host}`
// “Strict same-origin” means we only send cookies back to the exact originKey jar,
// and we ignore wide Domain cookies (parent domain). This improves safety and
// makes behavior deterministic behind a proxy.
//
// Note: perfect browser cookie semantics are more complex; this is the best
// non-browser emulation that remains stable.

const SESSION_COOKIE = "euphoria_sid";
const SESSIONS = new Map();

function newSid() {
  return crypto.randomBytes(16).toString("hex") + Date.now().toString(36);
}

function parseCookieHeader(header = "") {
  const out = {};
  header
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((p) => {
      const idx = p.indexOf("=");
      if (idx === -1) return;
      const k = p.slice(0, idx).trim();
      const v = p.slice(idx + 1).trim();
      if (k) out[k] = v;
    });
  return out;
}

function setSessionCookie(res, sid) {
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
      ip: req.ip || req.socket.remoteAddress || null,
      ua: DEFAULT_UA,
      cookieJar: new Map(), // originKey -> Map(name -> cookieObj)
      strictCookies: STRICT_COOKIES_DEFAULT,
      rewriteMode: DEFAULT_REWRITE_MODE, // auto|fast|dom|strict
      preferEngine: "auto", // auto|basic|scramjet
    });
    setSessionCookie(res, sid);
  }
  const s = SESSIONS.get(sid);
  s.last = nowMs();
  s.ip = req.ip || s.ip;
  return { sid, s };
}

// clean stale sessions
setInterval(() => {
  const cutoff = nowMs() - 24 * 60 * 60 * 1000;
  for (const [sid, s] of SESSIONS.entries()) {
    if (!s || s.last < cutoff) SESSIONS.delete(sid);
  }
}, 30 * 60 * 1000);

// Cookie helpers
function normalizeHost(h) {
  return String(h || "").trim().toLowerCase();
}
function normalizePath(p) {
  const s = String(p || "/");
  return s.startsWith("/") ? s : "/" + s;
}

// Split Set-Cookie correctly (best effort):
// - Node 20 Headers sometimes supports headers.getSetCookie()
// - Otherwise split on comma only when it looks like a new cookie pair
function splitSetCookieHeader(value) {
  return String(value || "")
    .split(/,(?=[^ ;]+=)/g)
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseSetCookieLoose(sc) {
  // returns { name,value,domain,path,expiresAt,secure,httpOnly,sameSite }
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
        if (!Number.isNaN(sec)) out.expiresAt = Date.now() + sec * 1000;
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
  if (!session.cookieJar.has(originKey)) session.cookieJar.set(originKey, new Map());
  return session.cookieJar.get(originKey);
}

function storeSetCookiesStrict(session, originUrl, setCookieValues) {
  // strict same-origin: accept only cookies matching exact host
  let u;
  try {
    u = new URL(originUrl);
  } catch {
    return;
  }
  const host = normalizeHost(u.hostname);
  const originKey = `${u.protocol}//${u.host}`;
  const jar = ensureOriginJar(session, originKey);

  for (const sc of setCookieValues || []) {
    const parsed = parseSetCookieLoose(sc);
    if (!parsed) continue;

    const cookieDomain = parsed.domain ? normalizeHost(parsed.domain) : host;

    // strict: only exact host (no parent-domain cookies)
    if (cookieDomain !== host) continue;

    // secure cookies only over https origin
    if (parsed.secure && u.protocol !== "https:") continue;

    // expiration
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

function domainMatches(cookieDomain, reqHost) {
  if (!cookieDomain) return false;
  const cd = normalizeHost(cookieDomain);
  const rh = normalizeHost(reqHost);
  return rh === cd || rh.endsWith("." + cd);
}

function pathMatches(cookiePath, reqPath) {
  const cp = normalizePath(cookiePath || "/");
  const rp = normalizePath(reqPath || "/");
  return rp === cp || rp.startsWith(cp);
}

function buildCookieHeaderStrict(session, targetUrl) {
  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    return "";
  }
  const originKey = `${u.protocol}//${u.host}`;
  const jar = session.cookieJar.get(originKey);
  if (!jar) return "";

  const host = normalizeHost(u.hostname);
  const pth = normalizePath(u.pathname || "/");
  const now = Date.now();

  const pairs = [];
  for (const [name, c] of jar.entries()) {
    if (c.expiresAt && c.expiresAt <= now) {
      jar.delete(name);
      continue;
    }
    if (c.secure && u.protocol !== "https:") continue;
    if (!domainMatches(c.domain, host)) continue;
    if (!pathMatches(c.path, pth)) continue;
    pairs.push(`${name}=${c.value}`);
  }
  return pairs.join("; ");
}

// ──────────────────────────────────────────────────────────────────────────────
// URL parsing + search shorthand
// ──────────────────────────────────────────────────────────────────────────────

function looksUrlish(input) {
  const s = String(input || "").trim();
  if (!s) return false;
  if (/^https?:\/\//i.test(s)) return true;
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/].*)?$/i.test(s)) return true;
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

  if (looksUrlish(s)) {
    try {
      return new URL("https://" + s).href;
    } catch {
      return null;
    }
  }

  return null;
}

function googleSearchUrl(q) {
  const t = String(q || "").trim();
  if (!t) return "https://www.google.com/";
  return "https://www.google.com/search?q=" + encodeURIComponent(t);
}

// Asset guess
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

function isHtmlContentType(ct) {
  const s = String(ct || "").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

// ──────────────────────────────────────────────────────────────────────────────
// Proxy URL builder (mode-aware)
// ──────────────────────────────────────────────────────────────────────────────

function shouldSkipRewrite(v) {
  if (!v) return true;
  const s = String(v);
  if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(s)) return true;
  if (s.includes("/proxy?url=") || s.includes("/sj?url=")) return true;
  return false;
}

function toAbsMaybe(urlLike, base) {
  try {
    return new URL(urlLike, base).href;
  } catch {
    return null;
  }
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

// ──────────────────────────────────────────────────────────────────────────────
// Upstream client (http/https) with keep-alive + timeout + streaming
// ──────────────────────────────────────────────────────────────────────────────
//
// We do NOT rely on undici imports. We use http/https directly for predictable behavior.

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 256 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 256 });

function headersToObject(nodeHeaders) {
  const out = {};
  for (const [k, v] of Object.entries(nodeHeaders || {})) {
    if (v == null) continue;
    if (Array.isArray(v)) out[k] = v.join(", ");
    else out[k] = String(v);
  }
  return out;
}

function normalizeHeaderKey(k) {
  return String(k || "").toLowerCase();
}

function filterOutgoingHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) {
    const lk = normalizeHeaderKey(k);
    if (!lk) continue;
    if (HOP_BY_HOP_HEADERS.has(lk)) continue;
    // We control accept-encoding; never forward client connection headers.
    out[lk] = v;
  }
  return out;
}

function filterIncomingHeaders(rawHeaders, { rewriting }) {
  const out = {};
  for (const [k, v] of Object.entries(rawHeaders || {})) {
    const lk = normalizeHeaderKey(k);
    if (!lk) continue;
    if (HOP_BY_HOP_HEADERS.has(lk)) continue;
    if (DROP_RESPONSE_HEADERS.has(lk)) continue;
    if (lk === "location") continue; // we trap redirects
    if (rewriting) {
      if (lk === "content-encoding") continue;
      if (lk === "content-length") continue;
    }
    out[k] = v;
  }
  return out;
}

function requestUpstream(targetUrl, opts = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(targetUrl);
    } catch (e) {
      reject(e);
      return;
    }

    const isHttps = u.protocol === "https:";
    const lib = isHttps ? https : http;

    const headers = filterOutgoingHeaders(opts.headers || {});
    const method = (opts.method || "GET").toUpperCase();

    // Avoid sending a Host header that disagrees with URL host
    headers["host"] = u.host;

    const reqOptions = {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      method,
      path: u.pathname + (u.search || ""),
      headers,
      agent: isHttps ? httpsAgent : httpAgent,
    };

    const req = lib.request(reqOptions, (res) => {
      // Node incoming headers can have set-cookie as array
      resolve({
        status: res.statusCode || 0,
        statusText: res.statusMessage || "",
        headers: headersToObject(res.headers),
        rawHeaders: res.headers,
        stream: res,
        finalUrl: targetUrl, // we do not follow redirects here
      });
    });

    const timer = setTimeout(() => {
      try {
        req.destroy(new Error("upstream_timeout"));
      } catch {}
    }, FETCH_TIMEOUT_MS);

    req.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });

    req.on("close", () => {
      clearTimeout(timer);
    });

    // We only proxy GET/HEAD in this build (your UI is “browser-like GET navigation”).
    // POST for login forms is usually via <form> + fetch/XHR. Those will work because
    // the browser sends POST to /proxy which needs forwarding. We DO support it below.
    if (opts.body) {
      req.write(opts.body);
    }
    req.end();
  });
}

async function readStreamToBuffer(stream, limitBytes = MAX_BODY_BYTES) {
  const chunks = [];
  let total = 0;
  return new Promise((resolve, reject) => {
    stream.on("data", (chunk) => {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += b.length;
      if (total > limitBytes) {
        try {
          stream.destroy(new Error("body_too_large"));
        } catch {}
        reject(new Error("body_too_large"));
        return;
      }
      chunks.push(b);
    });
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", (e) => reject(e));
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// Decompression helpers
// ──────────────────────────────────────────────────────────────────────────────

function maybeDecompress(buf, encoding) {
  const enc = String(encoding || "").toLowerCase();
  try {
    if (enc.includes("br") && zlib.brotliDecompressSync) return zlib.brotliDecompressSync(buf);
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
  } catch {}
  return buf;
}

// ──────────────────────────────────────────────────────────────────────────────
// HTML sanitation + service worker neutralization
// ──────────────────────────────────────────────────────────────────────────────

function sanitizeHtml(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch {}
  return html;
}

function neuterServiceWorkerJs(code) {
  if (!DISABLE_SERVICE_WORKERS) return code;
  try {
    return code
      .replace(
        /navigator\s*\.\s*serviceWorker\s*\.\s*register/gi,
        "/*euph*/null&&navigator.serviceWorker.register"
      )
      .replace(/serviceWorker\s*\.\s*register/gi, "/*euph*/null&&serviceWorker.register");
  } catch {
    return code;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Rewrite modes: fast | dom | strict
// ──────────────────────────────────────────────────────────────────────────────
//
// auto:
//  - if html too large => fast
//  - else if likely SPA/login => strict
//  - else dom
//
// strict:
//  - dom rewrite + runtime patch + aggressive navigation trapping
//  - disables SW register in inline scripts
//  - adds meta referrer
//
// dom:
//  - standard jsdom rewrite + runtime patch
//
// fast:
//  - regex rewrite only (href/src/action/srcset/url(...) + meta refresh)
//  - runtime patch (still injected) but no dom parse
//
// NOTE: CPU usage: jsdom is expensive. Fast rewrite is used as fallback.

function pickRewriteMode(session, req, htmlSize, baseUrl, contentType) {
  const qMode = String(req.query.rewrite || "").trim().toLowerCase();
  const sessionMode = String(session.rewriteMode || "").trim().toLowerCase();

  const normalizeMode = (m) => (["auto", "fast", "dom", "strict"].includes(m) ? m : "auto");

  let mode = normalizeMode(qMode || sessionMode || DEFAULT_REWRITE_MODE || "auto");

  if (mode !== "auto") return mode;

  // auto heuristics
  if (htmlSize > MAX_DOM_REWRITE_BYTES) return "fast";
  if (htmlSize > MAX_HTML_REWRITE_BYTES) return "fast";

  // “authy” hosts: default to strict to keep navigation trapped and avoid SW issues
  try {
    const h = new URL(baseUrl).hostname.toLowerCase();
    if (
      h.includes("accounts.") ||
      h.includes("login.") ||
      h.includes("microsoftonline.") ||
      h.includes("live.com") ||
      h.includes("xbox.") ||
      h.includes("google.com") ||
      h.includes("auth")
    ) {
      return "strict";
    }
  } catch {}

  // content type check
  if (!isHtmlContentType(contentType)) return "fast";

  return "dom";
}

// ──────────────────────────────────────────────────────────────────────────────
// Fast rewrite engine (regex-based)
// ──────────────────────────────────────────────────────────────────────────────

function fastRewriteHtml(html, baseUrl, req, mode) {
  const origin = getPublicOrigin(req);
  const basePath = mode === "sj" ? "/sj?url=" : "/proxy?url=";

  const proxAbs = (u) => {
    try {
      const abs = new URL(u, baseUrl).href;
      return origin + basePath + encodeURIComponent(abs);
    } catch {
      return u;
    }
  };

  // href/src/action attributes
  html = html.replace(
    /\b(href|src|action)=("([^"]+)"|'([^']+)')/gi,
    (m, attr, quoted, d1, d2) => {
      const val = d1 || d2 || "";
      if (shouldSkipRewrite(val)) return m;
      const abs = toAbsMaybe(val, baseUrl);
      if (!abs) return m;
      const prox = makeProxyUrl(abs, req, mode);
      const q = quoted.startsWith("'") ? "'" : '"';
      return `${attr}=${q}${prox}${q}`;
    }
  );

  // srcset
  html = html.replace(/\bsrcset=("([^"]+)"|'([^']+)')/gi, (m, quoted, d1, d2) => {
    const srcset = d1 || d2 || "";
    const parts = srcset
      .split(",")
      .map((part) => {
        const trimmed = part.trim();
        if (!trimmed) return part;
        const [u, size] = trimmed.split(/\s+/, 2);
        if (shouldSkipRewrite(u)) return part;
        const abs = toAbsMaybe(u, baseUrl);
        if (!abs) return part;
        const prox = makeProxyUrl(abs, req, mode);
        return prox + (size ? " " + size : "");
      })
      .join(", ");
    const q = quoted.startsWith("'") ? "'" : '"';
    return `srcset=${q}${parts}${q}`;
  });

  // url(...) in CSS
  html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
    if (!u) return m;
    if (shouldSkipRewrite(u)) return m;
    const abs = toAbsMaybe(u, baseUrl);
    if (!abs) return m;
    return `url("${makeProxyUrl(abs, req, mode)}")`;
  });

  // meta refresh
  html = html.replace(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*>/gi, (tag) => {
    try {
      const m = tag.match(/content=(["'])(.*?)\1/i);
      if (!m) return tag;
      const content = m[2] || "";
      const match = content.match(/url=(.+)$/i);
      if (!match) return tag;
      const dest = match[1].replace(/['"]/g, "").trim();
      if (!dest) return tag;
      const abs = toAbsMaybe(dest, baseUrl);
      if (!abs) return tag;
      const prox = makeProxyUrl(abs, req, mode);
      const replaced = content.replace(match[1], prox);
      return tag.replace(m[0], `content="${replaced}"`);
    } catch {
      return tag;
    }
  });

  return html;
}

// ──────────────────────────────────────────────────────────────────────────────
// DOM rewrite engine (JSDOM)
// ──────────────────────────────────────────────────────────────────────────────

function domRewriteHtml(html, baseUrl, req, mode) {
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
      const abs = toAbsMaybe(val, baseUrl);
      if (!abs) return;
      el.setAttribute(attr, makeProxyUrl(abs, req, mode));
    } catch {}
  };

  // anchors
  document.querySelectorAll("a[href]").forEach((a) => {
    rewriteAttr(a, "href");
    a.removeAttribute("target");
  });

  // forms
  document.querySelectorAll("form[action]").forEach((f) => rewriteAttr(f, "action"));

  // media/scripts/iframes
  ["img", "script", "iframe", "audio", "video", "source", "track"].forEach((tag) => {
    document.querySelectorAll(tag).forEach((el) => rewriteAttr(el, "src"));
  });

  // link href
  document.querySelectorAll("link[href]").forEach((el) => rewriteAttr(el, "href"));

  // srcset
  document.querySelectorAll("[srcset]").forEach((el) => {
    try {
      const srcset = el.getAttribute("srcset");
      if (!srcset) return;
      const out = srcset
        .split(",")
        .map((part) => {
          const [u, size] = part.trim().split(/\s+/, 2);
          if (shouldSkipRewrite(u)) return part;
          const abs = toAbsMaybe(u, baseUrl);
          if (!abs) return part;
          return makeProxyUrl(abs, req, mode) + (size ? " " + size : "");
        })
        .join(", ");
      el.setAttribute("srcset", out);
    } catch {}
  });

  // inline style url(...)
  document.querySelectorAll("[style]").forEach((el) => {
    try {
      const s = el.getAttribute("style") || "";
      if (!s) return;
      const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs = toAbsMaybe(u, baseUrl);
        if (!abs) return m;
        return `url("${makeProxyUrl(abs, req, mode)}")`;
      });
      el.setAttribute("style", out);
    } catch {}
  });

  // <style> blocks
  document.querySelectorAll("style").forEach((st) => {
    try {
      let css = st.textContent || "";
      css = css.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs = toAbsMaybe(u, baseUrl);
        if (!abs) return m;
        return `url("${makeProxyUrl(abs, req, mode)}")`;
      });
      st.textContent = css;
    } catch {}
  });

  // meta refresh
  document.querySelectorAll("meta[http-equiv]").forEach((m) => {
    try {
      if ((m.getAttribute("http-equiv") || "").toLowerCase() !== "refresh") return;
      const c = m.getAttribute("content") || "";
      const match = c.match(/url=(.+)$/i);
      if (!match) return;
      const abs = toAbsMaybe(match[1], baseUrl);
      if (!abs) return;
      m.setAttribute("content", c.replace(match[1], makeProxyUrl(abs, req, mode)));
    } catch {}
  });

  return dom.serialize();
}

// ──────────────────────────────────────────────────────────────────────────────
// Inline JS rewrite (best effort; do not overreach)
// ──────────────────────────────────────────────────────────────────────────────

function rewriteInlineJs(code, baseUrl, req, mode) {
  try {
    // fetch("...")
    code = code.replace(/fetch\(\s*(['"])([^'"]+)\1/g, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      const abs = toAbsMaybe(u, baseUrl);
      if (!abs) return m;
      return `fetch("${makeProxyUrl(abs, req, mode)}"`;
    });

    // xhr.open("GET","...")
    code = code.replace(
      /\.open\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+)\3/gi,
      (m, q1, method, q2, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs = toAbsMaybe(u, baseUrl);
        if (!abs) return m;
        return `.open("${method || "GET"}","${makeProxyUrl(abs, req, mode)}"`;
      }
    );

    // "/api/.."
    code = code.replace(/(['"])(\/[^'"]+?)\1/g, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      const abs = toAbsMaybe(u, baseUrl);
      if (!abs) return m;
      return `"${makeProxyUrl(abs, req, mode)}"`;
    });

    return code;
  } catch {
    return code;
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client runtime injection (navigation trapping, SPA safety, button reliability)
// ──────────────────────────────────────────────────────────────────────────────

function injectClientRuntime(html, req, mode) {
  const marker = "/*__EUPHORIA_CLIENT_RUNTIME_V5__*/";
  if (html.includes(marker)) return html;

  const origin = getPublicOrigin(req);
  const basePath = mode === "sj" ? "/sj?url=" : "/proxy?url=";

  const js = `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(origin)};
  const BASE = ${JSON.stringify(basePath)};

  function isProxied(u){ return typeof u === "string" && u.includes(BASE); }
  function abs(u){ try{ return new URL(u, document.baseURI).href; }catch(e){ return u; } }
  function prox(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(isProxied(u)) return u;
      if(/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u)) return u;
      return ORIGIN + BASE + encodeURIComponent(abs(u));
    }catch(e){ return u; }
  }

  // fetch
  try{
    const ofetch = window.fetch;
    window.fetch = function(resource, init){
      try{
        if(typeof resource === "string") resource = prox(resource);
        else if(resource && resource.url && resource instanceof Request && !isProxied(resource.url)){
          resource = new Request(prox(resource.url), resource);
        }
      }catch(e){}
      return ofetch.call(this, resource, init);
    };
  }catch(e){}

  // XHR
  try{
    const OXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const x = new OXHR();
      const open = x.open;
      x.open = function(method, url){
        try{ if(typeof url === "string") url = prox(url); }catch(e){}
        return open.apply(this, arguments);
      };
      return x;
    };
  }catch(e){}

  // History API
  try{
    const p = history.pushState;
    history.pushState = function(state, title, url){
      try{ if(typeof url === "string") url = prox(url); }catch(e){}
      return p.apply(this, arguments);
    };
    const r = history.replaceState;
    history.replaceState = function(state, title, url){
      try{ if(typeof url === "string") url = prox(url); }catch(e){}
      return r.apply(this, arguments);
    };
  }catch(e){}

  // window.open
  try{
    const o = window.open;
    window.open = function(url, name, specs){
      try{ if(typeof url === "string") url = prox(url); }catch(e){}
      return o.call(this, url, name, specs);
    };
  }catch(e){}

  // location.assign/replace
  try{
    const loc = window.location;
    const assign = loc.assign.bind(loc);
    const replace = loc.replace.bind(loc);
    loc.assign = function(u){ return assign(prox(u)); };
    loc.replace = function(u){ return replace(prox(u)); };
  }catch(e){}

  // Patch forms (action attribute)
  function patchForms(){
    try{
      document.querySelectorAll("form[action]").forEach(f=>{
        const a = f.getAttribute("action");
        if(a && !isProxied(a) && !/^(javascript:|mailto:|tel:|#)/i.test(a)){
          f.setAttribute("action", prox(a));
        }
      });
    }catch(e){}
  }
  patchForms();
  document.addEventListener("submit", function(){ try{ patchForms(); }catch(e){} }, true);

  // Patch anchors at click time
  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
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

// ──────────────────────────────────────────────────────────────────────────────
// HTML pipeline
// ──────────────────────────────────────────────────────────────────────────────

function addStrictMeta(doc) {
  try {
    if (!doc.querySelector('meta[name="referrer"]')) {
      const m = doc.createElement("meta");
      m.setAttribute("name", "referrer");
      m.setAttribute("content", "no-referrer-when-downgrade");
      (doc.head || doc.documentElement).appendChild(m);
    }
  } catch {}
}

async function processHtml({ session, req, mode, upstreamUrl, contentType, bodyBuf }) {
  // decompress
  const enc = req.__upstreamContentEncoding || "";
  let buf = maybeDecompress(bodyBuf, enc);

  // decode
  let html = "";
  try {
    html = buf.toString("utf8");
  } catch {
    html = Buffer.from(buf).toString("utf8");
  }

  html = sanitizeHtml(html);

  // choose rewrite mode
  const rewriteMode = pickRewriteMode(session, req, html.length, upstreamUrl, contentType);

  // rewrite
  if (rewriteMode === "fast") {
    html = fastRewriteHtml(html, upstreamUrl, req, mode);
    html = injectClientRuntime(html, req, mode);
    return { html, rewriteMode };
  }

  // dom/strict
  const domHtml = domRewriteHtml(html, upstreamUrl, req, mode);
  let out = injectClientRuntime(domHtml, req, mode);

  // post-process inline scripts (js rewrite + sw neuter)
  // strict gets additional meta + more aggressive SW neutralization
  try {
    const dom2 = new JSDOM(out, { url: upstreamUrl, contentType: "text/html" });
    const doc2 = dom2.window.document;

    if (rewriteMode === "strict") addStrictMeta(doc2);

    const scripts = Array.from(doc2.querySelectorAll("script:not([src])"));
    for (const s of scripts) {
      try {
        let code = s.textContent || "";
        if (!code.trim()) continue;
        if (rewriteMode === "strict") code = neuterServiceWorkerJs(code);
        code = rewriteInlineJs(code, upstreamUrl, req, mode);
        s.textContent = code;
      } catch {}
    }

    out = dom2.serialize();
  } catch {}

  return { html: out, rewriteMode };
}

// ──────────────────────────────────────────────────────────────────────────────
// Redirect trapping (keep navigation inside Euphoria)
// ──────────────────────────────────────────────────────────────────────────────

function handleRedirect(up, req, res, targetUrl, mode) {
  const loc = up.headers["location"] || up.headers["Location"];
  if (!loc) return false;

  let abs = "";
  try {
    abs = new URL(String(loc), targetUrl).href;
  } catch {
    abs = String(loc);
  }

  const prox = makeProxyUrl(abs, req, mode);
  res.status(up.status || 302);
  res.setHeader("Location", prox);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(`Redirecting to ${prox}`);
  return true;
}

// ──────────────────────────────────────────────────────────────────────────────
// Streaming (media, range)
// ──────────────────────────────────────────────────────────────────────────────

async function streamUpstreamToClient(up, res) {
  // Pipe node stream
  return new Promise((resolve) => {
    up.stream.on("error", () => {
      try {
        res.end();
      } catch {}
      resolve();
    });
    up.stream.on("end", () => resolve());
    up.stream.pipe(res);
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// Proxy route factory (supports GET/POST/etc)
// ──────────────────────────────────────────────────────────────────────────────

function buildUpstreamHeaders(session, req, targetUrl) {
  const hdrs = {};

  // User agent
  hdrs["user-agent"] = session.ua || DEFAULT_UA;

  // Accept headers
  hdrs["accept"] = req.headers.accept || "*/*";
  hdrs["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";

  // Let upstream respond compressed; we may decompress for HTML rewriting.
  hdrs["accept-encoding"] = "gzip, deflate, br";

  // Range support (critical for “complex images” + video seeking)
  if (req.headers.range) hdrs["range"] = req.headers.range;

  // Origin & referer: best-effort coherence
  if (req.headers.referer) hdrs["referer"] = req.headers.referer;
  try {
    hdrs["origin"] = new URL(targetUrl).origin;
  } catch {}

  // Cookies
  if (session.strictCookies) {
    const cookieHeader = buildCookieHeaderStrict(session, targetUrl);
    if (cookieHeader) hdrs["cookie"] = cookieHeader;
  } else {
    // relaxed mode: send browser cookies for our own domain only (not very useful for upstream)
    // We intentionally do NOT forward client cookies to upstream across origins.
  }

  // Forward some client hints (helps modern UIs render “real” layout)
  const passthrough = [
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
    "upgrade-insecure-requests",
  ];
  for (const k of passthrough) {
    const v = req.headers[k];
    if (v) hdrs[k] = v;
  }

  return hdrs;
}

function shouldCacheHtml(session, upstreamUrl) {
  // Safer default: no-cache for auth-heavy hosts
  try {
    const h = new URL(upstreamUrl).hostname.toLowerCase();
    if (
      h.includes("accounts.") ||
      h.includes("login.") ||
      h.includes("microsoftonline.") ||
      h.includes("live.com") ||
      h.includes("xbox.") ||
      h.includes("auth")
    ) {
      return false;
    }
  } catch {}
  return true;
}

function parseTargetFromReq(req) {
  // /proxy?url=... or /proxy?q=...
  // If url is not urlish, treat as google search
  let target = null;

  if (req.query.q && !req.query.url) {
    target = googleSearchUrl(String(req.query.q));
  } else if (req.query.url) {
    const raw = String(req.query.url);
    target = normalizeToHttpUrl(raw) || googleSearchUrl(raw);
  }

  return target;
}

function makeProxyRoute(mode) {
  return async (req, res) => {
    const { s: session } = getSession(req, res);

    // Session toggles via query params (UI can set these)
    if (typeof req.query.strictCookies !== "undefined") {
      session.strictCookies = String(req.query.strictCookies) !== "0";
    }
    if (typeof req.query.rewrite !== "undefined") {
      const m = String(req.query.rewrite).trim().toLowerCase();
      if (["auto", "fast", "dom", "strict"].includes(m)) session.rewriteMode = m;
    }

    // Parse target
    const target = parseTargetFromReq(req);
    if (!target) {
      return res
        .status(400)
        .send("Missing url (use /proxy?url=https://example.com) or /proxy?q=search");
    }

    const accept = String(req.headers.accept || "").toLowerCase();
    const wantsHtml =
      accept.includes("text/html") || req.query.force_html === "1" || req.headers["x-euphoria-client"] === "1";

    const hasRange = !!req.headers.range;
    const cacheAllowed = req.method === "GET" && !hasRange;

    const cacheKeyBase = `${mode}::${target}`;
    const key = wantsHtml ? `${cacheKeyBase}::html` : `${cacheKeyBase}::asset`;

    // cache hit
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

    // Build upstream request
    const upstreamHeaders = buildUpstreamHeaders(session, req, target);

    // Forward request body for non-GET/HEAD
    let body = null;
    if (req.method !== "GET" && req.method !== "HEAD") {
      // Read raw body (express.json() can consume; but browser POSTs to /proxy often are form-encoded)
      // Best effort: if express parsed, reconstruct; else buffer stream.
      try {
        if (req.is("application/json") && req.body && Object.keys(req.body).length) {
          body = Buffer.from(JSON.stringify(req.body), "utf8");
          upstreamHeaders["content-type"] = upstreamHeaders["content-type"] || "application/json";
        } else if (req.body && typeof req.body === "object" && Object.keys(req.body).length) {
          // urlencoded
          const params = new URLSearchParams();
          for (const [k, v] of Object.entries(req.body)) params.append(k, String(v));
          body = Buffer.from(params.toString(), "utf8");
          upstreamHeaders["content-type"] =
            upstreamHeaders["content-type"] || "application/x-www-form-urlencoded;charset=UTF-8";
        } else {
          // raw stream fallback
          // NOTE: express may have already consumed the stream in some configurations.
          // We keep this fallback minimal.
        }
      } catch {}
    }

    // content-length for body
    if (body && !upstreamHeaders["content-length"]) upstreamHeaders["content-length"] = String(body.length);

    // Upstream request
    let up;
    try {
      up = await requestUpstream(target, {
        method: req.method,
        headers: upstreamHeaders,
        body,
      });
    } catch (e) {
      return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
    }

    // Store set-cookies (strict jar)
    try {
      let setCookies = [];
      const raw = up.rawHeaders?.["set-cookie"];
      if (Array.isArray(raw)) setCookies = raw;
      else if (typeof raw === "string") setCookies = splitSetCookieHeader(raw);
      else {
        // some servers use capitalized key
        const raw2 = up.rawHeaders?.["Set-Cookie"];
        if (Array.isArray(raw2)) setCookies = raw2;
        else if (typeof raw2 === "string") setCookies = splitSetCookieHeader(raw2);
      }

      if (session.strictCookies && setCookies.length) {
        storeSetCookiesStrict(session, target, setCookies);
      }
    } catch {}

    // Redirect trap
    if ([301, 302, 303, 307, 308].includes(up.status)) {
      if (handleRedirect(up, req, res, target, mode)) return;
    }

    // Decide HTML vs asset
    const ct = up.headers["content-type"] || up.headers["Content-Type"] || "";
    const isHtml = wantsHtml || isHtmlContentType(ct);

    // HTML pipeline: buffer -> rewrite -> send
    if (isHtml) {
      let rawBuf;
      try {
        rawBuf = await readStreamToBuffer(up.stream, MAX_BODY_BYTES);
      } catch (e) {
        return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
      }

      // guard: if huge, avoid rewriting
      const upstreamUrl = target;

      // store upstream content-encoding for decompression
      req.__upstreamContentEncoding = up.headers["content-encoding"] || up.headers["Content-Encoding"] || "";

      // copy headers (minus encoding/length)
      const hdrObj = filterIncomingHeaders(up.headers, { rewriting: true });
      for (const [k, v] of Object.entries(hdrObj)) {
        try {
          res.setHeader(k, v);
        } catch {}
      }

      // transform
      let outHtml = "";
      let rewriteMode = "none";
      try {
        const processed = await processHtml({
          session,
          req,
          mode,
          upstreamUrl,
          contentType: ct,
          bodyBuf: rawBuf,
        });
        outHtml = processed.html;
        rewriteMode = processed.rewriteMode;
      } catch (e) {
        // fallback: send raw (still trap nav via runtime? only if safe)
        try {
          const buf = maybeDecompress(rawBuf, req.__upstreamContentEncoding);
          outHtml = buf.toString("utf8");
        } catch {
          outHtml = rawBuf.toString("utf8");
        }
        outHtml = sanitizeHtml(outHtml);
        outHtml = injectClientRuntime(outHtml, req, mode);
        rewriteMode = "fallback";
      }

      res.status(up.status || 200);
      res.setHeader("Content-Type", "text/html; charset=utf-8");

      // default: no-store for dynamic sites
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Euphoria-Rewrite", rewriteMode);

      // Cache small HTML only when safe
      const canCacheHtml = cacheAllowed && shouldCacheHtml(session, upstreamUrl) && outHtml.length <= HTML_CACHE_MAX;
      if (canCacheHtml) {
        const payload = {
          __type: "html",
          body: outHtml,
          headers: {
            "Cache-Control": "no-store",
            "X-Euphoria-Rewrite": rewriteMode,
          },
        };
        MEM_CACHE.set(key, payload, { ttl: CACHE_TTL_HTML_MS });
        diskSet(key, payload, CACHE_TTL_HTML_MS).catch(() => {});
      }

      return res.end(outHtml);
    }

    // Asset/media pipeline: stream if range or big, otherwise buffer+cache
    // copy headers (no rewriting)
    const hdrObj = filterIncomingHeaders(up.headers, { rewriting: false });
    for (const [k, v] of Object.entries(hdrObj)) {
      try {
        res.setHeader(k, v);
      } catch {}
    }

    res.status(up.status || 200);
    if (ct) {
      try {
        res.setHeader("Content-Type", ct);
      } catch {}
    }

    // If range, always stream (important for video/audio + complex images)
    if (hasRange) {
      return streamUpstreamToClient(up, res);
    }

    // Buffer for caching
    let bodyBuf;
    try {
      bodyBuf = await readStreamToBuffer(up.stream, MAX_BODY_BYTES);
    } catch {
      // fallback: stream
      try {
        return streamUpstreamToClient(up, res);
      } catch {
        return res.end();
      }
    }

    // Cache small assets
    if (cacheAllowed && bodyBuf.length <= ASSET_CACHE_MAX) {
      const headersObj = {};
      for (const [k, v] of Object.entries(up.headers || {})) {
        const lk = normalizeHeaderKey(k);
        if (DROP_RESPONSE_HEADERS.has(lk)) continue;
        if (HOP_BY_HOP_HEADERS.has(lk)) continue;
        if (lk === "content-length") continue;
        headersObj[k] = v;
      }

      const payload = { __type: "asset", headers: headersObj, bodyB64: bodyBuf.toString("base64") };
      MEM_CACHE.set(key, payload, { ttl: CACHE_TTL_ASSET_MS });
      diskSet(key, payload, CACHE_TTL_ASSET_MS).catch(() => {});
    }

    return res.end(bodyBuf);
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Routes: /proxy (basic rewrite engine)
// ──────────────────────────────────────────────────────────────────────────────

app.all("/proxy", makeProxyRoute("proxy"));

// /proxy/:host/* clean-path normalization
function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}
app.get(/^\/proxy\/([^/]+)\/(.*)$/i, (req, res, next) => {
  try {
    const host = req.params?.[0] || "";
    const rest = req.params?.[1] || "";
    if (!host) return next();
    const combined = `${host}/${rest}`;
    const url = normalizeToHttpUrl(decodeURIComponentSafe(combined));
    if (!url) return next();
    return res.redirect(302, `/proxy?url=${encodeURIComponent(url)}`);
  } catch {
    return next();
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// Scramjet mount: /sj
// ──────────────────────────────────────────────────────────────────────────────
//
// Goal: mount if possible; otherwise fall back to internal /sj pipeline (same as /proxy but mode=sj).
// This keeps deployments stable even when Scramjet’s API shape differs.

if (ENABLE_SCRAMJET) {
  if (typeof ScramjetFactory === "function") {
    try {
      const maybeServer = ScramjetFactory({
        prefix: "/sj",
      });

      // Middleware form
      if (typeof maybeServer === "function") {
        app.use("/sj", maybeServer);
        log("[SCRAMJET] mounted middleware at /sj");
      } else if (maybeServer && typeof maybeServer.handler === "function") {
        app.use("/sj", (req, res, next) => maybeServer.handler(req, res, next));
        log("[SCRAMJET] mounted handler at /sj");
      } else if (maybeServer && typeof maybeServer.fetch === "function") {
        // Fetch bridge form
        app.use("/sj", async (req, res) => {
          try {
            const origin = getPublicOrigin(req) || "http://localhost";
            const url = new URL(req.originalUrl, origin);
            const r = await maybeServer.fetch(url.href, { method: req.method, headers: req.headers });
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
      } else {
        // Unknown shape: fallback internal
        app.all("/sj", makeProxyRoute("sj"));
        log("[SCRAMJET] unknown shape; using internal /sj proxy");
      }
    } catch (e) {
      app.all("/sj", makeProxyRoute("sj"));
      warn("[SCRAMJET] init failed; internal /sj proxy:", e?.message || e);
    }
  } else {
    app.all("/sj", makeProxyRoute("sj"));
    warn("[SCRAMJET] factory missing; internal /sj proxy");
  }
} else {
  // keep endpoint anyway
  app.all("/sj", makeProxyRoute("sj"));
}

// ──────────────────────────────────────────────────────────────────────────────
// Escaped-path fallback: keeps in-site buttons working when assets “escape” /proxy
// ──────────────────────────────────────────────────────────────────────────────
//
// Many SPAs request /_next/static/... or similar absolute paths.
// When that happens outside /proxy, reconstruct target from referer (?url=...).

app.use((req, res, next) => {
  try {
    const p = req.path || "/";
    if (
      p.startsWith("/proxy") ||
      p.startsWith("/sj") ||
      p.startsWith("/_euph_ws") ||
      p.startsWith("/_wsproxy") ||
      p.startsWith("/_euph_debug") ||
      p.startsWith("/static") ||
      p.startsWith("/public")
    )
      return next();

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

// ──────────────────────────────────────────────────────────────────────────────
// Home (SPA)
// ──────────────────────────────────────────────────────────────────────────────

app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

// ──────────────────────────────────────────────────────────────────────────────
// Admin/debug endpoints
// ──────────────────────────────────────────────────────────────────────────────

app.get("/_euph_debug/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, s] of SESSIONS.entries()) {
    out[sid] = {
      created: new Date(s.created).toISOString(),
      last: new Date(s.last).toISOString(),
      ip: s.ip,
      strictCookies: !!s.strictCookies,
      rewriteMode: s.rewriteMode,
      preferEngine: s.preferEngine,
      jarOrigins: [...s.cookieJar.keys()].length,
    };
  }
  res.json({ count: SESSIONS.size, sessions: out });
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

// ──────────────────────────────────────────────────────────────────────────────
// WebSocket support
// ──────────────────────────────────────────────────────────────────────────────
//
// 1) /_euph_ws telemetry WS (simple ping/pong)
// 2) /_wsproxy?url=ws(s)://... tunnel: browser WS -> upstream WS
//
// This is essential for modern apps that rely on WS for UI updates.

function setupWsProxy(server) {
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });

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

      // accept incoming ws
      wssProxy.handleUpgrade(request, socket, head, (wsIn) => {
        // connect outbound
        let wsOut;
        try {
          wsOut = new WebSocket(target, {
            headers: {
              origin: request.headers.origin || getPublicOrigin({ headers: request.headers, socket: request.socket }) || "",
            },
          });
        } catch (e) {
          try {
            wsIn.close();
          } catch {}
          return;
        }

        const closeBoth = () => {
          try {
            wsIn.close();
          } catch {}
          try {
            wsOut.close();
          } catch {}
        };

        wsOut.on("open", () => {
          wsIn.on("message", (msg) => {
            try {
              wsOut.send(msg);
            } catch {}
          });
          wsOut.on("message", (msg) => {
            try {
              wsIn.send(msg);
            } catch {}
          });

          wsIn.on("close", closeBoth);
          wsOut.on("close", closeBoth);
        });

        wsOut.on("error", closeBoth);
        wsIn.on("error", closeBoth);
      });
    } catch {
      try {
        socket.destroy();
      } catch {}
    }
  });

  return wssProxy;
}

// Create HTTP server
const server = http.createServer(app);

// Telemetry WS
const wssTelemetry = new WebSocketServer({ server, path: "/_euph_ws" });
wssTelemetry.on("connection", (ws) => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", (raw) => {
    try {
      const p = JSON.parse(raw.toString());
      if (p && p.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch {}
  });
});

// WS proxy
setupWsProxy(server);

// Boot
server.listen(PORT, () => {
  log(`[BOOT] listening on ${PORT}`);
  log(`[BOOT] trust proxy hops = ${TRUST_PROXY_HOPS}`);
  log(`[BOOT] disk cache = ${ENABLE_DISK_CACHE ? "on" : "off"}`);
  log(`[BOOT] scramjet = ${ENABLE_SCRAMJET ? "on" : "off"} (${typeof ScramjetFactory === "function" ? "factory" : "none"})`);
});

// Safety
process.on("unhandledRejection", (e) => errlog("unhandledRejection", e?.stack || e));
process.on("uncaughtException", (e) => errlog("uncaughtException", e?.stack || e));
process.on("warning", (w) => warn("warning", w?.stack || w));

// Graceful shutdown
process.on("SIGINT", () => {
  try {
    server.close();
  } catch {}
  process.exit(0);
});
process.on("SIGTERM", () => {
  try {
    server.close();
  } catch {}
  process.exit(0);
});