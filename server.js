// server.js — Euphoria Hybrid (Basic rewrite proxy + optional Scramjet + hardened navigation trapping)
// Node 20+, ESM. No iframes. Designed for Koyeb-like reverse-proxy envs.
// Goals:
// - Any site loads (best effort)
// - Redirects stay in Euphoria
// - Buttons/UI stay in Euphoria
// - Google searches work (top bar + inside Google)
// - Better odds for logins (cookie partitioning + SW disable + stable origin model)
// - Media works (range/streaming, correct headers)
// - CPU stable (skip heavy DOM rewrite on huge docs, caching, heuristics)

import express from "express";
import compression from "compression";
import cors from "cors";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import http from "http";
import https from "https";
import crypto from "crypto";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import zlib from "zlib";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import { LRUCache } from "lru-cache";
import { WebSocketServer } from "ws";

// Scramjet: CommonJS-safe import (do not assume named exports)
import scramjetPkg from "@mercuryworkshop/scramjet";
const ScramjetFactory =
  scramjetPkg?.createScramjetServer ||
  scramjetPkg?.createServer ||
  scramjetPkg?.default?.createScramjetServer ||
  scramjetPkg?.default?.createServer ||
  null;

/* ───────────────────────────────────────────── */
/* Basic Process/Env                             */
/* ───────────────────────────────────────────── */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8000);
const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

const QUIET_LOGS = process.env.QUIET_LOGS === "1";
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const ENABLE_SCRAMJET = process.env.ENABLE_SCRAMJET !== "0";

const TRUST_PROXY_HOPS = Number(process.env.TRUST_PROXY_HOPS || 1);

// Timeouts/limits
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const MAX_UPSTREAM_BODY_BYTES = Number(process.env.MAX_UPSTREAM_BODY_BYTES || 30 * 1024 * 1024); // 30MB safety
const MAX_HTML_REWRITE_BYTES = Number(process.env.MAX_HTML_REWRITE_BYTES || 2 * 1024 * 1024); // 2MB: beyond this avoid full JSDOM
const MAX_INLINE_SCRIPT_REWRITE = Number(process.env.MAX_INLINE_SCRIPT_REWRITE || 256 * 1024); // rewrite inline JS only if small

// Caching
const MEM_CACHE_ITEMS = Number(process.env.MEM_CACHE_ITEMS || 7000);
const HTML_CACHE_MAX_BYTES = Number(process.env.HTML_CACHE_MAX_BYTES || 900 * 1024);
const ASSET_CACHE_MAX_BYTES = Number(process.env.ASSET_CACHE_MAX_BYTES || 6 * 1024 * 1024);
const CACHE_TTL_HTML_MS = Number(process.env.CACHE_TTL_HTML_MS || 6 * 60 * 1000);
const CACHE_TTL_ASSET_MS = Number(process.env.CACHE_TTL_ASSET_MS || 60 * 60 * 1000);

// Cookies/sessions
const SESSION_COOKIE = process.env.SESSION_COOKIE || "euphoria_sid";
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 24 * 60 * 60 * 1000);
const STRICT_COOKIES_DEFAULT = process.env.STRICT_COOKIES_DEFAULT !== "0";

// Hardening
const DISABLE_SERVICE_WORKERS = process.env.DISABLE_SERVICE_WORKERS !== "0";
const STRIP_SECURITY_HEADERS = process.env.STRIP_SECURITY_HEADERS !== "0";
const FORCE_NO_STORE_HTML = process.env.FORCE_NO_STORE_HTML !== "0";

// Default UA
const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

// Agents
const httpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 256,
  timeout: FETCH_TIMEOUT_MS,
});
const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 256,
  timeout: FETCH_TIMEOUT_MS,
});

// Memory caches
const MEM_CACHE = new LRUCache({
  max: MEM_CACHE_ITEMS,
});

// Ensure cache dir
if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

function log(...args) {
  if (!QUIET_LOGS) console.log(...args);
}

/* ───────────────────────────────────────────── */
/* Express Setup                                 */
/* ───────────────────────────────────────────── */

const app = express();

// IMPORTANT: avoid express-rate-limit permissive trust proxy error
app.set("trust proxy", TRUST_PROXY_HOPS);

app.use(cors({ origin: true, credentials: true }));
app.use(compression());
app.use(morgan("tiny"));

// Note: not using heavy body parsers for proxy paths; keep small JSON only for admin endpoints
app.use(express.json({ limit: "1mb" }));
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
/* Constants & Header Rules                      */
/* ───────────────────────────────────────────── */

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

const SPECIAL_FILES = [
  "service-worker.js",
  "sw.js",
  "worker.js",
  "manifest.json",
];

// Used for guessing assets and bypassing rewrite
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

/* ───────────────────────────────────────────── */
/* Admin                                         */
/* ───────────────────────────────────────────── */

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

/* ───────────────────────────────────────────── */
/* Public Origin Resolver                         */
/* ───────────────────────────────────────────── */

function getPublicOrigin(req) {
  const xfProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const xfHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const host = String(xfHost || req.headers.host || "").split(",")[0].trim();
  const proto = (xfProto || (req.socket.encrypted ? "https" : "http")).trim();
  if (!host) return "";
  return `${proto}://${host}`;
}

/* ───────────────────────────────────────────── */
/* Cache (disk + mem)                             */
/* ───────────────────────────────────────────── */

function nowMs() {
  return Date.now();
}

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

/* ───────────────────────────────────────────── */
/* Session + Cookie Partitioning                  */
/* ───────────────────────────────────────────── */

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
    .forEach((pair) => {
      const idx = pair.indexOf("=");
      if (idx === -1) return;
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
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
      strictCookies: STRICT_COOKIES_DEFAULT,
      // originKey -> Map(cookieName -> cookie)
      cookieJar: new Map(),
      // misc preferences (future)
      prefs: {
        modeDefault: "proxy",
      },
    });
    setSessionCookie(res, sid);
  }

  const s = SESSIONS.get(sid);
  s.last = nowMs();
  s.ip = req.ip || s.ip;
  return { sid, s };
}

setInterval(() => {
  const cutoff = nowMs() - SESSION_TTL_MS;
  for (const [sid, s] of SESSIONS.entries()) {
    if (!s || s.last < cutoff) SESSIONS.delete(sid);
  }
}, 30 * 60 * 1000);

function normalizeHost(h) {
  return String(h || "").trim().toLowerCase();
}
function normalizePath(p) {
  if (!p) return "/";
  const s = String(p);
  return s.startsWith("/") ? s : "/" + s;
}

function splitSetCookieHeader(setCookieHeaderValue) {
  // fetch sometimes combines; split only when it looks like a new cookie
  return String(setCookieHeaderValue || "")
    .split(/,(?=[^ ;]+=)/g)
    .map((s) => s.trim())
    .filter(Boolean);
}

// Loose cookie parser (good enough for many)
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

// Strict origin partitioning:
// - store cookies ONLY for exact host of the response origin
// - ignore parent-domain cookies (helps keep sessions stable inside proxy)
function storeSetCookiesStrict(session, originUrl, setCookieValues) {
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

    // strict: only exact host, no wider domain cookies
    if (cookieDomain !== host) continue;

    // secure cookies only over https
    if (parsed.secure && u.protocol !== "https:") continue;

    // if expired -> delete
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

/* ───────────────────────────────────────────── */
/* URL Parsing / Input Normalization              */
/* ───────────────────────────────────────────── */

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

// Detect already-proxied urls to avoid loops
function isAlreadyProxied(urlStr) {
  if (!urlStr) return false;
  return urlStr.includes("/proxy?url=") || urlStr.includes("/sj?url=");
}

// Most common “escape hatches” that cause Missing url
// Example: Google result links like /url?q=https://example.com&sa=...
function unwrapGoogleUrlRedirect(absUrl) {
  try {
    const u = new URL(absUrl);
    // Google redirect pattern
    if (u.hostname.endsWith("google.com") && u.pathname === "/url") {
      const q = u.searchParams.get("q") || u.searchParams.get("url");
      if (q && /^https?:\/\//i.test(q)) return q;
    }
  } catch {}
  return absUrl;
}

function shouldSkipRewrite(value) {
  if (!value) return true;
  const s = String(value);

  if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(s)) return true;
  if (isAlreadyProxied(s)) return true;

  return false;
}

function toAbsMaybe(urlLike, base) {
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

function makeProxyUrl(absUrl, req, mode = "proxy") {
  try {
    const origin = getPublicOrigin(req);
    const base = mode === "sj" ? "/sj" : "/proxy";
    const normalized = new URL(absUrl).href;
    return `${origin}${base}?url=${encodeURIComponent(normalized)}`;
  } catch {
    return absUrl;
  }
}

/* ───────────────────────────────────────────── */
/* Fetch (no undici import)                       */
/* ───────────────────────────────────────────── */

async function fetchUpstream(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const u = new URL(url);
    const agent = u.protocol === "https:" ? httpsAgent : httpAgent;

    // Node 20 fetch: "agent" is accepted in many hosted environments.
    // If not, it’s ignored; safe.
    const res = await fetch(url, {
      ...opts,
      redirect: "manual",
      signal: controller.signal,
      // @ts-ignore
      agent,
    });

    return res;
  } finally {
    clearTimeout(timer);
  }
}

/* ───────────────────────────────────────────── */
/* Encoding helpers                               */
/* ───────────────────────────────────────────── */

function maybeDecompress(buf, contentEncoding) {
  const enc = String(contentEncoding || "").toLowerCase();
  try {
    if (enc.includes("br") && zlib.brotliDecompressSync) return zlib.brotliDecompressSync(buf);
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
  } catch {}
  return buf;
}

function maybeCompressForClient(buf, acceptEncoding) {
  // We generally serve rewritten HTML uncompressed to avoid mismatches.
  // For large HTML, compression can help but adds CPU.
  // Keep simple: no recompress here.
  return { body: buf, encoding: null };
}

/* ───────────────────────────────────────────── */
/* Header copy / stripping                         */
/* ───────────────────────────────────────────── */

function copyHeaders(up, down, { rewriting = false } = {}) {
  try {
    for (const [k, v] of up.headers.entries()) {
      const lk = k.toLowerCase();

      if (HOP_BY_HOP_HEADERS.has(lk)) continue;

      if (STRIP_SECURITY_HEADERS && DROP_RESPONSE_HEADERS.has(lk)) continue;

      // We trap redirects ourselves
      if (lk === "location") continue;

      // If rewriting, avoid passing upstream encoding/length
      if (rewriting) {
        if (lk === "content-encoding") continue;
        if (lk === "content-length") continue;
      } else {
        // For streaming/range, keep accept-ranges, content-range, etc.
      }

      try {
        down.setHeader(k, v);
      } catch {}
    }
  } catch {}
}

function isHtmlContentType(ct) {
  const s = String(ct || "").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

/* ───────────────────────────────────────────── */
/* Streaming (assets/media)                        */
/* ───────────────────────────────────────────── */

async function streamBody(up, down) {
  // Node fetch body is ReadableStream
  const body = up.body;
  if (!body) {
    down.end();
    return;
  }
  if (typeof body.getReader === "function") {
    const reader = body.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) down.write(Buffer.from(value));
    }
    down.end();
    return;
  }

  // Fallback: buffer
  const ab = await up.arrayBuffer();
  down.end(Buffer.from(ab));
}

/* ───────────────────────────────────────────── */
/* Redirect trapping                               */
/* ───────────────────────────────────────────── */

function handleRedirect(up, req, res, requestTarget, mode) {
  const loc = up.headers.get("location");
  if (!loc) return false;

  let abs;
  try {
    abs = new URL(loc, up.url || requestTarget).href;
  } catch {
    abs = loc;
  }

  abs = unwrapGoogleUrlRedirect(abs);

  const prox = makeProxyUrl(abs, req, mode);

  res.status(up.status || 302);
  res.setHeader("Location", prox);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(`Redirecting to ${prox}`);
  return true;
}

/* ───────────────────────────────────────────── */
/* HTML Sanitization & Rewrite                     */
/* ───────────────────────────────────────────── */

function sanitizeHtml(html) {
  // Remove CSP meta tags and SRI/crossorigin that can block subresources after rewrite
  // Keep minimal to avoid breaking sites too much.
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch {}
  return html;
}

// Lightweight rewrite for massive HTML (avoid JSDOM CPU)
// - adds a small runtime
// - does NOT attempt deep DOM rewrite
function lightweightRewrite(html, baseUrl, req, mode) {
  let out = html;

  // Ensure base tag if missing (helps relative URLs)
  if (!/<base\s/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, (m) => `${m}\n<base href="${escapeHtmlAttr(baseUrl)}">`);
  }

  // Inject runtime to keep navigation inside Euphoria (most important)
  out = injectClientRuntime(out, req, mode);

  // Add a defensive referrer policy
  if (!/name=["']referrer["']/.test(out)) {
    out = out.replace(/<head([^>]*)>/i, (m) => `${m}\n<meta name="referrer" content="no-referrer-when-downgrade">`);
  }

  // Avoid google seizure: do not attempt to rewrite every href with regex (can create loops)
  return out;
}

function escapeHtmlAttr(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function rewriteDomWithJsdom(html, baseUrl, req, mode) {
  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }

  const document = dom.window.document;

  // Ensure base tag (but do NOT overwrite existing; some apps rely on their own base)
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

      const abs0 = toAbsMaybe(val, baseUrl);
      if (!abs0) return;

      const abs = unwrapGoogleUrlRedirect(abs0);
      el.setAttribute(attr, makeProxyUrl(abs, req, mode));
    } catch {}
  };

  // Anchor links
  document.querySelectorAll("a[href]").forEach((a) => {
    rewriteAttr(a, "href");
    a.removeAttribute("target");
    // Strip rel=noopener to avoid odd popups; optional.
    // keep rel if set by site? We'll leave as is.
  });

  // Form actions
  document.querySelectorAll("form[action]").forEach((f) => {
    rewriteAttr(f, "action");
  });

  // src/href resources
  ["img", "script", "iframe", "audio", "video", "source", "track"].forEach((tag) => {
    document.querySelectorAll(tag).forEach((el) => {
      rewriteAttr(el, "src");
    });
  });

  document.querySelectorAll("link[href]").forEach((el) => {
    rewriteAttr(el, "href");
  });

  // srcset (critical for “complex images”)
  document.querySelectorAll("[srcset]").forEach((el) => {
    try {
      const srcset = el.getAttribute("srcset");
      if (!srcset) return;

      const out = srcset
        .split(",")
        .map((part) => {
          const trimmed = part.trim();
          if (!trimmed) return part;

          const bits = trimmed.split(/\s+/, 2);
          const u = bits[0];
          const size = bits[1] || "";

          if (shouldSkipRewrite(u)) return part;

          const abs0 = toAbsMaybe(u, baseUrl);
          if (!abs0) return part;

          const abs = unwrapGoogleUrlRedirect(abs0);
          const pu = makeProxyUrl(abs, req, mode);

          return size ? `${pu} ${size}` : pu;
        })
        .join(", ");

      el.setAttribute("srcset", out);
    } catch {}
  });

  // style="...url(...)"
  document.querySelectorAll("[style]").forEach((el) => {
    try {
      const s = el.getAttribute("style") || "";
      if (!s) return;

      const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs0 = toAbsMaybe(u, baseUrl);
        if (!abs0) return m;
        const abs = unwrapGoogleUrlRedirect(abs0);
        return `url("${makeProxyUrl(abs, req, mode)}")`;
      });

      el.setAttribute("style", out);
    } catch {}
  });

  // <style> blocks url(...)
  document.querySelectorAll("style").forEach((st) => {
    try {
      let css = st.textContent || "";
      if (!css) return;

      css = css.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs0 = toAbsMaybe(u, baseUrl);
        if (!abs0) return m;
        const abs = unwrapGoogleUrlRedirect(abs0);
        return `url("${makeProxyUrl(abs, req, mode)}")`;
      });

      st.textContent = css;
    } catch {}
  });

  // Meta refresh redirects
  document.querySelectorAll("meta[http-equiv]").forEach((m) => {
    try {
      if ((m.getAttribute("http-equiv") || "").toLowerCase() !== "refresh") return;
      const c = m.getAttribute("content") || "";
      const match = c.match(/url=(.+)$/i);
      if (!match) return;

      const abs0 = toAbsMaybe(match[1], baseUrl);
      if (!abs0) return;

      const abs = unwrapGoogleUrlRedirect(abs0);
      m.setAttribute("content", c.replace(match[1], makeProxyUrl(abs, req, mode)));
    } catch {}
  });

  // Defensive: inject referrer meta (helps some login flows)
  try {
    if (!document.querySelector('meta[name="referrer"]')) {
      const meta = document.createElement("meta");
      meta.setAttribute("name", "referrer");
      meta.setAttribute("content", "no-referrer-when-downgrade");
      (document.head || document.documentElement).appendChild(meta);
    }
  } catch {}

  // Runtime injection (navigation + fetch/xhr)
  let out = dom.serialize();
  out = injectClientRuntime(out, req, mode);

  // Inline script rewrite (best effort, limited)
  out = rewriteInlineScriptsSafely(out, baseUrl, req, mode);

  return out;
}

function neuterServiceWorkerJs(code) {
  if (!DISABLE_SERVICE_WORKERS) return code;
  try {
    return code
      .replace(/navigator\s*\.\s*serviceWorker\s*\.\s*register/gi, "/*euph*/null&&navigator.serviceWorker.register")
      .replace(/serviceWorker\s*\.\s*register/gi, "/*euph*/null&&serviceWorker.register");
  } catch {
    return code;
  }
}

// Rewrite JS strings with URLs in common APIs (very best-effort)
// Keep conservative to avoid breaking heavy apps
function rewriteInlineJs(code, baseUrl, req, mode) {
  // Guard: avoid heavy regex on huge scripts
  if (!code || code.length > MAX_INLINE_SCRIPT_REWRITE) return code;

  const prox = (abs) => makeProxyUrl(abs, req, mode);

  try {
    // fetch("...")
    code = code.replace(/fetch\(\s*(['"])([^'"]+)\1/g, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      const abs0 = toAbsMaybe(u, baseUrl);
      if (!abs0) return m;
      return `fetch("${prox(unwrapGoogleUrlRedirect(abs0))}"`;
    });

    // XHR.open("GET","...")
    code = code.replace(
      /\.open\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+)\3/gi,
      (m, q1, method, q2, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs0 = toAbsMaybe(u, baseUrl);
        if (!abs0) return m;
        const mm = method || "GET";
        return `.open("${mm}","${prox(unwrapGoogleUrlRedirect(abs0))}"`;
      }
    );

    // location = "..."
    // VERY conservative; don’t rewrite arbitrary strings widely.
    code = code.replace(/location\s*=\s*(['"])(https?:\/\/[^'"]+)\1/gi, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      return `location="${prox(unwrapGoogleUrlRedirect(u))}"`;
    });

    return code;
  } catch {
    return code;
  }
}

// Second pass to rewrite inline scripts using JSDOM only if manageable
function rewriteInlineScriptsSafely(html, baseUrl, req, mode) {
  // If the HTML is huge, avoid another DOM pass
  if (!html || html.length > MAX_HTML_REWRITE_BYTES) return html;

  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const doc = dom.window.document;

    doc.querySelectorAll("script:not([src])").forEach((s) => {
      let code = s.textContent || "";
      if (!code.trim()) return;
      code = neuterServiceWorkerJs(code);
      code = rewriteInlineJs(code, baseUrl, req, mode);
      s.textContent = code;
    });

    return dom.serialize();
  } catch {
    return html;
  }
}

/* ───────────────────────────────────────────── */
/* Client runtime injection                        */
/* ───────────────────────────────────────────── */

function injectClientRuntime(html, req, mode) {
  const marker = "/*__EUPHORIA_CLIENT_RUNTIME_V6__*/";
  if (html.includes(marker)) return html;

  const origin = getPublicOrigin(req);
  const basePath = mode === "sj" ? "/sj?url=" : "/proxy?url=";

  // This runtime is the main “buttons stay in Euphoria” fix.
  // It prevents “escape” by intercepting:
  // - link clicks
  // - form submits
  // - History API
  // - fetch/XHR
  // - window.open
  // - location.assign/replace
  // It also handles Google’s /url?q= links (unwrap then proxy).
  const js = `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(origin)};
  const BASE = ${JSON.stringify(basePath)};

  function isProxied(u){
    return typeof u === "string" && (u.includes("/proxy?url=") || u.includes("/sj?url="));
  }

  function unwrapGoogle(u){
    try{
      const x = new URL(u, location.href);
      if(x.hostname.endsWith("google.com") && x.pathname === "/url"){
        const q = x.searchParams.get("q") || x.searchParams.get("url");
        if(q && /^https?:\\/\\//i.test(q)) return q;
      }
    }catch(e){}
    return u;
  }

  function abs(u){
    try { return new URL(u, document.baseURI).href; }
    catch(e){ return u; }
  }

  function prox(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(isProxied(u)) return u;
      if(/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u)) return u;

      u = unwrapGoogle(u);
      const a = abs(u);
      return ORIGIN + BASE + encodeURIComponent(a);
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
        try{ if(typeof url === "string") url = prox(url); }catch(e){}
        return open.apply(this, arguments);
      };
      return x;
    };
  }catch(e){}

  // Patch History API
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

  // Patch window.open
  try{
    const o = window.open;
    window.open = function(url, name, specs){
      try{ if(typeof url === "string") url = prox(url); }catch(e){}
      return o.call(this, url, name, specs);
    };
  }catch(e){}

  // Patch location.assign/replace
  try{
    const loc = window.location;
    const assign = loc.assign.bind(loc);
    const replace = loc.replace.bind(loc);
    loc.assign = function(u){ return assign(prox(u)); };
    loc.replace = function(u){ return replace(prox(u)); };
  }catch(e){}

  // Click-time anchor rewrite (captures dynamically inserted links)
  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
      if(!a) return;
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;

      const fixed = prox(href);
      if(fixed && fixed !== href){
        a.setAttribute("href", fixed);
        a.removeAttribute("target");
      }
    }catch(e){}
  }, true);

  // Form submits: rewrite action at submit-time
  function patchForms(){
    try{
      document.querySelectorAll("form[action]").forEach(f=>{
        const a = f.getAttribute("action");
        if(!a) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(a)) return;
        if(isProxied(a)) return;
        f.setAttribute("action", prox(a));
      });
    }catch(e){}
  }
  patchForms();
  document.addEventListener("submit", function(){ try{ patchForms(); }catch(e){} }, true);

})();
</script>`.trim();

  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, js + "\n</body>");
  return html + "\n" + js;
}

/* ───────────────────────────────────────────── */
/* Google handling                                */
/* ───────────────────────────────────────────── */

function isGoogleHost(u) {
  try {
    const x = new URL(u);
    return x.hostname.endsWith("google.com");
  } catch {
    return false;
  }
}

// Google “seizure” often occurs if:
// - base tag points to proxied URL and links get double-proxied repeatedly
// - the proxy rewrites the same links repeatedly across navigation
// - missing url occurs when Google uses relative /url?q= links and we don't reconstruct
// We address by:
// - strong isAlreadyProxied checks
// - unwrap /url?q=
// - runtime fixes for dynamic clicks
// - fallback handler for escaped asset paths
function shouldAvoidHeavyRewriteForHost(host) {
  const h = String(host || "").toLowerCase();

  // Avoid doing aggressive inline JS rewrites for very complex JS apps; runtime will do most
  if (h.includes("accounts.google.")) return true;
  if (h.includes("login.live.")) return true;
  if (h.includes("microsoftonline.")) return true;
  if (h.includes("xbox.")) return true;

  return false;
}

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

/* ───────────────────────────────────────────── */
/* Request target extraction                       */
/* ───────────────────────────────────────────── */

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// Supports:
// - /proxy?url=...
// - /proxy?q=...
// - /proxy/<host>/<path> (requested style)
// - Recover from internal navigation where the browser hits /url?... etc
function getTargetFromReq(req) {
  // direct
  const qUrl = req.query?.url;
  const qQ = req.query?.q;

  if (qQ && !qUrl) {
    return googleSearchUrl(String(qQ));
  }

  if (qUrl) {
    const raw = String(qUrl);
    // If it's not URLish, treat as search terms
    const asUrl = normalizeToHttpUrl(raw);
    if (asUrl) return asUrl;
    return googleSearchUrl(raw);
  }

  // /proxy/:host/* style via path
  // NOTE: We also have a dedicated route that redirects this to ?url=, but keep this for safety.
  if (req.path && req.path.startsWith("/proxy/")) {
    const rest = req.path.replace(/^\/proxy\//, "");
    if (!rest) return null;
    const decoded = decodeURIComponentSafe(rest);
    const asUrl = normalizeToHttpUrl(decoded);
    if (asUrl) return asUrl;
    if (/^https?:\/\//i.test(decoded)) return decoded;
  }

  // If the request is to /url or other escape path, try to reconstruct from referer
  // This is the core fix for “Missing url” when clicking inside Google or similar sites.
  const ref = req.headers.referer || req.headers.referrer || "";
  if (ref) {
    const m = String(ref).match(/[?&]url=([^&]+)/);
    if (m) {
      const base = decodeURIComponentSafe(m[1]);
      // Attempt to resolve this request path relative to the base origin
      try {
        const baseOrigin = new URL(base).origin;
        const abs = new URL(req.originalUrl, baseOrigin).href;
        return abs;
      } catch {}
    }
  }

  return null;
}

/* ───────────────────────────────────────────── */
/* Proxy route factory                             */
/* ───────────────────────────────────────────── */

function makeProxyRoute(mode = "proxy") {
  return async (req, res) => {
    const { s: session } = getSession(req, res);

    // Allow toggles
    if (typeof req.query.strictCookies !== "undefined") {
      session.strictCookies = String(req.query.strictCookies) !== "0";
    }

    let target = getTargetFromReq(req);

    if (!target) {
      return res
        .status(400)
        .send("Missing url. Use /proxy?url=https://example.com or /proxy?q=search");
    }

    // Normalize target
    target = unwrapGoogleUrlRedirect(target);

    // Cache decisions
    const accept = String(req.headers.accept || "").toLowerCase();
    const wantsHtml = accept.includes("text/html") || req.query.force_html === "1";

    const hasRange = !!req.headers.range;
    const cacheAllowed = req.method === "GET" && !hasRange;

    const cacheKeyBase = `${mode}::${target}`;
    const cacheKey = wantsHtml ? `${cacheKeyBase}::html` : `${cacheKeyBase}::asset`;

    // Serve from cache
    if (cacheAllowed) {
      const mem = MEM_CACHE.get(cacheKey);
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

      const disk = await diskGet(cacheKey);
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

    // Upstream headers
    const hdrs = {};
    try {
      hdrs["user-agent"] = session.ua || DEFAULT_UA;
      hdrs["accept"] = req.headers.accept || "*/*";
      hdrs["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
      hdrs["accept-encoding"] = "gzip, deflate, br";

      // Range is CRITICAL for media and some images
      if (req.headers.range) hdrs["range"] = req.headers.range;

      // Strict cookies
      if (session.strictCookies) {
        const cookieHeader = buildCookieHeaderStrict(session, target);
        if (cookieHeader) hdrs["cookie"] = cookieHeader;
      }

      // Referer/origin coherence
      if (req.headers.referer) hdrs["referer"] = req.headers.referer;
      try {
        hdrs["origin"] = new URL(target).origin;
      } catch {}
    } catch {}

    // Fetch
    let up;
    try {
      up = await fetchUpstream(target, {
        method: "GET",
        headers: hdrs,
        redirect: "manual",
      });
    } catch (e) {
      return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
    }

    // Store cookies
    try {
      const sc = up.headers.get("set-cookie");
      if (sc && session.strictCookies) {
        storeSetCookiesStrict(session, up.url || target, splitSetCookieHeader(sc));
      }
    } catch {}

    // Redirect trap
    if ([301, 302, 303, 307, 308].includes(up.status)) {
      if (handleRedirect(up, req, res, target, mode)) return;
    }

    const ct = up.headers.get("content-type") || "";
    const isHtml = wantsHtml || isHtmlContentType(ct);

    // HTML handling
    if (isHtml) {
      // Buffer (HTML rewriting requires buffering)
      let rawBuf;
      try {
        const ab = await up.arrayBuffer();
        rawBuf = Buffer.from(ab);
        if (rawBuf.length > MAX_UPSTREAM_BODY_BYTES) throw new Error("html_too_large");
      } catch (e) {
        return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
      }

      copyHeaders(up, res, { rewriting: true });

      // Decompress
      const dec = maybeDecompress(rawBuf, up.headers.get("content-encoding"));
      let html = "";
      try {
        html = dec.toString("utf8");
      } catch {
        html = Buffer.from(dec).toString("utf8");
      }

      html = sanitizeHtml(html);

      const baseUrl = up.url || target;

      // Determine rewrite strategy
      let out = "";
      let usedJsdom = false;

      try {
        const host = new URL(baseUrl).hostname;
        const avoidHeavy = shouldAvoidHeavyRewriteForHost(host);

        if (avoidHeavy || html.length > MAX_HTML_REWRITE_BYTES) {
          out = lightweightRewrite(html, baseUrl, req, mode);
        } else {
          usedJsdom = true;
          out = rewriteDomWithJsdom(html, baseUrl, req, mode);
        }
      } catch {
        out = lightweightRewrite(html, baseUrl, req, mode);
      }

      res.status(up.status || 200);
      res.setHeader("Content-Type", "text/html; charset=utf-8");

      // Cache: never cache auth-heavy HTML
      let cacheOk = cacheAllowed;
      try {
        const h = new URL(baseUrl).hostname;
        if (isAuthyHost(h)) cacheOk = false;
      } catch {}

      // Force no-store for HTML (best for login correctness)
      if (FORCE_NO_STORE_HTML) {
        res.setHeader("Cache-Control", "no-store");
      } else {
        res.setHeader("Cache-Control", cacheOk ? "public, max-age=30" : "no-store");
      }

      if (cacheOk && out.length <= HTML_CACHE_MAX_BYTES) {
        const payload = {
          __type: "html",
          body: out,
          headers: { "Cache-Control": "no-store" },
          meta: { usedJsdom: !!usedJsdom },
        };
        MEM_CACHE.set(cacheKey, payload, { ttl: CACHE_TTL_HTML_MS });
        diskSet(cacheKey, payload, CACHE_TTL_HTML_MS).catch(() => {});
      }

      return res.end(out);
    }

    // Asset / Media handling
    copyHeaders(up, res, { rewriting: false });
    res.status(up.status || 200);

    // Range streaming: MUST stream, no cache
    if (hasRange) {
      return streamBody(up, res);
    }

    // Buffer small, stream large
    let ab;
    try {
      ab = await up.arrayBuffer();
    } catch {
      return streamBody(up, res);
    }
    const bodyBuf = Buffer.from(ab);

    // Cache small assets
    if (cacheAllowed && bodyBuf.length <= ASSET_CACHE_MAX_BYTES) {
      const headersObj = {};
      try {
        for (const [k, v] of up.headers.entries()) {
          const lk = k.toLowerCase();
          if (HOP_BY_HOP_HEADERS.has(lk)) continue;
          if (STRIP_SECURITY_HEADERS && DROP_RESPONSE_HEADERS.has(lk)) continue;
          if (lk === "content-length") continue;
          headersObj[k] = v;
        }
      } catch {}

      const payload = {
        __type: "asset",
        headers: headersObj,
        bodyB64: bodyBuf.toString("base64"),
      };

      MEM_CACHE.set(cacheKey, payload, { ttl: CACHE_TTL_ASSET_MS });
      diskSet(cacheKey, payload, CACHE_TTL_ASSET_MS).catch(() => {});
    }

    return res.end(bodyBuf);
  };
}

/* ───────────────────────────────────────────── */
/* Routes                                         */
/* ───────────────────────────────────────────── */

// Main proxy routes
app.get("/proxy", makeProxyRoute("proxy"));
app.get("/sj", makeProxyRoute("sj"));

// /proxy/:host/* style support -> normalize to /proxy?url=https://host/...
app.get(/^\/proxy\/([^/]+)\/(.*)$/i, (req, res, next) => {
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

/* ───────────────────────────────────────────── */
/* Scramjet mount (safe)                          */
/* ───────────────────────────────────────────── */

if (ENABLE_SCRAMJET) {
  if (typeof ScramjetFactory === "function") {
    try {
      const sj = ScramjetFactory({ prefix: "/sj" });

      // Common shapes:
      // - middleware function
      // - { handler(req,res,next) }
      // - { fetch(url, opts) }
      if (typeof sj === "function") {
        app.use("/sj", sj);
        log("[SCRAMJET] mounted middleware at /sj");
      } else if (sj && typeof sj.handler === "function") {
        app.use("/sj", (req, res, next) => sj.handler(req, res, next));
        log("[SCRAMJET] mounted handler at /sj");
      } else if (sj && typeof sj.fetch === "function") {
        // Fetch-bridge fallback (rarely used)
        app.use("/sj", async (req, res) => {
          try {
            const origin = getPublicOrigin(req) || "http://localhost";
            const url = new URL(req.originalUrl, origin).href;
            const r = await sj.fetch(url, { method: req.method, headers: req.headers });
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
        log("[SCRAMJET] mounted fetch-bridge at /sj");
      } else {
        log("[SCRAMJET] unknown factory return shape; using internal /sj proxy handler");
      }
    } catch (e) {
      log("[SCRAMJET] init failed; using internal /sj proxy handler:", e?.message || e);
    }
  } else {
    log("[SCRAMJET] factory not available; using internal /sj proxy handler");
  }
}

/* ───────────────────────────────────────────── */
/* Escaped path fallback (fixes “Missing url”)    */
/* ───────────────────────────────────────────── */

// Many SPAs request /_next/* or /assets/* as absolute paths.
// When those hit our server without /proxy?url, we reconstruct from the referer’s url=...
app.use(async (req, res, next) => {
  try {
    const p = req.path || "/";

    if (
      p.startsWith("/proxy") ||
      p.startsWith("/sj") ||
      p.startsWith("/_euph_ws") ||
      p.startsWith("/_euph_debug") ||
      p.startsWith("/public") ||
      p === "/" ||
      p === "/index.html"
    ) {
      return next();
    }

    const ref = req.headers.referer || req.headers.referrer || "";
    const m = String(ref).match(/[?&]url=([^&]+)/);
    if (!m) return next();

    const base = decodeURIComponentSafe(m[1]);
    if (!base) return next();

    // Reconstruct as origin + requested path/query
    const baseOrigin = new URL(base).origin;
    const abs = new URL(req.originalUrl, baseOrigin).href;

    // Serve through proxy
    const mode = ref.includes("/sj?url=") ? "sj" : "proxy";
    return res.redirect(302, makeProxyUrl(abs, req, mode));
  } catch {
    return next();
  }
});

/* ───────────────────────────────────────────── */
/* Home + SPA fallback                            */
/* ───────────────────────────────────────────── */

app.get("/", (req, res) => {
  return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("*", (req, res, next) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

/* ───────────────────────────────────────────── */
/* Debug/Admin endpoints                          */
/* ───────────────────────────────────────────── */

app.get("/_euph_debug/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, s] of SESSIONS.entries()) {
    out[sid] = {
      created: new Date(s.created).toISOString(),
      last: new Date(s.last).toISOString(),
      ip: s.ip,
      strictCookies: !!s.strictCookies,
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

/* ───────────────────────────────────────────── */
/* WebSocket (telemetry / future WISP hook)       */
/* ───────────────────────────────────────────── */

const server = http.createServer(app);

const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", (raw) => {
    try {
      const p = JSON.parse(raw.toString());
      if (p && p.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch {}
  });
});

/* ───────────────────────────────────────────── */
/* Start                                          */
/* ───────────────────────────────────────────── */

server.listen(PORT, () => {
  log(`[BOOT] listening on ${PORT}`);
});

/* ───────────────────────────────────────────── */
/* Safety                                          */
/* ───────────────────────────────────────────── */

process.on("unhandledRejection", (err) => console.error("unhandledRejection", err?.stack || err));
process.on("uncaughtException", (err) => console.error("uncaughtException", err?.stack || err));
process.on("warning", (w) => console.warn("warning", w?.stack || w));
process.on("SIGINT", () => {
  try {
    server.close();
  } catch {}
  process.exit(0);
});
