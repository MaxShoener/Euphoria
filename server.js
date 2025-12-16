// server.js — Euphoria Hybrid (stable, Koyeb-safe)
// Node 20+, ESM. No iframes. Redirect trapping, DOM rewriting, runtime navigation interception,
// strict-origin cookie jar (optional), range streaming, disk+mem cache, optional Scramjet mount.
//
// NOTE: Some high-security login flows (Google/Microsoft/Xbox) may still fail due to bot/anti-proxy controls.
// This tries to maximize compatibility without headless browsers.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import path from "path";
import fs from "fs";
import fsPromises from "fs/promises";
import http from "http";
import https from "https";
import crypto from "crypto";
import zlib from "zlib";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";

// Optional Scramjet (never crash if missing / different API shape)
let scramjetPkg = null;
try {
  // eslint-disable-next-line import/no-extraneous-dependencies
  scramjetPkg = (await import("@mercuryworkshop/scramjet")).default ?? (await import("@mercuryworkshop/scramjet"));
} catch {
  scramjetPkg = null;
}

const ScramjetFactory =
  scramjetPkg?.createScramjetServer ||
  scramjetPkg?.createServer ||
  scramjetPkg?.default?.createScramjetServer ||
  scramjetPkg?.default?.createServer ||
  null;

/* =========================
 * Paths / ENV
 * ========================= */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8000);
const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

const QUIET_LOGS = process.env.QUIET_LOGS === "1";
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";

const ENABLE_SCRAMJET = process.env.ENABLE_SCRAMJET !== "0";
const SCRAMJET_PREFIX = process.env.SCRAMJET_PREFIX || "/sj";

const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const MAX_HTML_BYTES = Number(process.env.MAX_HTML_BYTES || 18 * 1024 * 1024);
const MAX_ASSET_BUFFER_BYTES = Number(process.env.MAX_ASSET_BUFFER_BYTES || 7 * 1024 * 1024);

const MEM_HTML_ITEMS = Number(process.env.MEM_HTML_ITEMS || 900);
const MEM_ASSET_ITEMS = Number(process.env.MEM_ASSET_ITEMS || 2500);

const TTL_HTML_MS = Number(process.env.TTL_HTML_MS || 5 * 60 * 1000);
const TTL_ASSET_MS = Number(process.env.TTL_ASSET_MS || 60 * 60 * 1000);

const STRICT_COOKIES_DEFAULT = process.env.STRICT_COOKIES_DEFAULT !== "0";
const DISABLE_SERVICE_WORKERS = process.env.DISABLE_SERVICE_WORKERS !== "0";
const ENABLE_BROTLI = process.env.ENABLE_BROTLI !== "0";

const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

// express-rate-limit complains if trust proxy === true. Use hop count.
const TRUST_PROXY_HOPS = Number(process.env.TRUST_PROXY_HOPS || 1);

function log(...args) {
  if (!QUIET_LOGS) console.log(...args);
}

/* =========================
 * Bootstrap disk cache dir
 * ========================= */

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

/* =========================
 * Express app
 * ========================= */

const app = express();
app.set("trust proxy", TRUST_PROXY_HOPS);

app.use(cors({ origin: true, credentials: true }));
app.use(morgan("tiny"));
app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(PUBLIC_DIR, { index: false }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.RATE_LIMIT_GLOBAL || 1200),
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      // stable-ish client identity behind proxies
      const xf = (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim();
      return xf || req.ip || req.socket?.remoteAddress || "unknown";
    },
  })
);

/* =========================
 * Headers policies
 * ========================= */

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

/* =========================
 * URL / origin helpers
 * ========================= */

function getPublicOrigin(req) {
  const xfProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const xfHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const host = String(xfHost || req.headers.host || "").split(",")[0].trim();
  const proto = (xfProto || (req.socket.encrypted ? "https" : "http")).trim();
  if (!host) return "";
  return `${proto}://${host}`;
}

function isUrlish(s) {
  const t = String(s || "").trim();
  if (!t) return false;
  if (/^https?:\/\//i.test(t)) return true;
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/].*)?$/i.test(t)) return true;
  return false;
}

function normalizeTarget(input) {
  const s = String(input || "").trim();
  if (!s) return null;

  // already proxied? let client-side runtime handle, but normalize anyway
  if (/^https?:\/\//i.test(s)) {
    try {
      return new URL(s).href;
    } catch {
      return null;
    }
  }

  // if urlish host/path, prepend scheme
  if (isUrlish(s)) {
    try {
      return new URL("https://" + s).href;
    } catch {
      return null;
    }
  }

  // otherwise treat as search query
  return "https://www.google.com/search?q=" + encodeURIComponent(s);
}

function makeProxyUrl(absUrl, req, mode = "proxy") {
  const origin = getPublicOrigin(req);
  const base = mode === "sj" ? SCRAMJET_PREFIX : "/proxy";
  try {
    const u = new URL(absUrl);
    return `${origin}${base}?url=${encodeURIComponent(u.href)}`;
  } catch {
    return `${origin}${base}?url=${encodeURIComponent(absUrl)}`;
  }
}

function decodeURIComponentSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/* =========================
 * Cache
 * ========================= */

const MEM_HTML = new LRUCache({ max: MEM_HTML_ITEMS, ttl: TTL_HTML_MS });
const MEM_ASSET = new LRUCache({ max: MEM_ASSET_ITEMS, ttl: TTL_ASSET_MS });

// lightweight cache for “is this likely an asset?” decisions
const MEM_ASSET_HINT = new LRUCache({ max: 5000, ttl: 60 * 60 * 1000 });

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
    if (Date.now() - obj.t > (obj.ttl || 0)) return null;
    return obj.v;
  } catch {
    return null;
  }
}

async function diskSet(key, value, ttl) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(f, JSON.stringify({ v: value, t: Date.now(), ttl }), "utf8");
  } catch {}
}

/* =========================
 * Sessions + strict cookie jars
 * ========================= */

const SESSION_COOKIE = "euphoria_sid";
const SESSIONS = new Map();

function newSid() {
  return crypto.randomBytes(16).toString("hex") + Date.now().toString(36);
}

function parseCookieHeader(header = "") {
  const out = {};
  header
    .split(";")
    .map((x) => x.trim())
    .filter(Boolean)
    .forEach((p) => {
      const i = p.indexOf("=");
      if (i < 1) return;
      out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
    });
  return out;
}

function setSessionCookie(res, sid) {
  const ck = `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax`;
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
      created: Date.now(),
      last: Date.now(),
      ua: DEFAULT_UA,
      ip: req.ip || req.socket.remoteAddress || null,
      strictCookies: STRICT_COOKIES_DEFAULT,
      // originKey -> Map(name -> cookieObj)
      cookieJar: new Map(),
    });
    setSessionCookie(res, sid);
  }
  const s = SESSIONS.get(sid);
  s.last = Date.now();
  s.ip = req.ip || s.ip;
  return { sid, s };
}

setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [sid, s] of SESSIONS.entries()) {
    if (!s || s.last < cutoff) SESSIONS.delete(sid);
  }
}, 30 * 60 * 1000);

function normalizeHost(h) {
  return String(h || "").trim().toLowerCase();
}

function normalizePath(p) {
  const s = String(p || "/");
  return s.startsWith("/") ? s : "/" + s;
}

function parseSetCookie(sc) {
  try {
    const parts = String(sc).split(";").map((x) => x.trim());
    const first = parts.shift() || "";
    const eq = first.indexOf("=");
    if (eq < 1) return null;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();

    const out = {
      name,
      value,
      domain: null,
      path: "/",
      secure: false,
      httpOnly: false,
      sameSite: null,
      expiresAt: null,
    };

    for (const p of parts) {
      const [kRaw, ...rest] = p.split("=");
      const k = String(kRaw || "").trim().toLowerCase();
      const v = rest.join("=").trim();

      if (k === "domain") out.domain = normalizeHost(v.replace(/^\./, ""));
      else if (k === "path") out.path = normalizePath(v || "/");
      else if (k === "secure") out.secure = true;
      else if (k === "httponly") out.httpOnly = true;
      else if (k === "samesite") out.sameSite = v || null;
      else if (k === "max-age") {
        const sec = parseInt(v, 10);
        if (!Number.isNaN(sec)) out.expiresAt = Date.now() + sec * 1000;
      } else if (k === "expires") {
        const ts = Date.parse(v);
        if (!Number.isNaN(ts)) out.expiresAt = ts;
      } else {
        // flags like Secure/HttpOnly already handled
      }
    }

    return out;
  } catch {
    return null;
  }
}

function ensureOriginJar(session, originKey) {
  if (!session.cookieJar.has(originKey)) session.cookieJar.set(originKey, new Map());
  return session.cookieJar.get(originKey);
}

function storeSetCookiesStrict(session, originUrl, setCookies) {
  let u;
  try {
    u = new URL(originUrl);
  } catch {
    return;
  }
  const originKey = `${u.protocol}//${u.host}`;
  const host = normalizeHost(u.hostname);
  const jar = ensureOriginJar(session, originKey);

  for (const sc of setCookies || []) {
    const parsed = parseSetCookie(sc);
    if (!parsed) continue;

    const cd = parsed.domain ? normalizeHost(parsed.domain) : host;

    // STRICT: only exact host cookies (prevents “global” domain cookies causing cross-site weirdness)
    if (cd !== host) continue;

    // secure cookies only over https
    if (parsed.secure && u.protocol !== "https:") continue;

    // deletion
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

// Set-Cookie splitting: handle combined headers best-effort
function splitSetCookieHeader(v) {
  // split on comma that starts a new cookie "NAME="
  return String(v || "")
    .split(/,(?=[^ ;]+=)/g)
    .map((s) => s.trim())
    .filter(Boolean);
}

/* =========================
 * Fetch engine (keep-alive agents)
 * ========================= */

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 256 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 256 });

async function fetchUpstream(url, opts = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const u = new URL(url);
    const agent = u.protocol === "https:" ? httpsAgent : httpAgent;
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      // @ts-ignore
      agent,
      redirect: "manual",
    });
    return res;
  } finally {
    clearTimeout(t);
  }
}

/* =========================
 * Response header copying
 * ========================= */

function copyHeaders(up, down, { rewriting = false } = {}) {
  try {
    for (const [k, v] of up.headers.entries()) {
      const lk = k.toLowerCase();
      if (DROP_RESPONSE_HEADERS.has(lk)) continue;
      if (HOP_BY_HOP_HEADERS.has(lk)) continue;
      if (lk === "location") continue;
      if (rewriting) {
        if (lk === "content-encoding") continue;
        if (lk === "content-length") continue;
      }
      try {
        down.setHeader(k, v);
      } catch {}
    }
  } catch {}
}

/* =========================
 * Content-type / asset hinting
 * ========================= */

const BINARY_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css",
  ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
  ".ttf", ".otf", ".woff", ".woff2", ".eot",
  ".json", ".map",
  ".mp4", ".webm", ".mp3", ".m4a", ".wav", ".ogg",
  ".pdf", ".zip", ".rar", ".7z", ".avi", ".mov", ".mkv",
];

const SPECIAL_FILES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

function looksLikeAssetByPath(urlStr) {
  const cached = MEM_ASSET_HINT.get(urlStr);
  if (cached != null) return cached;

  let out = false;
  try {
    const u = new URL(urlStr);
    const p = (u.pathname || "").toLowerCase();
    out =
      SPECIAL_FILES.some((sf) => p.endsWith("/" + sf) || p.endsWith(sf)) ||
      BINARY_EXTENSIONS.some((ext) => p.endsWith(ext));
  } catch {
    const s = String(urlStr || "").toLowerCase();
    out =
      SPECIAL_FILES.some((sf) => s.endsWith("/" + sf) || s.endsWith(sf)) ||
      BINARY_EXTENSIONS.some((ext) => s.endsWith(ext));
  }
  MEM_ASSET_HINT.set(urlStr, out);
  return out;
}

function isHtmlContentType(ct) {
  const s = String(ct || "").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

/* =========================
 * Decompression / safe HTML sanitize
 * ========================= */

function maybeDecompress(buf, encHeader) {
  const enc = String(encHeader || "").toLowerCase();
  try {
    if (enc.includes("br") && ENABLE_BROTLI && zlib.brotliDecompressSync) return zlib.brotliDecompressSync(buf);
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
  } catch {}
  return buf;
}

function sanitizeHtml(html) {
  try {
    // strip CSP meta
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // strip SRI
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    // strip crossorigin hints that can cause blocked loads
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch {}
  return html;
}

/* =========================
 * Rewrite rules
 * ========================= */

function shouldSkipRewrite(v) {
  if (!v) return true;
  const s = String(v);
  if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(s)) return true;
  if (s.includes("/proxy?url=") || s.includes(`${SCRAMJET_PREFIX}?url=`)) return true;
  return false;
}

function toAbsMaybe(urlLike, base) {
  try {
    return new URL(urlLike, base).href;
  } catch {
    return null;
  }
}

function rewriteHtmlDom(html, baseUrl, req, mode = "proxy") {
  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }

  const document = dom.window.document;

  // Ensure <base>
  if (!document.querySelector("base")) {
    const head = document.querySelector("head");
    if (head) {
      const b = document.createElement("base");
      b.setAttribute("href", baseUrl);
      head.insertBefore(b, head.firstChild);
    }
  }

  const prox = (abs) => makeProxyUrl(abs, req, mode);

  const rewriteAttr = (el, attr) => {
    try {
      const v = el.getAttribute(attr);
      if (shouldSkipRewrite(v)) return;
      const abs = toAbsMaybe(v, baseUrl);
      if (!abs) return;
      el.setAttribute(attr, prox(abs));
    } catch {}
  };

  // anchors
  document.querySelectorAll("a[href]").forEach((a) => {
    rewriteAttr(a, "href");
    a.removeAttribute("target");
    a.removeAttribute("rel");
  });

  // forms
  document.querySelectorAll("form[action]").forEach((f) => rewriteAttr(f, "action"));

  // core tags
  ["img", "script", "iframe", "audio", "video", "source", "track"].forEach((tag) => {
    document.querySelectorAll(tag).forEach((el) => rewriteAttr(el, "src"));
  });
  document.querySelectorAll("link[href]").forEach((el) => rewriteAttr(el, "href"));

  // srcset for responsive images
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
          return prox(abs) + (size ? " " + size : "");
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
        return `url("${prox(abs)}")`;
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
        return `url("${prox(abs)}")`;
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
      m.setAttribute("content", c.replace(match[1], prox(abs)));
    } catch {}
  });

  // help some sites that depend on referrer defaults
  try {
    if (!document.querySelector('meta[name="referrer"]')) {
      const meta = document.createElement("meta");
      meta.setAttribute("name", "referrer");
      meta.setAttribute("content", "no-referrer-when-downgrade");
      (document.head || document.documentElement).appendChild(meta);
    }
  } catch {}

  return dom.serialize();
}

/* =========================
 * Inline JS rewriting (best-effort)
 * ========================= */

function rewriteInlineJs(code, baseUrl, req, mode = "proxy") {
  const prox = (abs) => makeProxyUrl(abs, req, mode);

  try {
    // fetch("...")
    code = code.replace(/fetch\(\s*(['"])([^'"]+)\1/g, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      const abs = toAbsMaybe(u, baseUrl);
      if (!abs) return m;
      return `fetch("${prox(abs)}"`;
    });

    // xhr.open("GET","...")
    code = code.replace(
      /\.open\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+)\3/gi,
      (m, q1, method, q2, u) => {
        if (shouldSkipRewrite(u)) return m;
        const abs = toAbsMaybe(u, baseUrl);
        if (!abs) return m;
        return `.open("${method || "GET"}","${prox(abs)}"`;
      }
    );

    // "/api/.." (relative absolute-path strings)
    code = code.replace(/(['"])(\/[^'"]+?)\1/g, (m, q, u) => {
      if (shouldSkipRewrite(u)) return m;
      const abs = toAbsMaybe(u, baseUrl);
      if (!abs) return m;
      return `"${prox(abs)}"`;
    });

    return code;
  } catch {
    return code;
  }
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

/* =========================
 * Runtime injection (prevents escaping + fixes button nav)
 * ========================= */

function injectClientRuntime(html, req, mode = "proxy") {
  const marker = "/*__EUPH_RUNTIME__*/";
  if (html.includes(marker)) return html;

  const origin = getPublicOrigin(req);
  const base = mode === "sj" ? `${SCRAMJET_PREFIX}?url=` : `/proxy?url=`;

  // Anti-loop: detect when already on proxy and avoid rewriting proxy->proxy
  // Also traps: click navigation, location assignments, history API, window.open, fetch/xhr.
  const js = `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(origin)};
  const BASE = ${JSON.stringify(base)};

  function isProxied(u){
    try { return typeof u === "string" && u.includes(BASE); } catch { return false; }
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
      const a = abs(u);
      // prevent proxy loop
      if(a.includes("/proxy?url=") || a.includes("${SCRAMJET_PREFIX}?url=")) return a;
      return ORIGIN + BASE + encodeURIComponent(a);
    }catch(e){ return u; }
  }

  // Fetch
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

  // History API: keep SPA nav inside
  try{
    const p = history.pushState;
    history.pushState = function(state, title, url){
      try{
        if(typeof url === "string" && url.length){
          const nu = prox(url);
          return p.call(history, state, title, nu);
        }
      }catch(e){}
      return p.apply(history, arguments);
    };
    const r = history.replaceState;
    history.replaceState = function(state, title, url){
      try{
        if(typeof url === "string" && url.length){
          const nu = prox(url);
          return r.call(history, state, title, nu);
        }
      }catch(e){}
      return r.apply(history, arguments);
    };
  }catch(e){}

  // Patch anchors at click-time (covers late-inserted DOM)
  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
      if(!a) return;
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(!isProxied(href)) a.setAttribute("href", prox(href));
      a.removeAttribute("target");
    }catch(e){}
  }, true);

  // Patch forms at submit-time
  document.addEventListener("submit", function(ev){
    try{
      const f = ev.target;
      if(!f || !f.getAttribute) return;
      const a = f.getAttribute("action") || "";
      if(a && !isProxied(a) && !/^(javascript:|mailto:|tel:|#)/i.test(a)){
        f.setAttribute("action", prox(a));
      }
    }catch(e){}
  }, true);

})();
</script>`.trim();

  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, js + "\n</body>");
  return html + "\n" + js;
}

/* =========================
 * Redirect trapping
 * ========================= */

function handleRedirect(up, req, res, requestTarget, mode = "proxy") {
  const loc = up.headers.get("location");
  if (!loc) return false;

  let abs;
  try {
    abs = new URL(loc, up.url || requestTarget).href;
  } catch {
    // if it's relative but parse failed, bail to upstream location string
    abs = loc;
  }

  const prox = makeProxyUrl(abs, req, mode);
  res.status(up.status || 302);
  res.setHeader("Location", prox);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(`Redirecting to ${prox}`);
  return true;
}

/* =========================
 * Streaming helpers (Range + media)
 * ========================= */

async function streamBody(up, down) {
  const body = up.body;
  if (!body) {
    down.end();
    return;
  }

  // Node 20 fetch body is ReadableStream
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

  // fallback
  const ab = await up.arrayBuffer();
  down.end(Buffer.from(ab));
}

/* =========================
 * Main proxy handler factory
 * ========================= */

function makeProxyHandler(mode = "proxy") {
  return async (req, res) => {
    const { s: session } = getSession(req, res);

    // Allow UI toggles:
    // /proxy?url=...&strictCookies=0
    if (typeof req.query.strictCookies !== "undefined") {
      session.strictCookies = String(req.query.strictCookies) !== "0";
    }

    const raw = req.query.url;
    if (!raw) {
      return res.status(400).send("Missing url. Use /proxy?url=example.com or /proxy?url=search terms");
    }

    const target = normalizeTarget(raw);
    if (!target) return res.status(400).send("Bad target.");

    // Decide if request “wants HTML”
    const accept = String(req.headers.accept || "").toLowerCase();
    const wantsHtml = accept.includes("text/html") || req.query.force_html === "1";

    const hasRange = !!req.headers.range;
    const cacheAllowed = req.method === "GET" && !hasRange;

    const cacheKeyBase = `${mode}::${target}::${wantsHtml ? "html" : "asset"}`;

    // Cache read
    if (cacheAllowed) {
      const mem = wantsHtml ? MEM_HTML.get(cacheKeyBase) : MEM_ASSET.get(cacheKeyBase);
      if (mem) {
        // headers
        if (mem.headers) {
          for (const [k, v] of Object.entries(mem.headers)) {
            try {
              res.setHeader(k, v);
            } catch {}
          }
        }
        res.status(mem.status || 200);
        if (wantsHtml) return res.end(mem.body);
        return res.end(Buffer.from(mem.bodyB64, "base64"));
      }

      const disk = await diskGet(cacheKeyBase);
      if (disk) {
        if (disk.headers) {
          for (const [k, v] of Object.entries(disk.headers)) {
            try {
              res.setHeader(k, v);
            } catch {}
          }
        }
        res.status(disk.status || 200);
        if (wantsHtml) return res.end(disk.body);
        return res.end(Buffer.from(disk.bodyB64, "base64"));
      }
    }

    // Upstream headers
    const hdrs = {};
    hdrs["user-agent"] = session.ua || DEFAULT_UA;
    hdrs["accept"] = req.headers.accept || "*/*";
    hdrs["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
    hdrs["accept-encoding"] = "gzip, deflate, br";

    // Range support (media/images)
    if (req.headers.range) hdrs["range"] = req.headers.range;

    // Cookies (strict per-origin jars)
    if (session.strictCookies) {
      const cookieHeader = buildCookieHeaderStrict(session, target);
      if (cookieHeader) hdrs["cookie"] = cookieHeader;
    }

    // Referer / Origin
    if (req.headers.referer) hdrs["referer"] = req.headers.referer;
    try {
      hdrs["origin"] = new URL(target).origin;
    } catch {}

    let up;
    try {
      up = await fetchUpstream(target, { method: "GET", headers: hdrs });
    } catch (e) {
      return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
    }

    // Store cookies from upstream
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
    const upstreamIsHtml = isHtmlContentType(ct);
    const treatAsHtml = wantsHtml || upstreamIsHtml;

    // Copy headers (rewriting: strip encoding/length so we can safely change body)
    copyHeaders(up, res, { rewriting: treatAsHtml });

    // HTML path
    if (treatAsHtml) {
      let rawBuf;
      try {
        rawBuf = Buffer.from(await up.arrayBuffer());
        if (rawBuf.length > MAX_HTML_BYTES) throw new Error("html_too_large");
      } catch (e) {
        return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
      }

      // Decompress if needed
      const dec = maybeDecompress(rawBuf, up.headers.get("content-encoding"));

      // Decode
      let html = "";
      try {
        html = dec.toString("utf8");
      } catch {
        html = Buffer.from(dec).toString("utf8");
      }

      // sanitize + rewrite DOM
      html = sanitizeHtml(html);
      const baseUrl = up.url || target;

      let out = rewriteHtmlDom(html, baseUrl, req, mode);

      // optional: inline script rewrite + SW neuter (single pass, to reduce CPU)
      try {
        const dom2 = new JSDOM(out, { url: baseUrl, contentType: "text/html" });
        const doc2 = dom2.window.document;

        // neuter SW registration in inline scripts
        doc2.querySelectorAll("script:not([src])").forEach((s) => {
          let code = s.textContent || "";
          if (!code.trim()) return;
          code = neuterServiceWorkerJs(code);
          code = rewriteInlineJs(code, baseUrl, req, mode);
          s.textContent = code;
        });

        out = dom2.serialize();
      } catch {
        // keep out as-is
      }

      // inject runtime (keeps navigation/buttons inside)
      out = injectClientRuntime(out, req, mode);

      // Response headers
      res.status(up.status || 200);
      res.setHeader("Content-Type", "text/html; charset=utf-8");

      // IMPORTANT: avoid caching auth-heavy HTML by default (keeps logins more stable)
      res.setHeader("Cache-Control", "no-store");

      // Cache small non-auth HTML only (safe-ish)
      const cacheOk = cacheAllowed && out.length <= 700 * 1024;
      if (cacheOk) {
        const payload = { status: up.status || 200, headers: { "Content-Type": "text/html; charset=utf-8" }, body: out };
        MEM_HTML.set(cacheKeyBase, payload);
        diskSet(cacheKeyBase, payload, TTL_HTML_MS).catch(() => {});
      }

      return res.end(out);
    }

    // Asset path
    res.status(up.status || 200);

    // Range requests -> stream, no buffer
    if (hasRange) {
      return streamBody(up, res);
    }

    // Buffer for cache if small, else stream
    let ab;
    try {
      ab = await up.arrayBuffer();
    } catch {
      return streamBody(up, res);
    }
    const bodyBuf = Buffer.from(ab);

    // Cache small assets
    if (cacheAllowed && bodyBuf.length <= MAX_ASSET_BUFFER_BYTES) {
      const headersObj = {};
      try {
        for (const [k, v] of up.headers.entries()) {
          const lk = k.toLowerCase();
          if (DROP_RESPONSE_HEADERS.has(lk)) continue;
          if (HOP_BY_HOP_HEADERS.has(lk)) continue;
          if (lk === "content-length") continue;
          headersObj[k] = v;
        }
      } catch {}

      const payload = {
        status: up.status || 200,
        headers: headersObj,
        bodyB64: bodyBuf.toString("base64"),
      };

      MEM_ASSET.set(cacheKeyBase, payload);
      diskSet(cacheKeyBase, payload, TTL_ASSET_MS).catch(() => {});
    }

    return res.end(bodyBuf);
  };
}

/* =========================
 * Routes
 * ========================= */

// Basic proxy
app.get("/proxy", makeProxyHandler("proxy"));

// Clean URL style: /proxy/:host/* -> /proxy?url=https://host/*
app.get(/^\/proxy\/([^/]+)\/(.*)$/i, (req, res, next) => {
  try {
    const host = req.params?.[0] || "";
    const rest = req.params?.[1] || "";
    if (!host) return next();
    const combined = decodeURIComponentSafe(`${host}/${rest}`);
    const url = normalizeTarget(combined);
    if (!url) return next();
    return res.redirect(302, `/proxy?url=${encodeURIComponent(url)}`);
  } catch {
    return next();
  }
});

/* =========================
 * Scramjet mount (optional)
 * ========================= */

if (ENABLE_SCRAMJET) {
  if (typeof ScramjetFactory === "function") {
    try {
      const sj = ScramjetFactory({ prefix: SCRAMJET_PREFIX });

      // Best-effort shape detection
      if (typeof sj === "function") {
        app.use(SCRAMJET_PREFIX, sj);
        log("[SCRAMJET] mounted middleware at", SCRAMJET_PREFIX);
      } else if (sj && typeof sj.handler === "function") {
        app.use(SCRAMJET_PREFIX, (req, res, next) => sj.handler(req, res, next));
        log("[SCRAMJET] mounted handler at", SCRAMJET_PREFIX);
      } else {
        // fallback route using our proxy pipeline
        app.get(SCRAMJET_PREFIX, makeProxyHandler("sj"));
        log("[SCRAMJET] unknown API shape; falling back to internal /sj proxy pipeline");
      }
    } catch (e) {
      app.get(SCRAMJET_PREFIX, makeProxyHandler("sj"));
      log("[SCRAMJET] init failed; falling back to internal /sj proxy:", e?.message || e);
    }
  } else {
    app.get(SCRAMJET_PREFIX, makeProxyHandler("sj"));
    log("[SCRAMJET] package not available; internal /sj proxy pipeline enabled");
  }
} else {
  // keep route available as alias even if disabled
  app.get(SCRAMJET_PREFIX, makeProxyHandler("sj"));
}

/* =========================
 * Escaped-path catcher (keeps apps working)
 * ========================= */

app.use((req, res, next) => {
  const p = req.path || "/";
  if (
    p.startsWith("/proxy") ||
    p.startsWith(SCRAMJET_PREFIX) ||
    p.startsWith("/_euph_debug") ||
    p.startsWith("/static") ||
    p.startsWith("/public")
  ) return next();

  // If some site tries to load /_next/... directly, reconstruct from referer url=...
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

  let baseOrigin;
  try {
    baseOrigin = new URL(base).origin;
  } catch {
    return next();
  }

  const attempt = new URL(req.originalUrl, baseOrigin).href;
  return res.redirect(302, makeProxyUrl(attempt, req, "proxy"));
});

/* =========================
 * Home + SPA fallback
 * ========================= */

app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

/* =========================
 * Admin/debug
 * ========================= */

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

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
  MEM_HTML.clear();
  MEM_ASSET.clear();
  MEM_ASSET_HINT.clear();
  if (ENABLE_DISK_CACHE) {
    try {
      const files = await fsPromises.readdir(CACHE_DIR);
      for (const f of files) await fsPromises.unlink(path.join(CACHE_DIR, f)).catch(() => {});
    } catch {}
  }
  res.json({ ok: true });
});

/* =========================
 * Start server
 * ========================= */

const server = http.createServer(app);

server.listen(PORT, () => {
  log(`[BOOT] listening on ${PORT}`);
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
process.on("SIGTERM", () => {
  try {
    server.close();
  } catch {}
  process.exit(0);
});