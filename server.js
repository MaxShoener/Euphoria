// server.js — Euphoria Hybrid (Canonical DOM + Transport Proxy, no iframes)
// Node 20+, ESM. Express proxy that:
//  - HTML: rewrites URLs to absolute UPSTREAM (canonical), injects runtime that traps navigation/network into proxy
//  - Assets/Media: streams with Range support
//  - Redirects: trapped into /proxy
//  - Cookies: per-upstream-host cookie jar (domain/path/secure/expiry matching) for best-shot logins
//  - Scramjet: safe optional mount at /sj (never crashes if API shape changes)

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

// Scramjet: CommonJS-safe import (do not assume named exports)
import scramjetPkg from "@mercuryworkshop/scramjet";
const ScramjetFactory =
  scramjetPkg?.createScramjetServer ||
  scramjetPkg?.createServer ||
  scramjetPkg?.default?.createScramjetServer ||
  scramjetPkg?.default?.createServer ||
  null;

/* ───────────────────────────────────────────── */
/* Config                                        */
/* ───────────────────────────────────────────── */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8000);
const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

const TRUST_PROXY_HOPS = Number(process.env.TRUST_PROXY_HOPS || 1); // avoid permissive trust proxy warning
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
const QUIET_LOGS = process.env.QUIET_LOGS === "1";

const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const MAX_HTML_BYTES = Number(process.env.MAX_HTML_BYTES || 25 * 1024 * 1024);
const MAX_ASSET_CACHE_BYTES = Number(process.env.MAX_ASSET_CACHE_BYTES || 5 * 1024 * 1024);
const MAX_HTML_CACHE_CHARS = Number(process.env.MAX_HTML_CACHE_CHARS || 900_000);

const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const ENABLE_SCRAMJET = process.env.ENABLE_SCRAMJET !== "0";
const DISABLE_SERVICE_WORKERS = process.env.DISABLE_SERVICE_WORKERS !== "0";

const RATE_LIMIT_GLOBAL = Number(process.env.RATE_LIMIT_GLOBAL || 900);
const MEM_CACHE_ITEMS = Number(process.env.MEM_CACHE_ITEMS || 6000);

// drop headers that break embedding/proxying or are hop-by-hop
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

function log(...args) {
  if (!QUIET_LOGS) console.log(...args);
}

/* ───────────────────────────────────────────── */
/* Disk cache init                               */
/* ───────────────────────────────────────────── */

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
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
    if (Date.now() > (obj.expiresAt || 0)) return null;
    return obj.value ?? null;
  } catch {
    return null;
  }
}
async function diskSet(key, value, ttlMs) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(
      f,
      JSON.stringify({ value, expiresAt: Date.now() + ttlMs }),
      "utf8"
    );
  } catch {}
}

/* ───────────────────────────────────────────── */
/* Express setup                                 */
/* ───────────────────────────────────────────── */

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
    max: RATE_LIMIT_GLOBAL,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

/* ───────────────────────────────────────────── */
/* Public origin + target parsing                */
/* ───────────────────────────────────────────── */

function getPublicOrigin(req) {
  const xfProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const xfHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const host = String(xfHost || req.headers.host || "").split(",")[0].trim();
  const proto = (xfProto || (req.socket.encrypted ? "https" : "http")).trim();
  if (!host) return "";
  return `${proto}://${host}`;
}

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
  try {
    if (/^https?:\/\//i.test(s)) return new URL(s).href;
    if (looksUrlish(s)) return new URL("https://" + s).href;
    return null;
  } catch {
    return null;
  }
}
function googleSearchUrl(q) {
  const t = String(q || "").trim();
  if (!t) return "https://www.google.com/";
  return "https://www.google.com/search?q=" + encodeURIComponent(t);
}

function getTargetFromReq(req) {
  // supported:
  //  - /proxy?url=<url OR plain text => treated as search>
  //  - /proxy?q=<search>
  //  - /proxy/:host/*  (handled separately then redirected into /proxy?url=)
  if (req.query?.q && !req.query?.url) return googleSearchUrl(req.query.q);

  if (typeof req.query?.url !== "undefined") {
    const raw = String(req.query.url || "");
    const maybeUrl = normalizeToHttpUrl(raw);
    return maybeUrl || googleSearchUrl(raw); // IMPORTANT: text becomes Google search (prevents Missing url)
  }

  return null;
}

function makeProxyTransportUrl(absUpstreamUrl, req) {
  const origin = getPublicOrigin(req);
  return `${origin}/proxy?url=${encodeURIComponent(absUpstreamUrl)}`;
}

/* ───────────────────────────────────────────── */
/* Cookie jar (browser-like)                     */
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
      created: Date.now(),
      last: Date.now(),
      ua: DEFAULT_UA,
      // host -> Map(name -> cookie)
      // cookie: {value, domain, path, secure, httpOnly, sameSite, expiresAt}
      jar: new Map(),
      // toggles from UI (best-shot defaults)
      strictCookies: false,
    });
    setSessionCookie(res, sid);
  }
  const s = SESSIONS.get(sid);
  s.last = Date.now();
  setSessionCookie(res, sid);
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
function domainMatches(cookieDomain, reqHost) {
  if (!cookieDomain) return false;
  const cd = normalizeHost(cookieDomain).replace(/^\./, "");
  const rh = normalizeHost(reqHost);
  return rh === cd || rh.endsWith("." + cd);
}
function pathMatches(cookiePath, reqPath) {
  const cp = normalizePath(cookiePath || "/");
  const rp = normalizePath(reqPath || "/");
  return rp === cp || rp.startsWith(cp);
}

// Header.getSetCookie() exists in some Node builds; fallback split heuristic otherwise
function getSetCookiesFromHeaders(headers) {
  try {
    if (typeof headers.getSetCookie === "function") return headers.getSetCookie() || [];
  } catch {}
  const sc = headers.get("set-cookie");
  if (!sc) return [];
  return String(sc).split(/,(?=[^ ;]+=)/g).map((s) => s.trim()).filter(Boolean);
}

function parseSetCookie(sc) {
  // RFC-ish parser (good enough)
  try {
    const parts = String(sc).split(";").map((s) => s.trim());
    const first = parts.shift() || "";
    const eq = first.indexOf("=");
    if (eq < 1) return null;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();

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

function ensureHostJar(session, host) {
  const h = normalizeHost(host);
  if (!session.jar.has(h)) session.jar.set(h, new Map());
  return session.jar.get(h);
}

function storeSetCookies(session, upstreamUrl, setCookies) {
  let u;
  try {
    u = new URL(upstreamUrl);
  } catch {
    return;
  }

  const reqHost = normalizeHost(u.hostname);
  const jar = ensureHostJar(session, reqHost);

  for (const sc of setCookies || []) {
    const parsed = parseSetCookie(sc);
    if (!parsed) continue;

    const cookieDomain = parsed.domain ? normalizeHost(parsed.domain) : reqHost;

    // strictCookies = host-only; relaxed = browser-like domain suffix match
    if (session.strictCookies) {
      if (cookieDomain !== reqHost) continue;
    } else {
      if (!domainMatches(cookieDomain, reqHost)) continue;
    }

    // secure cookie should not be set from http upstream
    if (parsed.secure && u.protocol !== "https:") continue;

    // delete expired
    if (parsed.expiresAt && parsed.expiresAt <= Date.now()) {
      jar.delete(parsed.name);
      continue;
    }

    jar.set(parsed.name, {
      value: parsed.value,
      domain: cookieDomain,
      path: parsed.path || "/",
      secure: !!parsed.secure,
      httpOnly: !!parsed.httpOnly,
      sameSite: parsed.sameSite,
      expiresAt: parsed.expiresAt,
    });
  }
}

function buildCookieHeader(session, upstreamUrl) {
  let u;
  try {
    u = new URL(upstreamUrl);
  } catch {
    return "";
  }

  const host = normalizeHost(u.hostname);
  const jar = session.jar.get(host);
  if (!jar) return "";

  const isHttps = u.protocol === "https:";
  const reqPath = normalizePath(u.pathname || "/");
  const now = Date.now();

  const pairs = [];
  for (const [name, c] of jar.entries()) {
    if (c.expiresAt && c.expiresAt <= now) {
      jar.delete(name);
      continue;
    }
    if (c.secure && !isHttps) continue;
    if (!domainMatches(c.domain, host)) continue;
    if (!pathMatches(c.path, reqPath)) continue;
    pairs.push(`${name}=${c.value}`);
  }
  return pairs.join("; ");
}

/* ───────────────────────────────────────────── */
/* Upstream fetch (keepalive + timeout)          */
/* ───────────────────────────────────────────── */

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 256 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 256 });

async function fetchUpstream(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
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
    clearTimeout(timer);
  }
}

function isHtmlContentType(ct) {
  const s = String(ct || "").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

function maybeDecompress(buf, encoding) {
  const enc = String(encoding || "").toLowerCase();
  try {
    if (enc.includes("br") && zlib.brotliDecompressSync) return zlib.brotliDecompressSync(buf);
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
  } catch {}
  return buf;
}

function copyHeaders(up, down, { rewriting = false } = {}) {
  try {
    for (const [k, v] of up.headers.entries()) {
      const lk = k.toLowerCase();
      if (DROP_RESPONSE_HEADERS.has(lk)) continue;
      if (HOP_BY_HOP_HEADERS.has(lk)) continue;
      if (lk === "location") continue; // we trap redirects ourselves
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

async function streamBody(up, down) {
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
  const ab = await up.arrayBuffer();
  down.end(Buffer.from(ab));
}

/* ───────────────────────────────────────────── */
/* Canonical HTML rewrite                         */
/* ───────────────────────────────────────────── */

function shouldSkipUrl(u) {
  if (!u) return true;
  const s = String(u);
  return /^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(s);
}

function toAbsUpstream(urlLike, baseUrl) {
  try {
    return new URL(urlLike, baseUrl).href;
  } catch {
    return null;
  }
}

function rewriteHtmlToCanonicalAbsolute(html, baseUrl) {
  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }
  const document = dom.window.document;

  // Ensure base tag is canonical upstream baseUrl
  if (!document.querySelector("base")) {
    const head = document.querySelector("head");
    if (head) {
      const b = document.createElement("base");
      b.setAttribute("href", baseUrl);
      head.insertBefore(b, head.firstChild);
    }
  }

  const rewriteAttrToAbs = (el, attr) => {
    try {
      const val = el.getAttribute(attr);
      if (shouldSkipUrl(val)) return;
      if (!val) return;
      const abs = toAbsUpstream(val, baseUrl);
      if (!abs) return;
      el.setAttribute(attr, abs); // IMPORTANT: canonical upstream (NOT proxied)
    } catch {}
  };

  // anchors/forms
  document.querySelectorAll("a[href]").forEach((a) => {
    rewriteAttrToAbs(a, "href");
    a.removeAttribute("target");
  });
  document.querySelectorAll("form[action]").forEach((f) => rewriteAttrToAbs(f, "action"));

  // resources
  ["img", "script", "iframe", "audio", "video", "source", "track"].forEach((tag) => {
    document.querySelectorAll(tag).forEach((el) => rewriteAttrToAbs(el, "src"));
  });
  document.querySelectorAll("link[href]").forEach((el) => rewriteAttrToAbs(el, "href"));

  // srcset
  document.querySelectorAll("[srcset]").forEach((el) => {
    try {
      const srcset = el.getAttribute("srcset");
      if (!srcset) return;
      const out = srcset
        .split(",")
        .map((part) => {
          const [u, size] = part.trim().split(/\s+/, 2);
          if (shouldSkipUrl(u)) return part;
          const abs = toAbsUpstream(u, baseUrl);
          if (!abs) return part;
          return abs + (size ? " " + size : "");
        })
        .join(", ");
      el.setAttribute("srcset", out);
    } catch {}
  });

  // inline styles + style blocks url(...)
  const rewriteCssUrls = (css) =>
    String(css || "").replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
      if (shouldSkipUrl(u)) return m;
      const abs = toAbsUpstream(u, baseUrl);
      return abs ? `url("${abs}")` : m;
    });

  document.querySelectorAll("[style]").forEach((el) => {
    try {
      const s = el.getAttribute("style");
      if (!s) return;
      el.setAttribute("style", rewriteCssUrls(s));
    } catch {}
  });
  document.querySelectorAll("style").forEach((st) => {
    try {
      st.textContent = rewriteCssUrls(st.textContent || "");
    } catch {}
  });

  // meta refresh url=
  document.querySelectorAll("meta[http-equiv]").forEach((m) => {
    try {
      if ((m.getAttribute("http-equiv") || "").toLowerCase() !== "refresh") return;
      const c = m.getAttribute("content") || "";
      const match = c.match(/url=(.+)$/i);
      if (!match) return;
      const abs = toAbsUpstream(match[1], baseUrl);
      if (!abs) return;
      m.setAttribute("content", c.replace(match[1], abs));
    } catch {}
  });

  return dom.serialize();
}

function sanitizeHtml(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch {}
  return html;
}

function neuterServiceWorkerInline(code) {
  if (!DISABLE_SERVICE_WORKERS) return code;
  try {
    return String(code)
      .replace(/navigator\s*\.\s*serviceWorker\s*\.\s*register/gi, "/*euph*/null&&navigator.serviceWorker.register")
      .replace(/serviceWorker\s*\.\s*register/gi, "/*euph*/null&&serviceWorker.register");
  } catch {
    return code;
  }
}

function injectRuntime(html, req, canonicalBaseUrl) {
  const marker = "/*__EUPHORIA_RUNTIME_V1__*/";
  if (html.includes(marker)) return html;

  const origin = getPublicOrigin(req);
  const runtime = `
<script>
${marker}
(function(){
  // Canonical base is the upstream page URL (NOT the proxy URL)
  const CANON_BASE = ${JSON.stringify(canonicalBaseUrl)};
  const PROXY = ${JSON.stringify(origin + "/proxy?url=")};

  function isProxied(u){ return typeof u === "string" && u.startsWith(PROXY); }

  function toAbsUpstream(u){
    try { return new URL(u, CANON_BASE).href; } catch(e){ return u; }
  }
  function prox(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(isProxied(u)) return u;
      if(/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u)) return u;
      const abs = toAbsUpstream(u);
      return PROXY + encodeURIComponent(abs);
    }catch(e){ return u; }
  }

  // 1) Network layer
  try{
    const ofetch = window.fetch;
    window.fetch = function(resource, init){
      try{
        if(typeof resource === "string") resource = prox(resource);
        else if(resource instanceof Request) resource = new Request(prox(resource.url), resource);
      }catch(e){}
      return ofetch.call(this, resource, init);
    };
  }catch(e){}

  try{
    const OXHR = XMLHttpRequest;
    XMLHttpRequest = function(){
      const x = new OXHR();
      const open = x.open;
      x.open = function(method, url){
        try{ url = prox(url); }catch(e){}
        return open.apply(this, arguments);
      };
      return x;
    };
  }catch(e){}

  // 2) Navigation layer
  try{
    const assign = location.assign.bind(location);
    const replace = location.replace.bind(location);
    location.assign = u => assign(prox(u));
    location.replace = u => replace(prox(u));
  }catch(e){}

  try{
    const ps = history.pushState;
    history.pushState = function(state, title, url){
      // Keep the site's internal history canonical (upstream), not proxied
      // But if a site passes a relative url, normalize it canonical.
      try{
        if(typeof url === "string") url = toAbsUpstream(url);
      }catch(e){}
      return ps.apply(this, arguments);
    };
    const rs = history.replaceState;
    history.replaceState = function(state, title, url){
      try{
        if(typeof url === "string") url = toAbsUpstream(url);
      }catch(e){}
      return rs.apply(this, arguments);
    };
  }catch(e){}

  // 3) Click + form trapping (keeps you inside Euphoria)
  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
      if(!a) return;
      const href = a.getAttribute("href");
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      ev.preventDefault();
      // href in DOM is canonical absolute upstream (or normalized)
      location.href = prox(href);
    }catch(e){}
  }, true);

  document.addEventListener("submit", function(ev){
    try{
      const f = ev.target && ev.target.tagName === "FORM" ? ev.target : null;
      if(!f) return;
      const action = f.getAttribute("action") || CANON_BASE;
      // keep form action canonical in DOM (upstream absolute)
      const canon = toAbsUpstream(action);
      f.setAttribute("action", canon);
      // and force navigation through proxy:
      // NOTE: we let the browser submit normally, but action is upstream;
      // the navigation interception of location is not used for native submits.
      // So we rewrite action at the last moment into the proxy transport URL.
      f.setAttribute("action", PROXY + encodeURIComponent(canon));
    }catch(e){}
  }, true);

  // 4) Keep DOM canonical for dynamically inserted relative URLs
  // Lightweight observer: only touches common URL attrs, converts relative->absolute upstream
  const URL_ATTRS = ["href","src","action","poster"];
  function normalizeNode(node){
    try{
      if(!node || node.nodeType !== 1) return;
      const el = node;
      for(const a of URL_ATTRS){
        if(!el.hasAttribute || !el.hasAttribute(a)) continue;
        const v = el.getAttribute(a);
        if(!v) continue;
        if(/^(https?:|data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(v)) continue;
        try{
          el.setAttribute(a, toAbsUpstream(v));
        }catch(e){}
      }
      if(el.hasAttribute && el.hasAttribute("srcset")){
        const ss = el.getAttribute("srcset");
        if(ss){
          const out = ss.split(",").map(part=>{
            const bits = part.trim().split(/\\s+/, 2);
            const u = bits[0] || "";
            const size = bits[1] || "";
            if(!u) return part;
            if(/^(https?:|data:|blob:)/i.test(u)) return part;
            const abs = toAbsUpstream(u);
            return abs + (size ? " " + size : "");
          }).join(", ");
          el.setAttribute("srcset", out);
        }
      }
    }catch(e){}
  }

  try{
    const mo = new MutationObserver(muts=>{
      for(const m of muts){
        if(m.type === "attributes"){
          normalizeNode(m.target);
        }else if(m.addedNodes && m.addedNodes.length){
          m.addedNodes.forEach(n=>{
            normalizeNode(n);
            if(n.querySelectorAll){
              n.querySelectorAll("[href],[src],[action],[poster],[srcset]").forEach(normalizeNode);
            }
          });
        }
      }
    });
    mo.observe(document.documentElement, { subtree:true, childList:true, attributes:true, attributeFilter:["href","src","action","poster","srcset"] });
  }catch(e){}
})();
</script>`.trim();

  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, runtime + "\n</body>");
  return html + "\n" + runtime;
}

function rewriteInlineScripts(html, baseUrl) {
  // Keep it light: only neuter service-worker registrations.
  // (Heavy JS rewriting tends to be fragile + high CPU.)
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const doc = dom.window.document;
    doc.querySelectorAll("script:not([src])").forEach((s) => {
      try {
        const code = s.textContent || "";
        if (!code.trim()) return;
        s.textContent = neuterServiceWorkerInline(code);
      } catch {}
    });
    return dom.serialize();
  } catch {
    return html;
  }
}

/* ───────────────────────────────────────────── */
/* Proxy core                                    */
/* ───────────────────────────────────────────── */

const MEM_CACHE = new LRUCache({ max: MEM_CACHE_ITEMS });

function isCacheableHtml(req, upstreamUrl) {
  // Default: cache small HTML for speed, but avoid caching when user explicitly toggles it off
  // or if this looks like auth-related navigation.
  try {
    const u = new URL(upstreamUrl);
    const h = u.hostname.toLowerCase();
    if (h.includes("accounts.") || h.includes("login.") || h.includes("oauth") || h.includes("signin")) return false;
  } catch {}
  return true;
}

async function handleProxy(req, res) {
  const { s: session } = getSession(req, res);

  // UI toggle: strictCookies=1 (host-only) or 0 (browser-like domain matching)
  if (typeof req.query.strictCookies !== "undefined") {
    session.strictCookies = String(req.query.strictCookies) === "1";
  }

  const target = getTargetFromReq(req);
  if (!target) {
    return res.status(400).send("Missing url. Use /proxy?url=example.com or /proxy?q=search terms.");
  }

  const accept = String(req.headers.accept || "").toLowerCase();
  const wantsHtml = accept.includes("text/html") || req.query.force_html === "1";

  const hasRange = !!req.headers.range;
  const cacheAllowed = req.method === "GET" && !hasRange;

  const cacheBase = `proxy::${target}::${wantsHtml ? "html" : "asset"}`;

  // cache hit
  if (cacheAllowed) {
    const mem = MEM_CACHE.get(cacheBase);
    if (mem) {
      if (mem.type === "html") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.end(mem.body);
      }
      if (mem.type === "asset") {
        if (mem.headers) {
          for (const [k, v] of Object.entries(mem.headers)) {
            try { res.setHeader(k, v); } catch {}
          }
        }
        return res.end(Buffer.from(mem.bodyB64, "base64"));
      }
    }

    const disk = await diskGet(cacheBase);
    if (disk) {
      if (disk.type === "html") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.end(disk.body);
      }
      if (disk.type === "asset") {
        if (disk.headers) {
          for (const [k, v] of Object.entries(disk.headers)) {
            try { res.setHeader(k, v); } catch {}
          }
        }
        return res.end(Buffer.from(disk.bodyB64, "base64"));
      }
    }
  }

  // upstream headers
  const headers = {};
  headers["user-agent"] = session.ua || DEFAULT_UA;
  headers["accept"] = req.headers.accept || "*/*";
  headers["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
  headers["accept-encoding"] = "gzip, deflate, br";
  if (req.headers.range) headers["range"] = req.headers.range;

  // cookies
  const cookieHeader = buildCookieHeader(session, target);
  if (cookieHeader) headers["cookie"] = cookieHeader;

  // referer/origin coherence (helps some flows)
  if (req.headers.referer) headers["referer"] = req.headers.referer;
  try {
    headers["origin"] = new URL(target).origin;
  } catch {}

  let up;
  try {
    up = await fetchUpstream(target, { method: "GET", headers });
  } catch (e) {
    return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
  }

  // store cookies
  try {
    const setCookies = getSetCookiesFromHeaders(up.headers);
    if (setCookies.length) storeSetCookies(session, up.url || target, setCookies);
  } catch {}

  // redirect trap
  if ([301, 302, 303, 307, 308].includes(up.status)) {
    const loc = up.headers.get("location");
    if (loc) {
      let abs;
      try {
        abs = new URL(loc, up.url || target).href;
      } catch {
        abs = loc;
      }
      const prox = makeProxyTransportUrl(abs, req);
      res.status(up.status);
      res.setHeader("Location", prox);
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.end(`Redirecting to ${prox}`);
    }
  }

  const ct = up.headers.get("content-type") || "";
  const isHtml = wantsHtml || isHtmlContentType(ct);

  // HTML path: buffer, canonical rewrite, inject runtime, light SW neuter
  if (isHtml) {
    let raw;
    try {
      raw = Buffer.from(await up.arrayBuffer());
      if (raw.length > MAX_HTML_BYTES) throw new Error("html_too_large");
    } catch (e) {
      return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
    }

    copyHeaders(up, res, { rewriting: true });

    const dec = maybeDecompress(raw, up.headers.get("content-encoding"));
    let html = "";
    try {
      html = dec.toString("utf8");
    } catch {
      html = Buffer.from(dec).toString("utf8");
    }

    html = sanitizeHtml(html);

    const canonicalBase = up.url || target;
    let out = rewriteHtmlToCanonicalAbsolute(html, canonicalBase);
    out = rewriteInlineScripts(out, canonicalBase);
    out = injectRuntime(out, req, canonicalBase);

    res.status(up.status || 200);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");

    // cache small + non-authy HTML for speed (optional)
    if (cacheAllowed && isCacheableHtml(req, canonicalBase) && out.length <= MAX_HTML_CACHE_CHARS) {
      const payload = { type: "html", body: out };
      MEM_CACHE.set(cacheBase, payload);
      diskSet(cacheBase, payload, 6 * 60 * 1000).catch(() => {});
    }

    return res.end(out);
  }

  // Asset/media path: stream (Range supported), cache small
  copyHeaders(up, res, { rewriting: false });
  res.status(up.status || 200);

  // If range => stream without buffering
  if (hasRange) {
    return streamBody(up, res);
  }

  // buffer to optionally cache
  let ab;
  try {
    ab = await up.arrayBuffer();
  } catch {
    return streamBody(up, res);
  }
  const bodyBuf = Buffer.from(ab);

  if (cacheAllowed && bodyBuf.length <= MAX_ASSET_CACHE_BYTES) {
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
    const payload = { type: "asset", headers: headersObj, bodyB64: bodyBuf.toString("base64") };
    MEM_CACHE.set(cacheBase, payload);
    diskSet(cacheBase, payload, 60 * 60 * 1000).catch(() => {});
  }

  return res.end(bodyBuf);
}

/* ───────────────────────────────────────────── */
/* Routes                                        */
/* ───────────────────────────────────────────── */

app.get("/proxy", handleProxy);

// Clean style support: /proxy/:host/* -> /proxy?url=https://host/*
app.get(/^\/proxy\/([^/]+)\/(.*)$/i, (req, res, next) => {
  try {
    const host = req.params?.[0] || "";
    const rest = req.params?.[1] || "";
    if (!host) return next();
    const combined = `${host}/${rest}`;
    const decoded = (() => { try { return decodeURIComponent(combined); } catch { return combined; } })();
    const url = normalizeToHttpUrl(decoded);
    if (!url) return next();
    return res.redirect(302, `/proxy?url=${encodeURIComponent(url)}`);
  } catch {
    return next();
  }
});

// Optional Scramjet mount at /sj (safe; never crashes). If Scramjet is not usable, /sj falls back to /proxy behavior.
if (ENABLE_SCRAMJET) {
  if (typeof ScramjetFactory === "function") {
    try {
      const sj = ScramjetFactory({ prefix: "/sj" });

      if (typeof sj === "function") {
        app.use("/sj", sj);
        log("[SCRAMJET] mounted middleware at /sj");
      } else if (sj && typeof sj.handler === "function") {
        app.use("/sj", (req, res, next) => sj.handler(req, res, next));
        log("[SCRAMJET] mounted handler at /sj");
      } else if (sj && typeof sj.fetch === "function") {
        // fetch-bridge shape
        app.use("/sj", async (req, res) => {
          try {
            const origin = getPublicOrigin(req) || "http://localhost";
            const url = new URL(req.originalUrl, origin);
            const r = await sj.fetch(url.href, { method: req.method, headers: req.headers });
            res.status(r.status);
            r.headers.forEach((v, k) => { try { res.setHeader(k, v); } catch {} });
            const buf = Buffer.from(await r.arrayBuffer());
            res.end(buf);
          } catch (e) {
            res.status(502).send("Scramjet error: " + String(e?.message || e));
          }
        });
        log("[SCRAMJET] mounted fetch bridge at /sj");
      } else {
        // unknown shape fallback
        app.get("/sj", handleProxy);
        log("[SCRAMJET] unknown factory shape, /sj falling back to proxy");
      }
    } catch (e) {
      app.get("/sj", handleProxy);
      log("[SCRAMJET] init failed, /sj falling back to proxy:", e?.message || e);
    }
  } else {
    app.get("/sj", handleProxy);
    log("[SCRAMJET] not available, /sj falling back to proxy");
  }
} else {
  app.get("/sj", handleProxy);
}

// Keep “escaped” asset paths inside Euphoria by reconstructing from referer ?url=
app.use((req, res, next) => {
  try {
    const p = req.path || "/";
    if (
      p.startsWith("/proxy") ||
      p.startsWith("/sj") ||
      p.startsWith("/_euph_debug") ||
      p.startsWith("/static") ||
      p.startsWith("/public")
    ) return next();

    const ref = req.headers.referer || req.headers.referrer || "";
    const m = String(ref).match(/[?&]url=([^&]+)/);
    if (!m) return next();

    const base = decodeURIComponent(m[1] || "");
    if (!base) return next();

    const baseOrigin = new URL(base).origin;
    const attempt = new URL(req.originalUrl, baseOrigin).href;
    return res.redirect(302, `/proxy?url=${encodeURIComponent(attempt)}`);
  } catch {
    return next();
  }
});

// Home
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

// Debug/admin
app.get("/_euph_debug/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));
app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, s] of SESSIONS.entries()) {
    out[sid] = {
      created: new Date(s.created).toISOString(),
      last: new Date(s.last).toISOString(),
      strictCookies: !!s.strictCookies,
      hosts: [...s.jar.keys()].length,
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

// Start
const server = http.createServer(app);
server.listen(PORT, () => log(`[BOOT] listening on ${PORT}`));

process.on("unhandledRejection", (err) => console.error("unhandledRejection", err?.stack || err));
process.on("uncaughtException", (err) => console.error("uncaughtException", err?.stack || err));
process.on("SIGINT", () => { try { server.close(); } catch {} process.exit(0); });
process.on("SIGTERM", () => { try { server.close(); } catch {} process.exit(0); });