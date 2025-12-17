// server.js — Euphoria Hybrid WISP Server
// Node 20+, ESM. No iframes.
// Goals:
// - Keep navigation inside Euphoria (links/buttons/forms/history/location/open)
// - Fix Google search loops + Missing url when navigating from within Google
// - Better “browser-like” behavior: cookies (strict per-origin), redirects trapped, service workers neutered
// - Media support (audio/video) + Range streaming
// - Scramjet-safe integration (never crashes if API shape differs)
// - WISP discovery endpoint + recognizable headers

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import path from "path";
import fs from "fs";
import fsp from "fs/promises";
import http from "http";
import https from "https";
import crypto from "crypto";
import zlib from "zlib";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import { LRUCache } from "lru-cache";
import { WebSocketServer, WebSocket } from "ws";

// Scramjet: CommonJS-safe import (do not assume named exports)
import scramjetPkg from "@mercuryworkshop/scramjet";
const ScramjetFactory =
  scramjetPkg?.createScramjetServer ||
  scramjetPkg?.createServer ||
  scramjetPkg?.default?.createScramjetServer ||
  scramjetPkg?.default?.createServer ||
  null;

/* ────────────────────────────────────────────────────────── */
/* Paths / config                                             */
/* ────────────────────────────────────────────────────────── */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 8000);
const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

const QUIET_LOGS = process.env.QUIET_LOGS === "1";

const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const ENABLE_SCRAMJET = process.env.ENABLE_SCRAMJET !== "0";
const DISABLE_SERVICE_WORKERS = process.env.DISABLE_SERVICE_WORKERS !== "0";
const STRICT_COOKIES_DEFAULT = process.env.STRICT_COOKIES_DEFAULT !== "0";

const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const MAX_HTML_BYTES = Number(process.env.MAX_HTML_BYTES || 8 * 1024 * 1024); // cap HTML transforms to avoid runaway CPU
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 30 * 1024 * 1024);

const MEM_CACHE_ITEMS = Number(process.env.MEM_CACHE_ITEMS || 6000);
const HTML_CACHE_MAX = Number(process.env.HTML_CACHE_MAX || 700 * 1024);
const ASSET_CACHE_MAX = Number(process.env.ASSET_CACHE_MAX || 5 * 1024 * 1024);
const CACHE_TTL_HTML_MS = Number(process.env.CACHE_TTL_HTML_MS || 6 * 60 * 1000);
const CACHE_TTL_ASSET_MS = Number(process.env.CACHE_TTL_ASSET_MS || 60 * 60 * 1000);

const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

function log(...args) {
  if (!QUIET_LOGS) console.log(...args);
}
function nowMs() {
  return Date.now();
}

/* ────────────────────────────────────────────────────────── */
/* Express init                                               */
/* ────────────────────────────────────────────────────────── */

if (ENABLE_DISK_CACHE) {
  await fsp.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

const app = express();

// IMPORTANT: avoid express-rate-limit trust-proxy errors by using hop-count not `true`
app.set("trust proxy", Number(process.env.TRUST_PROXY_HOPS || 1));

app.use(cors({ origin: true, credentials: true }));
app.use(morgan("tiny"));
app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(express.static(PUBLIC_DIR, { index: false }));

/* ────────────────────────────────────────────────────────── */
/* WISP identity + discovery                                  */
/* ────────────────────────────────────────────────────────── */

function getPublicOrigin(req) {
  const xfProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const xfHost = String(req.headers["x-forwarded-host"] || "").split(",")[0].trim();
  const host = String(xfHost || req.headers.host || "").split(",")[0].trim();
  const proto = (xfProto || (req.socket.encrypted ? "https" : "http")).trim();
  return host ? `${proto}://${host}` : "";
}

app.use((req, res, next) => {
  // recognizable as WISP/Euphoria
  res.setHeader("X-WISP-Server", "Euphoria");
  res.setHeader(
    "X-WISP-Capabilities",
    "proxy,html-rewrite,css-rewrite,js-runtime,cookies,range,media,ws,scramjet"
  );
  next();
});

app.get("/.well-known/wisp.json", (req, res) => {
  const origin = getPublicOrigin(req);
  res.json({
    name: "Euphoria",
    type: "wisp",
    version: "3.2.0",
    origin,
    capabilities: {
      proxy: true,
      htmlRewrite: true,
      cssRewrite: true,
      jsRuntime: true,
      cookies: "strict-per-origin",
      media: true,
      range: true,
      websocket: true,
      scramjet: !!ScramjetFactory && ENABLE_SCRAMJET
    },
    endpoints: {
      home: "/",
      proxy: "/proxy?url=",
      scramjet: "/sj?url=",
      ws: "/ws?url=",
      ping: "/_euph/ping"
    }
  });
});

app.get("/_euph/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));

/* ────────────────────────────────────────────────────────── */
/* Cache (memory + optional disk)                             */
/* ────────────────────────────────────────────────────────── */

const MEM_CACHE = new LRUCache({ max: MEM_CACHE_ITEMS });

function cacheKey(s) {
  return Buffer.from(String(s)).toString("base64url");
}

async function diskGet(key) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(f)) return null;
    const raw = await fsp.readFile(f, "utf8");
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    if (Date.now() - obj.t > (obj.ttl || CACHE_TTL_HTML_MS)) return null;
    return obj.v;
  } catch {
    return null;
  }
}

async function diskSet(key, value, ttl) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const f = path.join(CACHE_DIR, cacheKey(key));
    await fsp.writeFile(f, JSON.stringify({ v: value, t: Date.now(), ttl }), "utf8");
  } catch {}
}

/* ────────────────────────────────────────────────────────── */
/* Strict per-origin sessions + cookie jars                   */
/* ────────────────────────────────────────────────────────── */

const SESSION_COOKIE = "euphoria_sid";
const SESSIONS = new Map();

function newSid() {
  return crypto.randomBytes(16).toString("hex") + Date.now().toString(36);
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
      ua: DEFAULT_UA,
      strictCookies: STRICT_COOKIES_DEFAULT,
      // originKey -> Map(name -> cookieObj)
      cookieJar: new Map()
    });
    setSessionCookie(res, sid);
  }
  const s = SESSIONS.get(sid);
  s.last = nowMs();
  return { sid, s };
}

setInterval(() => {
  const cutoff = nowMs() - 24 * 60 * 60 * 1000;
  for (const [sid, s] of SESSIONS.entries()) {
    if (!s || s.last < cutoff) SESSIONS.delete(sid);
  }
}, 30 * 60 * 1000);

function normHost(h) {
  return String(h || "").trim().toLowerCase();
}
function normPath(p) {
  const s = String(p || "/");
  return s.startsWith("/") ? s : "/" + s;
}

function splitSetCookieHeader(raw) {
  // split on comma only when it looks like a new cookie starts
  return String(raw || "").split(/,(?=[^ ;]+=)/g).map((s) => s.trim()).filter(Boolean);
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
      sameSite: null
    };

    for (const p of parts) {
      const [kRaw, ...rest] = p.split("=");
      const k = String(kRaw || "").trim().toLowerCase();
      const v = rest.join("=").trim();
      if (k === "domain") out.domain = normHost(v.replace(/^\./, ""));
      else if (k === "path") out.path = normPath(v || "/");
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

// Strict same-origin cookie emulation:
// - accept only cookies whose Domain matches exact host (no parent-domain cookies)
// - store per originKey: `${protocol}//${host}`
function storeSetCookiesStrict(session, originUrl, setCookies) {
  let u;
  try { u = new URL(originUrl); } catch { return; }
  const host = normHost(u.hostname);
  const originKey = `${u.protocol}//${u.host}`;
  const jar = ensureOriginJar(session, originKey);

  for (const sc of (setCookies || [])) {
    const parsed = parseSetCookieLoose(sc);
    if (!parsed) continue;

    const cookieDomain = parsed.domain ? normHost(parsed.domain) : host;
    if (cookieDomain !== host) {
      // strict mode: reject wide domain cookies (helps prevent cross-site bleed)
      continue;
    }
    if (parsed.secure && u.protocol !== "https:") continue;

    if (parsed.expiresAt && parsed.expiresAt <= Date.now()) {
      jar.delete(parsed.name);
      continue;
    }

    jar.set(parsed.name, {
      ...parsed,
      domain: host,
      path: parsed.path || "/",
      setAt: Date.now()
    });
  }
}

function domainMatches(cookieDomain, reqHost) {
  const cd = normHost(cookieDomain);
  const rh = normHost(reqHost);
  return rh === cd || rh.endsWith("." + cd);
}

function pathMatches(cookiePath, reqPath) {
  const cp = normPath(cookiePath || "/");
  const rp = normPath(reqPath || "/");
  return rp === cp || rp.startsWith(cp);
}

function buildCookieHeaderStrict(session, targetUrl) {
  let u;
  try { u = new URL(targetUrl); } catch { return ""; }

  const originKey = `${u.protocol}//${u.host}`;
  const jar = session.cookieJar.get(originKey);
  if (!jar) return "";

  const host = normHost(u.hostname);
  const pth = normPath(u.pathname || "/");
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

/* ────────────────────────────────────────────────────────── */
/* Proxy helpers: URL normalization + Google fix              */
/* ────────────────────────────────────────────────────────── */

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
    try { return new URL(s).href; } catch { return null; }
  }
  if (looksUrlish(s)) {
    try { return new URL("https://" + s).href; } catch { return null; }
  }
  return null;
}

function googleSearchUrl(q) {
  const t = String(q || "").trim();
  if (!t) return "https://www.google.com/";
  return "https://www.google.com/search?q=" + encodeURIComponent(t);
}

// Critical fix for Google infinite reload:
// Some navigations end up hitting /proxy?url=<already-proxied-url> or blank.
// We normalize nested proxied URLs by extracting the inner url= if present.
function unwrapIfProxiedMaybe(raw) {
  const s = String(raw || "");
  try {
    const u = new URL(s);
    const inner = u.searchParams.get("url");
    if (inner && /^https?:\/\//i.test(inner)) return inner;
  } catch {}
  return raw;
}

/* ────────────────────────────────────────────────────────── */
/* Upstream fetch: agents + timeout                            */
/* ────────────────────────────────────────────────────────── */

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
      // @ts-ignore (node fetch accepts agent in many runtimes)
      agent,
      redirect: "manual"
    });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/* ────────────────────────────────────────────────────────── */
/* Response header hardening (login + embed)                  */
/* ────────────────────────────────────────────────────────── */

const DROP_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
]);

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
      try { down.setHeader(k, v); } catch {}
    }
  } catch {}
}

/* ────────────────────────────────────────────────────────── */
/* Decompression                                               */
/* ────────────────────────────────────────────────────────── */

function maybeDecompress(buf, encoding) {
  const enc = String(encoding || "").toLowerCase();
  try {
    if (enc.includes("br") && typeof zlib.brotliDecompressSync === "function") {
      return zlib.brotliDecompressSync(buf);
    }
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
  } catch {}
  return buf;
}

function isHtmlContentType(ct) {
  const s = String(ct || "").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

/* ────────────────────────────────────────────────────────── */
/* Rewriting: URLs / CSS / srcset / meta refresh               */
/* ────────────────────────────────────────────────────────── */

function shouldSkipRewrite(v) {
  if (!v) return true;
  const s = String(v);
  if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(s)) return true;
  if (s.includes("/proxy?url=") || s.includes("/sj?url=")) return true;
  return false;
}

function toAbsMaybe(urlLike, base) {
  try { return new URL(urlLike, base).href; } catch { return null; }
}

function proxify(absUrl, req, mode = "proxy") {
  const origin = getPublicOrigin(req);
  const base = mode === "sj" ? "/sj" : "/proxy";
  try {
    const u = new URL(absUrl);
    return `${origin}${base}?url=${encodeURIComponent(u.href)}`;
  } catch {
    return `${origin}${base}?url=${encodeURIComponent(String(absUrl))}`;
  }
}

function rewriteCssUrls(cssText, baseUrl, req, mode) {
  // rewrite url(...) in CSS
  return String(cssText || "").replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
    if (shouldSkipRewrite(u)) return m;
    const abs = toAbsMaybe(u, baseUrl);
    if (!abs) return m;
    return `url("${proxify(abs, req, mode)}")`;
  });
}

function sanitizeHtml(html) {
  let out = String(html || "");
  // remove CSP meta
  out = out.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
  // remove integrity/crossorigin attributes (often break after rewrites)
  out = out.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
  out = out.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  return out;
}

/* ────────────────────────────────────────────────────────── */
/* Client runtime injection: keep navigation inside Euphoria   */
/* ────────────────────────────────────────────────────────── */

function injectClientRuntime(html, req, mode) {
  const marker = "/*__EUPHORIA_RUNTIME_V6__*/";
  if (String(html).includes(marker)) return html;

  const origin = getPublicOrigin(req);
  const basePath = mode === "sj" ? "/sj?url=" : "/proxy?url=";

  // This is the most important “buttons don’t escape” piece:
  // - intercept clicks on <a>, <button> with formaction, <form> submits
  // - patch fetch/XHR/history/open/location.assign/replace
  // - handle location.href assignments via setter interception attempt (best-effort)
  const js = `
<script>
${marker}
(function(){
  const ORIGIN = ${JSON.stringify(origin)};
  const BASE = ${JSON.stringify(basePath)};

  function isProxied(u){ return typeof u === "string" && u.indexOf(BASE) !== -1; }
  function abs(u){ try { return new URL(u, document.baseURI).href; } catch(e){ return u; } }
  function prox(u){
    try{
      if(!u) return u;
      if(typeof u !== "string") return u;
      if(isProxied(u)) return u;
      if(/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u)) return u;
      const a = abs(u);
      return ORIGIN + BASE + encodeURIComponent(a);
    }catch(e){ return u; }
  }

  // Patch fetch
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

  // Patch history
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

  // Patch open
  try{
    const o = window.open;
    window.open = function(url, name, specs){
      try{ if(typeof url === "string") url = prox(url); }catch(e){}
      return o.call(this, url, name, specs);
    };
  }catch(e){}

  // Patch location navigation
  try{
    const loc = window.location;
    const assign = loc.assign.bind(loc);
    const replace = loc.replace.bind(loc);
    loc.assign = function(u){ return assign(prox(u)); };
    loc.replace = function(u){ return replace(prox(u)); };
  }catch(e){}

  // Click interception (anchors + elements with href-like attributes)
  document.addEventListener("click", function(ev){
    try{
      const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
      if(a){
        const href = a.getAttribute("href") || "";
        if(!href || /^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(!isProxied(href)){
          a.setAttribute("href", prox(href));
          a.removeAttribute("target");
        }
        return;
      }

      // Buttons with formaction
      const b = ev.target && ev.target.closest ? ev.target.closest("button[formaction],input[formaction]") : null;
      if(b){
        const fa = b.getAttribute("formaction");
        if(fa && !isProxied(fa) && !/^(javascript:|mailto:|tel:|#)/i.test(fa)){
          b.setAttribute("formaction", prox(fa));
        }
        return;
      }
    }catch(e){}
  }, true);

  // Form patching
  function patchForms(){
    try{
      document.querySelectorAll("form[action]").forEach(f=>{
        const a = f.getAttribute("action") || "";
        if(!a) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(a)) return;
        if(!isProxied(a)) f.setAttribute("action", prox(a));
      });
    }catch(e){}
  }
  patchForms();
  document.addEventListener("submit", function(){ patchForms(); }, true);

  // Prevent some “self reload” loops by normalizing already-proxied params
  // (helps Google in certain flows)
  try{
    const url = new URL(location.href);
    const inner = url.searchParams.get("url");
    if(inner && inner.includes(BASE)){
      // if nested proxied, unwrap once
      const u2 = new URL(inner);
      const inner2 = u2.searchParams.get("url");
      if(inner2) {
        url.searchParams.set("url", inner2);
        history.replaceState(null, "", url.toString());
      }
    }
  }catch(e){}
})();
</script>
`.trim();

  if (/<\/body>/i.test(html)) return String(html).replace(/<\/body>/i, js + "\n</body>");
  return String(html) + "\n" + js;
}

/* ────────────────────────────────────────────────────────── */
/* HTML rewrite (DOM)                                          */
/* ────────────────────────────────────────────────────────── */

function rewriteHtmlDom(html, baseUrl, req, mode) {
  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }

  const document = dom.window.document;

  // Ensure base tag (helps relative URL resolving)
  if (!document.querySelector("base")) {
    const head = document.querySelector("head");
    if (head) {
      const b = document.createElement("base");
      b.setAttribute("href", baseUrl);
      head.insertBefore(b, head.firstChild);
    }
  }

  // Xbox / heavy SPA CSS compatibility (meaningful adjustments)
  // - prevent overflow clipping / weird viewport behavior
  // - keep pointer events intact
  // - avoid odd "height:100%" lockups
  const compat = document.createElement("style");
  compat.textContent = `
    html, body { height: auto !important; min-height: 100% !important; overflow: auto !important; }
    body { position: static !important; }
    * { max-width: 100vw; }
    video, audio { max-width: 100%; }
  `;
  (document.head || document.documentElement).appendChild(compat);

  function rewriteAttr(el, attr) {
    try {
      const val = el.getAttribute(attr);
      if (shouldSkipRewrite(val)) return;
      const abs = toAbsMaybe(val, baseUrl);
      if (!abs) return;
      el.setAttribute(attr, proxify(abs, req, mode));
    } catch {}
  }

  // Links
  document.querySelectorAll("a[href]").forEach((a) => {
    rewriteAttr(a, "href");
    a.removeAttribute("target");
  });

  // Forms
  document.querySelectorAll("form[action]").forEach((f) => rewriteAttr(f, "action"));

  // Media / scripts / frames / sources
  ["img", "script", "iframe", "audio", "video", "source", "track"].forEach((tag) => {
    document.querySelectorAll(tag).forEach((el) => rewriteAttr(el, "src"));
  });
  document.querySelectorAll("link[href]").forEach((el) => rewriteAttr(el, "href"));

  // srcset (critical for “complex images”)
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
          return proxify(abs, req, mode) + (size ? " " + size : "");
        })
        .join(", ");
      el.setAttribute("srcset", out);
    } catch {}
  });

  // Inline style url(...)
  document.querySelectorAll("[style]").forEach((el) => {
    try {
      const s = el.getAttribute("style");
      if (!s) return;
      el.setAttribute("style", rewriteCssUrls(s, baseUrl, req, mode));
    } catch {}
  });

  // <style> blocks url(...)
  document.querySelectorAll("style").forEach((st) => {
    try {
      const css = st.textContent || "";
      st.textContent = rewriteCssUrls(css, baseUrl, req, mode);
    } catch {}
  });

  // Meta refresh
  document.querySelectorAll("meta[http-equiv]").forEach((m) => {
    try {
      if ((m.getAttribute("http-equiv") || "").toLowerCase() !== "refresh") return;
      const c = m.getAttribute("content") || "";
      const match = c.match(/url=(.+)$/i);
      if (!match) return;
      const abs = toAbsMaybe(match[1], baseUrl);
      if (!abs) return;
      m.setAttribute("content", c.replace(match[1], proxify(abs, req, mode)));
    } catch {}
  });

  // Referrer meta improves some login flows
  if (!document.querySelector('meta[name="referrer"]')) {
    const m = document.createElement("meta");
    m.setAttribute("name", "referrer");
    m.setAttribute("content", "no-referrer-when-downgrade");
    (document.head || document.documentElement).appendChild(m);
  }

  return dom.serialize();
}

/* ────────────────────────────────────────────────────────── */
/* Service worker hardening                                    */
/* ────────────────────────────────────────────────────────── */

function neuterServiceWorkerJs(code) {
  if (!DISABLE_SERVICE_WORKERS) return code;
  const s = String(code || "");
  return s
    .replace(/navigator\s*\.\s*serviceWorker\s*\.\s*register/gi, "/*euph*/null&&navigator.serviceWorker.register")
    .replace(/serviceWorker\s*\.\s*register/gi, "/*euph*/null&&serviceWorker.register");
}

/* ────────────────────────────────────────────────────────── */
/* HTML processing pipeline                                    */
/* ────────────────────────────────────────────────────────── */

function isAuthyHost(hostname) {
  const h = String(hostname || "").toLowerCase();
  return (
    h.includes("accounts.google.") ||
    h.includes("login.live.") ||
    h.includes("microsoftonline.") ||
    h.includes("xbox.") ||
    h.includes("live.com")
  );
}

async function processHtmlResponse(up, rawBuf, req, baseUrl, mode) {
  const encoding = up.headers.get("content-encoding") || "";
  let buf = maybeDecompress(rawBuf, encoding);

  // Cap to avoid pathological CPU usage
  if (buf.length > MAX_HTML_BYTES) {
    // If too big, skip heavy DOM rewrite and do minimal injection only
    const html = sanitizeHtml(buf.toString("utf8"));
    return Buffer.from(injectClientRuntime(html, req, mode), "utf8");
  }

  let html = sanitizeHtml(buf.toString("utf8"));

  // DOM rewrite (urls/srcset/css)
  html = rewriteHtmlDom(html, baseUrl, req, mode);

  // Neuter SW patterns inside inline scripts (best-effort)
  // NOTE: second JSDOM pass is expensive; only do it for “reasonable” HTML sizes.
  if (html.length < 1_200_000) {
    try {
      const dom2 = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
      const doc = dom2.window.document;
      doc.querySelectorAll("script:not([src])").forEach((s) => {
        const code = s.textContent || "";
        if (!code.trim()) return;
        s.textContent = neuterServiceWorkerJs(code);
      });
      html = dom2.serialize();
    } catch {}
  }

  // Inject runtime LAST (so it sees final DOM)
  html = injectClientRuntime(html, req, mode);

  return Buffer.from(html, "utf8");
}

/* ────────────────────────────────────────────────────────── */
/* Streaming helper (media + big assets)                        */
/* ────────────────────────────────────────────────────────── */

async function streamBody(up, res) {
  const body = up.body;
  if (!body) return res.end();

  // Node 20 fetch body is ReadableStream
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

  // fallback
  const ab = await up.arrayBuffer();
  res.end(Buffer.from(ab));
}

/* ────────────────────────────────────────────────────────── */
/* Redirect trapping                                             */
/* ────────────────────────────────────────────────────────── */

function handleRedirect(up, req, res, requestTarget, mode) {
  const loc = up.headers.get("location");
  if (!loc) return false;

  let abs;
  try {
    abs = new URL(loc, up.url || requestTarget).href;
  } catch {
    abs = loc;
  }

  res.status(up.status || 302);
  res.setHeader("Location", proxify(abs, req, mode));
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end("Redirecting...");
  return true;
}

/* ────────────────────────────────────────────────────────── */
/* Proxy route factory                                           */
/* ────────────────────────────────────────────────────────── */

function buildTargetFromReq(req) {
  // Accept:
  // - /proxy?url=<url or search terms>
  // - /proxy?q=<search terms>
  // Normalize nested proxy params (prevents Google loops)
  const q = req.query.q ? String(req.query.q) : "";
  const url = req.query.url ? String(req.query.url) : "";

  if (q && !url) return googleSearchUrl(q);

  if (!url) return null;

  const unwrapped = unwrapIfProxiedMaybe(url);
  const normalized = normalizeToHttpUrl(unwrapped);
  if (normalized) return normalized;

  // treat as search string if not a URL
  return googleSearchUrl(unwrapped);
}

function makeProxyRoute(mode) {
  return async (req, res) => {
    const { s: session } = getSession(req, res);

    // Allow UI toggles:
    if (typeof req.query.strictCookies !== "undefined") {
      session.strictCookies = String(req.query.strictCookies) !== "0";
    }

    let target = buildTargetFromReq(req);
    if (!target) {
      return res.status(400).send("Missing url (use /proxy?url=https://example.com or /proxy?url=search terms)");
    }

    // Cache key (GET only, no Range)
    const accept = String(req.headers.accept || "").toLowerCase();
    const wantsHtml = accept.includes("text/html") || req.query.force_html === "1";
    const hasRange = !!req.headers.range;
    const cacheAllowed = req.method === "GET" && !hasRange;

    const keyBase = `${mode}::${target}`;
    const key = wantsHtml ? `${keyBase}::html` : `${keyBase}::asset`;

    if (cacheAllowed) {
      const mem = MEM_CACHE.get(key);
      if (mem) {
        if (mem.__type === "html") {
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          if (mem.headers) for (const [k, v] of Object.entries(mem.headers)) { try { res.setHeader(k, v); } catch {} }
          return res.end(mem.body);
        }
        if (mem.__type === "asset") {
          if (mem.headers) for (const [k, v] of Object.entries(mem.headers)) { try { res.setHeader(k, v); } catch {} }
          return res.end(Buffer.from(mem.bodyB64, "base64"));
        }
      }

      const disk = await diskGet(key);
      if (disk) {
        if (disk.__type === "html") {
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          if (disk.headers) for (const [k, v] of Object.entries(disk.headers)) { try { res.setHeader(k, v); } catch {} }
          return res.end(disk.body);
        }
        if (disk.__type === "asset") {
          if (disk.headers) for (const [k, v] of Object.entries(disk.headers)) { try { res.setHeader(k, v); } catch {} }
          return res.end(Buffer.from(disk.bodyB64, "base64"));
        }
      }
    }

    // Build upstream headers
    const hdrs = {};
    try {
      hdrs["user-agent"] = session.ua || DEFAULT_UA;
      hdrs["accept"] = req.headers.accept || "*/*";
      hdrs["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
      hdrs["accept-encoding"] = "gzip, deflate, br";

      // Range support (media/images)
      if (req.headers.range) hdrs["range"] = req.headers.range;

      // Cookies (strict per-origin)
      if (session.strictCookies) {
        const cookieHeader = buildCookieHeaderStrict(session, target);
        if (cookieHeader) hdrs["cookie"] = cookieHeader;
      }

      // Coherent origin/referrer
      try { hdrs["origin"] = new URL(target).origin; } catch {}
      if (req.headers.referer) hdrs["referer"] = req.headers.referer;
    } catch {}

    // Fetch upstream
    let up;
    try {
      up = await fetchUpstream(target, { method: "GET", headers: hdrs, redirect: "manual" });
    } catch (e) {
      return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
    }

    // Store cookies from upstream
    try {
      const sc = up.headers.get("set-cookie");
      if (sc && session.strictCookies) {
        const setCookies = splitSetCookieHeader(sc);
        storeSetCookiesStrict(session, up.url || target, setCookies);
      }
    } catch {}

    // Redirect trap
    if ([301, 302, 303, 307, 308].includes(up.status)) {
      if (handleRedirect(up, req, res, target, mode)) return;
    }

    const ct = up.headers.get("content-type") || "";
    const isHtml = wantsHtml || isHtmlContentType(ct);

    // HTML path
    if (isHtml) {
      let rawBuf;
      try {
        rawBuf = Buffer.from(await up.arrayBuffer());
        if (rawBuf.length > MAX_BODY_BYTES) throw new Error("html_body_too_large");
      } catch (e) {
        return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
      }

      copyHeaders(up, res, { rewriting: true });

      const baseUrl = up.url || target;
      let outBuf;
      try {
        outBuf = await processHtmlResponse(up, rawBuf, req, baseUrl, mode);
      } catch {
        // fallback: minimal injection
        const html = injectClientRuntime(sanitizeHtml(rawBuf.toString("utf8")), req, mode);
        outBuf = Buffer.from(html, "utf8");
      }

      res.status(up.status || 200);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");

      // Cache only small, non-authy pages
      let cacheOk = cacheAllowed && outBuf.length <= HTML_CACHE_MAX;
      try {
        const h = new URL(baseUrl).hostname;
        if (isAuthyHost(h)) cacheOk = false;
      } catch {}

      if (cacheOk) {
        const payload = { __type: "html", body: outBuf.toString("utf8"), headers: { "Cache-Control": "no-store" } };
        MEM_CACHE.set(key, payload, { ttl: CACHE_TTL_HTML_MS });
        diskSet(key, payload, CACHE_TTL_HTML_MS).catch(() => {});
      }

      return res.end(outBuf);
    }

    // Asset path
    copyHeaders(up, res, { rewriting: false });
    res.status(up.status || 200);
    if (ct) { try { res.setHeader("Content-Type", ct); } catch {} }

    // Range -> stream (important for media)
    if (hasRange) {
      return streamBody(up, res);
    }

    // Buffer small, stream large
    let ab;
    try { ab = await up.arrayBuffer(); } catch { return streamBody(up, res); }
    const bodyBuf = Buffer.from(ab);

    if (cacheAllowed && bodyBuf.length <= ASSET_CACHE_MAX) {
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
      const payload = { __type: "asset", headers: headersObj, bodyB64: bodyBuf.toString("base64") };
      MEM_CACHE.set(key, payload, { ttl: CACHE_TTL_ASSET_MS });
      diskSet(key, payload, CACHE_TTL_ASSET_MS).catch(() => {});
    }

    return res.end(bodyBuf);
  };
}

/* ────────────────────────────────────────────────────────── */
/* Routes: /proxy + clean style + fallback escape              */
/* ────────────────────────────────────────────────────────── */

app.get("/proxy", makeProxyRoute("proxy"));

// Clean style: /proxy/:host/* -> /proxy?url=https://host/*
app.get(/^\/proxy\/([^/]+)\/(.*)$/i, (req, res, next) => {
  try {
    const host = req.params?.[0] || "";
    const rest = req.params?.[1] || "";
    if (!host) return next();
    const combined = `${host}/${rest}`;
    const decoded = safeDecode(combined);
    const url = normalizeToHttpUrl(decoded);
    if (!url) return next();
    return res.redirect(302, `/proxy?url=${encodeURIComponent(url)}`);
  } catch {
    return next();
  }
});

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

// Fallback “escaped path”: if a site requests /_next/* etc outside /proxy, reconstruct using referer’s url=
app.use((req, res, next) => {
  try {
    const p = req.path || "/";
    if (
      p.startsWith("/proxy") ||
      p.startsWith("/sj") ||
      p.startsWith("/ws") ||
      p.startsWith("/_euph") ||
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
    return res.redirect(302, proxify(attempt, req, "proxy"));
  } catch {
    return next();
  }
});

/* ────────────────────────────────────────────────────────── */
/* Scramjet mount (safe)                                      */
/* ────────────────────────────────────────────────────────── */

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
        // bridge: convert /sj?url=... into sj.fetch() call
        app.get("/sj", makeProxyRoute("sj"));
        log("[SCRAMJET] unknown shape; using internal /sj proxy");
      } else {
        app.get("/sj", makeProxyRoute("sj"));
        log("[SCRAMJET] returned unknown; using internal /sj proxy");
      }
    } catch (e) {
      app.get("/sj", makeProxyRoute("sj"));
      log("[SCRAMJET] init failed; using internal /sj proxy:", e?.message || e);
    }
  } else {
    app.get("/sj", makeProxyRoute("sj"));
    log("[SCRAMJET] factory missing; using internal /sj proxy");
  }
} else {
  app.get("/sj", makeProxyRoute("sj"));
}

/* ────────────────────────────────────────────────────────── */
/* WebSocket proxy: /ws?url=wss://...                          */
/* ────────────────────────────────────────────────────────── */

// This helps sites that rely on WSS for UI updates.
// It won't solve all MS/Xbox auth flows, but it materially improves many SPAs.
function isWsLike(u) {
  const s = String(u || "").trim();
  return /^wss?:\/\//i.test(s);
}

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

// Upgrade handler: supports /ws?url=wss://...
server.on("upgrade", (req, socket, head) => {
  try {
    const origin = `http://${req.headers.host}`;
    const u = new URL(req.url, origin);
    if (u.pathname !== "/ws") return socket.destroy();

    const target = u.searchParams.get("url");
    if (!target || !isWsLike(target)) return socket.destroy();

    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req, target);
    });
  } catch {
    try { socket.destroy(); } catch {}
  }
});

wss.on("connection", (client, req, target) => {
  const upstream = new WebSocket(target, {
    headers: {
      "user-agent": DEFAULT_UA,
      "origin": (() => { try { return new URL(target).origin; } catch { return ""; } })()
    }
  });

  const closeBoth = () => {
    try { client.close(); } catch {}
    try { upstream.close(); } catch {}
  };

  upstream.on("open", () => {
    client.on("message", (data) => {
      try { upstream.send(data); } catch {}
    });
    upstream.on("message", (data) => {
      try { client.send(data); } catch {}
    });
  });

  upstream.on("error", closeBoth);
  client.on("error", closeBoth);
  upstream.on("close", closeBoth);
  client.on("close", closeBoth);
});

/* ────────────────────────────────────────────────────────── */
/* Home                                                       */
/* ────────────────────────────────────────────────────────── */

app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// SPA fallback (serves index for navigations)
app.get("*", (req, res, next) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

/* ────────────────────────────────────────────────────────── */
/* Boot + safety                                               */
/* ────────────────────────────────────────────────────────── */

server.listen(PORT, () => {
  log(`[EUPHORIA] listening on ${PORT}`);
});

process.on("unhandledRejection", (err) => console.error("unhandledRejection", err?.stack || err));
process.on("uncaughtException", (err) => console.error("uncaughtException", err?.stack || err));
process.on("SIGINT", () => { try { server.close(); } catch {} process.exit(0); });