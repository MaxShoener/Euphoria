// server.js — Euphoria Hybrid (Basic rewrite proxy + optional Scramjet mount)
// Node 20+, ESM. No iframes. Better redirects, range streaming, cookie jars, and client runtime patch.

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
import { JSDOM } from "jsdom";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import { WebSocketServer } from "ws";
import { EventEmitter } from "events";

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

const PORT = Number(process.env.PORT || 8000);
const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const QUIET_LOGS = process.env.QUIET_LOGS === "1";

const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 25 * 1024 * 1024); // 25MB
const MEM_CACHE_ITEMS = Number(process.env.MEM_CACHE_ITEMS || 6000);
const HTML_CACHE_MAX = Number(process.env.HTML_CACHE_MAX || 700 * 1024);
const ASSET_CACHE_MAX = Number(process.env.ASSET_CACHE_MAX || 5 * 1024 * 1024);
const CACHE_TTL_HTML_MS = Number(process.env.CACHE_TTL_HTML_MS || 6 * 60 * 1000);
const CACHE_TTL_ASSET_MS = Number(process.env.CACHE_TTL_ASSET_MS || 60 * 60 * 1000);

const ENABLE_SCRAMJET = process.env.ENABLE_SCRAMJET !== "0";
const STRICT_COOKIES_DEFAULT = process.env.STRICT_COOKIES_DEFAULT !== "0";
const DISABLE_SERVICE_WORKERS = process.env.DISABLE_SERVICE_WORKERS !== "0";

const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

// Avoid permissive trust proxy error with express-rate-limit: do NOT set true.
// Use hop-count (Koyeb typically sets x-forwarded-*).
const TRUST_PROXY_HOPS = Number(process.env.TRUST_PROXY_HOPS || 1);

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
  ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3", ".m4a", ".wav", ".ogg",
  ".pdf", ".zip", ".rar", ".7z", ".avi", ".mov", ".mkv"
];

const SPECIAL_FILES = [
  "service-worker.js", "sw.js", "worker.js", "manifest.json"
];

function log(...args){ if(!QUIET_LOGS) console.log(...args); }

// Init disk cache dir
if(ENABLE_DISK_CACHE){
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});
}

// Express app
const app = express();
app.set("trust proxy", TRUST_PROXY_HOPS);

app.use(cors({ origin: true, credentials: true }));
app.use(morgan("tiny"));
app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(express.static(PUBLIC_DIR, { index: false }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_GLOBAL || 900),
  standardHeaders: true,
  legacyHeaders: false,
}));

function requireAdmin(req, res, next){
  if(ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if(!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

// Public origin from forwarded headers
function getPublicOrigin(req){
  const xfProto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  const xfHost  = String(req.headers["x-forwarded-host"]  || "").split(",")[0].trim();
  const host    = String(xfHost || req.headers.host || "").split(",")[0].trim();
  const proto   = (xfProto || (req.socket.encrypted ? "https" : "http")).trim();
  if(!host) return "";
  return `${proto}://${host}`;
}

function cacheKey(s){ return Buffer.from(String(s)).toString("base64url"); }
function nowMs(){ return Date.now(); }

async function diskGet(key){
  if(!ENABLE_DISK_CACHE) return null;
  try{
    const f = path.join(CACHE_DIR, cacheKey(key));
    if(!fs.existsSync(f)) return null;
    const raw = await fsPromises.readFile(f, "utf8");
    const obj = JSON.parse(raw);
    if(!obj || typeof obj !== "object") return null;
    if(nowMs() - obj.t > (obj.ttl || CACHE_TTL_HTML_MS)) return null;
    return obj.v;
  }catch{
    return null;
  }
}
async function diskSet(key, value, ttl){
  if(!ENABLE_DISK_CACHE) return;
  try{
    const f = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(f, JSON.stringify({ v: value, t: nowMs(), ttl }), "utf8");
  }catch{}
}

const MEM_CACHE = new LRUCache({ max: MEM_CACHE_ITEMS });

// Sessions + strict cookie jars
const SESSION_COOKIE = "euphoria_sid";
const SESSIONS = new Map();

function newSid(){
  return crypto.randomBytes(16).toString("hex") + Date.now().toString(36);
}
function parseCookieHeader(header=""){
  const out = {};
  header.split(";").map(s=>s.trim()).filter(Boolean).forEach(p=>{
    const idx = p.indexOf("=");
    if(idx === -1) return;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx+1).trim();
    if(k) out[k] = v;
  });
  return out;
}
function setSessionCookie(res, sid){
  const ck = `${SESSION_COOKIE}=${sid}; Path=/; SameSite=Lax; HttpOnly`;
  const prev = res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie", ck);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, ck]);
  else res.setHeader("Set-Cookie", [prev, ck]);
}
function getSession(req, res){
  const cookies = parseCookieHeader(req.headers.cookie || "");
  let sid = cookies[SESSION_COOKIE] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)){
    sid = newSid();
    SESSIONS.set(sid, {
      created: nowMs(),
      last: nowMs(),
      ip: req.ip || req.socket.remoteAddress || null,
      ua: DEFAULT_UA,
      // originKey -> Map(cookieName -> cookieObj)
      cookieJar: new Map(),
      // user prefs (strict cookie default)
      strictCookies: STRICT_COOKIES_DEFAULT
    });
    setSessionCookie(res, sid);
  }
  const s = SESSIONS.get(sid);
  s.last = nowMs();
  s.ip = req.ip || s.ip;
  return { sid, s };
}
setInterval(()=>{
  const cutoff = nowMs() - 24*60*60*1000;
  for(const [sid, s] of SESSIONS.entries()){
    if(!s || s.last < cutoff) SESSIONS.delete(sid);
  }
}, 30*60*1000);

function normalizeHost(h){ return String(h||"").trim().toLowerCase(); }
function normalizePath(p){ return (p && String(p).startsWith("/")) ? String(p) : "/" + String(p||""); }

function parseSetCookieLoose(sc){
  // returns { name,value,domain,path,expiresAt,secure,httpOnly,sameSite }
  try{
    const parts = String(sc).split(";").map(s=>s.trim());
    const nv = parts.shift() || "";
    const eq = nv.indexOf("=");
    if(eq < 1) return null;
    const name = nv.slice(0,eq).trim();
    const value = nv.slice(eq+1).trim();

    const out = { name, value, domain:null, path:null, expiresAt:null, secure:false, httpOnly:false, sameSite:null };

    for(const p of parts){
      const [kRaw, ...rest] = p.split("=");
      const k = String(kRaw||"").trim().toLowerCase();
      const v = rest.join("=").trim();
      if(k === "domain") out.domain = normalizeHost(v.replace(/^\./,""));
      else if(k === "path") out.path = normalizePath(v || "/");
      else if(k === "expires"){
        const t = Date.parse(v);
        if(!Number.isNaN(t)) out.expiresAt = t;
      }else if(k === "max-age"){
        const sec = parseInt(v,10);
        if(!Number.isNaN(sec)) out.expiresAt = Date.now() + sec*1000;
      }else if(k === "secure") out.secure = true;
      else if(k === "httponly") out.httpOnly = true;
      else if(k === "samesite") out.sameSite = v || null;
      else if(kRaw && String(kRaw).toLowerCase()==="secure") out.secure=true;
      else if(kRaw && String(kRaw).toLowerCase()==="httponly") out.httpOnly=true;
    }
    if(!out.path) out.path = "/";
    return out;
  }catch{
    return null;
  }
}

function ensureOriginJar(session, originKey){
  if(!session.cookieJar.has(originKey)) session.cookieJar.set(originKey, new Map());
  return session.cookieJar.get(originKey);
}

function storeSetCookiesStrict(session, originUrl, setCookieValues){
  // Strict same-origin: accept only cookies matching exact origin host
  let u;
  try{ u = new URL(originUrl); } catch { return; }
  const host = normalizeHost(u.hostname);
  const originKey = `${u.protocol}//${u.host}`;
  const jar = ensureOriginJar(session, originKey);

  for(const sc of (setCookieValues || [])){
    const parsed = parseSetCookieLoose(sc);
    if(!parsed) continue;

    const cookieDomain = parsed.domain ? normalizeHost(parsed.domain) : host;
    // strict: only exact host (no parent-domain cookies)
    if(cookieDomain !== host) continue;
    // secure cookies only over https
    if(parsed.secure && u.protocol !== "https:") continue;

    if(parsed.expiresAt && parsed.expiresAt <= Date.now()){
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

function domainMatches(cookieDomain, reqHost){
  if(!cookieDomain) return false;
  const cd = normalizeHost(cookieDomain);
  const rh = normalizeHost(reqHost);
  return rh === cd || rh.endsWith("." + cd);
}
function pathMatches(cookiePath, reqPath){
  const cp = normalizePath(cookiePath || "/");
  const rp = normalizePath(reqPath || "/");
  return rp === cp || rp.startsWith(cp);
}

function buildCookieHeaderStrict(session, targetUrl){
  let u;
  try{ u = new URL(targetUrl); } catch { return ""; }
  const originKey = `${u.protocol}//${u.host}`;
  const jar = session.cookieJar.get(originKey);
  if(!jar) return "";

  const host = normalizeHost(u.hostname);
  const pth = normalizePath(u.pathname || "/");
  const now = Date.now();

  const pairs = [];
  for(const [name, c] of jar.entries()){
    if(c.expiresAt && c.expiresAt <= now){
      jar.delete(name);
      continue;
    }
    if(c.secure && u.protocol !== "https:") continue;
    if(!domainMatches(c.domain, host)) continue;
    if(!pathMatches(c.path, pth)) continue;
    pairs.push(`${name}=${c.value}`);
  }
  return pairs.join("; ");
}

// URL utilities
function looksUrlish(input){
  const s = String(input||"").trim();
  if(!s) return false;
  if(/^https?:\/\//i.test(s)) return true;
  if(/^[a-z0-9.-]+\.[a-z]{2,}([/].*)?$/i.test(s)) return true;
  return false;
}
function normalizeToHttpUrl(input){
  const s = String(input||"").trim();
  if(!s) return null;
  if(/^https?:\/\//i.test(s)){
    try{ return new URL(s).href; } catch { return null; }
  }
  if(looksUrlish(s)){
    try{ return new URL("https://" + s).href; } catch { return null; }
  }
  return null;
}
function googleSearchUrl(q){
  const t = String(q||"").trim();
  if(!t) return "https://www.google.com/";
  return "https://www.google.com/search?q=" + encodeURIComponent(t);
}
function isProbablyAssetUrl(urlStr){
  try{
    const u = new URL(urlStr);
    const p = (u.pathname||"").toLowerCase();
    if(SPECIAL_FILES.some(sf => p.endsWith("/"+sf) || p.endsWith(sf))) return true;
    if(BINARY_EXTENSIONS.some(ext => p.endsWith(ext))) return true;
    return false;
  }catch{
    const lower = String(urlStr||"").toLowerCase();
    if(SPECIAL_FILES.some(sf => lower.endsWith("/"+sf) || lower.endsWith(sf))) return true;
    if(BINARY_EXTENSIONS.some(ext => lower.endsWith(ext))) return true;
    return false;
  }
}
function shouldSkipRewrite(v){
  if(!v) return true;
  const s = String(v);
  if(/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(s)) return true;
  if(s.includes("/proxy?url=") || s.includes("/sj?url=")) return true;
  return false;
}
function toAbsMaybe(urlLike, base){
  try{ return new URL(urlLike, base).href; } catch { return null; }
}
function makeProxyUrl(absUrl, req, mode="proxy"){
  try{
    const origin = getPublicOrigin(req);
    const base = (mode === "sj") ? "/sj" : "/proxy";
    return `${origin}${base}?url=${encodeURIComponent(new URL(absUrl).href)}`;
  }catch{
    return absUrl;
  }
}

// Fetch (no undici import)
const httpAgent = new http.Agent({ keepAlive:true, maxSockets: 256 });
const httpsAgent = new https.Agent({ keepAlive:true, maxSockets: 256 });

async function fetchUpstream(url, opts={}){
  const controller = new AbortController();
  const t = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
  try{
    const u = new URL(url);
    const agent = (u.protocol === "https:") ? httpsAgent : httpAgent;
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      // @ts-ignore
      agent,
      redirect: "manual"
    });
    return res;
  } finally {
    clearTimeout(t);
  }
}

function stripResponseHeaders(entries){
  const out = {};
  for(const [k, v] of entries){
    const lk = k.toLowerCase();
    if(DROP_RESPONSE_HEADERS.has(lk)) continue;
    if(HOP_BY_HOP_HEADERS.has(lk)) continue;
    // we handle redirects ourselves
    if(lk === "location") continue;
    return void 0;
  }
  return out;
}

// safer header copier
function copyHeaders(resUp, resDown, { rewriting=false } = {}){
  try{
    for(const [k, v] of resUp.headers.entries()){
      const lk = k.toLowerCase();
      if(DROP_RESPONSE_HEADERS.has(lk)) continue;
      if(HOP_BY_HOP_HEADERS.has(lk)) continue;
      if(lk === "location") continue;
      if(rewriting){
        if(lk === "content-encoding") continue;
        if(lk === "content-length") continue;
      }
      try{ resDown.setHeader(k, v); } catch {}
    }
  }catch{}
}

function isHtmlContentType(ct){
  const s = String(ct||"").toLowerCase();
  return s.includes("text/html") || s.includes("application/xhtml+xml");
}

function maybeDecompress(buf, encoding){
  const enc = String(encoding||"").toLowerCase();
  try{
    if(enc.includes("br") && zlib.brotliDecompressSync) return zlib.brotliDecompressSync(buf);
    if(enc.includes("gzip")) return zlib.gunzipSync(buf);
    if(enc.includes("deflate")) return zlib.inflateSync(buf);
  }catch{}
  return buf;
}

function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  }catch{}
  return html;
}

// DOM rewrite
function rewriteHtml(html, baseUrl, req, mode="proxy"){
  let dom;
  try{
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  }catch{
    return html;
  }
  const document = dom.window.document;

  // Ensure base tag
  if(!document.querySelector("base")){
    const head = document.querySelector("head");
    if(head){
      const b = document.createElement("base");
      b.setAttribute("href", baseUrl);
      head.insertBefore(b, head.firstChild);
    }
  }

  const rewriteAttr = (el, attr)=>{
    try{
      const val = el.getAttribute(attr);
      if(shouldSkipRewrite(val)) return;
      const abs = toAbsMaybe(val, baseUrl);
      if(!abs) return;
      el.setAttribute(attr, makeProxyUrl(abs, req, mode));
    }catch{}
  };

  // anchors + remove target
  document.querySelectorAll("a[href]").forEach(a=>{
    rewriteAttr(a, "href");
    a.removeAttribute("target");
  });

  // forms
  document.querySelectorAll("form[action]").forEach(f=>rewriteAttr(f, "action"));

  // media + scripts + iframes
  ["img","script","iframe","audio","video","source","track"].forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>rewriteAttr(el, "src"));
  });
  document.querySelectorAll("link[href]").forEach(el=>rewriteAttr(el, "href"));

  // srcset (critical)
  document.querySelectorAll("[srcset]").forEach(el=>{
    try{
      const srcset = el.getAttribute("srcset");
      if(!srcset) return;
      const out = srcset.split(",").map(part=>{
        const [u, size] = part.trim().split(/\s+/, 2);
        if(shouldSkipRewrite(u)) return part;
        const abs = toAbsMaybe(u, baseUrl);
        if(!abs) return part;
        return makeProxyUrl(abs, req, mode) + (size ? " " + size : "");
      }).join(", ");
      el.setAttribute("srcset", out);
    }catch{}
  });

  // inline style url(...)
  document.querySelectorAll("[style]").forEach(el=>{
    try{
      const s = el.getAttribute("style") || "";
      if(!s) return;
      const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
        if(shouldSkipRewrite(u)) return m;
        const abs = toAbsMaybe(u, baseUrl);
        if(!abs) return m;
        return `url("${makeProxyUrl(abs, req, mode)}")`;
      });
      el.setAttribute("style", out);
    }catch{}
  });

  // <style> blocks
  document.querySelectorAll("style").forEach(st=>{
    try{
      let css = st.textContent || "";
      css = css.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
        if(shouldSkipRewrite(u)) return m;
        const abs = toAbsMaybe(u, baseUrl);
        if(!abs) return m;
        return `url("${makeProxyUrl(abs, req, mode)}")`;
      });
      st.textContent = css;
    }catch{}
  });

  // meta refresh
  document.querySelectorAll("meta[http-equiv]").forEach(m=>{
    try{
      if((m.getAttribute("http-equiv")||"").toLowerCase() !== "refresh") return;
      const c = m.getAttribute("content") || "";
      const match = c.match(/url=(.+)$/i);
      if(!match) return;
      const abs = toAbsMaybe(match[1], baseUrl);
      if(!abs) return;
      m.setAttribute("content", c.replace(match[1], makeProxyUrl(abs, req, mode)));
    }catch{}
  });

  return dom.serialize();
}

// Inline JS rewrite (best-effort)
function rewriteInlineJs(code, baseUrl, req, mode="proxy"){
  try{
    // fetch("...")
    code = code.replace(/fetch\(\s*(['"])([^'"]+)\1/g, (m,q,u)=>{
      if(shouldSkipRewrite(u)) return m;
      const abs = toAbsMaybe(u, baseUrl);
      if(!abs) return m;
      return `fetch("${makeProxyUrl(abs, req, mode)}"`;
    });

    // xhr.open("GET","...")
    code = code.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+)\3/gi,
      (m,q1,method,q2,u)=>{
        if(shouldSkipRewrite(u)) return m;
        const abs = toAbsMaybe(u, baseUrl);
        if(!abs) return m;
        return `.open("${method || "GET"}","${makeProxyUrl(abs, req, mode)}"`;
      }
    );

    // "/api/.."
    code = code.replace(/(['"])(\/[^'"]+?)\1/g, (m,q,u)=>{
      if(shouldSkipRewrite(u)) return m;
      const abs = toAbsMaybe(u, baseUrl);
      if(!abs) return m;
      return `"${makeProxyUrl(abs, req, mode)}"`;
    });

    return code;
  }catch{
    return code;
  }
}

// Disable/patch service worker patterns
function neuterServiceWorkerJs(code){
  if(!DISABLE_SERVICE_WORKERS) return code;
  try{
    return code
      .replace(/navigator\s*\.\s*serviceWorker\s*\.\s*register/gi, "/*euph*/null&&navigator.serviceWorker.register")
      .replace(/serviceWorker\s*\.\s*register/gi, "/*euph*/null&&serviceWorker.register");
  }catch{
    return code;
  }
}

// Client runtime patch: keeps navigation inside proxy; improves button behavior.
function injectClientRuntime(html, req, mode="proxy"){
  const marker = "/*__EUPHORIA_CLIENT_RUNTIME__*/";
  if(html.includes(marker)) return html;

  const origin = getPublicOrigin(req);
  const basePath = (mode === "sj") ? "/sj?url=" : "/proxy?url=";

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

  // patch forms
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

  // patch anchors at click time
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

  if(/<\/body>/i.test(html)) return html.replace(/<\/body>/i, js + "\n</body>");
  return html + "\n" + js;
}

function isAuthyHost(hostname){
  const h = String(hostname||"").toLowerCase();
  return (
    h.includes("accounts.google.") ||
    h.includes("login.live.") ||
    h.includes("microsoftonline.") ||
    h.includes("xbox.") ||
    h.includes("live.com") ||
    h.includes("google.com") && h.includes("accounts")
  );
}

function splitSetCookieHeader(setCookieHeaderValue){
  // Node fetch may combine; split on comma only when it looks like a new cookie pair.
  return String(setCookieHeaderValue || "").split(/,(?=[^ ;]+=)/g).map(s=>s.trim()).filter(Boolean);
}

// Stream upstream to client (supports media)
async function streamBody(resUp, resDown){
  const body = resUp.body;
  if(!body){
    resDown.end();
    return;
  }
  if(typeof body.getReader === "function"){
    const reader = body.getReader();
    while(true){
      const { value, done } = await reader.read();
      if(done) break;
      if(value) resDown.write(Buffer.from(value));
    }
    resDown.end();
    return;
  }
  // fallback: buffer
  const ab = await resUp.arrayBuffer();
  resDown.end(Buffer.from(ab));
}

// Redirect trapping
function handleRedirect(resUp, req, res, targetUrl, mode="proxy"){
  const loc = resUp.headers.get("location");
  if(!loc) return false;

  let abs;
  try{ abs = new URL(loc, resUp.url || targetUrl).href; }
  catch{ abs = loc; }

  const prox = makeProxyUrl(abs, req, mode);
  res.status(resUp.status || 302);
  res.setHeader("Location", prox);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(`Redirecting to ${prox}`);
  return true;
}

// Main proxy handler factory (basic vs scramjet route share most behavior)
function makeProxyRoute(mode="proxy"){
  return async (req, res)=>{
    const { s: session } = getSession(req, res);

    // Allow client toggles via query param (from UI settings) without breaking older links:
    // /proxy?...&strictCookies=0
    if(typeof req.query.strictCookies !== "undefined"){
      session.strictCookies = String(req.query.strictCookies) !== "0";
    }

    // Input parsing:
    // - ?url=<url or urlish> OR
    // - ?q=<search> OR
    // - if ?url is not urlish => treat as search
    let target = null;

    if(req.query.q && !req.query.url){
      target = googleSearchUrl(String(req.query.q));
    }else if(req.query.url){
      const u = String(req.query.url);
      target = normalizeToHttpUrl(u) || googleSearchUrl(u);
    }else{
      return res.status(400).send("Missing url (use /proxy?url=https://example.com) or /proxy?q=search");
    }

    if(!target) return res.status(400).send("Bad target");

    // Cache key
    const accept = String(req.headers.accept || "").toLowerCase();
    const wantsHtml = accept.includes("text/html") || req.query.force_html === "1";

    const hasRange = !!req.headers.range;
    const cacheAllowed = req.method === "GET" && !hasRange;

    const cacheKeyBase = `${mode}::${target}`;
    const key = wantsHtml ? `${cacheKeyBase}::html` : `${cacheKeyBase}::asset`;

    // Cache read
    if(cacheAllowed){
      const mem = MEM_CACHE.get(key);
      if(mem){
        if(mem.__type === "html"){
          res.setHeader("Content-Type","text/html; charset=utf-8");
          if(mem.headers) for(const [k,v] of Object.entries(mem.headers)) { try{ res.setHeader(k,v);}catch{} }
          return res.end(mem.body);
        }
        if(mem.__type === "asset"){
          if(mem.headers) for(const [k,v] of Object.entries(mem.headers)) { try{ res.setHeader(k,v);}catch{} }
          return res.end(Buffer.from(mem.bodyB64, "base64"));
        }
      }
      const disk = await diskGet(key);
      if(disk){
        if(disk.__type === "html"){
          res.setHeader("Content-Type","text/html; charset=utf-8");
          if(disk.headers) for(const [k,v] of Object.entries(disk.headers)) { try{ res.setHeader(k,v);}catch{} }
          return res.end(disk.body);
        }
        if(disk.__type === "asset"){
          if(disk.headers) for(const [k,v] of Object.entries(disk.headers)) { try{ res.setHeader(k,v);}catch{} }
          return res.end(Buffer.from(disk.bodyB64, "base64"));
        }
      }
    }

    // Upstream headers
    const hdrs = {};
    try{
      hdrs["user-agent"] = session.ua || DEFAULT_UA;
      hdrs["accept"] = req.headers.accept || "*/*";
      hdrs["accept-language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
      hdrs["accept-encoding"] = "gzip, deflate, br";

      // Range for media/images
      if(req.headers.range) hdrs["range"] = req.headers.range;

      // Strict cookies (per-origin)
      if(session.strictCookies){
        const cookieHeader = buildCookieHeaderStrict(session, target);
        if(cookieHeader) hdrs["cookie"] = cookieHeader;
      }

      // Referer/origin: try to keep coherent
      if(req.headers.referer) hdrs["referer"] = req.headers.referer;
      try{ hdrs["origin"] = new URL(target).origin; } catch {}
    }catch{}

    // Fetch
    let up;
    try{
      up = await fetchUpstream(target, {
        method: "GET",
        headers: hdrs,
        redirect: "manual"
      });
    }catch(e){
      return res.status(502).send("Euphoria: failed to fetch target: " + String(e?.message || e));
    }

    // Store cookies
    try{
      const sc = up.headers.get("set-cookie");
      if(sc && session.strictCookies){
        const setCookies = splitSetCookieHeader(sc);
        storeSetCookiesStrict(session, up.url || target, setCookies);
      }
    }catch{}

    // Redirect trap
    if([301,302,303,307,308].includes(up.status)){
      if(handleRedirect(up, req, res, target, mode)) return;
    }

    const ct = up.headers.get("content-type") || "";
    const isHtml = wantsHtml || isHtmlContentType(ct);

    // HTML path: buffer -> decompress -> rewrite -> inject runtime -> (optionally rewrite inline scripts) -> send
    if(isHtml){
      let rawBuf;
      try{
        rawBuf = Buffer.from(await up.arrayBuffer());
        if(rawBuf.length > MAX_BODY_BYTES) throw new Error("html_body_too_large");
      }catch(e){
        return res.status(502).send("Euphoria: failed to read HTML: " + String(e?.message || e));
      }

      copyHeaders(up, res, { rewriting:true });

      let buf = maybeDecompress(rawBuf, up.headers.get("content-encoding"));
      let html = "";
      try{ html = buf.toString("utf8"); } catch { html = Buffer.from(buf).toString("utf8"); }

      html = sanitizeHtml(html);

      // DOM rewrite (assets/links/forms/srcset/styles)
      const baseUrl = up.url || target;
      const rewrittenDom = rewriteHtml(html, baseUrl, req, mode);

      // Client runtime injection (navigation trapping)
      let out = injectClientRuntime(rewrittenDom, req, mode);

      // Inline script rewrite pass + SW neuter pass
      try{
        const dom2 = new JSDOM(out, { url: baseUrl, contentType:"text/html" });
        const doc2 = dom2.window.document;

        // Add <meta name=referrer> helps some flows remain consistent
        try{
          if(!doc2.querySelector('meta[name="referrer"]')){
            const m = doc2.createElement("meta");
            m.setAttribute("name","referrer");
            m.setAttribute("content","no-referrer-when-downgrade");
            (doc2.head || doc2.documentElement).appendChild(m);
          }
        }catch{}

        // Disable service worker registration (best shot for proxied auth flows)
        doc2.querySelectorAll("script:not([src])").forEach(s=>{
          let code = s.textContent || "";
          if(!code.trim()) return;
          code = neuterServiceWorkerJs(code);
          code = rewriteInlineJs(code, baseUrl, req, mode);
          s.textContent = code;
        });

        out = dom2.serialize();
      }catch{}

      // Response
      res.status(up.status || 200);
      res.setHeader("Content-Type","text/html; charset=utf-8");

      // Cache policy: avoid caching auth-heavy HTML; do cache small generic HTML
      let ttl = CACHE_TTL_HTML_MS;
      let cacheOk = cacheAllowed;

      try{
        const h = new URL(baseUrl).hostname;
        if(isAuthyHost(h)) cacheOk = false;
      }catch{}

      if(cacheOk && out.length <= HTML_CACHE_MAX){
        const payload = { __type:"html", body: out, headers: { "Cache-Control":"no-store" } };
        MEM_CACHE.set(key, payload, { ttl });
        diskSet(key, payload, ttl).catch(()=>{});
      }

      // Safer default for dynamic sites (helps logins)
      res.setHeader("Cache-Control", "no-store");
      return res.end(out);
    }

    // Asset path: copy headers and stream. Cache small assets.
    copyHeaders(up, res, { rewriting:false });
    res.status(up.status || 200);
    if(ct) { try{ res.setHeader("Content-Type", ct); } catch{} }

    // Range -> stream, no cache
    if(hasRange){
      return streamBody(up, res);
    }

    // Buffer to cache small, stream large
    let ab;
    try{
      ab = await up.arrayBuffer();
    }catch{
      return streamBody(up, res);
    }
    const bodyBuf = Buffer.from(ab);

    if(cacheAllowed && bodyBuf.length <= ASSET_CACHE_MAX){
      const headersObj = {};
      try{
        for(const [k,v] of up.headers.entries()){
          const lk = k.toLowerCase();
          if(DROP_RESPONSE_HEADERS.has(lk)) continue;
          if(HOP_BY_HOP_HEADERS.has(lk)) continue;
          if(lk === "content-length") continue;
          headersObj[k] = v;
        }
      }catch{}
      const payload = { __type:"asset", headers: headersObj, bodyB64: bodyBuf.toString("base64") };
      MEM_CACHE.set(key, payload, { ttl: CACHE_TTL_ASSET_MS });
      diskSet(key, payload, CACHE_TTL_ASSET_MS).catch(()=>{});
    }

    return res.end(bodyBuf);
  };
}

// Routes: /proxy = basic
app.get("/proxy", makeProxyRoute("proxy"));

// Clean path style: /proxy/:host/* -> /proxy?url=https://host/*
app.get(/^\/proxy\/([^/]+)\/(.*)$/i, (req, res, next)=>{
  try{
    const host = req.params?.[0] || "";
    const rest = req.params?.[1] || "";
    if(!host) return next();
    const combined = `${host}/${rest}`;
    const url = normalizeToHttpUrl(decodeURIComponentSafe(combined));
    if(!url) return next();
    return res.redirect(302, `/proxy?url=${encodeURIComponent(url)}`);
  }catch{
    return next();
  }
});
function decodeURIComponentSafe(s){
  try{ return decodeURIComponent(s); }catch{ return s; }
}

// /sj route: best-effort scramjet mount, but never crash if not available.
// If ScramjetFactory exists, try to create and mount. Otherwise fallback to proxy behavior.
if(ENABLE_SCRAMJET){
  if(typeof ScramjetFactory === "function"){
    try{
      const maybeServer = ScramjetFactory({
        // keep options conservative; API differs across builds
        prefix: "/sj",
      });

      // If it exposes express middleware:
      if(typeof maybeServer === "function"){
        app.use("/sj", maybeServer);
        log("[SCRAMJET] mounted as middleware at /sj");
      } else if(maybeServer && typeof maybeServer.handler === "function"){
        app.use("/sj", (req,res,next)=>maybeServer.handler(req,res,next));
        log("[SCRAMJET] mounted handler at /sj");
      } else if(maybeServer && typeof maybeServer.fetch === "function"){
        app.use("/sj", async (req,res)=>{
          try{
            // Convert express req -> fetch Request-like (minimal)
            const origin = getPublicOrigin(req) || "http://localhost";
            const url = new URL(req.originalUrl, origin);
            const r = await maybeServer.fetch(url.href, { method:req.method, headers:req.headers });
            res.status(r.status);
            r.headers.forEach((v,k)=>{ try{ res.setHeader(k,v);}catch{} });
            const buf = Buffer.from(await r.arrayBuffer());
            res.end(buf);
          }catch(e){
            res.status(502).send("Scramjet error: " + String(e?.message||e));
          }
        });
        log("[SCRAMJET] mounted fetch bridge at /sj");
      } else {
        // fallback: emulate scramjet by using our proxy pipeline
        app.get("/sj", makeProxyRoute("sj"));
        log("[SCRAMJET] factory returned unknown shape; falling back to internal /sj proxy");
      }
    }catch(e){
      // fallback to internal /sj proxy
      app.get("/sj", makeProxyRoute("sj"));
      log("[SCRAMJET] init failed; using internal /sj proxy:", e?.message || e);
    }
  } else {
    app.get("/sj", makeProxyRoute("sj"));
    log("[SCRAMJET] not available; using internal /sj proxy");
  }
} else {
  // scramjet disabled; still keep route as alias if you want
  app.get("/sj", makeProxyRoute("sj"));
}

// Fallback “escaped path” support: keep buttons working if site requests /_next/* etc outside /proxy.
app.use(async (req, res, next)=>{
  try{
    const p = req.path || "/";
    if(
      p.startsWith("/proxy") ||
      p.startsWith("/sj") ||
      p.startsWith("/_euph_ws") ||
      p.startsWith("/_wsproxy") ||
      p.startsWith("/_euph_debug") ||
      p.startsWith("/static") ||
      p.startsWith("/public")
    ) return next();

    const ref = req.headers.referer || req.headers.referrer || "";
    const m = String(ref).match(/[?&]url=([^&]+)/);
    if(!m) return next();

    let base;
    try{ base = decodeURIComponent(m[1]); }catch{ return next(); }
    if(!base) return next();

    const baseOrigin = new URL(base).origin;
    const attempt = new URL(req.originalUrl, baseOrigin).href;
    return res.redirect(302, makeProxyUrl(attempt, req, "proxy"));
  }catch{
    return next();
  }
});

// Home
app.get("/", (req,res)=>res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("*", (req,res,next)=>{
  if(req.method === "GET" && String(req.headers.accept||"").includes("text/html")){
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

// Debug/admin
app.get("/_euph_debug/ping", (req,res)=>res.json({ ok:true, ts: Date.now() }));
app.get("/_euph_debug/sessions", requireAdmin, (req,res)=>{
  const out = {};
  for(const [sid, s] of SESSIONS.entries()){
    out[sid] = {
      created: new Date(s.created).toISOString(),
      last: new Date(s.last).toISOString(),
      ip: s.ip,
      strictCookies: !!s.strictCookies,
      jarOrigins: [...s.cookieJar.keys()].length
    };
  }
  res.json({ count: SESSIONS.size, sessions: out });
});
app.post("/_euph_debug/clear_cache", requireAdmin, async (req,res)=>{
  MEM_CACHE.clear();
  if(ENABLE_DISK_CACHE){
    try{
      const files = await fsPromises.readdir(CACHE_DIR);
      for(const f of files) await fsPromises.unlink(path.join(CACHE_DIR,f)).catch(()=>{});
    }catch{}
  }
  res.json({ ok:true });
});

// Create HTTP server + telemetry websocket
const server = http.createServer(app);

const wssTelemetry = new WebSocketServer({ server, path: "/_euph_ws" });
wssTelemetry.on("connection", ws=>{
  ws.send(JSON.stringify({ msg:"welcome", ts: Date.now() }));
  ws.on("message", raw=>{
    try{
      const p = JSON.parse(raw.toString());
      if(p && p.cmd === "ping") ws.send(JSON.stringify({ msg:"pong", ts: Date.now() }));
    }catch{}
  });
});

server.listen(PORT, ()=>{
  log(`[BOOT] listening on ${PORT}`);
});

// Safety
process.on("unhandledRejection", err => console.error("unhandledRejection", err?.stack || err));
process.on("uncaughtException", err => console.error("uncaughtException", err?.stack || err));
process.on("warning", w => console.warn("warning", w?.stack || w));

process.on("SIGINT", ()=>{ try{ server.close(); }catch{} process.exit(0); });
process.on("SIGTERM", ()=>{ try{ server.close(); }catch{} process.exit(0); });