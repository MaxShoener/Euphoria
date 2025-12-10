// server.js
// EUPHORIA v2 (B1) — JSDOM-powered hybrid smart rewriter
// - Node 20+ recommended
// - Dependencies: express, jsdom, ws, compression, morgan, cors, cookie

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import { WebSocketServer } from "ws";
import cookie from "cookie";
import { EventEmitter } from "events";

EventEmitter.defaultMaxListeners = 200;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ------------------------ CONFIG ------------------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const FETCH_TIMEOUT_MS = 30000;
const ASSET_CACHE_THRESHOLD = 256 * 1024; // 256KB
const USER_AGENT_DEFAULT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// asset extensions considered binary
const ASSET_EXTENSIONS = [
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",
  ".ttf",".otf",".woff",".woff2",".eot",".json",".map",".mp4",".webm",".mp3"
];
const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// Headers to drop (CSP, frame policies, etc.)
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// ------------------------ EXPRESS SETUP ------------------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));
// ------------------------ CACHE (memory + disk) ------------------------
const MEM_CACHE = new Map();
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const e = MEM_CACHE.get(key);
  if(e && (now() - e.t) < CACHE_TTL) return e.v;
  if(ENABLE_DISK_CACHE){
    try {
      const fname = path.join(CACHE_DIR, cacheKey(key));
      if(fs.existsSync(fname)){
        const raw = fs.readFileSync(fname, "utf8");
        const obj = JSON.parse(raw);
        if((now() - obj.t) < CACHE_TTL){
          MEM_CACHE.set(key, { v: obj.v, t: obj.t });
          return obj.v;
        }
        try { fs.unlinkSync(fname); } catch(e){}
      }
    } catch(e){}
  }
  return null;
}
function cacheSet(key, val){
  MEM_CACHE.set(key, { v: val, t: now() });
  if(ENABLE_DISK_CACHE){
    const fname = path.join(CACHE_DIR, cacheKey(key));
    fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(()=>{});
  }
}
// ------------------------ SESSIONS / COOKIE STORE ------------------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();

function makeSid(){
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function createSession(){
  const sid = makeSid();
  const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT };
  SESSIONS.set(sid, payload);
  return { sid, payload };
}

function parseCookies(header = ""){
  const out = {};
  header.split(";").forEach(p => {
    const [k,v] = (p||"").split("=").map(s => (s||"").trim());
    if(k && v) out[k] = v;
  });
  return out;
}

function getSessionFromReq(req){
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid);
  payload.last = now();
  return { sid, payload };
}

function setSessionCookieHeader(res, sid){
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie", cookieStr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}

function storeSetCookieToSession(setCookies = [], sessionPayload){
  for(const sc of setCookies){
    try {
      const kv = sc.split(";")[0];
      const idx = kv.indexOf("=");
      if(idx === -1) continue;
      const k = kv.slice(0, idx).trim();
      const v = kv.slice(idx+1).trim();
      if(k) sessionPayload.cookies.set(k, v);
    } catch(e){}
  }
}

function buildCookieHeader(map){
  return [...map.entries()].map(([k,v]) => `${k}=${v}`).join("; ");
}

// Cleanup stale sessions every 30 minutes
setInterval(() => {
  const cutoff = Date.now() - (1000*60*60*24);
  for(const [k,p] of SESSIONS.entries()) if(p.last < cutoff) SESSIONS.delete(k);
}, 1000*60*30);
// ------------------------ HELPERS / URL REWRITING ------------------------
function isAlreadyProxiedHref(href){
  if(!href) return false;
  try {
    if(href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if(resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch(e){}
  return false;
}

function toAbsolute(href, base){
  try { return new URL(href, base).href; } catch(e) { return null; }
}

function proxyizeAbsoluteUrl(abs){
  try { 
    const u = new URL(abs);
    return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch(e) { 
    try { 
      const u2 = new URL("https://" + abs);
      return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`;
    } catch(e2) { 
      return abs; 
    } 
  }
}

function looksLikeAsset(urlStr){
  if(!urlStr) return false;
  try {
    const p = new URL(urlStr, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(p.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(p.endsWith(s)) return true;
    return false;
  } catch(e){
    const lower = urlStr.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(lower.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(lower.endsWith(s)) return true;
    return false;
  }
}

// sanitize HTML string: remove CSP meta, integrity, crossorigin attributes
function sanitizeHtml(html){
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch(e){}
  return html;
}

// ------------------------ JSDOM TRANSFORM ------------------------
function jsdomTransform(html, baseUrl){
  try{
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;

    // inject base if missing
    if(!document.querySelector('base')){
      const head = document.querySelector('head');
      if(head) {
        const b = document.createElement('base');
        b.setAttribute('href', baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }

    // rewrite anchors
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    anchors.forEach(a => {
      try {
        const href = a.getAttribute('href');
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(isAlreadyProxiedHref(href)) return;
        const abs = toAbsolute(href, baseUrl) || href;
        a.setAttribute('href', proxyizeAbsoluteUrl(abs));
        a.removeAttribute('target');
      } catch(e){}
    });

    // rewrite forms
    const forms = Array.from(document.querySelectorAll('form[action]'));
    forms.forEach(f => {
      try {
        const act = f.getAttribute('action') || '';
        if(!act) return;
        if(isAlreadyProxiedHref(act)) return;
        const abs = toAbsolute(act, baseUrl) || act;
        f.setAttribute('action', proxyizeAbsoluteUrl(abs));
      } catch(e){}
    });

    // assets: src / href attributes
    const assetTags = ['img','script','link','iframe','source','video','audio'];
    assetTags.forEach(tag => {
      const nodes = Array.from(document.getElementsByTagName(tag));
      nodes.forEach(el => {
        try {
          const srcAttr = el.getAttribute('src') ? 'src' : (el.getAttribute('href') ? 'href' : null);
          if(!srcAttr) return;
          const v = el.getAttribute(srcAttr);
          if(!v) return;
          if(/^data:/i.test(v)) return;
          if(isAlreadyProxiedHref(v)) return;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(srcAttr, proxyizeAbsoluteUrl(abs));
        } catch(e){}
      });
    });

    // srcset rewrite
    const srcsetEls = Array.from(document.querySelectorAll('[srcset]'));
    srcsetEls.forEach(el => {
      try {
        const ss = el.getAttribute('srcset') || '';
        const parts = ss.split(',').map(p => {
          const [u, rest] = p.trim().split(/\s+/,2);
          if(!u) return p;
          if(/^data:/i.test(u)) return p;
          if(isAlreadyProxiedHref(u)) return p;
          const abs = toAbsolute(u, baseUrl) || u;
          return proxyizeAbsoluteUrl(abs) + (rest ? ' ' + rest : '');
        });
        el.setAttribute('srcset', parts.join(', '));
      } catch(e){}
    });

    return dom.serialize();
  } catch(err){
    console.warn("jsdom transform failed", err && err.message ? err.message : err);
    return html;
  }
}
// ------------------------ INLINE JS REWRITING ------------------------
function rewriteInlineJs(source, baseUrl){
  try{
    // 1) fetch('...') -> proxied
    source = source.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs)}'`;
      } catch(e){ return m; }
    });
    // 2) XHR open: open('GET','/path'...)
    source = source.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs)}'`;
      } catch(e){ return m; }
    });
    // 3) string literals that look like relative/absolute URLs
    source = source.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `'${proxyizeAbsoluteUrl(abs)}'`;
      } catch(e){ return m; }
    });
    return source;
  } catch(e){ return source; }
}

// ------------------------ SERVICE WORKER PATCH ------------------------
function patchServiceWorker(source, baseUrl){
  try{
    let s = source;
    // importScripts(...) -> proxied
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m, args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(item => {
          if(typeof item === 'string'){
            const abs = toAbsolute(item, baseUrl) || item;
            return `'${proxyizeAbsoluteUrl(abs)}'`;
          }
          return JSON.stringify(item);
        });
        return `importScripts(${out.join(',')})`;
      } catch(e){ return m; }
    });
    // fetch('...') -> proxied
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs)}'`;
      } catch(e){ return m; }
    });
    return s;
  } catch(e){ return source; }
}
// ------------------------ MAIN /proxy ENDPOINT ------------------------
app.get("/proxy", async (req, res) => {
  // accept both /proxy?url=... and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session + cookie
  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}

  // caching keys
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'b1' || req.query.force_html === '1';
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // small asset cache
  if(!wantHtml){
    const cached = cacheGet(assetKey);
    if(cached){
      if(cached.headers) Object.entries(cached.headers).forEach(([k,v]) => { try { res.setHeader(k,v); } catch(e){} });
      return res.send(Buffer.from(cached.body, "base64"));
    }
  } else {
    const cachedHtml = cacheGet(htmlKey);
    if(cachedHtml){ res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // build upstream headers
  const originHeaders = {
    "User-Agent": session.payload.ua || (req.headers['user-agent'] || USER_AGENT_DEFAULT),
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if(req.headers.referer) originHeaders["Referer"] = req.headers.referer;
  try { originHeaders["Origin"] = new URL(raw).origin; } catch(e){}

  // fetch upstream (manual redirect to rewrite Location)
  let originRes;
  try {
    const controller = new AbortController();
    const to = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(to);
  } catch(err){
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // persist set-cookie
  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch(e){}

  // handle redirects (rewrite Location to our proxy)
  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      let abs;
      try{ abs = new URL(loc, raw).href; } catch(e){ abs = loc; }
      const proxied = proxyizeAbsoluteUrl(abs);
      try { res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); } catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  // content detection
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;

  // asset: stream binary + cache small ones
  if(treatAsAsset){
    try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
    try{ setSessionCookieHeader(res, session.sid); } catch(e){}
    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if(buf.length < ASSET_CACHE_THRESHOLD){
        try { cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch(e){}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch(err){
      try { originRes.body.pipe(res); return; } catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // HTML path: read and transform
  let htmlText;
  try { htmlText = await originRes.text(); } catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }

  htmlText = sanitizeHtml(htmlText);

  // JSDOM structural transformation
  let transformed = jsdomTransform(htmlText, originRes.url || raw);

  // Inject client-side rewrite snippet if missing (runtime fetch/XHR interception)
  const clientMarker = "/* EUPHORIA_CLIENT_REWRITE */";
  if(!transformed.includes(clientMarker)){
    const clientSnippet = `
<script>
${clientMarker}
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; if(/^data:/i.test(u)) return u; const abs=new URL(u, document.baseURI).href; return DEPLOY + '/proxy?url=' + encodeURIComponent(abs);}catch(e){return u;} }
  (function(){
    const origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        else if(resource instanceof Request && !resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
      } catch(e){}
      return origFetch(resource, init);
    };
    const OrigXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new OrigXHR();
      const open = xhr.open;
      xhr.open = function(method, url, ...rest){
        try{
          if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)){
            url = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href);
          }
        }catch(e){}
        return open.call(this, method, url, ...rest);
      };
      return xhr;
    };
  })();
})();
</script>
`;
    transformed = transformed.replace(/<\/body>/i, clientSnippet + "</body>");
  }

  // Post-process inline scripts: conservative regex rewrites (fetch/XHR etc.) and SW patching
  try {
    const dom2 = new JSDOM(transformed, { url: originRes.url || raw });
    const document2 = dom2.window.document;
    const scripts = Array.from(document2.querySelectorAll('script'));
    for(const s of scripts){
      try {
        const src = s.getAttribute('src');
        if(src) continue; // already proxied
        let code = s.textContent || '';
        if(!code.trim()) continue;
        const lower = code.slice(0, 300).toLowerCase();
        if(lower.includes('self.addeventlistener') || lower.includes('importscripts') || lower.includes('caches.open')){
          code = patchServiceWorker(code, originRes.url || raw);
        }
        code = rewriteInlineJs(code, originRes.url || raw);
        s.textContent = code;
      } catch(e){}
    }
    transformed = dom2.serialize();
  } catch(e){ console.warn("post-process inline scripts failed", e && e.message ? e.message : e); }

  // forward safe headers
  try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}

  // cache small HTML
  try{ if(transformed && transformed.length < 512 * 1024) cacheSet(htmlKey, transformed); } catch(e){}

  return res.send(transformed);
});
// ------------------------ FALLBACK: direct-path requests using Referer ------------------------
app.use(async (req, res, next) => {
  const p = req.path || "/";
  if(p.startsWith("/proxy") || p.startsWith("/_euph_ws") || p.startsWith("/static") || p.startsWith("/public")) return next();

  const referer = req.headers.referer || req.headers.referrer || "";
  const m = referer.match(/[?&]url=([^&]+)/);
  if(!m) return next();

  let orig;
  try { orig = decodeURIComponent(m[1]); } catch(e) { return next(); }
  if(!orig) return next();

  let baseOrigin;
  try { baseOrigin = new URL(orig).origin; } catch(e){ return next(); }
  const attempted = new URL(req.originalUrl, baseOrigin).href;

  try{
    const session = getSessionFromReq(req);
    setSessionCookieHeader(res, session.sid);
    const originHeaders = { 
      "User-Agent": session.payload.ua || USER_AGENT_DEFAULT, 
      "Accept": req.headers.accept || "*/*", 
      "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9" 
    };
    const cookieHdr = buildCookieHeader(session.payload.cookies);
    if(cookieHdr) originHeaders["Cookie"] = cookieHdr;

    const controller = new AbortController();
    const to = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    const originRes = await fetch(attempted, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(to);

    if([301,302,303,307,308].includes(originRes.status)){
      const loc = originRes.headers.get("location");
      if(loc){ 
        const abs = new URL(loc, attempted).href; 
        return res.redirect(proxyizeAbsoluteUrl(abs)); 
      }
    }

    const ct = (originRes.headers.get("content-type") || "").toLowerCase();
    if(!ct.includes("text/html")){
      originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      res.setHeader("Content-Type", ct || "application/octet-stream");
      return res.send(buf);
    }

    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = jsdomTransform(html, originRes.url || attempted);
    const final = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA FALLBACK */
(function(){ 
  const D="${DEPLOYMENT_ORIGIN}"; 
  (function(){ 
    const orig = window.fetch; 
    window.fetch = function(r,i){ 
      try{ 
        if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); 
      }catch(e){} 
      return orig.call(this,r,i); 
    }; 
  })(); 
})();
</script></body>`);
    originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.send(final);
  } catch(err){
    console.error("fallback proxy error", err && err.message ? err.message : err);
    return next();
  }
});

// ------------------------ SPA fallback ------------------------
app.get("/", (req,res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) 
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// ------------------------ ERRORS ------------------------
process.on("unhandledRejection", err => console.error("unhandledRejection", err));
process.on("uncaughtException", err => console.error("uncaughtException", err));
// ------------------------ SECTION 9: ERROR HANDLING & LOGGING ------------------------
process.on("unhandledRejection", (err) => {
  console.error("[EUPHORIA ERROR] unhandledRejection:", err && err.stack ? err.stack : err);
});

process.on("uncaughtException", (err) => {
  console.error("[EUPHORIA ERROR] uncaughtException:", err && err.stack ? err.stack : err);
});

// optional: capture warnings
process.on("warning", (warning) => {
  console.warn("[EUPHORIA WARNING]:", warning.name, warning.message, warning.stack);
});

// ------------------------ SECTION 10: OPTIONAL EXTENSIONS / PLUGINS ------------------------
// Example hooks for extending Euphoria functionality
const EXTENSIONS = new Map();

// register an extension
function registerExtension(name, fn) {
  if(typeof fn !== "function") throw new Error("Extension must be a function");
  EXTENSIONS.set(name, fn);
}

// run all extensions on HTML transform
async function runExtensions(html, context={}) {
  let output = html;
  for(const [name, fn] of EXTENSIONS.entries()) {
    try { output = await fn(output, context) || output; } catch(e){ console.error(`Extension ${name} failed:`, e); }
  }
  return output;
}

// Example usage: add a small banner to all HTML pages
registerExtension("bannerInject", (html, context) => {
  if(!html.includes("<body")) return html;
  const banner = `<div style="position:fixed;top:0;width:100%;background:#222;color:#fff;text-align:center;z-index:9999;font-family:sans-serif;padding:4px 0;font-size:12px;">Euphoria Proxy Active</div>`;
  return html.replace(/<body[^>]*>/i, (match) => match + banner);
});

// ------------------------ SECTION 11: ADMIN / DEBUG ENDPOINTS ------------------------
app.get("/_euph_debug/sessions", (req, res) => {
  // optionally add simple auth here
  const sessions = {};
  for(const [sid, payload] of SESSIONS.entries()){
    sessions[sid] = {
      lastActive: new Date(payload.last).toISOString(),
      cookies: Object.fromEntries(payload.cookies.entries()),
      ua: payload.ua
    };
  }
  res.json({ activeSessions: sessions });
});

app.get("/_euph_debug/cache", (req, res) => {
  const memCache = {};
  for(const [key, val] of MEM_CACHE.entries()){
    memCache[key] = { ageSec: Math.floor((Date.now() - val.t)/1000), size: val.v.length || 0 };
  }
  res.json({ memoryCache: memCache });
});

app.get("/_euph_debug/extensions", (req, res) => {
  res.json({ registeredExtensions: Array.from(EXTENSIONS.keys()) });
});

// simple ping endpoint
app.get("/_euph_debug/ping", (req,res) => res.json({ msg:"pong", ts:Date.now() }));

// ------------------------ END OF SECTIONS 9-11 ------------------------