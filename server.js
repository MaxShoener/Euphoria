// server.js
// Euphoria v2 - single-file production-ready hybrid proxy
// Minimal comments, section headers.

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
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import http from "http";
import https from "https";

EventEmitter.defaultMaxListeners = 300;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* -----------------------
   CONFIG / CONSTANTS
   ----------------------- */
const PORT = parseInt(process.env.PORT || "3000", 10);
const DEPLOYMENT_ORIGIN_ENV = process.env.DEPLOYMENT_ORIGIN || "";
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = parseInt(process.env.CACHE_TTL_MS || String(1000 * 60 * 6), 10);
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || String(30000), 10);
const ASSET_CACHE_THRESHOLD = parseInt(process.env.ASSET_CACHE_THRESHOLD || String(256 * 1024), 10);
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ITEMS = parseInt(process.env.MAX_MEMORY_CACHE_ITEMS || "10240", 10);
const PER_HOST_CACHE_CONTROLS = {}; // add host overrides dynamically if needed
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

/* ensure cache dir */
if (ENABLE_DISK_CACHE) await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

/* binary asset extensions */
const ASSET_EXTENSIONS = [
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",
  ".ttf",".otf",".woff",".woff2",".eot",".json",".map",".mp4",".webm",".mp3"
];
const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

/* -----------------------
   EXPRESS / MIDDLEWARE
   ----------------------- */
const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

/* global rate limiter */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || "1200"),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down."
});
app.use(globalLimiter);

/* -----------------------
   LRU MEMORY CACHE
   ----------------------- */
const MEM_CACHE = new LRUCache({
  maxSize: MAX_MEMORY_CACHE_ITEMS,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) => {
    if (typeof val === "string") return Buffer.byteLength(val, "utf8");
    try { return Buffer.byteLength(JSON.stringify(val), "utf8"); } catch(e){ return 1; }
  }
});

/* -----------------------
   DISK CACHE HELPERS
   ----------------------- */
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }

async function diskGet(key){
  if(!ENABLE_DISK_CACHE) return null;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname);
    // stored as JSON: { t: number, v: <base64 or string>, binary: boolean, headers: {} }
    const parsed = JSON.parse(raw.toString("utf8"));
    if((now() - parsed.t) < CACHE_TTL) return parsed.v;
    try{ await fsPromises.unlink(fname); }catch(e){}
  }catch(e){}
  return null;
}
async function diskSet(key, val){
  if(!ENABLE_DISK_CACHE) return;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(()=>{});
  }catch(e){}
}

/* -----------------------
   SESSIONS (in-memory)
   ----------------------- */
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT, ip: null }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header=""){ const out = {}; header.split(";").forEach(p=>{ const [k,v] = (p||"").split("=").map(s=> (s||"").trim()); if(k && v) out[k]=v; }); return out; }
function getSessionFromReq(req){
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)) {
    const c = createSession();
    c.payload.ip = req.ip || req.socket.remoteAddress || null;
    return c;
  }
  const payload = SESSIONS.get(sid);
  payload.last = now();
  payload.ip = req.ip || payload.ip;
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
      const k = kv.slice(0, idx).trim(); const v = kv.slice(idx+1).trim();
      if(k) sessionPayload.cookies.set(k, v);
    } catch(e){}
  }
}
function buildCookieHeader(map){ return [...map.entries()].map(([k,v]) => `${k}=${v}`).join("; "); }

/* cleanup stale sessions */
setInterval(()=>{
  const cutoff = Date.now() - (1000*60*60*24);
  for(const [sid, p] of SESSIONS.entries()){
    if(p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000*60*30);

/* -----------------------
   UTIL: public origin resolver
   - prefers DEPLOYMENT_ORIGIN env var
   - otherwise derives from request (supports proxies via x-forwarded headers)
   ----------------------- */
function getPublicOrigin(req){
  if(DEPLOYMENT_ORIGIN_ENV && DEPLOYMENT_ORIGIN_ENV.length) return DEPLOYMENT_ORIGIN_ENV.replace(/\/+$/,"");
  // derive
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0];
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0];
  if(!host) return `http://localhost:${PORT}`;
  return `${proto}://${host}`.replace(/\/+$/,"");
}
function proxyizeAbsoluteUrl(abs, req){
  try {
    const u = new URL(abs);
    const origin = getPublicOrigin(req);
    return `${origin}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch(e){
    try { const u2 = new URL("https://" + abs); const origin = getPublicOrigin(req); return `${origin}/proxy?url=${encodeURIComponent(u2.href)}`; } catch(e2) { return abs; }
  }
}

/* -----------------------
   HELPERS: asset detection, sanitize
   ----------------------- */
function looksLikeAsset(urlStr){
  if(!urlStr) return false;
  try {
    const p = new URL(urlStr, "https://example.com").pathname.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(p.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(p.endsWith(s)) return true;
    return false;
  } catch(e){
    const lower = (urlStr||"").toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(lower.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(lower.endsWith(s)) return true;
    return false;
  }
}
function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  }catch(e){}
  return html;
}

/* -----------------------
   JSDOM HTML TRANSFORM
   - rewrites anchors, forms, assets, srcset, meta refresh, styles, inline styles
   - uses req to construct proxy URLs (no localhost leakage)
   ----------------------- */
function jsdomTransform(html, baseUrl, req){
  try{
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;
    // base
    if(!document.querySelector('base')){
      const head = document.querySelector('head');
      if(head){
        const b = document.createElement('base');
        b.setAttribute('href', baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }
    // anchors
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    anchors.forEach(a=>{
      try{
        const href = a.getAttribute('href');
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(href.includes('/proxy?url=')) return;
        const abs = new URL(href, baseUrl).href;
        a.setAttribute('href', proxyizeAbsoluteUrl(abs, req));
        a.removeAttribute('target');
      }catch(e){}
    });
    // forms
    const forms = Array.from(document.querySelectorAll('form[action]'));
    forms.forEach(f=>{
      try{
        const act = f.getAttribute('action') || '';
        if(!act) return;
        if(act.includes('/proxy?url=')) return;
        const abs = new URL(act, baseUrl).href;
        f.setAttribute('action', proxyizeAbsoluteUrl(abs, req));
      }catch(e){}
    });
    // assets: img, script, link, iframe, source, video, audio
    const assetTags = ['img','script','link','iframe','source','video','audio'];
    assetTags.forEach(tag=>{
      const nodes = Array.from(document.getElementsByTagName(tag));
      nodes.forEach(el=>{
        try{
          const srcAttr = el.getAttribute('src') ? 'src' : (el.getAttribute('href') ? 'href' : null);
          if(!srcAttr) return;
          const v = el.getAttribute(srcAttr);
          if(!v) return;
          if(/^data:/i.test(v)) return;
          if(v.includes('/proxy?url=')) return;
          const abs = new URL(v, baseUrl).href;
          el.setAttribute(srcAttr, proxyizeAbsoluteUrl(abs, req));
        }catch(e){}
      });
    });
    // srcset
    const srcsetEls = Array.from(document.querySelectorAll('[srcset]'));
    srcsetEls.forEach(el=>{
      try{
        const ss = el.getAttribute('srcset') || '';
        const parts = ss.split(',').map(p=>{
          const [u, rest] = p.trim().split(/\s+/,2);
          if(!u) return p;
          if(/^data:/i.test(u)) return p;
          if(u.includes('/proxy?url=')) return p;
          const abs = new URL(u, baseUrl).href;
          return proxyizeAbsoluteUrl(abs, req) + (rest ? ' ' + rest : '');
        });
        el.setAttribute('srcset', parts.join(', '));
      }catch(e){}
    });
    // style blocks url(...) rewriting
    const styles = Array.from(document.querySelectorAll('style'));
    styles.forEach(st=>{
      try{
        let txt = st.textContent || '';
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(u.includes('/proxy?url=')) return m;
          try{ const abs = new URL(u, baseUrl).href; return `url("${proxyizeAbsoluteUrl(abs, req)}")`; }catch(e){ return m; }
        });
        st.textContent = txt;
      }catch(e){}
    });
    // inline style attributes
    const inlines = Array.from(document.querySelectorAll('[style]'));
    inlines.forEach(el=>{
      try{
        const s = el.getAttribute('style') || '';
        const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(u.includes('/proxy?url=')) return m;
          try{ const abs = new URL(u, baseUrl).href; return `url("${proxyizeAbsoluteUrl(abs, req)}")`; }catch(e){ return m; }
        });
        el.setAttribute('style', out);
      }catch(e){}
    });
    // meta refresh
    const metas = Array.from(document.querySelectorAll('meta[http-equiv]'));
    metas.forEach(m=>{
      try{
        if((m.getAttribute('http-equiv')||'').toLowerCase() !== 'refresh') return;
        const c = m.getAttribute('content') || '';
        const parts = c.split(';');
        if(parts.length < 2) return;
        const urlpart = parts.slice(1).join(';').match(/url=(.*)/i);
        if(!urlpart) return;
        const dest = urlpart[1].replace(/['"]/g,'').trim();
        const abs = new URL(dest, baseUrl).href;
        m.setAttribute('content', parts[0] + ';url=' + proxyizeAbsoluteUrl(abs, req));
      }catch(e){}
    });
    // remove noscript blocks (to avoid confusing fallbacks)
    const noscripts = Array.from(document.getElementsByTagName('noscript'));
    noscripts.forEach(n=>{ try{ n.parentNode && n.parentNode.removeChild(n);}catch(e){} });
    return dom.serialize();
  }catch(err){
    console.warn("jsdom transform failed", err && err.message ? err.message : err);
    return html;
  }
}

/* -----------------------
   JS INLINE REWRITE / SW PATCH
   ----------------------- */
function rewriteInlineJs(source, baseUrl, req){
  try{
    source = source.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `fetch('${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    source = source.replace(/(new\s+Request\()(['"])([^'"]+?)\2/gi, (m,p1,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `${p1}'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    source = source.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    return source;
  }catch(e){ return source; }
}
function patchServiceWorker(source, baseUrl, req){
  try{
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m,args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(item => {
          if(typeof item === 'string'){ const abs = new URL(item, baseUrl).href; return `'${proxyizeAbsoluteUrl(abs, req)}'`; }
          return JSON.stringify(item);
        });
        return `importScripts(${out.join(',')})`;
      }catch(e){ return m; }
    });
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `fetch('${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){ return source; }
}

/* -----------------------
   AGENTS & UPSTREAM FETCH
   - use keepAlive agents
   - add browser-like headers to improve compatibility
   ----------------------- */
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

async function upstreamFetch(url, opts = {}, useRotation = false){
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
  let fetchOpts = { ...opts, signal: controller.signal };
  if(!fetchOpts.headers) fetchOpts.headers = {};
  // add sensible headers if missing to mimic browser
  fetchOpts.headers['user-agent'] = fetchOpts.headers['user-agent'] || USER_AGENT_DEFAULT;
  fetchOpts.headers['accept'] = fetchOpts.headers['accept'] || "*/*";
  if(!fetchOpts.headers['accept-language']) fetchOpts.headers['accept-language'] = 'en-US,en;q=0.9';
  if(!fetchOpts.headers['sec-fetch-site']) fetchOpts.headers['sec-fetch-site'] = 'none';
  if(!fetchOpts.headers['sec-fetch-mode']) fetchOpts.headers['sec-fetch-mode'] = 'navigate';
  if(!fetchOpts.headers['sec-fetch-dest']) fetchOpts.headers['sec-fetch-dest'] = 'document';
  if(!fetchOpts.headers['upgrade-insecure-requests']) fetchOpts.headers['upgrade-insecure-requests'] = '1';
  if(isHttps) fetchOpts.agent = httpsAgent; else fetchOpts.agent = httpAgent;
  try{
    // rotation hook placeholder
    if(useRotation){
      try{
        const rotated = await ipRotationHook(u.hostname);
        if(rotated && rotated.proxy && rotated.proxy.href){
          // placeholder for upstream proxy usage
        }
      }catch(e){}
    }
    const res = await fetch(url, fetchOpts);
    clearTimeout(timeout);
    return res;
  }catch(err){
    clearTimeout(timeout);
    throw err;
  }
}

/* -----------------------
   WEBSOCKET PROXY (upgrade)
   - path: /wsproxy?url=<ws://...> or /_wsproxy?url=
   ----------------------- */
function setupWsProxy(server){
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  server.on('upgrade', async (request, socket, head) => {
    try{
      const urlObj = new URL(request.url, `http://${request.headers.host}`);
      if(!urlObj.pathname.includes('/_wsproxy') && !urlObj.pathname.includes('/wsproxy')) return;
      const target = urlObj.searchParams.get('url');
      if(!target){
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }
      wssProxy.handleUpgrade(request, socket, head, (wsSocket) => {
        // connect to target
        const outbound = new WebSocket(target, { headers: { origin: request.headers.origin || getPublicOrigin(request) } });
        // pipe messages both ways
        outbound.on('open', () => {
          wsSocket.on('message', msg => { try{ outbound.send(msg); }catch(e){} });
          outbound.on('message', msg => { try{ wsSocket.send(msg); }catch(e){} });
          const forwardClose = (code, reason) => { try{ wsSocket.close(code, reason); }catch(e){}; try{ outbound.close(code, reason); }catch(e){}; };
          wsSocket.on('close', forwardClose);
          outbound.on('close', forwardClose);
        });
        outbound.on('error', () => wsSocket.close());
        wsSocket.on('error', () => outbound.close());
      });
    }catch(e){
      try{ socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); }catch(e){}
    }
  });
  return wssProxy;
}

/* -----------------------
   START SERVER + TELEMETRY WS
   ----------------------- */
const server = http.createServer(app);
const wssTelemetry = new WebSocketServer({ server, path: "/_euph_ws" });
wssTelemetry.on("connection", ws=>{
  ws.send(JSON.stringify({ msg:"welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try { const parsed = JSON.parse(raw.toString()); if(parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg:'pong', ts: Date.now() })); } catch(e){}
  });
});
setupWsProxy(server);
server.listen(PORT, ()=> console.log(`Euphoria v2 running on port ${PORT}`));

/* -----------------------
   ROUTES
   - /proxy?url=...
   - /proxy/:host/*   (host-style mapping)
   - /tunnel?url=...  (raw passthrough no rewrite)
   - /_euph_debug/*   admin
   ----------------------- */

/* core proxy handler used by routes */
async function handleProxyToUrl(req, res, rawUrl, wantHtmlHint = null){
  if(!rawUrl) return res.status(400).send("Missing url (use /proxy?url=https://example.com or /proxy/<host>/<path>)");
  if(!/^https?:\/\//i.test(rawUrl)) rawUrl = "https://" + rawUrl;

  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = (wantHtmlHint === null) ? (accept.includes("text/html") || req.query.force_html === '1') : Boolean(wantHtmlHint);

  const assetKey = rawUrl + "::asset";
  const htmlKey = rawUrl + "::html";
  let host = null;
  try{ host = new URL(rawUrl).hostname; }catch(e){}
  const hostCacheCfg = PER_HOST_CACHE_CONTROLS[host] || {};

  // serve cached non-html assets
  if(!wantHtml){
    const mem = MEM_CACHE.get(assetKey);
    if(mem){
      if(mem.headers) Object.entries(mem.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} });
      return res.send(Buffer.from(mem.body, "base64"));
    }
    const disk = await diskGet(assetKey);
    if(disk){
      if(disk.headers) Object.entries(disk.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} });
      return res.send(Buffer.from(disk.body, "base64"));
    }
  } else {
    const memHtml = MEM_CACHE.get(htmlKey);
    if(memHtml){ res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(memHtml); }
    const diskHtml = await diskGet(htmlKey);
    if(diskHtml){ res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(diskHtml); }
  }

  // prepare upstream headers
  const originHeaders = {
    "User-Agent": session.payload.ua || (req.headers['user-agent'] || USER_AGENT_DEFAULT),
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": req.headers.referer || req.headers.referrer || undefined
  };
  // some sites rely on sec-fetch* headers
  originHeaders['sec-fetch-site'] = req.headers['sec-fetch-site'] || 'cross-site';
  originHeaders['sec-fetch-mode'] = req.headers['sec-fetch-mode'] || 'navigate';
  originHeaders['sec-fetch-dest'] = req.headers['sec-fetch-dest'] || 'document';
  if(req.headers.origin) originHeaders['Origin'] = req.headers.origin;
  // send cookies for the origin from session store
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;

  // upstream fetch
  let originRes;
  try{
    originRes = await upstreamFetch(rawUrl, { headers: originHeaders, redirect: "manual", method: req.method }, true);
  }catch(err){
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // capture set-cookie
  try{
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  }catch(e){}

  const status = originRes.status || 200;
  // redirect chaining: rewrite location to proxied public origin
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      let abs;
      try{ abs = new URL(loc, rawUrl).href; }catch(e){ abs = loc; }
      const proxied = proxyizeAbsoluteUrl(abs, req);
      try{ res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); }catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  // content-type
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html") || (wantHtml && contentType === "");
  const treatAsAsset = !isHtml;

  if(treatAsAsset){
    // forward headers (but drop security headers)
    try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
    try{ setSessionCookieHeader(res, session.sid); } catch(e){}
    try{
      // prefer arrayBuffer for binary safety
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if(hostCacheCfg.disable !== true && buf.length < ASSET_CACHE_THRESHOLD){
        const data = { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") };
        MEM_CACHE.set(assetKey, data);
        diskSet(assetKey, data).catch(()=>{});
      }
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      // pass through content-encoding if present
      const ce = originRes.headers.get("content-encoding");
      if(ce) res.setHeader("Content-Encoding", ce);
      return res.send(buf);
    }catch(err){
      // fallback to streaming if arrayBuffer fails
      try{ originRes.body.pipe(res); return; }catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // HTML path - read text, sanitize, transform
  let htmlText;
  try{ htmlText = await originRes.text(); }catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }
  htmlText = sanitizeHtml(htmlText);

  // JSDOM transform with per-request public origin
  let transformed = jsdomTransform(htmlText, originRes.url || rawUrl, req);

  // inject client-side fetch/xhr wrapper to force same-proxy usage for SPA requests
  const clientMarker = "/* EUPHORIA_CLIENT_REWRITE */";
  if(!transformed.includes(clientMarker)){
    const deploy = getPublicOrigin(req);
    const clientSnippet = `<script>${clientMarker}(function(){const DEPLOY='${deploy}';const origFetch=window.fetch;window.fetch=function(resource,init){try{ if(typeof resource==='string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href); else if(resource instanceof Request && !resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);}catch(e){} return origFetch(resource, init);}; const OrigXHR=window.XMLHttpRequest; window.XMLHttpRequest=function(){ const xhr=new OrigXHR(); const open=xhr.open; xhr.open=function(method,url,...rest){ try{ if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)) url = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href); }catch(e){} return open.call(this, method, url, ...rest); }; return xhr; };})();</script>`;
    transformed = transformed.replace(/<\/body>/i, clientSnippet + "</body>");
  }

  // Inline scripts rewrite and SW patch
  try{
    const dom2 = new JSDOM(transformed, { url: originRes.url || rawUrl });
    const document2 = dom2.window.document;
    const scripts = Array.from(document2.querySelectorAll('script'));
    for(const s of scripts){
      try{
        const src = s.getAttribute('src');
        if(src) continue;
        let code = s.textContent || '';
        if(!code.trim()) continue;
        const lower = code.slice(0,300).toLowerCase();
        if(lower.includes('importscripts') || lower.includes('caches.open') || lower.includes('serviceworker')){
          code = patchServiceWorker(code, originRes.url || rawUrl, req);
        }
        code = rewriteInlineJs(code, originRes.url || rawUrl, req);
        s.textContent = code;
      }catch(e){}
    }
    transformed = dom2.serialize();
  }catch(e){ console.warn("post-process inline scripts failed", e && e.message ? e.message : e); }

  // forward headers (dropping dangerous ones)
  try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  try{ if(hostCacheCfg.disable !== true && transformed && Buffer.byteLength(transformed,'utf8') < 512 * 1024){ MEM_CACHE.set(htmlKey, transformed); diskSet(htmlKey, transformed).catch(()=>{}); } } catch(e){}

  return res.send(transformed);
}

/* route: /proxy?url=... */
app.get("/proxy", async (req, res) => {
  return handleProxyToUrl(req, res, req.query.url || req.query.u || null, null);
});

/* route: /proxy/:host/*  -> map host + rest to URL */
app.all("/proxy/:host/*", async (req, res) => {
  try{
    const host = req.params.host;
    const tail = req.params[0] || "";
    const proto = req.query._proto || (req.headers['x-forwarded-proto'] || req.protocol) || 'https';
    const raw = `${proto}://${host}/${tail}`.replace(/([^:])\/{2,}/g, "$1/");
    return handleProxyToUrl(req, res, raw, null);
  }catch(e){
    console.error("proxy host route error", e);
    return res.status(400).send("Bad proxy target");
  }
});

/* route: /tunnel?url=...  - raw passthrough with minimal rewrites (good for login APIs) */
app.all("/tunnel", async (req, res) => {
  let raw = req.query.url || null;
  if(!raw) return res.status(400).send("Missing url (use /tunnel?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  const method = req.method || "GET";
  const headers = { 'user-agent': session.payload.ua || USER_AGENT_DEFAULT, ...req.headers };
  delete headers.host;
  try{
    const originRes = await upstreamFetch(raw, { method, headers, redirect: "follow" }, false);
    originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} });
    const arr = await originRes.arrayBuffer();
    return res.status(originRes.status || 200).send(Buffer.from(arr));
  }catch(err){
    console.error("tunnel error", err);
    return res.status(502).send("Tunnel error: " + String(err));
  }
});

/* fallback direct-path logic: keep for referenced pages that include ?url= in referer */
app.use(async (req, res, next) => {
  const p = req.path || "/";
  if(p.startsWith("/proxy") || p.startsWith("/_euph_ws") || p.startsWith("/_wsproxy") || p.startsWith("/_euph_debug") || p.startsWith("/static") || p.startsWith("/public") || p.startsWith("/tunnel")) return next();
  const referer = req.headers.referer || req.headers.referrer || "";
  const m = referer.match(/[?&]url=([^&]+)/);
  if(!m) return next();
  let orig;
  try{ orig = decodeURIComponent(m[1]); } catch(e){ return next(); }
  if(!orig) return next();
  let baseOrigin;
  try{ baseOrigin = new URL(orig).origin; } catch(e){ return next(); }
  const attempted = new URL(req.originalUrl, baseOrigin).href;
  try{
    return await handleProxyToUrl(req, res, attempted, null);
  }catch(err){
    console.error("fallback proxy error", err && err.message ? err.message : err);
    return next();
  }
});

/* SPA fallback */
app.get("/", (req,res) => {
  const index = path.join(__dirname, "public", "index.html");
  if(fs.existsSync(index)) return res.sendFile(index);
  return res.send(`<html><body><h3>Euphoria Proxy</h3><p>Use /proxy?url=...</p></body></html>`);
});
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")){
    const index = path.join(__dirname, "public", "index.html");
    if(fs.existsSync(index)) return res.sendFile(index);
  }
  next();
});

/* -----------------------
   ADMIN / DEBUG ENDPOINTS
   ----------------------- */
function requireAdmin(req,res,next){
  if(ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if(!ADMIN_TOKEN && (req.ip === '127.0.0.1' || req.ip === '::1')) return next();
  res.status(403).json({ error: "forbidden" });
}
app.get("/_euph_debug/ping", (req,res) => res.json({ msg:"pong", ts: Date.now() }));
app.get("/_euph_debug/sessions", requireAdmin, (req,res) => {
  const out = {};
  for(const [sid, payload] of SESSIONS.entries()){
    out[sid] = { last: new Date(payload.last).toISOString(), ua: payload.ua, ip: payload.ip, cookies: Object.fromEntries(payload.cookies.entries()) };
  }
  res.json({ sessions: out, count: SESSIONS.size });
});
app.get("/_euph_debug/cache", requireAdmin, (req,res) => {
  const mem = {};
  MEM_CACHE.forEach((v,k)=>{ mem[k] = { size: typeof v === 'string' ? Buffer.byteLength(v,'utf8') : JSON.stringify(v).length }; });
  res.json({ memory: mem, memoryCount: MEM_CACHE.size });
});
app.post("/_euph_debug/clear_cache", requireAdmin, async (req,res) => {
  MEM_CACHE.clear();
  if(ENABLE_DISK_CACHE){
    try{ const files = await fsPromises.readdir(CACHE_DIR); for(const f of files) await fsPromises.unlink(path.join(CACHE_DIR,f)).catch(()=>{}); }catch(e){}
  }
  res.json({ ok:true });
});
app.get("/_euph_debug/extensions", requireAdmin, (req,res) => res.json({ extensions: Array.from(EXTENSIONS.keys()) }));
app.post("/_euph_debug/set_origin", requireAdmin, (req,res) => {
  const newOrigin = req.body && req.body.origin;
  if(!newOrigin) return res.status(400).json({ error: "missing origin" });
  process.env.DEPLOYMENT_ORIGIN = newOrigin;
  return res.json({ ok:true, origin: newOrigin });
});

/* -----------------------
   EXTENSIONS HOOK
   ----------------------- */
const EXTENSIONS = new Map();
function registerExtension(name, fn){ if(typeof fn !== "function") throw new Error("extension must be function"); EXTENSIONS.set(name, fn); }
async function runExtensions(html, context={}){ let out = html; for(const [name,fn] of EXTENSIONS.entries()){ try{ out = await fn(out, context) || out; }catch(e){ console.error(`extension ${name} failed`, e); } } return out; }
// sample extension injection (kept lightweight)
registerExtension("bannerInject", (html) => {
  if(!html.includes("<body")) return html;
  const banner = `<div style="position:fixed;top:0;width:100%;background:#222;color:#fff;text-align:center;z-index:9999;font-family:sans-serif;padding:4px 0;font-size:12px;">Euphoria Proxy Active</div>`;
  return html.replace(/<body([^>]*)>/i, (m)=> m + banner);
});

/* -----------------------
   ERROR HANDLING & SHUTDOWN
   ----------------------- */
process.on("unhandledRejection", err => console.error("unhandledRejection", err && err.stack ? err.stack : err));
process.on("uncaughtException", err => console.error("uncaughtException", err && err.stack ? err.stack : err));
process.on("warning", w => console.warn("warning", w && w.stack ? w.stack : w));

async function shutdown(){
  try{ server.close(); }catch(e){}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);