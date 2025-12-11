// server.js
// Euphoria v2 - production-grade hybrid proxy with JSDOM rewriting, caching, sessions, ws proxy, rate limiting,
// per-host cache controls, IP rotation hook points and admin endpoints.
// Minimal comments, feature-rich, Node 20+.

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
import { LRUCache } from "lru-cache"; // <-- FIXED import
import http from "http";
import https from "https";

EventEmitter.defaultMaxListeners = 300;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// CONFIG
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "http://localhost:3000";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6;
const FETCH_TIMEOUT_MS = 30000;
const ASSET_CACHE_THRESHOLD = 256 * 1024;
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ITEMS = 1024;
const PER_HOST_CACHE_CONTROLS = {}; // override per host TTLs or disable caching

if (ENABLE_DISK_CACHE) await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

// binary asset extensions
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

// EXPRESS SETUP
const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// rate limiter (global)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || "600"),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down."
});
app.use(globalLimiter);

// memory cache using LRUCache
// estimate average item size in bytes (adjust if needed)
const AVG_ITEM_SIZE = 50 * 1024; // 50 KB per entry

const MEM_CACHE = new LRUCache({
  // total cache size in bytes
  maxSize: MAX_MEMORY_CACHE_ITEMS * AVG_ITEM_SIZE,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) =>
    typeof val === "string" ? Buffer.byteLength(val, "utf8") : JSON.stringify(val).length
});

// disk cache helper
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }

async function diskGet(key){
  if(!ENABLE_DISK_CACHE) return null;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname, "utf8");
    const obj = JSON.parse(raw);
    if((now() - obj.t) < CACHE_TTL) return obj.v;
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

// SESSIONS
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

// cleanup stale sessions
setInterval(()=>{
  const cutoff = Date.now() - (1000*60*60*24);
  for(const [sid, p] of SESSIONS.entries()){
    if(p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000*60*30);

// HOOKS: IP rotation and external resolver
async function ipRotationHook(host){
  if(typeof process.env.IP_ROTATION_PROVIDER_URL === "string" && process.env.IP_ROTATION_PROVIDER_URL.length){
    try{
      // user can replace with real API integration
      // placeholder: call provider to get upstream proxy or outbound IP route
      return null;
    }catch(e){}
  }
  return null;
}

// HELPERS & REWRITES
function isAlreadyProxiedHref(href){
  if(!href) return false;
  try{
    if(href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if(resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  }catch(e){}
  return false;
}
function toAbsolute(href, base){
  try{ return new URL(href, base).href; } catch(e){ return null; }
}
function proxyizeAbsoluteUrl(abs){
  try { const u = new URL(abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; }
  catch(e){ try { const u2 = new URL("https://" + abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch(e2) { return abs; } }
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
function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  }catch(e){}
  return html;
}

// JSDOM transform
function jsdomTransform(html, baseUrl){
  try{
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;
    if(!document.querySelector('base')){
      const head = document.querySelector('head');
      if(head){
        const b = document.createElement('base');
        b.setAttribute('href', baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    anchors.forEach(a=>{
      try{
        const href = a.getAttribute('href');
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(isAlreadyProxiedHref(href)) return;
        const abs = toAbsolute(href, baseUrl) || href;
        a.setAttribute('href', proxyizeAbsoluteUrl(abs));
        a.removeAttribute('target');
      }catch(e){}
    });
    const forms = Array.from(document.querySelectorAll('form[action]'));
    forms.forEach(f=>{
      try{
        const act = f.getAttribute('action') || '';
        if(!act) return;
        if(isAlreadyProxiedHref(act)) return;
        const abs = toAbsolute(act, baseUrl) || act;
        f.setAttribute('action', proxyizeAbsoluteUrl(abs));
      }catch(e){}
    });
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
          if(isAlreadyProxiedHref(v)) return;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(srcAttr, proxyizeAbsoluteUrl(abs));
        }catch(e){}
      });
    });
    const srcsetEls = Array.from(document.querySelectorAll('[srcset]'));
    srcsetEls.forEach(el=>{
      try{
        const ss = el.getAttribute('srcset') || '';
        const parts = ss.split(',').map(p=>{
          const [u, rest] = p.trim().split(/\s+/,2);
          if(!u) return p;
          if(/^data:/i.test(u)) return p;
          if(isAlreadyProxiedHref(u)) return p;
          const abs = toAbsolute(u, baseUrl) || u;
          return proxyizeAbsoluteUrl(abs) + (rest ? ' ' + rest : '');
        });
        el.setAttribute('srcset', parts.join(', '));
      }catch(e){}
    });
    const styles = Array.from(document.querySelectorAll('style'));
    styles.forEach(st=>{
      try{
        let txt = st.textContent || '';
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(isAlreadyProxiedHref(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyizeAbsoluteUrl(abs)}")`;
        });
        st.textContent = txt;
      }catch(e){}
    });
    const inlines = Array.from(document.querySelectorAll('[style]'));
    inlines.forEach(el=>{
      try{
        const s = el.getAttribute('style') || '';
        const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(isAlreadyProxiedHref(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyizeAbsoluteUrl(abs)}")`;
        });
        el.setAttribute('style', out);
      }catch(e){}
    });
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
        const abs = toAbsolute(dest, baseUrl) || dest;
        m.setAttribute('content', parts[0] + ';url=' + proxyizeAbsoluteUrl(abs));
      }catch(e){}
    });
    const noscripts = Array.from(document.getElementsByTagName('noscript'));
    noscripts.forEach(n=>{ try{ n.parentNode && n.parentNode.removeChild(n);}catch(e){} });
    return dom.serialize();
  }catch(err){
    console.warn("jsdom transform failed", err && err.message ? err.message : err);
    return html;
  }
}

// JS rewrites and SW patch
function rewriteInlineJs(source, baseUrl){
  try{
    source = source.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs)}'`;
      }catch(e){ return m; }
    });
    source = source.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs)}'`;
      }catch(e){ return m; }
    });
    source = source.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `'${proxyizeAbsoluteUrl(abs)}'`;
      }catch(e){ return m; }
    });
    return source;
  }catch(e){ return source; }
}
function patchServiceWorker(source, baseUrl){
  try{
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m,args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(item => {
          if(typeof item === 'string'){ const abs = toAbsolute(item, baseUrl) || item; return `'${proxyizeAbsoluteUrl(abs)}'`; }
          return JSON.stringify(item);
        });
        return `importScripts(${out.join(',')})`;
      }catch(e){ return m; }
    });
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){ return source; }
}

// AGENTS for upstream (respect keepalive)
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });

// fetch wrapper using global fetch with agent support and optional ip rotation (hook)
async function upstreamFetch(url, opts = {}, hostRotation=null){
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
  let fetchOpts = { ...opts, signal: controller.signal };
  if(!fetchOpts.headers) fetchOpts.headers = {};
  fetchOpts.headers['user-agent'] = fetchOpts.headers['user-agent'] || USER_AGENT_DEFAULT;
  if(isHttps) fetchOpts.agent = httpsAgent; else fetchOpts.agent = httpAgent;
  try{
    const rotated = hostRotation ? await ipRotationHook(u.hostname) : null;
    if(rotated && rotated.proxy && rotated.proxy.href){
      // If user provides an external proxy, route through it (optional advanced mode).
      if(rotated.proxy && rotated.proxy.href){
        // Not implementing full upstream proxying here; hook point for operator.
      }
    }
    const res = await fetch(url, fetchOpts);
    clearTimeout(timeout);
    return res;
  }catch(err){
    clearTimeout(timeout);
    throw err;
  }
}

// WEBSOCKET PROXY: production-grade (handles ws/wss proxied through our HTTP server)
function setupWsProxy(server){
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  server.on('upgrade', async (request, socket, head) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if(url.pathname !== '/_wsproxy') return;
    const target = url.searchParams.get('url');
    if(!target){
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
      return;
    }
    try{
      // create a client WebSocket connection to the target and proxy messages both ways
      const wsClient = new WebSocket(target, { headers: { origin: request.headers.origin || DEPLOYMENT_ORIGIN } });
      wsClient.on('open', () => {
        const proxySocket = new WebSocket(null);
      });
      // Instead we fallback to simple tunneling approach using built-in ws server
      // Accept the incoming upgrade as a WebSocket on our server
      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        // connect outbound
        const outbound = new WebSocket(target);
        outbound.on('open', () => {
          ws.on('message', msg => { try{ outbound.send(msg); }catch(e){} });
          outbound.on('message', msg => { try{ ws.send(msg); }catch(e){} });
          const forwardClose = (code, reason) => {
            try{ ws.close(code, reason); }catch(e){}
            try{ outbound.close(code, reason); }catch(e){}
          };
          ws.on('close', forwardClose);
          outbound.on('close', forwardClose);
        });
        outbound.on('error', () => ws.close());
        ws.on('error', () => outbound.close());
      });
    }catch(e){
      try{ socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); }catch(e){}
    }
  });
  return wssProxy;
}

// start server & ws proxy
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

// /proxy endpoint
app.get("/proxy", async (req, res) => {
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//,"")) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'bc-hybrid' || req.query.force_html === '1';
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";
  // check per-host cache disable
  let host = null;
  try{ host = new URL(raw).hostname; }catch(e){}
  const hostCacheCfg = PER_HOST_CACHE_CONTROLS[host] || {};
  if(!wantHtml){
    const mem = MEM_CACHE.get(assetKey);
    if(mem) {
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
    if(memHtml) { res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(memHtml); }
    const diskHtml = await diskGet(htmlKey);
    if(diskHtml) { res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(diskHtml); }
  }
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
  let originRes;
  try{
    originRes = await upstreamFetch(raw, { headers: originHeaders, redirect: "manual" }, true);
  }catch(err){
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }
  try{
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  }catch(e){}
  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      let abs;
      try{ abs = new URL(loc, raw).href; }catch(e){ abs = loc; }
      const proxied = proxyizeAbsoluteUrl(abs);
      try{ res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); }catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;
  if(treatAsAsset){
    try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
    try{ setSessionCookieHeader(res, session.sid); } catch(e){}
    try{
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if(hostCacheCfg.disable !== true && buf.length < ASSET_CACHE_THRESHOLD){
        const data = { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") };
        MEM_CACHE.set(assetKey, data);
        diskSet(assetKey, data).catch(()=>{});
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    }catch(err){
      try{ originRes.body.pipe(res); return; }catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }
  let htmlText;
  try{ htmlText = await originRes.text(); }catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }
  htmlText = sanitizeHtml(htmlText);
  let transformed = jsdomTransform(htmlText, originRes.url || raw);
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
  try{
    const dom2 = new JSDOM(transformed, { url: originRes.url || raw });
    const document2 = dom2.window.document;
    const scripts = Array.from(document2.querySelectorAll('script'));
    for(const s of scripts){
      try{
        const src = s.getAttribute('src');
        if(src) continue;
        let code = s.textContent || '';
        if(!code.trim()) continue;
        const lower = code.slice(0,300).toLowerCase();
        if(lower.includes('self.addeventlistener') || lower.includes('importscripts') || lower.includes('caches.open')){
          code = patchServiceWorker(code, originRes.url || raw);
        }
        code = rewriteInlineJs(code, originRes.url || raw);
        s.textContent = code;
      }catch(e){}
    }
    transformed = dom2.serialize();
  }catch(e){ console.warn("post-process inline scripts failed", e && e.message ? e.message : e); }
  try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  try{ if(hostCacheCfg.disable !== true && transformed && Buffer.byteLength(transformed,'utf8') < 512 * 1024){ MEM_CACHE.set(htmlKey, transformed); diskSet(htmlKey, transformed).catch(()=>{}); } } catch(e){}
  return res.send(transformed);
});

// fallback direct-path
app.use(async (req, res, next) => {
  const p = req.path || "/";
  if(p.startsWith("/proxy") || p.startsWith("/_euph_ws") || p.startsWith("/_wsproxy") || p.startsWith("/_euph_debug") || p.startsWith("/static") || p.startsWith("/public")) return next();
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
    const session = getSessionFromReq(req);
    setSessionCookieHeader(res, session.sid);
    const originHeaders = { "User-Agent": session.payload.ua || USER_AGENT_DEFAULT, "Accept": req.headers.accept || "*/*", "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9" };
    const cookieHdr = buildCookieHeader(session.payload.cookies);
    if(cookieHdr) originHeaders["Cookie"] = cookieHdr;
    const originRes = await upstreamFetch(attempted, { headers: originHeaders, redirect: "manual" }, true);
    if([301,302,303,307,308].includes(originRes.status)){
      const loc = originRes.headers.get("location");
      if(loc){ const abs = new URL(loc, attempted).href; return res.redirect(proxyizeAbsoluteUrl(abs)); }
    }
    const ct = (originRes.headers.get("content-type") || "").toLowerCase();
    if(!ct.includes("text/html")){
      originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
      const arr = await originRes.arrayBuffer();
      return res.send(Buffer.from(arr));
    }
    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = jsdomTransform(html, originRes.url || attempted);
    const final = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA FALLBACK */
(function(){ const D="${DEPLOYMENT_ORIGIN}"; (function(){ const orig = window.fetch; window.fetch = function(r,i){ try{ if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); }catch(e){} return orig.call(this,r,i); }; })(); })();
</script></body>`);
    originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.send(final);
  }catch(err){
    console.error("fallback proxy error", err && err.message ? err.message : err);
    return next();
  }
});

// SPA fallback
app.get("/", (req,res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// ADMIN endpoints
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
function requireAdmin(req,res,next){
  if(ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  // allow local dev
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

// EXTENSIONS hook
const EXTENSIONS = new Map();
function registerExtension(name, fn){ if(typeof fn !== "function") throw new Error("extension must be function"); EXTENSIONS.set(name, fn); }
async function runExtensions(html, context={}){ let out = html; for(const [name,fn] of EXTENSIONS.entries()){ try{ out = await fn(out, context) || out; }catch(e){ console.error(`extension ${name} failed`, e); } } return out; }
// sample extension
registerExtension("bannerInject", (html) => {
  if(!html.includes("<body")) return html;
  const banner = `<div style="position:fixed;top:0;width:100%;background:#222;color:#fff;text-align:center;z-index:9999;font-family:sans-serif;padding:4px 0;font-size:12px;">Euphoria Proxy Active</div>`;
  return html.replace(/<body([^>]*)>/i, (m)=> m + banner);
});

// error handling
process.on("unhandledRejection", err => console.error("unhandledRejection", err && err.stack ? err.stack : err));
process.on("uncaughtException", err => console.error("uncaughtException", err && err.stack ? err.stack : err));
process.on("warning", w => console.warn("warning", w && w.stack ? w.stack : w));

// ensure graceful shutdown
async function shutdown(){
  try{ server.close(); }catch(e){}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);