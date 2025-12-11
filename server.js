// server.js
// Euphoria v2 - production-grade hybrid proxy
// Minimal section headers, Node 20+

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import { WebSocketServer, WebSocket } from "ws";
import cookie from "cookie";
import { EventEmitter } from "events";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import http from "http";
import https from "https";
import { pipeline } from "stream";
import { promisify } from "util";

EventEmitter.defaultMaxListeners = 300;
const pipelineAsync = promisify(pipeline);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* ====== CONFIG ====== */
const ENV_DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const CACHE_TTL = Number(process.env.CACHE_TTL_MS || String(1000 * 60 * 6)); // 6 minutes default
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || String(30000));
const ASSET_CACHE_THRESHOLD = Number(process.env.ASSET_CACHE_THRESHOLD || String(256 * 1024));
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ITEMS = Number(process.env.MAX_MEMORY_CACHE_ITEMS || "2048");
const PER_HOST_CACHE_CONTROLS = {}; // runtime override map: hostname -> { disable: true, ttl: ms }
const NO_TRANSFORM_HOSTS = new Set((process.env.NO_TRANSFORM_HOSTS || "static.example.com").split(",").map(s=>s.trim()).filter(Boolean));
const TRUST_HOST_HEADER_TO_ORIGIN = process.env.TRUST_HOST_HEADER_TO_ORIGIN === "1"; // if true, use DEPLOYMENT_ORIGIN env as canonical

// ensure disk cache
if (ENABLE_DISK_CACHE) await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

/* ====== HELPERS / CONSTANTS ====== */
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

function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function safeJSONParse(str, fallback=null){
  try{ return JSON.parse(str); }catch(e){ return fallback; }
}
function isLikelyAssetByPath(p){
  if(!p) return false;
  const lower = p.toLowerCase();
  for(const ext of ASSET_EXTENSIONS) if(lower.endsWith(ext)) return true;
  for(const s of SPECIAL_FILES) if(lower.endsWith(s)) return true;
  return false;
}
function headerNames(obj){
  try{ return Object.keys(obj || {}).map(k => k.toLowerCase()); }catch(e){ return []; }
}

/* ====== LRU MEMORY CACHE ====== */
const MEM_CACHE = new LRUCache({
  maxSize: MAX_MEMORY_CACHE_ITEMS,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) => {
    try {
      if(typeof val === "string") return Buffer.byteLength(val, "utf8");
      return Buffer.byteLength(JSON.stringify(val), "utf8");
    } catch(e){ return 1; }
  }
});

/* ====== DISK CACHE ====== */
async function diskGet(key){
  if(!ENABLE_DISK_CACHE) return null;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname, "utf8");
    const obj = safeJSONParse(raw, null);
    if(!obj) return null;
    if((now() - obj.t) < (obj.ttl || CACHE_TTL)) return obj.v;
    await fsPromises.unlink(fname).catch(()=>{});
  }catch(e){}
  return null;
}
async function diskSet(key, val, ttl = CACHE_TTL){
  if(!ENABLE_DISK_CACHE) return;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    const obj = { v: val, t: now(), ttl };
    await fsPromises.writeFile(fname, JSON.stringify(obj), "utf8").catch(()=>{});
  }catch(e){}
}

/* ====== SESSIONS ====== */
const SESSION_NAME = process.env.SESSION_NAME || "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT, ip: null }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header = "") {
  const out = {};
  header.split(";").forEach(p => {
    const [k, ...rest] = (p||"").split("=").map(s => (s||"").trim());
    if(k) out[k] = (rest||[]).join("=");
  });
  return out;
}
function getSessionFromReq(req){
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)){
    const c = createSession();
    c.payload.ip = req.ip || req.socket?.remoteAddress || null;
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
function buildCookieHeader(map){
  if(!map || !(map instanceof Map)) return "";
  return [...map.entries()].map(([k,v]) => `${k}=${v}`).join("; ");
}

/* cleanup stale sessions */
setInterval(()=>{
  const cutoff = Date.now() - (1000*60*60*24);
  for(const [sid, p] of SESSIONS.entries()){
    if(p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000*60*30);

/* ====== EXPRESS SETUP ====== */
const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(morgan(process.env.LOG_FORMAT || "tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

/* ====== RATE LIMITER ====== */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_GLOBAL || 600),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down."
});
app.use(globalLimiter);

/* ====== AGENTS ====== */
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

/* ====== UPSTREAM FETCH WRAPPER ====== */
async function upstreamFetch(url, opts = {}, hostRotation=false){
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const to = setTimeout(()=> controller.abort(), FETCH_TIMEOUT_MS);
  let fetchOpts = { ...opts, signal: controller.signal };
  try{
    if(!fetchOpts.headers) fetchOpts.headers = {};
    // ensure common headers
    fetchOpts.headers['user-agent'] = fetchOpts.headers['user-agent'] || USER_AGENT_DEFAULT;
    if(!fetchOpts.headers['accept']) fetchOpts.headers['accept'] = "*/*";
    if(!fetchOpts.headers['accept-language']) fetchOpts.headers['accept-language'] = "en-US,en;q=0.9";
    // sec-fetch headers for sites that check them
    if(!fetchOpts.headers['sec-fetch-site']) fetchOpts.headers['sec-fetch-site'] = 'none';
    if(!fetchOpts.headers['sec-fetch-mode']) fetchOpts.headers['sec-fetch-mode'] = 'navigate';
    if(!fetchOpts.headers['sec-fetch-dest']) fetchOpts.headers['sec-fetch-dest'] = 'document';
    // set keepalive agent
    if(isHttps) fetchOpts.agent = httpsAgent; else fetchOpts.agent = httpAgent;
    // rotation hook (no-op by default)
    const rotated = hostRotation ? await ipRotationHook(u.hostname) : null;
    if(rotated && rotated.proxy && rotated.proxy.href){
      // operator can implement an upstream proxy by returning details from ipRotationHook
      // Not implementing full proxy tunneling here (left as extension point).
    }
    const res = await fetch(url, fetchOpts);
    clearTimeout(to);
    return res;
  }catch(err){
    clearTimeout(to);
    throw err;
  }
}

/* ====== PROXY URL HELPERS ====== */
function canonicalDeploymentOrigin(req){
  // prefer explicit env if provided and TRUST_HOST_HEADER_TO_ORIGIN false is not forcing runtime host
  if(ENV_DEPLOYMENT_ORIGIN && ENV_DEPLOYMENT_ORIGIN.length && !TRUST_HOST_HEADER_TO_ORIGIN) return ENV_DEPLOYMENT_ORIGIN.replace(/\/$/, "");
  // build from request
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host = req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}
function proxyizeAbsoluteUrlForRequest(abs, req){
  try{
    const u = new URL(abs);
    const base = canonicalDeploymentOrigin(req);
    return `${base}/proxy?url=${encodeURIComponent(u.href)}`;
  }catch(e){
    try{
      const u2 = new URL("https://" + abs);
      const base = canonicalDeploymentOrigin(req);
      return `${base}/proxy?url=${encodeURIComponent(u2.href)}`;
    }catch(e){
      return abs;
    }
  }
}

/* ====== REWRITE UTILITIES ====== */
function isAlreadyProxiedHrefForReq(href, req){
  if(!href) return false;
  try{
    if(href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, canonicalDeploymentOrigin(req));
    const deployOrigin = new URL(canonicalDeploymentOrigin(req));
    if(resolved.origin === deployOrigin.origin && resolved.pathname.startsWith("/proxy")) return true;
  }catch(e){}
  return false;
}

/* ====== SANITIZE HTML ====== */
function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
    // remove strict-same-origin CSP policies embedded in meta+headers
    return html;
  }catch(e){
    return html;
  }
}

/* ====== JSDOM TRANSFORM ====== */
function jsdomTransformForReq(html, baseUrl, req){
  try{
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;
    // inject base if none
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
        if(isAlreadyProxiedHrefForReq(href, req)) return;
        const abs = new URL(href, baseUrl).href;
        a.setAttribute('href', proxyizeAbsoluteUrlForRequest(abs, req));
        a.removeAttribute('target');
      }catch(e){}
    });
    // forms
    const forms = Array.from(document.querySelectorAll('form[action]'));
    forms.forEach(f=>{
      try{
        const act = f.getAttribute('action') || '';
        if(!act) return;
        if(isAlreadyProxiedHrefForReq(act, req)) return;
        const abs = new URL(act, baseUrl).href;
        f.setAttribute('action', proxyizeAbsoluteUrlForRequest(abs, req));
      }catch(e){}
    });
    // assets (img, script, link, iframe, source, video, audio)
    const assetTags = ['img','script','link','iframe','source','video','audio','picture','track'];
    assetTags.forEach(tag=>{
      const nodes = Array.from(document.getElementsByTagName(tag));
      nodes.forEach(el=>{
        try{
          const srcAttr = el.getAttribute('src') ? 'src' : (el.getAttribute('href') ? 'href' : null);
          if(!srcAttr) return;
          const v = el.getAttribute(srcAttr);
          if(!v) return;
          if(/^data:/i.test(v)) return;
          if(isAlreadyProxiedHrefForReq(v, req)) return;
          const abs = new URL(v, baseUrl).href;
          // For assets hosted on same host as the target, we still proxy to preserve cookies + auth
          el.setAttribute(srcAttr, proxyizeAbsoluteUrlForRequest(abs, req));
        }catch(e){}
      });
    });
    // srcset handling
    const srcsetEls = Array.from(document.querySelectorAll('[srcset]'));
    srcsetEls.forEach(el=>{
      try{
        const ss = el.getAttribute('srcset') || '';
        const parts = ss.split(',').map(p=>{
          const [u, rest] = p.trim().split(/\s+/,2);
          if(!u) return p;
          if(/^data:/i.test(u)) return p;
          if(isAlreadyProxiedHrefForReq(u, req)) return p;
          const abs = new URL(u, baseUrl).href;
          return proxyizeAbsoluteUrlForRequest(abs, req) + (rest ? ' ' + rest : '');
        });
        el.setAttribute('srcset', parts.join(', '));
      }catch(e){}
    });
    // inline style url(...) rewriting
    const styles = Array.from(document.querySelectorAll('style'));
    styles.forEach(st=>{
      try{
        let txt = st.textContent || '';
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(isAlreadyProxiedHrefForReq(u, req)) return m;
          const abs = new URL(u, baseUrl).href;
          return `url("${proxyizeAbsoluteUrlForRequest(abs, req)}")`;
        });
        st.textContent = txt;
      }catch(e){}
    });
    // inline element style attributes
    const inlineEls = Array.from(document.querySelectorAll('[style]'));
    inlineEls.forEach(el=>{
      try{
        const s = el.getAttribute('style') || '';
        const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(isAlreadyProxiedHrefForReq(u, req)) return m;
          const abs = new URL(u, baseUrl).href;
          return `url("${proxyizeAbsoluteUrlForRequest(abs, req)}")`;
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
        m.setAttribute('content', parts[0] + ';url=' + proxyizeAbsoluteUrlForRequest(abs, req));
      }catch(e){}
    });
    // remove noscript
    const noscripts = Array.from(document.getElementsByTagName('noscript'));
    noscripts.forEach(n=>{ try{ n.parentNode && n.parentNode.removeChild(n);}catch(e){} });
    return dom.serialize();
  }catch(err){
    console.warn("jsdom transform failed", err && err.message ? err.message : err);
    return html;
  }
}

/* ====== JS INLINE REWRITE & SERVICE WORKER PATCH ====== */
function rewriteInlineJsForReq(source, baseUrl, req){
  try{
    let s = source;
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `fetch('${proxyizeAbsoluteUrlForRequest(abs, req)}'`;
      }catch(e){ return m; }
    });
    s = s.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrlForRequest(abs, req)}'`;
      }catch(e){ return m; }
    });
    s = s.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `'${proxyizeAbsoluteUrlForRequest(abs, req)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){ return source; }
}
function patchServiceWorkerForReq(source, baseUrl, req){
  try{
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m,args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(item => {
          if(typeof item === 'string'){ const abs = new URL(item, baseUrl).href; return `'${proxyizeAbsoluteUrlForRequest(abs, req)}'`; }
          return JSON.stringify(item);
        });
        return `importScripts(${out.join(',')})`;
      }catch(e){ return m; }
    });
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `fetch('${proxyizeAbsoluteUrlForRequest(abs, req)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){ return source; }
}

/* ====== WS PROXY (robust bidirectional tunnel) ====== */
function setupWsProxy(server){
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  server.on('upgrade', async (request, socket, head) => {
    try{
      const u = new URL(request.url, `http://${request.headers.host}`);
      if(u.pathname !== '/_wsproxy') return;
      const target = u.searchParams.get('url');
      if(!target){
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }
      // Accept incoming upgrade
      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        // create outbound
        const outbound = new WebSocket(target, {
          headers: { origin: request.headers.origin || request.headers.host || "" }
        });
        function cleanup(){
          try{ ws.terminate(); }catch(e){}
          try{ outbound.terminate(); }catch(e){}
        }
        outbound.on('open', () => {
          ws.on('message', msg => { try{ outbound.send(msg); }catch(e){} });
          outbound.on('message', msg => { try{ ws.send(msg); }catch(e){} });
          ws.on('close', () => { try{ outbound.close(); }catch(e){} });
          outbound.on('close', () => { try{ ws.close(); }catch(e){} });
        });
        outbound.on('error', () => cleanup());
        ws.on('error', () => cleanup());
      });
    }catch(e){
      try{ socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); }catch(e){}
    }
  });
  return wssProxy;
}

/* ====== START SERVER & TELEMETRY WS ====== */
const server = http.createServer(app);
const wssTelemetry = new WebSocketServer({ server, path: "/_euph_ws", clientTracking: false });
wssTelemetry.on("connection", ws=>{
  ws.send(JSON.stringify({ msg:"welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try { const parsed = JSON.parse(raw.toString()); if(parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg:'pong', ts: Date.now() })); } catch(e){}
  });
});
setupWsProxy(server);
server.listen(PORT, ()=> console.log(`Euphoria v2 running on port ${PORT}`));

/* ====== MAIN /proxy ENDPOINT ====== */
app.get("/proxy", async (req, res) => {
  // dynamic origin for rewrites
  const DEPLOYMENT_ORIGIN = canonicalDeploymentOrigin(req);

  // fetch url
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//,"")) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session
  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}

  // Accept header to decide HTML vs asset
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'bc-hybrid' || req.query.force_html === '1';

  // cache keys
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // host-level cache config
  let host = null;
  try{ host = new URL(raw).hostname; }catch(e){}
  const hostCacheCfg = PER_HOST_CACHE_CONTROLS[host] || {};

  // Fast cache return for assets
  if(!wantHtml){
    const mem = MEM_CACHE.get(assetKey);
    if(mem){
      if(mem.headers) Object.entries(mem.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} });
      res.setHeader("X-Euphoria-Cache","HIT-MEM");
      return res.send(Buffer.from(mem.body, "base64"));
    }
    const disk = await diskGet(assetKey);
    if(disk){
      if(disk.headers) Object.entries(disk.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} });
      res.setHeader("X-Euphoria-Cache","HIT-DISK");
      return res.send(Buffer.from(disk.body, "base64"));
    }
  } else {
    const memHtml = MEM_CACHE.get(htmlKey);
    if(memHtml){
      res.setHeader("Content-Type","text/html; charset=utf-8");
      res.setHeader("X-Euphoria-Cache","HIT-MEM");
      return res.send(memHtml);
    }
    const diskHtml = await diskGet(htmlKey);
    if(diskHtml){
      res.setHeader("Content-Type","text/html; charset=utf-8");
      res.setHeader("X-Euphoria-Cache","HIT-DISK");
      return res.send(diskHtml);
    }
  }

  // upstream headers (provide good defaults and forward useful bits)
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

  // prefer to set sec-fetch-site depending on referer/target relationship
  try {
    const refererHost = req.headers.referer ? new URL(req.headers.referer).hostname : null;
    originHeaders['sec-fetch-site'] = (refererHost && refererHost !== new URL(raw).hostname) ? 'cross-site' : 'same-origin';
    originHeaders['sec-fetch-mode'] = 'navigate';
    originHeaders['sec-fetch-dest'] = 'document';
  } catch(e){}

  // attempt fetch
  let originRes;
  try{
    originRes = await upstreamFetch(raw, { headers: originHeaders, redirect: "manual" }, true);
  }catch(err){
    console.error("fetch error", err && err.message ? err.message : err);
    // If some sites fail due to TLS or other, attempt a fallback with looser headers
    try{
      originRes = await upstreamFetch(raw, { headers: { "User-Agent": USER_AGENT_DEFAULT, "Accept": "*/*" }, redirect: "manual" }, false);
    }catch(err2){
      console.error("fetch fallback also failed", err2 && err2.message ? err2.message : err2);
      return res.status(502).send("Euphoria: failed to fetch target: " + String(err2 || err));
    }
  }

  // collect set-cookie
  try{
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  }catch(e){}

  // handle redirect responses
  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      let abs;
      try{ abs = new URL(loc, raw).href; }catch(e){ abs = loc; }
      // rewrite redirect locations to proxied path using current deployment origin
      const proxied = proxyizeAbsoluteUrlForRequest(abs, req);
      try{ res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); }catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  // content type
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html") || contentType.includes("application/xhtml+xml");
  const treatAsAsset = !isHtml;

  // deliver asset (binary / static) — stream/pipe where possible
  if(treatAsAsset){
    try{
      // copy safe headers (exclude drop list)
      try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
      try{ setSessionCookieHeader(res, session.sid); } catch(e){}
      // stream body
      const body = originRes.body;
      if(!body){
        // fallback: arrayBuffer then send
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        // caching small assets
        if(hostCacheCfg.disable !== true && buf.length < ASSET_CACHE_THRESHOLD){
          const data = { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") };
          MEM_CACHE.set(assetKey, data);
          diskSet(assetKey, data).catch(()=>{});
        }
        res.setHeader("Content-Type", contentType || "application/octet-stream");
        if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
        return res.send(buf);
      } else {
        // streaming path
        res.setHeader("Content-Type", contentType || "application/octet-stream");
        if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
        // Buffer a small amount to optionally cache
        // We will stream directly to client and also capture into memory if small
        const reader = body.getReader();
        const chunks = [];
        let total = 0;
        for(;;){
          const r = await reader.read();
          if(r.done) break;
          const c = Buffer.from(r.value);
          chunks.push(c);
          total += c.length;
          res.write(c);
          // if size grows too big, stop capturing for cache
          if(total > ASSET_CACHE_THRESHOLD) {
            // drain rest to client without caching
            let rr = await reader.read();
            while(!rr.done){
              res.write(Buffer.from(rr.value));
              rr = await reader.read();
            }
            break;
          }
        }
        res.end();
        // if under threshold, save cache
        if(hostCacheCfg.disable !== true && total <= ASSET_CACHE_THRESHOLD){
          const buf = Buffer.concat(chunks, total);
          const data = { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") };
          MEM_CACHE.set(assetKey, data);
          diskSet(assetKey, data).catch(()=>{});
        }
        return;
      }
    }catch(err){
      console.error("asset stream error", err && err.stack ? err.stack : err);
      try{ originRes.body?.pipe?.(res); return; }catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // HTML path
  let htmlText;
  try{ htmlText = await originRes.text(); }catch(e){
    console.error("read html error", e && e.message ? e.message : e);
    return res.status(502).send("Euphoria: failed to read HTML");
  }

  htmlText = sanitizeHtml(htmlText);

  // per-host no-transform option for fragile hosts
  const noTransform = NO_TRANSFORM_HOSTS.has(host) || (PER_HOST_CACHE_CONTROLS[host] && PER_HOST_CACHE_CONTROLS[host].noTransform);

  let transformed = noTransform ? htmlText : jsdomTransformForReq(htmlText, originRes.url || raw, req);

  // client-side rewrite injection
  const clientMarker = "/* EUPHORIA_CLIENT_REWRITE */";
  if(!transformed.includes(clientMarker) && !noTransform){
    const clientSnippet = `
<script>
${clientMarker}
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  (function(){
    const realFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')){
          resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request && !resource.url.includes('/proxy?url=')){
          resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      }catch(e){}
      return realFetch.call(this, resource, init);
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

  // inline script post-processing
  try{
    if(!noTransform){
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
          if(lower.includes('self.addEventListener') || lower.includes('importScripts') || lower.includes('caches.open')){
            code = patchServiceWorkerForReq(code, originRes.url || raw, req);
          }
          code = rewriteInlineJsForReq(code, originRes.url || raw, req);
          s.textContent = code;
        }catch(e){}
      }
      transformed = dom2.serialize();
    }
  }catch(e){
    console.warn("post-process inline scripts failed", e && e.message ? e.message : e);
  }

  // copy headers from origin except DROP_HEADERS
  try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}

  // cache HTML if small
  try{
    if(hostCacheCfg.disable !== true && !noTransform && transformed && Buffer.byteLength(transformed,'utf8') < 512 * 1024){
      MEM_CACHE.set(htmlKey, transformed);
      diskSet(htmlKey, transformed).catch(()=>{});
    }
  }catch(e){}

  return res.send(transformed);
});

/* ====== FALLBACK DIRECT-PATH HANDLER (for links using ?url= in referer) ====== */
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
      if(loc){ const abs = new URL(loc, attempted).href; return res.redirect(proxyizeAbsoluteUrlForRequest(abs, req)); }
    }
    const ct = (originRes.headers.get("content-type") || "").toLowerCase();
    if(!ct.includes("text/html")){
      originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
      const arr = await originRes.arrayBuffer();
      return res.send(Buffer.from(arr));
    }
    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = jsdomTransformForReq(html, originRes.url || attempted, req);
    const final = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA FALLBACK */
(function(){ const D="${ENV_DEPLOYMENT_ORIGIN || (`http://localhost:${PORT}`)}"; (function(){ const orig = window.fetch; window.fetch = function(r,i){ try{ if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); }catch(e){} return orig.call(this,r,i); }; })(); })();
</script></body>`);
    originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.send(final);
  }catch(err){
    console.error("fallback proxy error", err && err.message ? err.message : err);
    return next();
  }
});

/* ====== SPA / static fallback ====== */
app.get("/", (req,res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

/* ====== ADMIN / DEBUG ENDPOINTS ====== */
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
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
app.post("/_euph_debug/set_no_transform", requireAdmin, express.json(), (req,res)=>{
  const { host, on } = req.body || {};
  if(!host) return res.status(400).json({ error: "host required" });
  if(on) NO_TRANSFORM_HOSTS.add(host); else NO_TRANSFORM_HOSTS.delete(host);
  res.json({ ok:true, host, on });
});

/* ====== EXTENSIONS HOOK ====== */
const EXTENSIONS = new Map();
function registerExtension(name, fn){
  if(typeof fn !== "function") throw new Error("extension must be function");
  EXTENSIONS.set(name, fn);
}
async function runExtensions(html, context = {}){
  let out = html;
  for(const [name, fn] of EXTENSIONS.entries()){
    try{ out = await fn(out, context) || out; }catch(e){ console.error(`extension ${name} failed`, e); }
  }
  return out;
}
// sample extension
registerExtension("bannerInject", (html) => {
  if(!html.includes("<body")) return html;
  const banner = `<div style="position:fixed;top:0;width:100%;background:#222;color:#fff;text-align:center;z-index:9999;font-family:sans-serif;padding:4px 0;font-size:12px;">Euphoria Proxy Active</div>`;
  return html.replace(/<body([^>]*)>/i, (m)=> m + banner);
});

/* ====== ERROR HANDLING & SHUTDOWN ====== */
process.on("unhandledRejection", err => console.error("unhandledRejection", err && err.stack ? err.stack : err));
process.on("uncaughtException", err => console.error("uncaughtException", err && err.stack ? err.stack : err));
process.on("warning", w => console.warn("warning", w && w.stack ? w.stack : w));

async function shutdown(){
  try{ server.close(); }catch(e){}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

/* ====== END ====== */
