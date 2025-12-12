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
import { WebSocket, WebSocketServer } from "ws";
import cookie from "cookie";
import { EventEmitter } from "events";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import http from "http";
import https from "https";

EventEmitter.defaultMaxListeners = 300;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// CONFIG
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "false";
const CACHE_TTL = Number(process.env.CACHE_TTL_MS || 1000 * 60 * 6);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 30000);
const ASSET_CACHE_THRESHOLD = Number(process.env.ASSET_CACHE_THRESHOLD || 256 * 1024);
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ITEMS = Number(process.env.MAX_MEMORY_CACHE_ITEMS || 1024);
const PER_HOST_CACHE_CONTROLS = {}; // can be populated at runtime or via admin endpoints
const UPSTREAM_RETRY_COUNT = Number(process.env.UPSTREAM_RETRY_COUNT || 2);
const UPSTREAM_RETRY_DELAY_MS = Number(process.env.UPSTREAM_RETRY_DELAY_MS || 300);

// ensure disk cache dir
if (ENABLE_DISK_CACHE) await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

// asset ext
const ASSET_EXTENSIONS = [
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",
  ".ttf",".otf",".woff",".woff2",".eot",".json",".map",".mp4",".webm",".mp3"
];
const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// headers to drop (CSP, COOP may block embedding or cross origin)
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// metrics
const METRICS = { requests:0, proxied:0, cacheHits:0, cacheMiss:0, fetchErrors:0 };

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

// LRU cache: set maxSize as number of entries (fallback) but sizeCalculation returns approximate bytes
const MEM_CACHE = new LRUCache({
  // interpret maxSize as number of entries here; if you prefer bytes set a larger maxSize and tune sizeCalculation
  maxSize: MAX_MEMORY_CACHE_ITEMS,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) => {
    try{
      if(typeof val === "string") return Buffer.byteLength(val, "utf8");
      if(val && val.body && typeof val.body === "string") return Buffer.byteLength(val.body, "base64");
      return JSON.stringify(val || "").length;
    }catch(e){ return 1; }
  }
});

// disk helpers
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }

async function diskGet(key){
  if(!ENABLE_DISK_CACHE) return null;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname);
    // stored as JSON, but it may be binary-safe: try parse
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

// SESSIONS
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT, ip: null }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header=""){ const out = {}; header.split(";").forEach(p=>{ const [k,v] = (p||"").split("=").map(s=> (s||"").trim()); if(k && v !== undefined) out[k]=v; }); return out; }
function getSessionFromReq(req){
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)) {
    const c = createSession();
    c.payload.ip = req.ip || req.socket && req.socket.remoteAddress || null;
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

// HOOKS
async function ipRotationHook(host){
  if(typeof process.env.IP_ROTATION_PROVIDER_URL === "string" && process.env.IP_ROTATION_PROVIDER_URL.length){
    try{
      // placeholder - operator can implement real rotation
      return null;
    }catch(e){}
  }
  return null;
}

// Utilities: compute deploy origin at request time (priority: env DEPLOYMENT_ORIGIN > X-Forwarded-Proto/Host > req)
function getDeployOriginForReq(req){
  if(DEPLOYMENT_ORIGIN && DEPLOYMENT_ORIGIN.length) return DEPLOYMENT_ORIGIN.replace(/\/+$/,'');
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
  const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`.replace(/\/+$/,'');
}

// helpers for safe header copying
function copyHeadersForResponse(originHeaders, res){
  try{
    originHeaders.forEach((value, key) => {
      if(DROP_HEADERS.has(key.toLowerCase())) return;
      // express setHeader will throw on invalid values; guard
      try{ res.setHeader(key, value); }catch(e){}
    });
  }catch(e){
    // originHeaders may not be iterable (older Response object), try fallback
    try{
      const entries = Object.fromEntries(originHeaders.entries ? originHeaders.entries() : []);
      Object.entries(entries).forEach(([k,v]) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); }catch(e){} });
    }catch(e){}
  }
}

// helpers for rewriting proxied absolute urls
function proxyizeAbsoluteUrl(abs, req){
  try{
    const u = new URL(abs);
    const base = getDeployOriginForReq(req);
    // canonical route is /proxy/:host/<path>?url-encoded or we will use query form
    const hostEncoded = encodeURIComponent(u.hostname + (u.port ? `:${u.port}` : ""));
    const p = u.pathname + (u.search || '') + (u.hash || '');
    // build canonical: /proxy/:host/<path>?url=... is robust: we'll use query form for full fidelity
    const proxyQuery = `${base}/proxy?url=${encodeURIComponent(u.href)}`;
    return proxyQuery;
  }catch(e){
    try{
      const u2 = new URL("https://" + abs);
      const base2 = getDeployOriginForReq(req);
      return `${base2}/proxy?url=${encodeURIComponent(u2.href)}`;
    }catch(e2){
      return abs;
    }
  }
}

// helpers to detect asset
function looksLikeAsset(urlStr){
  if(!urlStr) return false;
  try {
    const p = new URL(urlStr, "https://example.com").pathname.toLowerCase();
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

// sanitize minimal risky attributes
function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  }catch(e){}
  return html;
}

// JSDOM transform (now accepts req to produce correct deploy origin)
function jsdomTransform(html, baseUrl, req){
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
        if(href.includes('/proxy?url=')) return;
        const abs = toAbsolute(href, baseUrl) || href;
        a.setAttribute('href', proxyizeAbsoluteUrl(abs, req));
        a.removeAttribute('target');
      }catch(e){}
    });
    const forms = Array.from(document.querySelectorAll('form[action]'));
    forms.forEach(f=>{
      try{
        const act = f.getAttribute('action') || '';
        if(!act) return;
        if(act.includes('/proxy?url=')) return;
        const abs = toAbsolute(act, baseUrl) || act;
        f.setAttribute('action', proxyizeAbsoluteUrl(abs, req));
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
          if(v.includes('/proxy?url=')) return;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(srcAttr, proxyizeAbsoluteUrl(abs, req));
          // remove crossorigin attribute to avoid opaque responses that may block usage
          try{ el.removeAttribute('crossorigin'); }catch(e){}
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
          if(u.includes('/proxy?url=')) return p;
          const abs = toAbsolute(u, baseUrl) || u;
          return proxyizeAbsoluteUrl(abs, req) + (rest ? ' ' + rest : '');
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
          if(u.includes('/proxy?url=')) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyizeAbsoluteUrl(abs, req)}")`;
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
          if(u.includes('/proxy?url=')) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyizeAbsoluteUrl(abs, req)}")`;
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
        m.setAttribute('content', parts[0] + ';url=' + proxyizeAbsoluteUrl(abs, req));
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

// helpers to convert to absolute
function toAbsolute(href, base){
  try{ return new URL(href, base).href; } catch(e){ return null; }
}

// rewrite inline JS
function rewriteInlineJs(source, baseUrl, req){
  try{
    let s = source;
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    s = s.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    s = s.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){ return source; }
}

// patch service worker
function patchServiceWorker(source, baseUrl, req){
  try{
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m,args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(item => {
          if(typeof item === 'string'){ const abs = toAbsolute(item, baseUrl) || item; return `'${proxyizeAbsoluteUrl(abs, req)}'`; }
          return JSON.stringify(item);
        });
        return `importScripts(${out.join(',')})`;
      }catch(e){ return m; }
    });
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){ return source; }
}

// upstream fetch wrapper with retry and agent
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

async function upstreamFetch(url, opts = {}, hostRotation=null){
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  let fetchOpts = { ...opts };
  fetchOpts.headers = fetchOpts.headers || {};
  // ensure Host header set to target host to avoid some SNI/virtual-hosting issues
  fetchOpts.headers["host"] = u.host;
  // default headers
  fetchOpts.headers["user-agent"] = fetchOpts.headers["user-agent"] || USER_AGENT_DEFAULT;
  fetchOpts.headers["accept"] = fetchOpts.headers["accept"] || "*/*";
  fetchOpts.redirect = fetchOpts.redirect || "manual";
  if(isHttps) fetchOpts.agent = httpsAgent; else fetchOpts.agent = httpAgent;

  let lastErr;
  for(let attempt=0; attempt<Math.max(1,UPSTREAM_RETRY_COUNT); attempt++){
    const controller = new AbortController();
    const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    fetchOpts.signal = controller.signal;
    try{
      const rotated = hostRotation ? await ipRotationHook(u.hostname) : null;
      if(rotated && rotated.proxy && rotated.proxy.href){
        // hook point - operator may want to implement curl/proxying here
      }
      // use global fetch
      const res = await fetch(url, fetchOpts);
      clearTimeout(timeout);
      return res;
    }catch(err){
      clearTimeout(timeout);
      lastErr = err;
      // transient network errors -> retry with small backoff
      if(err && (err.type === 'aborted' || err.code === 'ECONNRESET' || err.code === 'EPIPE' || err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED')){
        await new Promise(r => setTimeout(r, UPSTREAM_RETRY_DELAY_MS * (attempt + 1)));
        continue;
      }
      // try protocol swap fallback for hostnames often redirecting http<->https
      if(attempt === 0){
        try{
          const swapped = u.protocol === "https:" ? "http:" : "https:";
          const alt = new URL(url);
          alt.protocol = swapped;
          url = alt.href;
          // next iteration will try swapped protocol
          await new Promise(r => setTimeout(r, 80));
          continue;
        }catch(e){}
      }
      break;
    }
  }
  METRICS.fetchErrors++;
  const e = lastErr || new Error("upstream fetch failed");
  throw e;
}

// WEBSOCKET PROXY setup
function setupWsProxy(server){
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  server.on('upgrade', async (request, socket, head) => {
    try{
      const url = new URL(request.url, `http://${request.headers.host}`);
      // allow both /_wsproxy?url= and /proxy style ws: /proxy?url=ws://host/...
      if(url.pathname !== '/_wsproxy' && !url.pathname.startsWith('/proxy')) {
        return;
      }
      let target = url.searchParams.get('url');
      if(!target && url.pathname.startsWith('/proxy/')){
        // handle /proxy/:host/...
        const rest = url.pathname.replace(/^\/proxy\//,'');
        if(rest) {
          // reconstruct target
          // allow encoded url as next segment
          target = decodeURIComponent(rest);
        }
      }
      if(!target){
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        socket.destroy();
        return;
      }
      // accept incoming ws as server side and create outbound client
      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        let outbound;
        try{
          outbound = new WebSocket(target, {
            headers: { origin: request.headers.origin || getDeployOriginForReq({ headers: request.headers, protocol: request.socket.encrypted ? "https" : "http" }) }
          });
        }catch(err){
          try{ ws.close(); }catch(e){}
          return;
        }
        const forward = (src, dst) => {
          src.on('message', msg => { try{ dst.send(msg); }catch(e){} });
          const forwardClose = (code, reason) => { try{ dst.close(code, reason); }catch(e){}; try{ src.close(code, reason); }catch(e){}; };
          src.on('close', forwardClose);
          dst.on('close', forwardClose);
          src.on('error', ()=>{ try{ dst.close(); }catch(e){} });
          dst.on('error', ()=>{ try{ src.close(); }catch(e){} });
        };
        outbound.on('open', () => forward(ws, outbound));
        outbound.on('message', msg => { try{ ws.send(msg); }catch(e){} });
        outbound.on('error', ()=>{ try{ ws.close(); }catch(e){}; });
        ws.on('error', ()=>{ try{ outbound.close(); }catch(e){}; });
      });
    }catch(e){
      try{ socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); }catch(e){}
    }
  });
  return wssProxy;
}

// start server & ws telemetry
const server = http.createServer(app);
const wssTelemetry = new WebSocketServer({ server, path: "/_euph_ws" });
wssTelemetry.on("connection", ws=>{
  ws.send(JSON.stringify({ msg:"welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try { const parsed = JSON.parse(String(raw)); if(parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg:'pong', ts: Date.now() })); } catch(e){}
  });
});
setupWsProxy(server);
server.listen(PORT, ()=> console.log(`Euphoria v2 running on port ${PORT}`));

// canonical proxy route: supports /proxy?url=... and /proxy/:host/<path>
app.get("/proxy", async (req, res) => {
  METRICS.requests++;
  // normalize url param
  let raw = req.query.url || null;
  if(!raw && req.path && req.path.startsWith("/proxy/")){
    raw = decodeURIComponent(req.path.replace(/^\/proxy\//,""));
  }
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}

  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'bc-hybrid' || req.query.force_html === '1';
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  let host = null;
  try{ host = new URL(raw).hostname; }catch(e){}
  const hostCacheCfg = PER_HOST_CACHE_CONTROLS[host] || {};

  // handle cache (assets & html)
  if(!wantHtml){
    const mem = MEM_CACHE.get(assetKey);
    if(mem){
      METRICS.cacheHits++;
      if(mem.headers) Object.entries(mem.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); }catch(e){} });
      return res.send(Buffer.from(mem.body, "base64"));
    }
    const disk = await diskGet(assetKey);
    if(disk){
      METRICS.cacheHits++;
      if(disk.headers) Object.entries(disk.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); }catch(e){} });
      return res.send(Buffer.from(disk.body, "base64"));
    }
  } else {
    const memHtml = MEM_CACHE.get(htmlKey);
    if(memHtml){
      METRICS.cacheHits++;
      res.setHeader("Content-Type","text/html; charset=utf-8");
      return res.send(memHtml);
    }
    const diskHtml = await diskGet(htmlKey);
    if(diskHtml){
      METRICS.cacheHits++;
      res.setHeader("Content-Type","text/html; charset=utf-8");
      return res.send(diskHtml);
    }
  }
  METRICS.cacheMiss++;

  // prepare upstream headers
  const userAgent = session.payload.ua || req.headers['user-agent'] || USER_AGENT_DEFAULT;
  const originHeaders = {
    "User-Agent": userAgent,
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9",
    "Accept-Encoding": req.headers['accept-encoding'] || "gzip, deflate, br",
    "Referer": req.headers.referer || req.headers.referrer || undefined,
    "Sec-Fetch-Site": req.headers['sec-fetch-site'] || undefined
  };

  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;

  try { originHeaders["Origin"] = new URL(raw).origin; } catch(e){}

  let originRes;
  try{
    originRes = await upstreamFetch(raw, { headers: originHeaders, redirect: "manual" }, true);
  }catch(err){
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err && err.message ? err.message : err));
  }

  // capture set-cookie into session
  try{
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  }catch(e){}

  const status = originRes.status || 200;
  // handle redirects from upstream: rewrite to proxyized link (use request deploy origin)
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get ? originRes.headers.get("location") : null;
    if(loc){
      let abs;
      try{ abs = new URL(loc, raw).href; }catch(e){ abs = loc; }
      const proxied = proxyizeAbsoluteUrl(abs, req);
      try{ res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); }catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  const contentType = (originRes.headers.get ? originRes.headers.get("content-type") : "") || "";
  const isHtml = contentType.toLowerCase().includes("text/html");
  const treatAsAsset = !isHtml;

  if(treatAsAsset){
    try{ copyHeadersForResponse(originRes.headers, res); }catch(e){}
    try{ setSessionCookieHeader(res, session.sid); } catch(e){}
    try{
      // stream or buffer
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      // small assets cached
      if(hostCacheCfg.disable !== true && buf.length < ASSET_CACHE_THRESHOLD){
        const data = { headers: Object.fromEntries(originRes.headers.entries ? originRes.headers.entries() : []), body: buf.toString("base64") };
        try{ MEM_CACHE.set(assetKey, data); }catch(e){}
        diskSet(assetKey, data).catch(()=>{});
      }
      // ensure content-type
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      const cc = originRes.headers.get ? originRes.headers.get("cache-control") : null;
      if(cc) res.setHeader("Cache-Control", cc);
      if(originRes.headers.get && originRes.headers.get("content-length")) res.setHeader("Content-Length", originRes.headers.get("content-length"));
      return res.send(buf);
    }catch(err){
      try{ if(originRes.body && typeof originRes.body.pipe === "function"){ originRes.body.pipe(res); return; } }catch(e){}
      return res.status(502).send("Euphoria: asset stream failed");
    }
  }

  // HTML transform path
  let htmlText;
  try{ htmlText = await originRes.text(); }catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }
  htmlText = sanitizeHtml(htmlText);
  let transformed = jsdomTransform(htmlText, originRes.url || raw, req);

  // inject client-side proxy monkeypatch if absent
  const clientMarker = "/* EUPHORIA_CLIENT_REWRITE */";
  if(!transformed.includes(clientMarker)){
    const clientSnippet = `
<script>
${clientMarker}
(function(){
  const DEPLOY = "${getDeployOriginForReq(req)}";
  (function(){
    const origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')){
          resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request && !resource.url.includes('/proxy?url=')){
          resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
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

  // post-process inline scripts (rewrite fetch/xhr and SW patterns)
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
        if(lower.includes('self.addEventListener') || lower.includes('importscripts') || lower.includes('caches.open') || lower.includes('serviceworker')){
          code = patchServiceWorker(code, originRes.url || raw, req);
        }
        code = rewriteInlineJs(code, originRes.url || raw, req);
        s.textContent = code;
      }catch(e){}
    }
    transformed = dom2.serialize();
  }catch(e){ console.warn("post-process inline scripts failed", e && e.message ? e.message : e); }

  try{ copyHeadersForResponse(originRes.headers, res); }catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  try{
    if(hostCacheCfg.disable !== true && transformed && Buffer.byteLength(transformed,'utf8') < 512 * 1024){
      try{ MEM_CACHE.set(htmlKey, transformed); diskSet(htmlKey, transformed).catch(()=>{}); }catch(e){}
    }
  } catch(e){}
  METRICS.proxied++;
  return res.send(transformed);
});

// canonical : /proxy/:host/<path> -> redirect to query form preserve path
app.get("/proxy/:host/*", (req, res) => {
  // build full target from param and rest
  const hostPart = req.params.host;
  const rest = req.params[0] || "";
  // try decode first - if hostPart is encoded url, use that
  let target;
  try{
    // if hostPart contains scheme already (encoded), decode it
    if(/:\/\//.test(hostPart)) target = decodeURIComponent(hostPart) + (rest ? `/${rest}` : "");
    else {
      // if rest contains query-like elements, preserve
      target = `https://${hostPart}/${rest}`;
      // if there is query in original URL, append it
      if(Object.keys(req.query || {}).length){
        // if query contains url param, respect it
        if(req.query.url) target = req.query.url;
        else {
          const q = new URLSearchParams(req.query).toString();
          if(q) target += `?${q}`;
        }
      }
    }
  }catch(e){ target = `https://${hostPart}/${rest}`; }
  return res.redirect(302, `/proxy?url=${encodeURIComponent(target)}`);
});

// fallback direct-path (preserves referer url=... pattern)
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
      if(loc){ const abs = new URL(loc, attempted).href; return res.redirect(proxyizeAbsoluteUrl(abs, req)); }
    }
    const ct = (originRes.headers.get("content-type") || "").toLowerCase();
    if(!ct.includes("text/html")){
      copyHeadersForResponse(originRes.headers, res);
      const arr = await originRes.arrayBuffer();
      return res.send(Buffer.from(arr));
    }
    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = jsdomTransform(html, originRes.url || attempted, req);
    const final = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA FALLBACK */
(function(){ const D="${getDeployOriginForReq(req)}"; (function(){ const orig = window.fetch; window.fetch = function(r,i){ try{ if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); }catch(e){} return orig.call(this,r,i); }; })(); })();
</script></body>`);
    copyHeadersForResponse(originRes.headers, res);
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.send(final);
  }catch(err){
    console.error("fallback proxy error", err && err.message ? err.message : err);
    return next();
  }
});

// health + admin
app.get("/healthz", (req,res) => res.json({ ok:true, ts: Date.now() }));
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
function requireAdmin(req,res,next){
  if(ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if(!ADMIN_TOKEN && (req.ip === '127.0.0.1' || req.ip === '::1')) return next();
  res.status(403).json({ error: "forbidden" });
}
app.get("/_euph_debug/ping", (req,res) => res.json({ msg:"pong", ts: Date.now() }));
app.get("/_euph_debug/metrics", requireAdmin, (req,res) => res.json(METRICS));
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

// graceful shutdown
async function shutdown(){
  try{ server.close(); }catch(e){}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);