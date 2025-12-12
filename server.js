// server.js
// Euphoria v2 — production-grade hybrid proxy + embedded Wisp bridge/server
// Node 20+ (ESM). Minimal comments. Feature-rich: JSDOM rewriting, caching, sessions,
// ws proxy/bridge, embedded Wisp endpoint, per-host cache controls, rate-limit, admin.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import WebSocket, { WebSocketServer } from "ws";
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
const ENV_DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = parseInt(process.env.CACHE_TTL || String(1000 * 60 * 6), 10);
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "30000", 10);
const ASSET_CACHE_THRESHOLD = parseInt(process.env.ASSET_CACHE_THRESHOLD || String(256 * 1024), 10);
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ITEMS = parseInt(process.env.MAX_MEMORY_CACHE_ITEMS || "1024", 10);
const PER_HOST_CACHE_CONTROLS = {}; // override per host TTLs or disable caching via config or admin endpoints
const ENABLE_UPSTREAM_IP_ROTATION = !!process.env.IP_ROTATION_PROVIDER_URL;

// ensure cache dir
if (ENABLE_DISK_CACHE) await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

// binary asset extensions + special files
const ASSET_EXTENSIONS = [
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",
  ".ttf",".otf",".woff",".woff2",".eot",".json",".map",".mp4",".webm",".mp3",".avif",".bmp"
];
const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// headers to drop from origin to client
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// helpers
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function safeJson(v){ try{ return JSON.stringify(v); }catch(e){ return String(v); } }

// compute deployment origin (prefer env but fallback to request info)
function computeDeploymentOrigin(req){
  if(typeof ENV_DEPLOYMENT_ORIGIN === "string" && ENV_DEPLOYMENT_ORIGIN.length) return ENV_DEPLOYMENT_ORIGIN;
  if(req){
    const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
    const host = req.get('host') || req.headers.host || 'localhost:3000';
    return `${proto}://${host}`;
  }
  return "http://localhost:3000";
}

// proxyize absolute url using req if possible so we don't default to localhost
function proxyizeAbsoluteUrl(abs, req=null){
  try {
    const u = new URL(abs);
    const origin = computeDeploymentOrigin(req);
    return `${origin.replace(/\/$/,'')}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch(e) {
    try {
      const u2 = new URL("https://" + abs);
      const origin = computeDeploymentOrigin(req);
      return `${origin.replace(/\/$/,'')}/proxy?url=${encodeURIComponent(u2.href)}`;
    } catch(e2){
      return abs;
    }
  }
}

function isAlreadyProxiedHref(href, req=null){
  if(!href) return false;
  try{
    if(href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, computeDeploymentOrigin(req));
    if(resolved.origin === (new URL(computeDeploymentOrigin(req))).origin && resolved.pathname.startsWith("/proxy")) return true;
  }catch(e){}
  return false;
}

function toAbsolute(href, base){
  try{ return new URL(href, base).href; } catch(e){ return null; }
}

function looksLikeAsset(urlStr){
  if(!urlStr) return false;
  try {
    const p = new URL(urlStr, "https://example.invalid").pathname.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(p.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(p.endsWith(s)) return true;
    return false;
  } catch(e){
    const lower = (urlStr || "").toLowerCase();
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

// disk cache helpers
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

// EXPRESS SETUP
const app = express();
app.set("trust proxy", true);
app.use(cors({ origin: true }));
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// rate limiter (global)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || "1200", 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down."
});
app.use(globalLimiter);

// memory cache using LRUCache (count by entries)
const MEM_CACHE = new LRUCache({
  maxSize: MAX_MEMORY_CACHE_ITEMS,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) => 1
});

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

// periodic cleanup of stale sessions
setInterval(()=>{
  const cutoff = Date.now() - (1000*60*60*24);
  for(const [sid, p] of SESSIONS.entries()){
    if(p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000*60*30);

// IP rotation hook (operator can plug in)
async function ipRotationHook(host){
  if(!ENABLE_UPSTREAM_IP_ROTATION) return null;
  try{
    // Placeholder: call out to provider and return a routing hint:
    // { proxy: { href: 'http://proxy.example:3128' }, ip: '1.2.3.4' }
    return null;
  }catch(e){ return null; }
}

// AGENTS for upstream (respect keepalive)
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

// upstreamFetch: wrapper around global fetch with agent support and timeouts
async function upstreamFetch(url, opts = {}, useRotation = false){
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
  let fetchOpts = { ...opts, signal: controller.signal };
  if(!fetchOpts.headers) fetchOpts.headers = {};
  fetchOpts.headers['user-agent'] = fetchOpts.headers['user-agent'] || USER_AGENT_DEFAULT;
  // prefer accept-encoding that we can handle (node's fetch will decompress automatically)
  fetchOpts.headers['accept-encoding'] = fetchOpts.headers['accept-encoding'] || "gzip, deflate, br";
  if(isHttps) fetchOpts.agent = httpsAgent; else fetchOpts.agent = httpAgent;
  try{
    const rotated = useRotation ? await ipRotationHook(u.hostname) : null;
    // Hook point: if rotated contains outbound proxy info, operator may wire that in here
    const res = await fetch(url, fetchOpts);
    clearTimeout(timeout);
    return res;
  }catch(err){
    clearTimeout(timeout);
    throw err;
  }
}

// JSDOM transform + rewrites (keeps base href, proxies anchors/forms/assets)
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
        if(isAlreadyProxiedHref(href, req)) return;
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
        if(isAlreadyProxiedHref(act, req)) return;
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
          if(isAlreadyProxiedHref(v, req)) return;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(srcAttr, proxyizeAbsoluteUrl(abs, req));
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
          if(isAlreadyProxiedHref(u, req)) return p;
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
          if(isAlreadyProxiedHref(u, req)) return m;
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
          if(isAlreadyProxiedHref(u, req)) return m;
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

// rewrite inline JS to re-point fetch/XHR/open calls to proxy
function rewriteInlineJs(source, baseUrl, req){
  try{
    let src = source;
    src = src.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    src = src.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    src = src.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    return src;
  }catch(e){ return source; }
}

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

// ----- WISP BRIDGE / EMBEDDED SERVER -----
// Wisp session store and management
const WISP_SESSIONS = new Map();
function makeWispId(){ return "wisp_" + Math.random().toString(36).slice(2) + Date.now().toString(36); }

// Create an HTTP server first so we can attach upgrade handlers
const server = http.createServer(app);

// start server early listener
server.listen(PORT, ()=> console.log(`Euphoria v2 (with embedded Wisp) running on port ${PORT}`));

// WebSocket server for telemetry / admin
const wssTelemetry = new WebSocketServer({ server, path: "/_euph_ws", clientTracking: false });
wssTelemetry.on("connection", ws=>{
  ws.send(JSON.stringify({ msg:"welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try { const parsed = JSON.parse(raw.toString()); if(parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg:'pong', ts: Date.now() })); } catch(e){}
  });
});

// setupWsProxy — upgrade handler for generic ws proxying and /_wsproxy compatibility
function setupWsProxy(srv){
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  srv.on('upgrade', async (request, socket, head) => {
    try {
      const url = new URL(request.url, `http://${request.headers.host}`);
      // internal ws proxy endpoint for simple tunneling
      if(url.pathname === '/_wsproxy'){
        const target = url.searchParams.get('url');
        if(!target){
          socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
          socket.destroy();
          return;
        }
        // accept upgrade locally and bridge to outbound
        wssProxy.handleUpgrade(request, socket, head, (clientWs) => {
          let outbound;
          try{
            outbound = new WebSocket(target);
          }catch(e){
            try{ clientWs.close(1011, "Bad target"); }catch(_){} 
            return;
          }
          outbound.on('open', () => {
            clientWs.on('message', (m) => { try{ outbound.send(m); }catch(e){} });
            outbound.on('message', (m) => { try{ clientWs.send(m); }catch(e){} });
            const forwardClose = (code, reason) => { try{ clientWs.close(code, reason); }catch(e){}; try{ outbound.close(code, reason); }catch(e){}; };
            clientWs.on('close', forwardClose);
            outbound.on('close', forwardClose);
          });
          outbound.on('error', () => clientWs.close());
          clientWs.on('error', () => outbound.close());
        });
        return;
      }
      // handle wisp upgrade on same server upgrade handler (below)
      // fallthrough to next handlers
    } catch(e){
      try{ socket.destroy(); }catch(_){}
    }
  });
  return wssProxy;
}
const wssProxy = setupWsProxy(server);

// WISP endpoint: accepts upgrade at /wisp, can act as bridge to upstream wisp servers
// Query parameters:
//   upstream (optional): ws:// or wss:// upstream wisp server to connect and bridge
//   token (optional): token for auth (passed through)
const wssWisp = new WebSocketServer({ noServer: true, clientTracking: true });

server.on('upgrade', (request, socket, head) => {
  try{
    const url = new URL(request.url, `http://${request.headers.host}`);
    if(url.pathname !== '/wisp') return;
    // Accept upgrade and handle wisp session
    wssWisp.handleUpgrade(request, socket, head, async (ws) => {
      const qs = Object.fromEntries(url.searchParams.entries());
      const upstream = qs.upstream || null;
      const wispId = makeWispId();
      const meta = { id: wispId, created: Date.now(), upstream: upstream || null, remote: request.socket.remoteAddress || request.headers['x-forwarded-for'] || null };
      WISP_SESSIONS.set(wispId, { ws, meta, upstreamWs: null, open: true });
      ws.on('message', async (data, isBinary) => {
        try{
          // If we have an upstream to bridge, forward raw frames
          const s = WISP_SESSIONS.get(wispId);
          if(s && s.upstream && s.upstreamWs && s.upstreamWs.readyState === WebSocket.OPEN){
            s.upstreamWs.send(data, { binary: isBinary });
            return;
          }
          // No upstream: this is an inbound wisp client talking to embedded endpoint.
          // For now we treat frames as opaque and echo or log. Operators extend this.
          // Minimal echo logic: respond to ping frames or small control messages.
          if(!isBinary){
            const text = data.toString();
            if(text === "ping") ws.send("pong");
            else {
              // simple JSON control support
              try{
                const parsed = JSON.parse(text);
                if(parsed && parsed.cmd === "list-wisp") {
                  ws.send(JSON.stringify({ cmd: "wisp-list", sessions: Array.from(WISP_SESSIONS.keys()) }));
                } else {
                  // echo back
                  ws.send(JSON.stringify({ echo: parsed }));
                }
              }catch(e){
                ws.send(`echo:${text}`);
              }
            }
          }
        }catch(e){}
      });
      ws.on('close', () => {
        const s = WISP_SESSIONS.get(wispId);
        if(s && s.upstreamWs) try{ s.upstreamWs.close(); }catch(_){} 
        WISP_SESSIONS.delete(wispId);
      });
      ws.on('error', () => {
        const s = WISP_SESSIONS.get(wispId);
        if(s && s.upstreamWs) try{ s.upstreamWs.close(); }catch(_){} 
        WISP_SESSIONS.delete(wispId);
      });

      // If client requested bridging to an upstream, open outbound WebSocket to upstream and bridge frames both ways
      if(upstream){
        let upstreamWs = null;
        try{
          upstreamWs = new WebSocket(upstream, { headers: { origin: computeDeploymentOrigin(null) } });
        }catch(e){
          try{ ws.close(1011, "Invalid upstream"); }catch(_){} 
          WISP_SESSIONS.delete(wispId);
          return;
        }
        upstreamWs.on('open', () => {
          const s = WISP_SESSIONS.get(wispId);
          if(s) s.upstreamWs = upstreamWs;
          // pipe messages
          ws.on('message', (m, isBinary) => { try{ upstreamWs.send(m, { binary: isBinary }); }catch(_){} });
          upstreamWs.on('message', (m, isBinary) => { try{ ws.send(m, { binary: isBinary }); }catch(_){} });
        });
        upstreamWs.on('close', ()=> {
          try{ ws.close(); }catch(_){} 
          WISP_SESSIONS.delete(wispId);
        });
        upstreamWs.on('error', (err) => {
          try{ ws.close(1011, "upstream error"); }catch(_){} 
          WISP_SESSIONS.delete(wispId);
        });
      }

      // send welcome
      try{ ws.send(JSON.stringify({ msg: "wisp-connected", id: wispId, upstream: upstream || null, ts: Date.now() })); }catch(e){}
    });
  }catch(e){
    try{ socket.destroy(); }catch(_){} 
  }
});

// ADMIN WS listing endpoints over HTTP
app.get("/_euph_debug/wisp_sessions", (req,res) => {
  const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
  if(ADMIN_TOKEN && req.headers.authorization !== `Bearer ${ADMIN_TOKEN}`) return res.status(403).json({ error: "forbidden" });
  const out = {};
  for(const [id, obj] of WISP_SESSIONS.entries()){
    out[id] = { meta: obj.meta, open: obj.open, upstream: obj.meta.upstream || null };
  }
  res.json({ sessions: out, count: WISP_SESSIONS.size });
});

// runExtensions hook (same pattern as earlier)
const EXTENSIONS = new Map();
function registerExtension(name, fn){ if(typeof fn !== "function") throw new Error("extension must be function"); EXTENSIONS.set(name, fn); }
async function runExtensions(html, context={}){ let out = html; for(const [name,fn] of EXTENSIONS.entries()){ try{ out = await fn(out, context) || out; }catch(e){ console.error(`extension ${name} failed`, e); } } return out; }
registerExtension("bannerInject", (html) => {
  if(!html.includes("<body")) return html;
  const banner = `<div style="position:fixed;top:0;width:100%;background:#222;color:#fff;text-align:center;z-index:9999;font-family:sans-serif;padding:4px 0;font-size:12px;">Euphoria Proxy Active</div>`;
  return html.replace(/<body([^>]*)>/i, (m)=> m + banner);
});

// /proxy routes
// supports: /proxy?url=, /proxy//host/... and /proxy/:host/*
app.get("/proxy", async (req, res) => {
  // main query-style proxy
  let raw = req.query.url || null;
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com or /proxy//host/path)");
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  return await handleProxyRequest(raw, req, res);
});

// handle /proxy//host/path (double-slash) and /proxy/:host/*
app.get("/proxy/*", async (req, res) => {
  // if query param present, previous handler catches; else interpret path
  if(req.path === "/proxy") return res.status(400).send("Missing url");
  const rest = req.path.replace(/^\/proxy\//,'');
  // support two styles: leading //host/... => rest starts with /host/..., or host/... 
  if(rest.startsWith("/")){
    // //host/...
    const parts = rest.replace(/^\//,'').split('/');
    const host = parts.shift();
    const pathRest = parts.join('/');
    const assembled = (pathRest ? `https://${host}/${pathRest}` : `https://${host}`);
    return await handleProxyRequest(assembled, req, res);
  } else {
    // host/...
    const parts = rest.split('/');
    const host = parts.shift();
    const pathRest = parts.join('/');
    const assembled = (pathRest ? `https://${host}/${pathRest}` : `https://${host}`);
    return await handleProxyRequest(assembled, req, res);
  }
});

async function handleProxyRequest(rawUrl, req, res){
  // normalise
  let raw = rawUrl;
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
  // cache check
  if(!wantHtml){
    const mem = MEM_CACHE.get(assetKey);
    if(mem) {
      if(mem.headers) Object.entries(mem.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} });
      return res.status(200).send(Buffer.from(mem.body, "base64"));
    }
    const disk = await diskGet(assetKey);
    if(disk){
      if(disk.headers) Object.entries(disk.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} });
      return res.status(200).send(Buffer.from(disk.body, "base64"));
    }
  } else {
    const memHtml = MEM_CACHE.get(htmlKey);
    if(memHtml) { res.setHeader("Content-Type","text/html; charset=utf-8"); return res.status(200).send(memHtml); }
    const diskHtml = await diskGet(htmlKey);
    if(diskHtml) { res.setHeader("Content-Type","text/html; charset=utf-8"); return res.status(200).send(diskHtml); }
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
  // Attempt real upstream fetch
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
      const proxied = proxyizeAbsoluteUrl(abs, req);
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
      // cache small assets (images, css, small js)
      if(hostCacheCfg.disable !== true && buf.length < ASSET_CACHE_THRESHOLD){
        const data = { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") };
        MEM_CACHE.set(assetKey, data);
        diskSet(assetKey, data).catch(()=>{});
      }
      // preserve content-type and encoding
      if(originRes.headers.get("content-type")) res.setHeader("Content-Type", originRes.headers.get("content-type"));
      if(originRes.headers.get("content-encoding")) res.setHeader("Content-Encoding", originRes.headers.get("content-encoding"));
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.status(status).send(buf);
    }catch(err){
      try{ // pipe fallback
        if(originRes.body && typeof originRes.body.pipe === 'function'){ originRes.body.pipe(res); return; }
      }catch(e){}
      return res.status(502).send("Euphoria: asset stream failed");
    }
  }

  // HTML path
  let htmlText;
  try{ htmlText = await originRes.text(); }catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }
  htmlText = sanitizeHtml(htmlText);
  let transformed = jsdomTransform(htmlText, originRes.url || raw, req);
  const clientMarker = "/* EUPHORIA_CLIENT_REWRITE */";
  if(!transformed.includes(clientMarker)){
    const deploy = computeDeploymentOrigin(req);
    const clientSnippet = `
<script>
${clientMarker}
(function(){
  const DEPLOY = "${deploy}";
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
    // rewrite inline scripts
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
          code = patchServiceWorker(code, originRes.url || raw, req);
        }
        code = rewriteInlineJs(code, originRes.url || raw, req);
        s.textContent = code;
      }catch(e){}
    }
    transformed = dom2.serialize();
  }catch(e){ console.warn("post-process inline scripts failed", e && e.message ? e.message : e); }

  try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  try{ if(hostCacheCfg.disable !== true && transformed && Buffer.byteLength(transformed,'utf8') < 512 * 1024){ MEM_CACHE.set(htmlKey, transformed); diskSet(htmlKey, transformed).catch(()=>{}); } } catch(e){}
  return res.status(status).send(transformed);
}

// fallback direct-path handler (handles embedded links that used ?url= in referer)
app.use(async (req, res, next) => {
  const p = req.path || "/";
  if(p.startsWith("/proxy") || p.startsWith("/_euph_ws") || p.startsWith("/_wsproxy") || p.startsWith("/_euph_debug") || p.startsWith("/static") || p.startsWith("/public") || p.startsWith("/wisp")) return next();
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
      originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
      const arr = await originRes.arrayBuffer();
      return res.status(200).send(Buffer.from(arr));
    }
    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = jsdomTransform(html, originRes.url || attempted, req);
    const final = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA FALLBACK */
(function(){ const D="${computeDeploymentOrigin(req)}"; (function(){ const orig = window.fetch; window.fetch = function(r,i){ try{ if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); }catch(e){} return orig.call(this,r,i); }; })(); })();
</script></body>`);
    originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.status(200).send(final);
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
app.get("/_euph_debug/wisp_sessions", requireAdmin, (req,res) => {
  const out = {};
  for(const [id, obj] of WISP_SESSIONS.entries()){
    out[id] = { meta: obj.meta, upstream: obj.meta.upstream || null, open: obj.open || false };
  }
  res.json({ sessions: out, count: WISP_SESSIONS.size });
});
app.post("/_euph_debug/wisp_close", requireAdmin, (req,res) => {
  const id = req.body && req.body.id;
  if(!id || !WISP_SESSIONS.has(id)) return res.status(404).json({ error: "not found" });
  try{
    const s = WISP_SESSIONS.get(id);
    if(s && s.ws) s.ws.close();
    WISP_SESSIONS.delete(id);
  }catch(e){}
  res.json({ ok:true });
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