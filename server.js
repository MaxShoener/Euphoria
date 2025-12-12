// server.js
// Euphoria v2 - production-grade hybrid proxy
// Minimal comments, focused on correctness & production readiness

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

// CONFIG (override with env)
const PORT = parseInt(process.env.PORT || "3000", 10);
const DEPLOYMENT_ORIGIN_ENV = process.env.DEPLOYMENT_ORIGIN || ""; // optional override
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = (process.env.ENABLE_DISK_CACHE ?? "1") !== "0";
const CACHE_TTL = parseInt(process.env.CACHE_TTL_MS || String(1000 * 60 * 6), 10);
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "30000", 10);
const ASSET_CACHE_THRESHOLD = parseInt(process.env.ASSET_CACHE_THRESHOLD || String(256 * 1024), 10); // bytes
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ITEMS = parseInt(process.env.MAX_MEMORY_CACHE_ITEMS || "1500", 10);
const PER_HOST_CACHE_CONTROLS = {}; // can be populated dynamically or via env later
const TRUSTED_ADMIN_IPS = (process.env.EUPH_ADMIN_TRUSTED_IPS || "127.0.0.1,::1").split(",").map(s => s.trim()).filter(Boolean);

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});
}

// assets and special file names
const ASSET_EXTENSIONS = [
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",
  ".avif",".apng",".ttf",".otf",".woff",".woff2",".eot",".json",".map",".mp4",".webm",".mp3"
];
const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// headers to drop when forwarding back to client
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
app.use(morgan(process.env.MORGAN_FORMAT || "tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || "1200", 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down."
});
app.use(globalLimiter);

// memory cache using LRUCache
const MEM_CACHE = new LRUCache({
  // maxSize counts items, not bytes; for byte-limited sizing you'd set maxSize and sizeCalculation
  maxSize: MAX_MEMORY_CACHE_ITEMS,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) => {
    try {
      if (typeof val === "string") return Buffer.byteLength(val, "utf8");
      return Buffer.byteLength(JSON.stringify(val), "utf8");
    } catch (e) { return 1; }
  }
});

// helpers
const now = () => Date.now();
const cacheKey = s => Buffer.from(s).toString("base64url");
async function diskGet(key){
  if(!ENABLE_DISK_CACHE) return null;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname, "utf8");
    const obj = JSON.parse(raw);
    if((now() - obj.t) < CACHE_TTL) return obj.v;
    await fsPromises.unlink(fname).catch(()=>{});
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

// SESSIONS (simple in-memory)
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

// cleanup stale sessions periodically
setInterval(()=>{
  const cutoff = Date.now() - (1000*60*60*24);
  for(const [sid, p] of SESSIONS.entries()){
    if(p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000*60*30);

// utility to determine deployment origin for link rewriting (prefer env, otherwise derive from request)
function deploymentOriginForReq(req){
  if(DEPLOYMENT_ORIGIN_ENV && DEPLOYMENT_ORIGIN_ENV.length) return DEPLOYMENT_ORIGIN_ENV.replace(/\/+$/,'');
  // prefer X-Forwarded-* headers (when behind proxy)
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`.replace(/\/+$/,'');
}
function isAssetUrl(urlStr){
  if(!urlStr) return false;
  try {
    const p = new URL(urlStr).pathname.toLowerCase();
    return ASSET_EXTENSIONS.some(ext => p.endsWith(ext)) || SPECIAL_FILES.some(s => p.endsWith(s));
  } catch(e){
    const lower = urlStr.toLowerCase();
    return ASSET_EXTENSIONS.some(ext => lower.endsWith(ext)) || SPECIAL_FILES.some(s => lower.endsWith(s));
  }
}

// sanitize and rewrite helpers
function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  }catch(e){}
  return html;
}

// MAIN: proxy URL maker (uses req to build correct host/proto for links)
function makeProxyUrlFor(req, targetUrl){
  try {
    const deploy = deploymentOriginForReq(req);
    const u = new URL(targetUrl);
    // encode full target
    return `${deploy.replace(/\/$/,'')}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch (e) {
    // fallback: treat as raw string
    const deploy = deploymentOriginForReq(req);
    return `${deploy.replace(/\/$/,'')}/proxy?url=${encodeURIComponent(String(targetUrl))}`;
  }
}

// helper used inside JSDOM transforms where req-specific deploy origin is needed
function buildProxyizeFunction(req){
  const deploy = deploymentOriginForReq(req);
  return function proxyizeAbsoluteUrl(abs){
    try { const u = new URL(abs); return `${deploy}/proxy?url=${encodeURIComponent(u.href)}`; }
    catch(e){ try { const u2 = new URL("https://" + abs); return `${deploy}/proxy?url=${encodeURIComponent(u2.href)}`; } catch(e2) { return abs; } }
  };
}

// JSDOM: transform HTML, make links/forms/assets route through our /proxy
function jsdomTransform(html, baseUrl, req){
  try{
    const proxyize = buildProxyizeFunction(req);
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;

    // ensure <base> so relative URLs resolve consistently
    if(!document.querySelector('base')){
      const head = document.querySelector('head');
      if(head){
        const b = document.createElement('base');
        b.setAttribute('href', baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }

    // anchors
    Array.from(document.querySelectorAll('a[href]')).forEach(a=>{
      try{
        const href = a.getAttribute('href');
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(href.includes('/proxy?url=')) return;
        const abs = new URL(href, baseUrl).href;
        a.setAttribute('href', proxyize(abs));
        a.removeAttribute('target');
      }catch(e){}
    });

    // forms
    Array.from(document.querySelectorAll('form[action]')).forEach(f=>{
      try{
        const act = f.getAttribute('action') || '';
        if(!act) return;
        if(act.includes('/proxy?url=')) return;
        const abs = new URL(act, baseUrl).href;
        f.setAttribute('action', proxyize(abs));
      }catch(e){}
    });

    // assets: src/href
    const assetTags = ['img','script','link','iframe','source','video','audio'];
    assetTags.forEach(tag=>{
      Array.from(document.getElementsByTagName(tag)).forEach(el=>{
        try{
          const srcAttr = el.getAttribute('src') ? 'src' : (el.getAttribute('href') ? 'href' : null);
          if(!srcAttr) return;
          const v = el.getAttribute(srcAttr);
          if(!v) return;
          if(/^data:/i.test(v)) return;
          if(v.includes('/proxy?url=')) return;
          const abs = new URL(v, baseUrl).href;
          el.setAttribute(srcAttr, proxyize(abs));
        }catch(e){}
      });
    });

    // srcset
    Array.from(document.querySelectorAll('[srcset]')).forEach(el=>{
      try{
        const ss = el.getAttribute('srcset') || '';
        const parts = ss.split(',').map(p=>{
          const [u, rest] = p.trim().split(/\s+/,2);
          if(!u) return p;
          if(/^data:/i.test(u)) return p;
          if(u.includes('/proxy?url=')) return p;
          const abs = new URL(u, baseUrl).href;
          return proxyize(abs) + (rest ? ' ' + rest : '');
        });
        el.setAttribute('srcset', parts.join(', '));
      }catch(e){}
    });

    // inline style urls
    Array.from(document.querySelectorAll('style')).forEach(st=>{
      try{
        let txt = st.textContent || '';
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(u.includes('/proxy?url=')) return m;
          const abs = new URL(u, baseUrl).href;
          return `url("${proxyize(abs)}")`;
        });
        st.textContent = txt;
      }catch(e){}
    });
    Array.from(document.querySelectorAll('[style]')).forEach(el=>{
      try{
        const s = el.getAttribute('style') || '';
        const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(u.includes('/proxy?url=')) return m;
          const abs = new URL(u, baseUrl).href;
          return `url("${proxyize(abs)}")`;
        });
        el.setAttribute('style', out);
      }catch(e){}
    });

    // meta refresh
    Array.from(document.querySelectorAll('meta[http-equiv]')).forEach(m=>{
      try{
        if((m.getAttribute('http-equiv')||'').toLowerCase() !== 'refresh') return;
        const c = m.getAttribute('content') || '';
        const parts = c.split(';');
        if(parts.length < 2) return;
        const urlpart = parts.slice(1).join(';').match(/url=(.*)/i);
        if(!urlpart) return;
        const dest = urlpart[1].replace(/['"]/g,'').trim();
        const abs = new URL(dest, baseUrl).href;
        m.setAttribute('content', parts[0] + ';url=' + proxyize(abs));
      }catch(e){}
    });

    // remove noscript contents (may reference originals)
    Array.from(document.getElementsByTagName('noscript')).forEach(n => { try{ n.parentNode && n.parentNode.removeChild(n);}catch(e){} });

    return dom.serialize();
  }catch(err){
    console.warn("jsdom transform failed", err && err.message ? err.message : err);
    return html;
  }
}

// JS rewriting for inline scripts (best-effort)
function rewriteInlineJs(source, baseUrl, req){
  try{
    const proxyize = buildProxyizeFunction(req);
    let s = source;
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `fetch('${proxyize(abs)}'`;
      }catch(e){ return m; }
    });
    s = s.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `.open(${p1}${method || ''}${p1},'${proxyize(abs)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){
    return source;
  }
}

// Agents for upstream (keepAlive)
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

// upstream fetch wrapper (uses global fetch - Node 18+). adds timeout, agent selection, and header hygiene
async function upstreamFetch(url, opts = {}, reqHints = {}){
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
  const fetchOpts = { ...opts, signal: controller.signal };

  // ensure headers object
  fetchOpts.headers = Object.assign({}, fetchOpts.headers || {});
  // prefer provided UA, else session UA or default
  fetchOpts.headers['user-agent'] = fetchOpts.headers['user-agent'] || USER_AGENT_DEFAULT;

  // remove hop-by-hop headers or other problematic ones
  const forbidden = ["connection","keep-alive","proxy-authorization","proxy-authenticate","upgrade","host"];
  for(const h of forbidden) delete fetchOpts.headers[h];

  // For some sites (xbox etc.) remove Sec-Fetch / Origin to avoid rejections
  ['sec-fetch-site','sec-fetch-mode','sec-fetch-dest','sec-fetch-user','origin'].forEach(h => {
    if(fetchOpts.headers[h]) delete fetchOpts.headers[h];
  });

  // agent
  fetchOpts.agent = isHttps ? httpsAgent : httpAgent;

  try {
    const res = await fetch(url, fetchOpts);
    clearTimeout(timeout);
    return res;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// WEBSOCKET PROXY (path: /_wsproxy?url=ws://...)
function setupWsProxy(server){
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  server.on('upgrade', (request, socket, head) => {
    try{
      const url = new URL(request.url, `http://${request.headers.host}`);
      if(url.pathname !== '/_wsproxy') return;
      const target = url.searchParams.get('url');
      if(!target){ socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); socket.destroy(); return; }

      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        // outbound connection
        const outbound = new (require('ws'))(target); // dynamic require for compatibility
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

// create http server and telemetry ws
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

// Proxy route: supports ?url= and /proxy/:host/* style
app.get(['/proxy'], async (req, res) => {
  // canonical target url
  let raw = req.query.url || null;

  // also check path-style: /proxy/:host/* (Express didn't mount a path param; so allow using req.path)
  if(!raw && req.path && req.path.startsWith('/proxy/')) {
    // /proxy/<encoded-host>/<rest> or /proxy/<host>/<path...>
    const rest = req.path.replace(/^\/proxy\//,'');
    // try decodeURIComponent, else as-is
    try { raw = decodeURIComponent(rest); } catch(e){ raw = rest; }
  }

  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com or /proxy/<host>/<path>)");

  // normalize
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}

  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'bc-hybrid' || req.query.force_html === '1';

  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // per-host cache
  let host = null;
  try{ host = new URL(raw).hostname; }catch(e){}

  const hostCacheCfg = PER_HOST_CACHE_CONTROLS[host] || {};

  // try caches first
  try {
    if(!wantHtml) {
      const mem = MEM_CACHE.get(assetKey);
      if(mem) { if(mem.headers) Object.entries(mem.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} }); return res.send(Buffer.from(mem.body, "base64")); }
      const disk = await diskGet(assetKey);
      if(disk) { if(disk.headers) Object.entries(disk.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); } catch(e){} }); return res.send(Buffer.from(disk.body, "base64")); }
    } else {
      const memHtml = MEM_CACHE.get(htmlKey);
      if(memHtml) { res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(memHtml); }
      const diskHtml = await diskGet(htmlKey);
      if(diskHtml) { res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(diskHtml); }
    }
  } catch(e){ /* cache read errors ignored */ }

  // build origin headers from client (but clean some)
  const originHeaders = {
    "User-Agent": session.payload.ua || (req.headers['user-agent'] || USER_AGENT_DEFAULT),
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if(req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  // Some sites reject Origin; attach only if necessary later
  try { originHeaders["Origin"] = new URL(raw).origin; }catch(e){}

  // special-case header hygiene for known problem sites
  const lowerHost = (host || "").toLowerCase();
  if(lowerHost.includes("xbox") || lowerHost.includes("xboxlive") || lowerHost.includes("microsoft")) {
    // remove sec-fetch and origin to reduce rejections
    ["sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-fetch-user","origin"].forEach(h => delete originHeaders[h]);
  }

  // fetch upstream
  let originRes;
  try {
    originRes = await upstreamFetch(raw, { headers: originHeaders, redirect: "manual" }, { req });
  } catch (err) {
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err && err.message ? err.message : err));
  }

  // capture set-cookie
  try{
    const rawCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(rawCookies.length) storeSetCookieToSession(rawCookies, session.payload);
  }catch(e){}

  // handle redirects from origin - rewrite to proxied URL using request host/proto
  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      let abs;
      try{ abs = new URL(loc, raw).href; }catch(e){ abs = loc; }
      const proxied = makeProxyUrlFor(req, abs);
      try{ res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); }catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  // determine content-type
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;

  // streaming/binary path for non-HTML (fixes images, videos, fonts, complex assets)
  if(treatAsAsset){
    try {
      // copy safe headers
      try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
      try{ setSessionCookieHeader(res, session.sid); } catch(e){}

      // read full buffer (so we can optionally cache)
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);

      // caching policy
      if(hostCacheCfg.disable !== true && buf.length < ASSET_CACHE_THRESHOLD){
        const data = { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") };
        try{ MEM_CACHE.set(assetKey, data); }catch(e){}
        diskSet(assetKey, data).catch(()=>{});
      }

      // forward content-type and cache-control if present
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      const cc = originRes.headers.get("cache-control");
      if(cc) res.setHeader("Cache-Control", cc);

      return res.send(buf);
    } catch(err){
      try{ originRes.body.pipe(res); return; }catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // otherwise HTML path
  let htmlText;
  try{ htmlText = await originRes.text(); }catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }

  htmlText = sanitizeHtml(htmlText);

  // JSDOM transform uses req so link rewriting uses correct deployment host
  let transformed = jsdomTransform(htmlText, originRes.url || raw, req);

  // inject client-side fetch/xhr rewriting once
  const clientMarker = "/* EUPHORIA_CLIENT_REWRITE */";
  if(!transformed.includes(clientMarker)){
    const deploy = deploymentOriginForReq(req);
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

  // post-process inline scripts to rewrite fetch/xhr where possible
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
        if(lower.includes('self.addEventListener') || lower.includes('importScripts') || lower.includes('caches.open')){
          code = patchServiceWorker(code, originRes.url || raw, req);
        }
        code = rewriteInlineJs(code, originRes.url || raw, req);
        s.textContent = code;
      }catch(e){}
    }
    transformed = dom2.serialize();
  }catch(e){ console.warn("post-process inline scripts failed", e && e.message ? e.message : e); }

  // forward safe headers
  try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  try{
    if(hostCacheCfg.disable !== true && transformed && Buffer.byteLength(transformed,'utf8') < 512 * 1024){
      MEM_CACHE.set(htmlKey, transformed);
      diskSet(htmlKey, transformed).catch(()=>{});
    }
  } catch(e){}

  return res.send(transformed);
});

// path-style proxy: /proxy/:host/*
app.get('/proxy/:host/*', async (req, res) => {
  const host = req.params.host;
  const rest = req.params[0] || '';
  const protoHostPath = `${host}/${rest}`;
  // redirect to canonical /proxy?url= form which the main route already supports
  const target = (req.query.url) ? req.query.url : `https://${protoHostPath}`;
  return res.redirect(302, `/proxy?url=${encodeURIComponent(target)}`);
});

// fallback direct-path (handles referer with ?url=... pattern)
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
    const originRes = await upstreamFetch(attempted, { headers: originHeaders, redirect: "manual" }, { req });
    if([301,302,303,307,308].includes(originRes.status)){
      const loc = originRes.headers.get("location");
      if(loc){ const abs = new URL(loc, attempted).href; return res.redirect(makeProxyUrlFor(req, abs)); }
    }
    const ct = (originRes.headers.get("content-type") || "").toLowerCase();
    if(!ct.includes("text/html")){
      originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
      const arr = await originRes.arrayBuffer();
      return res.send(Buffer.from(arr));
    }
    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = jsdomTransform(html, originRes.url || attempted, req);
    const final = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA FALLBACK */
(function(){ const D="${deploymentOriginForReq(req)}"; (function(){ const orig = window.fetch; window.fetch = function(r,i){ try{ if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); }catch(e){} return orig.call(this,r,i); }; })(); })();
</script></body>`);
    originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.send(final);
  }catch(err){
    console.error("fallback proxy error", err && err.message ? err.message : err);
    return next();
  }
});

// SPA fallback - serve index.html from public (if exists)
app.get("/", (req,res) => {
  const f = path.join(__dirname, "public", "index.html");
  if(fs.existsSync(f)) return res.sendFile(f);
  return res.status(200).send("Euphoria proxy running");
});
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) {
    const f = path.join(__dirname, "public", "index.html");
    if(fs.existsSync(f)) return res.sendFile(f);
  }
  next();
});

// ADMIN endpoints
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";
function requireAdmin(req,res,next){
  if(ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if(!ADMIN_TOKEN){
    // allow trusted ips
    const ip = (req.ip || req.connection.remoteAddress || "").replace(/^::ffff:/,"");
    if(TRUSTED_ADMIN_IPS.includes(ip)) return next();
  }
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
app.get("/_euph_debug/health", (req,res) => res.json({ ok: true, ts: Date.now(), env: process.env.NODE_ENV || "production" }));

// EXTENSIONS hook
const EXTENSIONS = new Map();
function registerExtension(name, fn){ if(typeof fn !== "function") throw new Error("extension must be function"); EXTENSIONS.set(name, fn); }
async function runExtensions(html, context = {}){ let out = html; for(const [name,fn] of EXTENSIONS.entries()){ try{ out = await fn(out, context) || out; }catch(e){ console.error(`extension ${name} failed`, e); } } return out; }
// sample extension
registerExtension("bannerInject", (html) => {
  if(!html.includes("<body")) return html;
  const banner = `<div style="position:fixed;top:0;width:100%;background:#222;color:#fff;text-align:center;z-index:9999;font-family:sans-serif;padding:4px 0;font-size:12px;">Euphoria Proxy Active</div>`;
  return html.replace(/<body([^>]*)>/i, (m)=> m + banner);
});
app.get("/_euph_debug/extensions", requireAdmin, (req,res) => res.json({ extensions: Array.from(EXTENSIONS.keys()) }));

// Service worker patch helper (best-effort)
function patchServiceWorker(source, baseUrl, req){
  try{
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m,args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(item => {
          if(typeof item === 'string'){ const abs = new URL(item, baseUrl).href; return `'${makeProxyUrlFor(req, abs)}'`; }
          return JSON.stringify(item);
        });
        return `importScripts(${out.join(',')})`;
      }catch(e){ return m; }
    });
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = new URL(u, baseUrl).href;
        return `fetch('${makeProxyUrlFor(req,abs)}'`;
      }catch(e){ return m; }
    });
    return s;
  }catch(e){ return source; }
}

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