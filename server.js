// server.js — Euphoria v3 (chunk 1 of N)
// Minimal inline comments. Node 20+ (ESM).

import express from 'express';
import compression from 'compression';
import morgan from 'morgan';
import cors from 'cors';
import fs from 'fs';
import fsPromises from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { JSDOM } from 'jsdom';
import { WebSocketServer, WebSocket } from 'ws';
import { EventEmitter } from 'events';
import rateLimit from 'express-rate-limit';
import { LRUCache } from 'lru-cache';
import http from 'http';
import https from 'https';
import { pipeline } from 'stream';
import { promisify } from 'util';

const pipe = promisify(pipeline);
EventEmitter.defaultMaxListeners = 300;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// CONFIG - prefer explicit PUBLIC_ORIGIN env; fallback to heuristic
const PUBLIC_ORIGIN = (process.env.DEPLOYMENT_ORIGIN || process.env.PUBLIC_ORIGIN || '').trim();
const PORT = parseInt(process.env.PORT || '3000', 10);
const CACHE_DIR = path.join(__dirname, 'cache');
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== 'false';
const CACHE_TTL = parseInt(process.env.CACHE_TTL_MS || String(1000 * 60 * 6), 10);
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || String(30000), 10);
const ASSET_CACHE_THRESHOLD = parseInt(process.env.ASSET_CACHE_THRESHOLD || String(256 * 1024), 10);
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ENTRIES = parseInt(process.env.MAX_MEMORY_CACHE_ENTRIES || '2048', 10);
const PER_HOST_CACHE_CONTROLS = {}; // can be populated dynamically via admin

if (ENABLE_DISK_CACHE) {
  await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// helpful sets
const ASSET_EXTENSIONS = new Set([
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",
  ".ttf",".otf",".woff",".woff2",".eot",".json",".map",".mp4",".webm",".mp3"
]);
const SPECIAL_FILES = new Set(["service-worker.js","sw.js","worker.js","manifest.json"]);
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// express
const app = express();
app.set('trust proxy', true);
app.use(cors({ origin: true, credentials: true }));
app.use(morgan(process.env.MORGAN_FORMAT || 'tiny'));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// global rate limiter
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_WINDOW_MS || String(15 * 60 * 1000), 10),
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || '1200', 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down."
});
app.use(globalLimiter);

// memory LRU cache
const MEM_CACHE = new LRUCache({
  maxSize: MAX_MEMORY_CACHE_ENTRIES,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) => {
    try {
      if (typeof val === 'string') return Buffer.byteLength(val, 'utf8');
      return Buffer.byteLength(JSON.stringify(val), 'utf8');
    } catch (e) {
      return 1;
    }
  }
});

// disk cache helpers
const now = () => Date.now();
const cacheKey = (s) => {
  // safe filename
  const b = Buffer.from(String(s));
  return b.toString('base64url');
};
async function diskGet(key){
  if(!ENABLE_DISK_CACHE) return null;
  try{
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname, 'utf8');
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
    await fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), 'utf8').catch(()=>{});
  }catch(e){}
}

// SESSIONS
const SESSION_NAME = 'euphoria_sid';
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT, ip: null }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header=""){ const out = {}; header.split(';').forEach(p=>{ const [k,v] = (p||'').split('=').map(s=> (s||'').trim()); if(k) out[k]=v; }); return out; }
function getSessionFromReq(req){
  const parsed = parseCookies(req.headers.cookie || '');
  let sid = parsed[SESSION_NAME] || req.headers['x-euphoria-session'];
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
  const prev = res.getHeader('Set-Cookie');
  if(!prev) res.setHeader('Set-Cookie', cookieStr);
  else if(Array.isArray(prev)) res.setHeader('Set-Cookie', [...prev, cookieStr]);
  else res.setHeader('Set-Cookie', [prev, cookieStr]);
}
function storeSetCookieToSession(setCookies = [], sessionPayload){
  for(const sc of setCookies){
    try{
      const kv = sc.split(';')[0];
      const idx = kv.indexOf('=');
      if(idx === -1) continue;
      const k = kv.slice(0, idx).trim(); const v = kv.slice(idx+1).trim();
      if(k) sessionPayload.cookies.set(k, v);
    }catch(e){}
  }
}
function buildCookieHeader(map){
  return [...map.entries()].map(([k,v])=> `${k}=${v}`).join('; ');
}
setInterval(()=>{
  const cutoff = Date.now() - (1000 * 60 * 60 * 24);
  for(const [sid, p] of SESSIONS.entries()){
    if(p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 30);

// HOOK: ip rotation provider placeholder
async function ipRotationHook(host){
  if(typeof process.env.IP_ROTATION_PROVIDER_URL === 'string' && process.env.IP_ROTATION_PROVIDER_URL.length){
    try{
      // implement real provider integration here
      return null;
    }catch(e){}
  }
  return null;
}

// HELPERS & REWRITES
function isAlreadyProxiedHref(href, deploymentOrigin){
  if(!href) return false;
  try{
    if(href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, deploymentOrigin || PUBLIC_ORIGIN || 'http://localhost');
    if((PUBLIC_ORIGIN && resolved.origin === PUBLIC_ORIGIN) || (deploymentOrigin && resolved.origin === deploymentOrigin)){
      if(resolved.pathname.startsWith('/proxy')) return true;
    }
  }catch(e){}
  return false;
}
function toAbsolute(href, base){
  try{ return new URL(href, base).href; } catch(e){ return null; }
}
function computeDeploymentOriginForReq(req){
  // prefer explicit PUBLIC_ORIGIN env; otherwise derive from incoming Host + protocol
  if(PUBLIC_ORIGIN) return PUBLIC_ORIGIN;
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  const host = req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}
function proxyizeAbsoluteUrl(abs, req){
  // when inside a request, prefer request-derived origin, else PUBLIC_ORIGIN, else fallback to localhost
  const base = req ? computeDeploymentOriginForReq(req) : (PUBLIC_ORIGIN || `http://localhost:${PORT}`);
  try{
    const u = new URL(abs);
    return base.replace(/\/$/,'') + '/proxy?url=' + encodeURIComponent(u.href);
  }catch(e){
    try{
      const u2 = new URL('https://' + abs);
      return base.replace(/\/$/,'') + '/proxy?url=' + encodeURIComponent(u2.href);
    }catch(e){
      return abs;
    }
  }
}
function looksLikeAsset(urlStr){
  if(!urlStr) return false;
  try{
    const p = new URL(urlStr, 'http://localhost').pathname.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(p.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(p.endsWith(s)) return true;
    return false;
  }catch(e){
    const lower = (urlStr || '').toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(lower.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(lower.endsWith(s)) return true;
    return false;
  }
}
function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, '');
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, '');
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, '');
  }catch(e){}
  return html;
}

// JSDOM transform (rewrites to proxyized URLs). Note: pass req to proxyizeAbsoluteUrl so host origin is correct.
function jsdomTransform(html, baseUrl, req){
  try{
    const dom = new JSDOM(html, { url: baseUrl, contentType: 'text/html' });
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
        if(isAlreadyProxiedHref(href, computeDeploymentOriginForReq(req))) return;
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
        if(isAlreadyProxiedHref(act, computeDeploymentOriginForReq(req))) return;
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
          if(isAlreadyProxiedHref(v, computeDeploymentOriginForReq(req))) return;
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
          if(isAlreadyProxiedHref(u, computeDeploymentOriginForReq(req))) return p;
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
          if(isAlreadyProxiedHref(u, computeDeploymentOriginForReq(req))) return m;
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
          if(isAlreadyProxiedHref(u, computeDeploymentOriginForReq(req))) return m;
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
    console.warn('jsdom transform failed', err && err.message ? err.message : err);
    return html;
  }
}

// inline JS rewrites (client-side fetch/XHR rewriting). Accept req to build correct proxied URLs.
function rewriteInlineJs(source, baseUrl, req){
  try{
    source = source.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    source = source.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    source = source.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `'${proxyizeAbsoluteUrl(abs, req)}'`;
      }catch(e){ return m; }
    });
    return source;
  }catch(e){ return source; }
}

// patch service-worker sources to import proxied paths
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

// AGENTS
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

// upstream fetch wrapper (uses global fetch). Supports optional ip rotation hook.
async function upstreamFetch(url, opts = {}, useRotation = false){
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
  let fetchOpts = { ...opts, signal: controller.signal, redirect: 'manual' };
  if(!fetchOpts.headers) fetchOpts.headers = {};
  fetchOpts.headers['user-agent'] = fetchOpts.headers['user-agent'] || USER_AGENT_DEFAULT;
  // prefer explicit accept-encoding, but leave to node fetch to handle decompressing
  if(!fetchOpts.headers['accept']) fetchOpts.headers['accept'] = '*/*';
  if(isHttps) fetchOpts.agent = httpsAgent; else fetchOpts.agent = httpAgent;

  try{
    const rotated = useRotation ? await ipRotationHook(u.hostname) : null;
    if(rotated && rotated.proxy && rotated.proxy.href){
      // hook point where an upstream proxy could be used (left as integration point)
    }
    const res = await fetch(url, fetchOpts);
    clearTimeout(timeout);
    return res;
  }catch(err){
    clearTimeout(timeout);
    throw err;
  }
}

function forwardHeaders(originHeaders, res, req) {
  try {
    for (const [k, v] of originHeaders.entries()) {
      const kl = k.toLowerCase();
      if (DROP_HEADERS.has(kl)) continue;
      if (kl === 'content-length') {
        // we'll let Node set content-length after streaming if appropriate
        try { res.setHeader('Content-Length', v); } catch(e){}
        continue;
      }
      if (kl === 'location') {
        // rewrite Location to proxied url that points back to this deployment
        try {
          const abs = new URL(v, req.origTarget || computeDeploymentOriginForReq(req)).href;
          res.setHeader('Location', proxyizeAbsoluteUrl(abs, req));
        } catch(e){
          // fallback: send through as-is
          try{ res.setHeader('Location', v); }catch(e){}
        }
        continue;
      }
      // copy everything else
      try { res.setHeader(k, v); } catch(e){}
    }
  } catch (err) {
    // ignore
  }
}

// robust streaming of binary assets
async function streamOriginToRes(originRes, res, req) {
  try {
    // forward some headers first (content-type, cache-control etc)
    const ct = originRes.headers.get('content-type');
    if (ct) res.setHeader('Content-Type', ct);
    const cc = originRes.headers.get('cache-control');
    if (cc) res.setHeader('Cache-Control', cc);
    const etag = originRes.headers.get('etag');
    if (etag) res.setHeader('ETag', etag);
    // forward rest, with Location rewrite
    forwardHeaders(originRes.headers, res, req);
    // prefer streaming body when available
    if (originRes.body && typeof originRes.body.pipe === 'function') {
      // originRes is a Node stream-like; pipe directly
      originRes.body.pipe(res);
    } else {
      // fallback read as arrayBuffer
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      res.setHeader('Content-Length', buf.length);
      return res.send(buf);
    }
  } catch (err) {
    // fallback: try to read as arrayBuffer
    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      res.setHeader('Content-Length', buf.length);
      return res.send(buf);
    } catch (e) {
      return res.status(502).send('Euphoria: asset stream failed');
    }
  }
}

// Accept /proxy?url=... OR /proxy//host/path (double-slash) OR /proxy/:host/*
// Also support legacy /proxy/:host:port/... if user used that pattern.
app.get(['/proxy', '/proxy/*'], async (req, res) => {
  // resolve incoming target from query, path (/proxy//host/...), or /proxy/host/...
  let raw = req.query.url || null;
  if (!raw) {
    // path after /proxy
    const tail = (req.path || '').replace(/^\/proxy\/?/, '') || '';
    // handle double-slash pattern: /proxy//example.com/path -> leading '' in tail when split, so tail may start with '/'
    if (req.path.startsWith('/proxy//')) {
      // remove leading slash to get //host/path -> then strip the leading '/' to produce /host/path
      const after = req.path.replace(/^\/proxy/, '');
      // after starts with //host/..., drop leading slash to get /host/...
      raw = after.slice(1);
    } else if (tail) {
      // treat 'host/path' or encoded path
      // if tail looks like host with domain (has dot) or contains ':' treat as host/path form
      const candidate = decodeURIComponent(tail);
      if (/^[^\/]+\.[^\/]+/.test(candidate) || /^[^\/]+:\d+/.test(candidate)) {
        // ensure protocol
        if (!/^https?:\/\//i.test(candidate)) raw = 'https://' + candidate;
        else raw = candidate;
      } else {
        // final fallback: build origin + tail if referer passed
        raw = candidate;
      }
    }
  }

  if (!raw) {
    return res.status(400).send('Missing url (use /proxy?url=https://example.com or /proxy//host/path)');
  }

  // if missing scheme, assume https
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;

  // keep for rewrite heuristics
  req.origTarget = raw;

  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}

  // Choose how to treat response (html vs asset)
  const wantHtml = (req.query.force_html === '1') || (req.headers['x-euphoria-client'] === 'bc-hybrid');

  const assetKey = raw + '::asset';
  const htmlKey = raw + '::html';
  const host = (() => { try{ return new URL(raw).hostname }catch(e){return null;} })();
  const hostCacheCfg = PER_HOST_CACHE_CONTROLS[host] || {};

  // Serve from cache for assets
  if (!wantHtml) {
    const mem = MEM_CACHE.get(assetKey);
    if (mem) {
      // copy headers saved
      if (mem.headers) Object.entries(mem.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); }catch(e){} });
      try{ setSessionCookieHeader(res, session.sid); }catch(e){}
      return res.send(Buffer.from(mem.body, 'base64'));
    }
    const disk = await diskGet(assetKey);
    if (disk) {
      if (disk.headers) Object.entries(disk.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); }catch(e){} });
      try{ setSessionCookieHeader(res, session.sid); }catch(e){}
      return res.send(Buffer.from(disk.body, 'base64'));
    }
  } else {
    const memHtml = MEM_CACHE.get(htmlKey);
    if (memHtml) { res.setHeader('Content-Type','text/html; charset=utf-8'); return res.send(memHtml); }
    const diskHtml = await diskGet(htmlKey);
    if (diskHtml) { res.setHeader('Content-Type','text/html; charset=utf-8'); return res.send(diskHtml); }
  }

  // Build origin headers with sensible fallbacks & pass-throughs
  const originHeaders = {
    'User-Agent': session.payload.ua || req.headers['user-agent'] || USER_AGENT_DEFAULT,
    'Accept': req.headers.accept || '*/*',
    'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br'
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) originHeaders['Cookie'] = cookieHdr;
  if (req.headers.referer) originHeaders['Referer'] = req.headers.referer;
  try { originHeaders['Origin'] = new URL(raw).origin; } catch(e){}

  let originRes;
  try {
    originRes = await upstreamFetch(raw, { headers: originHeaders, redirect: 'manual' }, true);
  } catch (err) {
    // try a lighter retry (some hosts reject complex headers)
    console.warn('initial fetch failed, retrying lightweight', err && err.message ? err.message : err);
    try {
      originRes = await upstreamFetch(raw, { headers: { 'user-agent': USER_AGENT_DEFAULT, 'accept': '*/*' }, redirect: 'manual' }, false);
    } catch (err2) {
      console.error('fetch error', err2 && err2.message ? err2.message : err2);
      return res.status(502).send('Euphoria: failed to fetch target: ' + String(err2 && err2.message ? err2.message : err2));
    }
  }

  // store any Set-Cookie headers into session
  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch(e){}

  const status = originRes.status || 200;
  // Handle redirects by rewriting Location to proxied path
  if ([301,302,303,307,308].includes(status)) {
    const loc = originRes.headers.get('location');
    if (loc) {
      let abs;
      try { abs = new URL(loc, raw).href; } catch(e) { abs = loc; }
      const proxied = proxyizeAbsoluteUrl(abs, req);
      try { res.setHeader('Location', proxied); setSessionCookieHeader(res, session.sid); } catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  const contentType = (originRes.headers.get('content-type') || '').toLowerCase();
  const isHtml = contentType.includes('text/html') || (req.query.force_html === '1');
  const treatAsAsset = !isHtml;

  if (treatAsAsset) {
    try { 
      // copy headers & stream body
      await streamOriginToRes(originRes, res, req);
      try{ setSessionCookieHeader(res, session.sid); }catch(e){}
      // read buffer for caching if small
      try {
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        if (hostCacheCfg.disable !== true && buf.length < ASSET_CACHE_THRESHOLD) {
          const data = { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString('base64') };
          MEM_CACHE.set(assetKey, data);
          diskSet(assetKey, data).catch(()=>{});
        }
      } catch (e) {
        // cannot cache streamed body easily; ignore
      }
      return;
    } catch (err) {
      console.error('asset streaming failed', err && err.message ? err.message : err);
      try { originRes.body && originRes.body.pipe && originRes.body.pipe(res); return; } catch(e){ return res.status(502).send('Euphoria: asset stream failed'); }
    }
  }

  // HTML path: read text, sanitize, jsdom transform
  let htmlText;
  try { htmlText = await originRes.text(); } catch(e) { console.error('read html error', e); return res.status(502).send('Euphoria: failed to read HTML'); }
  htmlText = sanitizeHtml(htmlText);

  // jsdom transform requires request for correct base origin rewrite
  let transformed = jsdomTransform(htmlText, originRes.url || raw, req);

  // inject client rewrite snippet that uses computeDeploymentOriginForReq(req) — produce a runtime snippet using request origin
  const clientMarker = '/* EUPHORIA_CLIENT_REWRITE */';
  if (!transformed.includes(clientMarker)) {
    const deployOrigin = computeDeploymentOriginForReq(req);
    const clientSnippet = `
<script>
${clientMarker}
(function(){
  const DEPLOY = "${deployOrigin.replace(/"/g,'\\"')}";
  (function(){
    const origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        else if(resource instanceof Request && !resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
      }catch(e){}
      return origFetch.call(this, resource, init);
    };
    const OrigXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new OrigXHR();
      const _open = xhr.open;
      xhr.open = function(method, url, ...rest){
        try{
          if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)){
            url = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href);
          }
        }catch(e){}
        return _open.call(this, method, url, ...rest);
      };
      return xhr;
    };
  })();
})();
</script>
`;
    transformed = transformed.replace(/<\/body>/i, clientSnippet + '</body>');
  }

  // post-process inline scripts for proxying XHR/fetch inside page
  try {
    const dom2 = new JSDOM(transformed, { url: originRes.url || raw });
    const document2 = dom2.window.document;
    const scripts = Array.from(document2.querySelectorAll('script'));
    for (const s of scripts) {
      try {
        const src = s.getAttribute('src');
        if (src) continue;
        let code = s.textContent || '';
        if (!code.trim()) continue;
        const lower = code.slice(0, 400).toLowerCase();
        if (lower.includes('self.addEventListener') || lower.includes('importscripts') || lower.includes('caches.open')) {
          code = patchServiceWorker(code, originRes.url || raw, req);
        }
        code = rewriteInlineJs(code, originRes.url || raw, req);
        s.textContent = code;
      } catch(e){}
    }
    transformed = dom2.serialize();
  } catch(e) {
    console.warn('post-process inline scripts failed', e && e.message ? e.message : e);
  }

  // forward headers (drop dangerous CSP/COEP etc)
  try { originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  try{ setSessionCookieHeader(res, session.sid); }catch(e){}
  try {
    if (hostCacheCfg.disable !== true && transformed && Buffer.byteLength(transformed, 'utf8') < 512 * 1024) {
      MEM_CACHE.set(htmlKey, transformed);
      diskSet(htmlKey, transformed).catch(()=>{});
    }
  } catch(e){}

  return res.send(transformed);
});

// Fallback direct-path (same logic simplified)
app.use(async (req, res, next) => {
  const p = req.path || '/';
  if (p.startsWith('/proxy') || p.startsWith('/_euph_ws') || p.startsWith('/_wsproxy') || p.startsWith('/_euph_debug') || p.startsWith('/static') || p.startsWith('/public')) return next();
  const referer = req.headers.referer || req.headers.referrer || '';
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
    const originHeaders = { 'User-Agent': session.payload.ua || USER_AGENT_DEFAULT, 'Accept': req.headers.accept || '*/*', 'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9' };
    const cookieHdr = buildCookieHeader(session.payload.cookies);
    if (cookieHdr) originHeaders['Cookie'] = cookieHdr;
    const originRes = await upstreamFetch(attempted, { headers: originHeaders, redirect: 'manual' }, true);
    if([301,302,303,307,308].includes(originRes.status)){
      const loc = originRes.headers.get('location');
      if(loc){ const abs = new URL(loc, attempted).href; return res.redirect(proxyizeAbsoluteUrl(abs, req)); }
    }
    const ct = (originRes.headers.get('content-type') || '').toLowerCase();
    if(!ct.includes('text/html')){
      forwardHeaders(originRes.headers, res, req);
      const arr = await originRes.arrayBuffer();
      return res.send(Buffer.from(arr));
    }
    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = jsdomTransform(html, originRes.url || attempted, req);
    const final = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA FALLBACK */
(function(){ const D="${computeDeploymentOriginForReq(req)}"; (function(){ const orig = window.fetch; window.fetch = function(r,i){ try{ if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); }catch(e){} return orig.call(this,r,i); }; })(); })();
</script></body>`);
    forwardHeaders(originRes.headers, res, req);
    res.setHeader('Content-Type','text/html; charset=utf-8');
    return res.send(final);
  }catch(err){
    console.error('fallback proxy error', err && err.message ? err.message : err);
    return next();
  }
});

// SPA fallback
app.get('/', (req,res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('*', (req,res,next) => {
  if(req.method === 'GET' && req.headers.accept && req.headers.accept.includes('text/html')) return res.sendFile(path.join(__dirname,'public','index.html'));
  next();
});

// WEBSOCKET PROXY (upgrade handling) - handles /_wsproxy?url=...
function setupWsProxy(server) {
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  server.on('upgrade', async (request, socket, head) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname !== '/_wsproxy') return;
    const target = url.searchParams.get('url');
    if (!target) {
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); socket.destroy(); return;
    }
    try {
      // Accept incoming and connect to target
      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        // create outgoing and tie them together
        const outbound = new WebSocket(target);
        outbound.on('open', () => {
          ws.on('message', msg => { try{ outbound.send(msg); } catch(e){} });
          outbound.on('message', msg => { try{ ws.send(msg); } catch(e){} });
          const forwardClose = (code, reason) => {
            try{ ws.close(code, reason); } catch(e){}
            try{ outbound.close(code, reason); } catch(e){}
          };
          ws.on('close', forwardClose);
          outbound.on('close', forwardClose);
        });
        outbound.on('error', () => ws.close());
        ws.on('error', () => outbound.close());
      });
    } catch(e) {
      try{ socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); }catch(e){}
    }
  });
  return wssProxy;
}
// ensure ws proxy is attached (server defined in chunk1)
setupWsProxy(server);

// ADMIN endpoints
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || '';
function requireAdmin(req,res,next){
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === '127.0.0.1' || req.ip === '::1' || req.socket.remoteAddress === '::1')) return next();
  return res.status(403).json({ error: 'forbidden' });
}
app.get('/_euph_debug/ping', (req,res) => res.json({ msg:'pong', ts: Date.now(), host: computeDeploymentOriginForReq(req) }));
app.get('/_euph_debug/sessions', requireAdmin, (req,res) => {
  const out = {};
  for(const [sid, payload] of SESSIONS.entries()){
    out[sid] = { last: new Date(payload.last).toISOString(), ua: payload.ua, ip: payload.ip, cookies: Object.fromEntries(payload.cookies.entries()) };
  }
  res.json({ sessions: out, count: SESSIONS.size });
});
app.get('/_euph_debug/cache', requireAdmin, (req,res) => {
  const mem = {};
  MEM_CACHE.forEach((v,k)=>{ mem[k] = { size: typeof v === 'string' ? Buffer.byteLength(v,'utf8') : JSON.stringify(v).length }; });
  res.json({ memory: mem, memoryCount: MEM_CACHE.size });
});
app.post('/_euph_debug/clear_cache', requireAdmin, async (req,res) => {
  MEM_CACHE.clear();
  if (ENABLE_DISK_CACHE) {
    try{ const files = await fsPromises.readdir(CACHE_DIR); for(const f of files) await fsPromises.unlink(path.join(CACHE_DIR,f)).catch(()=>{}); }catch(e){}
  }
  res.json({ ok:true });
});
app.get('/_euph_debug/extensions', requireAdmin, (req,res) => res.json({ extensions: Array.from(EXTENSIONS.keys()) }));
