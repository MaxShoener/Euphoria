// server.js
// EUPHORIA BC-Hybrid (Option 2) — JSDOM + client sandbox runtime
// - No iframes (per user request)
// - Full redirect rewriting
// - Cookie/session persistence
// - JSDOM-based HTML transforms
// - Client-side sandbox injector for fetch/XHR/WebSocket/window.open/location/serviceWorker
// - Binary streaming for assets, cache small assets, progressive HTML handling
// - WebSocket telemetry and WS proxy endpoint for proxied websocket connections

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
import os from "os";
import fetch from "node-fetch"; // node-fetch v3.x ESM
EventEmitter.defaultMaxListeners = 200;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- CONFIG ----------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6;
const FETCH_TIMEOUT_MS = 30000;
const ASSET_CACHE_THRESHOLD = 256 * 1024;
const USER_AGENT_DEFAULT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";

if(ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

// Binary asset extensions
const ASSET_EXTENSIONS = [
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",
  ".ttf",".otf",".woff",".woff2",".eot",".json",".map",".mp4",".webm",".mp3"
];
const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// Headers to drop from proxied responses (CSP etc.)
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// ---------- EXPRESS SETUP ----------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---------- SIMPLE CACHE ----------
const MEM_CACHE = new Map();
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const e = MEM_CACHE.get(key);
  if(e && (now() - e.t) < CACHE_TTL) return e.v;
  if(ENABLE_DISK_CACHE){
    try {
      const f = path.join(CACHE_DIR, cacheKey(key));
      if(fs.existsSync(f)){
        const raw = fs.readFileSync(f, "utf8");
        const obj = JSON.parse(raw);
        if((now() - obj.t) < CACHE_TTL){ MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
        try{ fs.unlinkSync(f); } catch(e){}
      }
    } catch(e){}
  }
  return null;
}
function cacheSet(key, val){
  MEM_CACHE.set(key, { v: val, t: now() });
  if(ENABLE_DISK_CACHE){
    const f = path.join(CACHE_DIR, cacheKey(key));
    fsPromises.writeFile(f, JSON.stringify({ v: val, t: now() }), "utf8").catch(()=>{});
  }
}

// ---------- SESSIONS & COOKIES ----------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: Date.now(), ua: USER_AGENT_DEFAULT }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header=""){
  const out = {};
  header.split(";").forEach(p=>{
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
  payload.last = Date.now();
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
function buildCookieHeader(map){ return [...map.entries()].map(([k,v]) => `${k}=${v}`).join("; "); }

// session maintenance
setInterval(()=>{ const cutoff = now() - (1000*60*60*24); for(const [k,p] of SESSIONS.entries()) if(p.last < cutoff) SESSIONS.delete(k); }, 1000*60*30);

// ---------- HELPERS ----------
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
  try { const u = new URL(abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; }
  catch(e){ try { const u2 = new URL("https://" + abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch(e2) { return abs; } }
}
function looksLikeAsset(urlStr){
  if(!urlStr) return false;
  try {
    const p = new URL(urlStr, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for(const e of ASSET_EXTENSIONS) if(p.endsWith(e)) return true;
    for(const s of SPECIAL_FILES) if(p.endsWith(s)) return true;
    return false;
  } catch(e){
    const lower = urlStr.toLowerCase();
    for(const e of ASSET_EXTENSIONS) if(lower.endsWith(e)) return true;
    for(const s of SPECIAL_FILES) if(lower.endsWith(s)) return true;
    return false;
  }
}
function sanitizeHtml(html){
  try{
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi,'');
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi,'');
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi,'');
  } catch(e){}
  return html;
}

// ---------- Transform using JSDOM ----------
function jsdomTransform(html, baseUrl){
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;

    // ensure base
    if(!document.querySelector('base')){
      const head = document.querySelector('head');
      if(head){
        const b = document.createElement('base');
        b.setAttribute('href', baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }

    // rewrite anchors
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    anchors.forEach(a => {
      try {
        const href = a.getAttribute('href') || '';
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
    forms.forEach(f=>{
      try{
        const act = f.getAttribute('action') || '';
        if(!act) return;
        if(isAlreadyProxiedHref(act)) return;
        const abs = toAbsolute(act, baseUrl) || act;
        f.setAttribute('action', proxyizeAbsoluteUrl(abs));
      } catch(e){}
    });

    // rewrite common asset tags
    ['img','script','link','iframe','source','video','audio'].forEach(tag=>{
      const nodes = Array.from(document.getElementsByTagName(tag));
      nodes.forEach(el=>{
        try{
          const srcAttr = el.getAttribute('src') ? 'src' : (el.getAttribute('href') ? 'href' : null);
          if(!srcAttr) return;
          const val = el.getAttribute(srcAttr) || '';
          if(!val) return;
          if(/^data:/i.test(val)) return;
          if(isAlreadyProxiedHref(val)) return;
          const abs = toAbsolute(val, baseUrl) || val;
          el.setAttribute(srcAttr, proxyizeAbsoluteUrl(abs));
          // remove integrity/crossorigin
          el.removeAttribute('integrity'); el.removeAttribute('crossorigin');
        } catch(e){}
      });
    });

    // rewrite srcset
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
      } catch(e){}
    });

    // CSS url(...) rewrite in <style> and inline style attributes
    Array.from(document.querySelectorAll('style')).forEach(st=>{
      try{
        let txt = st.textContent || '';
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u) => {
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(isAlreadyProxiedHref(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyizeAbsoluteUrl(abs)}")`;
        });
        st.textContent = txt;
      } catch(e){}
    });
    Array.from(document.querySelectorAll('[style]')).forEach(el=>{
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
      } catch(e){}
    });

    // meta refresh rewrite
    Array.from(document.querySelectorAll('meta[http-equiv]')).forEach(m=>{
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
      } catch(e){}
    });

    // remove noscript - often hides content
    Array.from(document.getElementsByTagName('noscript')).forEach(n => { try { n.parentNode && n.parentNode.removeChild(n); } catch(e){} });

    return dom.serialize();
  } catch(err){
    console.warn('jsdomTransform failed', err && err.message ? err.message : err);
    return html;
  }
}

// ---------- JS inline conservative rewrites ----------
function rewriteInlineJs(source, baseUrl){
  try{
    // fetch('...') literal rewrites
    source = source.replace(/fetch\((['"`])([^'"`]+?)\1/gi, (m,q,u)=>{
      try{
        if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs)}'`;
      } catch(e){ return m; }
    });
    // XHR open('GET','...') rewrites
    source = source.replace(/open\(\s*(['"`])?(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1?\s*,\s*(['"`])([^'"`]+?)\3/gi,
      (m,p1,method,p3,u)=>{
        try{
          if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `.open('${method || 'GET'}','${proxyizeAbsoluteUrl(abs)}'`;
        } catch(e){ return m; }
    });
    // importScripts('...') (service workers)
    source = source.replace(/importScripts\(([^)]+)\)/gi, (m,args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(it=>{
          if(typeof it === 'string'){
            if(it.includes('/proxy?url=') || /^data:/i.test(it)) return JSON.stringify(it);
            const abs = toAbsolute(it, baseUrl) || it;
            return JSON.stringify(proxyizeAbsoluteUrl(abs));
          }
          return JSON.stringify(it);
        });
        return `importScripts(${out.join(',')})`;
      } catch(e){ return m; }
    });
    return source;
  } catch(e){
    return source;
  }
}

// ---------- SERVICE-WORKER patch ----------
function patchServiceWorker(source, baseUrl){
  try{
    let s = source;
    s = s.replace(/importScripts$begin:math:text$\(\[\^\)\]\+\)$end:math:text$/gi, (m,args)=>{
      try{
        const arr = eval("[" + args + "]");
        const mapped = arr.map(a=>{
          if(typeof a === 'string'){
            if(a.includes('/proxy?url=') || /^data:/i.test(a)) return a;
            return proxyizeAbsoluteUrl(toAbsolute(a, baseUrl) || a);
          }
          return a;
        });
        return `importScripts(${mapped.map(x=>JSON.stringify(x)).join(',')})`;
      } catch(e){ return m; }
    });
    s = s.replace(/fetch\((['"`])([^'"`]+?)\1/gi, (m,q,u)=>{
      try{ if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m; return `fetch('${proxyizeAbsoluteUrl(toAbsolute(u, baseUrl) || u)}'`; } catch(e){ return m; }
    });
    return s;
  } catch(e){ return source; }
}

// ---------- WEBSOCKET PROXY ROUTE (simple pass-through) ----------
/*
  The client-side sandbox rewrites new WebSocket(url) to DEPLOY/_wsproxy?url=encoded(url).
  Here we'll accept an HTTP upgrade and proxy to target ws host using ws client.
*/
import { createProxyServer } from "http-proxy";
const wsProxy = createProxyServer({ xfwd: true, secure: false, ws: true });
wsProxy.on("error", (err, req, res) => {
  try { if(res && !res.headersSent) res.writeHead(502); if(res && res.end) res.end("WS proxy error"); } catch(e){}
});

app.get('/_wsproxy', (req, res) => {
  // Respond to non-upgrade with 400
  res.status(400).send("WebSocket proxied endpoint (use WS upgrade)");
});
app.on('upgrade', (req, socket, head) => {
  // if proxied path, extract url query param and proxy websocket
  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  if(urlObj.pathname === '/_wsproxy'){
    const target = urlObj.searchParams.get('url');
    if(!target){ socket.destroy(); return; }
    try {
      // proxy upgrade to target websocket
      wsProxy.ws(req, socket, head, { target });
    } catch(e){
      socket.destroy();
    }
  }
});

// ---------- WEBSOCKET TELEMETRY (for UI) ----------
const server = app.listen(PORT, () => console.log(`Euphoria BC-Hybrid running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now(), host: os.hostname() }));
  ws.on("message", raw => {
    try {
      const d = JSON.parse(raw.toString());
      if(d && d.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch(e){}
  });
});

// ---------- MAIN PROXY HANDLER ----------
app.get("/proxy", async (req, res) => {
  // support /proxy?url=... and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//,'')) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session + cookie header early
  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}

  // accept header decide html or asset
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'bc-hybrid' || req.query.force_html === '1';
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // quick asset cache for non-html
  if(!wantHtml){
    const cached = cacheGet(assetKey);
    if(cached){
      if(cached.headers) Object.entries(cached.headers).forEach(([k,v]) => { try{ res.setHeader(k,v); }catch(e){} });
      return res.send(Buffer.from(cached.body, "base64"));
    }
  } else {
    const cachedHtml = cacheGet(htmlKey);
    if(cachedHtml){ res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // build fetch headers
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

  // fetch upstream (manual redirect handling)
  let originRes;
  try{
    const controller = new AbortController();
    const t = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(t);
  } catch(err){
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch: " + String(err));
  }

  // persist set-cookie
  try {
    const setCookies = originRes.headers.raw ? (originRes.headers.raw()['set-cookie'] || []) : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch(e){}

  // redirect handling: rewrite Location -> our /proxy?url=...
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

  // content-type detection
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;

  // assets: stream binary and cache small ones
  if(treatAsAsset){
    try{ originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}
    try{ setSessionCookieHeader(res, session.sid); } catch(e){}
    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if(buf.length < ASSET_CACHE_THRESHOLD){
        try{ cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch(e){}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch(err){
      try { originRes.body.pipe(res); return; } catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // HTML path: read + transform + inject sandbox
  let htmlText;
  try { htmlText = await originRes.text(); } catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }
  htmlText = sanitizeHtml(htmlText);

  // JSDOM transform (rewrites anchors, assets, forms, srcset, css url)
  let transformed = jsdomTransform(htmlText, originRes.url || raw);

  // Post-process inline scripts: conservative rewrites and SW patch
  try {
    const dom2 = new JSDOM(transformed, { url: originRes.url || raw });
    const document2 = dom2.window.document;
    const scripts = Array.from(document2.querySelectorAll('script'));
    for(const s of scripts){
      try {
        const src = s.getAttribute('src');
        if(src){
          // external script: server already rewrote src-> /proxy?url=...
          // remove integrity/crossorigin
          s.removeAttribute('integrity'); s.removeAttribute('crossorigin');
          continue;
        }
        let code = s.textContent || '';
        if(!code.trim()) continue;
        const lower = code.slice(0,300).toLowerCase();
        if(lower.includes('self.addEventListener') || lower.includes('importscripts') || lower.includes('caches.open') || lower.includes('serviceworker')){
          code = patchServiceWorker(code, originRes.url || raw);
        }
        code = rewriteInlineJs(code, originRes.url || raw);
        s.textContent = code;
      } catch(e){}
    }
    transformed = dom2.serialize();
  } catch(e){
    console.warn("post inline script processing failed", e && e.message ? e.message : e);
  }

  // Inject the client-side sandbox runtime (robust version) and telemetry stub if missing
  const SANDBOX_ID = "__EUPHORIA_CLIENT_SANDBOX_v2__";
  if(!transformed.includes(SANDBOX_ID)){
    const sandbox = buildClientSandboxSnippet(DEPLOYMENT_ORIGIN);
    transformed = transformed.replace(/<\/body>/i, sandbox + "</body>");
  }

  // forward safe headers (dropping CSP / frame policies)
  try{ originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}

  // cache if small
  try{ if(transformed && transformed.length < 512 * 1024) cacheSet(htmlKey, transformed); } catch(e){}

  return res.send(transformed);
});

// ---------- buildClientSandboxSnippet (large client-side sandbox runtime) ----------
function buildClientSandboxSnippet(deployOrigin){
  // This snippet is injected into every proxied HTML to provide the sandboxing and
  // network interception layer. It is intentionally thorough and conservative.
  return `
<!-- ${'__EUPHORIA_CLIENT_SANDBOX_v2__'} -->
<script id="__EUPHORIA_CLIENT_SANDBOX_v2__">
(function(){
  // EUPHORIA CLIENT SANDBOX v2
  const DEPLOY = "${deployOrigin}";
  function prox(u){
    try {
      if(!u) return u;
      if(u.includes('/proxy?url=')) return u;
      if(/^data:/i.test(u)) return u;
      return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href);
    } catch(e){ return u; }
  }

  // Replace window.fetch
  (function(){
    const origFetch = window.fetch.bind(window);
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=') && !/^data:/i.test(resource)){
          resource = prox(resource);
        } else if(resource instanceof Request){
          if(!resource.url.includes('/proxy?url=')){
            resource = new Request(prox(resource.url), { method: resource.method, headers: resource.headers, body: resource.body, mode: resource.mode, credentials: resource.credentials, cache: resource.cache });
          }
        }
      } catch(e){}
      return origFetch(resource, init);
    };
  })();

  // Replace XMLHttpRequest
  (function(){
    const OrigXHR = window.XMLHttpRequest;
    function EuphXHR(){
      const xhr = new OrigXHR();
      const origOpen = xhr.open;
      xhr.open = function(method, url, ...rest){
        try {
          if(url && !url.includes('/proxy?url=') && !/^(blob:|data:|about:|javascript:)/i.test(url)){
            url = prox(url);
          }
        } catch(e){}
        return origOpen.call(this, method, url, ...rest);
      };
      return xhr;
    }
    try { window.XMLHttpRequest = EuphXHR; } catch(e){}
  })();

  // Replace WebSocket: map to server endpoint /_wsproxy?url=
  (function(){
    try {
      const OrigWS = window.WebSocket;
      const ProxyWS = function(url, protocol){
        if(url && !url.includes('/proxy?url=')){
          try {
            const mapped = DEPLOY + '/_wsproxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href);
            return new OrigWS(mapped, protocol);
          } catch(e){}
        }
        return new OrigWS(url, protocol);
      };
      ProxyWS.prototype = OrigWS.prototype;
      window.WebSocket = ProxyWS;
    } catch(e){}
  })();

  // override window.open & location.* assign/replace
  (function(){
    const origOpen = window.open.bind(window);
    window.open = function(url, name, specs){
      try {
        if(url && !url.includes('/proxy?url=') && !/^(data:|javascript:)/i.test(url)){
          url = prox(url);
        }
      } catch(e){}
      return origOpen(url, name, specs);
    };
    try {
      const _assign = location.assign.bind(location);
      location.assign = function(u){ try{ if(u && !u.includes('/proxy?url=')) u = prox(u); }catch(e){} return _assign(u); };
      const _replace = location.replace.bind(location);
      location.replace = function(u){ try{ if(u && !u.includes('/proxy?url=')) u = prox(u); }catch(e){} return _replace(u); };
    } catch(e){}
  })();

  // intercept navigator.serviceWorker.register
  (function(){
    try {
      if(navigator && navigator.serviceWorker && navigator.serviceWorker.register){
        const origRegister = navigator.serviceWorker.register.bind(navigator.serviceWorker);
        navigator.serviceWorker.register = function(scriptURL, ...rest){
          try { if(scriptURL && !scriptURL.includes('/proxy?url=')) scriptURL = prox(scriptURL); } catch(e){}
          return origRegister(scriptURL, ...rest);
        };
      }
    } catch(e){}
  })();

  // intercept HTML forms that submit to relative/absolute URLs: rewrite them
  (function(){
    function rewriteFormAction(f){
      try {
        const a = f.getAttribute('action') || '';
        if(!a) return;
        if(a.includes('/proxy?url=')) return;
        if(/^(javascript:|#)/i.test(a)) return;
        f.setAttribute('action', prox(a));
      } catch(e){}
    }
    document.addEventListener('submit', function(ev){
      const f = ev.target;
      if(f && f.tagName && f.tagName.toLowerCase() === 'form') rewriteFormAction(f);
    }, true);
  })();

  // rewrite anchors dynamically added to DOM
  (function(){
    function rewriteAnchor(a){
      try {
        const href = a.getAttribute('href') || '';
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(href.includes('/proxy?url=')) return;
        a.setAttribute('href', prox(href));
        a.removeAttribute('target');
      } catch(e){}
    }
    const observer = new MutationObserver(muts=>{
      muts.forEach(m=>{
        m.addedNodes.forEach(node=>{
          try {
            if(node.nodeType !== 1) return;
            if(node.matches && node.matches('a[href]')) rewriteAnchor(node);
            node.querySelectorAll && node.querySelectorAll('a[href]').forEach(rewriteAnchor);
          } catch(e){}
        });
      });
    });
    observer.observe(document.documentElement || document, { childList: true, subtree: true });
    // rewrite existing
    document.querySelectorAll('a[href]').forEach(rewriteAnchor);
  })();

  // small helper to rewrite inline src/srcset on DOM mutation (images, sources)
  (function(){
    const attrs = ['src','href','poster','data-src','data-href'];
    function rewriteAsset(el){
      try {
        attrs.forEach(attr=>{
          if(!el.hasAttribute || !el.hasAttribute(attr)) return;
          const v = el.getAttribute(attr);
          if(!v) return;
          if(/^data:/i.test(v)) return;
          if(v.includes('/proxy?url=')) return;
          el.setAttribute(attr, prox(v));
        });
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return prox(u) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }
      } catch(e){}
    }
    const mo = new MutationObserver(muts=>{
      muts.forEach(m=>{
        m.addedNodes.forEach(n=>{
          if(n.nodeType !== 1) return;
          rewriteAsset(n);
          n.querySelectorAll && n.querySelectorAll('img,source,video,audio,iframe,link').forEach(rewriteAsset);
        });
      });
    });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });
    document.querySelectorAll('img,source,video,audio,iframe,link').forEach(rewriteAsset);
  })();

  // light telemetry bridge (optional)
  (function(){
    try {
      const ws = new WebSocket((location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/_euph_ws');
      ws.addEventListener('open', ()=> { /* connected */ });
      ws.addEventListener('message', (m)=>{ /* ignore */ });
      window.__EUPHORIA_WS = ws;
    } catch(e){}
  })();

  // expose helper
  window.__EUPHORIA_PROXY = { proxURL: prox, DEPLOY };
})();
</script>
<!-- end sandbox -->
`;
}

// ---------- FALLBACK SPA endpoints ----------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req, res, next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// ---------- ERROR HANDLING ----------
process.on("unhandledRejection", (err) => console.error("unhandledRejection", err));
process.on("uncaughtException", (err) => console.error("uncaughtException", err));