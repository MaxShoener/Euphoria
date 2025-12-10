// server.js — EUPHORIA C / Auto-proxy (no iframe)
// Node 18+ required (global fetch available). Uses cheerio for HTML parsing.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import cheerio from "cheerio";
import { WebSocketServer } from "ws";
import cookie from "cookie";
import os from "os";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- CONFIG ----------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6;
const ASSET_CACHE_MAX = 256 * 1024;
const FETCH_TIMEOUT = 30000;
const SESSION_NAME = "euphoria_sid";
const USER_AGENT_FALLBACK = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";

if(ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

// asset extensions treated as binary
const ASSET_EXTENSIONS = [".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",".svg",".ico",".ttf",".woff",".woff2",".eot",".mp4",".webm",".mp3",".json",".map"];
const SPECIAL_FILES = ["service-worker.js","sw.js","worker.js","manifest.json"];

// headers to drop (CSP etc.)
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// ---------------- APP ----------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---------------- CACHE ----------------
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
        if((now() - obj.t) < CACHE_TTL) { MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
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

// ---------------- SESSIONS ----------------
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), ua: USER_AGENT_FALLBACK, last: now() }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header=""){ const out={}; header.split(";").forEach(p=>{ const [k,v] = (p||"").split("=").map(s => (s||"").trim()); if(k && v) out[k] = v; }); return out; }
function getSessionFromReq(req){ const parsed = parseCookies(req.headers.cookie || ""); let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"]; if(!sid || !SESSIONS.has(sid)) return createSession(); const payload = SESSIONS.get(sid); payload.last = now(); return { sid, payload }; }
function setSessionCookie(res, sid){ const str = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`; const prev = res.getHeader("Set-Cookie"); if(!prev) res.setHeader("Set-Cookie", str); else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, str]); else res.setHeader("Set-Cookie", [prev, str]); }
function storeSetCookie(setCookies=[], sessionPayload){ for(const sc of setCookies){ try{ const kv = sc.split(";")[0]; const idx = kv.indexOf("="); if(idx === -1) continue; const k = kv.slice(0, idx).trim(); const v = kv.slice(idx+1).trim(); if(k) sessionPayload.cookies.set(k, v); } catch(e){} } }
function buildCookieHeader(map){ return [...map.entries()].map(([k,v]) => `${k}=${v}`).join("; "); }

// periodic cleanup
setInterval(()=>{ const cutoff = now() - (1000*60*60*24); for(const [k,p] of SESSIONS.entries()) if(p.last < cutoff) SESSIONS.delete(k); }, 1000*60*30);

// ---------------- HELPERS ----------------
function isAlreadyProxied(href){
  if(!href) return false;
  try {
    if(href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if(resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch(e){}
  return false;
}
function toAbsolute(href, base){ try { return new URL(href, base).href; } catch(e){ return null; } }
function proxyLink(abs){ try{ const u = new URL(abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; } catch(e){ try{ const u2 = new URL("https://" + abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch(e2){ return abs; } } }
function looksLikeAsset(u){
  if(!u) return false;
  try {
    const p = new URL(u, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(p.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(p.endsWith(s)) return true;
    return false;
  } catch(e){
    const low = u.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(low.endsWith(ext)) return true;
    for(const s of SPECIAL_FILES) if(low.endsWith(s)) return true;
    return false;
  }
}
function sanitize(html){ try{ html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, ""); html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, ""); html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, ""); }catch(e){} return html; }

// ---------------- INJECTION SNIPPET (client sandbox) ----------------
function clientSandboxSnippet(){
  return `
<!-- EUPHORIA-SANDBOX -->
<script id="__EUPHORIA_SANDBOX">
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; if(/^data:/i.test(u)) return u; return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href); }catch(e){return u;} }
  // fetch
  (function(){
    const orig = window.fetch.bind(window);
    window.fetch = function(resource, init){
      try{
        if(typeof resource === 'string' && !resource.includes('/proxy?url=') && !/^data:/i.test(resource)) resource = prox(resource);
        else if(resource instanceof Request && !resource.url.includes('/proxy?url=')) resource = new Request(prox(resource.url), resource);
      }catch(e){}
      return orig(resource, init);
    };
  })();
  // XHR
  (function(){
    try{
      const Orig = window.XMLHttpRequest;
      window.XMLHttpRequest = function(){
        const xhr = new Orig();
        const open = xhr.open;
        xhr.open = function(method, url, ...rest){
          try{ if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)) url = prox(url); }catch(e){}
          return open.call(this, method, url, ...rest);
        };
        return xhr;
      };
    }catch(e){}
  })();
  // WebSocket
  (function(){
    try{
      const Orig = window.WebSocket;
      window.WebSocket = function(url, protocol){
        try{ if(url && !url.includes('/proxy?url=')) url = DEPLOY + '/_wsproxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href); }catch(e){}
        return new Orig(url, protocol);
      };
    }catch(e){}
  })();
  // window.open
  (function(){
    const origOpen = window.open.bind(window);
    window.open = function(url, name, specs){
      try{ if(url && !url.includes('/proxy?url=') && !/^(data:|javascript:)/i.test(url)) url = prox(url); }catch(e){}
      return origOpen(url, name, specs);
    };
  })();
  // service worker register
  (function(){
    try{
      if(navigator && navigator.serviceWorker && navigator.serviceWorker.register){
        const origRegister = navigator.serviceWorker.register.bind(navigator.serviceWorker);
        navigator.serviceWorker.register = function(scriptURL, options){
          try{ if(scriptURL && !scriptURL.includes('/proxy?url=')) scriptURL = prox(scriptURL); }catch(e){}
          return origRegister(scriptURL, options);
        };
      }
    }catch(e){}
  })();
  // rewrite anchors and assets dynamically
  (function(){
    function rewriteAnchor(a){
      try{
        const h = a.getAttribute('href'); if(!h) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return;
        if(h.includes('/proxy?url=')) return;
        a.setAttribute('href', prox(h));
        a.removeAttribute('target');
      }catch(e){}
    }
    function rewriteAsset(el){
      try{
        ['src','href','poster','data-src','data-href'].forEach(attr=>{
          if(el.hasAttribute && el.hasAttribute(attr)){
            const v = el.getAttribute(attr); if(!v) return;
            if(/^data:/i.test(v) || v.includes('/proxy?url=')) return;
            el.setAttribute(attr, prox(v));
          }
        });
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u, rest] = p.trim().split(/\\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u) || u.includes('/proxy?url=')) return p;
            return prox(u) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }
      }catch(e){}
    }
    const mo = new MutationObserver(muts=>{
      muts.forEach(m=>{
        m.addedNodes.forEach(n=>{
          if(n.nodeType !== 1) return;
          if(n.matches && n.matches('a[href]')) rewriteAnchor(n);
          n.querySelectorAll && n.querySelectorAll('a[href]').forEach(rewriteAnchor);
          ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
            if(n.matches && n.matches(tag+'[src]')) rewriteAsset(n);
            n.querySelectorAll && n.querySelectorAll(tag+'[src]').forEach(rewriteAsset);
            if(n.matches && n.matches(tag+'[href]')) rewriteAsset(n);
            n.querySelectorAll && n.querySelectorAll(tag+'[href]').forEach(rewriteAsset);
          });
          n.querySelectorAll && n.querySelectorAll('[srcset]').forEach(el=>{
            rewriteAsset(el);
          });
        });
      });
    });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });
    // initial
    document.querySelectorAll('a[href]').forEach(rewriteAnchor);
    document.querySelectorAll('img,script,link,source,video,audio,iframe').forEach(rewriteAsset);
  })();
})();
</script>
<!-- END EUPHORIA-SANDBOX -->
`;
}

// ---------------- WS PROXY (upgrade) ----------------
import http from "http";
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => { ws.send(JSON.stringify({ msg: "welcome", ts: Date.now(), host: os.hostname() })); ws.on("message", m=>{ try{ const d = JSON.parse(m.toString()); if(d && d.cmd==='ping') ws.send(JSON.stringify({ msg:'pong', ts:Date.now() })); }catch(e){} }); });

import { createProxyServer } from "http-proxy";
const wsProxy = createProxyServer({ ws: true, secure: false, xfwd: true });
wsProxy.on("error", (err, req, res)=>{ try{ if(res && !res.headersSent) res.writeHead(502); if(res && res.end) res.end("WS proxy error"); }catch(e){} });

// accept upgrade: route to _wsproxy?url=
server.on('upgrade', (req, socket, head) => {
  try {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    if(urlObj.pathname === '/_wsproxy'){
      const target = urlObj.searchParams.get('url');
      if(!target){ socket.destroy(); return; }
      wsProxy.ws(req, socket, head, { target });
    }
  } catch(e){ socket.destroy(); }
});

// ---------------- AUTO-PROXY ROUTE (support /host.tld as shorthand) ----------------
app.use((req, res, next) => {
  // if path looks like /example.com or /www.example.com, redirect to /proxy?url=https://...
  const p = (req.path || '').replace(/^\//,'');
  if(p && !p.includes('proxy') && req.method === 'GET' && /^[\w.-]+\.[a-z]{2,}/i.test(p) && !req.path.includes('.')) {
    // ignore static file paths (public/)
  }
  // If the client requested root with a single segment that looks like hostname, rewrite
  const segments = req.path.split('/').filter(Boolean);
  if(segments.length === 1 && /^[\w.-]+\.[a-z]{2,}$/i.test(segments[0])){
    const host = segments[0];
    const url = 'https://' + host;
    // rewrite to /proxy?url=...
    req.url = '/proxy?url=' + encodeURIComponent(url) + (req.url.includes('?') ? '&' + req.url.split('?')[1] : '');
  }
  next();
});

// ---------------- MAIN /proxy HANDLER ----------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url || null;
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  try{ raw = decodeURIComponent(raw); } catch(e){}
  if(!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;

  const session = getSessionFromReq(req);
  try{ setSessionCookie(res, session.sid); } catch(e){}

  // choose accept
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.query.force_html === '1' || req.headers['x-euphoria-client'] === 'c-autoproxy';
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // quick asset cache
  if(!wantHtml){
    const cached = cacheGet(assetKey);
    if(cached){ if(cached.headers) Object.entries(cached.headers).forEach(([k,v])=>res.setHeader(k,v)); return res.send(Buffer.from(cached.body, "base64")); }
  } else {
    const cachedHtml = cacheGet(htmlKey);
    if(cachedHtml){ res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // build headers for upstream request
  const originHeaders = {
    "User-Agent": session.payload.ua || (req.headers['user-agent'] || USER_AGENT_FALLBACK),
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if(req.headers.referer) originHeaders["Referer"] = req.headers.referer;
  try { originHeaders["Origin"] = new URL(raw).origin; } catch(e){}

  // fetch upstream (manual redirect handling to rewrite Location)
  let originRes;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(()=>controller.abort(), FETCH_TIMEOUT);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);
  } catch(err){
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // collect set-cookie
  try { const setCookies = originRes.headers.raw ? (originRes.headers.raw()['set-cookie'] || []) : []; if(setCookies.length) storeSetCookie(setCookies, session.payload); } catch(e){}

  // handle redirects: rewrite Location to our /proxy?url=...
  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      const abs = toAbsolute(loc, raw) || loc;
      const prox = proxyLink(abs);
      try{ res.setHeader("Location", prox); setSessionCookie(res, session.sid); } catch(e){}
      return res.status(status).send(`Redirecting to ${prox}`);
    }
  }

  const contentType = (originRes.headers.get("content-type")||"").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;

  // stream asset
  if(treatAsAsset){
    try{ originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) }catch(e){} }); } catch(e){}
    try{ setSessionCookie(res, session.sid); } catch(e){}
    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if(buf.length < ASSET_CACHE_MAX){
        try{ cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch(e){}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch(err){
      try { originRes.body.pipe(res); return; } catch(e){ return res.status(502).send("Euphoria: asset streaming failed"); }
    }
  }

  // HTML path
  let html;
  try { html = await originRes.text(); } catch(e){ return res.status(502).send("Euphoria: failed to read HTML"); }
  html = sanitize(html);

  // parse & rewrite with cheerio
  try {
    const $ = cheerio.load(html, { decodeEntities: false });

    // insert base tag if missing
    if($('base').length === 0){
      const baseHref = originRes.url || raw;
      $('head').prepend(`<base href="${baseHref}">`);
    }

    // remove CSP meta tags
    $('meta[http-equiv]').each((i,el)=>{ try{ const eq = ($(el).attr('http-equiv')||'').toLowerCase(); if(eq === 'content-security-policy') $(el).remove(); }catch(e){} });

    // remove integrity/crossorigin attributes
    $('[integrity]').each((i,el)=> $(el).removeAttr('integrity'));
    $('[crossorigin]').each((i,el)=> $(el).removeAttr('crossorigin'));

    // rewrite anchors
    $('a[href]').each((i,el)=>{
      try {
        const href = $(el).attr('href') || '';
        if(!href) return;
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(isAlreadyProxied(href)) return;
        const abs = toAbsolute(href, originRes.url || raw) || href;
        $(el).attr('href', proxyLink(abs));
        $(el).removeAttr('target');
      } catch(e){}
    });

    // rewrite form actions
    $('form[action]').each((i,el)=>{
      try {
        const act = $(el).attr('action') || '';
        if(!act) return;
        if(isAlreadyProxied(act)) return;
        const abs = toAbsolute(act, originRes.url || raw) || act;
        $(el).attr('action', proxyLink(abs));
      } catch(e){}
    });

    // rewrite src/href for common tags
    const assetTags = ['img','script','link','source','video','audio','iframe'];
    assetTags.forEach(tag => {
      $(tag + '[src]').each((i,el)=>{
        try{
          const val = $(el).attr('src') || '';
          if(!val) return;
          if(/^data:/i.test(val)) return;
          if(isAlreadyProxied(val)) return;
          const abs = toAbsolute(val, originRes.url || raw) || val;
          $(el).attr('src', proxyLink(abs));
          $(el).removeAttr('integrity'); $(el).removeAttr('crossorigin');
        }catch(e){}
      });
      $(tag + '[href]').each((i,el)=>{
        try{
          const val = $(el).attr('href') || '';
          if(!val) return;
          if(/^data:/i.test(val)) return;
          if(isAlreadyProxied(val)) return;
          const abs = toAbsolute(val, originRes.url || raw) || val;
          $(el).attr('href', proxyLink(abs));
          $(el).removeAttr('integrity'); $(el).removeAttr('crossorigin');
        }catch(e){}
      });
    });

    // rewrite srcset attributes
    $('[srcset]').each((i,el)=>{
      try{
        const ss = $(el).attr('srcset') || '';
        const parts = ss.split(',').map(p=>{
          const [u, rest] = p.trim().split(/\s+/,2);
          if(!u) return p;
          if(/^data:/i.test(u)) return p;
          if(isAlreadyProxied(u)) return p;
          const abs = toAbsolute(u, originRes.url || raw) || u;
          return proxyLink(abs) + (rest ? ' ' + rest : '');
        });
        $(el).attr('srcset', parts.join(', '));
      } catch(e){}
    });

    // rewrite CSS url(...) in style tags
    $('style').each((i,el)=>{
      try{
        let txt = $(el).html() || '';
        txt = txt.replace(/url\\((['"]?)(.*?)\\1\\)/gi, (m, q, p) => {
          if(!p) return m;
          if(/^data:/i.test(p)) return m;
          if(isAlreadyProxied(p)) return m;
          const abs = toAbsolute(p, originRes.url || raw) || p;
          return 'url("' + proxyLink(abs) + '")';
        });
        $(el).text(txt);
      }catch(e){}
    });

    // rewrite inline style attributes
    $('[style]').each((i,el)=>{
      try{
        let s = $(el).attr('style') || '';
        s = s.replace(/url\\((['"]?)(.*?)\\1\\)/gi, (m,q,u)=>{
          if(!u) return m;
          if(/^data:/i.test(u)) return m;
          if(isAlreadyProxied(u)) return m;
          const abs = toAbsolute(u, originRes.url || raw) || u;
          return 'url("' + proxyLink(abs) + '")';
        });
        $(el).attr('style', s);
      } catch(e){}
    });

    // meta refresh rewrite
    $('meta[http-equiv]').each((i,el)=>{
      try {
        const eq = ($(el).attr('http-equiv')||'').toLowerCase();
        if(eq !== 'refresh') return;
        const c = $(el).attr('content') || '';
        const parts = c.split(';');
        if(parts.length < 2) return;
        const urlPart = parts.slice(1).join(';').match(/url=(.*)/i);
        if(!urlPart) return;
        const dest = urlPart[1].replace(/['"]/g,'').trim();
        const abs = toAbsolute(dest, originRes.url || raw) || dest;
        $(el).attr('content', parts[0] + ';url=' + proxyLink(abs));
      } catch(e){}
    });

    // remove common trackers (best-effort)
    $('script[src]').each((i,el) => {
      try{
        const s = ($(el).attr('src')||'').toLowerCase();
        if(/googletagmanager|googlesyndication|doubleclick|analytics|gtag/gi.test(s)) $(el).remove();
      } catch(e){}
    });

    // inject sandbox snippet just before </body>
    const injection = clientSandboxSnippet();
    $('body').append(injection);

    // final html
    html = $.html();
    // cache smaller HTML
    if(html && html.length < 512 * 1024) cacheSet(htmlKey, html);
  } catch(e){
    console.warn("cheerio transform failed", e && e.message ? e.message : e);
  }

  // set safe headers (forward upstream except DROP_HEADERS)
  try { originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookie(res, session.sid); } catch(e){}
  return res.send(html);
});

// ---------------- FALLBACK SPA ----------
app.get("/", (req,res)=> res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// ---------------- ERRORS ----------------
process.on('unhandledRejection', err => console.error('unhandledRejection', err));
process.on('uncaughtException', err => console.error('uncaughtException', err));

server.listen(PORT, ()=> console.log(`Euphoria C Auto-proxy running on port ${PORT}`));