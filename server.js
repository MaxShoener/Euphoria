// server.js
// EUPHORIA v3 — Full-featured JSDOM hybrid smart rewriter / proxy
// Node 20+ recommended
// Dependencies: express, jsdom, ws, compression, morgan, cors, cookie

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
import { setTimeout as delay } from "timers/promises";

EventEmitter.defaultMaxListeners = 200;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ------------------------ CONFIG ------------------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://your-deployment.example.com";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const FETCH_TIMEOUT_MS = 30000;
const ASSET_CACHE_THRESHOLD = 256 * 1024; // 256KB
const USER_AGENT_DEFAULT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// ------------------------ ASSET CONFIG ------------------------
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

// ------------------------ MEMORY + DISK CACHE ------------------------
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheKey(s) { return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const e = MEM_CACHE.get(key);
  if(e && (now() - e.t) < CACHE_TTL) return e.v;
  if(ENABLE_DISK_CACHE){
    try {
      const fname = path.join(CACHE_DIR, cacheKey(key));
      if(fs.existsSync(fname)){
        const raw = fs.readFileSync(fname, "utf8");
        const obj = JSON.parse(raw);
        if((now() - obj.t) < CACHE_TTL){ MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
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

// ------------------------ SESSIONS ------------------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header=""){ const out = {}; header.split(";").forEach(p=>{ const [k,v] = (p||"").split("=").map(s=> (s||"").trim()); if(k && v) out[k]=v; }); return out; }
function getSessionFromReq(req){
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid); payload.last = now(); return { sid, payload };
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
setInterval(()=>{ const cutoff = Date.now() - (1000*60*60*24); for(const [k,p] of SESSIONS.entries()) if(p.last < cutoff) SESSIONS.delete(k); }, 1000*60*30);

// ------------------------ HELPERS ------------------------
function isAlreadyProxiedHref(href){
  if(!href) return false;
  try{
    if(href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if(resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch(e){}
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
    if(!document.querySelector('base')){
      const head = document.querySelector('head');
      if(head) { const b = document.createElement('base'); b.setAttribute('href', baseUrl); head.insertBefore(b, head.firstChild); }
    }
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

    const assetTags = ['img','script','link','iframe','source','video','audio'];
    assetTags.forEach(tag => {
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
      } catch(e){}
    });

    const noscripts = Array.from(document.getElementsByTagName('noscript'));
    noscripts.forEach(n => { try { n.parentNode && n.parentNode.removeChild(n); } catch(e){} });

    return dom.serialize();
  } catch(err){
    console.warn("jsdom transform failed", err && err.message ? err.message : err);
    return html;
  }
}

// Inline JS rewrite
function rewriteInlineJs(source, baseUrl){
  try{
    source = source.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u) => {
      try{ if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m; const abs = toAbsolute(u, baseUrl) || u; return `fetch('${proxyizeAbsoluteUrl(abs)}'`; } catch(e){ return m; }
    });
    source = source.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m,p1,method,p3,u)=>{ try{ if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m; const abs = toAbsolute(u, baseUrl) || u; return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs)}'`; } catch(e){ return m; } });
    source = source.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m,q,u)=>{ try{ if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m; const abs = toAbsolute(u, baseUrl) || u; return `'${proxyizeAbsoluteUrl(abs)}'`; } catch(e){ return m; } });
    return source;
  } catch(e){ return source; }
}

// Service Worker patch
function patchServiceWorker(source, baseUrl){
  try{
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m, args)=>{
      try{
        const arr = eval("[" + args + "]");
        const out = arr.map(item => { if(typeof item === 'string'){ const abs = toAbsolute(item, baseUrl) || item; return `'${proxyizeAbsoluteUrl(abs)}'`; } return JSON.stringify(item); });
        return `importScripts(${out.join(',')})`;
      } catch(e){ return m; }
    });
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m,q,u)=>{ try{ if(u.includes('/proxy?url=') || /^data:/i.test(u)) return m; const abs = toAbsolute(u, baseUrl) || u; return `fetch('${proxyizeAbsoluteUrl(abs)}'`; } catch(e){ return m; } });
    return s;
  } catch(e){ return source; }
}

// ------------------------ WEBSOCKET TELEMETRY ------------------------
const server = app.listen(PORT, () => console.log(`Euphoria v3 running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws=>{
  ws.send(JSON.stringify({ msg:"welcome", ts: Date.now() }));
  ws.on("message", raw => { try { const parsed = JSON.parse(raw.toString()); if(parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg:'pong', ts: Date.now() })); } catch(e){} });
});

// ------------------------ PROXY ENDPOINT ------------------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}

  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'b1' || req.query.force_html === '1';
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

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

  const originHeaders = { "User-Agent": session.payload.ua || (req.headers['user-agent'] || USER_AGENT_DEFAULT), "Accept": req.headers.accept || "*/*", "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br" };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if(req.headers.referer) originHeaders["Referer"] = req.headers.referer;
  try { originHeaders["Origin"] = new URL(raw).origin; } catch(e){}

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

  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch(e){}

  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){ let abs; try{ abs = new URL(loc, raw).href; } catch(e){ abs = loc; } const proxied = proxyizeAbsoluteUrl(abs); try { res.setHeader("Location", proxied); setSessionCookieHeader(res, session.sid); } catch(e){} return res.status(status).send(`Redirecting to ${proxied}`); }
  }

  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;

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

  let htmlText;
  try { htmlText = await originRes.text(); } catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }

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

  try {
    const dom2 = new JSDOM(transformed, { url: originRes.url || raw });
    const document2 = dom2.window.document;
    const scripts = Array.from(document2.querySelectorAll('script'));
    for(const s of scripts){
      try {
        const src = s.getAttribute('src');
        if(src) continue;
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

  try{ originRes.headers.forEach((v,k) => { if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}
  try{ if(transformed && transformed.length < 512 * 1024) cacheSet(htmlKey, transformed); } catch(e){}
  return res.send(transformed);
});

// ------------------------ SPA / FALLBACK ------------------------
app.get("/", (req,res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// ------------------------ ERRORS ------------------------
process.on("unhandledRejection", err => console.error("unhandledRejection", err));
process.on("uncaughtException", err => console.error("uncaughtException", err));