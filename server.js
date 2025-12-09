// server.js
// EUPHORIA v2 — HYBRID OVERKILL (A3)
// Node 20+ recommended (uses global fetch). External deps: see package.json.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { WebSocketServer } from "ws";
import cookie from "cookie";
import cheerio from "cheerio";
import acorn from "acorn";
import escodegen from "escodegen";
import { EventEmitter } from "events";

EventEmitter.defaultMaxListeners = 200;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- CONFIG ----------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6;
const FETCH_TIMEOUT_MS = 30000;
const ASSET_CACHE_THRESHOLD = 256 * 1024; // 256KB
const USER_AGENT_DEFAULT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

if(ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

// ---------------- EXPRESS SETUP ----------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---------------- UTIL: cache ----------------
const MEM_CACHE = new Map();
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const ent = MEM_CACHE.get(key);
  if(ent && (now() - ent.t) < CACHE_TTL) return ent.v;
  if(ENABLE_DISK_CACHE){
    try{
      const fname = path.join(CACHE_DIR, cacheKey(key));
      if(fs.existsSync(fname)){
        const txt = fs.readFileSync(fname, "utf8");
        const obj = JSON.parse(txt);
        if((now() - obj.t) < CACHE_TTL){ MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
        try{ fs.unlinkSync(fname); } catch(e){}
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

// ---------------- SESSIONS + COOKIES ----------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT, bucket: null}; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header=""){ const out={}; header.split(";").forEach(p=>{ const [k,v] = (p||"").split("=").map(s=> (s||"").trim()); if(k && v) out[k]=v; }); return out; }
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
    try{
      const kv = sc.split(";")[0];
      const idx = kv.indexOf("=");
      if(idx === -1) continue;
      const k = kv.slice(0, idx).trim(); const v = kv.slice(idx+1).trim();
      if(k) sessionPayload.cookies.set(k, v);
    }catch(e){}
  }
}
function buildCookieHeader(map){
  return [...map.entries()].map(([k,v])=>`${k}=${v}`).join("; ");
}
// periodic cleanup
setInterval(()=>{ const cutoff = Date.now() - (1000*60*60*24); for(const [k,p] of SESSIONS.entries()) if(p.last < cutoff) SESSIONS.delete(k); }, 1000*60*30);

// ---------------- HEADER / HYGINE ----------------
const DROP_HEADERS = new Set([
  "content-security-policy", "x-frame-options", "cross-origin-opener-policy",
  "cross-origin-embedder-policy", "cross-origin-resource-policy", "permissions-policy"
]);

function forwardHeadersToRes(originHeaders, res){
  try{ originHeaders.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
}

// ---------------- HELPERS: URL / proxyization ----------------
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
  try{ return new URL(href, base).href; } catch(e) { return null; }
}
function proxyizeAbsoluteUrl(abs){
  try{ const u = new URL(abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; } catch(e){ try{ const u2 = new URL("https://" + abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch(e2){ return abs; } }
}

// ---------------- SANITIZERS & TRANSFORMERS ----------------
function sanitizeHtml(html){
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch(e){}
  return html;
}

// Cheerio body-level transform: anchors, src/href, forms, srcset, css url(...)
function cheerioTransform(html, base){
  const $ = cheerio.load(html, { decodeEntities: false });

  // base injection for relative resolution
  if($('base').length === 0 && base){
    $('head').first().prepend(`<base href="${base}">`);
  }

  // anchor rewrite
  $('a[href]').each((i,el)=>{
    try{
      const $el = $(el); const href = $el.attr('href') || '';
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(isAlreadyProxiedHref(href)) return;
      const abs = toAbsolute(href, base) || href;
      $el.attr('href', proxyizeAbsoluteUrl(abs));
      $el.attr('target','_self');
    }catch(e){}
  });

  // forms
  $('form[action]').each((i,el)=>{
    try{
      const $el = $(el); const act = $el.attr('action') || '';
      if(!act) return;
      if(isAlreadyProxiedHref(act)) return;
      const abs = toAbsolute(act, base) || act;
      $el.attr('action', proxyizeAbsoluteUrl(abs));
    }catch(e){}
  });

  // src/href
  $('img[src], script[src], link[href], iframe[src], source[src], video[src], audio[src]').each((i,el)=>{
    try{
      const $el = $(el);
      const attr = $el.attr('src') ? 'src' : ($el.attr('href') ? 'href' : null);
      if(!attr) return;
      const v = $el.attr(attr);
      if(!v) return;
      if(/^data:/i.test(v)) return;
      if(isAlreadyProxiedHref(v)) return;
      const abs = toAbsolute(v, base) || v;
      $el.attr(attr, proxyizeAbsoluteUrl(abs));
    }catch(e){}
  });

  // srcset
  $('[srcset]').each((i, el)=>{
    try{
      const $el = $(el);
      const ss = $el.attr('srcset') || '';
      const parts = ss.split(',').map(p=>{
        const [u,rest] = p.trim().split(/\s+/,2);
        if(!u) return p;
        if(/^data:/i.test(u)) return p;
        if(isAlreadyProxiedHref(u)) return p;
        const abs = toAbsolute(u, base) || u;
        return proxyizeAbsoluteUrl(abs) + (rest ? ' ' + rest : '');
      });
      $el.attr('srcset', parts.join(', '));
    } catch(e){}
  });

  // CSS url(...) rewrite inside style blocks and style attributes
  $('style').each((i, el)=>{
    try{
      let txt = $(el).html() || '';
      txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u)=>{
        if(!u) return m;
        if(/^data:/i.test(u)) return m;
        if(isAlreadyProxiedHref(u)) return m;
        const abs = toAbsolute(u, base) || u;
        return `url("${proxyizeAbsoluteUrl(abs)}")`;
      });
      $(el).html(txt);
    }catch(e){}
  });
  $('[style]').each((i,el)=>{
    try{
      const s = $(el).attr('style');
      if(!s) return;
      const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,u)=>{
        if(!u) return m;
        if(/^data:/i.test(u)) return m;
        if(isAlreadyProxiedHref(u)) return m;
        const abs = toAbsolute(u, base) || u;
        return `url("${proxyizeAbsoluteUrl(abs)}")`;
      });
      $(el).attr('style', out);
    }catch(e){}
  });

  return $.html();
}

// JS AST transform: rewrite literal URLs and common fetch/XHR open calls
function transformJsAst(source, base){
  try{
    const ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "module" });
    // traverse simple walker
    const walk = (node, parent) => {
      if(!node) return;
      // string literal nodes
      if(node.type === 'Literal' && typeof node.value === 'string'){
        const v = node.value;
        // if value looks like a URL or relative path that isn't data:, rewrite to proxied absolute
        if(v && !v.startsWith('data:') && (v.startsWith('http') || v.startsWith('/') || v.match(/\.[a-z]{2,4}($|\/|\?)/i))){
          try{
            const abs = toAbsolute(v, base) || v;
            const prox = proxyizeAbsoluteUrl(abs);
            node.value = prox;
            node.raw = JSON.stringify(prox);
          }catch(e){}
        }
      }
      // handle CallExpression e.g., fetch('/path')
      if(node.type === 'CallExpression' && node.callee){
        const calleeName = node.callee.name || (node.callee.property && node.callee.property.name);
        if(calleeName === 'fetch' && node.arguments && node.arguments[0] && node.arguments[0].type === 'Literal'){
          const v = node.arguments[0].value;
          if(v && !v.startsWith('/proxy?url=') && !v.startsWith('data:')){
            try { const abs = toAbsolute(v, base) || v; node.arguments[0].value = proxyizeAbsoluteUrl(abs); node.arguments[0].raw = JSON.stringify(proxyizeAbsoluteUrl(abs)); } catch(e){}
          }
        }
        // XHR open
        if(node.callee.type === 'MemberExpression' && node.callee.property && node.callee.property.name === 'open'){
          const args = node.arguments;
          if(args && args[1] && args[1].type === 'Literal'){
            const v = args[1].value;
            if(v && !v.startsWith('/proxy?url=') && !v.startsWith('data:')){
              try{ const abs = toAbsolute(v, base) || v; args[1].value = proxyizeAbsoluteUrl(abs); args[1].raw = JSON.stringify(proxyizeAbsoluteUrl(abs)); } catch(e){}
            }
          }
        }
      }
      // traverse children
      for(const k in node){
        if(k === 'parent') continue;
        const child = node[k];
        if(Array.isArray(child)){ child.forEach(c=>{ if(c && typeof c.type === 'string') { c.parent = node; walk(c,node); } }); }
        else if(child && typeof child.type === 'string'){ child.parent = node; walk(child,node); }
      }
    };
    walk(ast, null);
    const output = escodegen.generate(ast);
    return output;
  } catch(e){
    // if parsing fails, return original source
    return source;
  }
}

// Service worker patcher: rewrite fetch/importScripts to route through proxy
function patchServiceWorker(source, base){
  try{
    // simple replacements to rewrite fetch() and importScripts()
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m, args)=> {
      try {
        const parts = eval('[' + args + ']'); // parse literal array of args
        const replaced = parts.map(p => {
          if(typeof p === 'string'){
            const abs = toAbsolute(p, base) || p;
            return `'${proxyizeAbsoluteUrl(abs)}'`;
          }
          return JSON.stringify(p);
        });
        return `importScripts(${replaced.join(',')})`;
      } catch(e){ return m; }
    });
    // rough fetch argument rewrite using regex for string-literal fetch calls
    s = s.replace(/fetch\((['"])(.*?)\1/gi, (m, q, urlStr) => {
      try {
        if(urlStr.startsWith('/proxy?url=')) return m;
        if(/^data:/i.test(urlStr)) return m;
        const abs = toAbsolute(urlStr, base) || urlStr;
        return `fetch('${proxyizeAbsoluteUrl(abs)}`;
      } catch(e){ return m; }
    });
    return s;
  } catch(e){ return source; }
}

// ---------------- WEBSOCKET PROXY (lightweight) ----------------
const server = app.listen(PORT, ()=> console.log(`Euphoria v2 (A3 hybrid) running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on('message', raw => {
    try{ const parsed = JSON.parse(raw.toString()); if(parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg:'pong', ts: Date.now() })); } catch(e){}
  });
});

// ---------------- MAIN /proxy HANDLER ----------------
app.get("/proxy", async (req, res) => {
  // Support /proxy?url=... and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//,'')) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // Normalize
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session
  const session = getSessionFromReq(req);
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}

  // caching keys
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // Decide whether the client expects HTML
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.headers['x-euphoria-client'] === 'a3' || req.query.force_html === '1';

  // quick asset cache for non-HTML
  if(!wantHtml){
    const cached = cacheGet(assetKey);
    if(cached){
      if(cached.headers) Object.entries(cached.headers).forEach(([k,v]) => { try { res.setHeader(k,v) } catch(e){} });
      return res.send(Buffer.from(cached.body, "base64"));
    }
  } else {
    const cachedHtml = cacheGet(htmlKey);
    if(cachedHtml){ res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // Build upstream headers (fingerprint lightly)
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

  // Fetch upstream (manual redirect handling to rewrite Location)
  let originRes;
  try{
    const controller = new AbortController();
    const to = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(to);
  } catch(err){
    console.error("fetch error", err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // persist set-cookie
  try{
    const setCookies = originRes.headers.raw ? originRes.headers.raw()['set-cookie'] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch(e){}

  // handle upstream redirects: rewrite Location to our proxy
  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      let abs;
      try{ abs = new URL(loc, raw).href; } catch(e){ abs = loc; }
      const prox = proxyizeAbsoluteUrl(abs);
      try{ res.setHeader("Location", prox); setSessionCookieHeader(res, session.sid); } catch(e){}
      return res.status(status).send(`Redirecting to ${prox}`);
    }
  }

  // content type detection
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;

  // If asset, stream/copy binary
  if(treatAsAsset){
    try{ originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}
    try{ setSessionCookieHeader(res, session.sid); } catch(e){}
    try{
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

  // HTML path: read text, sanitize, transform
  let htmlText;
  try{ htmlText = await originRes.text(); } catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }
  htmlText = sanitizeHtml(htmlText);

  // Cheerio transform (structure + assets)
  let transformed = cheerioTransform(htmlText, originRes.url || raw);

  // Inject client rewrite shim if not present (to rewrite dynamic fetch/XHR at runtime)
  const rewriteMarker = "/* EUPHORIA_CLIENT_REWRITE */";
  if(!transformed.includes(rewriteMarker)){
    const clientSnippet = `
<script>
${rewriteMarker}
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; if(/^data:/i.test(u)) return u; const abs=new URL(u, document.baseURI).href; return DEPLOY + '/proxy?url=' + encodeURIComponent(abs);}catch(e){return u;} }
  // rewrite dynamic fetch/xhr
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

  // Post-process script blocks: attempt AST-based rewriting for inline scripts and rewrite external script srcs handled by cheerioTransform
  try{
    const $ = cheerio.load(transformed, { decodeEntities:false });
    const scripts = $('script').toArray();
    for(const s of scripts){
      const src = $(s).attr('src');
      if(src) {
        // external scripts usually already proxied by cheerioTransform; nothing further to do
        continue;
      }
      // inline script -> attempt AST transform (to rewrite literal URLs & fetch calls)
      const code = $(s).html() || '';
      if(!code.trim()) continue;
      const patched = transformJsAst(code, originRes.url || raw);
      // also patch potential service worker registration bodies for importScripts/fetch
      const final = patched.includes('self.addEventListener') ? patchServiceWorker(patched, originRes.url || raw) : patched;
      $(s).text(final);
    }
    transformed = $.html();
  } catch(e){
    // if JS transform fails, ignore — we still have cheerio-level fixes
    console.warn("js ast transform failed", e && e.message ? e.message : e);
  }

  // forward upstream safe headers
  try{ originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} }); } catch(e){}

  res.setHeader("Content-Type","text/html; charset=utf-8");
  try{ setSessionCookieHeader(res, session.sid); } catch(e){}

  // cache small HTML
  try{ if(transformed && transformed.length < 512 * 1024) cacheSet(htmlKey, transformed); } catch(e){}

  return res.send(transformed);
});

// ---------------- FALLBACK: relative resource requests (referer-based) ----------------
// If the browser requests /xjs/... directly (no ?url=), try reconstructing using referer ?url=...
app.use(async (req, res, next) => {
  const p = req.path || "/";
  if(p.startsWith("/proxy") || p.startsWith("/_euph_ws") || p.startsWith("/static") || p.startsWith("/public")) return next();

  const referer = req.headers.referer || req.headers.referrer || "";
  const m = referer.match(/[?&]url=([^&]+)/);
  if(!m) return next();

  let orig;
  try{ orig = decodeURIComponent(m[1]); } catch(e){ return next(); }
  if(!orig) return next();

  let baseOrigin;
  try{ baseOrigin = new URL(orig).origin; } catch(e){ return next(); }

  const attempted = new URL(req.originalUrl, baseOrigin).href;

  // proxy attempted
  try{
    const session = getSessionFromReq(req);
    setSessionCookieHeader(res, session.sid);
    const originHeaders = { "User-Agent": session.payload.ua || USER_AGENT_DEFAULT, "Accept": req.headers.accept || "*/*", "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9" };
    const cookieHdr = buildCookieHeader(session.payload.cookies);
    if(cookieHdr) originHeaders["Cookie"] = cookieHdr;

    const controller = new AbortController();
    const to = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    const originRes = await fetch(attempted, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(to);

    // redirects
    if([301,302,303,307,308].includes(originRes.status)){
      const loc = originRes.headers.get("location");
      if(loc){ const abs = new URL(loc, attempted).href; return res.redirect(proxyizeAbsoluteUrl(abs)); }
    }

    const ct = (originRes.headers.get("content-type") || "").toLowerCase();
    if(!ct.includes("text/html")){
      originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      res.setHeader("Content-Type", ct || "application/octet-stream");
      return res.send(buf);
    }

    // html fallback transform
    let html = await originRes.text();
    html = sanitizeHtml(html);
    const transformed = cheerioTransform(html, originRes.url || attempted);
    let finalHtml = transformed.replace(/<\/body>/i, `
<script>
/* EUPHORIA CLIENT FALLBACK */
(function(){ const D="${DEPLOYMENT_ORIGIN}"; /* lightweight runtime rewrite */ window.fetch = (orig=> function(r,i){ try{ if(typeof r==='string' && !r.includes('/proxy?url=')) r = D + '/proxy?url=' + encodeURIComponent(new URL(r, document.baseURI).href); }catch(e){} return orig.call(this,r,i); })(window.fetch); })();
</script>
</body>`);

    originRes.headers.forEach((v,k)=>{ if(!DROP_HEADERS.has(k.toLowerCase())) try{ res.setHeader(k,v) } catch(e){} });
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.send(finalHtml);

  } catch(err){
    console.error("fallback proxy error", err);
    return next();
  }
});

// ---------------- SPA fallback ----------------
app.get("/", (req,res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// ---------------- ERRORS ----------------
process.on("unhandledRejection", err => console.error("unhandledRejection", err));
process.on("uncaughtException", err => console.error("uncaughtException", err));
