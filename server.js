// server.js — EUPHORIA v2 (no-iframe, robust HTML rewrite & redirect handling)
import express from "express";
import { JSDOM } from "jsdom";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { WebSocketServer } from "ws";
import { EventEmitter } from "events";

EventEmitter.defaultMaxListeners = 200;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --------------- CONFIG ---------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX = 256 * 1024; // 256 KB
const FETCH_TIMEOUT_MS = 30000; // 30s

const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif",
  ".svg", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3"
];
const SPECIAL_ASSET_NAMES = ["service-worker.js","sw.js","worker.js","manifest.json"];

const DROP_HEADERS_LOWER = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

if (ENABLE_DISK_CACHE) {
  fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});
}

// --------------- EXPRESS SETUP ---------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// --------------- SESSIONS/COOKIES ---------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();

function makeSid(){ return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession(){ const sid = makeSid(); const payload = { cookies: new Map(), last: Date.now() }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(cookieHeader = "") {
  const out = {};
  cookieHeader.split(";").forEach(p=>{
    const [k,v] = (p||"").split("=").map(s => (s||"").trim());
    if(k && v) out[k] = v;
  });
  return out;
}
function getSessionFromReq(req){
  const cookies = parseCookies(req.headers.cookie || "");
  let sid = cookies[SESSION_NAME] || req.headers["x-euphoria-session"];
  if(!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid); payload.last = Date.now(); return { sid, payload };
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
function buildCookieHeader(map){
  return [...map.entries()].map(([k,v])=>`${k}=${v}`).join("; ");
}
// cleanup stale sessions
setInterval(()=>{ const cutoff = Date.now() - (1000*60*30); for(const [sid,p] of SESSIONS.entries()) if(p.last < cutoff) SESSIONS.delete(sid); }, 1000*60*5);

// --------------- CACHE ---------------
const MEM_CACHE = new Map();
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const e = MEM_CACHE.get(key);
  if(e && (now() - e.t) < CACHE_TTL) return e.v;
  if(ENABLE_DISK_CACHE){
    const fn = path.join(CACHE_DIR, cacheKey(key));
    if(fs.existsSync(fn)){
      try {
        const raw = fs.readFileSync(fn, "utf8");
        const obj = JSON.parse(raw);
        if((now() - obj.t) < CACHE_TTL){ MEM_CACHE.set(key, {v:obj.v,t:obj.t}); return obj.v; } else { try{ fs.unlinkSync(fn);}catch(e){} }
      } catch(e){}
    }
  }
  return null;
}
function cacheSet(key, val){ MEM_CACHE.set(key, { v: val, t: now() }); if(ENABLE_DISK_CACHE){ const fn = path.join(CACHE_DIR, cacheKey(key)); fsPromises.writeFile(fn, JSON.stringify({v:val,t:now()}), "utf8").catch(()=>{}); } }

// --------------- HELPERS ---------------
function toAbsolute(href, base){ try { return new URL(href, base).href; } catch(e){ return null; } }
function isAlreadyProxiedHref(href){
  if(!href) return false;
  try {
    if(href.includes("/proxy?url=")) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if(resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch(e){}
  return false;
}
function proxyizeAbsoluteUrl(absUrl){
  try { const u = new URL(absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; }
  catch(e){ try{ const u2 = new URL("https://" + absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch(e2){ return absUrl; } }
}
function looksLikeAssetPath(urlStr){
  if(!urlStr) return false;
  try {
    const p = new URL(urlStr, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(p.endsWith(ext)) return true;
    for(const seg of SPECIAL_ASSET_NAMES) if(p.endsWith(seg)) return true;
    return false;
  } catch(e){
    const lower = urlStr.toLowerCase();
    for(const ext of ASSET_EXTENSIONS) if(lower.endsWith(ext)) return true;
    for(const seg of SPECIAL_ASSET_NAMES) if(lower.endsWith(seg)) return true;
    return false;
  }
}

// --------------- INJECTED REWRITE SCRIPT (clientside) ---------------
const INJECT_MARKER = "<!--EUPHORIA-REWRITE-INJECTED-->";
const INJECT_SCRIPT = `
${INJECT_MARKER}
<script id="EUPHORIA_REWRITE_MARKER">
(function(){
  const DEPLOY="${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; if(/^data:/i.test(u)) return u; const abs = new URL(u, document.baseURI).href; return DEPLOY + '/proxy?url=' + encodeURIComponent(abs); }catch(e){return u;} }
  function rewrite(root){
    try {
      root.querySelectorAll('a[href]').forEach(a=>{
        try { const h=a.getAttribute('href'); if(!h) return; if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return; if(h.includes('/proxy?url=')) return; a.setAttribute('href', prox(h)); a.removeAttribute('target'); }catch(e){}
      });
      root.querySelectorAll('form[action]').forEach(f=>{
        try{ const a=f.getAttribute('action'); if(!a) return; if(a.includes('/proxy?url=')) return; f.setAttribute('action', prox(a)); }catch(e){}
      });
      ['img','script','link','iframe','source','video','audio'].forEach(tag=>{
        root.querySelectorAll(tag+'[src]').forEach(el=>{
          try{ const v=el.getAttribute('src'); if(!v) return; if(/^data:/i.test(v)) return; if(v.includes('/proxy?url=')) return; el.setAttribute('src', prox(v)); }catch(e){}
        });
        root.querySelectorAll(tag+'[href]').forEach(el=>{
          try{ const v=el.getAttribute('href'); if(!v) return; if(/^data:/i.test(v)) return; if(v.includes('/proxy?url=')) return; el.setAttribute('href', prox(v)); }catch(e){}
        });
      });
      root.querySelectorAll('[srcset]').forEach(el=>{
        try{
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u,rest] = p.trim().split(/\\s+/,2); if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return prox(u) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }catch(e){}
      });
    } catch(e){}
  }
  rewrite(document);
  try {
    const mo = new MutationObserver(muts=>{
      for(const m of muts) m.addedNodes && Array.from(m.addedNodes).forEach(n=>{ if(n.nodeType!==1) return; rewrite(n); });
    });
    mo.observe(document.documentElement||document, { childList:true, subtree:true });
  } catch(e){}
  try {
    const origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        else if(resource instanceof Request) { if(!resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource); }
      } catch(e){}
      return origFetch(resource, init);
    };
  } catch(e){}
})();
</script>
`;

// --------------- WEBSOCKET TELEMETRY ---------------
const server = app.listen(PORT, () => console.log(`Euphoria v2 running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try {
      const parsed = JSON.parse(raw.toString());
      if(parsed && parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch(e){}
  });
});

// --------------- PROXY HANDLER ---------------
app.get("/proxy", async (req, res) => {
  // accept /proxy?url= and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize schemeless hosts
  if(!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch(e){}

  const accept = (req.headers.accept || "").toLowerCase();
  const forcedHtml = !!req.headers["x-euphoria-client"];
  const wantHtml = forcedHtml || accept.includes("text/html");

  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  // quick asset cache if not HTML request
  if(!wantHtml){
    const cached = cacheGet(assetKey);
    if(cached){
      try { Object.entries(cached.headers || {}).forEach(([k,v])=>res.setHeader(k,v)); } catch(e){}
      return res.send(Buffer.from(cached.body, "base64"));
    }
  }

  // HTML cache
  if(wantHtml){
    const cachedHtml = cacheGet(htmlKey);
    if(cachedHtml){ res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // build origin headers; include cookie store
  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/2.0",
    "Accept": wantHtml ? "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" : (req.headers.accept || "*/*"),
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  // spy: some origin-sensitive sites expect a referer/origin matching the target; spoof them
  try { originHeaders["Referer"] = raw; originHeaders["Origin"] = new URL(raw).origin; } catch(e){}
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) originHeaders["Cookie"] = cookieHdr;

  // perform fetch with timeout & follow redirects
  let originRes;
  try {
    const controller = new AbortController();
    const to = setTimeout(()=>controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "manual", signal: controller.signal });
    clearTimeout(to);
  } catch(err){
    console.error("fetch error", err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // If upstream set-cookie, save to session
  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch(e){}

  // Handle redirects specially: rewrite Location header to deployment proxy so client follows via our proxy
  const status = originRes.status || 200;
  if([301,302,303,307,308].includes(status)){
    const loc = originRes.headers.get("location");
    if(loc){
      // convert relative location to absolute against raw
      let abs;
      try { abs = new URL(loc, raw).href; } catch(e) { abs = loc; }
      const proxied = proxyizeAbsoluteUrl(abs);
      // send rewritten redirect to client
      try {
        res.setHeader("Location", proxied);
        setSessionCookieHeader(res, session.sid);
      } catch(e){}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  // Determine content-type
  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = looksLikeAssetPath(raw) || !isHtml;

  // ASSET PATH
  if(treatAsAsset){
    // forward safe headers
    try { originRes.headers.forEach((v,k)=> { if(!DROP_HEADERS_LOWER.has(k.toLowerCase())) try{ res.setHeader(k,v); } catch(e){} }); } catch(e){}
    try { setSessionCookieHeader(res, session.sid); } catch(e){}

    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if(buf.length < ASSET_CACHE_MAX) {
        try { cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch(e){}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if(originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch(err){
      // fallback stream
      try { originRes.body.pipe(res); return; } catch(e){ return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // HTML PATH
  try { originRes.headers.forEach((v,k)=> { if(DROP_HEADERS_LOWER.has(k.toLowerCase())){} else try{ res.setHeader(k,v);}catch(e){} }); } catch(e){}
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  // read HTML fully for jsdom processing
  let rawHtml;
  try { rawHtml = await originRes.text(); } catch(e){ console.error("read html error", e); return res.status(502).send("Euphoria: failed to read HTML"); }

  // remove problematic meta CSP tags and integrity/crossorigin attributes
  try {
    rawHtml = rawHtml.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    rawHtml = rawHtml.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    rawHtml = rawHtml.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch(e){}

  // rewrite with jsdom
  let finalHtml = rawHtml;
  try {
    finalHtml = await (async function rewrite(html, base){
      try {
        const dom = new JSDOM(html, { url: base });
        const doc = dom.window.document;

        // inject base tag if missing
        if(doc.head && !doc.querySelector('base')){
          try {
            const baseEl = doc.createElement('base');
            baseEl.setAttribute('href', base);
            doc.head.insertBefore(baseEl, doc.head.firstChild);
          } catch(e){}
        }

        // rewrite anchors/forms/assets
        const rewriteAttr = (el, attr) => {
          try {
            if(!el || !el.getAttribute) return;
            const val = el.getAttribute(attr);
            if(!val) return;
            if(isAlreadyProxiedHref(val)) return;
            if(/^(javascript:|mailto:|tel:|#)/i.test(val)) return;
            if(/^data:/i.test(val)) return;
            const abs = toAbsolute(val, base) || val;
            el.setAttribute(attr, proxyizeAbsoluteUrl(abs));
            if(attr === 'href') el.removeAttribute('target');
          } catch(e){}
        };

        const tags = [
          ['a','href'],
          ['link','href'],
          ['script','src'],
          ['img','src'],
          ['iframe','src'],
          ['source','src'],
          ['video','src'],
          ['audio','src'],
          ['form','action']
        ];
        for(const [tag, attr] of tags){
          const nodes = Array.from(doc.getElementsByTagName(tag));
          for(const n of nodes) rewriteAttr(n, attr);
        }

        // rewrite srcset
        Array.from(doc.querySelectorAll('[srcset]')).forEach(el=>{
          try {
            const ss = el.getAttribute('srcset') || '';
            const parts = ss.split(',').map(p=>{
              const [u, rest] = p.trim().split(/\s+/,2);
              if(!u) return p;
              if(isAlreadyProxiedHref(u)) return p;
              if(/^data:/i.test(u)) return p;
              const abs = toAbsolute(u, base) || u;
              return proxyizeAbsoluteUrl(abs) + (rest ? ' ' + rest : '');
            });
            el.setAttribute('srcset', parts.join(', '));
          } catch(e){}
        });

        // rewrite CSS url(...) inside style tags and inline style attributes
        Array.from(doc.querySelectorAll('style')).forEach(st=>{
          try {
            const txt = st.textContent.replace(/url\\(([^)]+)\\)/g, (_, raw) => {
              const clean = raw.replace(/['"]/g, '').trim();
              if(!clean) return `url(${clean})`;
              if(isAlreadyProxiedHref(clean)) return `url(${clean})`;
              if(/^data:/i.test(clean)) return `url(${clean})`;
              const abs = toAbsolute(clean, base) || clean;
              return `url(${proxyizeAbsoluteUrl(abs)})`;
            });
            st.textContent = txt;
          } catch(e){}
        });

        Array.from(doc.querySelectorAll('[style]')).forEach(el=>{
          try {
            const s = el.getAttribute('style') || '';
            const rewritten = s.replace(/url\\(([^)]+)\\)/g, (_, raw) => {
              const clean = raw.replace(/['"]/g,'').trim();
              if(!clean) return `url(${clean})`;
              if(isAlreadyProxiedHref(clean)) return `url(${clean})`;
              if(/^data:/i.test(clean)) return `url(${clean})`;
              const abs = toAbsolute(clean, base) || clean;
              return `url(${proxyizeAbsoluteUrl(abs)})`;
            });
            el.setAttribute('style', rewritten);
          } catch(e){}
        });

        // rewrite meta refresh
        Array.from(doc.querySelectorAll('meta[http-equiv]')).forEach(m=>{
          try{
            if(m.getAttribute('http-equiv').toLowerCase() !== 'refresh') return;
            const c = m.getAttribute('content') || '';
            const parts = c.split(';');
            if(parts.length < 2) return;
            const urlpart = parts.slice(1).join(';').match(/url=(.*)/i);
            if(!urlpart) return;
            const dest = urlpart[1].replace(/['"]/g,'').trim();
            const abs = toAbsolute(dest, base) || dest;
            m.setAttribute('content', parts[0] + ';url=' + proxyizeAbsoluteUrl(abs));
          } catch(e){}
        });

        // replace window.location assignments inside inline scripts (best effort)
        Array.from(doc.querySelectorAll('script')).forEach(s=>{
          try {
            if(!s.textContent) return;
            let txt = s.textContent;
            txt = txt.replace(/(window\\.location(?:\\.href|\\.assign|\\.replace)?\\s*=\\s*['"])([^'"]+)(['"])/gi, (m,p1,p2,p3)=>{
              try {
                const abs = new URL(p2, base).href;
                return p1 + proxyizeAbsoluteUrl(abs) + p3;
              } catch(e){ return m; }
            });
            txt = txt.replace(/(location\\.href\\s*=\\s*['"])([^'"]+)(['"])/gi, (m,p1,p2,p3)=>{
              try { const abs = new URL(p2, base).href; return p1 + proxyizeAbsoluteUrl(abs) + p3; } catch(e){ return m; }
            });
            // history.pushState/replaceState - best effort: leave but some single page apps will use fetch/ajax that we rewrite clientside
            s.textContent = txt;
          } catch(e){}
        });

        // inject small clientside rewrite script (so runtime-created items are proxied)
        try {
          const markerPresent = doc.documentElement && doc.documentElement.innerHTML && doc.documentElement.innerHTML.includes('EUPHORIA_REWRITE_MARKER');
          if(!markerPresent){
            const frag = JSDOM.fragment(INJECT_SCRIPT);
            (doc.body || doc.documentElement || doc).appendChild(frag);
          }
        } catch(e){}

        // remove integrity/crossorigin attr from elements to avoid browser blocking
        Array.from(doc.querySelectorAll('[integrity]')).forEach(el => el.removeAttribute('integrity'));
        Array.from(doc.querySelectorAll('[crossorigin]')).forEach(el => el.removeAttribute('crossorigin'));

        // serialize and return
        return dom.serialize();
      } catch(err) {
        console.error("jsdom rewrite error", err);
        return html;
      }
    })(rawHtml, originRes.url || raw);
  } catch(err){
    console.error("rewrite error", err);
    finalHtml = rawHtml;
  }

  // set session cookie header before sending
  try { setSessionCookieHeader(res, session.sid); } catch(e){}

  // cache small HTML
  try { if(finalHtml && finalHtml.length < 512 * 1024) cacheSet(htmlKey, finalHtml); } catch(e){}

  return res.send(finalHtml);
});

// --------------- FALLBACKS ---------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req,res,next) => {
  if(req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// --------------- ERROR HANDLING ---------------
process.on("unhandledRejection", (r) => console.error("unhandledRejection", r));
process.on("uncaughtException", (err) => console.error("uncaughtException", err));

console.log(`Euphoria v2 starting on port ${PORT}`);