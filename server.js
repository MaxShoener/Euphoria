// server.js — Euphoria proxy full-featured (550+ lines)
// Save as ESM: node server.js

import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import scramjetPkg from "scramjet";
const { StringStream } = scramjetPkg;
import { WebSocketServer } from "ws";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

// --- Middleware ---
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// --- Sessions ---
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24h
const SESSIONS = new Map();

function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function now() { return Date.now(); }

function createSession() {
  const sid = makeSid();
  const payload = { cookies: new Map(), last: now() };
  SESSIONS.set(sid, payload);
  return { sid, payload };
}

function getSessionFromReq(req) {
  const cookieHeader = req.headers.cookie || "";
  const parsed = {};
  cookieHeader.split(";").forEach(p => {
    const [k, v] = p.split("=").map(s => (s || "").trim());
    if (k && v) parsed[k] = v;
  });
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid);
  payload.last = now();
  return { sid, payload };
}

function setSessionCookieHeader(res, sid) {
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev = res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie", cookieStr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}

function storeSetCookieToSession(setCookies, sessionPayload){
  for(const sc of setCookies || []){
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

// --- Cache ---
const CACHE_DIR = path.join(__dirname, "cache");
if(!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 6;

function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const m = MEM_CACHE.get(key);
  if(m && (now() - m.t) < CACHE_TTL) return m.v;
  const file = path.join(CACHE_DIR, cacheKey(key));
  if(fs.existsSync(file)){
    try {
      const raw = fs.readFileSync(file, "utf8");
      const obj = JSON.parse(raw);
      if((now() - obj.t) < CACHE_TTL){ MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
      try { fs.unlinkSync(file); } catch(e){}
    } catch(e){}
  }
  return null;
}
function cacheSet(key, val){
  MEM_CACHE.set(key, { v: val, t: now() });
  try { fs.writeFileSync(path.join(CACHE_DIR, cacheKey(key)), JSON.stringify({ v: val, t: now() }), "utf8"); } catch(e){}
}

// --- Helpers ---
function toAbsolute(href, base){
  try { return new URL(href, base).href; } catch(e) { return null; }
}

function buildCookieHeader(map){
  const parts = [];
  for(const [k,v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

function looksLikeSearch(input){
  if(!input) return true;
  if(input.includes(" ")) return true;
  if(/^https?:\/\//i.test(input)) return false;
  if(/\./.test(input)) return false;
  return true;
}

function normalizeToUrl(input){
  const v = (input || "").trim();
  if(!v) return "https://www.google.com";
  if(looksLikeSearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if(/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// --- Inject Topbar + Transform Script ---
const INJECT = `
<!-- Euphoria Topbar -->
<div id="euphoria-topbar" style="position:fixed;top:12px;left:50%;transform:translateX(-50%);width:min(1100px,86%);background:rgba(17,17,17,0.85);border-radius:28px;padding:8px 10px;display:flex;gap:8px;align-items:center;z-index:2147483647;box-shadow:0 6px 20px rgba(0,0,0,0.6);backdrop-filter:blur(6px);">
  <button id="eph-back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" placeholder="Enter URL or search..." style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" />
  <button id="eph-go" style="min-width:48px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
</div>
<style>#euphoria-loading{position:fixed;top:0;left:0;width:0%;height:3px;background:#2e7d32;transition:width 0.3s;z-index:2147483647}</style>
<div id="euphoria-loading"></div>
<script>
(function(){
  const input = document.getElementById('eph-input');
  const go = document.getElementById('eph-go');
  const back = document.getElementById('eph-back');
  const forward = document.getElementById('eph-forward');
  const refresh = document.getElementById('eph-refresh');
  const home = document.getElementById('eph-home');
  const full = document.getElementById('eph-full');
  const loading = document.getElementById('euphoria-loading');
  const getAbs = h => { try { return new URL(h, document.baseURI).href; } catch(e){return h;} };
  const toProxy = href => '/proxy?url=' + encodeURIComponent(href);

  go.onclick = ()=>{ const u=input.value; if(/\\/proxy\\?url=/.test(u)){ location.href=u; return;} location.href=toProxy(u); };
  input.onkeydown = e=>{if(e.key==='Enter') go.onclick();};
  back.onclick=()=>history.back(); forward.onclick=()=>history.forward();
  refresh.onclick=()=>location.reload(); home.onclick=()=>location.href='/'; full.onclick=()=>{ if(!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

  const rewrite = ()=>{document.querySelectorAll('a[href]').forEach(a=>{try{const v=a.href;if(!v) return;if(v.startsWith('/proxy?')) return;a.href=toProxy(getAbs(v));}catch(e){}});};
  rewrite();
  const mo=new MutationObserver(rewrite);
  mo.observe(document.documentElement,{childList:true,subtree:true});
  window.addEventListener('beforeunload',()=>{loading.style.width='0%';});
  const startLoad=()=>{loading.style.width='20%';}; const endLoad=()=>{loading.style.width='100%'; setTimeout(()=>loading.style.width='0%',300);};
  window.addEventListener('load',endLoad); startLoad();
})();
</script>
`;

// --- WebSocket telemetry ---
const server = app.listen(PORT, ()=>console.log(`Euphoria proxy running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws=>{
  ws.send(JSON.stringify({ msg:"welcome", ts:Date.now() }));
  ws.on("message", raw=>{
    try { const parsed=JSON.parse(raw.toString()); if(parsed.cmd==='ping') ws.send(JSON.stringify({msg:'pong',ts:Date.now()})); } catch(e){}
  });
});

// --- Main proxy endpoint ---
app.get("/proxy", async (req,res)=>{
  let raw = req.query.url;
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw='https://'+raw;

  const session=getSessionFromReq(req);
  setSessionCookieHeader(res, session.sid);
  const cacheKeyHtml=raw+"::html"; const cacheKeyAsset=raw+"::asset";

  const cachedHtml=cacheGet(cacheKeyHtml);
  if(cachedHtml && req.headers.accept?.includes('text/html')){
    res.setHeader("Content-Type","text/html; charset=utf-8");
    return res.send(cachedHtml);
  }

  const headers={"User-Agent":req.headers['user-agent']||'Euphoria/1.0',"Accept":req.headers.accept||'*/*',"Accept-Language":req.headers['accept-language']||'en-US,en;q=0.9'};
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if(cookieHdr) headers["Cookie"]=cookieHdr;
  if(req.headers.referer) headers["Referer"]=req.headers.referer;

  try{
    const ctrl=new AbortController(); const to=setTimeout(()=>ctrl.abort(),20000);
    const originRes=await fetch(raw,{headers,redirect:'follow',signal:ctrl.signal}); clearTimeout(to);
    const setCookies=originRes.headers.raw()?originRes.headers.raw()['set-cookie']||[]:[];
    if(setCookies.length) storeSetCookieToSession(setCookies,session.payload);
    const contentType=(originRes.headers.get("content-type")||"").toLowerCase();
    if(!contentType.includes("text/html")){
      const arr=await originRes.arrayBuffer();
      const buf=Buffer.from(arr);
      if(buf.length<128*1024) cacheSet(cacheKeyAsset,{headers:{"Content-Type":contentType},body:buf.toString("base64")});
      res.setHeader("Content-Type",contentType);
      const cc=originRes.headers.get("cache-control"); if(cc) res.setHeader("Cache-Control",cc);
      return res.send(buf);
    }

    let html=await originRes.text();
    html=html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi,"");
    html=html.replace(/\s+integrity=(["'])(.*?)\1/gi,"").replace(/\s+crossorigin=(["'])(.*?)\1/gi,"");
    const finalUrl=originRes.url||raw;
    if(/<head[\s>]/i.test(html)) html=html.replace(/<head([^>]*)>/i,(_,g)=>`<head${g}><base href="${finalUrl}">`);
    else html=`<base href="${finalUrl}">`+html;

    // Rewrite anchors/assets/forms/meta-refresh
    html=html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi,(m,p,q,v)=>{ if(!v||v.startsWith('/proxy?')||/^(javascript:|mailto:|tel:|#)/i.test(v)) return m; const a=toAbsolute(v,finalUrl)||v; return `<a${p}href="/proxy?url=${encodeURIComponent(a)}"`; });
    html=html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|srcset)=)(["'])([^"']*)\3/gi,(m,p,a,q,v)=>{ if(!v||v.startsWith('/proxy?')||/^data:/i.test(v)) return m; const abs=toAbsolute(v,finalUrl)||v; return `${p}${a}${q}/proxy?url=${encodeURIComponent(abs)}${q}`; });
    html=html.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi,m=>{ const match=m.match(/content\s*=\s*["']([^"']*)["']/i); if(!match) return m; const parts=match[1].split(";"); if(parts.length<2) return m; const urlPart=parts.slice(1).join(";").match(/url=(.*)/i); if(!urlPart) return m; const dest=urlPart[1].replace(/['"]/g,"").trim(); const abs=toAbsolute(dest,finalUrl)||dest; return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`; });

    // Remove analytics scripts (best effort)
    html=html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi,"");
    html=html.replace(/<script[^>]*>\s*window\.ga=.*?<\/script>/gi,"");

    // Inject topbar after <body>
    if(/<body[^>]*>/i.test(html)) html=html.replace(/<body([^>]*)>/i,(m,g)=>`<body${g}>`+INJECT);
    else html=INJECT+html;

    if(originRes.status===200) cacheSet(cacheKeyHtml,html);

    res.setHeader("Content-Type","text/html; charset=utf-8");
    setSessionCookieHeader(res, session.sid);
    const stream=StringStream.from(html);
    stream.pipe(res);
    stream.on("end",()=>{ try{res.end();}catch(e){} });
    stream.on("error",()=>{ try{res.end();}catch(e){} });
  }catch(err){
    console.error("Proxy error:",err?.message||err);
    setSessionCookieHeader(res, session.sid);
    res.status(500).send(`<div style="padding:1rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err?.message)||String(err)}</div>`);
  }
});

// --- Fallback to index.html ---
app.use((req,res,next)=>{
  if(req.method==='GET' && req.accepts && req.accepts('html')) return res.sendFile(path.join(__dirname,'public','index.html'));
  next();
});
