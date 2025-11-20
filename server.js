// server.js
// EUPHORIA v2 — Express + Scramjet hybrid web proxy

import express from "express";
import fetch from "node-fetch";
import scramjetPkg from "scramjet";
const { StringStream } = scramjetPkg;
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import { WebSocketServer } from "ws";
import fsPromises from "fs/promises";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { pipeline } from "stream";
import { promisify } from "util";
import { EventEmitter } from "events";

EventEmitter.defaultMaxListeners = 50;
const pipe = promisify(pipeline);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------- CONFIG --------------------
const DEPLOYMENT_ORIGIN = "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_TTL = 1000 * 60 * 6;
const ASSET_CACHE_MAX = 128 * 1024;
const FETCH_TIMEOUT_MS = 25000;
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");

if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(()=>{});

const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif",
  ".svg", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3"
];

const SPECIAL_PATH_SEGMENTS = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];
const DROP_META_HEADERS = [
  "content-security-policy","x-frame-options","cross-origin-opener-policy",
  "cross-origin-embedder-policy","cross-origin-resource-policy","permissions-policy"
];

// -------------------- EXPRESS SETUP --------------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -------------------- SIMPLE CACHE --------------------
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheKey(s) { return Buffer.from(s).toString("base64url"); }
function cacheGet(key) {
  const entry = MEM_CACHE.get(key);
  if(entry && now()-entry.t<CACHE_TTL) return entry.v;
  if(ENABLE_DISK_CACHE){
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(fs.existsSync(fname)){
      try {
        const raw = fs.readFileSync(fname,"utf8");
        const obj = JSON.parse(raw);
        if(now()-obj.t<CACHE_TTL){
          MEM_CACHE.set(key,{v:obj.v,t:obj.t});
          return obj.v;
        } else { try{fs.unlinkSync(fname);}catch(e){} }
      } catch(e){}
    }
  }
  return null;
}
function cacheSet(key,val){
  MEM_CACHE.set(key,{v:val,t:now()});
  if(ENABLE_DISK_CACHE){
    const fname = path.join(CACHE_DIR, cacheKey(key));
    fsPromises.writeFile(fname,JSON.stringify({v:val,t:now()}),"utf8").catch(()=>{});
  }
}

// -------------------- SESSIONS --------------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid(){ return Math.random().toString(36).slice(2)+Date.now().toString(36); }
function createSession(){ const sid=makeSid(); const payload={cookies:new Map(),last:now()}; SESSIONS.set(sid,payload); return {sid,payload}; }
function parseCookies(h=""){ const out={}; h.split(";").forEach(p=>{const [k,v]=(p||"").split("=").map(s=>(s||"").trim()); if(k&&v) out[k]=v; }); return out; }
function getSessionFromReq(req){
  const cookies=parseCookies(req.headers.cookie||"");
  let sid=cookies[SESSION_NAME]||req.headers["x-euphoria-session"];
  if(!sid||!SESSIONS.has(sid)) return createSession();
  const payload=SESSIONS.get(sid);
  payload.last=now();
  return {sid,payload};
}
function setSessionCookieHeader(res,sid){
  const cstr=`${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev=res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie",cstr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie",[...prev,cstr]);
  else res.setHeader("Set-Cookie",[prev,cstr]);
}
function storeSetCookieToSession(sc=[],sessionPayload){
  for(const c of sc){
    try{
      const kv=c.split(";")[0]; const idx=kv.indexOf("="); if(idx===-1) continue;
      const k=kv.slice(0,idx).trim(); const v=kv.slice(idx+1).trim();
      if(k) sessionPayload.cookies.set(k,v);
    }catch(e){}
  }
}
function buildCookieHeader(map){ return [...map.entries()].map(([k,v])=>`${k}=${v}`).join("; "); }

// -------------------- HELPERS --------------------
function toAbsolute(href,base){ try{return new URL(href,base).href}catch(e){return null;} }
function looksLikeAssetPath(urlStr){ if(!urlStr) return false; try{ const p=new URL(urlStr,DEPLOYMENT_ORIGIN).pathname.toLowerCase(); return ASSET_EXTENSIONS.some(e=>p.endsWith(e))||SPECIAL_PATH_SEGMENTS.some(s=>p.endsWith(s));}catch(e){ const lower=urlStr.toLowerCase(); return ASSET_EXTENSIONS.some(e=>lower.endsWith(e))||SPECIAL_PATH_SEGMENTS.some(s=>lower.endsWith(s)); } }
function isAlreadyProxiedHref(h){ if(!h) return false; try{ if(h.includes("/proxy?url=")) return true; const u=new URL(h,DEPLOYMENT_ORIGIN); return u.origin===new URL(DEPLOYMENT_ORIGIN).origin && u.pathname.startsWith("/proxy"); }catch(e){return false;} }
function proxyizeAbsoluteUrl(absUrl){ try{ const u=new URL(absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}` } catch(e){try{const u2=new URL("https://"+absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`;}catch(e2){return absUrl;}}}
function toDeploymentProxyLink(h,base){ if(!h) return h; if(isAlreadyProxiedHref(h)){ try{ const r=new URL(h,base||DEPLOYMENT_ORIGIN); if(r.pathname.startsWith("/proxy")){ const orig=r.searchParams.get("url"); if(orig) return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(orig)}`; } }catch(e){} return h;} const abs=toAbsolute(h,base)||h; return proxyizeAbsoluteUrl(abs);}

// -------------------- INJECTION --------------------
const INJECT_MARKER="<!--EUPHORIA-REWRITE-INJECTED-->";
const INJECT_REWRITE_SCRIPT=`<script>
(function(){
  const DEPLOY="${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; const abs=new URL(u,document.baseURI).href; return DEPLOY+'/proxy?url='+encodeURIComponent(abs); }catch(e){return u;} }
  document.querySelectorAll('a[href]').forEach(a=>{ try{ const h=a.getAttribute('href'); if(!h) return; if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return; if(h.includes('/proxy?url=')) return; a.setAttribute('href',prox(h)); a.removeAttribute('target'); }catch(e){} });
  document.querySelectorAll('form[action]').forEach(f=>{ try{ const act=f.getAttribute('action'); if(!act) return; if(act.includes('/proxy?url=')) return; f.setAttribute('action',prox(act)); }catch(e){} });
})();
</script>`;

// -------------------- WEBSOCKET --------------------
const server=app.listen(PORT,()=>console.log(`Euphoria v2 running on port ${PORT}`));
const wss=new WebSocketServer({server,path:"/_euph_ws"});
wss.on("connection",ws=>{
  ws.send(JSON.stringify({msg:"welcome",ts:Date.now()}));
  ws.on("message",raw=>{try{ const p=JSON.parse(raw.toString()); if(p.cmd==="ping") ws.send(JSON.stringify({msg:"pong",ts:Date.now()})); }catch(e){} });
});

// -------------------- PROXY --------------------
app.get("/proxy",async(req,res)=>{
  let raw=req.query.url || (req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//,"")) : null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw="https://"+raw;

  const session=getSessionFromReq(req);
  setSessionCookieHeader(res,session.sid);
  const accept=(req.headers.accept||"").toLowerCase();

  try{
    const controller=new AbortController();
    const to=setTimeout(()=>controller.abort(),FETCH_TIMEOUT_MS);
    const originRes=await fetch(raw,{headers:{"User-Agent":req.headers["user-agent"]||"Euphoria/2.0","Accept":req.headers.accept||"*/*"},redirect:"follow",signal:controller.signal});
    clearTimeout(to);

    const setCookies=originRes.headers.raw ? originRes.headers.raw()["set-cookie"]||[] : [];
    if(setCookies.length) storeSetCookieToSession(setCookies,session.payload);
    const contentType=(originRes.headers.get("content-type")||"").toLowerCase();

    if(!contentType.includes("text/html")||looksLikeAssetPath(raw)){
      originRes.headers.forEach((v,k)=>{ if(!DROP_META_HEADERS.includes(k.toLowerCase())) res.setHeader(k,v); });
      return pipe(originRes.body,res);
    }

    // HTML transform
    let html=await originRes.text();
    if(!html.includes(INJECT_MARKER)) html=html.replace(/<head>/i,"<head>"+INJECT_REWRITE_SCRIPT+INJECT_MARKER);
    res.setHeader("Content-Type","text/html; charset=utf-8");
    res.send(html);

  }catch(e){ console.error("Proxy error:",e); res.status(502).send("Proxy fetch failed"); }
});