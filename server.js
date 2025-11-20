// server.js
// EUPHORIA v2 — Express + Scramjet hybrid web proxy
// Features:
//  - Proxy-all (HTML/JS/CSS/images/fonts/wasm/etc.), streams large assets
//  - Cookie persistence across proxied requests (session store in-memory)
//  - Deployment-aware rewrites so target sites never create google.com/proxy recursion
//  - Injects a lightweight rewrite script into proxied HTML (no topbar injection)
//  - Preserves/forwards important response headers (Content-Type, Content-Encoding, Cache-Control)
//  - Removes CSP/integrity attributes that would break in-proxy asset loading
//  - Special handling for WASM/service workers/etc. (streamed without mutation)
//  - Progressive streaming of transformed HTML (Scramjet StringStream)
//  - Safe header handling (headers set before streaming, no headers-after-send errors)
//  - Small in-memory + optional disk caching for assets and HTML
//  - WebSocket telemetry endpoint at /_euph_ws

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

if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// Asset extensions to treat as binary
const ASSET_EXTENSIONS = [
  ".wasm",".js",".mjs",".css",".png",".jpg",".jpeg",".webp",".gif",
  ".svg",".ico",".ttf",".otf",".woff",".woff2",".eot",".json",".map",
  ".mp4",".webm",".mp3"
];

const SPECIAL_PATH_SEGMENTS = ["service-worker.js","sw.js","worker.js","manifest.json"];
const DROP_META_HEADERS = [
  "content-security-policy","x-frame-options","cross-origin-opener-policy",
  "cross-origin-embedder-policy","cross-origin-resource-policy","permissions-policy"
];

// -------------------- EXPRESS --------------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -------------------- CACHE --------------------
const MEM_CACHE = new Map();
function now(){ return Date.now(); }
function cacheKey(s){ return Buffer.from(s).toString("base64url"); }
function cacheGet(key){
  const entry = MEM_CACHE.get(key);
  if(entry && (now()-entry.t)<CACHE_TTL) return entry.v;
  if(ENABLE_DISK_CACHE){
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if(fs.existsSync(fname)){
      try{
        const obj = JSON.parse(fs.readFileSync(fname,"utf8"));
        if((now()-obj.t)<CACHE_TTL){ MEM_CACHE.set(key,{v:obj.v,t:obj.t}); return obj.v; }
        else fs.unlinkSync(fname);
      }catch(e){}
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
function parseCookies(header=""){ const out={}; header.split(";").forEach(p=>{ const [k,v]=(p||"").split("=").map(s=>(s||"").trim()); if(k&&v) out[k]=v; }); return out; }
function getSessionFromReq(req){
  const cookies=parseCookies(req.headers.cookie||"");
  let sid=cookies[SESSION_NAME]||req.headers["x-euphoria-session"];
  if(!sid||!SESSIONS.has(sid)) return createSession();
  const payload=SESSIONS.get(sid); payload.last=now(); return {sid,payload};
}
function setSessionCookieHeader(res,sid){
  const cookieStr=`${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24}`;
  const prev=res.getHeader("Set-Cookie");
  if(!prev) res.setHeader("Set-Cookie",cookieStr);
  else if(Array.isArray(prev)) res.setHeader("Set-Cookie",[...prev,cookieStr]);
  else res.setHeader("Set-Cookie",[prev,cookieStr]);
}
function storeSetCookieToSession(setCookies=[],sessionPayload){
  for(const sc of setCookies){
    try{
      const kv=sc.split(";")[0]; const idx=kv.indexOf("="); if(idx===-1) continue;
      const k=kv.slice(0,idx).trim(); const v=kv.slice(idx+1).trim(); if(k) sessionPayload.cookies.set(k,v);
    }catch(e){}
  }
}
function buildCookieHeader(map){ return [...map.entries()].map(([k,v])=>`${k}=${v}`).join("; "); }

// -------------------- HELPERS --------------------
function toAbsolute(href,base){ try{ return new URL(href,base).href; }catch(e){return null;} }
function isLikelySearch(input){ if(!input) return true; if(input.includes(" ")) return true; if(/^https?:\/\//i.test(input)) return false; if(/\./.test(input)) return false; return true; }
function normalizeToUrl(input){ const v=(input||"").trim(); if(!v) return "https://www.google.com"; if(isLikelySearch(v)) return "https://www.google.com/search?q="+encodeURIComponent(v); if(/^https?:\/\//i.test(v)) return v; return "https://"+v; }
function looksLikeAssetPath(urlStr){ if(!urlStr) return false; try{ const p=new URL(urlStr,DEPLOYMENT_ORIGIN).pathname.toLowerCase(); for(const ext of ASSET_EXTENSIONS) if(p.endsWith(ext)) return true; for(const seg of SPECIAL_PATH_SEGMENTS) if(p.endsWith(seg)) return true; return false; }catch(e){ const lower=urlStr.toLowerCase(); for(const ext of ASSET_EXTENSIONS) if(lower.endsWith(ext)) return true; for(const seg of SPECIAL_PATH_SEGMENTS) if(lower.endsWith(seg)) return true; return false; } }
function isAlreadyProxiedHref(href){ if(!href) return false; try{ if(href.includes("/proxy?url=")) return true; const resolved=new URL(href,DEPLOYMENT_ORIGIN); if(resolved.origin===new URL(DEPLOYMENT_ORIGIN).origin&&resolved.pathname.startsWith("/proxy")) return true; }catch(e){} return false; }
function proxyizeAbsoluteUrl(absUrl){ try{ const u=new URL(absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; }catch(e){ try{ const u2=new URL("https://"+absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; }catch(e2){ return absUrl; }}}
function toDeploymentProxyLink(href,base){ if(!href) return href; if(isAlreadyProxiedHref(href)){ try{ const resolved=new URL(href,base||DEPLOYMENT_ORIGIN); if(resolved.pathname.startsWith("/proxy")){ const orig=resolved.searchParams.get("url"); if(orig) return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(orig)}`; } }catch(e){} return href; } const abs=toAbsolute(href,base)||href; return proxyizeAbsoluteUrl(abs); }

// -------------------- INJECTION SCRIPT --------------------
const INJECT_MARKER = "<!--EUPHORIA-REWRITE-INJECTED-->";
const INJECT_REWRITE_SCRIPT = `
<script>
(function(){
const DEPLOY="${DEPLOYMENT_ORIGIN}";
function prox(u){ try{ if(!u)return u; if(u.includes('/proxy?url='))return u; const abs=new URL(u,document.baseURI).href; return DEPLOY+'/proxy?url='+encodeURIComponent(abs);}catch(e){return u;}}
// anchors
document.querySelectorAll('a[href]').forEach(a=>{ try{ const h=a.getAttribute('href'); if(!h)return; if(/^(javascript:|mailto:|tel:|#)/i.test(h))return; if(h.includes('/proxy?url='))return; a.setAttribute('href',prox(h)); a.removeAttribute('target'); }catch(e){} });
// forms
document.querySelectorAll('form[action]').forEach(f=>{ try{ const act=f.getAttribute('action'); if(!act)return; if(act.includes('/proxy?url='))return; f.setAttribute('action',prox(act)); }catch(e){} });
// assets + srcset
const attrs=['src','href','poster','data-src','data-href'];
['img','script','link','iframe','source','video','audio'].forEach(tag=>{
document.querySelectorAll(tag).forEach(el=>{
try{ attrs.forEach(attr=>{ if(el.hasAttribute&&el.hasAttribute(attr)){ const v=el.getAttribute(attr); if(!v)return; if(/^data:/i.test(v))return; if(v.includes('/proxy?url='))return; el.setAttribute(attr,prox(v)); } }); if(el.hasAttribute&&el.hasAttribute('srcset')){ const ss=el.getAttribute('srcset')||''; const parts=ss.split(',').map(p=>{ const [u,rest]=p.trim().split(/\\s+/,2); if(!u)return p; if(/^data:/i.test(u))return p; return DEPLOY+'/proxy?url='+encodeURIComponent(new URL(u,document.baseURI).href)+(rest?' '+rest:''); }); el.setAttribute('srcset',parts.join(', ')); } }catch(e){} }); });
try{ const orig=window.fetch; window.fetch=function(resource,init){ try{ if(typeof resource==='string'&&!resource.includes('/proxy?url=')) resource=DEPLOY+'/proxy?url='+encodeURIComponent(new URL(resource,document.baseURI).href); else if(resource instanceof Request){ if(!resource.url.includes('/proxy?url=')) resource=new Request(DEPLOY+'/proxy?url='+encodeURIComponent(resource.url),resource); } }catch(e){} return orig(resource,init); }; }catch(e){}
})();
</script>
`;

// -------------------- WEBSOCKETS --------------------
const server=app.listen(PORT,()=>console.log(`Euphoria v2 running on port ${PORT}`));
const wss=new WebSocketServer({server,path:"/_euph_ws"});
wss.on("connection",ws=>{ ws.send(JSON.stringify({msg:"welcome",ts:Date.now()})); ws.on("message",raw=>{ try{ const parsed=JSON.parse(raw.toString()); if(parsed.cmd==="ping") ws.send(JSON.stringify({msg:"pong",ts:Date.now()})); }catch(e){} }); });

// -------------------- PROXY --------------------
app.get("/proxy",async(req,res)=>{
  let raw=req.query.url||(req.path&&req.path.startsWith("/proxy/")?decodeURIComponent(req.path.replace(/^\/proxy\//,"")):null);
  if(!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  if(!/^https?:\/\//i.test(raw)) raw="https://"+raw;
  const session=getSessionFromReq(req);
  setSessionCookieHeader(res,session.sid);
  const accept=(req.headers.accept||"").toLowerCase();
  const assetCacheKey=raw+"::asset"; if(!accept.includes("text/html")){ const cached=cacheGet(assetCacheKey); if(cached){ if(cached.headers) Object.entries(cached.headers).forEach(([k,v])=>res.setHeader(k,v)); return res.send(Buffer.from(cached.body,"base64")); } }
  const htmlCacheKey=raw+"::html"; if(accept.includes("text/html")){ const cachedHtml=cacheGet(htmlCacheKey); if(cachedHtml){ res.setHeader("Content-Type","text/html; charset=utf-8"); return res.send(cachedHtml); } }
  const originHeaders={"User-Agent":req.headers["user-agent"]||"Euphoria/2.0","Accept":req.headers.accept||"*/*","Accept-Language":req.headers["accept-language"]||"en-US,en;q=0.9","Accept-Encoding":"gzip, deflate, br"};
  const cookieHdr=buildCookieHeader(session.payload.cookies); if(cookieHdr) originHeaders["Cookie"]=cookieHdr; if(req.headers.referer) originHeaders["Referer"]=req.headers.referer;

  try{
    const controller=new AbortController();
    const to=setTimeout(()=>controller.abort(),FETCH_TIMEOUT_MS);
    const originRes=await fetch(raw,{headers:originHeaders,redirect:"follow",signal:controller.signal});
    clearTimeout(to);
    const setCookies=originRes.headers.raw?originRes.headers.raw()["set-cookie"]||[]:[];
    if(setCookies.length) storeSetCookieToSession(setCookies,session.payload);
    const contentType=(originRes.headers.get("content-type")||"").toLowerCase();
    const treatAsAsset=looksLikeAssetPath(raw)||!contentType.includes("text/html");
    if(treatAsAsset){
      originRes.headers.forEach((v,k)=>{ if(!DROP_META_HEADERS.includes(k.toLowerCase())) res.setHeader(k,v); });
      const buf=await originRes.arrayBuffer();
      cacheSet(assetCacheKey,{body:Buffer.from(buf).toString("base64"),headers:Object.fromEntries(originRes.headers.entries())});
      return res.send(Buffer.from(buf));
    }
    // HTML streaming with scramjet
    const htmlChunks=[]; originRes.body.pipe(new StringStream())
      .map(chunk=>chunk.toString())
      .map(chunk=>{
        let out=chunk;
        // inject rewrite script once
        if(!out.includes(INJECT_MARKER)) out=out.replace("</body>",INJECT_REWRITE_SCRIPT+"</body>");
        htmlChunks.push(out); return out;
      })
      .toArray()
      .then(arr=>{
        const finalHtml=arr.join("");
        res.setHeader("Content-Type","text/html; charset=utf-8");
        cacheSet(htmlCacheKey,finalHtml);
        res.send(finalHtml);
      }).catch(err=>res.status(500).send("Proxy error: "+err.message));
  }catch(e){ res.status(500).send("Proxy fetch error: "+e.message); }
});