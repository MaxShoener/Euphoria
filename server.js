import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { StringStream } from "scramjet";
import { WebSocketServer } from "ws";

const __filename=fileURLToPath(import.meta.url);
const __dirname=path.dirname(__filename);
const app=express();
const PORT=parseInt(process.env.PORT||"3000",10);

// middleware
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({threshold:1024}));
app.use(express.urlencoded({extended:false}));
app.use(express.json());
app.use(express.static(path.join(__dirname,"public"),{index:false}));

// Simple in-memory session
const SESSIONS=new Map();
function makeSid(){return Math.random().toString(36).slice(2)+Date.now().toString(36);}
function getSession(req){ let sid=req.headers["x-euphoria-session"]; if(!sid||!SESSIONS.has(sid)){sid=makeSid(); SESSIONS.set(sid,{cookies:new Map()});} return {sid, payload:SESSIONS.get(sid)};}
function setSessionCookie(res,sid){ res.setHeader("Set-Cookie",`euphoria_sid=${sid}; Path=/; HttpOnly; Max-Age=${60*60*24}`);}
function buildCookieHeader(map){return [...map.entries()].map(([k,v])=>k+'='+v).join('; ');}
function storeSetCookie(setCookies,map){for(const sc of setCookies||[]){try{const [k,v]=sc.split(';')[0].split('='); if(k)v&&map.set(k,v);}catch{} }}

// Helpers
function toAbsolute(href, base){try{return new URL(href, base).href}catch{return null;}}
function extractProxyUrl(req){return req.query.url||null;}
function normalizeUrl(raw){ if(!/^https?:\/\//i.test(raw)) raw='https://'+raw; return raw; }

// --- clean INJECT: only URL rewriting ---
const INJECT=`<script>
(function(){
  function proxifyURL(url){try{const u=new URL(url,window.location.href);return '/proxy?url='+encodeURIComponent(u.href);}catch(e){return url;}}
  document.querySelectorAll('a[href]').forEach(a=>{const h=a.getAttribute('href');if(h&&!/^javascript:|mailto:|tel:|#/.test(h)){a.href=proxifyURL(h);a.target='_self';}});
  document.querySelectorAll('form[action]').forEach(f=>{const h=f.getAttribute('action');if(h)f.action=proxifyURL(h);});
  ['img','script','link','iframe','video','audio','source'].forEach(tag=>{document.querySelectorAll(tag).forEach(el=>{['src','href'].forEach(attr=>{const v=el.getAttribute(attr);if(v&&!/^data:/.test(v))el.setAttribute(attr,proxifyURL(v));});});});
})();
</script>`;

// WebSocket server
const server=app.listen(PORT,()=>console.log(`Euphoria running on port ${PORT}`));
const wss=new WebSocketServer({server,path:"/_euph_ws"});
wss.on("connection",ws=>{ ws.send(JSON.stringify({msg:"welcome"})); ws.on("message",m=>{ try{const p=JSON.parse(m.toString()); if(p.cmd==="ping") ws.send(JSON.stringify({msg:"pong"}));}catch{} });});

// Main proxy endpoint
app.get("/proxy", async (req,res)=>{
  let raw=extractProxyUrl(req);
  if(!raw) return res.status(400).send("Missing url");

  const session=getSession(req);
  setSessionCookie(res,session.sid);

  const headers={"User-Agent": req.headers["user-agent"]||"Euphoria/1.0","Accept":req.headers.accept||"*/*","Accept-Language":req.headers["accept-language"]||"en-US,en;q=0.9"};
  const cookieHdr=buildCookieHeader(session.payload.cookies); if(cookieHdr) headers.Cookie=cookieHdr;

  try{
    const originRes=await fetch(normalizeUrl(raw),{headers,redirect:"follow"});
    const setCookies=originRes.headers.raw ? originRes.headers.raw()["set-cookie"]||[] : [];
    storeSetCookie(setCookies,session.payload.cookies);
    const contentType=(originRes.headers.get("content-type")||"").toLowerCase();

    if(!contentType.includes("text/html")){
      const arr=await originRes.arrayBuffer();
      res.setHeader("Content-Type",contentType);
      return res.send(Buffer.from(arr));
    }

    let html=await originRes.text();
    html=html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi,"");
    html=html.replace(/\s+integrity=(["'])(.*?)\1/gi,"").replace(/\s+crossorigin=(["'])(.*?)\1/gi,"");
    const finalUrl=originRes.url||raw;
    if(/<head[\s>]/i.test(html)) html=html.replace(/<head([^>]*)>/i,`<head$1><base href="${finalUrl}">`);
    else html=`<base href="${finalUrl}">`+html;

    // Inject only URL rewriting script
    if(/<body[^>]*>/i.test(html)) html=html.replace(/<body([^>]*)>/i,`<body$1>`+INJECT);
    else html=INJECT+html;

    res.setHeader("Content-Type","text/html; charset=utf-8");
    const stream=StringStream.from(html);
    stream.pipe(res);
    stream.on("end",()=>res.end());
    stream.on("error",()=>res.end());
  }catch(err){
    console.error("Proxy error:",err);
    res.status(500).send(`<div style="padding:1rem;background:#fee;color:#900;font-family:system-ui;">Proxy error: ${(err.message)||String(err)}</div>`);
  }
});

// fallback to index.html
app.use((req,res,next)=>{if(req.method==="GET"&&req.accepts&&req.accepts("html")) return res.sendFile(path.join(__dirname,"public","index.html")); next();});
