// server.js — updated: streaming + non-blocking + proper headers + srcset fixes
import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { StringStream } from "scramjet";
import { WebSocketServer } from "ws";
import { pipeline } from "stream";
import { promisify } from "util";

const pipe = promisify(pipeline);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

// middleware
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// --- In-memory session/cookie store (simple) ---
const SESSIONS = new Map();
function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: Date.now() }; SESSIONS.set(sid, payload); return { sid, payload }; }
function getSessionFromReq(req) {
  const cookieHeader = req.headers.cookie || "";
  const parsed = {};
  cookieHeader.split(";").forEach(p => {
    const [k, v] = (p || "").split("=").map(s => (s || "").trim());
    if (k && v) parsed[k] = v;
  });
  let sid = parsed["euphoria_sid"] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid);
  payload.last = Date.now();
  return { sid, payload };
}
function setSessionCookieHeader(res, sid) {
  const cookieStr = `euphoria_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function storeSetCookieToSession(setCookies, sessionPayload) {
  for (const sc of setCookies || []) {
    try {
      const kv = sc.split(";")[0];
      const idx = kv.indexOf("=");
      if (idx === -1) continue;
      const k = kv.slice(0, idx).trim();
      const v = kv.slice(idx + 1).trim();
      if (k) sessionPayload.cookies.set(k, v);
    } catch (e) { /* ignore */ }
  }
}
function buildCookieHeader(map) {
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

// --- Simple memory cache ONLY (no blocking disk writes) ---
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 6;
function now() { return Date.now(); }
function cacheGet(key) {
  const entry = MEM_CACHE.get(key);
  if (entry && (now() - entry.t) < CACHE_TTL) return entry.v;
  return null;
}
function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
}

// --- Helpers ---
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function looksLikeSearch(input) {
  if (!input) return true;
  if (input.includes(" ")) return true;
  if (/^https?:\/\//i.test(input)) return false;
  if (/\./.test(input)) return false;
  return true;
}
function normalizeToUrl(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (looksLikeSearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// Minimal injection (no duplicate topbars) — only URL rewriting + small loading script
const INJECT = `
<script>
(function(){
  function proxifyURL(u){ try{ const abs = new URL(u, document.baseURI).href; return '/proxy?url=' + encodeURIComponent(abs); }catch(e){ return u; } }
  // anchors
  document.querySelectorAll('a[href]').forEach(a=>{
    try {
      const href = a.getAttribute('href');
      if(!href) return;
      if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if(href.startsWith('/proxy?url=')) return;
      a.setAttribute('href', proxifyURL(href));
      a.removeAttribute('target');
    } catch(e){}
  });
  // forms
  document.querySelectorAll('form[action]').forEach(f=>{
    try {
      const a = f.getAttribute('action'); if(!a) return;
      if(a.startsWith('/proxy?url=')) return;
      f.setAttribute('action', proxifyURL(a));
    } catch(e){}
  });
  // src / href attributes for many tags, and srcset handling
  const tags = ['img','script','link','iframe','source','video','audio'];
  tags.forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      ['src','href'].forEach(attr=>{
        try {
          const v = el.getAttribute(attr); if(!v) return;
          if(/^data:/i.test(v)) return;
          if(v.startsWith('/proxy?url=')) return;
          el.setAttribute(attr, proxifyURL(v));
        } catch(e){}
      });
      // srcset
      try {
        if(el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset');
          if(ss){
            const parts = ss.split(',').map(p=>{
              const [url, rest] = p.trim().split(/\s+/,2);
              if(!url) return p;
              if(/^data:/i.test(url)) return p;
              return '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href) + (rest? ' ' + rest : '');
            });
            el.setAttribute('srcset', parts.join(', '));
          }
        }
      } catch(e){}
    });
  });
  // CSS url(...) rewriting in style tags (best-effort)
  try {
    document.querySelectorAll('style').forEach(s=>{
      try {
        let t = s.textContent;
        if(!t) return;
        t = t.replace(/url\\((['"]?)([^'")]+)\\1\\)/g, function(full, q, u){
          if(!u) return full;
          if(/^data:/i.test(u)) return full;
          try{ const abs = new URL(u, document.baseURI).href; return 'url("/proxy?url=' + encodeURIComponent(abs) + '")'; }catch(e){ return full; }
        });
        s.textContent = t;
      } catch(e){}
    });
  } catch(e){}
  // intercept fetch to proxy XHR/fetch calls
  try {
    const __origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.startsWith('/proxy?url=')){
          resource = '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        } else if(resource instanceof Request){
          resource = new Request('/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      } catch(e){}
      return __origFetch(resource, init);
    };
  } catch(e){}
})();
</script>
`;

// --- WebSocket telemetry ---
const server = app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try {
      const parsed = JSON.parse(raw.toString());
      if (parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch (e) { /* ignore */ }
  });
});

// --- Main proxy endpoint ---
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // Normalize human-entered hosts like "google.com"
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSessionFromReq(req);
  setSessionCookieHeader(res, session.sid);

  // Build outgoing headers for origin request
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    // allow compressed responses so we can forward Content-Encoding
    "Accept-Encoding": "gzip, deflate, br",
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) headers["Cookie"] = cookieHdr;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    // small timeout guard
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);

    // fetch origin with redirect: follow
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // capture set-cookie
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    const contentType = (originRes.headers.get("content-type") || "").toLowerCase();

    // If non-HTML (images, fonts, js, css, video...), stream directly (fast)
    if (!contentType.includes("text/html")) {
      // Forward key headers
      const cencoding = originRes.headers.get("content-encoding");
      const clen = originRes.headers.get("content-length");
      const cacheControl = originRes.headers.get("cache-control");

      if (contentType) res.setHeader("Content-Type", contentType);
      if (cencoding) res.setHeader("Content-Encoding", cencoding);
      if (clen) res.setHeader("Content-Length", clen);
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      // allow browser to use proxied resources in cross-origin contexts
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Vary", "Accept-Encoding");

      setSessionCookieHeader(res, session.sid);

      // Stream origin body to client WITHOUT buffering whole body
      if (originRes.body && typeof originRes.body.pipe === "function") {
        // originRes.body is a Node Readable stream — pipeline it to res
        await pipe(originRes.body, res);
        return;
      } else {
        // Fallback: buffer then send (should be rare)
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        res.send(buf);
        return;
      }
    }

    // HTML path: small transformations (strip CSP meta, integrity/cors attrs, inject base, rewrite assets)
    let html = await originRes.text();

    // Remove CSP meta tags (they often block our injections)
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // strip integrity/crossorigin attributes that break proxied assets
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

    const finalUrl = originRes.url || raw;
    // Inject <base href="finalUrl"> to help resolving relative URLs
    if (/<head[\s>]/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // Rewrite anchors to /proxy?url=abs
    html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, function (m, pre, q, val) {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // Rewrite common asset tags (img/script/link/source/video/audio/iframe)
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?)(\b(?:src|href|srcset)=)(["'])([^"']*)\3/gi, function (m, prefix, attr, q, val) {
      if (!val) return m;
      if (val.startsWith("/proxy?url=") || /^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      // handle srcset specially — although this will also be caught in client-side injection
      if (attr.toLowerCase() === "srcset=") {
        // convert each candidate
        const parts = val.split(",").map(p => {
          const [u, rest] = p.trim().split(/\s+/, 2);
          if (!u) return p;
          if (/^data:/i.test(u)) return p;
          const a = toAbsolute(u, finalUrl) || u;
          return `/proxy?url=${encodeURIComponent(a)}` + (rest ? " " + rest : "");
        });
        return `${prefix}${attr}${q}${parts.join(", ")}${q}`;
      }
      return `${prefix}${attr}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // Rewrite CSS url(...) occurrences
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, function (m, q, val) {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Rewrite form actions
    html = html.replace(/(<\s*form\b[^>]*?\baction=)(["'])([^"']*)\2/gi, function (m, pre, q, val) {
      if (!val) return m;
      if (val.startsWith("/proxy?url=")) return m;
      if (/^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // Meta refresh rewrite
    html = html.replace(/<meta[^>]*http-equiv=(["']?)refresh\1[^>]*>/gi, function (m) {
      const match = m.match(/content\s*=\s*["']([^"']*)["']/i);
      if (!match) return m;
      const parts = match[1].split(";");
      if (parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
      if (!urlPart) return m;
      const dest = urlPart[1].replace(/['"]/g, "").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // Remove some analytics/tracker scripts (best-effort)
    html = html.replace(/<script[^>]+src=(["'])[^\1>]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication|googlesyndication)[^"']*\1[^>]*>(?:\s*<\/script>)?/gi, "");
    html = html.replace(/<script[^>]*>\s*window\.ga=.*?<\/script>/gi, "");

    // Inject minimal INJECT script for dynamic rewriting on the client side (no extra topbars)
    if (/<body[^>]*>/i.test(html)) {
      html = html.replace(/<body([^>]*)>/i, (m, g) => `<body${g}>` + INJECT);
    } else {
      html = INJECT + html;
    }

    // Cache HTML in memory
    try { cacheSet(raw + "::html", html); } catch (e) { /* ignore cache errors */ }

    // Send HTML progressively — StringStream is fine for this use
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Access-Control-Allow-Origin", "*");
    setSessionCookieHeader(res, session.sid);

    const stream = StringStream.from(html);
    await pipe(stream, res);
    return;
  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : err);
    setSessionCookieHeader(res, session.sid);
    return res.status(500).send(`<div style="padding:1rem;background:#fee;color:#900;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// fallback to frontend
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});
