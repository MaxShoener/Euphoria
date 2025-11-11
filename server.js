// server.js
// Euphoria: WebSocket WISP-style proxy backend (no iframe, no headless browsers).
// - HTTP endpoints: / (static), /asset?url=..., /health
// - WebSocket endpoint: /wisp  (multiplexed messages: { id, method, url, headers, body })
// - Caches: small LRU for HTML and assets
// - Rewrites HTML: remove CSP meta, inject topbar+containment script, rewrite CSS url(...) -> /asset, rewrite assets -> /asset
// - Streams binary assets back with proper content-type

import express from "express";
import { createServer } from "http";
import { WebSocketServer } from "ws";
import fetch from "node-fetch";
import compression from "compression";
import morgan from "morgan";
import { LRUCache } from "lru-cache";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import cookie from "cookie";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server, path: "/wisp" });

const PORT = process.env.PORT || 3000;
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes

app.use(morgan("tiny"));
app.use(compression());
app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));

// LRU caches
const htmlCache = new LRUCache({ max: 200, ttl: CACHE_TTL });
const assetCache = new LRUCache({ max: 500, ttl: CACHE_TTL });

function now() { return Date.now(); }
function isLikelySearch(q) {
  if (!q) return true;
  if (q.includes(" ")) return true;
  if (/^https?:\/\//i.test(q)) return false;
  if (/\./.test(q)) return false;
  return true;
}
function normalizeInputToUrl(v) {
  v = (v || "").trim();
  if (!v) return "https://www.google.com";
  if (isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}
function safeEncode(u){ try{ return encodeURIComponent(u); }catch{ return encodeURIComponent(String(u)); } }

function removeMetaCSP(html) {
  return html.replace(/<meta[^>]*http-equiv=(["'])?content-security-policy\1[^>]*>/ig, "");
}

function stripIntegrityAttrs(html) {
  html = html.replace(/\sintegrity=(["'])(.*?)\1/ig, "");
  html = html.replace(/\scrossorigin=(["'])(.*?)\1/ig, "");
  return html;
}

function rewriteAssetUrls(html, base) {
  // replace src/href/srcset and CSS url(...) occurrences to point to /asset?url=...
  html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?(?:src|href)=)(["'])([^"']*)\2/ig, (m, pre, q, val) => {
    if (!val) return m;
    if (/^data:/i.test(val)) return m;
    if (/^\/asset\?url=/i.test(val)) return m; // already proxied
    if (/^\/proxy\?url=/i.test(val)) return m;
    if (/^https?:\/\//i.test(val) || val.startsWith("/")) {
      const abs = toAbsolute(val, base) || val;
      return `${pre}${q}/asset?url=${safeEncode(abs)}${q}`;
    }
    try {
      const abs = new URL(val, base).href;
      return `${pre}${q}/asset?url=${safeEncode(abs)}${q}`;
    } catch {
      return m;
    }
  });

  // srcset
  html = html.replace(/\ssrcset=(["'])(.*?)\1/ig, (m, q, val) => {
    if (!val) return m;
    const parts = val.split(",").map(p => {
      p = p.trim();
      const [url, rest] = p.split(/\s+/, 2);
      if (!url) return p;
      if (/^data:/i.test(url)) return p;
      const abs = toAbsolute(url, base) || url;
      return `/asset?url=${safeEncode(abs)}` + (rest ? " " + rest : "");
    });
    return ` srcset=${q}${parts.join(", ")}${q}`;
  });

  // CSS url(...)
  html = html.replace(/url\((['"]?)(.*?)\1\)/ig, (m, q, val) => {
    if (!val) return m;
    if (/^data:/i.test(val)) return m;
    const abs = toAbsolute(val, base) || val;
    return `url("/asset?url=${safeEncode(abs)}")`;
  });

  return html;
}

const TOPBAR_INJECTION = `
<!-- EUPHORIA TOPBAR -->
<div id="euphoria-topbar" style="position:fixed;top:14px;left:50%;transform:translateX(-50%);width:80%;max-width:1200px;background:rgba(12,12,12,0.95);border-radius:26px;padding:8px 12px;display:flex;align-items:center;gap:10px;z-index:2147483647;box-shadow:0 6px 20px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
  <button id="eph-back" aria-label="Back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" aria-label="Forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" aria-label="Refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" aria-label="Home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" aria-label="Address" style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" placeholder="Enter URL or search..." />
  <button id="eph-go" aria-label="Go" style="min-width:64px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" aria-label="Fullscreen" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
</div>
<style>html,body{padding-top:76px !important;background:transparent !important;}</style>

<script>
// Containment script to make dynamic links/forms send messages to the Euphoria frontend (via window.__EUPHORIA_WISP)
(function(){
  try{
    const toAbsolute = (h) => { try { return new URL(h, document.baseURI).href; } catch { return h; } };
    const ipc = window.__EUPHORIA_WISP; // injected by client when inserting HTML; fallback: perform normal navigation
    function hookAnchors(root){
      root.querySelectorAll && root.querySelectorAll('a[href]').forEach(a=>{
        try{
          const href = a.getAttribute('href') || '';
          if(!href) return;
          if(/^javascript:|^mailto:|^tel:|^#/i.test(href)) return;
          if(href.startsWith('/asset?url=') || href.startsWith('/proxy?url=')) {
            // allow; these will be direct asset/proxy requests
          } else {
            const abs = toAbsolute(href);
            a.setAttribute('href', abs);
            a.removeAttribute('target');
            a.addEventListener('click', function(ev){
              if(ipc && ipc.sendRequest){
                ev.preventDefault();
                ipc.sendRequest({ url: abs, method: 'GET' });
              }
            }, { capture:true });
          }
        }catch(e){}
      });
    }
    function hookForms(root){
      root.querySelectorAll && root.querySelectorAll('form').forEach(f=>{
        try{
          const action = f.getAttribute('action') || '';
          if(!action) return;
          if(action.startsWith('/asset?url=') || action.startsWith('/proxy?url=')) return;
          const abs = toAbsolute(action);
          f.setAttribute('data-euphoria-action', abs);
          f.addEventListener('submit', function(ev){
            try{
              ev.preventDefault();
              const formData = new FormData(f);
              const params = new URLSearchParams();
              for(const [k,v] of formData.entries()) params.append(k,v);
              if(window.__EUPHORIA_WISP && window.__EUPHORIA_WISP.sendRequest){
                window.__EUPHORIA_WISP.sendRequest({ url: abs, method: (f.method||'GET').toUpperCase(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params.toString() });
              } else {
                // fallback
                fetch(abs, { method: (f.method||'GET').toUpperCase(), body: params });
              }
            }catch(e){}
          }, { capture:true });
        }catch(e){}
      });
    }
    function mutateAndHook(){
      hookAnchors(document);
      hookForms(document);
      new MutationObserver((muts)=>{
        muts.forEach(mut=>{
          mut.addedNodes && mut.addedNodes.forEach(n=>{
            if(n.nodeType!==1) return;
            hookAnchors(n);
            hookForms(n);
          });
        });
      }).observe(document.documentElement||document, { childList:true, subtree:true });
    }
    // run after small delay
    setTimeout(mutateAndHook, 200);
  }catch(e){}
})();
</script>
`;

// --- /asset endpoint: proxies binary/text assets directly (with caching) ---
app.get("/asset", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const url = raw;
  try {
    const cached = assetCache.get(url);
    if (cached) {
      if (cached.headers) Object.entries(cached.headers).forEach(([k, v]) => res.setHeader(k, v));
      const buf = Buffer.from(cached.body, "base64");
      return res.send(buf);
    }

    const controller = new AbortController();
    const timeout = setTimeout(()=>controller.abort(), 20000);
    const r = await fetch(url, { redirect: "follow", signal: controller.signal, headers: { "User-Agent": "Euphoria/1.0" } });
    clearTimeout(timeout);

    const contentType = r.headers.get("content-type") || "application/octet-stream";
    const arr = await r.arrayBuffer();
    const buf = Buffer.from(arr);

    res.setHeader("Content-Type", contentType);
    const cacheControl = r.headers.get("cache-control");
    if (cacheControl) res.setHeader("Cache-Control", cacheControl);

    // small assets cached in LRU
    try {
      if (buf.length < 100 * 1024) {
        assetCache.set(url, { headers: { "Content-Type": contentType }, body: buf.toString("base64"), t: now() });
      }
    } catch (e) {}

    return res.send(buf);
  } catch (err) {
    console.error("Asset fetch error:", err && err.message ? err.message : err);
    return res.status(502).send("Asset fetch error: " + (err && err.message ? err.message : "unknown"));
  }
});

// Health
app.get("/health", (req, res) => res.send({ ok: true }));

// --- WISP-style WebSocket: multiplexed request/response pairs ---
// Messages from client:
// { id: "uuid", method: "GET", url: "https://...", headers: {...}, body: string|null }
// Response:
// { id, status, headers, body }  (body is text/html or base64 for binary with isBinary: true flag)
wss.on("connection", (ws, req) => {
  ws.isAlive = true;
  ws.on("pong", () => ws.isAlive = true);

  // attach helper so injected pages can call back via window.__EUPHORIA_WISP (client sets this)
  ws.on("message", async (message) => {
    let msg;
    try {
      msg = JSON.parse(message.toString());
    } catch (e) {
      ws.send(JSON.stringify({ error: "invalid json" }));
      return;
    }
    if (!msg || !msg.id || !msg.url) {
      ws.send(JSON.stringify({ error: "invalid message format (need id and url)" }));
      return;
    }

    const id = msg.id;
    const method = (msg.method || "GET").toUpperCase();
    const headers = Object.assign({}, msg.headers || {}, { "User-Agent": msg.userAgent || "Euphoria-WISP/1.0" });
    const body = msg.body || null;

    // quick normalize for searches/simple hostnames
    let target = msg.url;
    if (!/^https?:\/\//i.test(target)) target = normalizeInputToUrl(target);

    // caching: cache HTML keyed by final URL
    try {
      const cacheKey = target;
      if (method === "GET") {
        const cached = htmlCache.get(cacheKey);
        if (cached) {
          ws.send(JSON.stringify({ id, status: 200, headers: { "content-type": "text/html; charset=utf-8", fromCache: "true" }, body: cached }));
          return;
        }
      }

      // fetch origin
      const controller = new AbortController();
      const timeout = setTimeout(()=>controller.abort(), 20000);
      const fetchOpts = { method, headers, redirect: "follow", signal: controller.signal };
      if (body && method !== "GET" && method !== "HEAD") fetchOpts.body = body;
      const originRes = await fetch(target, fetchOpts);
      clearTimeout(timeout);

      const contentType = originRes.headers.get("content-type") || "";

      // Save cookies from origin? (very lightweight: we don't maintain cookies across requests here)
      // If needed later, we can persist per-socket cookie jars.

      // Binary asset
      if (!contentType.includes("text/html")) {
        const arr = await originRes.arrayBuffer();
        const buf = Buffer.from(arr);
        const b64 = buf.toString("base64");
        // send binary as base64 with isBase64 flag
        ws.send(JSON.stringify({
          id, status: originRes.status,
          headers: Object.fromEntries(originRes.headers.entries()),
          isBase64: true,
          body: b64
        }));
        return;
      }

      // HTML path
      let html = await originRes.text();

      // Transformations
      html = removeMetaCSP(html);
      html = stripIntegrityAttrs(html);

      const finalUrl = originRes.url || target;

      // inject a base tag if missing to help relative URL resolution
      if (/<head[\s>]/i.test(html)) {
        html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
      } else {
        html = `<base href="${finalUrl}">` + html;
      }

      // rewrite assets to point at /asset
      html = rewriteAssetUrls(html, finalUrl);

      // Inject topbar + containment so when the client inserts html into DOM anchors/forms are handled
      if (/<body[\s>]/i.test(html)) {
        html = html.replace(/<body([^>]*)>/i, (m) => m + TOPBAR_INJECTION);
      } else {
        html = TOPBAR_INJECTION + html;
      }

      // cache and respond
      if (originRes.status === 200 && method === "GET") {
        try { htmlCache.set(target, html); } catch(e) {}
      }

      ws.send(JSON.stringify({
        id,
        status: originRes.status,
        headers: Object.fromEntries(originRes.headers.entries()),
        body: html
      }));
    } catch (err) {
      console.error("WISP fetch error:", err && err.message ? err.message : err);
      ws.send(JSON.stringify({ id, status: 502, error: (err && err.message) || String(err) }));
    }
  });
});

// keepalive for websockets
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping(() => {});
  });
}, 30000);

server.listen(PORT, () => {
  console.log(`Euphoria WISP server listening on http://localhost:${PORT}`);
});