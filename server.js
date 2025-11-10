// server.js
// Euphoria proxy (no iframe) - streams and rewrites pages, caches, handles redirects
import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet"; // scramjet is CommonJS -> default import then destructure
const { StringStream } = pkg;
import LRU from "lru-cache";
import compression from "compression";
import fs from "fs";
import path from "path";
import { URL } from "url";

const __dirname = path.resolve();

// Config
const PORT = Number(process.env.PORT || 3000);
const CACHE_TTL_MS = 1000 * 60 * 6; // 6 minutes
const CACHE_MAX_ITEMS = 200;
const DISK_CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(DISK_CACHE_DIR)) fs.mkdirSync(DISK_CACHE_DIR, { recursive: true });

// LRU in-memory cache (stores HTML or small assets)
const cache = new LRU({ max: CACHE_MAX_ITEMS, ttl: CACHE_TTL_MS });

const app = express();
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Helpers
function cacheKeyFor(url) {
  return Buffer.from(url).toString("base64url");
}
function readDiskCache(url) {
  try {
    const key = cacheKeyFor(url);
    const fp = path.join(DISK_CACHE_DIR, key);
    if (!fs.existsSync(fp)) return null;
    const raw = fs.readFileSync(fp, "utf8");
    const obj = JSON.parse(raw);
    if (Date.now() - obj.t > CACHE_TTL_MS) {
      try { fs.unlinkSync(fp); } catch(e) {}
      return null;
    }
    return obj.body;
  } catch (e) {
    return null;
  }
}
function writeDiskCache(url, body) {
  try {
    const key = cacheKeyFor(url);
    const fp = path.join(DISK_CACHE_DIR, key);
    fs.writeFileSync(fp, JSON.stringify({ t: Date.now(), body }), "utf8");
  } catch (e) {}
}
function setCache(url, body) {
  cache.set(url, body);
  writeDiskCache(url, body);
}
function getCache(url) {
  const m = cache.get(url);
  if (m) return m;
  const disk = readDiskCache(url);
  if (disk) {
    cache.set(url, disk);
    return disk;
  }
  return null;
}

function isLikelySearch(v) {
  if (!v) return true;
  if (v.includes(" ")) return true;
  if (/^https?:\/\//i.test(v)) return false;
  if (!v.includes(".")) return true;
  return false;
}
function normalizeUserInput(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (isLikelySearch(v)) return `https://www.google.com/search?q=${encodeURIComponent(v)}`;
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}
function toAbsolute(url, base) {
  try { return new URL(url, base).href; } catch (e) { return null; }
}

// Strip CSP/integrity/crossorigin/meta-refresh and remove known analytics scripts
function sanitizeHTMLForProxy(html) {
  // remove content-security-policy meta tags
  html = html.replace(/<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");
  // remove integrity attrs and crossorigin attrs
  html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
  html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");
  // remove strict-referrer meta and other restrictive meta tags (best-effort)
  html = html.replace(/<meta[^>]*(referrer|referrer-policy|permissions-policy)[^>]*>/gi, "");
  // remove known analytics script tags that load external libs (best-effort)
  html = html.replace(/<script[^>]*src=(["'])[^\1]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^\1]*\1[^>]*><\/script>/gi, "");
  html = html.replace(/<script[^>]*>.*?(?:googletagmanager|gtag|analytics|doubleclick|googlesyndication).*?<\/script>/gsi, "");
  return html;
}

// Rewrite links and assets to go through /proxy?url= absolute
function rewriteResources(html, baseUrl) {
  // add <base> to keep relative resolution working for scripts that query document.baseURI
  if (/<head[\s>]/i.test(html)) {
    html = html.replace(/<head([^>]*)>/i, `<head$1><base href="${baseUrl}">`);
  } else {
    html = `<base href="${baseUrl}">` + html;
  }

  // href/src/srcset attributes
  html = html.replace(/(href|src|action)=["']([^"']*)["']/gi, (m, attr, val) => {
    if (!val) return m;
    if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
    if (/^data:/i.test(val)) return m;
    if (val.startsWith("/proxy?url=")) return m;
    const abs = toAbsolute(val, baseUrl);
    if (!abs) return m;
    return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
  });

  // srcset handling
  html = html.replace(/srcset=\s*"(.*?)"/gi, (m, val) => {
    if (!val) return m;
    try {
      const parts = val.split(",").map(p => {
        const [u, rest] = p.trim().split(/\s+/, 2);
        if (!u || /^data:/i.test(u)) return p.trim();
        const abs = toAbsolute(u, baseUrl) || u;
        return `/proxy?url=${encodeURIComponent(abs)}` + (rest ? " " + rest : "");
      });
      return `srcset="${parts.join(",")}"`;
    } catch (e) { return m; }
  });

  // CSS url(...) -> proxied
  html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
    if (!u) return m;
    if (/^data:/i.test(u)) return m;
    const abs = toAbsolute(u, baseUrl) || u;
    return `url("/proxy?url=${encodeURIComponent(abs)}")`;
  });

  // meta refresh -> rewrite to proxy
  html = html.replace(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*>/gi, (m) => {
    const match = m.match(/content\s*=\s*["']([^"']+)["']/i);
    if (!match) return m;
    const parts = match[1].split(";");
    if (parts.length < 2) return m;
    const urlPart = parts.slice(1).join(";");
    const um = urlPart.match(/url=(.*)/i);
    if (!um) return m;
    const dest = um[1].replace(/['"]/g, "").trim();
    const abs = toAbsolute(dest, baseUrl) || dest;
    return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
  });

  return html;
}

// Inject the topbar/containment script into the proxied HTML (so navigation remains inside /proxy)
function injectTopbarAndContainment(html, finalUrl) {
  const topbar = `
  <!-- EUPHORIA TOPBAR INJECTED -->
  <div id="euphoria-topbar" style="position:fixed;top:14px;left:50%;transform:translateX(-50%);width:86%;max-width:1200px;background:#111;border-radius:28px;padding:8px 12px;display:flex;align-items:center;gap:8px;z-index:2147483647;box-shadow:0 8px 30px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
    <button id="eph-back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
    <button id="eph-forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
    <button id="eph-refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
    <button id="eph-home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
    <input id="eph-input" placeholder="Enter URL or search..." style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" />
    <button id="eph-go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
    <button id="eph-full" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
  </div>
  <style>body{padding-top:76px !important;background:transparent !important;}</style>
  <script>
  (function(){
    // containment script to keep navigation inside /proxy
    const toLoad = (href) => '/proxy?url=' + encodeURIComponent(href);
    const absolute = (h) => { try { return new URL(h, document.baseURI).href; } catch(e) { return h; } };
    const input = document.getElementById('eph-input');
    const go = document.getElementById('eph-go');
    document.getElementById('eph-back').onclick = () => history.back();
    document.getElementById('eph-forward').onclick = () => history.forward();
    document.getElementById('eph-refresh').onclick = () => location.reload();
    document.getElementById('eph-home').onclick = () => location.href = toLoad('https://www.google.com');
    document.getElementById('eph-full').onclick = () => { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };
    try { const m = location.search.match(/[?&]url=([^&]+)/); if (m) input.value = decodeURIComponent(m[1]); } catch(e){}
    function normalize(v){
      v = (v||'').trim();
      if(!v) return 'https://www.google.com';
      if (v.indexOf(' ') !== -1 || (!v.includes('.') && !v.startsWith('http'))) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
      try { new URL(v); return v; } catch(e) {}
      return 'https://' + v;
    }
    go.onclick = () => {
      const val = input.value;
      if (/\\/proxy\\?url=/i.test(val)) { location.href = val; return; }
      const u = normalize(val);
      location.href = toLoad(u);
    };
    input.addEventListener('keydown', e => { if (e.key === 'Enter') go.onclick(); });
    // rewrite anchors/assets already on page
    function absoluteHref(h){ try { return new URL(h, document.baseURI).href; } catch(e){ return h } }
    function rewriteAnchor(a){
      try {
        const href = a.getAttribute('href'); if(!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if (href.startsWith('/proxy?url=')) { a.removeAttribute('target'); return; }
        const abs = absoluteHref(href);
        a.setAttribute('href', toLoad(abs));
        a.removeAttribute('target');
      } catch(e){}
    }
    function rewriteAsset(el, attr){
      try {
        const v = el.getAttribute(attr); if(!v) return;
        if (/^data:/i.test(v)) return;
        if (v.startsWith('/proxy?url=')) return;
        const abs = absoluteHref(v);
        el.setAttribute(attr, '/proxy?url=' + encodeURIComponent(abs));
      } catch(e){}
    }
    function rewriteAll(){
      document.querySelectorAll('a[href]').forEach(rewriteAnchor);
      ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
        document.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
        document.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
      });
      document.querySelectorAll('[srcset]').forEach(el=>{
        try{
          const ss = el.getAttribute('srcset'); if(!ss) return;
          const parts = ss.split(',').map(p=>{ const [u, r] = p.trim().split(/\\s+/,2); if(!u) return p; if(/^data:/i.test(u)) return p; return '/proxy?url=' + encodeURIComponent(absoluteHref(u)) + (r ? ' ' + r : ''); });
          el.setAttribute('srcset', parts.join(', '));
        }catch(e){}
      });
    }
    rewriteAll();
    // watch mutations
    const mo = new MutationObserver(muts=>{
      muts.forEach(mut=>{
        mut.addedNodes.forEach(n=>{
          if(n.nodeType !== 1) return;
          if(n.matches && n.matches('a[href]')) rewriteAnchor(n);
          n.querySelectorAll && n.querySelectorAll('a[href]').forEach(rewriteAnchor);
          ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
            if(n.matches && n.matches(tag + '[src]')) rewriteAsset(n,'src');
            n.querySelectorAll && n.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
            if(n.matches && n.matches(tag + '[href]')) rewriteAsset(n,'href');
            n.querySelectorAll && n.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
          });
          if(n.querySelectorAll && n.querySelectorAll('[srcset]').length){
            n.querySelectorAll('[srcset]').forEach(el=>{
              const ss = el.getAttribute('srcset'); if(!ss) return;
              const parts = ss.split(',').map(p=>{ const [u,r] = p.trim().split(/\\s+/,2); if(!u) return p; if(/^data:/i.test(u)) return p; return '/proxy?url=' + encodeURIComponent(absoluteHref(u)) + (r ? ' ' + r : ''); });
              el.setAttribute('srcset', parts.join(', '));
            });
          }
        });
      });
    });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });
    // intercept clicks to force proxy navigation
    document.addEventListener('click', function(e){
      const a = e.target.closest && e.target.closest('a[href]');
      if(!a) return;
      try {
        const href = a.getAttribute('href') || '';
        if(!href) return;
        if(href.startsWith('/proxy?url=')) return; // already proxied
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = absoluteHref(href);
        location.href = toLoad(abs);
      } catch(e){}
    }, true);
    // patch history API
    (function(h){ const push = h.pushState; h.pushState = function(s,t,u){ try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toLoad(absolute(u)); }catch(e){} return push.apply(h, arguments); }; const rep = h.replaceState; h.replaceState = function(s,t,u){ try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toLoad(absolute(u)); }catch(e){} return rep.apply(h, arguments); }; })(window.history);
    // patch open
    (function(){ try{ const orig = window.open; window.open = function(u,...rest){ try{ if(!u) return orig.apply(window, arguments); const abs = absolute(u); location.href = toLoad(abs); return null; }catch(e){ return orig.apply(window, arguments); } }; }catch(e){} })();
  })();
  </script>
  `;

  if (/<body/i.test(html)) {
    html = html.replace(/<body([^>]*)>/i, (m) => m + topbar);
  } else {
    html = topbar + html;
  }
  return html;
}

// Main /proxy route
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing 'url' query parameter");

  // normalize input if somebody passes plain host or search
  try {
    if (!/^https?:\/\//i.test(raw)) {
      // if looks like a search -> google search
      const maybe = decodeURIComponent(raw || "");
      if (isLikelySearch(maybe)) raw = "https://www.google.com/search?q=" + encodeURIComponent(maybe);
      else raw = "https://" + maybe;
    }
  } catch (e) {
    raw = "https://" + raw;
  }

  // check in-memory/disk cache
  const cached = getCache(raw);
  if (cached) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    // stream cached via scramjet for consistent behavior
    StringStream.from(cached).pipe(res);
    return;
  }

  try {
    // Fetch origin and follow redirects server-side
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const headers = {
      "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
      "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
    };
    if (req.headers.referer) headers.Referer = req.headers.referer;

    let originRes = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // handle redirect responses (3xx)
    if (originRes.status >= 300 && originRes.status < 400 && originRes.headers.get("location")) {
      const loc = originRes.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      // redirect through our proxy
      return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    const contentType = originRes.headers.get("content-type") || "";

    // Non-HTML: return raw bytes (images, css, js, etc). Cache small assets.
    if (!contentType.includes("text/html")) {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      res.setHeader("Content-Type", contentType);
      const cacheCtrl = originRes.headers.get("cache-control");
      if (cacheCtrl) res.setHeader("Cache-Control", cacheCtrl);
      // cache small assets on disk/memory
      if (buf.length < 100 * 1024) {
        try { setCache(raw, buf.toString("base64")); } catch(e){}
      }
      return res.send(buf);
    }

    // HTML path: read full string so we can safely rewrite
    let html = await originRes.text();

    // sanitize and rewrite
    html = sanitizeHTMLForProxy(html);
    html = rewriteResources(html, originRes.url || raw);

    // inject topbar and containment
    html = injectTopbarAndContainment(html, originRes.url || raw);

    // set CSP to allow inline styles/scripts we inject, allow images etc
    res.setHeader("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; img-src * data: blob:;");

    // cache and stream
    try { setCache(raw, html); } catch(e) {}
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    StringStream.from(html).pipe(res);
  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : err);
    res.status(500).send(`<div style="padding:1rem;background:#111;color:#fff;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// Simple health
app.get("/_health", (req, res) => res.send("ok"));

// Start server
app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
