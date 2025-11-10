/**
 * EUPHORIA — Expanded server.js
 *
 * Objectives:
 *  - Single-file, feature-packed proxy backend for "Euphoria"
 *  - No headless browser; uses fetch + rewriting
 *  - LRU memory cache + optional disk fallback cache
 *  - Session cookie management (so proxied sites can set cookies)
 *  - HTML rewriting (anchors, assets, forms, srcset, CSS url())
 *  - Injection of floating oval topbar + containment script
 *  - Defensive sanitization: remove CSP metas, integrity/crossorigin attributes
 *  - Careful regex usage to avoid syntax errors
 *  - Extensive logging and error handling
 *
 * Deployment notes:
 *  - package.json must include "type":"module"
 *  - dependencies: express, node-fetch, lru-cache, compression, cors, cookie
 *  - Exposes /proxy?url=... endpoint
 */

import express from "express";
import fetch from "node-fetch";
import LRU from "lru-cache";
import compression from "compression";
import cors from "cors";
import cookie from "cookie";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// Basic __dirname shim for ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Configuration ----------
const PORT = process.env.PORT || 3000;
const CACHE_TTL_MS = 1000 * 60 * 10; // 10 minutes
const CACHE_MAX = 1000; // LRU max entries
const DISK_CACHE_DIR = path.join(__dirname, "cache"); // optional disk cache
const SESSION_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours session TTL

// Create cache dir if not exists
try {
  if (!fs.existsSync(DISK_CACHE_DIR)) fs.mkdirSync(DISK_CACHE_DIR, { recursive: true });
} catch (err) {
  console.warn("Warning: cannot create disk cache directory:", err && err.message);
}

// ---------- App bootstrap ----------
const app = express();
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---------- LRU Memory Cache ----------
const memCache = new LRU({
  max: CACHE_MAX,
  ttl: CACHE_TTL_MS,
  updateAgeOnGet: true,
});

// ---------- Simple Disk Cache helpers ----------
function diskCacheKey(url) {
  // base64url safe filename
  return Buffer.from(url).toString("base64url");
}
function diskCacheRead(url) {
  try {
    const file = path.join(DISK_CACHE_DIR, diskCacheKey(url));
    if (!fs.existsSync(file)) return null;
    const raw = fs.readFileSync(file, "utf8");
    const parsed = JSON.parse(raw);
    if (Date.now() - parsed.t > CACHE_TTL_MS) {
      try { fs.unlinkSync(file); } catch (e) {}
      return null;
    }
    return parsed.v;
  } catch (e) {
    return null;
  }
}
function diskCacheWrite(url, value) {
  try {
    const file = path.join(DISK_CACHE_DIR, diskCacheKey(url));
    fs.writeFileSync(file, JSON.stringify({ t: Date.now(), v: value }), "utf8");
  } catch (e) { /* best-effort */ }
}

// ---------- Session store (in-memory minimal) ----------
const sessions = new Map();
function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function getSessionData(req) {
  const headerCookie = req.headers.cookie || "";
  const parsed = cookie.parse(headerCookie || "");
  let sid = parsed["euphoria_sid"] || req.headers["x-euphoria-session"];
  if (!sid || !sessions.has(sid)) {
    const newSid = makeSid();
    sessions.set(newSid, { cookies: new Map(), last: Date.now() });
    return { sid: newSid, data: sessions.get(newSid), created: true };
  }
  const data = sessions.get(sid);
  data.last = Date.now();
  return { sid, data, created: false };
}
function persistSessionCookie(res, sid) {
  // set cookie if not already set
  const cookieStr = cookie.serialize("euphoria_sid", sid, { httpOnly: true, path: "/", sameSite: "Lax", maxAge: 60*60*24 });
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function storeSetCookies(setCookieArray, sessionData) {
  // parse "Set-Cookie" strings and store simple k=v pairs
  for (const sc of (setCookieArray || [])) {
    try {
      const firstPart = sc.split(";")[0];
      const parsed = cookie.parse(firstPart || "");
      for (const k in parsed) if (k) sessionData.cookies.set(k, parsed[k]);
    } catch (e) { }
  }
}
function buildCookieHeaderFromSession(sessionData) {
  const parts = [];
  for (const [k, v] of sessionData.cookies.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

// ---------- Utility helpers ----------
function isLikelySearch(input) {
  if (!input) return true;
  if (input.includes(" ")) return true;
  if (/^https?:\/\//i.test(input)) return false;
  if (/\./.test(input)) return false;
  return true;
}
function normalizeToUrl(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function safeReplaceOnce(source, searchValue, replaceValue) {
  // helper that preserves original if replace fails
  try { return source.replace(searchValue, replaceValue); } catch (e) { return source; }
}

// ---------- Injection: topbar + containment script ----------
// This is the "old perfect" floating oval top bar, injected into proxied pages.
// Keep style minimal and solid dark oval as requested.
const INJECT_TOPBAR = `
<div id="euphoria-topbar" style="
  position:fixed; top:12px; left:50%; transform:translateX(-50%);
  width:80%; max-width:1200px; background:#0f1112; border-radius:28px;
  padding:8px 12px; display:flex; align-items:center; gap:8px;
  z-index:2147483647; box-shadow:0 8px 30px rgba(0,0,0,0.6); font-family:system-ui,Arial,sans-serif;">
  <button id="eph-back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#171819;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#171819;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#171819;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#171819;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" placeholder="Enter URL or search..." style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#151617;color:#fff;outline:none" />
  <button id="eph-go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#277A3B;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#171819;color:#fff;cursor:pointer">⛶</button>
</div>
<style>body{padding-top:76px !important;background:transparent !important;}</style>

<script>
(function(){
  // containment script to keep navigation internal to /proxy
  // helpers
  const q = (s) => document.querySelector(s);
  const absolute = (h) => { try { return new URL(h, document.baseURI).href } catch (e) { return h } };
  const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);

  const input = q('#eph-input');
  const go = q('#eph-go');
  const back = q('#eph-back');
  const forward = q('#eph-forward');
  const refresh = q('#eph-refresh');
  const home = q('#eph-home');
  const full = q('#eph-full');

  // prefill input with ?url= param if present
  try {
    const m = location.search.match(/[?&]url=([^&]+)/);
    if (m) input.value = decodeURIComponent(m[1] || '');
  } catch(e){}

  function isLikelySearch(v) {
    if (!v) return true;
    if (v.includes(' ')) return true;
    if (/^https?:\\/\\//i.test(v)) return false;
    if (/\\./.test(v)) return false;
    return true;
  }
  function normalize(v) {
    v = (v||'').trim();
    if (!v) return 'https://www.google.com';
    if (isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
    try { new URL(v); return v; } catch(e) {}
    return 'https://' + v;
  }

  go.onclick = () => {
    const raw = input.value.trim();
    // If user pasted a full /proxy?url= link, navigate directly
    if (/\\/proxy\\?url=/i.test(raw)) { location.href = raw; return; }
    const u = normalize(raw);
    location.href = toProxy(u);
  };
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') go.onclick(); });

  back.onclick = () => { history.back(); };
  forward.onclick = () => { history.forward(); };
  refresh.onclick = () => { location.reload(); };
  home.onclick = () => { location.href = '/proxy?url=' + encodeURIComponent('https://www.google.com'); };
  full.onclick = () => { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

  // Rewrite anchors/assets/forms in DOM to keep them proxied
  function absoluteHref(h) { try { return new URL(h, document.baseURI).href } catch(e){ return h; } }

  function rewriteAnchor(a) {
    try {
      const href = a.getAttribute('href');
      if (!href) return;
      if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      if (href.startsWith('/proxy?url=')) { a.removeAttribute('target'); return; }
      const abs = absoluteHref(href);
      a.setAttribute('href', toProxy(abs));
      a.removeAttribute('target');
    } catch(e){}
  }
  function rewriteAsset(el, attr) {
    try {
      const v = el.getAttribute(attr);
      if (!v) return;
      if (/^data:/i.test(v)) return;
      if (v.startsWith('/proxy?url=')) return;
      const abs = absoluteHref(v);
      el.setAttribute(attr, toProxy(abs));
    } catch(e){}
  }
  function rewriteSrcset(el) {
    try {
      const ss = el.getAttribute('srcset');
      if (!ss) return;
      const parts = ss.split(',').map(p => {
        const [url, rest] = p.trim().split(/\\s+/, 2);
        if (!url) return p;
        if (/^data:/i.test(url)) return p;
        return toProxy(absoluteHref(url)) + (rest ? ' ' + rest : '');
      });
      el.setAttribute('srcset', parts.join(', '));
    } catch(e){}
  }

  function rewriteAll() {
    document.querySelectorAll('a[href]').forEach(rewriteAnchor);
    ['img','script','link','source','video','audio','iframe'].forEach(tag => {
      document.querySelectorAll(tag + '[src]').forEach(el => rewriteAsset(el,'src'));
      document.querySelectorAll(tag + '[href]').forEach(el => rewriteAsset(el,'href'));
    });
    document.querySelectorAll('[srcset]').forEach(rewriteSrcset);
  }

  // observe DOM changes to rewrite new nodes (for SPAs)
  const mo = new MutationObserver(muts => {
    for (const m of muts) {
      if (m.type === 'childList') {
        m.addedNodes.forEach(n => {
          if (n.nodeType !== 1) return;
          if (n.matches && n.matches('a[href]')) rewriteAnchor(n);
          n.querySelectorAll && n.querySelectorAll('a[href]').forEach(rewriteAnchor);
          ['img','script','link','source','video','audio','iframe'].forEach(tag => {
            if (n.matches && n.matches(tag + '[src]')) rewriteAsset(n,'src');
            n.querySelectorAll && n.querySelectorAll(tag + '[src]').forEach(el => rewriteAsset(el,'src'));
            if (n.matches && n.matches(tag + '[href]')) rewriteAsset(n,'href');
            n.querySelectorAll && n.querySelectorAll(tag + '[href]').forEach(el => rewriteAsset(el,'href'));
          });
          if (n.querySelectorAll && n.querySelectorAll('[srcset]').length) {
            n.querySelectorAll('[srcset]').forEach(rewriteSrcset);
          }
        });
      }
    }
  });
  mo.observe(document.documentElement || document, { childList:true, subtree:true });

  // handle clicks on anchors to ensure they go via /proxy
  document.addEventListener('click', function(ev) {
    const a = ev.target.closest && ev.target.closest('a[href]');
    if (!a) return;
    try {
      const href = a.getAttribute('href') || '';
      if (!href) return;
      if (href.startsWith('/proxy?url=')) return; // already proxied
      if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
      ev.preventDefault();
      const abs = absoluteHref(href);
      location.href = toProxy(abs);
    } catch(e){}
  }, true);

  // intercept pushState/replaceState to keep SPA navigation inside /proxy if scripts use pushState with relative paths
  (function(history){
    const _push = history.pushState;
    history.pushState = function(s,t,u) {
      try {
        if (typeof u === 'string' && u && !u.startsWith('/proxy?url=')) {
          const abs = absoluteHref(u);
          u = toProxy(abs);
        }
      } catch(e){}
      return _push.apply(this, arguments);
    };
    const _replace = history.replaceState;
    history.replaceState = function(s,t,u) {
      try {
        if (typeof u === 'string' && u && !u.startsWith('/proxy?url=')) {
          const abs = absoluteHref(u);
          u = toProxy(abs);
        }
      } catch(e){}
      return _replace.apply(this, arguments);
    };
  })(window.history);

  // patch window.open to navigate same tab via /proxy
  (function(){
    const orig = window.open;
    window.open = function(url, ...rest) {
      try {
        if (!url) return orig.apply(window, [url, ...rest]);
        const abs = absoluteHref(url);
        location.href = toProxy(abs);
        return null;
      } catch(e) { return orig.apply(window, [url, ...rest]); }
    };
  })();

  // initial rewrite run after small delay (many pages mutate)
  setTimeout(()=>{ try { rewriteAll(); } catch(e){}; }, 600);
})();
</script>
`;

// ---------- Helpers: rewrite HTML server-side ----------

/**
 * rewriteHtmlForProxy(originalHtml, originUrl)
 * - strips CSP/meta that will break injection
 * - removes integrity/crossorigin attributes
 * - injects <base href="origin"> to help relative resolution
 * - rewrites href/src/srcset/url(...) to /proxy?url=absolute
 * - injects INJECT_TOPBAR after <body>
 */
function rewriteHtmlForProxy(html, originUrl) {
  if (typeof html !== "string") return html;

  // 1) remove content-security-policy meta tags (simple)
  html = html.replace(/<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");

  // 2) remove x-frame-options meta/header style tags inside html that could block
  html = html.replace(/<meta[^>]*http-equiv\s*=\s*["']?x-frame-options["']?[^>]*>/gi, "");

  // 3) remove integrity and crossorigin attributes which break proxied assets
  html = html.replace(/\sintegrity=(["'])[^"']*\1/gi, "");
  html = html.replace(/\scrossorigin=(["'])[^"']*\1/gi, "");

  // 4) inject <base> after <head ...>
  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${originUrl}">`);
  } else {
    html = `<base href="${originUrl}">` + html;
  }

  // 5) rewrite anchors: <a ... href="...">
  // safe approach: match <a ... href="..."> capturing preceding attributes
  html = html.replace(/<a\b([^>]*?)\bhref=(["'])([^"']*)\2/gi, (m, pre, q, href) => {
    if (!href) return m;
    if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return m;
    if (href.startsWith('/proxy?url=')) return m;
    let abs = toAbsolute(href, originUrl) || href;
    // ensure we don't re-encode already proxied
    return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
  });

  // 6) rewrite common asset tags src/href/srcset
  // For img, script, link, source, video, audio, iframe — replace src/href with proxy
  html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?(?:\s(?:src|href|srcset)\s*=\s*))(["'])([^"']*)\2/gi,
    (m, prefix, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      if (val.startsWith('/proxy?url=')) return m;
      // srcset is handled separately below
      const abs = toAbsolute(val, originUrl) || val;
      return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

  // 7) rewrite srcset attributes separately (more nuanced)
  html = html.replace(/([\s\S]*?)srcset=(["'])(.*?)\2/gi, (m, before, q, srcset) => {
    // split srcset parts by comma, map urls
    try {
      const parts = srcset.split(",").map(p => {
        const trimmed = p.trim();
        const [url, descriptor] = trimmed.split(/\s+/, 2);
        if (!url) return p;
        if (/^data:/i.test(url)) return p;
        const abs = toAbsolute(url, originUrl) || url;
        return `/proxy?url=${encodeURIComponent(abs)}` + (descriptor ? " " + descriptor : "");
      });
      return before + `srcset=${q}${parts.join(", ")}${q}`;
    } catch (e) {
      return m;
    }
  });

  // 8) rewrite CSS url(...) occurrences in inline styles and style tags
  html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, quote, url) => {
    if (!url) return m;
    if (/^data:/i.test(url)) return m;
    const abs = toAbsolute(url, originUrl) || url;
    return `url("/proxy?url=${encodeURIComponent(abs)}")`;
  });

  // 9) rewrite form actions
  html = html.replace(/(<\s*form\b[^>]*\baction=)(["'])([^"']*)\2/gi, (m, pre, q, act) => {
    if (!act) return m;
    if (/^(javascript:|#)/i.test(act)) return m;
    if (act.startsWith('/proxy?url=')) return m;
    const abs = toAbsolute(act, originUrl) || act;
    return `${pre}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
  });

  // 10) rewrite meta refresh tags
  html = html.replace(/<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/gi, (m) => {
    const contentMatch = m.match(/content\s*=\s*["']([^"']*)["']/i);
    if (!contentMatch) return m;
    const parts = contentMatch[1].split(";");
    if (parts.length < 2) return m;
    const urlPart = parts.slice(1).join(";").match(/url=(.*)/i);
    if (!urlPart) return m;
    const dest = urlPart[1].replace(/['"]/g, "").trim();
    const abs = toAbsolute(dest, originUrl) || dest;
    return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
  });

  // 11) strip well-known trackers (selective)
  html = html.replace(/<script[^>]*src=(["'])[^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication|adsbygoogle)[^"']*\1[^>]*>[\s\S]*?<\/script>/gi, "");

  // 12) inject topbar and containment script after opening <body>
  if (/<body[^>]*>/i.test(html)) {
    html = html.replace(/<body([^>]*)>/i, (m, g) => `${m}\n${INJECT_TOPBAR}\n`);
  } else {
    // fallback: prepend
    html = INJECT_TOPBAR + html;
  }

  return html;
}

// ---------- /proxy endpoint ----------
app.get("/proxy", async (req, res) => {
  // Accept either /proxy?url=... or /proxy/<encoded>
  let raw = req.query.url;
  if (!raw) {
    // maybe path /proxy/<encoded>
    const m = req.path.match(/^\/proxy\/(.+)$/);
    if (m && m[1]) raw = decodeURIComponent(m[1]);
  }
  if (!raw) return res.status(400).send("Missing url parameter. Use /proxy?url=https://example.com");

  // Normalize: if user supplied plain host or search query (no protocol), try to normalize
  if (!/^https?:\/\//i.test(raw)) {
    try {
      const dec = decodeURIComponent(raw);
      raw = isLikelySearch(dec) ? `https://www.google.com/search?q=${encodeURIComponent(dec)}` : `https://${dec}`;
    } catch (e) {
      raw = `https://${raw}`;
    }
  }

  const session = getSessionData(req);
  persistSessionCookie(res, session.sid);

  const cacheKeyHtml = raw + "::html";
  const cacheKeyAsset = raw + "::asset";

  // If HTML cached in memory, return it directly
  try {
    const mem = memCache.get(cacheKeyHtml);
    if (mem) {
      res.setHeader("Content-Type", mem.type || "text/html; charset=utf-8");
      persistSessionCookie(res, session.sid);
      return res.send(mem.body);
    }
    // fallback: try disk
    const disk = diskCacheRead(cacheKeyHtml);
    if (disk) {
      memCache.set(cacheKeyHtml, { body: disk.body, type: disk.type, t: Date.now() });
      res.setHeader("Content-Type", disk.type || "text/html; charset=utf-8");
      persistSessionCookie(res, session.sid);
      return res.send(disk.body);
    }
  } catch (e) { /* ignore cache errors */ }

  // Build request headers for origin fetch
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers["accept"] || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
  };
  const sessionCookieHeader = buildCookieHeaderFromSession(session.data.cookies);
  if (sessionCookieHeader) headers["Cookie"] = sessionCookieHeader;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  // Fetch origin (follow redirects server-side to capture final URL)
  try {
    const controller = new AbortController();
    const timeoutTimer = setTimeout(() => controller.abort(), 20000);

    // follow redirects here so we get final HTML (many sites redirect)
    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeoutTimer);

    // store Set-Cookie headers into session store
    const setCookieArr = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if (setCookieArr.length) storeSetCookies(setCookieArr, session.data);

    const contentType = originRes.headers.get("content-type") || "";
    // If non-html (binary) — stream bytes, optionally cache small assets
    if (!contentType.includes("text/html")) {
      const buf = Buffer.from(await originRes.arrayBuffer());
      // small asset caching
      try {
        if (buf.length < 128 * 1024) {
          const assetObj = { body: buf.toString("base64"), type: contentType, t: Date.now() };
          memCache.set(cacheKeyAsset, assetObj);
          diskCacheWrite(cacheKeyAsset, assetObj);
        }
      } catch (e) { /* ignore */ }

      // forward headers (content-type + cache-control)
      res.setHeader("Content-Type", contentType);
      const ccontrol = originRes.headers.get("cache-control");
      if (ccontrol) res.setHeader("Cache-Control", ccontrol);
      persistSessionCookie(res, session.sid);
      return res.send(buf);
    }

    // HTML path: get full text so we can rewrite
    let html = await originRes.text();
    const finalUrl = originRes.url || raw;

    // sanitize: remove CSP meta tags that would prevent our injected scripts/styles
    html = html.replace(/<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");

    // remove integrity/crossorigin attrs
    html = html.replace(/\sintegrity\s*=\s*(["'])[^"']*\1/gi, "");
    html = html.replace(/\scrossorigin\s*=\s*(["'])[^"']*\1/gi, "");

    // minimal replacement to keep page layout stable: inject small CSS to make content responsive inside the viewport
    html = html.replace(/<head([^>]*)>/i, (m,g) => `${m}\n<style>img,video{max-width:100%;height:auto;display:block;}</style>`);

    // Use server-side rewrite helper
    const rewritten = rewriteHtmlForProxy(html, finalUrl);

    // store in caches (mem + disk)
    try {
      const store = { body: rewritten, type: "text/html; charset=utf-8", t: Date.now() };
      memCache.set(cacheKeyHtml, store);
      diskCacheWrite(cacheKeyHtml, store);
    } catch (e) {
      // ignore
    }

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    return res.send(rewritten);

  } catch (err) {
    // handle fetch errors
    console.error("Euphoria fetch error for", raw, ":", err && err.message ? err.message : String(err));
    persistSessionCookie(res, session.sid);
    const msg = (err && err.name === "AbortError") ? "Request timed out" : (err && err.message) ? err.message : String(err);
    return res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${msg}</div>`);
  }
});

// ---------- Suggest endpoint (autocomplete) ----------
app.get("/suggest", async (req, res) => {
  const q = req.query.q || "";
  if (!q) return res.json([]);
  try {
    const r = await fetch("https://suggestqueries.google.com/complete/search?client=firefox&q=" + encodeURIComponent(q));
    const j = await r.json();
    return res.json(j[1] || []);
  } catch (e) {
    return res.json([]);
  }
});

// ---------- Health check & status ----------
app.get("/_health", (req, res) => res.json({ ok: true, time: Date.now(), memCacheSize: memCache.size }));

// ---------- Fallback: serve index.html for SPA navigation ----------
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// ---------- Periodic cleanup for sessions & disk cache pruning ----------
setInterval(() => {
  try {
    const now = Date.now();
    // sessions prune
    for (const [sid, s] of sessions) {
      if ((s.last || 0) + SESSION_TTL_MS < now) sessions.delete(sid);
    }
    // simple disk prune: remove files older than CACHE_TTL_MS
    const files = fs.readdirSync(DISK_CACHE_DIR);
    for (const f of files) {
      try {
        const stat = fs.statSync(path.join(DISK_CACHE_DIR, f));
        if (Date.now() - stat.mtimeMs > CACHE_TTL_MS * 2) {
          try { fs.unlinkSync(path.join(DISK_CACHE_DIR, f)); } catch (e) {}
        }
      } catch (e) {}
    }
  } catch (e) { /* ignore periodic errors */ }
}, 1000 * 60 * 5);

// ---------- Error handling ----------
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err && err.stack ? err.stack : err);
});
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err && err.stack ? err.stack : err);
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`Euphoria proxy listening on port ${PORT}`);
});