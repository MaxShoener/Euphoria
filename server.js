// server.js
// EUPHORIA — single-tab interception proxy
// ~500 lines (expanded and heavily commented for readability and future edits)
//
// Features:
//  - /proxy?url=... endpoint that fetches remote resources and rewrites pages so they
//    continue to navigate through /proxy (no iframes, no puppeteer/Playwright).
//  - Session cookie handling (in-memory session store; cookie persisted to client).
//  - Lightweight memory + disk cache for small assets and HTML pages.
//  - HTML rewriting: anchors, src/href/srcset, CSS url(), forms, meta-refresh.
//  - Injects a dark oval topbar (the "perfect" UI) and containment scripts to keep
//    navigations inside the /proxy endpoint (rewrites pushState/replaceState, window.open).
//  - Removes CSP meta tags and integrity/crossorigin attributes that break proxied loads.
//  - Handles redirects server-side and preserves cookies set by upstream.
//  - Good error handling and timeouts.
//  - SPA fallback: serves public/index.html for unrecognized GETs.
//
// IMPORTANT: This file avoids scramjet / puppeteer to keep deploys predictable.
// If you still want scramjet-specific behavior, I can provide it as an alternate server file.
//
// -----------------------------------------------------------------------------
// Imports & bootstrap
// -----------------------------------------------------------------------------

import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import cookie from "cookie";
import morgan from "morgan";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create express app and set port
const app = express();
const PORT = process.env.PORT || 3000;

// -----------------------------------------------------------------------------
// Middleware
// -----------------------------------------------------------------------------
// logger, compression, parsers, static files
app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Serve static public files from /public (but we won't serve index by default here)
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -----------------------------------------------------------------------------
// Session store (simple in-memory) + cookie helpers
// -----------------------------------------------------------------------------

const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24 hours
const SESSIONS = new Map();

// create random-ish session id
function mkSid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function now() {
  return Date.now();
}

function createSession() {
  const sid = mkSid();
  const data = { cookies: new Map(), last: now() };
  SESSIONS.set(sid, data);
  return { sid, data };
}

// Read or create session for incoming request
function getSession(req) {
  const hdr = req.headers.cookie || "";
  const parsed = cookie.parse(hdr || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const data = SESSIONS.get(sid);
  data.last = now();
  return { sid, data };
}

// Persist Set-Cookie session identifier to outgoing response
function persistSessionCookie(res, sid) {
  const sc = cookie.serialize(SESSION_NAME, sid, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    maxAge: 60 * 60 * 24, // seconds
  });
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", sc);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, sc]);
  else res.setHeader("Set-Cookie", [prev, sc]);
}

// Parse and store upstream Set-Cookie headers into session map
function storeSetCookieStrings(setCookies = [], sessionData) {
  for (const sc of setCookies) {
    try {
      const kv = sc.split(";")[0];
      const parsed = cookie.parse(kv || "");
      for (const k in parsed) if (k) sessionData.cookies.set(k, parsed[k]);
    } catch (e) {
      // ignore parsing failure for weird cookies
    }
  }
}

// Periodically prune expired sessions to avoid memory leaks
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) {
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

// -----------------------------------------------------------------------------
// Lightweight Cache (memory + disk)
// -----------------------------------------------------------------------------

const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) {
  try {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
  } catch (e) {
    // ignore
  }
}
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes

function cacheKey(k) {
  // base64url safe key
  return Buffer.from(k).toString("base64url");
}

function cacheGet(k) {
  const m = MEM_CACHE.get(k);
  if (m && now() - m.t < CACHE_TTL) return m.val;
  const f = path.join(CACHE_DIR, cacheKey(k));
  if (fs.existsSync(f)) {
    try {
      const raw = fs.readFileSync(f, "utf8");
      const obj = JSON.parse(raw);
      if (now() - obj.t < CACHE_TTL) {
        MEM_CACHE.set(k, { val: obj.val, t: obj.t });
        return obj.val;
      } else {
        try {
          fs.unlinkSync(f);
        } catch (e) {}
      }
    } catch (e) {
      // ignore JSON parse errors
    }
  }
  return null;
}

function cacheSet(k, v) {
  MEM_CACHE.set(k, { val: v, t: now() });
  try {
    fs.writeFileSync(path.join(CACHE_DIR, cacheKey(k)), JSON.stringify({ val: v, t: now() }), "utf8");
  } catch (e) {
    // ignore disk write errors
  }
}

// -----------------------------------------------------------------------------
// Helper utilities
// -----------------------------------------------------------------------------

function toAbsolute(href, base) {
  try {
    return new URL(href, base).href;
  } catch (e) {
    return null;
  }
}

function buildCookieHeader(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

function extractUrl(req) {
  if (req.query && req.query.url) return req.query.url;
  const m = req.path.match(/^\/proxy\/(.+)$/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}

function isLikelySearch(input) {
  if (!input) return true;
  if (input.includes(" ")) return true;
  if (/^https?:\/\//i.test(input)) return false;
  if (/\./.test(input)) return false;
  return true;
}

function normalizeInputToURL(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// -----------------------------------------------------------------------------
// Topbar HTML + containment script (injected into proxied pages)
// - solid dark oval background
// - uniform button sizing
// - wired Go/Enter/Back/Forward/Refresh/Home/Fullscreen
// - containment script rewrites DOM anchors/assets/forms and patches pushState/window.open
// -----------------------------------------------------------------------------

const INJECT_TOPBAR_AND_CONTAINMENT = `
<!-- EUPHORIA TOPBAR (injected) -->
<div id="euphoria-topbar" style="
  position:fixed;
  top:12px;
  left:50%;
  transform:translateX(-50%);
  width:78%;
  max-width:1200px;
  background:#0f1112; /* solid dark */
  border-radius:28px;
  padding:8px 12px;
  display:flex;
  align-items:center;
  gap:8px;
  z-index:2147483647;
  box-shadow:0 6px 20px rgba(0,0,0,0.6);
  font-family:system-ui,Arial,sans-serif;
">
  <button id="eph-back" style="min-width:46px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
  <button id="eph-forward" style="min-width:46px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
  <button id="eph-refresh" style="min-width:46px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
  <button id="eph-home" style="min-width:46px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
  <input id="eph-input" style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" placeholder="Enter URL or search..." />
  <button id="eph-go" style="min-width:46px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
  <button id="eph-full" style="min-width:46px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
</div>

<style>
  /* Ensure proxied pages render nicely in our container */
  body { padding-top: 76px !important; background: transparent !important; }
  img, video { max-width: 100% !important; height: auto !important; }
</style>

<script>
/* EUPHORIA containment script */
(function() {
  try {
    const topbarInput = document.getElementById('eph-input');
    const btnGo = document.getElementById('eph-go');
    const btnBack = document.getElementById('eph-back');
    const btnForward = document.getElementById('eph-forward');
    const btnRefresh = document.getElementById('eph-refresh');
    const btnHome = document.getElementById('eph-home');
    const btnFull = document.getElementById('eph-full');

    // Fill input from ?url= if present
    try {
      const m = location.search.match(/[?&]url=([^&]+)/);
      if (m) topbarInput.value = decodeURIComponent(m[1]);
    } catch (e) {}

    // Normalization: if a user types a plain hostname or a search phrase, convert
    function isLikelySearch(v) {
      if (!v) return true;
      if (v.indexOf(' ') !== -1) return true;
      if (/^https?:\\/\\//i.test(v)) return false;
      if (/\\./.test(v)) return false;
      return true;
    }
    function normalize(v) {
      v = (v || '').trim();
      if (!v) return 'https://www.google.com';
      if (isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
      if (/^https?:\\/\\//i.test(v)) return v;
      return 'https://' + v;
    }

    // Routing helper to our proxy
    function toProxy(href) {
      return '/proxy?url=' + encodeURIComponent(href);
    }

    btnGo.addEventListener('click', function() {
      const v = topbarInput.value || '';
      if (!v) return;
      // If user pasted already-proxied url, go directly
      if (/\\/proxy\\?url=/.test(v)) { location.href = v; return; }
      const normalized = normalize(v);
      location.href = toProxy(normalized);
    });

    topbarInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') btnGo.click();
    });

    btnBack.addEventListener('click', function() { history.back(); });
    btnForward.addEventListener('click', function() { history.forward(); });
    btnRefresh.addEventListener('click', function() { location.reload(); });
    btnHome.addEventListener('click', function() { location.href = '/'; });
    btnFull.addEventListener('click', function() {
      if (!document.fullscreenElement) document.documentElement.requestFullscreen();
      else document.exitFullscreen();
    });

    // DOM rewriting helpers
    function absolute(h) {
      try { return new URL(h, document.baseURI).href; } catch (e) { return h; }
    }

    function rewriteAnchor(a) {
      try {
        if (!a || !a.getAttribute) return;
        let href = a.getAttribute('href');
        if (!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if (href.startsWith('/proxy?url=')) return;
        const abs = absolute(href);
        a.setAttribute('href', toProxy(abs));
        a.removeAttribute('target');
      } catch (e) {}
    }

    function rewriteAsset(el, attr) {
      try {
        if (!el || !el.getAttribute) return;
        const v = el.getAttribute(attr);
        if (!v) return;
        if (/^data:/i.test(v)) return;
        if (v.startsWith('/proxy?url=')) return;
        const abs = absolute(v);
        el.setAttribute(attr, toProxy(abs));
      } catch (e) {}
    }

    function rewriteSrcset(el) {
      try {
        const ss = el.getAttribute('srcset');
        if (!ss) return;
        const parts = ss.split(',').map(p => {
          const [url, rest] = p.trim().split(/\s+/, 2);
          if (!url) return p;
          if (/^data:/i.test(url)) return p;
          return toProxy(absolute(url)) + (rest ? ' ' + rest : '');
        });
        el.setAttribute('srcset', parts.join(', '));
      } catch (e) {}
    }

    function rewriteAll() {
      document.querySelectorAll('a[href]').forEach(rewriteAnchor);
      ['img','script','link','source','video','audio','iframe'].forEach(tag => {
        document.querySelectorAll(tag + '[src]').forEach(el => rewriteAsset(el,'src'));
        document.querySelectorAll(tag + '[href]').forEach(el => rewriteAsset(el,'href'));
      });
      document.querySelectorAll('[srcset]').forEach(rewriteSrcset);
    }

    // Initial rewrite pass and mutation observer for dynamic apps
    rewriteAll();
    const mo = new MutationObserver(muts => {
      for (const mut of muts) {
        if (mut.type === 'childList' && mut.addedNodes.length) {
          rewriteAll();
        }
      }
    });
    mo.observe(document.documentElement || document, { childList: true, subtree: true });

    // Intercept clicks to anchor elements to route through /proxy
    document.addEventListener('click', function(e) {
      try {
        const a = e.target.closest && e.target.closest('a[href]');
        if (!a) return;
        const href = a.getAttribute('href') || '';
        if (!href) return;
        if (href.startsWith('/proxy?url=') || href.startsWith('/')) return; // already proxied/local
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = absolute(href);
        location.href = toProxy(abs);
      } catch (e) {}
    }, true);

    // Intercept form submits
    document.addEventListener('submit', function(e) {
      try {
        const f = e.target;
        if (!f) return;
        const a = f.getAttribute('action') || '';
        if (!a || a.startsWith('/proxy?url=')) return;
        if (/^(javascript:|#)/i.test(a)) return;
        const abs = absolute(a);
        f.setAttribute('action', '/proxy?url=' + encodeURIComponent(abs));
      } catch (e) {}
    }, true);

    // Patch pushState/replaceState to remain inside proxy
    (function(history) {
      const push = history.pushState;
      history.pushState = function(state, title, url) {
        try {
          if (typeof url === 'string' && url && !url.startsWith('/proxy?url=')) {
            url = toProxy(absolute(url));
          }
        } catch (e) {}
        return push.apply(history, arguments);
      };
      const replace = history.replaceState;
      history.replaceState = function(state, title, url) {
        try {
          if (typeof url === 'string' && url && !url.startsWith('/proxy?url=')) {
            url = toProxy(absolute(url));
          }
        } catch (e) {}
        return replace.apply(history, arguments);
      };
    })(window.history);

    // Patch window.open so it loads in same tab via proxy (most sites expect new window)
    (function() {
      try {
        const origOpen = window.open;
        window.open = function(u, name, specs) {
          try {
            if (!u) return origOpen.apply(window, arguments);
            const abs = absolute(u);
            // navigate current window via proxy
            location.href = toProxy(abs);
            // return null to signal we didn't open a new window
            return null;
          } catch (e) {
            return origOpen.apply(window, arguments);
          }
        };
      } catch (e) {}
    })();

  } catch (e) {
    // swallow injection-time errors so proxied page doesn't break entirely
  }
})();
</script>
`;

// -----------------------------------------------------------------------------
// /proxy endpoint
// -----------------------------------------------------------------------------

app.get("/proxy", async (req, res) => {
  // determine requested URL (query param or path style)
  let raw = extractUrl(req) || req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // if user supplied a plain hostname or search term, normalize
  if (!/^https?:\/\//i.test(raw)) {
    try {
      const maybe = decodeURIComponent(raw);
      if (isLikelySearch(maybe)) raw = "https://www.google.com/search?q=" + encodeURIComponent(maybe);
      else raw = "https://" + maybe;
    } catch (e) {
      raw = "https://" + raw;
    }
  }

  // session handling
  const session = getSession(req);
  persistSessionCookie(res, session.sid);

  // keys for cache lookups
  const keyHtml = raw + "::html";
  const assetKey = raw + "::asset";

  // if a small asset cached and client doesn't want HTML, return from cache
  try {
    const cachedAsset = cacheGet(assetKey);
    if (cachedAsset && !req.headers.accept?.includes("text/html")) {
      const obj = typeof cachedAsset === "string" ? JSON.parse(cachedAsset) : cachedAsset;
      if (obj.headers) Object.entries(obj.headers).forEach(([k, v]) => res.setHeader(k, v));
      return res.send(Buffer.from(obj.body, "base64"));
    }
  } catch (e) {
    // ignore cache read errors
  }

  // build upstream headers (pass user agent and accept headers)
  const cookieHeader = buildCookieHeader(session.data.cookies);
  const upstreamHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers["accept"] || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };
  if (cookieHeader) upstreamHeaders["Cookie"] = cookieHeader;
  if (req.headers.referer) upstreamHeaders["Referer"] = req.headers.referer;

  try {
    // fetch upstream with a timeout and follow redirects server-side so we can keep navigation inside proxy
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20_000);
    const originRes = await fetch(raw, { headers: upstreamHeaders, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // save any Set-Cookie headers to our session store
    const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if (setCookies.length) storeSetCookieStrings(setCookies, session.data);

    const contentType = originRes.headers.get("content-type") || "";

    // If not HTML, pipe bytes (images, scripts, css, etc.)
    if (!contentType.includes("text/html")) {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      // cache small assets for speed
      if (buf.length < 100 * 1024) {
        try {
          cacheSet(assetKey, JSON.stringify({ headers: { "Content-Type": contentType }, body: buf.toString("base64") }));
        } catch (e) {}
      }

      // forward common headers
      res.setHeader("Content-Type", contentType);
      const cacheControl = originRes.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);

      persistSessionCookie(res, session.sid);
      return res.send(buf);
    }

    // HTML path — read full text
    let html = await originRes.text();

    // remove CSP meta tags that will block our injection and scripts
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");

    // remove integrity/crossorigin on tags so proxied assets load
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // ensure relative URLs resolve correctly by adding a base tag to head
    const finalUrl = originRes.url || raw;
    if (/\<head/i.test(html)) {
      html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${finalUrl}">`);
    } else {
      html = `<base href="${finalUrl}">` + html;
    }

    // REWRITES:
    //  - anchors: <a href="..."> -> /proxy?url=abs
    //  - assets: src/href/srcset -> /proxy?url=abs
    //  - CSS url(...) -> /proxy?url=abs
    //  - forms action -> /proxy?url=abs
    //  - meta-refresh -> /proxy?url=abs
    //  - remove some heavy analytics script includes (best-effort)
    //
    // We avoid rewriting URLs already pointing to /proxy?url=... to prevent loops.

    // anchors
    html = html.replace(/<a\b([^>]*?)href=(["'])([^"']*)\2/gi, (m, pre, q, val) => {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // assets with src/href/srcset
    html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)[^>]*?(?:src|href|srcset)=)(["'])([^"']*)\2/gi, (m, prefix, q2, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      if (val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${prefix}${q2}/proxy?url=${encodeURIComponent(abs)}${q2}`;
    });

    // CSS url(...)
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q3, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      if (abs.startsWith('/proxy?url=')) return m;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // forms action
    html = html.replace(/(<\s*form[^>]*action=)(["'])([^"']*)(["'])/gi, (m, pre, q1, val, q2) => {
      if (!val) return m;
      if (/^(javascript:|#)/i.test(val)) return m;
      if (val.startsWith('/proxy?url=')) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q1}/proxy?url=${encodeURIComponent(abs)}${q2}`;
    });

    // meta refresh
    html = html.replace(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*>/gi, (m) => {
      const match = m.match(/content\s*=\s*"(.*?)"/i);
      if (!match) return m;
      const parts = match[1].split(";");
      if (parts.length < 2) return m;
      const urlPart = parts.slice(1).join(";");
      const uMatch = urlPart.match(/url=(.*)/i);
      if (!uMatch) return m;
      const dest = uMatch[1].replace(/['"]/g, "").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=/proxy?url=${encodeURIComponent(abs)}">`;
    });

    // Remove some known analytics scripts (best-effort) to speed pages
    // This regex is safe (no stray backslash flags)
    html = html.replace(/<script[^>]*src=(["'])[^\"]*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*\1[^>]*><\/script>/gi, "");

    // Inject the topbar + containment script immediately after <body>
    if (/<body/i.test(html)) {
      html = html.replace(/<body([^>]*)>/i, (m) => m + INJECT_TOPBAR_AND_CONTAINMENT);
    } else {
      // fallback: if no body tag, prepend
      html = INJECT_TOPBAR_AND_CONTAINMENT + html;
    }

    // Cache HTML for subsequent faster load
    if (originRes.status === 200) {
      try { cacheSet(keyHtml, html); } catch (e) {}
    }

    // Serve final HTML
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    return res.send(html);

  } catch (err) {
    // network errors or aborts (timeout)
    console.error("Euphoria proxy error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    res.status(500).send(`<div style="padding:1.5rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// -----------------------------------------------------------------------------
// SPA fallback: serve index.html from public as the single-page entry
// -----------------------------------------------------------------------------
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    const idx = path.join(__dirname, "public", "index.html");
    if (fs.existsSync(idx)) return res.sendFile(idx);
  }
  next();
});

// -----------------------------------------------------------------------------
// Start server
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Euphoria Proxy running on port ${PORT}`);
});