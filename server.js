// server.js
import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import { fileURLToPath } from "url";
import path from "path";
import cookie from "cookie";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Simple in-memory session store (SID -> { cookies: Map(name->value), last })
const SESSIONS = new Map();
const SESS_COOKIE_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24 hours

function createSession() {
  const sid = Math.random().toString(36).slice(2) + Date.now().toString(36);
  const data = { cookies: new Map(), last: Date.now() };
  SESSIONS.set(sid, data);
  return { sid, data };
}
function getSessionFromReq(req) {
  const hdr = req.headers.cookie || "";
  const parsed = cookie.parse(hdr || "");
  let sid = parsed[SESS_COOKIE_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) {
    const s = createSession();
    sid = s.sid;
    return { sid, data: s.data, isNew: true };
  }
  const data = SESSIONS.get(sid);
  data.last = Date.now();
  return { sid, data, isNew: false };
}
function persistSessionCookie(res, sid) {
  // HttpOnly session cookie for the client so client re-sends it
  res.setHeader("Set-Cookie", cookie.serialize(SESS_COOKIE_NAME, sid, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    maxAge: 60 * 60 * 24, // 1 day
  }));
}

// helpers
function toAbsolute(url, base) {
  try { return new URL(url, base).href; } catch { return null; }
}
function buildCookieHeaderFromMap(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}
function storeSetCookieStringsToSession(setCookieStrings = [], sessionData) {
  // Parse each Set-Cookie string, store name=value (no domain/path handling)
  for (const sc of setCookieStrings) {
    try {
      const parsed = cookie.parse(sc);
      Object.entries(parsed).forEach(([k, v]) => {
        if (k) sessionData.cookies.set(k, v);
      });
    } catch (e) { /* ignore parse errors */ }
  }
}

// Minimal cache for HTML content to speed reloads
const CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes
function cacheGet(key) {
  const v = CACHE.get(key);
  if (!v) return null;
  if (Date.now() - v.t > CACHE_TTL) {
    CACHE.delete(key);
    return null;
  }
  return v.val;
}
function cacheSet(key, val) {
  CACHE.set(key, { val, t: Date.now() });
}

// Main /load route: fetch HTML, rewrite, inject UI overlay, return HTML
app.get("/load", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url query param (e.g. /load?url=https://google.com)");

  // Normalize: if user gave "google.com" -> make it https://google.com
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // session
  const sess = getSessionFromReq(req);
  if (sess.isNew) persistSessionCookie(res, sess.sid);
  // try cached
  const cached = cacheGet(raw + ":html");
  if (cached) {
    // always return session header so client gets sid
    res.setHeader("x-euphoria-session", sess.sid);
    return res.type("html").send(cached);
  }

  try {
    // Build Cookie header to send to target site (from our stored session cookies)
    const cookieHeader = buildCookieHeaderFromMap(sess.data.cookies);

    // Build headers forwarded from client (some important ones)
    const headers = {
      "User-Agent": req.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
      "Referer": req.headers["referer"] || undefined,
    };
    if (cookieHeader) headers["Cookie"] = cookieHeader;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const r = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // Store any Set-Cookie headers from target server into our session store
    const setCookieArr = r.headers.raw()["set-cookie"] || [];
    if (setCookieArr.length) storeSetCookieStringsToSession(setCookieArr, sess.data);

    // handle redirects by returning a small client-side redirect wrapper that calls /load with resolved location
    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      const loc = r.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      // Update session cookies possibly set by redirect response
      persistSessionCookie(res, sess.sid);
      return res.type("html").send(`<meta http-equiv="refresh" content="0;url=/load?url=${encodeURIComponent(resolved)}">`);
    }

    const ctype = r.headers.get("content-type") || "";
    if (!ctype.includes("text/html")) {
      // non-html: stream binary back (images/scripts/css)
      const buffer = Buffer.from(await r.arrayBuffer());
      // set content type & forward some cache control
      if (r.headers.get("content-type")) res.setHeader("Content-Type", r.headers.get("content-type"));
      if (r.headers.get("cache-control")) res.setHeader("Cache-Control", r.headers.get("cache-control"));
      // propagate Set-Cookie to client? No — we keep cookies server-side, but give session cookie
      persistSessionCookie(res, sess.sid);
      return res.send(buffer);
    }

    // Get HTML, then rewrite it before sending to client.
    let html = await r.text();

    // Remove CSP meta tags (they will often block our injected UI or proxied resources)
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");

    // Remove SRI/integrity and crossorigin attributes to avoid blocked resources due to mismatched hashes
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // Inject a <base> tag so relative URLs resolve more predictably
    html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${raw}">`);

    // Rewrite href/src/srcset to go through /proxy route (so subsequent asset requests go to our server and we attach cookies)
    html = html.replace(/(href|src|srcset)=["']([^"']*)["']/gi, (m, attr, val) => {
      if (!val) return m;
      // keep javascript:, data:, mailto:, tel:, # anchors as is
      if (/^(javascript:|data:|mailto:|tel:|#)/i.test(val)) return m;
      // already proxied
      if (val.startsWith("/proxy?url=") || /^\/\//.test(val)) {
        // for protocol-relative URLs (//domain/path) convert to absolute using raw origin
        if (/^\/\//.test(val)) {
          const abs = new URL(val, raw).href;
          return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
        }
        return m;
      }
      const abs = toAbsolute(val, raw) || val;
      try { return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`; } catch { return m; }
    });

    // Rewrite CSS url(...) values to proxy
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, quote, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, raw) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Inject our top oval UI into the proxied page (inline CSS + script so only index.html is used as frontend)
    const uiHtml = `
      <div id="euphoria-topbar" style="
        position:fixed;top:12px;left:50%;transform:translateX(-50%);
        z-index:2147483647; width:78%; max-width:1200px;
        background:#111;border-radius:28px;padding:8px 12px;display:flex;align-items:center;gap:8px;
        box-shadow:0 6px 20px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
        <button id="eph-back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
        <button id="eph-forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
        <button id="eph-refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
        <button id="eph-home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
        <input id="eph-input" style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" placeholder="Enter URL or search..." />
        <button id="eph-go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
        <button id="eph-full" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
      </div>
      <style>
        /* ensure proxied page space isn't hidden under the topbar */
        body { padding-top: 76px !important; }
      </style>
      <script>
        (function(){
          try {
            const input = document.getElementById('eph-input');
            const go = document.getElementById('eph-go');
            const back = document.getElementById('eph-back');
            const forward = document.getElementById('eph-forward');
            const refresh = document.getElementById('eph-refresh');
            const home = document.getElementById('eph-home');
            const full = document.getElementById('eph-full');

            // preload input with current location
            input.value = window.location.href.replace(window.location.origin + '/load?url=', '') || '';

            function normalizeInput(v){
              v = v.trim();
              if(!v) return 'https://www.google.com';
              try { new URL(v); return v; } catch {}
              if (v.includes(' ')) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
              return 'https://' + v;
            }
            go.onclick = () => {
              const url = normalizeInput(input.value);
              window.location.href = '/load?url=' + encodeURIComponent(url);
            };
            input.onkeydown = (e) => { if (e.key === 'Enter') go.onclick(); };
            back.onclick = () => window.history.back();
            forward.onclick = () => window.history.forward();
            refresh.onclick = () => window.location.reload();
            home.onclick = () => window.location.href = '/';
            full.onclick = () => {
              if (!document.fullscreenElement) document.documentElement.requestFullscreen();
              else document.exitFullscreen();
            };

            // append session header to all XHR/fetch calls by monkey-patching fetch (so server sees session header if client sends it)
            const origFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
              init.headers = init.headers || {};
              // propagate euphoria session header automatically from cookie (the server sets it)
              const cookieValue = document.cookie.split('; ').find(c => c.startsWith('${SESS_COOKIE_NAME}='));
              if(cookieValue) {
                const sid = cookieValue.split('=')[1];
                init.headers['x-euphoria-session'] = sid;
              }
              return origFetch(resource, init);
            };
          } catch(e) { console.warn('UI injection error', e); }
        })();
      </script>
    `;

    // Insert our UI after opening <body>
    html = html.replace(/<body([^>]*)>/i, (m) => m + uiHtml);

    // cache & respond
    cacheSet(raw + ":html", html);

    // ensure client gets the session cookie
    persistSessionCookie(res, sess.sid);
    res.setHeader("x-euphoria-session", sess.sid);
    res.type("html").send(html);

  } catch (err) {
    console.error("Load error:", err);
    res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;">Proxy error: ${String(err)}</div>`);
  }
});

// /proxy route to fetch any asset (images, scripts, css, XHR targets) via server session cookies
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const sess = getSessionFromReq(req);
  if (sess.isNew) persistSessionCookie(res, sess.sid);

  // Use cached small resources for speed
  const cacheKey = raw;
  const c = cacheGet(cacheKey);
  if (c) {
    if (c.headers) {
      for (const [k, v] of Object.entries(c.headers)) res.setHeader(k, v);
    }
    return res.send(c.body);
  }

  try {
    const headers = {
      "User-Agent": req.headers["user-agent"] || "Mozilla/5.0",
      "Accept": req.headers["accept"] || "*/*",
      "Referer": req.headers["referer"] || undefined,
    };
    const cookieHeader = buildCookieHeaderFromMap(sess.data.cookies);
    if (cookieHeader) headers["Cookie"] = cookieHeader;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const r = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // capture set-cookie from asset responses too
    const setCookieArr = r.headers.raw()["set-cookie"] || [];
    if (setCookieArr.length) storeSetCookieStringsToSession(setCookieArr, sess.data);

    // handle redirects by returning a small redirect
    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      const loc = r.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      persistSessionCookie(res, sess.sid);
      return res.status(302).setHeader("Location", `/proxy?url=${encodeURIComponent(resolved)}`).end();
    }

    const ctype = r.headers.get("content-type") || "application/octet-stream";
    res.setHeader("Content-Type", ctype);

    // forward caching headers when present
    const cl = r.headers.get("content-length");
    if (cl) res.setHeader("Content-Length", cl);
    const cc = r.headers.get("cache-control");
    if (cc) res.setHeader("Cache-Control", cc);

    const buf = Buffer.from(await r.arrayBuffer());
    // small resources cached
    if (buf.length < 1024 * 100) {
      cacheSet(cacheKey, { headers: { "Content-Type": ctype }, body: buf });
    }

    persistSessionCookie(res, sess.sid);
    return res.send(buf);
  } catch (err) {
    console.error("Proxy asset error:", err);
    res.status(500).send("Proxy asset error: " + err.message);
  }
});

// housekeeping: prune stale sessions occasionally
setInterval(() => {
  const now = Date.now();
  for (const [sid, data] of SESSIONS.entries()) {
    if (now - (data.last || 0) > SESSION_TTL) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

app.listen(PORT, () => console.log(`Euphoria proxy listening on ${PORT}`));