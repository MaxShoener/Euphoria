// server.js
/* EUPHORIA proxy server
   - /           -> serves public/index.html
   - /load?url=  -> fetch HTML, rewrite, inject top-bar, return HTML (no iframe)
   - /proxy?url= -> fetch arbitrary assets and forward bytes (attaches session cookies)
   - Sessions: server-side cookie store mapped by euphoria_sid HttpOnly cookie
   - Caching: in-memory + disk for speed
   - Safe defaults and helpful logs
*/

import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import cookie from "cookie";
import morgan from "morgan";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// --- Config ---
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24h
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes default
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

// --- In-memory stores ---
const SESSIONS = new Map(); // sid -> { cookies: Map, last: timestamp }
const MEM_CACHE = new Map(); // key -> { val, t }

// --- Helpers ---
function makeSid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
function now() { return Date.now(); }

function createSession() {
  const sid = makeSid();
  const data = { cookies: new Map(), last: now() };
  SESSIONS.set(sid, data);
  return { sid, data };
}

function getSession(req) {
  const hdr = req.headers.cookie || "";
  const parsed = cookie.parse(hdr || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) {
    const s = createSession();
    return { sid: s.sid, data: s.data, isNew: true };
  }
  const data = SESSIONS.get(sid);
  data.last = now();
  return { sid, data, isNew: false };
}

function persistSessionCookie(res, sid) {
  const sc = cookie.serialize(SESSION_NAME, sid, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    maxAge: 60 * 60 * 24
  });
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", sc);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, sc]);
  else res.setHeader("Set-Cookie", [prev, sc]);
}

function cacheKey(key) {
  return Buffer.from(key).toString("base64url");
}

function cacheGet(key) {
  const m = MEM_CACHE.get(key);
  if (m && (now() - m.t) < CACHE_TTL) return m.val;
  const f = path.join(CACHE_DIR, cacheKey(key));
  if (fs.existsSync(f)) {
    try {
      const raw = fs.readFileSync(f, "utf8");
      const parsed = JSON.parse(raw);
      if ((now() - parsed.t) < CACHE_TTL) {
        MEM_CACHE.set(key, { val: parsed.val, t: parsed.t });
        return parsed.val;
      } else {
        try { fs.unlinkSync(f); } catch {}
      }
    } catch {}
  }
  return null;
}

function cacheSet(key, val) {
  MEM_CACHE.set(key, { val, t: now() });
  const f = path.join(CACHE_DIR, cacheKey(key));
  try { fs.writeFileSync(f, JSON.stringify({ val, t: now() }), "utf8"); } catch {}
}

function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

function buildCookieHeaderFromMap(map) {
  const parts = [];
  for (const [k,v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

function storeSetCookieStringsToSession(setCookieStrings = [], sessionData) {
  for (const sc of setCookieStrings) {
    try {
      const parsed = cookie.parse(sc);
      for (const k in parsed) {
        if (!k) continue;
        sessionData.cookies.set(k, parsed[k]);
      }
    } catch (e) { /* ignore parse error */ }
  }
}

// prune sessions periodically
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) {
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

// --- Routes ---

// root: serve single-file frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// support both query style /proxy?url=... and path style /proxy/<encoded>
// and accept raw hostnames/urls
function extractUrl(req) {
  if (req.query && req.query.url) return req.query.url;
  // path style: /proxy/https%3A%2F%2Fgoogle.com or /proxy/google.com
  const m = req.path.match(/^\/proxy\/(.+)$/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}

// /load -> fetch HTML page, rewrite references, inject UI, return HTML
app.get("/load", async (req, res) => {
  let raw = req.query.url;
  if (!raw) {
    return res.status(400).send("Missing url (e.g. /load?url=https://google.com)");
  }
  // Normalize
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSession(req);
  if (session.isNew) persistSessionCookie(res, session.sid);

  // caching
  const cacheKeyHtml = raw + "::html";
  const cached = cacheGet(cacheKeyHtml);
  if (cached) {
    res.setHeader("x-euphoria-session", session.sid);
    return res.type("html").send(cached);
  }

  // Prepare headers forwarded to origin
  const cookieHeader = buildCookieHeaderFromMap(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "EuphoriaProxy/1.0",
    "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const originRes = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // Capture set-cookie and store to session
    const setCookies = originRes.headers.raw()["set-cookie"] || [];
    if (setCookies.length) storeSetCookieStringsToSession(setCookies, session.data);

    // handle redirects (meta redirect wrapper)
    if (originRes.status >= 300 && originRes.status < 400 && originRes.headers.get("location")) {
      const loc = originRes.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      persistSessionCookie(res, session.sid);
      return res.type("html").send(`<meta http-equiv="refresh" content="0;url=/load?url=${encodeURIComponent(resolved)}">`);
    }

    const ctype = originRes.headers.get("content-type") || "";
    if (!ctype.includes("text/html")) {
      // return binary directly
      const buffer = Buffer.from(await originRes.arrayBuffer());
      persistSessionCookie(res, session.sid);
      if (originRes.headers.get("content-type")) res.setHeader("Content-Type", originRes.headers.get("content-type"));
      return res.send(buffer);
    }

    let html = await originRes.text();

    // remove CSP meta tags that would block our injected UI
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");

    // remove SRI/integrity and crossorigin that would block proxied assets
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // inject <base> to make relative URLs easier
    html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><base href="${raw}">`);

    // rewrite href/src/srcset to route through /proxy
    html = html.replace(/(href|src|srcset)=["']([^"']*)["']/gi, (m, attr, val) => {
      if (!val) return m;
      if (/^(javascript:|data:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=") || /^\/\//.test(val)) {
        if (/^\/\//.test(val)) {
          try {
            const abs = new URL(val, raw).href;
            return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
          } catch { return m; }
        }
        return m;
      }
      const abs = toAbsolute(val, raw) || val;
      try { return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`; } catch { return m; }
    });

    // Rewriting CSS url(...) references
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, raw) || val;
      try { return `url("/proxy?url=${encodeURIComponent(abs)}")`; } catch { return m; }
    });

    // remove some heavy analytics scripts (best-effort)
    html = html.replace(/<script[^>]*src=["'][^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*["'][^>]*><\/script>/gi, "");

    // inject our topbar (solid dark oval) and small helper style/script
    const injectedUI = `
      <div id="euphoria-topbar" style="position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:2147483647;width:78%;max-width:1200px;background:#111;border-radius:28px;padding:8px 12px;display:flex;align-items:center;gap:8px;box-shadow:0 6px 20px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
        <button id="eph-back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
        <button id="eph-forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
        <button id="eph-refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
        <button id="eph-home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
        <input id="eph-input" style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" placeholder="Enter URL or search..." />
        <button id="eph-go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
        <button id="eph-full" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
      </div>
      <style>body{padding-top:76px !important;}</style>
      <script>
        (function(){
          const input = document.getElementById('eph-input');
          const go = document.getElementById('eph-go');
          const back = document.getElementById('eph-back');
          const forward = document.getElementById('eph-forward');
          const refresh = document.getElementById('eph-refresh');
          const home = document.getElementById('eph-home');
          const full = document.getElementById('eph-full');

          // prefill with current URL
          try {
            const m = window.location.search.match(/[?&]url=([^&]+)/);
            input.value = m ? decodeURIComponent(m[1]) : '';
          } catch (e) {}

          function normalize(v) {
            v = (v||'').trim();
            if (!v) return 'https://www.google.com';
            try { new URL(v); return v; } catch(e) {}
            if (v.indexOf(' ') !== -1) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
            return 'https://' + v;
          }

          go.onclick = () => { const url = normalize(input.value); window.location.href = '/load?url=' + encodeURIComponent(url); };
          input.onkeydown = e => { if (e.key === 'Enter') go.onclick(); };
          back.onclick = () => window.history.back();
          forward.onclick = () => window.history.forward();
          refresh.onclick = () => window.location.reload();
          home.onclick = () => window.location.href = '/';
          full.onclick = () => { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

          // monkeypatch fetch to include euphoria session header derived from HttpOnly cookie (can't read HttpOnly) — fallback uses header if present
          // This is best-effort: server attaches session cookie itself, client XHR will include cookies automatically for same-origin.
        })();
      </script>
    `;

    html = html.replace(/<body([^>]*)>/i, (m) => m + injectedUI);

    cacheSet(cacheKeyHtml, html);
    persistSessionCookie(res, session.sid);
    res.setHeader("x-euphoria-session", session.sid);
    res.type("html").send(html);

  } catch (err) {
    console.error("Load error:", err);
    persistSessionCookie(res, session.sid);
    res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// /proxy -> fetch arbitrary assets and forward bytes (images, css, js, XHR)
app.get("/proxy", async (req, res) => {
  let raw = extractUrl(req);
  if (!raw) raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");

  // normalize protocol
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSession(req);
  if (session.isNew) persistSessionCookie(res, session.sid);

  // small-asset cache key
  const cacheKeyAsset = raw + "::asset";
  const cached = cacheGet(cacheKeyAsset);
  if (cached) {
    try {
      const obj = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (obj.headers) {
        for (const [k,v] of Object.entries(obj.headers)) res.setHeader(k, v);
      }
      res.send(Buffer.from(obj.body, "base64"));
      return;
    } catch {}
  }

  const cookieHeader = buildCookieHeaderFromMap(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "EuphoriaProxy/1.0",
    "Accept": req.headers["accept"] || "*/*",
    "Referer": req.headers["referer"] || undefined
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const originRes = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // store Set-Cookie to session
    const setCookies = originRes.headers.raw()["set-cookie"] || [];
    if (setCookies.length) storeSetCookieStringsToSession(setCookies, session.data);

    // handle redirect
    if (originRes.status >= 300 && originRes.status < 400 && originRes.headers.get("location")) {
      const loc = originRes.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      persistSessionCookie(res, session.sid);
      return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    const ctype = originRes.headers.get("content-type") || "application/octet-stream";
    res.setHeader("Content-Type", ctype);
    if (originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));

    const arr = await originRes.arrayBuffer();
    const buf = Buffer.from(arr);

    // cache small assets
    if (buf.length < 100 * 1024) {
      try { cacheSet(cacheKeyAsset, JSON.stringify({ headers: { "Content-Type": ctype }, body: buf.toString("base64") })); } catch {}
    }

    persistSessionCookie(res, session.sid);
    return res.send(buf);

  } catch (err) {
    console.error("Proxy asset error:", err);
    persistSessionCookie(res, session.sid);
    return res.status(500).send("Proxy asset error: " + (err && err.message ? err.message : String(err)));
  }
});

// fallback to index.html for unknown routes (useful when hosting single-file frontends)
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// start
app.listen(PORT, () => console.log(`Euphoria proxy listening on port ${PORT}`));