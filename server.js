// server.js
import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import cookie from "cookie";
import morgan from "morgan";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

//
// Simple session + cookie store
//
const SESSIONS = new Map();
const SESS_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24 hours

function makeSid() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function createSession() {
  const sid = makeSid();
  const data = { cookies: new Map(), last: Date.now() };
  SESSIONS.set(sid, data);
  return { sid, data };
}

function getSession(req) {
  const rawCookies = req.headers.cookie || "";
  const parsed = cookie.parse(rawCookies || "");
  let sid = parsed[SESS_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) {
    const s = createSession();
    return { sid: s.sid, data: s.data, isNew: true };
  }
  const data = SESSIONS.get(sid);
  data.last = Date.now();
  return { sid, data, isNew: false };
}

function persistSessionCookie(res, sid) {
  const sc = cookie.serialize(SESS_NAME, sid, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    maxAge: 60 * 60 * 24
  });
  // if there are already Set-Cookie headers, append
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", sc);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, sc]);
  else res.setHeader("Set-Cookie", [prev, sc]);
}

//
// Simple cache (memory + disk)
//
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes

function cacheKey(url) {
  // file-system safe
  return Buffer.from(url).toString("base64url");
}
function getCached(url) {
  const m = MEM_CACHE.get(url);
  if (m && Date.now() - m.t < CACHE_TTL) return m.v;
  const f = path.join(CACHE_DIR, cacheKey(url));
  if (fs.existsSync(f)) {
    try {
      const raw = fs.readFileSync(f, "utf8");
      const parsed = JSON.parse(raw);
      if (Date.now() - parsed.t < CACHE_TTL) {
        MEM_CACHE.set(url, { v: parsed.v, t: parsed.t });
        return parsed.v;
      } else {
        fs.unlinkSync(f);
      }
    } catch (e) { /* ignore */ }
  }
  return null;
}
function setCached(url, value) {
  const t = Date.now();
  MEM_CACHE.set(url, { v: value, t });
  const f = path.join(CACHE_DIR, cacheKey(url));
  try {
    fs.writeFileSync(f, JSON.stringify({ v: value, t }), "utf8");
  } catch (e) { /* ignore */ }
}

function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

function buildCookieHeaderFromMap(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
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
    } catch (e) { /* ignore parse errors */ }
  }
}

// keep sessions trimmed
setInterval(() => {
  const now = Date.now();
  for (const [sid, data] of SESSIONS.entries()) {
    if ((now - (data.last || 0)) > SESSION_TTL) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

//
// /load : load an HTML page, rewrite URLs, inject UI, return HTML
//
app.get("/load", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url query (e.g. /load?url=https://google.com)");

  // normalize
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSession(req);
  if (session.isNew) persistSessionCookie(res, session.sid);

  // cache
  const cached = getCached(raw + "::html");
  if (cached) {
    res.setHeader("x-euphoria-session", session.sid);
    return res.type("html").send(cached);
  }

  // prepare headers to forward
  const cookieHeader = buildCookieHeaderFromMap(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const r = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // save Set-Cookie from target to session store
    const setCookies = r.headers.raw()["set-cookie"] || [];
    if (setCookies.length) storeSetCookieStringsToSession(setCookies, session.data);

    // handle redirect responses
    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      const loc = r.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      persistSessionCookie(res, session.sid);
      return res.type("html").send(`<meta http-equiv="refresh" content="0;url=/load?url=${encodeURIComponent(resolved)}">`);
    }

    const ctype = r.headers.get("content-type") || "";
    if (!ctype.includes("text/html")) {
      // non-html served here (rare); forward bytes
      const buf = Buffer.from(await r.arrayBuffer());
      persistSessionCookie(res, session.sid);
      if (r.headers.get("content-type")) res.setHeader("Content-Type", r.headers.get("content-type"));
      return res.send(buf);
    }

    let html = await r.text();

    // sanitize meta CSP + SRI/CORS blocking attributes that break proxied pages
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // inject base tag to help relative URL resolution
    html = html.replace(/<head([^>]*)>/i, (m,g)=>`<head${g}><base href="${raw}">`);

    // rewrite resource URLs to /proxy so assets use server session cookies
    html = html.replace(/(href|src|srcset)=["']([^"']*)["']/gi, (m, attr, val) => {
      if (!val) return m;
      if (/^(javascript:|data:|mailto:|tel:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      // convert protocol-relative URLs
      if (/^\/\//.test(val)) {
        try {
          const abs = new URL(val, raw).href;
          return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
        } catch { return m; }
      }
      const abs = toAbsolute(val, raw) || val;
      try { return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`; } catch { return m; }
    });

    // rewrite CSS url(...) references
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, raw) || val;
      try { return `url("/proxy?url=${encodeURIComponent(abs)}")`; } catch { return m; }
    });

    // remove some known analytics scripts to reduce noise (best-effort)
    html = html.replace(/<script[^>]*src=["'][^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*["'][^>]*><\/script>/gi, "");

    // inject euphoria topbar UI right after <body> — this keeps the frontend single-file (index.html) approach compatibility
    const ui = `
      <div id="euphoria-topbar" style="position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:2147483647;width:78%;max-width:1200px;background:#111;border-radius:28px;padding:8px 12px;display:flex;align-items:center;gap:8px;box-shadow:0 6px 20px rgba(0,0,0,0.6);font-family:system-ui,Arial,sans-serif;">
        <button id="eph-back" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">◀</button>
        <button id="eph-forward" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">▶</button>
        <button id="eph-refresh" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⟳</button>
        <button id="eph-home" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">🏠</button>
        <input id="eph-input" style="flex:1;padding:8px 12px;border-radius:12px;border:0;background:#222;color:#fff;outline:none" placeholder="Enter URL or search..." />
        <button id="eph-go" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#2e7d32;color:#fff;cursor:pointer">Go</button>
        <button id="eph-full" style="min-width:44px;padding:8px;border-radius:12px;border:0;background:#222;color:#fff;cursor:pointer">⛶</button>
      </div>
      <style>body{padding-top:76px !important;} </style>
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

            // preload input with friendly display url
            try {
              const loc = window.location.search.match(/[?&]url=([^&]+)/);
              input.value = loc ? decodeURIComponent(loc[1]) : '';
            } catch(e){}

            function normalizeInput(v){
              v = (v||'').trim();
              if (!v) return 'https://www.google.com';
              try { new URL(v); return v; } catch(e) {}
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

            // monkeypatch fetch to include session header (makes XHR on page include session)
            const origFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
              init.headers = init.headers || {};
              try {
                const cookieVal = document.cookie.split('; ').find(c => c.startsWith('${SESS_NAME}='));
                if (cookieVal) init.headers['x-euphoria-session'] = cookieVal.split('=')[1];
              } catch (e) {}
              return origFetch(resource, init);
            };
          } catch(e) { console.warn('Euphoria UI injection error', e); }
        })();
      </script>
    `;

    html = html.replace(/<body([^>]*)>/i, (m) => m + ui);

    // cache and respond
    setCached(raw + "::html", html);
    persistSessionCookie(res, session.sid);
    res.setHeader("x-euphoria-session", session.sid);
    return res.type("html").send(html);

  } catch (err) {
    console.error("load error:", err && err.message ? err.message : err);
    return res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

//
// /proxy : proxy arbitrary assets (js/css/images/xhr targets) and attach session cookies
//
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSession(req);
  if (session.isNew) persistSessionCookie(res, session.sid);

  // small memory cache for assets
  const cached = getCached(raw + "::asset");
  if (cached) {
    // cached value is an object { body: base64, headers: { ... } }
    try {
      const obj = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (obj.headers) {
        for (const [k, v] of Object.entries(obj.headers)) res.setHeader(k, v);
      }
      res.send(Buffer.from(obj.body, "base64"));
      return;
    } catch (e) { /* ignore parse error and fetch anew */ }
  }

  // prepare headers
  const cookieHeader = buildCookieHeaderFromMap(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Mozilla/5.0",
    "Accept": req.headers["accept"] || "*/*",
    "Referer": req.headers["referer"] || undefined
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const r = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // propagate set-cookie to session
    const setCookies = r.headers.raw()["set-cookie"] || [];
    if (setCookies.length) storeSetCookieStringsToSession(setCookies, session.data);

    // redirects -> re-route through /proxy
    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      const loc = r.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      persistSessionCookie(res, session.sid);
      return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    const ctype = r.headers.get("content-type") || "application/octet-stream";
    res.setHeader("Content-Type", ctype);
    if (r.headers.get("cache-control")) res.setHeader("Cache-Control", r.headers.get("cache-control"));

    const arr = await r.arrayBuffer();
    const buf = Buffer.from(arr);

    // cache small assets
    if (buf.length < 100 * 1024) {
      try {
        setCached(raw + "::asset", JSON.stringify({ headers: { "Content-Type": ctype }, body: buf.toString("base64") }));
      } catch (e) { /* ignore */ }
    }

    persistSessionCookie(res, session.sid);
    return res.send(buf);
  } catch (err) {
    console.error("proxy asset error:", err && err.message ? err.message : err);
    return res.status(500).send("Proxy asset error: " + (err && err.message ? err.message : String(err)));
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));