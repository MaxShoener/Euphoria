// server.js — Euphoria single-tab proxy (no iframe, no playwright)
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

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(morgan("tiny"));
app.use(compression());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Config & storage
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24h
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

const SESSIONS = new Map(); // sid -> { cookies: Map, last: timestamp }
const MEM_CACHE = new Map(); // key -> { val, t }

// Helpers
function now() { return Date.now(); }
function mkSid() { return Math.random().toString(36).slice(2) + now().toString(36); }

function createSession() {
  const sid = mkSid();
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

function cacheKey(k) { return Buffer.from(k).toString("base64url"); }
function cacheGet(k) {
  const m = MEM_CACHE.get(k);
  if (m && (now() - m.t) < CACHE_TTL) return m.val;
  const f = path.join(CACHE_DIR, cacheKey(k));
  if (fs.existsSync(f)) {
    try {
      const raw = fs.readFileSync(f, "utf8");
      const obj = JSON.parse(raw);
      if ((now() - obj.t) < CACHE_TTL) {
        MEM_CACHE.set(k, { val: obj.val, t: obj.t });
        return obj.val;
      } else {
        try { fs.unlinkSync(f); } catch {}
      }
    } catch {}
  }
  return null;
}
function cacheSet(k, v) {
  MEM_CACHE.set(k, { val: v, t: now() });
  const f = path.join(CACHE_DIR, cacheKey(k));
  try { fs.writeFileSync(f, JSON.stringify({ val: v, t: now() }), "utf8"); } catch (e) {}
}

function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

function buildCookieHeader(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

function storeSetCookieStrings(setCookieStrings = [], sessionData) {
  for (const sc of setCookieStrings) {
    try {
      // parse first "k=v" segment
      const kv = sc.split(";")[0];
      const parsed = cookie.parse(kv || "");
      for (const k in parsed) {
        if (!k) continue;
        sessionData.cookies.set(k, parsed[k]);
      }
    } catch (e) { /* ignore */ }
  }
}

// prune sessions periodically
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) {
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

// utility: extract url from /proxy/<encoded> or ?url=
function extractUrl(req) {
  if (req.query && req.query.url) return req.query.url;
  const m = req.path.match(/^\/proxy\/(.+)$/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}

// Heuristic: decide if an input is a search or a URL
function isLikelySearch(input) {
  if (!input) return true;
  const s = input.trim();
  if (s.includes(" ")) return true; // spaces => search
  if (/^https?:\/\//i.test(s)) return false;
  // if looks like ip or domain with dot, treat as URL
  if (/\./.test(s)) return false;
  // otherwise search (e.g. "gmail", "how to cook")
  return true;
}

// Normalize user input into a proper URL or search
function normalizeInputToURL(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// Routes

// Serve frontend index.html at root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// /load?url=... -> returns rewritten HTML with topbar injected
app.get("/load", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (e.g. /load?url=https://google.com)");

  // normalize if input was a search or plain hostname
  raw = normalizeInputToURL(decodeURIComponent(raw));

  const session = getSession(req);
  if (session.isNew) persistSessionCookie(res, session.sid);

  const cacheKeyHtml = raw + "::html";
  const cached = cacheGet(cacheKeyHtml);
  if (cached) {
    res.setHeader("x-euphoria-session", session.sid);
    return res.type("html").send(cached);
  }

  const cookieHeader = buildCookieHeader(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;
  if (req.headers.referer) headers["Referer"] = req.headers.referer;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    // follow redirects server-side so the response HTML is final and navigation stays inside /load
    const response = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    // store set-cookie
    const setCookies = response.headers.raw ? (response.headers.raw()["set-cookie"] || []) : [];
    if (setCookies.length) storeSetCookieStrings(setCookies, session.data);

    const finalUrl = response.url || raw;
    const contentType = response.headers.get("content-type") || "";

    if (!contentType.includes("text/html")) {
      const buffer = Buffer.from(await response.arrayBuffer());
      persistSessionCookie(res, session.sid);
      if (response.headers.get("content-type")) res.setHeader("Content-Type", response.headers.get("content-type"));
      return res.send(buffer);
    }

    let html = await response.text();

    // remove CSP meta tags to avoid blocking injections
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");

    // remove integrity/crossorigin attributes that break proxied assets
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // inject base tag for relative resolution
    html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><base href="${finalUrl}">`);

    // Remove target="_blank" everywhere
    html = html.replace(/\s+target=(["'])(.*?)\1/gi, " ");

    // Convert window.open(...) -> location.href=... to keep navigation in same tab (best-effort)
    // very simple replace for common patterns:
    html = html.replace(/window\.open\((["'])(https?:\/\/[^"']+)\1(,[^)]+)?\)/gi, (m, q, url) => {
      try { const u = new URL(url).href; return `window.location.href=${q}${u}${q}`; } catch { return m; }
    });

    // Rewrite anchor tags (<a ... href="...">) to /load so clicks navigate full pages via /load
    html = html.replace(/<a\b([^>]*?)href=(["'])([^"']*)\2/gi, (m, pre, q, val) => {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m; // keep non-http
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/load?url=${encodeURIComponent(abs)}"`;
    });

    // For common asset tags (img, script, link), rewrite src/href/srcset to /proxy so browser fetches them through proxy
    html = html.replace(/(<\s*(?:img|script|link)[^>]*?(?:src|href|srcset)=)(["'])([^"']*)\2/gi, (m, prefix, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // Also rewrite inline CSS url(...) references to /proxy
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Rewrite form actions to /proxy so submissions pass through proxy routing
    html = html.replace(/(<\s*form[^>]*action=)(["'])([^"']*)(["'])/gi, (m, pre, q1, val, q2) => {
      if (!val) return m;
      if (/^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q1}/proxy?url=${encodeURIComponent(abs)}${q2}`;
    });

    // Rewrite meta refresh to /load
    html = html.replace(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*>/gi, (m) => {
      const match = m.match(/content\s*=\s*"(.*?)"/i);
      if (!match) return m;
      const parts = match[1].split(";");
      if (parts.length < 2) return m;
      let urlPart = parts.slice(1).join(";");
      const uMatch = urlPart.match(/url=(.*)/i);
      if (!uMatch) return m;
      const dest = uMatch[1].replace(/['"]/g, "").trim();
      const abs = toAbsolute(dest, finalUrl) || dest;
      return `<meta http-equiv="refresh" content="${parts[0]};url=/load?url=${encodeURIComponent(abs)}">`;
    });

    // Remove known analytics scripts to improve performance (best-effort)
    html = html.replace(/<script[^>]*src=["'][^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*["'][^>]*><\/script>/gi, "");

    // Inject topbar UI (solid dark oval)
    const injectedTopbar = `
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
          try {
            const input = document.getElementById('eph-input');
            const go = document.getElementById('eph-go');
            const back = document.getElementById('eph-back');
            const forward = document.getElementById('eph-forward');
            const refresh = document.getElementById('eph-refresh');
            const home = document.getElementById('eph-home');
            const full = document.getElementById('eph-full');

            try {
              const m = window.location.search.match(/[?&]url=([^&]+)/);
              input.value = m ? decodeURIComponent(m[1]) : '';
            } catch (e) {}

            function normalize(v){
              v = (v||'').trim();
              if (!v) return 'https://www.google.com';
              // if looks like a search -> google search
              if (v.includes(' ') || !/\\./.test(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
              try { new URL(v); return v; } catch(e) {}
              return 'https://' + v;
            }

            go.onclick = () => { const url = normalize(input.value); window.location.href = '/load?url=' + encodeURIComponent(url); };
            input.onkeydown = e => { if (e.key === 'Enter') go.onclick(); };
            back.onclick = () => window.history.back();
            forward.onclick = () => window.history.forward();
            refresh.onclick = () => window.location.reload();
            home.onclick = () => window.location.href = '/';
            full.onclick = () => { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };
          } catch(e){}
        })();
      </script>
    `;

    html = html.replace(/<body([^>]*)>/i, (m) => m + injectedTopbar);

    // cache and return
    cacheSet(cacheKeyHtml, html);
    persistSessionCookie(res, session.sid);
    res.setHeader("x-euphoria-session", session.sid);
    res.type("html").send(html);

  } catch (err) {
    console.error("Load error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    res.status(500).send(`<div style="padding:1.5rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// /proxy -> used for assets (images, css, js, XHR). forwards bytes, caches small ones.
app.get("/proxy", async (req, res) => {
  let raw = extractUrl(req);
  if (!raw) raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  const session = getSession(req);
  if (session.isNew) persistSessionCookie(res, session.sid);

  const cacheKeyAsset = raw + "::asset";
  const cached = cacheGet(cacheKeyAsset);
  if (cached) {
    try {
      const obj = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (obj.headers) {
        for (const [k, v] of Object.entries(obj.headers)) res.setHeader(k, v);
      }
      return res.send(Buffer.from(obj.body, "base64"));
    } catch {}
  }

  const cookieHeader = buildCookieHeader(session.data.cookies);
  const headers = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
    "Accept": req.headers["accept"] || "*/*",
    "Referer": req.headers["referer"] || undefined
  };
  if (cookieHeader) headers["Cookie"] = cookieHeader;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const originRes = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

    const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
    if (setCookies.length) storeSetCookieStrings(setCookies, session.data);

    const ctype = originRes.headers.get("content-type") || "application/octet-stream";
    res.setHeader("Content-Type", ctype);
    if (originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));

    const arr = await originRes.arrayBuffer();
    const buf = Buffer.from(arr);

    // Cache small assets to disk+memory
    if (buf.length < 100 * 1024) {
      try {
        cacheSet(cacheKeyAsset, JSON.stringify({ headers: { "Content-Type": ctype }, body: buf.toString("base64") }));
      } catch (e) {}
    }

    persistSessionCookie(res, session.sid);
    return res.send(buf);

  } catch (err) {
    console.error("Proxy asset error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    return res.status(500).send("Proxy asset error: " + (err && err.message ? err.message : String(err)));
  }
});

// fallback to index.html for SPA routing
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
