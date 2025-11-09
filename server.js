// server.js — Euphoria proxy (no iframe, scramjet streaming)
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import mime from "mime-types";
import pkg from "scramjet"; // scramjet is CommonJS -> default import then destructure
const { StringStream } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// static public (index.html lives in /public)
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -- Simple in-memory session store for cookies --
const SESSION_TTL = 1000 * 60 * 60 * 24;
const SESSIONS = new Map();
function mkSid() { return Math.random().toString(36).slice(2) + "-" + Date.now().toString(36); }
function now() { return Date.now(); }
function createSession() {
  const sid = mkSid();
  const data = { cookies: new Map(), created: now(), last: now() };
  SESSIONS.set(sid, data);
  return { sid, data };
}
function getSession(req) {
  const header = req.headers.cookie || "";
  const m = (header.match(/euphoria_sid=([^;]+)/) || [null, null])[1];
  if (!m || !SESSIONS.has(m)) return createSession();
  const data = SESSIONS.get(m);
  data.last = now();
  return { sid: m, data };
}
function persistSessionCookie(res, sid) {
  const cookie = `euphoria_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookie);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [prev, cookie]);
}
function storeSetCookieStrings(setCookies = [], sessionData) {
  for (const sc of setCookies) {
    try {
      const kv = sc.split(";")[0];
      const [k, v] = kv.split("=");
      if (k && v) sessionData.cookies.set(k.trim(), v.trim());
    } catch (e) { }
  }
}
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
}, 1000 * 60 * 10);

// -- Lightweight cache (memory + disk) --
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 10;

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
      } else try { fs.unlinkSync(f); } catch (e) { }
    } catch (e) { }
  }
  return null;
}
function cacheSet(k, v) {
  MEM_CACHE.set(k, { val: v, t: now() });
  try { fs.writeFileSync(path.join(CACHE_DIR, cacheKey(k)), JSON.stringify({ val: v, t: now() }), "utf8"); } catch (e) { }
}

// -- helpers --
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function isLikelySearch(input) {
  if (!input) return true;
  if (input.includes(" ")) return true;
  if (/^https?:\/\//i.test(input)) return false;
  if (!input.includes(".")) return true;
  return false;
}
function normalizeInput(raw) {
  raw = (raw || "").trim();
  if (!raw) return "https://www.google.com";
  if (/^https?:\/\//i.test(raw)) return raw;
  if (isLikelySearch(raw)) return "https://www.google.com/search?q=" + encodeURIComponent(raw);
  return "https://" + raw;
}
function removeMetaCSP(html) {
  return html.replace(/<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");
}
function stripKnownTrackers(html) {
  // remove common external analytics script tags (best-effort)
  return html.replace(/<script[^>]+src=(["'])([^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*)\1[^>]*><\/script>/gi, "");
}

// rewrite HTML to route resource links through our proxy endpoints
function rewriteHtmlForProxy(baseUrl, html) {
  if (!html || typeof html !== "string") return html;
  html = removeMetaCSP(html);
  html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
  html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  html = stripKnownTrackers(html);

  // inject base
  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(/<head([^>]*)>/i, `<head$1><base href="${baseUrl}">`);
  } else {
    html = `<base href="${baseUrl}">` + html;
  }

  // anchors -> /proxy?url=
  html = html.replace(/(<a\b[^>]*?\bhref=)(["'])([^"'>]+)\2/gi, (m, before, quote, href) => {
    if (!href) return m;
    if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return m;
    if (href.startsWith("/proxy?url=") || href.startsWith("data:")) return m;
    const abs = toAbsolute(href, baseUrl) || href;
    return `${before}${quote}/proxy?url=${encodeURIComponent(abs)}${quote}`;
  });

  // asset tags (img/script/link/source/video/audio/iframe) -> /asset?url=
  html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?\b(?:src|href)=)(["'])([^"'>]+)\2/gi, (m, before, quote, src) => {
    if (!src) return m;
    if (/^data:/i.test(src) || src.startsWith("/asset?url=") || src.startsWith("/proxy?url=")) return m;
    const abs = toAbsolute(src, baseUrl) || src;
    return `${before}${quote}/asset?url=${encodeURIComponent(abs)}${quote}`;
  });

  // srcset rewrite
  html = html.replace(/(<[^>]+?\bsrcset=)(["'])([^"']+)["']/gi, (m, before, quote, val) => {
    try {
      const parts = val.split(",").map(p => {
        const t = p.trim();
        const [u, rest] = t.split(/\s+/, 2);
        if (!u) return t;
        if (/^data:/i.test(u)) return t;
        const abs = toAbsolute(u, baseUrl) || u;
        return `/asset?url=${encodeURIComponent(abs)}` + (rest ? " " + rest : "");
      });
      return `${before}${quote}${parts.join(", ")}${quote}`;
    } catch (e) {
      return m;
    }
  });

  // CSS url(...) rewrite
  html = html.replace(/url\((['"]?)(?!data:)([^'")]+)\1\)/gi, (m, q, url) => {
    const abs = toAbsolute(url, baseUrl) || url;
    return `url("/asset?url=${encodeURIComponent(abs)}")`;
  });

  return html;
}

// /asset endpoint -> fetch binary/text resources and forward
app.get("/asset", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const target = /^https?:\/\//i.test(raw) ? raw : ("https://" + raw);
  const key = target + "::asset";
  const cached = cacheGet(key);
  if (cached) {
    try {
      const obj = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (obj.headers) Object.entries(obj.headers).forEach(([k, v]) => res.setHeader(k, v));
      return res.send(Buffer.from(obj.body, "base64"));
    } catch (e) { /* fallback */ }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    const r = await fetch(target, { signal: controller.signal, redirect: "follow", headers: { "User-Agent": "Euphoria/1.0" } });
    clearTimeout(timeout);
    const buffer = Buffer.from(await r.arrayBuffer());
    const ctype = r.headers.get("content-type") || mime.lookup(path.basename(target)) || "application/octet-stream";
    res.setHeader("Content-Type", ctype);
    const cacheControl = r.headers.get("cache-control");
    if (cacheControl) res.setHeader("Cache-Control", cacheControl);
    if (buffer.length < 100 * 1024) {
      try { cacheSet(key, JSON.stringify({ headers: { "Content-Type": ctype }, body: buffer.toString("base64") })); } catch (e) { }
    }
    return res.send(buffer);
  } catch (err) {
    console.error("Asset error:", err && err.message ? err.message : err);
    return res.status(500).send("Asset load failed");
  }
});

// /proxy endpoint -> fetch HTML, rewrite, inject containment
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const session = getSession(req);
  persistSessionCookie(res, session.sid);

  try {
    // decode & normalize
    try { raw = decodeURIComponent(raw); } catch (e) { /* ok */ }
    if (!/^https?:\/\//i.test(raw)) raw = normalizeInput(raw);

    const cacheKeyHtml = raw + "::html";
    const cached = cacheGet(cacheKeyHtml);
    if (cached) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      try { StringStream.from(cached).pipe(res); return; } catch (e) { res.send(cached); return; }
    }

    // Build headers with cookies from session
    const cookieParts = [];
    for (const [k, v] of session.data.cookies.entries()) cookieParts.push(`${k}=${v}`);
    const cookieHeader = cookieParts.join("; ");
    const headers = {
      "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    };
    if (cookieHeader) headers["Cookie"] = cookieHeader;
    if (req.headers.referer) headers["Referer"] = req.headers.referer;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const originRes = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // handle server-side redirects -> route through our /proxy
    if (originRes.status >= 300 && originRes.status < 400 && originRes.headers.get("location")) {
      const loc = originRes.headers.get("location");
      const resolved = toAbsolute(loc, raw);
      if (resolved) return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    // store set-cookie values in session
    try {
      const sc = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
      if (sc.length) storeSetCookieStrings(sc, session.data);
    } catch (e) { }

    const contentType = originRes.headers.get("content-type") || "";
    if (!contentType.includes("text/html")) {
      const buffer = Buffer.from(await originRes.arrayBuffer());
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      const cacheControl = originRes.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      persistSessionCookie(res, session.sid);
      return res.send(buffer);
    }

    // HTML path
    let html = await originRes.text();
    const finalUrl = originRes.url || raw;

    // rewrite safely
    const out = rewriteHtmlForProxy(finalUrl, html);

    // inject a lightweight containment helper snippet (if not already present)
    const CONTAIN_SNIP = `<div id="euphoria-proxy-marker" style="display:none"></div>`;
    let finalOut = out;
    if (!finalOut.includes('id="euphoria-proxy-marker"')) {
      if (/<body[^>]*>/i.test(finalOut)) finalOut = finalOut.replace(/<body([^>]*)>/i, `<body$1>${CONTAIN_SNIP}`);
      else finalOut = CONTAIN_SNIP + finalOut;
    }

    // cache and stream
    cacheSet(cacheKeyHtml, finalOut);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    try { StringStream.from(finalOut).pipe(res); }
    catch (e) { res.send(finalOut); }
  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    res.status(500).send(`<div style="padding:1rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// fallback to index.html for SPA routes
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));