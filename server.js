// server.js — Euphoria (Scramjet-based proxy; no iframe)
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import mime from "mime-types";
import pkg from "scramjet"; // scramjet is CommonJS; import default then destructure
const { StringStream } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));

/* -------------------- Simple session store (in-memory) -------------------- */
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24h
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
    } catch (e) { /* ignore */ }
  }
}
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
}, 1000 * 60 * 10);

/* -------------------- Lightweight cache (memory + disk) -------------------- */
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes
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

/* -------------------- Helpers -------------------- */
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function normalizeInput(raw) {
  if (!raw) return "";
  raw = raw.trim();
  if (/^https?:\/\//i.test(raw)) return raw;
  // if it looks like a search (space or no dot), treat as google search
  if (raw.includes(" ") || !raw.includes(".")) return "https://www.google.com/search?q=" + encodeURIComponent(raw);
  return "https://" + raw;
}
function removeMetaCSP(html) {
  return html.replace(/<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");
}
// safe sanitizer for analytics scripts: remove external script tags that contain certain hostnames
function stripKnownTrackers(html) {
  // keep regex simple and safe — no nested escaped quotes that break parsing
  return html.replace(/<script[^>]+src=["'][^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*["'][^>]*><\/script>/gi, "");
}

/* -------------------- HTML rewriting --------------------
   We must carefully replace href/src/srcset/url(...) with proxied endpoints.
   Avoid messing with data: and javascript: and already proxied urls.
-------------------------------------------------------------------------*/
function rewriteHtmlForProxy(baseUrl, html) {
  if (!html || typeof html !== "string") return html;
  // remove meta CSP tags and integrity/crossorigin attributes
  html = removeMetaCSP(html);
  html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
  html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  html = stripKnownTrackers(html);

  // inject base if missing (helps relative URLs)
  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(/<head([^>]*)>/i, `<head$1><base href="${baseUrl}">`);
  } else {
    html = `<base href="${baseUrl}">` + html;
  }

  // rewrite hrefs (absolute or relative) -> /proxy?url=abs
  html = html.replace(/(<a\b[^>]*?\bhref=)(["'])([^"'>]+)\2/gi, (m, before, quote, href) => {
    if (!href) return m;
    const skip = /^(javascript:|mailto:|tel:|#)/i.test(href) || href.startsWith("/proxy?url=") || href.startsWith("data:");
    if (skip) return m;
    const abs = toAbsolute(href, baseUrl) || href;
    return `${before}${quote}/proxy?url=${encodeURIComponent(abs)}${quote}`;
  });

  // rewrite src and href on assets (img, script, link, source, video, audio)
  html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?\b(?:src|href)=)(["'])([^"'>]+)\2/gi, (m, before, quote, src) => {
    if (!src) return m;
    if (/^data:/i.test(src) || src.startsWith("/proxy?url=")) return m;
    if (/^javascript:/i.test(src)) return m;
    const abs = toAbsolute(src, baseUrl) || src;
    // serve assets via /asset so content-type is preserved
    return `${before}${quote}/asset?url=${encodeURIComponent(abs)}${quote}`;
  });

  // rewrite srcset attributes
  html = html.replace(/(<[^>]+?\bsrcset=)(["'])([^"']+)["']/gi, (m, before, quote, val) => {
    try {
      const parts = val.split(",").map(p => {
        const t = p.trim();
        const [u, rest] = t.split(/\s+/, 2);
        if (!u) return t;
        if (/^data:/i.test(u) || u.startsWith("/proxy?url=")) return t;
        const abs = toAbsolute(u, baseUrl) || u;
        return `/asset?url=${encodeURIComponent(abs)}` + (rest ? " " + rest : "");
      });
      return `${before}${quote}${parts.join(", ")}${quote}`;
    } catch (e) {
      return m;
    }
  });

  // rewrite CSS url(...)
  html = html.replace(/url\((['"]?)(?!data:)([^'")]+)\1\)/gi, (m, q, url) => {
    const abs = toAbsolute(url, baseUrl) || url;
    return `url("/asset?url=${encodeURIComponent(abs)}")`;
  });

  return html;
}

/* -------------------- /asset endpoint -------------------- */
app.get("/asset", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const target = /^https?:\/\//i.test(raw) ? raw : ("https://" + raw);
  // cache key
  const key = target + "::asset";
  const cached = cacheGet(key);
  if (cached) {
    try {
      const obj = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (obj.headers) Object.entries(obj.headers).forEach(([k, v]) => res.setHeader(k, v));
      return res.send(Buffer.from(obj.body, "base64"));
    } catch (e) { /* fallback to fetch */ }
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
    // small assets cached
    if (buffer.length < 100 * 1024) {
      try { cacheSet(key, JSON.stringify({ headers: { "Content-Type": ctype }, body: buffer.toString("base64") })); } catch (e) { }
    }
    return res.send(buffer);
  } catch (err) {
    console.error("Asset error:", err && err.message ? err.message : err);
    return res.status(500).send("Asset load failed");
  }
});

/* -------------------- /proxy endpoint (HTML streaming) -------------------- */
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  // session
  const { sid, data: sessionData } = getSession(req);
  persistSessionCookie(res, sid);

  // Normalize and detect search-ish inputs
  try {
    raw = decodeURIComponent(raw);
  } catch (e) { /* ok */ }
  if (!/^https?:\/\//i.test(raw)) raw = normalizeInput(raw);

  const cacheKeyHtml = raw + "::html";
  // try cache
  const cached = cacheGet(cacheKeyHtml);
  if (cached) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    // stream via scramjet
    try {
      StringStream.from(cached).pipe(res);
      return;
    } catch (e) { res.send(cached); return; }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    // Build cookie header from session
    const cookieParts = [];
    for (const [k, v] of sessionData.cookies.entries()) cookieParts.push(`${k}=${v}`);
    const cookieHeader = cookieParts.join("; ");
    const headers = {
      "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    };
    if (cookieHeader) headers["Cookie"] = cookieHeader;
    if (req.headers.referer) headers["Referer"] = req.headers.referer;

    const originRes = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // follow server-side redirect to keep navigation inside proxy
    if (originRes.status >= 300 && originRes.status < 400 && originRes.headers.get("location")) {
      const loc = originRes.headers.get("location");
      const resolved = toAbsolute(loc, raw);
      if (resolved) return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    // store set-cookie in session store
    try {
      const sc = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
      if (sc.length) storeSetCookieStrings(sc, sessionData);
    } catch (e) { }

    const contentType = originRes.headers.get("content-type") || "";
    if (!contentType.includes("text/html")) {
      // binary
      const buffer = Buffer.from(await originRes.arrayBuffer());
      if (buffer.length < 100 * 1024) {
        try { cacheSet(cacheKeyHtml, buffer.toString("base64")); } catch (e) { }
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      persistSessionCookie(res, sid);
      return res.send(buffer);
    }

    // HTML path: fully read as text (we need full string for safe rewriting and script re-injection)
    let html = await originRes.text();

    // rewrite with proxy references
    const finalUrl = originRes.url || raw;
    let out = rewriteHtmlForProxy(finalUrl, html);

    // inject containment/topbar placeholder only if not already injected
    const TOPBAR_SNIPPET = `<div id="euphoria-host-topbar"></div>`;
    if (!out.includes("id=\"euphoria-host-topbar\"")) {
      // inject a small placeholder for the topbar (actual topbar from index.html will remain)
      if (/<body[^>]*>/i.test(out)) {
        out = out.replace(/<body([^>]*)>/i, `<body$1>${TOPBAR_SNIPPET}`);
      } else {
        out = TOPBAR_SNIPPET + out;
      }
    }

    // cache and stream response
    cacheSet(cacheKeyHtml, out);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, sid);
    // stream using scramjet for progressive send
    try {
      StringStream.from(out).pipe(res);
    } catch (e) {
      // fallback
      res.send(out);
    }
  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : err);
    persistSessionCookie(res, sid);
    res.status(500).send(`<div style="padding:1rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

/* -------------------- fallback to index.html for SPA routes -------------------- */
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

/* -------------------- start -------------------- */
app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));