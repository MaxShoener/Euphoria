// server.js
// EUPHORIA v2 (B2 FULL) — JSDOM-powered hybrid smart rewriter with enhanced features
// - Node 20+ recommended
// - Dependencies: express, jsdom, ws, compression, morgan, cors, cookie

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { JSDOM } from "jsdom";
import { WebSocketServer } from "ws";
import cookie from "cookie";
import { EventEmitter } from "events";
import crypto from "crypto";

EventEmitter.defaultMaxListeners = 500;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ------------------------ CONFIG ------------------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes
const FETCH_TIMEOUT_MS = 30000;
const ASSET_CACHE_THRESHOLD = 512 * 1024; // 512KB for assets
const USER_AGENT_DEFAULT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

// Ensure cache directory exists
if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// Asset extensions considered binary
const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
  ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map", ".mp4", ".webm", ".mp3"
];
const SPECIAL_FILES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

// Headers to drop (CSP, frame policies, etc.)
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// ------------------------ EXPRESS SETUP ------------------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ------------------------ CACHE (memory + disk) ------------------------
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheKey(s) { return crypto.createHash("sha256").update(s).digest("base64url"); }

function cacheGet(key) {
  const e = MEM_CACHE.get(key);
  if (e && (now() - e.t) < CACHE_TTL) return e.v;
  if (ENABLE_DISK_CACHE) {
    try {
      const fname = path.join(CACHE_DIR, cacheKey(key));
      if (fs.existsSync(fname)) {
        const raw = fs.readFileSync(fname, "utf8");
        const obj = JSON.parse(raw);
        if ((now() - obj.t) < CACHE_TTL) { MEM_CACHE.set(key, { v: obj.v, t: obj.t }); return obj.v; }
        try { fs.unlinkSync(fname); } catch (e) { }
      }
    } catch (e) { }
  }
  return null;
}

function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(() => { });
  }
}

// ------------------------ SESSIONS / COOKIE STORE ------------------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header = "") { const out = {}; header.split(";").forEach(p => { const [k, v] = (p || "").split("=").map(s => (s || "").trim()); if (k && v) out[k] = v; }); return out; }
function getSessionFromReq(req) {
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid); payload.last = now(); return { sid, payload };
}
function setSessionCookieHeader(res, sid) {
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function storeSetCookieToSession(setCookies = [], sessionPayload) {
  for (const sc of setCookies) {
    try {
      const kv = sc.split(";")[0];
      const idx = kv.indexOf("=");
      if (idx === -1) continue;
      const k = kv.slice(0, idx).trim(); const v = kv.slice(idx + 1).trim();
      if (k) sessionPayload.cookies.set(k, v);
    } catch (e) { }
  }
}
function buildCookieHeader(map) { return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; "); }

// cleanup stale sessions occasionally
setInterval(() => { const cutoff = Date.now() - (1000 * 60 * 60 * 24); for (const [k, p] of SESSIONS.entries()) if (p.last < cutoff) SESSIONS.delete(k); }, 1000 * 60 * 30);

// ------------------------ HELPERS ------------------------
function isAlreadyProxiedHref(href) {
  if (!href) return false;
  try {
    if (href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if (resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch (e) { }
  return false;
}
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function proxyizeAbsoluteUrl(abs) {
  try { const u = new URL(abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; }
  catch (e) { try { const u2 = new URL("https://" + abs); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch (e2) { return abs; } }
}
function looksLikeAsset(urlStr) {
  if (!urlStr) return false;
  try {
    const p = new URL(urlStr, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (p.endsWith(ext)) return true;
    for (const s of SPECIAL_FILES) if (p.endsWith(s)) return true;
    return false;
  } catch (e) {
    const lower = urlStr.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (lower.endsWith(ext)) return true;
    for (const s of SPECIAL_FILES) if (lower.endsWith(s)) return true;
    return false;
  }
}

// sanitize HTML string: remove CSP meta, integrity, crossorigin attributes
function sanitizeHtml(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch (e) { }
  return html;
}

// ------------------------ JSDOM TRANSFORM ------------------------
function jsdomTransform(html, baseUrl) {
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;

    // inject base if missing
    if (!document.querySelector('base')) {
      const head = document.querySelector('head');
      if (head) {
        const b = document.createElement('base');
        b.setAttribute('href', baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }

    // rewrite anchors
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    anchors.forEach(a => {
      try {
        const href = a.getAttribute('href');
        if (!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if (isAlreadyProxiedHref(href)) return;
        const abs = toAbsolute(href, baseUrl) || href;
        a.setAttribute('href', proxyizeAbsoluteUrl(abs));
        a.removeAttribute('target');
      } catch (e) { }
    });

    // rewrite forms
    const forms = Array.from(document.querySelectorAll('form[action]'));
    forms.forEach(f => {
      try {
        const act = f.getAttribute('action') || '';
        if (!act) return;
        if (isAlreadyProxiedHref(act)) return;
        const abs = toAbsolute(act, baseUrl) || act;
        f.setAttribute('action', proxyizeAbsoluteUrl(abs));
      } catch (e) { }
    });

    // assets rewrite
    const assetTags = ['img', 'script', 'link', 'iframe', 'source', 'video', 'audio'];
    assetTags.forEach(tag => {
      const nodes = Array.from(document.getElementsByTagName(tag));
      nodes.forEach(el => {
        try {
          const srcAttr = el.getAttribute('src') ? 'src' : (el.getAttribute('href') ? 'href' : null);
          if (!srcAttr) return;
          const v = el.getAttribute(srcAttr);
          if (!v) return;
          if (/^data:/i.test(v)) return;
          if (isAlreadyProxiedHref(v)) return;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(srcAttr, proxyizeAbsoluteUrl(abs));
        } catch (e) { }
      });
    });

    // srcset rewrite
    const srcsetEls = Array.from(document.querySelectorAll('[srcset]'));
    srcsetEls.forEach(el => {
      try {
        const ss = el.getAttribute('srcset') || '';
        const parts = ss.split(',').map(p => {
          const [u, rest] = p.trim().split(/\s+/, 2);
          if (!u) return p;
          if (/^data:/i.test(u)) return p;
          if (isAlreadyProxiedHref(u)) return p;
          const abs = toAbsolute(u, baseUrl) || u;
          return proxyizeAbsoluteUrl(abs) + (rest ? ' ' + rest : '');
        });
        el.setAttribute('srcset', parts.join(', '));
      } catch (e) { }
    });

    // CSS url(...) rewrite
    const styles = Array.from(document.querySelectorAll('style'));
    styles.forEach(st => {
      try {
        let txt = st.textContent || '';
        txt = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
          if (!u) return m;
          if (/^data:/i.test(u)) return m;
          if (isAlreadyProxiedHref(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyizeAbsoluteUrl(abs)}")`;
        });
        st.textContent = txt;
      } catch (e) { }
    });
    const inlines = Array.from(document.querySelectorAll('[style]'));
    inlines.forEach(el => {
      try {
        const s = el.getAttribute('style') || '';
        const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
          if (!u) return m;
          if (/^data:/i.test(u)) return m;
          if (isAlreadyProxiedHref(u)) return m;
          const abs = toAbsolute(u, baseUrl) || u;
          return `url("${proxyizeAbsoluteUrl(abs)}")`;
        });
        el.setAttribute('style', out);
      } catch (e) { }
    });

    // meta refresh rewrite
    const metas = Array.from(document.querySelectorAll('meta[http-equiv]'));
    metas.forEach(m => {
      try {
        if ((m.getAttribute('http-equiv') || '').toLowerCase() !== 'refresh') return;
        const c = m.getAttribute('content') || '';
        const parts = c.split(';');
        if (parts.length < 2) return;
        const urlpart = parts.slice(1).join(';').match(/url=(.*)/i);
        if (!urlpart) return;
        const dest = urlpart[1].replace(/['"]/g, '').trim();
        const abs = toAbsolute(dest, baseUrl) || dest;
        m.setAttribute('content', parts[0] + ';url=' + proxyizeAbsoluteUrl(abs));
      } catch (e) { }
    });

    // remove problematic noscript blocks
    const noscripts = Array.from(document.getElementsByTagName('noscript'));
    noscripts.forEach(n => { try { n.parentNode && n.parentNode.removeChild(n); } catch (e) { } });

    return dom.serialize();
  } catch (err) {
    console.warn("jsdom transform failed", err && err.message ? err.message : err);
    return html;
  }
}

// ------------------------ INLINE JS REWRITE ------------------------
function rewriteInlineJs(source, baseUrl) {
  try {
    source = source.replace(/fetch\((['"])([^'"]+?)\1/gi, (m, q, u) => {
      try {
        if (u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs)}'`;
      } catch (e) { return m; }
    });
    source = source.replace(/\.open\(\s*(['"])(GET|POST|PUT|DELETE|HEAD|OPTIONS)?\1\s*,\s*(['"])([^'"]+?)\3/gi, (m, p1, method, p3, u) => {
      try {
        if (u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `.open(${p1}${method || ''}${p1},'${proxyizeAbsoluteUrl(abs)}'`;
      } catch (e) { return m; }
    });
    source = source.replace(/(['"])(\/[^'"]+?\.[a-z0-9]{2,6}[^'"]*?)\1/gi, (m, q, u) => {
      try {
        if (u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `'${proxyizeAbsoluteUrl(abs)}'`;
      } catch (e) { return m; }
    });
    return source;
  } catch (e) { return source; }
}

// ------------------------ SERVICE WORKER PATCH ------------------------
function patchServiceWorker(source, baseUrl) {
  try {
    let s = source;
    s = s.replace(/importScripts\(([^)]+)\)/gi, (m, args) => {
      try {
        const arr = eval("[" + args + "]");
        const out = arr.map(item => {
          if (typeof item === 'string') {
            const abs = toAbsolute(item, baseUrl) || item;
            return `'${proxyizeAbsoluteUrl(abs)}'`;
          }
          return JSON.stringify(item);
        });
        return `importScripts(${out.join(',')})`;
      } catch (e) { return m; }
    });
    s = s.replace(/fetch\((['"])([^'"]+?)\1/gi, (m, q, u) => {
      try {
        if (u.includes('/proxy?url=') || /^data:/i.test(u)) return m;
        const abs = toAbsolute(u, baseUrl) || u;
        return `fetch('${proxyizeAbsoluteUrl(abs)}'`;
      } catch (e) { return m; }
    });
    return s;
  } catch (e) { return source; }
}

// ------------------------ WEBSOCKET TELEMETRY ------------------------
const server = app.listen(PORT, () => console.log(`Euphoria v2 (B2 FULL) running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try { const parsed = JSON.parse(raw.toString()); if (parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg: 'pong', ts: Date.now() })); } catch (e) { }
  });
});

// ------------------------ /proxy ENDPOINT ------------------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url || (req.query.u || "");
  if (!raw) return res.status(400).send("Missing url parameter");

  const { sid, payload } = getSessionFromReq(req);
  setSessionCookieHeader(res, sid);

  let cacheVal = cacheGet(raw);
  if (cacheVal) return sendProxiedContent(res, cacheVal);

  try {
    const headers = { "user-agent": payload.ua };
    if (payload.cookies.size > 0) headers["cookie"] = buildCookieHeader(payload.cookies);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const resp = await fetch(raw, { headers, signal: controller.signal, redirect: "follow" });
    clearTimeout(timeout);

    // store session cookies
    storeSetCookieToSession(resp.headers.raw()['set-cookie'] || [], payload);

    // drop problematic headers
    const outHeaders = {};
    resp.headers.forEach((v, k) => { if (!DROP_HEADERS.has(k.toLowerCase())) outHeaders[k] = v; });
    res.writeHead(resp.status, outHeaders);

    const contentType = (resp.headers.get("content-type") || "").toLowerCase();
    if (contentType.includes("text/html")) {
      let text = await resp.text();
      text = sanitizeHtml(text);
      text = jsdomTransform(text, raw);
      cacheSet(raw, text);
      return res.send(text);
    } else if (contentType.includes("javascript") || contentType.includes("json")) {
      let text = await resp.text();
      text = rewriteInlineJs(text, raw);
      if (SPECIAL_FILES.some(f => raw.endsWith(f))) text = patchServiceWorker(text, raw);
      cacheSet(raw, text);
      return res.send(text);
    } else {
      const buffer = await resp.arrayBuffer();
      cacheSet(raw, buffer);
      return res.send(Buffer.from(buffer));
    }
  } catch (e) {
    console.error("Proxy error:", e && e.message ? e.message : e);
    return res.status(500).send("Proxy fetch failed");
  }
});

function sendProxiedContent(res, content) {
  if (Buffer.isBuffer(content)) return res.send(content);
  return res.send(content.toString());
}

// ------------------------ 404 CATCH ------------------------
app.use((req, res) => res.status(404).send("Euphoria: Not found"));