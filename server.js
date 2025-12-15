// server.js
// Euphoria v3 - "browser-like" proxy: aggressive HTML/CSS/JS rewriting + client runtime hooks.
// Node 20+, single-file deployment.
//
// SECTION: Imports

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
import { EventEmitter } from "events";
import rateLimit from "express-rate-limit";
import { LRUCache } from "lru-cache";
import http from "http";
import https from "https";
import zlib from "zlib";

EventEmitter.defaultMaxListeners = 300;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// SECTION: Config

const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = process.env.ENABLE_DISK_CACHE !== "0";
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS || String(1000 * 60 * 10), 10); // 10 min
const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "35000", 10);
const USER_AGENT_DEFAULT =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const MAX_MEM_CACHE_BYTES = parseInt(process.env.MAX_MEM_CACHE_BYTES || String(128 * 1024 * 1024), 10); // 128MB
const MAX_ASSET_CACHE_BYTES = parseInt(process.env.MAX_ASSET_CACHE_BYTES || String(2 * 1024 * 1024), 10); // 2MB per asset
const MAX_HTML_CACHE_BYTES = parseInt(process.env.MAX_HTML_CACHE_BYTES || String(2 * 1024 * 1024), 10); // 2MB per html
const PER_HOST_CACHE_CONTROLS = {}; // { "example.com": { disable: true, ttlMs: 60000 } }

const SESSION_NAME = "euphoria_sid";
const SESSION_TTL_MS = parseInt(process.env.SESSION_TTL_MS || String(1000 * 60 * 60 * 8), 10); // 8h
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

if (ENABLE_DISK_CACHE) await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// SECTION: Constants

const DROP_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy",
  "strict-transport-security", // optional; can cause odd loops in proxy contexts
]);

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css",
  ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico", ".avif",
  ".ttf", ".otf", ".woff", ".woff2", ".eot",
  ".json", ".map",
  ".mp4", ".webm", ".mp3", ".m4a", ".ogg",
  ".pdf",
];

const SPECIAL_FILES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

// SECTION: App

const app = express();
app.set("trust proxy", true);
app.use(cors({ origin: true, credentials: true }));
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || "900", 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down.",
});
app.use(globalLimiter);

// SECTION: Memory Cache (byte-sized)

const MEM_CACHE = new LRUCache({
  maxSize: MAX_MEM_CACHE_BYTES,
  ttl: CACHE_TTL_MS,
  sizeCalculation: (val) => {
    try {
      if (!val) return 1;
      if (typeof val === "string") return Buffer.byteLength(val, "utf8");
      if (Buffer.isBuffer(val)) return val.length;
      if (val.body && typeof val.body === "string") return val.body.length;
      return Buffer.byteLength(JSON.stringify(val), "utf8");
    } catch {
      return 1024;
    }
  },
});

// SECTION: Disk Cache

function now() { return Date.now(); }
function cacheKey(s) { return Buffer.from(s).toString("base64url"); }

async function diskGet(key, ttlMs) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname, "utf8");
    const obj = JSON.parse(raw);
    const ttl = typeof ttlMs === "number" ? ttlMs : CACHE_TTL_MS;
    if ((now() - obj.t) < ttl) return obj.v;
    try { await fsPromises.unlink(fname); } catch {}
  } catch {}
  return null;
}

async function diskSet(key, val) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(() => {});
  } catch {}
}

// SECTION: Sessions (cookie jar)

const SESSIONS = new Map();
function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }

function createSession(req) {
  const sid = makeSid();
  const payload = {
    cookies: new Map(),       // cookieName -> value
    cookieAttrs: new Map(),   // cookieName -> { domain, path, secure, httpOnly, sameSite, expires }
    last: now(),
    ua: USER_AGENT_DEFAULT,
    ip: req.ip || req.socket?.remoteAddress || null,
  };
  SESSIONS.set(sid, payload);
  return { sid, payload };
}

function parseCookieHeader(header = "") {
  const out = {};
  header.split(";").forEach((p) => {
    const idx = p.indexOf("=");
    if (idx === -1) return;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    if (k) out[k] = v;
  });
  return out;
}

function getSessionFromReq(req) {
  const parsed = parseCookieHeader(req.headers.cookie || "");
  const sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession(req);
  const payload = SESSIONS.get(sid);
  payload.last = now();
  payload.ip = payload.ip || req.ip || null;
  return { sid, payload };
}

function setSessionCookieHeader(res, sid) {
  const cookieStr = `${SESSION_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}

function parseSetCookieLine(line) {
  const parts = line.split(";").map((s) => s.trim());
  const [kv, ...attrs] = parts;
  const idx = kv.indexOf("=");
  if (idx === -1) return null;
  const name = kv.slice(0, idx).trim();
  const value = kv.slice(idx + 1).trim();
  const out = { name, value, domain: null, path: "/", secure: false, httpOnly: false, sameSite: null, expires: null };
  for (const a of attrs) {
    const [ak, av] = a.split("=").map((s) => s.trim());
    const lk = (ak || "").toLowerCase();
    if (lk === "domain") out.domain = (av || "").toLowerCase();
    else if (lk === "path") out.path = av || "/";
    else if (lk === "secure") out.secure = true;
    else if (lk === "httponly") out.httpOnly = true;
    else if (lk === "samesite") out.sameSite = (av || "").toLowerCase();
    else if (lk === "expires") out.expires = av || null;
    else if (lk === "max-age") { /* ignore; we keep in-memory */ }
  }
  return out;
}

function storeSetCookies(setCookies = [], sessionPayload, responseUrl) {
  let host = null;
  try { host = new URL(responseUrl).hostname.toLowerCase(); } catch {}
  for (const sc of setCookies) {
    const parsed = parseSetCookieLine(sc);
    if (!parsed || !parsed.name) continue;
    sessionPayload.cookies.set(parsed.name, parsed.value);
    sessionPayload.cookieAttrs.set(parsed.name, {
      domain: parsed.domain || host,
      path: parsed.path || "/",
      secure: parsed.secure,
      httpOnly: parsed.httpOnly,
      sameSite: parsed.sameSite,
      expires: parsed.expires,
    });
  }
}

function cookieMatches(urlStr, attrs) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    const pathn = u.pathname || "/";
    const dom = (attrs.domain || host).toLowerCase();
    const domainOk = dom.startsWith(".")
      ? (host === dom.slice(1) || host.endsWith(dom))
      : (host === dom || host.endsWith("." + dom));
    const pathOk = pathn.startsWith(attrs.path || "/");
    return domainOk && pathOk;
  } catch {
    return false;
  }
}

function buildCookieHeaderForUrl(sessionPayload, urlStr) {
  const pairs = [];
  for (const [name, value] of sessionPayload.cookies.entries()) {
    const attrs = sessionPayload.cookieAttrs.get(name) || { domain: null, path: "/" };
    if (!cookieMatches(urlStr, attrs)) continue;
    pairs.push(`${name}=${value}`);
  }
  return pairs.join("; ");
}

// session cleanup
setInterval(() => {
  const cutoff = now() - SESSION_TTL_MS;
  for (const [sid, p] of SESSIONS.entries()) {
    if (p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

// SECTION: Public Origin (fix “localhost” bug)

function getPublicOrigin(req) {
  const proto = (req.headers["x-forwarded-proto"] || req.protocol || "http").toString().split(",")[0].trim();
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "").toString().split(",")[0].trim();
  if (!host) return `${proto}://localhost:${PORT}`;
  return `${proto}://${host}`;
}

// SECTION: Helpers (URL + content)

function isAlreadyProxiedHref(href) {
  if (!href) return false;
  return href.includes("/proxy?url=") || href.includes("/proxy/");
}

function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

function proxyizeAbsoluteUrl(publicOrigin, abs) {
  try {
    const u = new URL(abs);
    return `${publicOrigin}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch {
    try {
      const u2 = new URL("https://" + abs);
      return `${publicOrigin}/proxy?url=${encodeURIComponent(u2.href)}`;
    } catch {
      return abs;
    }
  }
}

function looksLikeAsset(urlStr) {
  if (!urlStr) return false;
  try {
    const p = new URL(urlStr).pathname.toLowerCase();
    if (SPECIAL_FILES.some((s) => p.endsWith(s))) return true;
    return ASSET_EXTENSIONS.some((ext) => p.endsWith(ext));
  } catch {
    const lower = urlStr.toLowerCase();
    if (SPECIAL_FILES.some((s) => lower.endsWith(s))) return true;
    return ASSET_EXTENSIONS.some((ext) => lower.endsWith(ext));
  }
}

function stripSecurityHeaders(headers) {
  const out = new Map();
  for (const [k, v] of headers.entries()) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (DROP_HEADERS.has(lk)) continue;
    out.set(k, v);
  }
  return out;
}

function sanitizeHtml(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+nonce=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch {}
  return html;
}

function rewriteCssUrls(cssText, baseUrl, publicOrigin) {
  let out = cssText || "";
  out = out.replace(/@import\s+(url\()?\s*(['"]?)([^'")]+)\2\s*\)?/gi, (m, _u, _q, url) => {
    if (!url || /^data:/i.test(url)) return m;
    if (isAlreadyProxiedHref(url)) return m;
    const abs = toAbsolute(url, baseUrl) || url;
    return m.replace(url, proxyizeAbsoluteUrl(publicOrigin, abs));
  });
  out = out.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, url) => {
    if (!url || /^data:/i.test(url)) return m;
    if (isAlreadyProxiedHref(url)) return m;
    const abs = toAbsolute(url, baseUrl) || url;
    return `url("${proxyizeAbsoluteUrl(publicOrigin, abs)}")`;
  });
  return out;
}

// SECTION: Aggressive DOM rewrite

function jsdomTransform(html, baseUrl, publicOrigin) {
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;

    // Ensure <base>
    if (!document.querySelector("base")) {
      const head = document.querySelector("head");
      if (head) {
        const b = document.createElement("base");
        b.setAttribute("href", baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }

    // Rewrite meta refresh
    for (const m of Array.from(document.querySelectorAll('meta[http-equiv="refresh"], meta[http-equiv="REFRESH"]'))) {
      try {
        const c = m.getAttribute("content") || "";
        const parts = c.split(";");
        if (parts.length < 2) continue;
        const match = parts.slice(1).join(";").match(/url=(.*)/i);
        if (!match) continue;
        const dest = match[1].replace(/['"]/g, "").trim();
        const abs = toAbsolute(dest, baseUrl) || dest;
        m.setAttribute("content", parts[0] + ";url=" + proxyizeAbsoluteUrl(publicOrigin, abs));
      } catch {}
    }

    // Rewrite all href/src/action/poster/data
    const urlAttrs = ["href", "src", "action", "poster", "data"];
    const all = Array.from(document.querySelectorAll("*"));
    for (const el of all) {
      for (const attr of urlAttrs) {
        try {
          if (!el.hasAttribute(attr)) continue;
          const v = el.getAttribute(attr);
          if (!v) continue;
          if (/^(javascript:|mailto:|tel:|#)/i.test(v)) continue;
          if (/^data:/i.test(v)) continue;
          if (isAlreadyProxiedHref(v)) continue;
          const abs = toAbsolute(v, baseUrl) || v;
          el.setAttribute(attr, proxyizeAbsoluteUrl(publicOrigin, abs));
        } catch {}
      }

      // srcset
      try {
        if (el.hasAttribute("srcset")) {
          const ss = el.getAttribute("srcset") || "";
          const parts = ss.split(",").map((p) => {
            const [u, rest] = p.trim().split(/\s+/, 2);
            if (!u) return p;
            if (/^data:/i.test(u)) return p;
            if (isAlreadyProxiedHref(u)) return p;
            const abs = toAbsolute(u, baseUrl) || u;
            return proxyizeAbsoluteUrl(publicOrigin, abs) + (rest ? " " + rest : "");
          });
          el.setAttribute("srcset", parts.join(", "));
        }
      } catch {}

      // inline style url(...)
      try {
        if (el.hasAttribute("style")) {
          const s = el.getAttribute("style") || "";
          el.setAttribute("style", rewriteCssUrls(s, baseUrl, publicOrigin));
        }
      } catch {}

      // iframe srcdoc: make inside doc "proxy-aware" by injecting hook
      try {
        if (el.tagName?.toLowerCase() === "iframe" && el.hasAttribute("srcdoc")) {
          const srcdoc = el.getAttribute("srcdoc") || "";
          const patched = injectClientShim(sanitizeHtml(srcdoc), publicOrigin, baseUrl);
          el.setAttribute("srcdoc", patched);
        }
      } catch {}
    }

    // Rewrite <style> blocks
    for (const st of Array.from(document.querySelectorAll("style"))) {
      try {
        const txt = st.textContent || "";
        st.textContent = rewriteCssUrls(txt, baseUrl, publicOrigin);
      } catch {}
    }

    // Remove noscript (often breaks UX)
    for (const ns of Array.from(document.getElementsByTagName("noscript"))) {
      try { ns.remove(); } catch {}
    }

    return dom.serialize();
  } catch (err) {
    console.warn("jsdom transform failed:", err?.message || err);
    return html;
  }
}

// SECTION: Client shim (browser-like network + nav hooks)

function injectClientShim(html, publicOrigin, pageBase) {
  const marker = "/* EUPHORIA_CLIENT_V3 */";
  if (html.includes(marker)) return html;

  // NOTE: keep it compact, but wide coverage.
  const script = `
<script>${marker}
(() => {
  const PUBLIC_ORIGIN = ${JSON.stringify(publicOrigin)};
  const PAGE_BASE = ${JSON.stringify(pageBase || "")};

  const isAbs = (u) => { try { new URL(u); return true; } catch { return false; } };
  const isBad = (u) => !u || /^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u);
  const isProx = (u) => typeof u === 'string' && (u.includes('/proxy?url=') || u.includes('/proxy/'));
  const abs = (u) => { try { return new URL(u, document.baseURI || PAGE_BASE || location.href).href; } catch { return u; } };
  const prox = (u) => {
    try {
      if (isBad(u)) return u;
      if (typeof u !== 'string') return u;
      if (isProx(u)) return u;
      const a = abs(u);
      return PUBLIC_ORIGIN + '/proxy?url=' + encodeURIComponent(a);
    } catch { return u; }
  };

  // fetch
  const origFetch = window.fetch;
  window.fetch = function(resource, init) {
    try {
      if (typeof resource === 'string') resource = prox(resource);
      else if (resource && resource.url && resource instanceof Request) resource = new Request(prox(resource.url), resource);
    } catch {}
    return origFetch.call(this, resource, init);
  };

  // XHR
  const OrigXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    const xhr = new OrigXHR();
    const open = xhr.open;
    xhr.open = function(method, url, ...rest) {
      try { url = prox(url); } catch {}
      return open.call(this, method, url, ...rest);
    };
    return xhr;
  };

  // sendBeacon
  if (navigator.sendBeacon) {
    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {
      try { url = prox(url); } catch {}
      return origBeacon(url, data);
    };
  }

  // WebSocket
  const OrigWS = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    try {
      // If it's ws(s) and absolute: tunnel via server ws proxy endpoint
      const u = typeof url === 'string' ? url : (url && url.toString ? url.toString() : '');
      if (/^wss?:/i.test(u) && !isProx(u)) {
        const wsurl = PUBLIC_ORIGIN.replace(/^http/i, 'ws') + '/_wsproxy?url=' + encodeURIComponent(u);
        return protocols ? new OrigWS(wsurl, protocols) : new OrigWS(wsurl);
      }
    } catch {}
    return protocols ? new OrigWS(url, protocols) : new OrigWS(url);
  };
  window.WebSocket.prototype = OrigWS.prototype;

  // EventSource
  if (window.EventSource) {
    const OrigES = window.EventSource;
    window.EventSource = function(url, cfg) {
      try { url = prox(url); } catch {}
      return new OrigES(url, cfg);
    };
    window.EventSource.prototype = OrigES.prototype;
  }

  // Worker / SharedWorker
  if (window.Worker) {
    const OrigW = window.Worker;
    window.Worker = function(url, opts) {
      try { url = prox(url); } catch {}
      return new OrigW(url, opts);
    };
    window.Worker.prototype = OrigW.prototype;
  }
  if (window.SharedWorker) {
    const OrigSW = window.SharedWorker;
    window.SharedWorker = function(url, nameOrOpts) {
      try { url = prox(url); } catch {}
      return new OrigSW(url, nameOrOpts);
    };
    window.SharedWorker.prototype = OrigSW.prototype;
  }

  // history + location
  const origPush = history.pushState;
  const origReplace = history.replaceState;
  history.pushState = function(state, title, url) {
    try { if (typeof url === 'string') url = prox(url); } catch {}
    return origPush.call(this, state, title, url);
  };
  history.replaceState = function(state, title, url) {
    try { if (typeof url === 'string') url = prox(url); } catch {}
    return origReplace.call(this, state, title, url);
  };

  const locAssign = location.assign.bind(location);
  const locReplace = location.replace.bind(location);
  location.assign = function(url) { try { url = prox(url); } catch {} return locAssign(url); };
  location.replace = function(url) { try { url = prox(url); } catch {} return locReplace(url); };

  // Intercept clicks so navigations stay inside proxy
  document.addEventListener('click', (e) => {
    try {
      const a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
      if (!a) return;
      const href = a.getAttribute('href');
      if (!href || isBad(href) || isProx(href)) return;
      e.preventDefault();
      const next = prox(href);
      locAssign(next);
    } catch {}
  }, true);

  // forms: ensure action is proxied, even if script changes it later
  const origSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    try {
      const a = this.getAttribute('action') || '';
      if (a && !isBad(a) && !isProx(a)) this.setAttribute('action', prox(a));
    } catch {}
    return origSubmit.call(this);
  };

  // Patch setAttribute for src/href/action on the fly
  const origSetAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    try {
      const n = String(name || '').toLowerCase();
      if ((n === 'src' || n === 'href' || n === 'action' || n === 'poster' || n === 'data') && typeof value === 'string') {
        if (!isBad(value) && !isProx(value)) value = prox(value);
      }
      if (n === 'srcset' && typeof value === 'string') {
        value = value.split(',').map(p => {
          const parts = p.trim().split(/\\s+/, 2);
          const u = parts[0]; const rest = parts[1] || '';
          if (!u || isBad(u) || isProx(u)) return p;
          return prox(u) + (rest ? ' ' + rest : '');
        }).join(', ');
      }
    } catch {}
    return origSetAttr.call(this, name, value);
  };

})();
</script>`;

  if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, script + "</body>");
  return html + script;
}

// SECTION: Upstream fetch (decompress, range, headers)

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128 });

function withTimeout(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { signal: c.signal, cancel: () => clearTimeout(t) };
}

async function upstreamFetch(url, opts = {}) {
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const { signal, cancel } = withTimeout(FETCH_TIMEOUT_MS);

  const headers = new Headers(opts.headers || {});
  if (!headers.has("user-agent")) headers.set("user-agent", USER_AGENT_DEFAULT);
  if (!headers.has("accept")) headers.set("accept", "*/*");
  if (!headers.has("accept-language")) headers.set("accept-language", "en-US,en;q=0.9");
  // NOTE: let Node fetch do encoding; we can still accept br/gzip
  if (!headers.has("accept-encoding")) headers.set("accept-encoding", "gzip, deflate, br");

  const fetchOpts = {
    method: opts.method || "GET",
    headers,
    redirect: opts.redirect || "manual",
    body: opts.body,
    signal,
    // Node 20: "dispatcher" is undici-specific; do NOT use it to avoid missing deps.
  };

  // Agent support via global undici is not the same; Node fetch ignores node:http agent.
  // We'll still keep keep-alive by relying on undici internal pooling.
  // (Do not import undici; Koyeb error shows it wasn't installed.)

  try {
    const res = await fetch(url, fetchOpts);
    cancel();
    return res;
  } catch (e) {
    cancel();
    throw e;
  }
}

async function readBodyMaybeDecompress(res) {
  // Node fetch will typically auto-decompress; but on some platforms it may not.
  // We'll handle common encodings if they still appear.
  const enc = (res.headers.get("content-encoding") || "").toLowerCase();
  const buf = Buffer.from(await res.arrayBuffer());
  if (!enc || enc === "identity") return buf;
  try {
    if (enc.includes("gzip")) return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
    if (enc.includes("br")) return zlib.brotliDecompressSync(buf);
  } catch {}
  return buf;
}

// SECTION: WS proxy (tunnel ws/wss)

function setupWsProxy(server, getOriginFn) {
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });

  server.on("upgrade", (request, socket, head) => {
    try {
      const url = new URL(request.url, getOriginFn({ headers: request.headers, protocol: "http", host: request.headers.host }));
      if (url.pathname !== "/_wsproxy") return;
      const target = url.searchParams.get("url");
      if (!target) {
        socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
        socket.destroy();
        return;
      }

      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        let outbound;
        try {
          // global WebSocket is NOT defined in Node; must import from ws.
          // We'll create outbound using ws's WebSocket constructor:
          // eslint-disable-next-line no-undef
        } catch {}

        const WebSocket = (await import("ws")).default; // dynamic to avoid import cycles in some envs
        outbound = new WebSocket(target, {
          headers: {
            origin: request.headers.origin || getOriginFn({ headers: request.headers, protocol: "http", host: request.headers.host }),
            "user-agent": USER_AGENT_DEFAULT,
          },
        });

        outbound.on("open", () => {
          ws.on("message", (msg) => { try { outbound.send(msg); } catch {} });
          outbound.on("message", (msg) => { try { ws.send(msg); } catch {} });

          const closeBoth = () => {
            try { ws.close(); } catch {}
            try { outbound.close(); } catch {}
          };
          ws.on("close", closeBoth);
          outbound.on("close", closeBoth);
        });

        outbound.on("error", () => { try { ws.close(); } catch {} });
        ws.on("error", () => { try { outbound.close(); } catch {} });
      });
    } catch {
      try { socket.destroy(); } catch {}
    }
  });
}

// SECTION: Proxy routes

function extractTargetUrl(req) {
  // Supports:
  // 1) /proxy?url=https://example.com
  // 2) /proxy/:host/*  (e.g. /proxy/xbox.com/en-US/)
  // 3) /proxy/https://example.com (rare)
  const q = req.query?.url;
  if (typeof q === "string" && q.length) return q;

  const p = req.path || "";
  if (p.startsWith("/proxy/")) {
    const rest = p.slice("/proxy/".length);
    if (!rest) return null;

    // /proxy/https://...
    if (/^https?:\/\//i.test(rest)) return rest;

    // /proxy/:host/...
    const parts = rest.split("/").filter(Boolean);
    if (parts.length >= 1) {
      const host = parts[0];
      const tail = rest.slice(host.length);
      const u = `https://${host}${tail.startsWith("/") ? tail : "/" + tail}`;
      return u;
    }
  }
  return null;
}

function normalizeUrl(raw) {
  if (!raw) return null;
  let u = raw.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u;
}

function isHtmlRequest(req) {
  const accept = String(req.headers.accept || "").toLowerCase();
  if (accept.includes("text/html")) return true;
  if (req.query.force_html === "1") return true;
  if (req.headers["x-euphoria-client"] === "bc-hybrid") return true;
  return false;
}

app.get("/proxy", handleProxy);
app.get("/proxy/*", handleProxy);

async function handleProxy(req, res) {
  const publicOrigin = getPublicOrigin(req);
  let raw = extractTargetUrl(req);
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com or /proxy/<host>/...)");
  raw = normalizeUrl(raw);

  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch {}

  const wantHtml = isHtmlRequest(req);
  const host = (() => { try { return new URL(raw).hostname; } catch { return null; } })();
  const hostCfg = PER_HOST_CACHE_CONTROLS[host] || {};
  const ttlMs = typeof hostCfg.ttlMs === "number" ? hostCfg.ttlMs : CACHE_TTL_MS;

  const cacheKeyBase = raw + (wantHtml ? "::html" : "::asset");
  const memHit = MEM_CACHE.get(cacheKeyBase);
  if (memHit) {
    try {
      if (wantHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.send(memHit);
      }
      if (memHit.headers) for (const [k, v] of Object.entries(memHit.headers)) res.setHeader(k, v);
      return res.send(Buffer.from(memHit.body, "base64"));
    } catch {}
  }
  const diskHit = await diskGet(cacheKeyBase, ttlMs);
  if (diskHit) {
    try {
      if (wantHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.send(diskHit);
      }
      if (diskHit.headers) for (const [k, v] of Object.entries(diskHit.headers)) res.setHeader(k, v);
      return res.send(Buffer.from(diskHit.body, "base64"));
    } catch {}
  }

  // Build upstream headers
  const originHeaders = {};
  originHeaders["User-Agent"] = session.payload.ua || (req.headers["user-agent"] || USER_AGENT_DEFAULT);
  originHeaders["Accept"] = req.headers.accept || "*/*";
  originHeaders["Accept-Language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
  originHeaders["Accept-Encoding"] = "gzip, deflate, br";
  if (req.headers["range"]) originHeaders["Range"] = req.headers["range"];
  if (req.headers["if-none-match"]) originHeaders["If-None-Match"] = req.headers["if-none-match"];
  if (req.headers["if-modified-since"]) originHeaders["If-Modified-Since"] = req.headers["if-modified-since"];

  // Cookie jar for THIS target URL
  const cookieHdr = buildCookieHeaderForUrl(session.payload, raw);
  if (cookieHdr) originHeaders["Cookie"] = cookieHdr;

  // Referer/Origin should be target origin, not proxy origin
  try { originHeaders["Origin"] = new URL(raw).origin; } catch {}
  if (req.headers.referer) {
    // Best effort: if referer was proxied, derive underlying origin url param
    originHeaders["Referer"] = req.headers.referer;
  }

  let upstream;
  try {
    upstream = await upstreamFetch(raw, { headers: originHeaders, redirect: "manual" });
  } catch (err) {
    console.error("fetch error", err?.message || err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err?.message || err));
  }

  // Collect set-cookie (Node fetch doesn’t provide raw() consistently; use getSetCookie if present)
  try {
    const any = upstream.headers;
    const setCookies = typeof any.getSetCookie === "function" ? any.getSetCookie() : [];
    if (Array.isArray(setCookies) && setCookies.length) storeSetCookies(setCookies, session.payload, upstream.url || raw);
  } catch {}

  const status = upstream.status || 200;

  // Redirect handling: ALWAYS proxy the location
  if ([301, 302, 303, 307, 308].includes(status)) {
    const loc = upstream.headers.get("location");
    if (loc) {
      let absLoc = loc;
      try { absLoc = new URL(loc, upstream.url || raw).href; } catch {}
      const proxied = proxyizeAbsoluteUrl(publicOrigin, absLoc);
      res.setHeader("Location", proxied);
      try { setSessionCookieHeader(res, session.sid); } catch {}
      return res.status(status).send(`Redirecting to ${proxied}`);
    }
  }

  // Copy headers minus security blockers
  const safeHeaders = stripSecurityHeaders(upstream.headers);
  for (const [k, v] of safeHeaders.entries()) {
    try {
      // We will set our own content-length after transforms
      if (k.toLowerCase() === "content-length") continue;
      res.setHeader(k, v);
    } catch {}
  }
  try { setSessionCookieHeader(res, session.sid); } catch {}

  const contentType = (upstream.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const isCss = contentType.includes("text/css");
  const treatAsHtml = wantHtml || isHtml;

  // Assets: stream with range support
  if (!treatAsHtml && !isCss) {
    try {
      const ab = await upstream.arrayBuffer();
      const buf = Buffer.from(ab);
      if (hostCfg.disable !== true && buf.length <= MAX_ASSET_CACHE_BYTES) {
        const data = { headers: Object.fromEntries(safeHeaders.entries()), body: buf.toString("base64") };
        MEM_CACHE.set(cacheKeyBase, data, { ttl: ttlMs });
        diskSet(cacheKeyBase, data).catch(() => {});
      }
      return res.status(status).send(buf);
    } catch (e) {
      // fallback to piping when available
      try {
        res.statusCode = status;
        if (upstream.body && upstream.body.pipe) return upstream.body.pipe(res);
      } catch {}
      return res.status(502).send("Euphoria: asset stream failed");
    }
  }

  // CSS rewrite
  if (isCss && !treatAsHtml) {
    try {
      const buf = await readBodyMaybeDecompress(upstream);
      const css = buf.toString("utf8");
      const rewritten = rewriteCssUrls(css, upstream.url || raw, publicOrigin);
      if (hostCfg.disable !== true && Buffer.byteLength(rewritten, "utf8") <= MAX_HTML_CACHE_BYTES) {
        MEM_CACHE.set(cacheKeyBase, rewritten, { ttl: ttlMs });
        diskSet(cacheKeyBase, rewritten).catch(() => {});
      }
      res.setHeader("Content-Type", "text/css; charset=utf-8");
      return res.status(status).send(rewritten);
    } catch (e) {
      return res.status(502).send("Euphoria: failed to rewrite CSS");
    }
  }

  // HTML rewrite + inject client shim
  let htmlText = "";
  try {
    const buf = await readBodyMaybeDecompress(upstream);
    htmlText = buf.toString("utf8");
  } catch (e) {
    console.error("read html error", e?.message || e);
    return res.status(502).send("Euphoria: failed to read HTML");
  }

  htmlText = sanitizeHtml(htmlText);

  // Aggressive JSDOM rewrite
  let transformed = jsdomTransform(htmlText, upstream.url || raw, publicOrigin);

  // Inject client shim that keeps navigations inside proxy and proxies runtime-created resources
  transformed = injectClientShim(transformed, publicOrigin, upstream.url || raw);

  // Cache HTML
  try {
    if (hostCfg.disable !== true && Buffer.byteLength(transformed, "utf8") <= MAX_HTML_CACHE_BYTES) {
      MEM_CACHE.set(cacheKeyBase, transformed, { ttl: ttlMs });
      diskSet(cacheKeyBase, transformed).catch(() => {});
    }
  } catch {}

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(status).send(transformed);
}

// SECTION: Fallback direct-path (supports in-site relative requests)

app.use(async (req, res, next) => {
  const p = req.path || "/";
  if (
    p.startsWith("/proxy") ||
    p.startsWith("/_wsproxy") ||
    p.startsWith("/_euph_debug") ||
    p.startsWith("/static") ||
    p.startsWith("/public")
  ) return next();

  const ref = String(req.headers.referer || req.headers.referrer || "");
  const m = ref.match(/[?&]url=([^&]+)/);
  if (!m) return next();

  let base;
  try { base = decodeURIComponent(m[1]); } catch { return next(); }
  if (!base) return next();

  let baseOrigin;
  try { baseOrigin = new URL(base).origin; } catch { return next(); }

  const attempted = new URL(req.originalUrl, baseOrigin).href;

  // internally redirect to /proxy
  const publicOrigin = getPublicOrigin(req);
  const proxied = proxyizeAbsoluteUrl(publicOrigin, attempted);
  return res.redirect(302, proxied);
});

// SECTION: SPA

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// SECTION: Admin

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN && req.headers.authorization === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  res.status(403).json({ error: "forbidden" });
}

app.get("/_euph_debug/ping", (req, res) => res.json({ msg: "pong", ts: Date.now() }));

app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, payload] of SESSIONS.entries()) {
    out[sid] = {
      last: new Date(payload.last).toISOString(),
      ua: payload.ua,
      ip: payload.ip,
      cookies: Object.fromEntries(payload.cookies.entries()),
    };
  }
  res.json({ sessions: out, count: SESSIONS.size });
});

app.get("/_euph_debug/cache", requireAdmin, (req, res) => {
  const mem = {};
  MEM_CACHE.forEach((v, k) => {
    mem[k] = { approxSize: MEM_CACHE.sizeCalculation(v) };
  });
  res.json({ memoryCount: MEM_CACHE.size, memory: mem });
});

app.post("/_euph_debug/clear_cache", requireAdmin, async (req, res) => {
  MEM_CACHE.clear();
  if (ENABLE_DISK_CACHE) {
    try {
      const files = await fsPromises.readdir(CACHE_DIR);
      for (const f of files) await fsPromises.unlink(path.join(CACHE_DIR, f)).catch(() => {});
    } catch {}
  }
  res.json({ ok: true });
});

// SECTION: Server + WS

const server = http.createServer(app);
setupWsProxy(server, (fakeReq) => {
  const proto = (fakeReq.headers?.["x-forwarded-proto"] || "http").toString().split(",")[0].trim();
  const host = (fakeReq.headers?.["x-forwarded-host"] || fakeReq.host || fakeReq.headers?.host || "").toString().split(",")[0].trim();
  return `${proto}://${host || `localhost:${PORT}`}`;
});

server.listen(PORT, () => console.log(`Euphoria v3 running on port ${PORT}`));

// SECTION: Errors + shutdown

process.on("unhandledRejection", (err) => console.error("unhandledRejection", err?.stack || err));
process.on("uncaughtException", (err) => console.error("uncaughtException", err?.stack || err));
process.on("warning", (w) => console.warn("warning", w?.stack || w));

async function shutdown() {
  try { server.close(); } catch {}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);