// server.js
// Euphoria v3 — Hybrid Proxy + Scramjet (Node 20+, ESM)
// Section headers only, feature-heavy, Koyeb-safe origins, better images/redirects, search, sessions.

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import http from "http";
import https from "https";
import { fileURLToPath } from "url";
import rateLimit from "express-rate-limit";
import { JSDOM } from "jsdom";
import { WebSocketServer } from "ws";
import cookie from "cookie";
import { LRUCache } from "lru-cache";

// ---- Scramjet import FIX (CommonJS default import) ----
import scramjetPkg from "@mercuryworkshop/scramjet";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------- config --------------------
const PORT = parseInt(process.env.PORT || "3000", 10);
const PUBLIC_DIR = path.join(__dirname, "public");
const CACHE_DIR = path.join(__dirname, "cache");

const ENABLE_DISK_CACHE = (process.env.ENABLE_DISK_CACHE || "1") === "1";
const DISK_TTL_MS = parseInt(process.env.DISK_TTL_MS || String(1000 * 60 * 10), 10);

const MEM_MAX_BYTES = parseInt(process.env.MEM_MAX_BYTES || String(64 * 1024 * 1024), 10);
const MEM_TTL_MS = parseInt(process.env.MEM_TTL_MS || String(1000 * 60 * 5), 10);

const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "30000", 10);
const MAX_HTML_BYTES = parseInt(process.env.MAX_HTML_BYTES || String(2 * 1024 * 1024), 10);

const PROXY_PATH = "/proxy";
const SJ_PATH = "/sj";
const WS_TUNNEL_PATH = "/_wsproxy";

const USER_AGENT =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const DROP_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy",
  "strict-transport-security"
]);

const PASS_REQ_HEADERS = [
  "accept",
  "accept-language",
  "accept-encoding",
  "cache-control",
  "pragma",
  "range",
  "dnt",
  "upgrade-insecure-requests",
  "sec-fetch-dest",
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-user",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "origin",
  "referer"
];

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 256 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 256 });

// -------------------- app --------------------
const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR, { index: false }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_GLOBAL || "900", 10),
    standardHeaders: true,
    legacyHeaders: false
  })
);

// -------------------- cache --------------------
const MEM_CACHE = new LRUCache({
  maxSize: MEM_MAX_BYTES,
  ttl: MEM_TTL_MS,
  sizeCalculation: (val) => {
    if (val == null) return 1;
    if (Buffer.isBuffer(val)) return val.length;
    if (typeof val === "string") return Buffer.byteLength(val, "utf8");
    try { return Buffer.byteLength(JSON.stringify(val), "utf8"); } catch { return 512; }
  }
});

if (ENABLE_DISK_CACHE) {
  await fsp.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

function b64url(s) {
  return Buffer.from(s).toString("base64url");
}

async function diskGet(key) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const fp = path.join(CACHE_DIR, b64url(key));
    if (!fs.existsSync(fp)) return null;
    const raw = await fsp.readFile(fp, "utf8");
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== "object") return null;
    if (Date.now() - obj.t > DISK_TTL_MS) {
      try { await fsp.unlink(fp); } catch {}
      return null;
    }
    return obj.v ?? null;
  } catch {
    return null;
  }
}

async function diskSet(key, val) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const fp = path.join(CACHE_DIR, b64url(key));
    await fsp.writeFile(fp, JSON.stringify({ t: Date.now(), v: val }), "utf8").catch(() => {});
  } catch {}
}

// -------------------- origin helpers --------------------
function getRequestOrigin(req) {
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0].trim();
  const proto = xfProto || (req.secure ? "https" : "http");
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "").toString().split(",")[0].trim();
  if (!host) return `${proto}://localhost:${PORT}`;
  return `${proto}://${host}`;
}

// -------------------- session + cookie jar --------------------
const SESSION_COOKIE = "euphoria_sid";
const SESSIONS = new Map(); // sid -> { last, cookies: Map(host->Map(name->val)) }

function now() { return Date.now(); }
function rand() { return Math.random().toString(36).slice(2); }
function makeSid() { return rand() + rand() + Date.now().toString(36); }

function parseCookieHeader(h = "") {
  try { return cookie.parse(h || ""); } catch { return {}; }
}

function getSid(req) {
  const parsed = parseCookieHeader(req.headers.cookie || "");
  return parsed[SESSION_COOKIE] || (req.headers["x-euphoria-session"] ? String(req.headers["x-euphoria-session"]) : null);
}

function ensureSession(req, res) {
  let sid = getSid(req);
  if (!sid || !SESSIONS.has(sid)) {
    sid = makeSid();
    SESSIONS.set(sid, { last: now(), cookies: new Map() });
  }
  const sess = SESSIONS.get(sid);
  sess.last = now();

  // set cookie for client (only our domain)
  const set = cookie.serialize(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24
  });
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", set);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, set]);
  else res.setHeader("Set-Cookie", [prev, set]);

  return { sid, sess };
}

function jarGetHost(sess, host) {
  if (!sess.cookies.has(host)) sess.cookies.set(host, new Map());
  return sess.cookies.get(host);
}

function jarToHeader(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

function storeSetCookies(sess, urlStr, setCookies) {
  if (!setCookies || !setCookies.length) return;
  let host = "";
  try { host = new URL(urlStr).hostname; } catch {}
  if (!host) return;
  const hostJar = jarGetHost(sess, host);
  for (const sc of setCookies) {
    try {
      const kv = sc.split(";")[0];
      const i = kv.indexOf("=");
      if (i === -1) continue;
      const k = kv.slice(0, i).trim();
      const v = kv.slice(i + 1).trim();
      if (k) hostJar.set(k, v);
    } catch {}
  }
}

// -------------------- url helpers --------------------
function isProbablyUrl(s) {
  if (!s) return false;
  return /^(https?:\/\/)/i.test(s) || /^[a-z0-9.-]+\.[a-z]{2,}([/:?]|$)/i.test(s) || /^localhost(:\d+)?([/:]|$)/i.test(s);
}

function normalizeUserInputUrl(input) {
  if (!input) return null;
  const t = String(input).trim();
  if (!t) return null;
  if (isProbablyUrl(t)) return /^https?:\/\//i.test(t) ? t : `https://${t}`;
  return null;
}

function googleSearchUrl(q) {
  return `https://www.google.com/search?q=${encodeURIComponent(q || "")}`;
}

function proxied(origin, absUrl) {
  return `${origin}${PROXY_PATH}?url=${encodeURIComponent(absUrl)}`;
}

function scramjetLink(origin, absUrl) {
  return `${origin}${SJ_PATH}/${encodeURIComponent(absUrl)}`;
}

function absoluteUrl(maybe, base) {
  try { return new URL(maybe, base).href; } catch { return null; }
}

// -------------------- upstream fetch --------------------
function pickAgent(urlStr) {
  try {
    const u = new URL(urlStr);
    return u.protocol === "https:" ? httpsAgent : httpAgent;
  } catch {
    return httpsAgent;
  }
}

function sanitizeResponseHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) {
    const lk = k.toLowerCase();
    if (DROP_HEADERS.has(lk)) continue;
    out[k] = v;
  }
  return out;
}

function buildUpstreamHeaders(req, targetUrl, sess) {
  const h = {};
  // pass selected headers from client
  for (const name of PASS_REQ_HEADERS) {
    const v = req.headers[name];
    if (v != null) h[name] = v;
  }
  h["user-agent"] = req.headers["user-agent"] || USER_AGENT;

  // origin/referrer coherence
  try { h["origin"] = new URL(targetUrl).origin; } catch {}
  if (!h["referer"]) {
    // keep empty unless browser sent it; setting wrong referer can break auth
  }

  // server-side cookie jar
  try {
    const host = new URL(targetUrl).hostname;
    const hostJar = jarGetHost(sess, host);
    const cookieHeader = jarToHeader(hostJar);
    if (cookieHeader) h["cookie"] = cookieHeader;
  } catch {}

  return h;
}

async function fetchWithTimeout(url, opts = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      // Node fetch ignores "agent" but supports "dispatcher" (undici) in newer versions.
      // However Node 20 in many hosts still accepts agent on RequestInit in practice in some environments.
      // We'll still set it for environments that honor it.
      agent: pickAgent(url)
    });
    return res;
  } finally {
    clearTimeout(t);
  }
}

function getSetCookieCompat(res) {
  // Node 20+ fetch Headers: getSetCookie() exists.
  try {
    if (typeof res.headers.getSetCookie === "function") return res.headers.getSetCookie();
  } catch {}
  // fallback: attempt raw (not always present)
  try {
    const any = res.headers;
    if (any && typeof any.raw === "function") {
      const raw = any.raw();
      return raw["set-cookie"] || [];
    }
  } catch {}
  return [];
}

function isHtml(ct = "") {
  ct = String(ct).toLowerCase();
  return ct.includes("text/html") || ct.includes("application/xhtml+xml");
}

function isAsset(ct = "") {
  ct = String(ct).toLowerCase();
  if (!ct) return false;
  if (isHtml(ct)) return false;
  return (
    ct.startsWith("image/") ||
    ct.startsWith("video/") ||
    ct.startsWith("audio/") ||
    ct.includes("font/") ||
    ct.includes("application/octet-stream") ||
    ct.includes("application/javascript") ||
    ct.includes("text/css") ||
    ct.includes("application/wasm") ||
    ct.includes("application/json")
  );
}

// -------------------- html rewriting --------------------
function jsdomRewrite(html, baseUrl, origin) {
  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }
  const { document } = dom.window;

  if (!document.querySelector("base")) {
    const b = document.createElement("base");
    b.setAttribute("href", baseUrl);
    document.head?.prepend(b);
  }

  // anchors
  document.querySelectorAll("a[href]").forEach((a) => {
    const href = a.getAttribute("href");
    if (!href) return;
    if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
    const abs = absoluteUrl(href, baseUrl);
    if (!abs) return;
    a.setAttribute("href", proxied(origin, abs));
    // do NOT remove target for all sites; some SPAs rely on it; keep it
  });

  // forms
  document.querySelectorAll("form[action]").forEach((f) => {
    const act = f.getAttribute("action");
    if (!act) return;
    const abs = absoluteUrl(act, baseUrl);
    if (!abs) return;
    f.setAttribute("action", proxied(origin, abs));
  });

  // src/href assets
  document.querySelectorAll("img,script,link,source,video,audio").forEach((el) => {
    const attr = el.getAttribute("src") ? "src" : (el.getAttribute("href") ? "href" : null);
    if (!attr) return;
    const v = el.getAttribute(attr);
    if (!v || /^data:/i.test(v)) return;
    const abs = absoluteUrl(v, baseUrl);
    if (!abs) return;
    el.setAttribute(attr, proxied(origin, abs));
  });

  // srcset
  document.querySelectorAll("[srcset]").forEach((el) => {
    const ss = el.getAttribute("srcset");
    if (!ss) return;
    const out = ss.split(",").map((part) => {
      const p = part.trim();
      if (!p) return part;
      const [u, d] = p.split(/\s+/, 2);
      if (!u || /^data:/i.test(u)) return part;
      const abs = absoluteUrl(u, baseUrl);
      if (!abs) return part;
      return proxied(origin, abs) + (d ? " " + d : "");
    }).join(", ");
    el.setAttribute("srcset", out);
  });

  // style url()
  document.querySelectorAll("style").forEach((st) => {
    const txt = st.textContent || "";
    if (!txt) return;
    st.textContent = txt.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
      if (!u || /^data:/i.test(u)) return m;
      const abs = absoluteUrl(u, baseUrl);
      if (!abs) return m;
      return `url("${proxied(origin, abs)}")`;
    });
  });

  document.querySelectorAll("[style]").forEach((el) => {
    const s = el.getAttribute("style") || "";
    if (!s) return;
    const out = s.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
      if (!u || /^data:/i.test(u)) return m;
      const abs = absoluteUrl(u, baseUrl);
      if (!abs) return m;
      return `url("${proxied(origin, abs)}")`;
    });
    el.setAttribute("style", out);
  });

  // meta refresh
  document.querySelectorAll('meta[http-equiv]').forEach((m) => {
    const he = (m.getAttribute("http-equiv") || "").toLowerCase();
    if (he !== "refresh") return;
    const c = m.getAttribute("content") || "";
    const parts = c.split(";");
    const match = c.match(/url=(.*)$/i);
    if (!match) return;
    const dest = match[1].replace(/['"]/g, "").trim();
    const abs = absoluteUrl(dest, baseUrl);
    if (!abs) return;
    m.setAttribute("content", parts[0] + ";url=" + proxied(origin, abs));
  });

  // injection for SPA buttons/navigation/network
  const inject = `
<script>
(() => {
  const ORIGIN = ${JSON.stringify(origin)};
  const PROXY = ${JSON.stringify(PROXY_PATH)};
  const prox = (u) => {
    try{
      if(!u) return u;
      if(typeof u !== 'string') u = String(u);
      if(u.includes(PROXY + '?url=')) return u;
      if(/^data:|^blob:|^about:|^javascript:/i.test(u)) return u;
      const abs = new URL(u, document.baseURI).href;
      return ORIGIN + PROXY + '?url=' + encodeURIComponent(abs);
    }catch{ return u; }
  };

  // fetch
  const _fetch = window.fetch;
  window.fetch = function(resource, init){
    try{
      if(typeof resource === 'string') resource = prox(resource);
      else if(resource instanceof Request) resource = new Request(prox(resource.url), resource);
    }catch{}
    return _fetch(resource, init);
  };

  // XHR
  const XHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function(){
    const x = new XHR();
    const open = x.open;
    x.open = function(method, url, ...rest){
      try{ url = prox(url); }catch{}
      return open.call(this, method, url, ...rest);
    };
    return x;
  };

  // forms
  document.addEventListener('submit', (e) => {
    const f = e.target;
    if(!(f instanceof HTMLFormElement)) return;
    const a = f.getAttribute('action') || '';
    if(!a) return;
    try{ f.setAttribute('action', prox(a)); }catch{}
  }, true);

  // link clicks
  document.addEventListener('click', (e) => {
    const a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if(!a) return;
    const href = a.getAttribute('href');
    if(!href || href.startsWith('#') || href.startsWith('javascript:')) return;
    // allow ctrl/cmd-click open new tab default behavior
    if(e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    try{ location.href = prox(href); }catch{ location.href = href; }
  }, true);

  // history
  const _push = history.pushState;
  const _replace = history.replaceState;
  history.pushState = function(s,t,u){ return _push.call(this,s,t, u ? prox(u) : u); };
  history.replaceState = function(s,t,u){ return _replace.call(this,s,t, u ? prox(u) : u); };

  // location helpers
  const _assign = location.assign.bind(location);
  const _replaceLoc = location.replace.bind(location);
  location.assign = (u) => _assign(prox(u));
  location.replace = (u) => _replaceLoc(prox(u));
})();
</script>
`;
  document.body?.insertAdjacentHTML("beforeend", inject);

  return dom.serialize();
}

// -------------------- scramjet setup (best-effort) --------------------
let scramjetEnabled = true;
let scramjetHandler = null;

(function initScramjet() {
  try {
    // Scramjet is CommonJS here; scramjetPkg is the default export object.
    const candidate =
      scramjetPkg?.createScramjetServer ||
      scramjetPkg?.default?.createScramjetServer ||
      scramjetPkg?.createServer ||
      scramjetPkg?.default?.createServer ||
      null;

    if (!candidate || typeof candidate !== "function") {
      scramjetEnabled = false;
      console.warn("[scramjet] create server fn not found; scramjet disabled");
      return;
    }

    // Some versions return (req,res,next) handler; others return object with .handler or .middleware
    const serverOrHandler = candidate({ prefix: SJ_PATH });

    if (typeof serverOrHandler === "function") {
      scramjetHandler = serverOrHandler;
      return;
    }
    if (serverOrHandler && typeof serverOrHandler.handler === "function") {
      scramjetHandler = serverOrHandler.handler;
      return;
    }
    if (serverOrHandler && typeof serverOrHandler.middleware === "function") {
      scramjetHandler = serverOrHandler.middleware;
      return;
    }

    scramjetEnabled = false;
    console.warn("[scramjet] unsupported return shape; scramjet disabled");
  } catch (e) {
    scramjetEnabled = false;
    console.warn("[scramjet] init failed; disabled:", e?.message || e);
  }
})();

// mount scramjet if available
if (scramjetEnabled && scramjetHandler) {
  app.use(SJ_PATH, (req, res, next) => scramjetHandler(req, res, next));
}

// -------------------- proxy endpoint --------------------
// Supports:
//  - /proxy?url=https://example.com
//  - /proxy?q=search terms
//  - /proxy?url=google.com (auto https://)
//  - /proxy?url=some search (if not url, treat as search)
app.get(PROXY_PATH, async (req, res) => {
  const origin = getRequestOrigin(req);
  const { sess } = ensureSession(req, res);

  const urlParam = req.query.url ? String(req.query.url) : "";
  const qParam = req.query.q ? String(req.query.q) : "";

  let target = normalizeUserInputUrl(urlParam);

  if (!target && qParam) {
    target = googleSearchUrl(qParam);
  } else if (!target && urlParam) {
    // interpret as search query if not URL
    if (!isProbablyUrl(urlParam.trim())) {
      target = googleSearchUrl(urlParam.trim());
    }
  }

  if (!target) {
    return res.status(400).send("Missing url (use /proxy?url=https://example.com or /proxy?q=search)");
  }

  // optional: if scramjet is enabled and user wants it for this host, you can flip by env
  // But classic proxy stays default; UI can force /sj/ links.
  const cacheKey = `html:${target}`;
  const cached = MEM_CACHE.get(cacheKey);
  if (cached) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(cached);
  }

  let upstream;
  try {
    upstream = await fetchWithTimeout(target, {
      headers: buildUpstreamHeaders(req, target, sess),
      redirect: "manual"
    });
  } catch (e) {
    return res.status(502).send("Error: Failed to fetch");
  }

  const setCookies = getSetCookieCompat(upstream);
  if (setCookies.length) storeSetCookies(sess, target, setCookies);

  // redirects
  if ([301, 302, 303, 307, 308].includes(upstream.status)) {
    const loc = upstream.headers.get("location");
    if (loc) {
      const abs = absoluteUrl(loc, target) || loc;
      const out = proxied(origin, abs);
      res.status(upstream.status);
      res.setHeader("Location", out);
      return res.send(`Redirecting to ${out}`);
    }
  }

  const ct = upstream.headers.get("content-type") || "";

  // assets (images/video/css/js/json/etc)
  if (isAsset(ct)) {
    // pass through safe headers
    const headers = {};
    upstream.headers.forEach((v, k) => (headers[k] = v));
    const cleaned = sanitizeResponseHeaders(headers);
    for (const [k, v] of Object.entries(cleaned)) {
      try { res.setHeader(k, v); } catch {}
    }

    res.status(upstream.status);

    // stream for large/complex assets (better for images + range)
    try {
      if (upstream.body) {
        // ensure content-type exists
        if (!res.getHeader("Content-Type") && ct) res.setHeader("Content-Type", ct);
        return upstream.body.pipeTo(
          new WritableStream({
            write(chunk) { res.write(Buffer.from(chunk)); },
            close() { res.end(); },
            abort() { try { res.end(); } catch {} }
          })
        );
      }
    } catch {
      // fallback buffer
    }

    const buf = Buffer.from(await upstream.arrayBuffer());
    return res.send(buf);
  }

  // non-html
  if (!isHtml(ct)) {
    res.status(upstream.status);
    return res.send(Buffer.from(await upstream.arrayBuffer()));
  }

  // html
  let html;
  try {
    html = await upstream.text();
  } catch {
    return res.status(502).send("Failed to read HTML");
  }

  if (Buffer.byteLength(html, "utf8") > MAX_HTML_BYTES) {
    return res.status(413).send("HTML too large");
  }

  // rewrite html
  const rewritten = jsdomRewrite(html, upstream.url || target, origin);

  MEM_CACHE.set(cacheKey, rewritten);
  diskSet(cacheKey, rewritten).catch(() => {});

  res.status(upstream.status);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.send(rewritten);
});

// -------------------- disk cache warm path (optional) --------------------
app.get("/_euph_cache_get", async (req, res) => {
  const key = req.query.k ? String(req.query.k) : "";
  if (!key) return res.status(400).json({ error: "missing k" });
  const v = await diskGet(key);
  res.json({ ok: true, hit: !!v, v });
});

// -------------------- websocket tunnel (best-effort) --------------------
function setupWsProxy(server) {
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });

  server.on("upgrade", (request, socket, head) => {
    try {
      const u = new URL(request.url, `http://${request.headers.host}`);
      if (u.pathname !== WS_TUNNEL_PATH) return;
      const target = u.searchParams.get("url");
      if (!target) {
        socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
        socket.destroy();
        return;
      }
      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        // minimal tunnel: connect out and forward frames
        const { WebSocket } = globalThis;
        const out = new WebSocket(target);

        out.addEventListener("open", () => {
          ws.on("message", (msg) => { try { out.send(msg); } catch {} });
          out.addEventListener("message", (evt) => { try { ws.send(evt.data); } catch {} });
        });

        const closeBoth = () => {
          try { ws.close(); } catch {}
          try { out.close(); } catch {}
        };
        ws.on("close", closeBoth);
        ws.on("error", closeBoth);
        out.addEventListener("close", closeBoth);
        out.addEventListener("error", closeBoth);
      });
    } catch {
      try { socket.destroy(); } catch {}
    }
  });
}

// -------------------- routes --------------------
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("*", (req, res, next) => {
  // keep static 404s correct; don’t SPA-catch non-html
  if (req.method === "GET" && (req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  next();
});

// -------------------- admin/debug --------------------
const ADMIN_TOKEN = process.env.EUPH_ADMIN_TOKEN || "";

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  if (ADMIN_TOKEN && auth === `Bearer ${ADMIN_TOKEN}`) return next();
  if (!ADMIN_TOKEN && (req.ip === "127.0.0.1" || req.ip === "::1")) return next();
  return res.status(403).json({ error: "forbidden" });
}

app.get("/_euph_debug/ping", (req, res) => res.json({ ok: true, ts: Date.now() }));
app.get("/_euph_debug/sessions", requireAdmin, (req, res) => {
  const out = {};
  for (const [sid, s] of SESSIONS.entries()) {
    out[sid] = { last: s.last, hosts: [...s.cookies.keys()] };
  }
  res.json({ count: SESSIONS.size, sessions: out });
});
app.get("/_euph_debug/cache", requireAdmin, (req, res) => {
  res.json({ memSize: MEM_CACHE.size, memMax: MEM_MAX_BYTES });
});
app.post("/_euph_debug/clear_cache", requireAdmin, async (req, res) => {
  MEM_CACHE.clear();
  if (ENABLE_DISK_CACHE) {
    try {
      const files = await fsp.readdir(CACHE_DIR);
      for (const f of files) await fsp.unlink(path.join(CACHE_DIR, f)).catch(() => {});
    } catch {}
  }
  res.json({ ok: true });
});
app.get("/_euph_debug/scramjet", requireAdmin, (req, res) => {
  res.json({ enabled: !!(scramjetEnabled && scramjetHandler) });
});

// -------------------- cleanup --------------------
setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [sid, s] of SESSIONS.entries()) {
    if ((s.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 30 * 60 * 1000);

// -------------------- start --------------------
const server = http.createServer(app);
setupWsProxy(server);

server.listen(PORT, () => {
  console.log(`Euphoria v3 running on port ${PORT}`);
  console.log(`Proxy: ${PROXY_PATH} | Scramjet: ${SJ_PATH} (enabled=${!!(scramjetEnabled && scramjetHandler)})`);
});

// -------------------- process guards --------------------
process.on("unhandledRejection", (e) => console.error("unhandledRejection", e));
process.on("uncaughtException", (e) => console.error("uncaughtException", e));
process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));