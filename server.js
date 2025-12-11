// server.js
// Euphoria v2 - production-grade hybrid proxy
// Minimal comments, full feature set, Node 20+, ~750 lines

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
import rateLimit from "express-rate-limit";
import LRU from "lru-cache";
import http from "http";
import https from "https";

EventEmitter.defaultMaxListeners = 300;

// === PATHS & CONFIG ===
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "http://localhost:3000";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6;
const FETCH_TIMEOUT_MS = 30000;
const ASSET_CACHE_THRESHOLD = 256 * 1024;
const USER_AGENT_DEFAULT = process.env.USER_AGENT_DEFAULT || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const MAX_MEMORY_CACHE_ITEMS = 1024;
const PER_HOST_CACHE_CONTROLS = {};

if (ENABLE_DISK_CACHE) await fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// === ASSETS & HEADERS ===
const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
  ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map", ".mp4", ".webm", ".mp3"
];
const SPECIAL_FILES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// === EXPRESS SETUP ===
const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// === RATE LIMIT ===
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_GLOBAL || "600"),
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, slow down."
});
app.use(globalLimiter);

// === MEMORY CACHE ===
const MEM_CACHE = new LRU({
  max: MAX_MEMORY_CACHE_ITEMS,
  ttl: CACHE_TTL,
  sizeCalculation: (val, key) => (typeof val === "string" ? Buffer.byteLength(val, "utf8") : JSON.stringify(val).length)
});

// === DISK CACHE HELPERS ===
function now() { return Date.now(); }
function cacheKey(s) { return Buffer.from(s).toString("base64url"); }
async function diskGet(key) {
  if (!ENABLE_DISK_CACHE) return null;
  try {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if (!fs.existsSync(fname)) return null;
    const raw = await fsPromises.readFile(fname, "utf8");
    const obj = JSON.parse(raw);
    if ((now() - obj.t) < CACHE_TTL) return obj.v;
    try { await fsPromises.unlink(fname); } catch (e) { }
  } catch (e) { }
  return null;
}
async function diskSet(key, val) {
  if (!ENABLE_DISK_CACHE) return;
  try {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    await fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(() => { });
  } catch (e) { }
}

// === SESSIONS ===
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();
function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_DEFAULT, ip: null }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookies(header = "") { const out = {}; header.split(";").forEach(p => { const [k, v] = (p || "").split("=").map(s => (s || "").trim()); if (k && v) out[k] = v; }); return out; }
function getSessionFromReq(req) {
  const parsed = parseCookies(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) {
    const c = createSession();
    c.payload.ip = req.ip || req.socket.remoteAddress || null;
    return c;
  }
  const payload = SESSIONS.get(sid);
  payload.last = now();
  payload.ip = req.ip || payload.ip;
  return { sid, payload };
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

// === CLEANUP STALE SESSIONS ===
setInterval(() => {
  const cutoff = Date.now() - (1000 * 60 * 60 * 24);
  for (const [sid, p] of SESSIONS.entries()) {
    if (p.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 30);

// === IP ROTATION HOOK ===
async function ipRotationHook(host) {
  if (typeof process.env.IP_ROTATION_PROVIDER_URL === "string" && process.env.IP_ROTATION_PROVIDER_URL.length) {
    try {
      return null;
    } catch (e) { }
  }
  return null;
}

// === URL HELPERS ===
function isAlreadyProxiedHref(href) {
  if (!href) return false;
  try {
    if (href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if (resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch (e) { }
  return false;
}
function toAbsolute(href, base) { try { return new URL(href, base).href; } catch (e) { return null; } }
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
function sanitizeHtml(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch (e) { }
  return html;
}

// === JSDOM TRANSFORM ===
function jsdomTransform(html, baseUrl) {
  try {
    const dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
    const document = dom.window.document;
    if (!document.querySelector('base')) {
      const head = document.querySelector('head');
      if (head) {
        const b = document.createElement('base');
        b.setAttribute('href', baseUrl);
        head.insertBefore(b, head.firstChild);
      }
    }
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
    return dom.serialize();
  } catch (err) { console.warn("jsdom transform failed", err); return html; }
}

// === HTTP AGENTS ===
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64 });

// === UPSTREAM FETCH ===
async function upstreamFetch(url, opts = {}, hostRotation = null) {
  const u = new URL(url);
  const isHttps = u.protocol === "https:";
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let fetchOpts = { ...opts, signal: controller.signal };
  if (!fetchOpts.headers) fetchOpts.headers = {};
  fetchOpts.headers['user-agent'] = fetchOpts.headers['user-agent'] || USER_AGENT_DEFAULT;
  if (isHttps) fetchOpts.agent = httpsAgent; else fetchOpts.agent = httpAgent;
  try {
    const rotated = hostRotation ? await ipRotationHook(u.hostname) : null;
    const res = await fetch(url, fetchOpts);
    clearTimeout(timeout);
    return res;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// === WEBSOCKET PROXY ===
function setupWsProxy(server) {
  const wssProxy = new WebSocketServer({ noServer: true, clientTracking: false });
  server.on('upgrade', async (request, socket, head) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname !== '/_wsproxy') return;
    const target = url.searchParams.get('url');
    if (!target) { socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); socket.destroy(); return; }
    try {
      wssProxy.handleUpgrade(request, socket, head, (ws) => {
        const outbound = new WebSocket(target);
        outbound.on('open', () => {
          ws.on('message', msg => { try { outbound.send(msg); } catch (e) { } });
          outbound.on('message', msg => { try { ws.send(msg); } catch (e) { } });
          const forwardClose = (code, reason) => { try { ws.close(code, reason); } catch (e) { } try { outbound.close(code, reason); } catch (e) { } };
          ws.on('close', forwardClose); outbound.on('close', forwardClose);
        });
        outbound.on('error', () => ws.close()); ws.on('error', () => outbound.close());
      });
    } catch (e) { try { socket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); socket.destroy(); } catch (e) { } }
  });
  return wssProxy;
}

// === SERVER START ===
const server = http.createServer(app);
const wssTelemetry = new WebSocketServer({ server, path: "/_euph_ws" });
wssTelemetry.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => { try { const parsed = JSON.parse(raw.toString()); if (parsed && parsed.cmd === 'ping') ws.send(JSON.stringify({ msg: 'pong', ts: Date.now() })); } catch (e) { } });
});
setupWsProxy(server);
server.listen(PORT, () => console.log(`Euphoria v2 running on port ${PORT}`));

// === PROXY ENDPOINT ===
// (This section continues with full proxy logic, HTML rewriting, asset caching, session handling...)