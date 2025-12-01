// server.js — EUPHORIA v2 (complete corrected version)
// - No iframes. Index serves topbar; proxied HTML is injected into page.
// - Proxy-all (HTML, JS, CSS, images, fonts, WASM, video, JSON, etc.)
// - Session cookie persistence (memory store).
// - Deployment-aware rewrites to avoid recursion.
// - Injects compact rewrite shim into proxied HTML.
// - Streams binary assets; progressive HTML with scramjet StringStream.
// - Small in-memory + optional disk caching for assets and HTML.
// - WebSocket telemetry endpoint at /_euph_ws.
// - Defensive error handling and safe header handling.

import express from "express";
import fetch from "node-fetch";
import scramjetPkg from "scramjet";
const { StringStream } = scramjetPkg;
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import fs from "fs";
import fsPromises from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { pipeline } from "stream";
import { promisify } from "util";
import { EventEmitter } from "events";
import { WebSocketServer } from "ws";

EventEmitter.defaultMaxListeners = 200;
const pipe = promisify(pipeline);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------- Config --------------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX = 256 * 1024; // 256 KB
const ENABLE_DISK_CACHE = true;
const CACHE_DIR = path.join(__dirname, "cache");
const FETCH_TIMEOUT_MS = 30000;

if (ENABLE_DISK_CACHE) {
  fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});
}

// asset heuristics
const ASSET_EXTENSIONS = [
  ".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif",
  ".svg", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".json", ".map",
  ".mp4", ".webm", ".mp3"
];
const SPECIAL_ASSET_NAMES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

// headers that break injection or embedding
const DROP_HEADERS_LOWER = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// -------------------- Express setup --------------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// serve static UI from public/
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -------------------- simple session/cookie store --------------------
const SESSION_NAME = "euphoria_sid";
const SESSIONS = new Map();

function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: Date.now() }; SESSIONS.set(sid, payload); return { sid, payload }; }

function parseCookies(cookieHeader = "") {
  const out = {};
  cookieHeader.split(";").forEach(pair => {
    const [k, v] = (pair || "").split("=").map(s => (s || "").trim());
    if (k && v) out[k] = v;
  });
  return out;
}

function getSessionFromReq(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  let sid = cookies[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid);
  payload.last = Date.now();
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
      const k = kv.slice(0, idx).trim();
      const v = kv.slice(idx + 1).trim();
      if (k) sessionPayload.cookies.set(k, v);
    } catch (e) {
      // ignore invalid cookie formats
    }
  }
}

function buildCookieHeader(map) {
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

// cleanup stale sessions periodically
setInterval(() => {
  const cutoff = Date.now() - (1000 * 60 * 30);
  for (const [sid, payload] of SESSIONS.entries()) {
    if (payload.last < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 5);

// -------------------- cache --------------------
const MEM_CACHE = new Map();

function cacheKey(s) { return Buffer.from(s).toString("base64url"); }
function now() { return Date.now(); }

function cacheGet(key) {
  const entry = MEM_CACHE.get(key);
  if (entry && (now() - entry.t) < CACHE_TTL) return entry.v;
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    if (fs.existsSync(fname)) {
      try {
        const raw = fs.readFileSync(fname, "utf8");
        const obj = JSON.parse(raw);
        if ((now() - obj.t) < CACHE_TTL) {
          MEM_CACHE.set(key, { v: obj.v, t: obj.t });
          return obj.v;
        } else {
          try { fs.unlinkSync(fname); } catch (e) {}
        }
      } catch (e) {
        // ignore disk parse errors
      }
    }
  }
  return null;
}

function cacheSet(key, val) {
  MEM_CACHE.set(key, { v: val, t: now() });
  if (ENABLE_DISK_CACHE) {
    const fname = path.join(CACHE_DIR, cacheKey(key));
    fsPromises.writeFile(fname, JSON.stringify({ v: val, t: now() }), "utf8").catch(() => {});
  }
}

// -------------------- helpers --------------------
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}

function isAlreadyProxiedHref(href) {
  if (!href) return false;
  try {
    if (href.includes("/proxy?url=")) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if (resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch (e) {
    // ignore
  }
  return false;
}

function proxyizeAbsoluteUrl(absUrl) {
  try {
    const u = new URL(absUrl);
    return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`;
  } catch (e) {
    try {
      const u2 = new URL("https://" + absUrl);
      return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`;
    } catch (e2) {
      return absUrl;
    }
  }
}

function toDeploymentProxyLink(href, base) {
  if (!href) return href;
  if (isAlreadyProxiedHref(href)) {
    try {
      const resolved = new URL(href, base || DEPLOYMENT_ORIGIN);
      if (resolved.pathname.startsWith("/proxy")) {
        const orig = resolved.searchParams.get("url");
        if (orig) return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(orig)}`;
      }
    } catch (e) {}
    return href;
  }
  const abs = toAbsolute(href, base) || href;
  return proxyizeAbsoluteUrl(abs);
}

function looksLikeAssetPath(urlStr) {
  if (!urlStr) return false;
  try {
    const p = new URL(urlStr, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (p.endsWith(ext)) return true;
    for (const seg of SPECIAL_ASSET_NAMES) if (p.endsWith(seg)) return true;
    return false;
  } catch (e) {
    const lower = urlStr.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (lower.endsWith(ext)) return true;
    for (const seg of SPECIAL_ASSET_NAMES) if (lower.endsWith(seg)) return true;
    return false;
  }
}

// -------------------- injection script --------------------
const INJECT_REWRITE_SCRIPT = `
<script>
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; const abs=new URL(u, document.baseURI).href; return DEPLOY + '/proxy?url=' + encodeURIComponent(abs);}catch(e){return u;} }
  // anchors
  document.querySelectorAll('a[href]').forEach(a=>{ try{ const h=a.getAttribute('href'); if(!h) return; if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return; if(h.includes('/proxy?url=')) return; a.setAttribute('href', prox(h)); a.removeAttribute('target'); }catch(e){} });
  // forms
  document.querySelectorAll('form[action]').forEach(f=>{ try{ const act = f.getAttribute('action'); if(!act) return; if(act.includes('/proxy?url=')) return; f.setAttribute('action', prox(act)); }catch(e){} });
  // assets + srcset
  const attrs = ['src','href','poster','data-src','data-href'];
  ['img','script','link','iframe','source','video','audio'].forEach(tag=>{
    document.querySelectorAll(tag).forEach(el=>{
      try{
        attrs.forEach(attr=>{
          if(el.hasAttribute && el.hasAttribute(attr)){
            const v = el.getAttribute(attr);
            if(!v) return;
            if(/^data:/i.test(v)) return;
            if(v.includes('/proxy?url=')) return;
            el.setAttribute(attr, prox(v));
          }
        });
        if(el.hasAttribute && el.hasAttribute('srcset')){
          const ss = el.getAttribute('srcset') || '';
          const parts = ss.split(',').map(p=>{
            const [u,rest] = p.trim().split(/\\s+/,2);
            if(!u) return p;
            if(/^data:/i.test(u)) return p;
            return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }
      }catch(e){}
    });
  });
  // fetch interception
  try {
    const origFetch = window.fetch;
    window.fetch = function(resource, init){
      try {
        if(typeof resource === 'string' && !resource.includes('/proxy?url=')) resource = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(resource, document.baseURI).href);
        else if(resource instanceof Request) {
          if(!resource.url.includes('/proxy?url=')) resource = new Request(DEPLOY + '/proxy?url=' + encodeURIComponent(resource.url), resource);
        }
      } catch(e){}
      return origFetch(resource, init);
    };
  } catch(e){}
  // XHR interception
  try {
    const OrigXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new OrigXHR();
      const origOpen = xhr.open;
      xhr.open = function(method, url, ...rest){
        try {
          if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)){
            url = DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(url, document.baseURI).href);
          }
        } catch(e){}
        return origOpen.call(this, method, url, ...rest);
      };
      return xhr;
    };
  } catch(e){}
})();
</script>
`;

// -------------------- WebSocket telemetry --------------------
const server = app.listen(PORT, () => console.log(`Euphoria v2 running on port ${PORT}`));
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now() }));
  ws.on("message", raw => {
    try {
      const parsed = JSON.parse(raw.toString());
      if (parsed && parsed.cmd === "ping") ws.send(JSON.stringify({ msg: "pong", ts: Date.now() }));
    } catch (e) { /* ignore */ }
  });
});

// -------------------- /proxy handler --------------------
app.get("/proxy", async (req, res) => {
  // support both /proxy?url=... and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // normalize shorthand hostnames
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  // get session and set cookie header BEFORE streaming
  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch (e) {}

  // Accept header detection
  const accept = (req.headers.accept || "").toLowerCase();

  // quick asset cache for non-HTML
  const assetKey = raw + "::asset";
  if (!accept.includes("text/html")) {
    const cached = cacheGet(assetKey);
    if (cached) {
      if (cached.headers) Object.entries(cached.headers).forEach(([k, v]) => {
        try { res.setHeader(k, v); } catch (e) {}
      });
      return res.send(Buffer.from(cached.body, "base64"));
    }
  }

  // HTML cache
  const htmlKey = raw + "::html";
  if (accept.includes("text/html")) {
    const cachedHtml = cacheGet(htmlKey);
    if (cachedHtml) { res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // origin headers to pass
  const originHeaders = {
    "User-Agent": req.headers["user-agent"] || "Euphoria/2.0",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if (req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  // fetch from origin with timeout
  let originRes;
  try {
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    originRes = await fetch(raw, { headers: originHeaders, redirect: "follow", signal: controller.signal });
    clearTimeout(to);
  } catch (err) {
    console.error("fetch error:", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // store upstream Set-Cookie headers to session
  try {
    const setCookies = originRes.headers.raw ? originRes.headers.raw()["set-cookie"] || [] : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch (e) { /* ignore */ }

  const contentType = (originRes.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = looksLikeAssetPath(raw) || !isHtml;

  // Asset path: stream binary (with small caching)
  if (treatAsAsset) {
    // forward safe headers
    originRes.headers.forEach((v, k) => {
      try { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) res.setHeader(k, v); } catch (e) {}
    });
    try { setSessionCookieHeader(res, session.sid); } catch (e) {}
    try {
      const arr = await originRes.arrayBuffer();
      const buf = Buffer.from(arr);
      if (buf.length < ASSET_CACHE_MAX) {
        try { cacheSet(assetKey, { headers: Object.fromEntries(originRes.headers.entries()), body: buf.toString("base64") }); } catch (e) {}
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if (originRes.headers.get("cache-control")) res.setHeader("Cache-Control", originRes.headers.get("cache-control"));
      return res.send(buf);
    } catch (err) {
      // fallback streaming
      try {
        if (originRes.body && originRes.body.pipe) {
          originRes.body.pipe(res);
          return;
        }
        return res.status(502).send("Euphoria: asset stream failed");
      } catch (e) {
        return res.status(502).send("Euphoria: asset stream failed");
      }
    }
  }

  // HTML path: remove problematic headers and stream transformed HTML
  try {
    originRes.headers.forEach((v, k) => {
      try { if (!DROP_HEADERS_LOWER.has(k.toLowerCase())) res.setHeader(k, v); } catch (e) {}
    });
  } catch (e) {}

  // ensure we set content-type
  try { res.setHeader("Content-Type", "text/html; charset=utf-8"); } catch (e) {}

  // Progressive transform using scramjet StringStream
  try {
    const s = StringStream.from(originRes.body);
    let injected = false;
    const parts = []; // collect for caching if page small

    await s
      .map(chunk => chunk.toString())
      .map(chunk => {
        // sanitize integrity / crossorigin attributes
        let str = chunk.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
        // attempt to inject base or rewrite script early
        if (!injected) {
          if (/<head[^>]*>/i.test(str)) {
            const finalUrl = originRes.url || raw;
            str = str.replace(/<head([^>]*)>/i, `<head$1><base href="${finalUrl}">`);
          }
          if (str.toLowerCase().includes("</body>")) {
            str = str.replace(/<\/body>/i, INJECT_REWRITE_SCRIPT + "</body>");
            injected = true;
          } else if (/<\/head>/i.test(str) && !injected) {
            str = str.replace(/<\/head>/i, INJECT_REWRITE_SCRIPT + "</head>");
            injected = true;
          }
        }
        // conservative anchor rewrite
        str = str.replace(/(<\s*a\b[^>]*?\bhref=)(["'])([^"']*)\2/gi, function (m, pre, q, val) {
          try {
            if (!val) return m;
            if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
            if (isAlreadyProxiedHref(val)) return m;
            const abs = toAbsolute(val, originRes.url || raw) || val;
            return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}`;
          } catch (e) { return m; }
        });
        // conservative src/href rewrite for common tags
        str = str.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?\b(?:src|href)=)(["'])([^"']*)\2/gi, function (m, pre, q, val) {
          try {
            if (!val) return m;
            if (/^data:/i.test(val)) return m;
            if (isAlreadyProxiedHref(val)) return m;
            const abs = toAbsolute(val, originRes.url || raw) || val;
            return `${pre}${q}${proxyizeAbsoluteUrl(abs)}${q}`;
          } catch (e) { return m; }
        });
        return str;
      })
      .each(async transformedChunk => {
        try {
          if (!res.headersSent) {
            try { setSessionCookieHeader(res, session.sid); } catch (e) {}
          }
          parts.push(transformedChunk);
          res.write(transformedChunk);
        } catch (e) {
          // If write fails (client disconnected), just ignore and let stream finish
        }
      });

    try { res.end(); } catch (e) {}
    // cache on success if small
    try {
      const finalHtml = parts.join("");
      if (finalHtml.length > 0 && finalHtml.length < 512 * 1024) cacheSet(htmlKey, finalHtml);
    } catch (e) {}
    return;
  } catch (err) {
    console.error("html transform error:", err && err.message ? err.message : err);
    if (!res.headersSent) return res.status(500).send("Euphoria: failed to process HTML");
    try { res.end(); } catch (e) {}
    return;
  }
});

// -------------------- root and fallback --------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), err => {
    if (err) res.status(500).send("Failed to serve index.html");
  });
});

// fallback for HTML accept requests — serve index so SPA topbar works
app.get("*", (req, res, next) => {
  if (req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

// -------------------- process handlers --------------------
process.on("unhandledRejection", err => console.error("unhandledRejection", err));
process.on("uncaughtException", err => console.error("uncaughtException", err));