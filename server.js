// server.js — Euphoria v3 (hybrid)
// - Legacy HTML rewrite proxy for "simple/fast" pages
// - Scramjet mounted for "hard" SPAs (Xbox/Google login etc.)
// - Robust asset streaming + range support + redirect correctness
// Node 20+ (ESM)

import express from "express";
import compression from "compression";
import morgan from "morgan";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { JSDOM } from "jsdom";
import { LRUCache } from "lru-cache";
import { createScramjetServer } from "@mercuryworkshop/scramjet";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

// -------------------- paths --------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------------------- config --------------------
const PORT = parseInt(process.env.PORT || "3000", 10);
const NODE_ENV = process.env.NODE_ENV || "production";
const TRUST_PROXY = true;

const DEFAULT_UA =
  process.env.USER_AGENT_DEFAULT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const FETCH_TIMEOUT_MS = parseInt(process.env.FETCH_TIMEOUT_MS || "25000", 10);
const MAX_HTML_BYTES = parseInt(process.env.MAX_HTML_BYTES || String(2 * 1024 * 1024), 10);
const MAX_ASSET_BYTES_CACHE = parseInt(process.env.MAX_ASSET_BYTES_CACHE || String(2 * 1024 * 1024), 10);

const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS || String(1000 * 60 * 5), 10);
const CACHE_MAX_BYTES = parseInt(process.env.CACHE_MAX_BYTES || String(128 * 1024 * 1024), 10);

const ENABLE_REWRITE_PROXY = process.env.ENABLE_REWRITE_PROXY !== "0";
const ENABLE_SCRAMJET = process.env.ENABLE_SCRAMJET !== "0";

const SCRAMJET_PREFIX = "/sj";
const PROXY_PREFIX = "/proxy";

// Heuristics: if a site is painful in rewrite-mode, default to scramjet
const FORCE_SCRAMJET_HOSTS = new Set([
  "login.live.com",
  "account.live.com",
  "xbox.com",
  "www.xbox.com",
  "microsoft.com",
  "login.microsoftonline.com",
  "accounts.google.com",
  "consent.google.com",
  "myaccount.google.com"
]);

// -------------------- app --------------------
const app = express();
if (TRUST_PROXY) app.set("trust proxy", true);

app.use(cors());
app.use(morgan(NODE_ENV === "development" ? "dev" : "tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_GLOBAL || "600", 10),
    standardHeaders: true,
    legacyHeaders: false
  })
);

// Static
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// Healthcheck (Koyeb)
app.get("/_health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// -------------------- memory cache --------------------
const MEM = new LRUCache({
  maxSize: CACHE_MAX_BYTES,
  ttl: CACHE_TTL_MS,
  sizeCalculation: (v) => (typeof v === "string" ? Buffer.byteLength(v, "utf8") : Buffer.byteLength(JSON.stringify(v), "utf8"))
});

// -------------------- utils --------------------
function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function getRequestOrigin(req) {
  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "https")
    .split(",")[0]
    .trim();
  const host = String(req.headers["x-forwarded-host"] || req.headers.host || "localhost")
    .split(",")[0]
    .trim();
  return `${proto}://${host}`;
}

function isProbablySearch(q) {
  const s = String(q || "").trim();
  if (!s) return false;
  if (/^https?:\/\//i.test(s)) return false;
  if (s.includes(" ")) return true;
  if (!s.includes(".")) return true;
  return false;
}

function normalizeUserInputToUrl(input) {
  const s = String(input || "").trim();
  if (!s) return null;
  if (/^https?:\/\//i.test(s)) return s;
  if (isProbablySearch(s)) {
    return "https://www.google.com/search?q=" + encodeURIComponent(s);
  }
  // treat as hostname / domain / path
  return "https://" + s;
}

function toAbsoluteUrlMaybe(u, base) {
  try { return new URL(u, base).href; } catch { return null; }
}

function shouldUseScramjet(targetUrl) {
  try {
    const h = new URL(targetUrl).hostname;
    if (FORCE_SCRAMJET_HOSTS.has(h)) return true;
  } catch {}
  return false;
}

function proxyUrlFor(targetUrl, origin) {
  return `${origin}${PROXY_PREFIX}?url=${encodeURIComponent(targetUrl)}`;
}

function scramjetUrlFor(targetUrl) {
  // Scramjet server expects /sj?url=
  return `${SCRAMJET_PREFIX}?url=${encodeURIComponent(targetUrl)}`;
}

function isAssetContentType(ct) {
  const s = (ct || "").toLowerCase();
  if (!s) return false;
  if (s.includes("text/html")) return false;
  return true;
}

function dropHopByHopHeaders(headers) {
  const hop = new Set([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade"
  ]);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!k) continue;
    const lk = k.toLowerCase();
    if (hop.has(lk)) continue;
    out[k] = v;
  }
  return out;
}

function sanitizeResponseHeadersForBrowser(headers) {
  const drop = new Set([
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "permissions-policy"
  ]);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (drop.has(lk)) continue;
    out[k] = v;
  }
  // allow embedding
  out["X-Frame-Options"] = "ALLOWALL";
  return out;
}

function buildUpstreamHeaders(req, targetUrl) {
  const headers = {};
  headers["User-Agent"] = req.headers["user-agent"] || DEFAULT_UA;
  headers["Accept"] = req.headers["accept"] || "*/*";
  headers["Accept-Language"] = req.headers["accept-language"] || "en-US,en;q=0.9";
  headers["Accept-Encoding"] = "gzip, deflate, br";

  // forwarding referer/origin carefully
  if (req.headers.referer) headers["Referer"] = req.headers.referer;
  try { headers["Origin"] = new URL(targetUrl).origin; } catch {}

  // cookie pass-through (best effort)
  if (req.headers.cookie) headers["Cookie"] = req.headers.cookie;

  return headers;
}

async function fetchWithTimeout(url, init) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    return res;
  } finally {
    clearTimeout(t);
  }
}

function readRangeHeader(rangeValue, totalSize) {
  const v = String(rangeValue || "").trim();
  if (!v.toLowerCase().startsWith("bytes=")) return null;
  const rest = v.slice(6);
  const [a, b] = rest.split("-", 2);
  let start = a === "" ? null : parseInt(a, 10);
  let end = b === "" ? null : parseInt(b, 10);

  if (Number.isNaN(start)) start = null;
  if (Number.isNaN(end)) end = null;

  if (start === null && end === null) return null;

  // suffix range "-500"
  if (start === null && end !== null) {
    const length = clamp(end, 0, totalSize);
    return { start: Math.max(0, totalSize - length), end: totalSize - 1 };
  }

  if (start !== null) {
    if (end === null) end = totalSize - 1;
    start = clamp(start, 0, totalSize - 1);
    end = clamp(end, start, totalSize - 1);
    return { start, end };
  }

  return null;
}

function isHtmlWanted(req, upstreamContentType) {
  const accept = String(req.headers.accept || "").toLowerCase();
  if (accept.includes("text/html")) return true;
  const ct = String(upstreamContentType || "").toLowerCase();
  if (ct.includes("text/html")) return true;
  return false;
}

// -------------------- scramjet mount --------------------
if (ENABLE_SCRAMJET) {
  const scramjet = createScramjetServer({
    prefix: SCRAMJET_PREFIX
  });
  app.use(SCRAMJET_PREFIX, scramjet);
}

// -------------------- main proxy endpoint --------------------
if (ENABLE_REWRITE_PROXY) {
  app.get(PROXY_PREFIX, async (req, res) => {
    const origin = getRequestOrigin(req);

    const raw = req.query.url ? String(req.query.url) : "";
    const target = normalizeUserInputToUrl(raw);

    if (!target) {
      return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
    }

    // hard-site fallback to scramjet
    if (ENABLE_SCRAMJET && shouldUseScramjet(target)) {
      return res.redirect(scramjetUrlFor(target));
    }

    // cache key: include accept to avoid serving html for assets, etc.
    const cacheKey = `html:${target}`;

    // fast cache hit (HTML only)
    if (MEM.has(cacheKey)) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.send(MEM.get(cacheKey));
    }

    // fetch upstream
    let upstream;
    try {
      upstream = await fetchWithTimeout(target, {
        method: "GET",
        headers: buildUpstreamHeaders(req, target),
        redirect: "manual"
      });
    } catch (e) {
      // network failure => scramjet fallback if enabled
      if (ENABLE_SCRAMJET) return res.redirect(scramjetUrlFor(target));
      return res.status(502).send("Upstream fetch failed");
    }

    // handle redirect rewriting
    if ([301, 302, 303, 307, 308].includes(upstream.status)) {
      const loc = upstream.headers.get("location");
      if (loc) {
        const abs = toAbsoluteUrlMaybe(loc, target) || loc;
        // if redirect is to forced-scramjet host, jump there
        if (ENABLE_SCRAMJET && shouldUseScramjet(abs)) {
          return res.redirect(scramjetUrlFor(abs));
        }
        res.setHeader("Location", proxyUrlFor(abs, origin));
        return res.status(upstream.status).end();
      }
    }

    const ct = upstream.headers.get("content-type") || "";

    // If not HTML: stream as asset (fix complex images/video)
    if (isAssetContentType(ct)) {
      const passthrough = sanitizeResponseHeadersForBrowser(
        dropHopByHopHeaders(Object.fromEntries(upstream.headers.entries()))
      );

      // Range support
      const range = req.headers.range;
      if (range && upstream.headers.get("accept-ranges")) {
        // If upstream already supports range, just pass it through by refetching with range
        try {
          const ranged = await fetchWithTimeout(target, {
            method: "GET",
            headers: { ...buildUpstreamHeaders(req, target), Range: range },
            redirect: "manual"
          });
          res.status(ranged.status);
          for (const [k, v] of Object.entries(sanitizeResponseHeadersForBrowser(dropHopByHopHeaders(Object.fromEntries(ranged.headers.entries()))))) {
            try { res.setHeader(k, v); } catch {}
          }
          if (ranged.body) {
            return ranged.body.pipeTo(WritableStreamToNode(res));
          }
          const buf = Buffer.from(await ranged.arrayBuffer());
          return res.send(buf);
        } catch {
          // fallback to normal
        }
      }

      res.status(upstream.status);
      for (const [k, v] of Object.entries(passthrough)) {
        try { res.setHeader(k, v); } catch {}
      }

      // stream
      if (upstream.body) {
        try {
          return upstream.body.pipeTo(WritableStreamToNode(res));
        } catch {
          // fallback to buffer
        }
      }
      const buf = Buffer.from(await upstream.arrayBuffer());
      return res.send(buf);
    }

    // HTML: rewrite
    let html;
    try {
      const text = await upstream.text();
      // basic size guard
      if (Buffer.byteLength(text, "utf8") > MAX_HTML_BYTES) {
        if (ENABLE_SCRAMJET) return res.redirect(scramjetUrlFor(target));
      }
      html = text;
    } catch {
      if (ENABLE_SCRAMJET) return res.redirect(scramjetUrlFor(target));
      return res.status(502).send("Failed reading HTML");
    }

    // rewrite with JSDOM
    const out = rewriteHtmlDocument(html, target, origin);

    // cache HTML
    MEM.set(cacheKey, out);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(out);
  });
}

// -------------------- relative-path fallback --------------------
app.use((req, res, next) => {
  if (req.path.startsWith(PROXY_PREFIX) || req.path.startsWith(SCRAMJET_PREFIX) || req.path.startsWith("/_health")) return next();

  // If user clicks a relative link inside proxied page, try to reconstruct from referer
  const ref = req.headers.referer || req.headers.referrer;
  if (!ref) return next();

  const m = String(ref).match(/[?&]url=([^&]+)/);
  if (!m) return next();

  const base = safeDecode(m[1]);
  try {
    const abs = new URL(req.originalUrl, base).href;
    const origin = getRequestOrigin(req);
    // if it points to a hard host, scramjet
    if (ENABLE_SCRAMJET && shouldUseScramjet(abs)) return res.redirect(scramjetUrlFor(abs));
    return res.redirect(proxyUrlFor(abs, origin));
  } catch {
    return next();
  }
});

// -------------------- SPA fallback --------------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public/index.html")));
app.get("*", (req, res) => {
  if (req.method === "GET" && String(req.headers.accept || "").includes("text/html")) {
    return res.sendFile(path.join(__dirname, "public/index.html"));
  }
  res.status(404).send("Not found");
});

// -------------------- server start --------------------
http.createServer(app).listen(PORT, () => {
  console.log(`Euphoria v3 listening on ${PORT}`);
});

// -------------------- HTML rewriter --------------------
function rewriteHtmlDocument(html, baseUrl, origin) {
  // sanitize minimal
  html = String(html || "")
    .replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "")
    .replace(/\s+integrity=(["'])(.*?)\1/gi, "")
    .replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");

  let dom;
  try {
    dom = new JSDOM(html, { url: baseUrl, contentType: "text/html" });
  } catch {
    return html;
  }

  const doc = dom.window.document;

  // base tag
  if (!doc.querySelector("base")) {
    const head = doc.querySelector("head");
    if (head) {
      const b = doc.createElement("base");
      b.setAttribute("href", baseUrl);
      head.insertBefore(b, head.firstChild);
    }
  }

  // rewrite attributes
  const attrCandidates = [
    { sel: "a[href]", attr: "href" },
    { sel: "link[href]", attr: "href" },
    { sel: "script[src]", attr: "src" },
    { sel: "img[src]", attr: "src" },
    { sel: "iframe[src]", attr: "src" },
    { sel: "source[src]", attr: "src" },
    { sel: "video[src]", attr: "src" },
    { sel: "audio[src]", attr: "src" },
    { sel: "form[action]", attr: "action" }
  ];

  for (const { sel, attr } of attrCandidates) {
    const nodes = Array.from(doc.querySelectorAll(sel));
    for (const el of nodes) {
      const v = el.getAttribute(attr);
      if (!v) continue;
      if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(v)) continue;

      // already proxied?
      if (v.includes(`${PROXY_PREFIX}?url=`) || v.includes(`${SCRAMJET_PREFIX}?url=`)) continue;

      const abs = toAbsoluteUrlMaybe(v, baseUrl) || v;

      // hard hosts -> scramjet link
      if (ENABLE_SCRAMJET && shouldUseScramjet(abs)) {
        el.setAttribute(attr, scramjetUrlFor(abs));
      } else {
        el.setAttribute(attr, proxyUrlFor(abs, origin));
      }

      // avoid new tabs breaking
      if (el.tagName === "A") el.removeAttribute("target");
    }
  }

  // srcset
  const srcsets = Array.from(doc.querySelectorAll("[srcset]"));
  for (const el of srcsets) {
    const ss = el.getAttribute("srcset") || "";
    const parts = ss.split(",").map((p) => {
      const t = p.trim();
      if (!t) return t;
      const [u, rest] = t.split(/\s+/, 2);
      if (!u || /^data:/i.test(u)) return t;
      if (u.includes(`${PROXY_PREFIX}?url=`) || u.includes(`${SCRAMJET_PREFIX}?url=`)) return t;

      const abs = toAbsoluteUrlMaybe(u, baseUrl) || u;
      const rewritten =
        (ENABLE_SCRAMJET && shouldUseScramjet(abs)) ? scramjetUrlFor(abs) : proxyUrlFor(abs, origin);

      return rewritten + (rest ? " " + rest : "");
    });
    el.setAttribute("srcset", parts.join(", "));
  }

  // CSS url(...) in style tags + inline style
  const styleTags = Array.from(doc.querySelectorAll("style"));
  for (const st of styleTags) {
    const txt = st.textContent || "";
    st.textContent = rewriteCssUrls(txt, baseUrl, origin);
  }

  const inlineStyled = Array.from(doc.querySelectorAll("[style]"));
  for (const el of inlineStyled) {
    const s = el.getAttribute("style") || "";
    el.setAttribute("style", rewriteCssUrls(s, baseUrl, origin));
  }

  // meta refresh
  const metas = Array.from(doc.querySelectorAll('meta[http-equiv="refresh"], meta[http-equiv="Refresh"]'));
  for (const m of metas) {
    const c = m.getAttribute("content") || "";
    const parts = c.split(";");
    if (parts.length < 2) continue;
    const match = parts.slice(1).join(";").match(/url=(.*)/i);
    if (!match) continue;
    const dest = match[1].replace(/['"]/g, "").trim();
    const abs = toAbsoluteUrlMaybe(dest, baseUrl) || dest;
    const rewritten =
      (ENABLE_SCRAMJET && shouldUseScramjet(abs)) ? scramjetUrlFor(abs) : proxyUrlFor(abs, origin);
    m.setAttribute("content", parts[0] + ";url=" + rewritten);
  }

  // inject client patch: make fetch/xhr/form navigation go through proxy
  injectClientPatch(doc, baseUrl, origin);

  return dom.serialize();
}

function rewriteCssUrls(cssText, baseUrl, origin) {
  return String(cssText || "").replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
    const v = String(u || "").trim();
    if (!v) return m;
    if (/^(data:|blob:|about:)/i.test(v)) return m;
    if (v.includes(`${PROXY_PREFIX}?url=`) || v.includes(`${SCRAMJET_PREFIX}?url=`)) return m;

    const abs = toAbsoluteUrlMaybe(v, baseUrl) || v;
    const rewritten =
      (ENABLE_SCRAMJET && shouldUseScramjet(abs)) ? scramjetUrlFor(abs) : proxyUrlFor(abs, origin);

    return `url("${rewritten}")`;
  });
}

function injectClientPatch(doc, baseUrl, origin) {
  const marker = "/* EUPHORIA_CLIENT_PATCH_V3 */";
  if (doc.documentElement.outerHTML.includes(marker)) return;

  const script = doc.createElement("script");
  script.textContent = `
${marker}
(() => {
  const ORIGIN = ${JSON.stringify(origin)};
  const PROXY = ${JSON.stringify(PROXY_PREFIX)};
  const SJ = ${JSON.stringify(SCRAMJET_PREFIX)};
  const FORCE = new Set(${JSON.stringify(Array.from(FORCE_SCRAMJET_HOSTS))});

  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch { return u; } };
  const host = (u) => { try { return new URL(u).hostname; } catch { return ""; } };
  const needsSJ = (u) => FORCE.has(host(u));

  const wrap = (u) => {
    if (!u) return u;
    if (/^(data:|blob:|about:|javascript:|mailto:|tel:|#)/i.test(u)) return u;
    if (u.includes(PROXY + "?url=") || u.includes(SJ + "?url=")) return u;
    const a = abs(u);
    if (needsSJ(a)) return SJ + "?url=" + encodeURIComponent(a);
    return ORIGIN + PROXY + "?url=" + encodeURIComponent(a);
  };

  // fetch
  const ofetch = window.fetch;
  window.fetch = function(resource, init) {
    try {
      if (typeof resource === "string") resource = wrap(resource);
      else if (resource && resource.url) resource = new Request(wrap(resource.url), resource);
    } catch {}
    return ofetch.call(this, resource, init);
  };

  // xhr
  const OXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    const x = new OXHR();
    const o = x.open;
    x.open = function(method, url, ...rest) {
      try { url = wrap(url); } catch {}
      return o.call(this, method, url, ...rest);
    };
    return x;
  };

  // forms
  document.addEventListener("submit", (e) => {
    try {
      const f = e.target;
      if (!f || !f.action) return;
      f.action = wrap(f.action);
    } catch {}
  }, true);

  // navigation helpers
  const nav = (u) => { location.href = wrap(u); };
  window.__euphoriaNav = nav;
})();
`;
  (doc.body || doc.documentElement).appendChild(script);
}

// -------------------- stream bridge --------------------
function WritableStreamToNode(res) {
  // minimal WebStream->Node response writer
  return new WritableStream({
    write(chunk) {
      return new Promise((resolve, reject) => {
        res.write(Buffer.from(chunk), (err) => (err ? reject(err) : resolve()));
      });
    },
    close() {
      return new Promise((resolve) => {
        res.end(() => resolve());
      });
    },
    abort() {
      try { res.end(); } catch {}
    }
  });
}