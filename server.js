// server.js — Euphoria proxy (redirect containment, cookie passthrough, caching, injection)
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

// Config
const SESSION_NAME = "euphoria_sid";
const SESSION_TTL = 1000 * 60 * 60 * 24;
const CACHE_TTL = 1000 * 60 * 5;
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

const SESSIONS = new Map(); // sid -> { cookies: Map, last }
const MEM_CACHE = new Map(); // key -> { val, t }

function now() { return Date.now(); }
function mkSid() { return Math.random().toString(36).slice(2) + now().toString(36); }
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
      } else try { fs.unlinkSync(f); } catch {}
    } catch {}
  }
  return null;
}
function cacheSet(k, v) {
  MEM_CACHE.set(k, { val: v, t: now() });
  const f = path.join(CACHE_DIR, cacheKey(k));
  try { fs.writeFileSync(f, JSON.stringify({ val: v, t: now() }), "utf8"); } catch (e) {}
}

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
    httpOnly: true, path: "/", sameSite: "Lax", maxAge: 60 * 60 * 24
  });
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", sc);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, sc]);
  else res.setHeader("Set-Cookie", [prev, sc]);
}

function buildCookieHeader(map) {
  const parts = [];
  for (const [k, v] of map.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}
function storeSetCookieStrings(setCookieStrings = [], sessionData) {
  for (const sc of setCookieStrings) {
    try {
      const kv = sc.split(";")[0];
      const parsed = cookie.parse(kv || "");
      for (const k in parsed) if (k) sessionData.cookies.set(k, parsed[k]);
    } catch {}
  }
}
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) {
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}
function extractUrl(req) {
  if (req.query && req.query.url) return req.query.url;
  const m = req.path.match(/^\/proxy\/(.+)$/);
  if (m) return decodeURIComponent(m[1]);
  return null;
}

// Heuristics for search vs url (keep searches as searches)
function isLikelySearch(input) {
  if (!input) return true;
  const s = input.trim();
  if (s.includes(" ")) return true;
  if (/^https?:\/\//i.test(s)) return false;
  if (/\./.test(s)) return false;
  return true;
}
function normalizeInputToURL(input) {
  const v = (input || "").trim();
  if (!v) return "https://www.google.com";
  if (isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  if (/^https?:\/\//i.test(v)) return v;
  return "https://" + v;
}

// Serve index
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// /load -> full-page HTML (follows redirects server-side, rewrites links & injects containment script)
app.get("/load", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (e.g. /load?url=https://google.com)");
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
    // follow redirects server-side so user stays in one flow
    const response = await fetch(raw, { headers, redirect: "follow", signal: controller.signal });
    clearTimeout(timeout);

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

    // remove CSP meta tags
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    // remove integrity/crossorigin that break proxying
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // inject base tag pointing to canonical finalUrl (helps relative resolution in JS)
    html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><base href="${finalUrl}">`);

    // Remove target="_blank"
    html = html.replace(/\s+target=(["'])(.*?)\1/gi, " ");

    // Replace window.open(...) common patterns -> location.href to keep in same tab
    html = html.replace(/window\.open\((['"])(https?:\/\/[^'"]+)\1(,[^)]+)?\)/gi, (m, q, url) => {
      try { const u = new URL(url).href; return `window.location.href=${q}${u}${q}`; } catch { return m; }
    });

    // Rewrite anchor hrefs to /load?url=absolute (full page navigation)
    html = html.replace(/<a\b([^>]*?)href=(["'])([^"']*)\2/gi, (m, pre, q, val) => {
      if (!val) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `<a${pre}href="/load?url=${encodeURIComponent(abs)}"`;
    });

    // Rewrite asset src/href/srcset to /proxy?url=absolute
    html = html.replace(/(<\s*(?:img|script|link|source)[^>]*?(?:src|href|srcset)=)(["'])([^"']*)\2/gi, (m, prefix, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${prefix}${q}/proxy?url=${encodeURIComponent(abs)}${q}`;
    });

    // Rewrite CSS url(...) -> /proxy
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
      if (!val) return m;
      if (/^data:/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Rewrite form actions to /proxy (so submissions go through server)
    html = html.replace(/(<\s*form[^>]*action=)(["'])([^"']*)(["'])/gi, (m, pre, q1, val, q2) => {
      if (!val) return m;
      if (/^(javascript:|#)/i.test(val)) return m;
      const abs = toAbsolute(val, finalUrl) || val;
      return `${pre}${q1}/proxy?url=${encodeURIComponent(abs)}${q2}`;
    });

    // Meta-refresh rewrite to /load
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

    // Remove known analytics scripts (best-effort)
    html = html.replace(/<script[^>]*src=["'][^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*["'][^>]*><\/script>/gi, "");

    // INJECT: containment & runtime rewriting script
    // - rewrites anchors that appear later (MutationObserver)
    // - intercepts clicks and form submits
    // - patches history API and window.open
    const containmentScript = `
<script>
(function(){
  try {
    const toLoad = (href) => '/load?url=' + encodeURIComponent(href);
    const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);

    // normalize and absolute-ify relative hrefs using document.baseURI
    function absolute(h) {
      try { return new URL(h, document.baseURI).href; } catch { return h; }
    }

    // rewrite single anchor element href -> /load?url=abs
    function rewriteAnchor(a) {
      if (!a || !a.getAttribute) return;
      try {
        const href = a.getAttribute('href');
        if (!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        const abs = absolute(href);
        a.setAttribute('href', toLoad(abs));
        a.removeAttribute('target');
      } catch(e){}
    }

    // rewrite asset refs (img, script, link, source) to /proxy if not data:
    function rewriteAsset(el, attrName) {
      try {
        const val = el.getAttribute(attrName);
        if (!val) return;
        if (/^data:/i.test(val)) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(val)) return;
        const abs = absolute(val);
        el.setAttribute(attrName, toProxy(abs));
      } catch(e){}
    }

    function rewriteAll() {
      // anchors
      document.querySelectorAll('a[href]').forEach(rewriteAnchor);
      // assets
      ['img','script','link','source','video','audio','iframe'].forEach(tag => {
        document.querySelectorAll(tag + '[src]').forEach(el => rewriteAsset(el, 'src'));
        document.querySelectorAll(tag + '[href]').forEach(el => rewriteAsset(el, 'href'));
      });
      // srcset handling
      document.querySelectorAll('[srcset]').forEach(el => {
        try {
          const ss = el.getAttribute('srcset');
          if (!ss) return;
          const parts = ss.split(',').map(p => {
            const [url, rest] = p.trim().split(/\s+/,2);
            if (!url) return p;
            if (/^data:/i.test(url)) return p;
            return toProxy(absolute(url)) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        } catch(e){}
      });
    }

    // initial rewrite
    rewriteAll();

    // Observe mutations and rewrite newly added anchors/assets
    const mo = new MutationObserver(muts => {
      for (const mut of muts) {
        if (mut.type === 'childList') {
          mut.addedNodes.forEach(n => {
            if (n.nodeType !== 1) return;
            if (n.matches && n.matches('a[href]')) rewriteAnchor(n);
            n.querySelectorAll && n.querySelectorAll('a[href]').forEach(rewriteAnchor);
            // assets
            ['img','script','link','source','video','audio','iframe'].forEach(tag => {
              if (n.matches && n.matches(tag + '[src]')) rewriteAsset(n, 'src');
              n.querySelectorAll && n.querySelectorAll(tag + '[src]').forEach(el => rewriteAsset(el, 'src'));
              if (n.matches && n.matches(tag + '[href]')) rewriteAsset(n, 'href');
              n.querySelectorAll && n.querySelectorAll(tag + '[href]').forEach(el => rewriteAsset(el, 'href'));
            });
            if (n.querySelectorAll && n.querySelectorAll('[srcset]').length) {
              n.querySelectorAll('[srcset]').forEach(el => {
                const ss = el.getAttribute('srcset');
                if (!ss) return;
                const parts = ss.split(',').map(p => {
                  const [url, rest] = p.trim().split(/\\s+/,2);
                  if (!url) return p;
                  if (/^data:/i.test(url)) return p;
                  return toProxy(absolute(url)) + (rest ? ' ' + rest : '');
                });
                el.setAttribute('srcset', parts.join(', '));
              });
            }
          });
        }
      }
    });
    mo.observe(document.documentElement || document, { childList: true, subtree: true });

    // Intercept clicks on anchors to ensure navigation uses /load and not leaving page
    document.addEventListener('click', function(e){
      const a = e.target.closest && e.target.closest('a[href]');
      if (!a) return;
      try {
        const href = a.getAttribute('href');
        if (!href) return;
        if (href.startsWith('/load?url=') || href.startsWith('/proxy?url=')) {
          // already proxied — allow
          return;
        }
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = absolute(href);
        window.location.href = toLoad(abs);
      } catch(e){}
    }, true);

    // Intercept form submissions: rewrite action to /proxy so server can POST properly
    document.addEventListener('submit', function(e){
      const f = e.target;
      if (!f || !f.action) return;
      try {
        const act = f.getAttribute('action') || '';
        if (/^(javascript:|#)/i.test(act)) return;
        const abs = absolute(act);
        f.setAttribute('action', '/proxy?url=' + encodeURIComponent(abs));
      } catch(e){}
    }, true);

    // Patch history API to attempt to keep navigation proxied if scripts call pushState with relative urls
    (function(history){
      const push = history.pushState;
      history.pushState = function(state, title, url){
        try {
          if (typeof url === 'string' && url && !url.startsWith('/load?url=')) {
            const abs = absolute(url);
            url = toLoad(abs);
          }
        } catch(e){}
        return push.apply(history, arguments);
      };
      const replace = history.replaceState;
      history.replaceState = function(state, title, url){
        try {
          if (typeof url === 'string' && url && !url.startsWith('/load?url=')) {
            const abs = absolute(url);
            url = toLoad(abs);
          }
        } catch(e){}
        return replace.apply(history, arguments);
      };
    })(window.history);

    // patch window.open -> location.href
    try {
      const origOpen = window.open;
      window.open = function(u, ...rest) {
        try {
          if (!u) return origOpen.apply(window, arguments);
          const abs = absolute(u);
          window.location.href = toLoad(abs);
          return null;
        } catch(e){ return origOpen.apply(window, arguments); }
      };
    } catch(e){}

  } catch(e){}
})();
</script>
    `;

    html = html.replace(/<body([^>]*)>/i, (m) => m + containmentScript);

    // Cache & respond
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

// /proxy -> assets & form POSTs (pipes bytes, caches small items)
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
      if (obj.headers) for (const [k,v] of Object.entries(obj.headers)) res.setHeader(k, v);
      return res.send(Buffer.from(obj.body, "base64"));
    } catch {}
  }

  const cookieHeader = buildCookieHeader(session.data.cookies);
  const headers = { "User-Agent": req.headers["user-agent"] || "Euphoria/1.0", "Accept": req.headers["accept"] || "*/*", "Referer": req.headers["referer"] || undefined };
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

    if (buf.length < 100 * 1024) {
      try { cacheSet(cacheKeyAsset, JSON.stringify({ headers: { "Content-Type": ctype }, body: buf.toString("base64") })); } catch {}
    }

    persistSessionCookie(res, session.sid);
    return res.send(buf);

  } catch (err) {
    console.error("Proxy asset error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    return res.status(500).send("Proxy asset error: " + (err && err.message ? err.message : String(err)));
  }
});

// fallback for SPA routing to index.html
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
