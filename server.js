// server.js — Euphoria (no headless browser) with lightweight cache and modern UI injection
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import mime from "mime-types";
import pkg from "scramjet"; // scramjet is CommonJS — default import and destructure
const { StringStream } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// -------------------- Session cookie store --------------------
const SESSION_COOKIE_NAME = "euphoria_sid";
const SESSIONS = new Map();
const SESSION_TTL = 1000 * 60 * 60 * 24; // 24 hours

function mkSid() {
  return Math.random().toString(36).slice(2) + "-" + Date.now().toString(36);
}
function now() {
  return Date.now();
}
function createSession() {
  const sid = mkSid();
  const data = { cookies: new Map(), last: now() };
  SESSIONS.set(sid, data);
  return { sid, data };
}
function getSession(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(new RegExp(`${SESSION_COOKIE_NAME}=([^;]+)`));
  const sid = match ? match[1] : null;
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const data = SESSIONS.get(sid);
  data.last = now();
  return { sid, data };
}
function persistSessionCookie(res, sid) {
  const cookieStr = `${SESSION_COOKIE_NAME}=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookieStr);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookieStr]);
  else res.setHeader("Set-Cookie", [prev, cookieStr]);
}
function storeSetCookieStrings(setCookies = [], sessionData) {
  for (const sc of setCookies) {
    try {
      const kv = sc.split(";")[0];
      const [k, ...rest] = kv.split("=");
      const v = rest.join("=");
      if (k && v) sessionData.cookies.set(k.trim(), v.trim());
    } catch (e) {
      // ignore
    }
  }
}
// prune old sessions
setInterval(() => {
  const cutoff = now() - SESSION_TTL;
  for (const [sid, data] of SESSIONS.entries()) {
    if ((data.last || 0) < cutoff) SESSIONS.delete(sid);
  }
}, 1000 * 60 * 10);

// -------------------- Lightweight cache (memory + disk) --------------------
const CACHE_DIR = path.join(__dirname, "cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes

function cacheKey(k) {
  return Buffer.from(k).toString("base64url");
}
function cacheGet(k) {
  const m = MEM_CACHE.get(k);
  if (m && (now() - m.t) < CACHE_TTL) return m.val;
  const fpath = path.join(CACHE_DIR, cacheKey(k));
  if (fs.existsSync(fpath)) {
    try {
      const raw = fs.readFileSync(fpath, "utf8");
      const obj = JSON.parse(raw);
      if ((now() - obj.t) < CACHE_TTL) {
        MEM_CACHE.set(k, { val: obj.val, t: obj.t });
        return obj.val;
      } else {
        try { fs.unlinkSync(fpath); } catch (e) { }
      }
    } catch (e) { /* ignore */ }
  }
  return null;
}
function cacheSet(k, v) {
  MEM_CACHE.set(k, { val: v, t: now() });
  try {
    fs.writeFileSync(path.join(CACHE_DIR, cacheKey(k)), JSON.stringify({ val: v, t: now() }), "utf8");
  } catch (e) { /* ignore */ }
}

// -------------------- Helpers --------------------
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
function normalizeUserInput(v) {
  v = (v || "").trim();
  if (!v) return "https://www.google.com";
  if (/^https?:\/\//i.test(v)) return v;
  if (isLikelySearch(v)) return "https://www.google.com/search?q=" + encodeURIComponent(v);
  return "https://" + v;
}
function buildCookieHeader(cookieMap) {
  const parts = [];
  for (const [k, v] of cookieMap.entries()) parts.push(`${k}=${v}`);
  return parts.join("; ");
}

// safe removal of CSP meta tags
function removeMetaCSP(html) {
  return html.replace(/<meta[^>]*http-equiv\s*=\s*['"]?content-security-policy['"]?[^>]*>/gi, "");
}

// strip integrity and crossorigin (these break proxied assets)
function stripIntegrityAttrs(html) {
  return html.replace(/\s+integrity=(["'])(.*?)\1/gi, "").replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
}

// strip some heavy analytics scripts (best-effort)
function stripKnownAnalytics(html) {
  // remove external script tags referencing analytics/gtag/doubleclick etc.
  return html.replace(/<script[^>]+src=(["'])([^"']*(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^"']*)\1[^>]*><\/script>/gi, "");
}

// rewrite HTML to proxy resources
function rewriteHtmlForProxy(baseUrl, html) {
  if (!html || typeof html !== "string") return html;

  html = removeMetaCSP(html);
  html = stripIntegrityAttrs(html);
  html = stripKnownAnalytics(html);

  // inject base tag for relative resolution
  if (/<head[^>]*>/i.test(html)) {
    html = html.replace(/<head([^>]*)>/i, `<head$1><base href="${baseUrl}">`);
  } else {
    html = `<base href="${baseUrl}">` + html;
  }

  // rewrite anchors to /proxy?url=
  html = html.replace(/(<a\b[^>]*?\bhref=)(["'])([^"'>]+)\2/gi, (m, before, quote, href) => {
    if (!href) return m;
    if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return m;
    if (href.startsWith("/proxy?url=") || href.startsWith("data:")) return m;
    const abs = toAbsolute(href, baseUrl) || href;
    return `${before}${quote}/proxy?url=${encodeURIComponent(abs)}${quote}`;
  });

  // rewrite src/href for assets (images, scripts, styles, sources, videos)
  html = html.replace(/(<\s*(?:img|script|link|source|video|audio|iframe)\b[^>]*?\b(?:src|href)=)(["'])([^"'>]+)\2/gi, (m, before, quote, src) => {
    if (!src) return m;
    if (/^data:/i.test(src)) return m;
    if (src.startsWith("/asset?url=") || src.startsWith("/proxy?url=")) return m;
    const abs = toAbsolute(src, baseUrl) || src;
    return `${before}${quote}/asset?url=${encodeURIComponent(abs)}${quote}`;
  });

  // rewrite srcset
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
  html = html.replace(/url\((['"]?)(?!data:)([^'")]+)\1\)/gi, (m, q, urlVal) => {
    const abs = toAbsolute(urlVal, baseUrl) || urlVal;
    return `url("/asset?url=${encodeURIComponent(abs)}")`;
  });

  return html;
}

// -------------------- /asset endpoint --------------------
// fetches any resource (images/css/js/video) and forwards to client
app.get("/asset", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const target = /^https?:\/\//i.test(raw) ? raw : "https://" + raw;
  const key = target + "::asset";
  const cached = cacheGet(key);
  if (cached) {
    try {
      const obj = typeof cached === "string" ? JSON.parse(cached) : cached;
      if (obj.headers) Object.entries(obj.headers).forEach(([k, v]) => res.setHeader(k, v));
      return res.send(Buffer.from(obj.body, "base64"));
    } catch (e) { /* ignore fallback */ }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    const r = await fetch(target, { signal: controller.signal, redirect: "follow", headers: { "User-Agent": "Euphoria/1.0" } });
    clearTimeout(timeout);

    const buf = Buffer.from(await r.arrayBuffer());
    const ctype = r.headers.get("content-type") || mime.lookup(path.basename(target)) || "application/octet-stream";

    res.setHeader("Content-Type", ctype);
    const cacheControl = r.headers.get("cache-control");
    if (cacheControl) res.setHeader("Cache-Control", cacheControl);

    // small assets cached to disk
    if (buf.length < 100 * 1024) {
      try {
        cacheSet(key, JSON.stringify({ headers: { "Content-Type": ctype }, body: buf.toString("base64") }));
      } catch (e) { }
    }
    return res.send(buf);
  } catch (err) {
    console.error("Asset fetch error:", err && err.message ? err.message : err);
    return res.status(500).send("Asset load failed");
  }
});

// -------------------- /proxy endpoint --------------------
app.get("/proxy", async (req, res) => {
  let raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");

  // manage session cookies
  const session = getSession(req);
  persistSessionCookie(res, session.sid);

  // try decode once (some frontends double-encode)
  try { raw = decodeURIComponent(raw); } catch (e) { /* ignore */ }

  // normalize user input if non-protocol (eg: "google.com" or search)
  if (!/^https?:\/\//i.test(raw)) {
    raw = normalizeUserInput(raw);
  }

  const cacheKeyHtml = raw + "::html";
  const cachedHtml = cacheGet(cacheKeyHtml);
  if (cachedHtml) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    try {
      StringStream.from(cachedHtml).pipe(res);
      return;
    } catch (e) {
      return res.send(cachedHtml);
    }
  }

  try {
    // include session cookies when fetching origin
    const cookieHeader = buildCookieHeader(session.data.cookies);
    const headers = {
      "User-Agent": req.headers["user-agent"] || "Euphoria/1.0",
      "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
    };
    if (cookieHeader) headers["Cookie"] = cookieHeader;
    if (req.headers.referer) headers["Referer"] = req.headers.referer;

    // fetch origin but DO NOT follow redirects automatically — handle 3xx server-side to keep everything proxied
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const originRes = await fetch(raw, { headers, redirect: "manual", signal: controller.signal });
    clearTimeout(timeout);

    // if origin responded 3xx with Location, route through our /proxy
    if (originRes.status >= 300 && originRes.status < 400 && originRes.headers.get("location")) {
      const loc = originRes.headers.get("location");
      const resolved = toAbsolute(loc, raw) || loc;
      // preserve cookies from redirect response
      try {
        const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
        if (setCookies.length) storeSetCookieStrings(setCookies, session.data);
      } catch (e) { /* ignore */ }

      persistSessionCookie(res, session.sid);
      return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    // capture set-cookie from responses (helps auth)
    try {
      const setCookies = originRes.headers.raw ? (originRes.headers.raw()["set-cookie"] || []) : [];
      if (setCookies.length) storeSetCookieStrings(setCookies, session.data);
    } catch (e) { /* ignore */ }

    const contentType = originRes.headers.get("content-type") || "";

    // If not HTML, proxy raw bytes via /asset behavior
    if (!contentType.includes("text/html")) {
      const buf = Buffer.from(await originRes.arrayBuffer());
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      const cacheControl = originRes.headers.get("cache-control");
      if (cacheControl) res.setHeader("Cache-Control", cacheControl);
      persistSessionCookie(res, session.sid);
      return res.send(buf);
    }

    // HTML path: load full text (so we can safely replace and inject)
    let html = await originRes.text();
    const finalUrl = originRes.url || raw;

    // perform safe transforms
    let out = rewriteHtmlForProxy(finalUrl, html);

    // inject topbar & containment script after <body>
    const INJECT = buildInjectionSnippet(); // function below
    if (/<body[^>]*>/i.test(out)) {
      out = out.replace(/<body([^>]*)>/i, (m) => m + INJECT);
    } else {
      out = INJECT + out;
    }

    // cache HTML and respond
    cacheSet(cacheKeyHtml, out);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    persistSessionCookie(res, session.sid);
    try {
      StringStream.from(out).pipe(res);
    } catch (e) {
      res.send(out);
    }

  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : err);
    persistSessionCookie(res, session.sid);
    res.status(500).send(`<div style="padding:1rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

// -------------------- fallback to serve index.html for SPA paths --------------------
app.use((req, res, next) => {
  if (req.method === "GET" && req.accepts("html")) {
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  }
  next();
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));

// -------------------- Helper: injection snippet --------------------
function buildInjectionSnippet() {
  // This snippet injects the modern oval topbar and a containment script that rewrites anchors/forms,
  // patches history API and makes navigation use /proxy?url=... — it runs inside the proxied page.
  // Keep it concise but robust.
  const snip = `
<!-- EUPHORIA INJECTED TOPBAR -->
<div id="euph-topbar" style="position:fixed;left:50%;top:14px;transform:translateX(-50%);width:84%;max-width:1200px;padding:10px 14px;background:rgba(12,14,18,0.82);border-radius:36px;z-index:2147483647;display:flex;gap:8px;align-items:center;backdrop-filter:blur(8px);">
  <button id="euph-back" style="min-width:44px;height:44px;border-radius:12px;border:0;background:rgba(255,255,255,0.06);color:#fff;cursor:pointer">◀</button>
  <button id="euph-forward" style="min-width:44px;height:44px;border-radius:12px;border:0;background:rgba(255,255,255,0.06);color:#fff;cursor:pointer">▶</button>
  <button id="euph-refresh" style="min-width:44px;height:44px;border-radius:12px;border:0;background:rgba(255,255,255,0.06);color:#fff;cursor:pointer">⟳</button>
  <button id="euph-home" style="min-width:44px;height:44px;border-radius:12px;border:0;background:rgba(255,255,255,0.06);color:#fff;cursor:pointer">🏠</button>
  <input id="euph-input" placeholder="Enter URL or search..." style="flex:1;padding:10px 12px;border-radius:12px;border:0;background:rgba(255,255,255,0.02);color:#fff;outline:none" />
  <button id="euph-go" style="min-width:64px;height:44px;border-radius:12px;border:0;background:linear-gradient(90deg,#5ee0ff,#3fb5ff);color:#012;cursor:pointer">Go</button>
  <button id="euph-full" style="min-width:44px;height:44px;border-radius:12px;border:0;background:rgba(255,255,255,0.06);color:#fff;cursor:pointer">⛶</button>
</div>
<style>body{padding-top:76px !important;background:transparent !important}</style>

<script>
(function(){
  try {
    const toProxy = (href) => '/proxy?url=' + encodeURIComponent(href);
    const absolute = (h) => { try { return new URL(h, document.baseURI).href; } catch(e) { return h; } };

    const inp = document.getElementById('euph-input');
    const go = document.getElementById('euph-go');
    const back = document.getElementById('euph-back');
    const forward = document.getElementById('euph-forward');
    const refresh = document.getElementById('euph-refresh');
    const home = document.getElementById('euph-home');
    const full = document.getElementById('euph-full');

    // prefill input from query param url
    try {
      const m = location.search.match(/[?&]url=([^&]+)/);
      if (m) inp.value = decodeURIComponent(m[1]);
    } catch(e){}

    function isLikelySearch(v){
      if(!v) return true;
      if(v.includes(' ')) return true;
      if(/^https?:\\/\\//i.test(v)) return false;
      if(!v.includes('.')) return true;
      return false;
    }
    function normalize(v){
      v=(v||'').trim();
      if(!v) return 'https://www.google.com';
      if(isLikelySearch(v)) return 'https://www.google.com/search?q=' + encodeURIComponent(v);
      if(/^https?:\\/\\//i.test(v)) return v;
      return 'https://' + v;
    }

    go.onclick = function(){
      const v = inp.value;
      if (!v) return;
      if (/\\/proxy\\?url=/i.test(v)) { location.href = v; return; }
      const u = normalize(v);
      location.href = toProxy(u);
    };
    inp.addEventListener('keydown', function(e){ if (e.key === 'Enter') go.onclick(); });

    back.onclick = () => history.back();
    forward.onclick = () => history.forward();
    refresh.onclick = () => location.reload();
    home.onclick = () => location.href = toProxy('https://www.google.com');
    full.onclick = () => { if (!document.fullscreenElement) document.documentElement.requestFullscreen(); else document.exitFullscreen(); };

    // rewrite anchors and forms already in DOM
    function rewriteAnchor(a){
      try{
        const href = a.getAttribute('href');
        if(!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if(href.startsWith('/proxy?url=')) return;
        if(href.startsWith('data:')) return;
        const abs = absolute(href);
        a.setAttribute('href', toProxy(abs));
        a.removeAttribute('target');
      }catch(e){}
    }
    function rewriteAsset(el, attr){
      try{
        const v = el.getAttribute(attr);
        if(!v) return;
        if(/^data:/i.test(v)) return;
        if(v.startsWith('/asset?url=') || v.startsWith('/proxy?url=')) return;
        const abs = absolute(v);
        el.setAttribute(attr, '/asset?url=' + encodeURIComponent(abs));
      }catch(e){}
    }
    function rewriteAll(){
      document.querySelectorAll('a[href]').forEach(rewriteAnchor);
      ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
        document.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
        document.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
      });
      document.querySelectorAll('[srcset]').forEach(el=>{
        try{
          const ss = el.getAttribute('srcset');
          if(!ss) return;
          const parts = ss.split(',').map(p=>{
            const [url, rest] = p.trim().split(/\\s+/,2);
            if(!url) return p;
            if(/^data:/i.test(url)) return p;
            return '/asset?url='+encodeURIComponent(absolute(url)) + (rest ? ' ' + rest : '');
          });
          el.setAttribute('srcset', parts.join(', '));
        }catch(e){}
      });
    }
    rewriteAll();

    // watch for DOM changes
    const mo = new MutationObserver(muts=>{
      for(const mut of muts){
        if(mut.type === 'childList' && mut.addedNodes.length){
          mut.addedNodes.forEach(n=>{
            if(n.nodeType !== 1) return;
            if(n.matches && n.matches('a[href]')) rewriteAnchor(n);
            n.querySelectorAll && n.querySelectorAll('a[href]').forEach(rewriteAnchor);
            ['img','script','link','source','video','audio','iframe'].forEach(tag=>{
              if(n.matches && n.matches(tag + '[src]')) rewriteAsset(n,'src');
              n.querySelectorAll && n.querySelectorAll(tag + '[src]').forEach(el=>rewriteAsset(el,'src'));
              if(n.matches && n.matches(tag + '[href]')) rewriteAsset(n,'href');
              n.querySelectorAll && n.querySelectorAll(tag + '[href]').forEach(el=>rewriteAsset(el,'href'));
            });
            if(n.querySelectorAll && n.querySelectorAll('[srcset]').length){
              n.querySelectorAll('[srcset]').forEach(el=>{
                const ss = el.getAttribute('srcset');
                if(!ss) return;
                const parts = ss.split(',').map(p=>{
                  const [url, rest] = p.trim().split(/\\s+/,2);
                  if(!url) return p;
                  if(/^data:/i.test(url)) return p;
                  return '/asset?url='+encodeURIComponent(absolute(url)) + (rest ? ' ' + rest : '');
                });
                el.setAttribute('srcset', parts.join(', '));
              });
            }
          });
        }
      }
    });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });

    // intercept clicks to keep navigation via /proxy
    document.addEventListener('click', function(e){
      const a = e.target.closest && e.target.closest('a[href]');
      if(!a) return;
      try{
        const href = a.getAttribute('href') || '';
        if(!href) return;
        if(href.startsWith('/proxy?url=') || href.startsWith('/')) return; // local or already proxied
        if(/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        e.preventDefault();
        const abs = absolute(href);
        location.href = toProxy(abs);
      }catch(e){}
    }, true);

    // patch pushState/replaceState to keep SPA navigation proxied
    (function(history){
      const push = history.pushState;
      history.pushState = function(s,t,u){
        try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(absolute(u)); }catch(e){}
        return push.apply(history, arguments);
      };
      const rep = history.replaceState;
      history.replaceState = function(s,t,u){
        try{ if(typeof u === 'string' && u && !u.startsWith('/proxy?url=')) u = toProxy(absolute(u)); }catch(e){}
        return rep.apply(history, arguments);
      };
    })(window.history);

    // override window.open to open in same proxied tab
    (function(){
      try{
        const orig = window.open;
        window.open = function(u, ...rest){
          try{ if(!u) return orig.apply(window, arguments); const abs = absolute(u); location.href = toProxy(abs); return null; }catch(e){ return orig.apply(window, arguments); }
        };
      }catch(e){}
    })();

    // rewrite meta refresh tags
    function rewriteMetaRefresh(){
      document.querySelectorAll('meta[http-equiv]').forEach(m=>{
        try{
          if(m.getAttribute('http-equiv').toLowerCase() !== 'refresh') return;
          const c = m.getAttribute('content') || '';
          const parts = c.split(';');
          if(parts.length < 2) return;
          const urlpart = parts.slice(1).join(';').match(/url=(.*)/i);
          if(!urlpart) return;
          const dest = urlpart[1].replace(/['"]/g,'').trim();
          const abs = absolute(dest);
          m.setAttribute('content', parts[0] + ';url=' + toProxy(abs));
        }catch(e){}
      });
    }
    rewriteMetaRefresh();
    setTimeout(()=>{ rewriteAll(); rewriteMetaRefresh(); }, 500);

  } catch(e) { console.error('Euphoria inject error', e); }
})();
</script>
`;
  return snip;
}

// -------------------- small note: you can adjust cookie rewriting policy here if needed --------------------
// For certain deployments or local HTTP testing, you might want to strip "Secure" or "SameSite" from Set-Cookie strings.
// That is sensitive and may break security; by default we persist cookies as received into the in-memory session store.