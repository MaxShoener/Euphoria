// Core imports
import express from "express";
import fetch from "node-fetch";
import compression from "compression";
import path from "path";
import fs from "fs";
import https from "https";
import http from "http";
import { fileURLToPath } from "url";

// Setup dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Universal agent
const httpAgent = new http.Agent({ keepAlive: true });
const httpsAgent = new https.Agent({
    keepAlive: true,
    rejectUnauthorized: false // required for Xbox/Google TLS quirks
}););

// ---------------- CONFIG ----------------
const DEPLOYMENT_ORIGIN = process.env.DEPLOYMENT_ORIGIN || "https://useful-karil-maxshoener-6cb890d9.koyeb.app";
const PORT = parseInt(process.env.PORT || "3000", 10);
const CACHE_DIR = path.join(__dirname, "cache");
const ENABLE_DISK_CACHE = true;
const CACHE_TTL = 1000 * 60 * 6; // 6 minutes
const ASSET_CACHE_MAX = 256 * 1024; // 256 KB
const HTML_CACHE_MAX = 512 * 1024; // 512 KB
const FETCH_TIMEOUT = 30000;
const SESSION_NAME = "euphoria_sid";
const USER_AGENT_FALLBACK = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36";

// Create cache directory
if (ENABLE_DISK_CACHE) fsPromises.mkdir(CACHE_DIR, { recursive: true }).catch(() => {});

// Asset file endings (binary)
const ASSET_EXTENSIONS = [".wasm", ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico", ".ttf", ".woff", ".woff2", ".eot", ".mp4", ".webm", ".mp3", ".json", ".map"];
const SPECIAL_FILES = ["service-worker.js", "sw.js", "worker.js", "manifest.json"];

// Headers to drop (CSP / blocking)
const DROP_HEADERS = new Set([
  "content-security-policy",
  "x-frame-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "permissions-policy"
]);

// ---------------- EXPRESS SETUP ----------------
const app = express();
app.use(cors());
app.use(morgan("tiny"));
app.use(compression({ threshold: 1024 }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"), { index: false }));

// ---------------- SIMPLE CACHE ----------------
const MEM_CACHE = new Map();
function now() { return Date.now(); }
function cacheKey(s) { return Buffer.from(s).toString("base64url"); }
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
        try { fs.unlinkSync(fname); } catch (e) { /* ignore */ }
      }
    } catch (e) { /* ignore */ }
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

// ---------------- SESSION / COOKIES ----------------
const SESSIONS = new Map();
function makeSid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }
function createSession() { const sid = makeSid(); const payload = { cookies: new Map(), last: now(), ua: USER_AGENT_FALLBACK }; SESSIONS.set(sid, payload); return { sid, payload }; }
function parseCookieHeader(h = "") {
  const out = {};
  h.split(";").forEach(p => {
    const [k, v] = (p || "").split("=").map(s => (s || "").trim());
    if (k && v) out[k] = v;
  });
  return out;
}
function getSessionFromReq(req) {
  const parsed = parseCookieHeader(req.headers.cookie || "");
  let sid = parsed[SESSION_NAME] || req.headers["x-euphoria-session"];
  if (!sid || !SESSIONS.has(sid)) return createSession();
  const payload = SESSIONS.get(sid);
  payload.last = now();
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
      const parsed = setCookieParser.parse(sc);
      parsed.forEach(p => {
        if (p.name && p.value) sessionPayload.cookies.set(p.name, p.value);
      });
    } catch (e) { /* ignore */ }
  }
}
function buildCookieHeader(map) {
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

// cleanup old sessions occasionally
setInterval(() => {
  const cutoff = now() - (1000 * 60 * 60 * 24); // 24h TTL for this demo
  for (const [k, v] of SESSIONS.entries()) if (v.last < cutoff) SESSIONS.delete(k);
}, 1000 * 60 * 30);

// ---------------- UTIL FUNCTIONS ----------------
function toAbsolute(href, base) {
  try { return new URL(href, base).href; } catch (e) { return null; }
}
function isAlreadyProxiedHref(href) {
  if (!href) return false;
  try {
    if (href.includes('/proxy?url=')) return true;
    const resolved = new URL(href, DEPLOYMENT_ORIGIN);
    if (resolved.origin === (new URL(DEPLOYMENT_ORIGIN)).origin && resolved.pathname.startsWith("/proxy")) return true;
  } catch (e) { /* ignore */ }
  return false;
}
function proxyizeAbsoluteUrl(absUrl) {
  try { const u = new URL(absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u.href)}`; } catch (e) { try { const u2 = new URL("https://" + absUrl); return `${DEPLOYMENT_ORIGIN}/proxy?url=${encodeURIComponent(u2.href)}`; } catch (e2) { return absUrl; } }
}
function looksLikeAssetPath(urlStr) {
  if (!urlStr) return false;
  try {
    const p = new URL(urlStr, DEPLOYMENT_ORIGIN).pathname.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (p.endsWith(ext)) return true;
    for (const seg of SPECIAL_FILES) if (p.endsWith(seg)) return true;
    return false;
  } catch (e) {
    const low = urlStr.toLowerCase();
    for (const ext of ASSET_EXTENSIONS) if (low.endsWith(ext)) return true;
    for (const seg of SPECIAL_FILES) if (low.endsWith(seg)) return true;
    return false;
  }
}
function sanitizeHtml(html) {
  try {
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\s+integrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\s+crossorigin=(["'])(.*?)\1/gi, "");
  } catch (e) { /* ignore */ }
  return html;
}

// ---------------- CLIENT SANDBOX SNIPPET ----------------
function clientSandboxSnippet() {
  return `
<!-- EUPHORIA-SANDBOX -->
<script id="__EUPHORIA_SANDBOX">
(function(){
  const DEPLOY = "${DEPLOYMENT_ORIGIN}";
  function prox(u){ try{ if(!u) return u; if(u.includes('/proxy?url=')) return u; if(/^data:/i.test(u)) return u; return DEPLOY + '/proxy?url=' + encodeURIComponent(new URL(u, document.baseURI).href); }catch(e){return u;} }
  // fetch wrapper
  const origFetch = window.fetch.bind(window);
  window.fetch = function(resource, init){
    try{
      if(typeof resource === 'string' && !resource.includes('/proxy?url=') && !/^data:/i.test(resource)) resource = prox(resource);
      else if(resource instanceof Request && !resource.url.includes('/proxy?url=')) resource = new Request(prox(resource.url), resource);
    }catch(e){}
    return origFetch(resource, init);
  };
  // XHR wrapper
  try {
    const OrigXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function(){
      const xhr = new OrigXHR();
      const open = xhr.open;
      xhr.open = function(method, url, ...rest){
        try { if(url && !url.includes('/proxy?url=') && !/^(data:|blob:|about:|javascript:)/i.test(url)) url = prox(url); } catch(e){}
        return open.call(this, method, url, ...rest);
      };
      return xhr;
    };
  } catch(e){}
  // window.open
  try {
    const origOpen = window.open.bind(window);
    window.open = function(url,name,specs){
      try{ if(url && !url.includes('/proxy?url=') && !/^(data:|javascript:)/i.test(url)) url = prox(url); }catch(e){}
      return origOpen(url,name,specs);
    };
  } catch(e){}
  // rewrite anchors & assets dynamically
  (function(){
    function rewriteAnchor(a){ try{ const h=a.getAttribute('href'); if(!h) return; if(/^(javascript:|mailto:|tel:|#)/i.test(h)) return; if(h.includes('/proxy?url=')) return; a.setAttribute('href', prox(h)); a.removeAttribute('target'); }catch(e){} }
    function rewriteAsset(el){ try{ ['src','href','poster','data-src','data-href'].forEach(attr=>{ if(el.hasAttribute && el.hasAttribute(attr)){ const v=el.getAttribute(attr); if(!v) return; if(/^data:/i.test(v) || v.includes('/proxy?url=')) return; el.setAttribute(attr, prox(v)); } }); if(el.hasAttribute && el.hasAttribute('srcset')){ const ss = el.getAttribute('srcset')||''; const parts = ss.split(',').map(p=>{ const [u,rest]=p.trim().split(/\\s+/,2); if(!u) return p; if(/^data:/i.test(u) || u.includes('/proxy?url=')) return p; return prox(u) + (rest ? ' ' + rest : ''); }); el.setAttribute('srcset', parts.join(', ')); } }catch(e){} }
    const mo = new MutationObserver(muts=>{ muts.forEach(m=>{ m.addedNodes.forEach(n=>{ if(n.nodeType !== 1) return; if(n.matches && n.matches('a[href]')) rewriteAnchor(n); n.querySelectorAll && n.querySelectorAll('a[href]').forEach(rewriteAnchor); ['img','script','link','source','video','audio','iframe'].forEach(tag=>{ if(n.matches && n.matches(tag+'[src]')) rewriteAsset(n); n.querySelectorAll && n.querySelectorAll(tag+'[src]').forEach(rewriteAsset); if(n.matches && n.matches(tag+'[href]')) rewriteAsset(n); n.querySelectorAll && n.querySelectorAll(tag+'[href]').forEach(rewriteAsset); }); n.querySelectorAll && n.querySelectorAll('[srcset]').forEach(el=>rewriteAsset(el)); }); }); });
    mo.observe(document.documentElement || document, { childList:true, subtree:true });
    document.querySelectorAll('a[href]').forEach(rewriteAnchor);
    document.querySelectorAll('img,script,link,source,video,audio,iframe').forEach(rewriteAsset);
  })();
})();
</script>
<!-- END EUPHORIA-SANDBOX -->
`;
}

// ---------------- HTTP + WS PROXY SETUP ----------------
const server = http.createServer(app);

const wsProxy = createProxyServer({ ws: true, secure: false, xfwd: true });
wsProxy.on("error", (err, req, res) => {
  try { if (res && !res.headersSent) res.writeHead(502); if (res && res.end) res.end("WS proxy error"); } catch (e) { /* ignore */ }
});
server.on('upgrade', (req, socket, head) => {
  try {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    if (urlObj.pathname === '/_wsproxy') {
      const target = urlObj.searchParams.get('url');
      if (!target) { socket.destroy(); return; }
      wsProxy.ws(req, socket, head, { target });
    }
  } catch (e) { socket.destroy(); }
});

// telemetry WS for client (optional)
const wss = new WebSocketServer({ server, path: "/_euph_ws" });
wss.on("connection", ws => {
  ws.send(JSON.stringify({ msg: "welcome", ts: Date.now(), host: os.hostname() }));
  ws.on("message", m => {
    try { const d = JSON.parse(m.toString()); if (d && d.cmd === 'ping') ws.send(JSON.stringify({ msg: 'pong', ts: Date.now() })); } catch (e) { }
  });
});

// ---------------- AUTO-PROXY MIDDLEWARE (allow /host.tld style) ----------------
app.use((req, res, next) => {
  const segments = req.path.split('/').filter(Boolean);
  if (segments.length === 1 && /^[\w\.-]+\.[a-z]{2,}$/i.test(segments[0]) && req.method === 'GET') {
    const host = segments[0];
    req.url = '/proxy?url=' + encodeURIComponent('https://' + host) + (req.url.includes('?') ? '&' + req.url.split('?')[1] : '');
  }
  next();
});

// ---------------- CAPTCHA HELPER ROUTE ----------------
// This route fetches the target URL and if it detects a CAPTCHA/verification page
// it returns the page to the user (so human can solve it). Solved cookies are stored in session.
app.get("/__euph_captcha", async (req, res) => {
  const tgt = req.query.target;
  if (!tgt) return res.status(400).send("missing target");
  let raw = tgt;
  try { raw = decodeURIComponent(tgt); } catch (e) { }
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;

  const session = getSessionFromReq(req);
  setSessionCookieHeader(res, session.sid);

  // fetch raw page
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
    const upstream = await fetch(raw, { headers: { 'User-Agent': session.payload.ua }, signal: controller.signal });
    clearTimeout(timeout);

    const ct = (upstream.headers.get('content-type') || '').toLowerCase();

    // persist any cookies set by captcha provider
    const setCookies = upstream.headers.raw ? (upstream.headers.raw()['set-cookie'] || []) : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);

    if (ct.includes('text/html')) {
      let html = await upstream.text();
      html = sanitizeHtml(html);
      // inject our small helper to post cookies back to euphoria afterwards
      const $ = cheerio.load(html, { decodeEntities: false });
      $('head').append(`<meta name="euph-captcha" content="1">`);
      // append small script to notify after form submit (best-effort)
      $('body').append(`<script>
        (function(){
          try {
            // after successful solve, try to post cookies back via fetch
            setTimeout(()=>{ fetch('/__euph_captcha_done?target=${encodeURIComponent(raw)}', { method:'POST', credentials:'include' }).catch(()=>{}); }, 3000);
          } catch(e){}
        })();
      </script>`);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.send($.html());
    } else {
      const buffer = await upstream.arrayBuffer();
      res.setHeader("Content-Type", ct || "application/octet-stream");
      return res.send(Buffer.from(buffer));
    }
  } catch (err) {
    return res.status(502).send("Failed to fetch captcha target: " + String(err));
  }
});

// When user solved captcha in the UI, this route can be called to confirm cookies
app.post("/__euph_captcha_done", express.json(), (req, res) => {
  const session = getSessionFromReq(req);
  setSessionCookieHeader(res, session.sid);
  // developer can extend to fetch cookies from browser and store them here
  // for this simple helper we just mark session as captcha-solved
  session.payload.captcha_solved = true;
  return res.json({ ok: true });
});

// ---------------- MAIN /proxy HANDLER ----------------
app.get("/proxy", async (req, res) => {
  // support /proxy?url=... and /proxy/<encoded>
  let raw = req.query.url || (req.path && req.path.startsWith("/proxy/") ? decodeURIComponent(req.path.replace(/^\/proxy\//, "")) : null);
  if (!raw) return res.status(400).send("Missing url (use /proxy?url=https://example.com)");
  try { raw = decodeURIComponent(raw); } catch (e) { /* ignore */ }
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;

  const session = getSessionFromReq(req);
  try { setSessionCookieHeader(res, session.sid); } catch (e) { /* ignore */ }

  // quick asset cache for non-HTML Accepts
  const accept = (req.headers.accept || "").toLowerCase();
  const wantHtml = accept.includes("text/html") || req.query.force_html === '1' || req.headers['x-euphoria-client'] === 'c-autoproxy';
  const assetKey = raw + "::asset";
  const htmlKey = raw + "::html";

  if (!wantHtml) {
    const cached = cacheGet(assetKey);
    if (cached) {
      if (cached.headers) Object.entries(cached.headers).forEach(([k, v]) => res.setHeader(k, v));
      return res.send(Buffer.from(cached.body, "base64"));
    }
  } else {
    const cachedHtml = cacheGet(htmlKey);
    if (cachedHtml) { res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.send(cachedHtml); }
  }

  // build upstream headers
  const originHeaders = {
    "User-Agent": session.payload.ua || (req.headers['user-agent'] || USER_AGENT_FALLBACK),
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers['accept-language'] || "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br"
  };
  const cookieHdr = buildCookieHeader(session.payload.cookies);
  if (cookieHdr) originHeaders["Cookie"] = cookieHdr;
  if (req.headers.referer) originHeaders["Referer"] = req.headers.referer;

  // fetch upstream with manual redirect handling (so we can rewrite Location header to our proxy)
  let upstream;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

    // Use retry for flaky networks/abrupt closes (some large CDNs time out occasionally)
    upstream = await pRetry(() => fetch(raw, { method: "GET", headers: originHeaders, redirect: "manual", signal: controller.signal }), { retries: 1 });

    clearTimeout(timeout);
  } catch (err) {
    console.error("fetch error", err && err.message ? err.message : err);
    return res.status(502).send("Euphoria: failed to fetch target: " + String(err));
  }

  // record Set-Cookie headers
  try {
    const setCookies = upstream.headers.raw ? (upstream.headers.raw()['set-cookie'] || []) : [];
    if (setCookies.length) storeSetCookieToSession(setCookies, session.payload);
  } catch (e) { /* ignore */ }

  // handle redirects from upstream: rewrite Location header to point back to our /proxy?url=
  const status = upstream.status || 200;
  if ([301, 302, 303, 307, 308].includes(status)) {
    const loc = upstream.headers.get("location");
    if (loc) {
      const abs = toAbsolute(loc, raw) || loc;
      const prox = proxyizeAbsoluteUrl(abs);
      try { res.setHeader("Location", prox); setSessionCookieHeader(res, session.sid); } catch (e) { /* ignore */ }
      return res.status(status).send(`Redirecting to ${prox}`);
    }
  }

  // examine content-type
  const contentType = (upstream.headers.get("content-type") || "").toLowerCase();
  const isHtml = contentType.includes("text/html");
  const treatAsAsset = !isHtml;

  // ASSET path: stream binary data and cache small assets
  if (treatAsAsset) {
    try { upstream.headers.forEach((v, k) => { if (!DROP_HEADERS.has(k.toLowerCase())) try { res.setHeader(k, v); } catch (e) { } }); } catch (e) { }
    try { setSessionCookieHeader(res, session.sid); } catch (e) { }

    try {
      const buf = Buffer.from(await upstream.arrayBuffer());
      if (buf.length < ASSET_CACHE_MAX) {
        try { cacheSet(assetKey, { headers: Object.fromEntries(upstream.headers.entries()), body: buf.toString("base64") }); } catch (e) { /* ignore */ }
      }
      res.setHeader("Content-Type", contentType || "application/octet-stream");
      if (upstream.headers.get("cache-control")) res.setHeader("Cache-Control", upstream.headers.get("cache-control"));
      return res.send(buf);
    } catch (err) {
      // fallback streaming if arrayBuffer fails
      try { upstream.body.pipe(res); return; } catch (e) { return res.status(502).send("Euphoria: asset stream failed"); }
    }
  }

  // HTML transform path
  let html;
  try { html = await upstream.text(); } catch (e) { return res.status(502).send("Euphoria: failed to read HTML"); }
  html = sanitizeHtml(html);

  // Cheerios-based rewriting (robust)
  try {
    const $ = cheerio.load(html, { decodeEntities: false });

    // add <base> so relative links work
    if ($('base').length === 0) {
      const baseHref = upstream.url || raw;
      $('head').prepend(`<base href="${baseHref}">`);
    }

    // remove CSP meta tags
    $('meta[http-equiv]').each((i, el) => {
      try { if ((($(el).attr('http-equiv') || '').toLowerCase()) === 'content-security-policy') $(el).remove(); } catch (e) { }
    });

    // remove integrity/crossorigin attributes
    $('[integrity]').each((i, el) => $(el).removeAttr('integrity'));
    $('[crossorigin]').each((i, el) => $(el).removeAttr('crossorigin'));

    // rewrite anchor hrefs
    $('a[href]').each((i, el) => {
      try {
        const href = $(el).attr('href') || '';
        if (!href) return;
        if (/^(javascript:|mailto:|tel:|#)/i.test(href)) return;
        if (isAlreadyProxiedHref(href)) return;
        const abs = toAbsolute(href, upstream.url || raw) || href;
        $(el).attr('href', proxyizeAbsoluteUrl(abs));
        $(el).removeAttr('target');
      } catch (e) { /* ignore */ }
    });

    // rewrite forms
    $('form[action]').each((i, el) => {
      try {
        const act = $(el).attr('action') || '';
        if (!act) return;
        if (isAlreadyProxiedHref(act)) return;
        const abs = toAbsolute(act, upstream.url || raw) || act;
        $(el).attr('action', proxyizeAbsoluteUrl(abs));
      } catch (e) { /* ignore */ }
    });

    // rewrite assets (src/href) for common tags
    ['img','script','link','source','video','audio','iframe'].forEach(tag => {
      $(tag + '[src]').each((i, el) => {
        try {
          const val = $(el).attr('src') || '';
          if (!val) return;
          if (/^data:/i.test(val)) return;
          if (isAlreadyProxiedHref(val)) return;
          const abs = toAbsolute(val, upstream.url || raw) || val;
          $(el).attr('src', proxyizeAbsoluteUrl(abs));
          $(el).removeAttr('integrity'); $(el).removeAttr('crossorigin');
        } catch (e) {}
      });
      $(tag + '[href]').each((i, el) => {
        try {
          const val = $(el).attr('href') || '';
          if (!val) return;
          if (/^data:/i.test(val)) return;
          if (isAlreadyProxiedHref(val)) return;
          const abs = toAbsolute(val, upstream.url || raw) || val;
          $(el).attr('href', proxyizeAbsoluteUrl(abs));
          $(el).removeAttr('integrity'); $(el).removeAttr('crossorigin');
        } catch (e) {}
      });
    });

    // rewrite srcset
    $('[srcset]').each((i, el) => {
      try {
        const ss = $(el).attr('srcset') || '';
        const parts = ss.split(',').map(p => {
          const [u, rest] = p.trim().split(/\s+/, 2);
          if (!u) return p;
          if (/^data:/i.test(u)) return p;
          if (isAlreadyProxiedHref(u)) return p;
          const abs = toAbsolute(u, upstream.url || raw) || u;
          return proxyizeAbsoluteUrl(abs) + (rest ? ' ' + rest : '');
        });
        $(el).attr('srcset', parts.join(', '));
      } catch (e) { }
    });

    // rewrite CSS url(...) in <style> tags
    $('style').each((i, el) => {
      try {
        let txt = $(el).html() || '';
        txt = txt.replace(/url\\((['"]?)(.*?)\\1\\)/gi, (m, q, p) => {
          if (!p) return m;
          if (/^data:/i.test(p)) return m;
          if (isAlreadyProxiedHref(p)) return m;
          const abs = toAbsolute(p, upstream.url || raw) || p;
          return 'url("' + proxyizeAbsoluteUrl(abs) + '")';
        });
        $(el).text(txt);
      } catch (e) { /* ignore */ }
    });

    // inline style attribute rewrite
    $('[style]').each((i, el) => {
      try {
        let s = $(el).attr('style') || '';
        s = s.replace(/url\\((['"]?)(.*?)\\1\\)/gi, (m, q, u) => {
          if (!u) return m;
          if (/^data:/i.test(u)) return m;
          if (isAlreadyProxiedHref(u)) return m;
          const abs = toAbsolute(u, upstream.url || raw) || u;
          return 'url("' + proxyizeAbsoluteUrl(abs) + '")';
        });
        $(el).attr('style', s);
      } catch (e) { /* ignore */ }
    });

    // meta refresh rewrite
    $('meta[http-equiv]').each((i, el) => {
      try {
        const eq = (($(el).attr('http-equiv') || '').toLowerCase());
        if (eq !== 'refresh') return;
        const c = $(el).attr('content') || '';
        const parts = c.split(';');
        if (parts.length < 2) return;
        const urlPart = parts.slice(1).join(';').match(/url=(.*)/i);
        if (!urlPart) return;
        const dest = urlPart[1].replace(/['"]/g, '').trim();
        const abs = toAbsolute(dest, upstream.url || raw) || dest;
        $(el).attr('content', parts[0] + ';url=' + proxyizeAbsoluteUrl(abs));
      } catch (e) { /* ignore */ }
    });

    // best-effort remove known analytics/tracker scripts
    $('script[src]').each((i, el) => {
      try {
        const s = ($(el).attr('src') || '').toLowerCase();
        if (/googletagmanager|googlesyndication|doubleclick|analytics|gtag|ga.js|collect|adsbygoogle/i.test(s)) $(el).remove();
      } catch (e) {}
    });

    // inject client sandbox snippet before end of body
    $('body').append(clientSandboxSnippet());

    html = $.html();
    if (html && html.length < HTML_CACHE_MAX) cacheSet(htmlKey, html);
  } catch (e) {
    console.warn("cheerio transform failed", e && e.message ? e.message : e);
  }

  // forward safe headers from upstream (except DROP_HEADERS)
  try { upstream.headers.forEach((v, k) => { if (!DROP_HEADERS.has(k.toLowerCase())) try { res.setHeader(k, v); } catch (e) { } }); } catch (e) { }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  try { setSessionCookieHeader(res, session.sid); } catch (e) { }
  return res.send(html);
});

// ---------------- FALLBACK / SPA SERVE ----------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("*", (req, res, next) => {
  if (req.method === "GET" && req.headers.accept && req.headers.accept.includes("text/html")) return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

// ---------------- ERROR HANDLERS ----------------
process.on("unhandledRejection", err => console.error("unhandledRejection", err));
process.on("uncaughtException", err => console.error("uncaughtException", err));

// ---------------- START ----------------
server.listen(PORT, () => console.log(`Euphoria v3 starting on port ${PORT}. DEPLOYMENT_ORIGIN=${DEPLOYMENT_ORIGIN}`));