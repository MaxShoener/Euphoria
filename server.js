// server.js
import express from "express";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import cors from "cors";
import pkg from "scramjet"; // import default, then destructure
const { StringStream } = pkg;

const app = express();
app.use(cors());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const CACHE_DIR = path.resolve("./cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR);

const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes

function cacheKey(url) {
  return Buffer.from(url).toString("base64url");
}
function readDiskCache(url) {
  try {
    const p = path.join(CACHE_DIR, cacheKey(url));
    if (!fs.existsSync(p)) return null;
    const raw = fs.readFileSync(p, "utf8");
    const obj = JSON.parse(raw);
    if (Date.now() - obj.t > CACHE_TTL) {
      fs.unlinkSync(p);
      return null;
    }
    return obj.html;
  } catch (e) { return null; }
}
function writeDiskCache(url, html) {
  try {
    const p = path.join(CACHE_DIR, cacheKey(url));
    fs.writeFileSync(p, JSON.stringify({ t: Date.now(), html }), "utf8");
  } catch (e) { /* ignore */ }
}
function getCached(url) {
  const m = MEM_CACHE.get(url);
  if (m && (Date.now() - m.t) < CACHE_TTL) return m.html;
  const disk = readDiskCache(url);
  if (disk) {
    MEM_CACHE.set(url, { html: disk, t: Date.now() });
    return disk;
  }
  return null;
}
function setCached(url, html) {
  MEM_CACHE.set(url, { html, t: Date.now() });
  writeDiskCache(url, html);
}

// Helper to ensure absolute urls
function toAbsolute(url, base) {
  try { return new URL(url, base).href; } catch { return null; }
}

// Proxy endpoint
app.get("/proxy", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const target = raw.startsWith("http") ? raw : `https://${raw}`;

  // Check cache
  const cached = getCached(target);
  if (cached) {
    res.setHeader("content-type", "text/html; charset=utf-8");
    return res.send(cached);
  }

  try {
    // Fetch from origin (no redirect following - handle manually)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(target, {
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": "Euphoria-Scramjet-Proxy/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    });

    clearTimeout(timeout);

    // If redirect, resolve and redirect through proxy
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const loc = response.headers.get("location");
      const resolved = toAbsolute(loc, target);
      if (resolved) return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    const ctype = response.headers.get("content-type") || "";
    res.setHeader("content-type", ctype);

    if (!ctype.includes("text/html")) {
      // Binary asset — pipe directly and optionally cache small ones
      const buffer = Buffer.from(await response.arrayBuffer());
      if (buffer.length < 1024 * 100) setCached(target, buffer);
      return res.send(buffer);
    }

    // HTML: get full string (so .replace works)
    let html = await response.text();

    // Remove problematic CSP meta tags that would block resources
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");

    // Remove integrity/crossorigin attrs which would block proxied assets
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // Inject a <base> to help relative URL resolution
    html = html.replace(/<head([^>]*)>/i, (m, g) => {
      return `<head${g}><base href="${target}">`;
    });

    // Rewrite href/src/srcset to proxy through /proxy?url=...
    html = html.replace(/(href|src|srcset)=["']([^"']*)["']/gi, (m, attr, val) => {
      if (!val) return m;
      if (/^(javascript:|data:|#)/i.test(val)) return m;
      if (val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, target);
      if (!abs) return m;
      return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    // Rewrite CSS url(...) to proxy
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
      if (!val || /^data:/i.test(val)) return m;
      const abs = toAbsolute(val, target);
      if (!abs) return m;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Optional: for performance, strip <noscript> and heavy analytics scripts (best-effort)
    // (We **do not** remove all <script> tags — removing all breaks many pages.)
    // Instead, remove known trackers to reduce noise:
    html = html.replace(/<script[^>]*src=["'][^"']*(analytics|gtag|googlesyndication|doubleclick)[^"']*["'][^>]*><\/script>/gi, "");

    // Inject some stabilization CSS so pages layout properly inside injected container
    html = html.replace(/<head([^>]*)>/i, (m,g) => {
      return `<head${g}><style>img,video{max-width:100%;height:auto;}body{margin:0;background:transparent;}</style>`;
    });

    // Save to cache
    setCached(target, html);

    // Stream to client progressively using scramjet StringStream
    StringStream.from(html).pipe(res);
  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : String(err));
    res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

app.listen(PORT, () => console.log(`Euphoria Scramjet proxy listening on ${PORT}`));
