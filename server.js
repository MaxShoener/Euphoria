import express from "express";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import cors from "cors";
import pkg from "scramjet";
const { StringStream } = pkg;

const app = express();
app.use(cors());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const CACHE_DIR = path.resolve("./cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR);

const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 10;

function cacheKey(url) {
  return Buffer.from(url).toString("base64url");
}
function readDiskCache(url) {
  try {
    const p = path.join(CACHE_DIR, cacheKey(url));
    if (!fs.existsSync(p)) return null;
    const obj = JSON.parse(fs.readFileSync(p, "utf8"));
    if (Date.now() - obj.t > CACHE_TTL) {
      fs.unlinkSync(p);
      return null;
    }
    return obj.html;
  } catch { return null; }
}
function writeDiskCache(url, html) {
  try { fs.writeFileSync(path.join(CACHE_DIR, cacheKey(url)), JSON.stringify({ t: Date.now(), html }), "utf8"); }
  catch {}
}
function getCached(url) {
  const mem = MEM_CACHE.get(url);
  if (mem && Date.now() - mem.t < CACHE_TTL) return mem.html;
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

function toAbsolute(url, base) {
  try { return new URL(url, base).href; } catch { return null; }
}

app.get("/proxy", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const target = raw.startsWith("http") ? raw : `https://${raw}`;

  const cached = getCached(target);
  if (cached) {
    res.setHeader("content-type", "text/html; charset=utf-8");
    return res.send(cached);
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(target, {
      redirect: "manual",
      signal: controller.signal,
      headers: { "User-Agent": "Euphoria-Scramjet-Proxy/1.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" }
    });

    clearTimeout(timeout);

    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const loc = response.headers.get("location");
      const resolved = toAbsolute(loc, target);
      if (resolved) return res.redirect(`/proxy?url=${encodeURIComponent(resolved)}`);
    }

    const ctype = response.headers.get("content-type") || "";
    res.setHeader("content-type", ctype);

    if (!ctype.includes("text/html")) {
      const buffer = Buffer.from(await response.arrayBuffer());
      if (buffer.length < 1024*100) setCached(target, buffer);
      return res.send(buffer);
    }

    let html = await response.text();

    // Remove CSP/meta/integrity/crossorigin
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");

    // Inject <base>
    html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><base href="${target}">`);

    // Rewrite href/src/srcset to proxy
    html = html.replace(/(href|src|srcset)=["']([^"']*)["']/gi, (m, attr, val) => {
      if (!val || /^(javascript:|data:|#)/i.test(val) || val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, target);
      if (!abs) return m;
      return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
    });

    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
      if (!val || /^data:/i.test(val)) return m;
      const abs = toAbsolute(val, target);
      if (!abs) return m;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    // Inject CSS for images/videos
    html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><style>img,video{max-width:100%;height:auto;}body{margin:0;background:transparent;}</style>`);

    setCached(target, html);
    StringStream.from(html).pipe(res);

  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : String(err));
    res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

app.listen(PORT, () => console.log(`Euphoria Scramjet proxy listening on ${PORT}`));
