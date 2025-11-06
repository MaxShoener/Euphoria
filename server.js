import express from "express";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import cors from "cors";
import compression from "compression";
import pkg from "scramjet";
const { StringStream } = pkg;

const app = express();
app.use(cors());
app.use(compression());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const CACHE_DIR = path.resolve("./cache");
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR);

const MEM_CACHE = new Map();
const CACHE_TTL = 1000 * 60 * 10; // 10 min

function cacheKey(url) {
  return Buffer.from(url).toString("base64url");
}
function readDiskCache(url) {
  const p = path.join(CACHE_DIR, cacheKey(url));
  if (!fs.existsSync(p)) return null;
  const obj = JSON.parse(fs.readFileSync(p, "utf8"));
  if (Date.now() - obj.t > CACHE_TTL) {
    fs.unlinkSync(p);
    return null;
  }
  return obj.html;
}
function writeDiskCache(url, html) {
  fs.writeFileSync(path.join(CACHE_DIR, cacheKey(url)), JSON.stringify({ t: Date.now(), html }), "utf8");
}
function getCached(url) {
  const m = MEM_CACHE.get(url);
  if (m && Date.now() - m.t < CACHE_TTL) return m.html;
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
  if (cached) return res.type("html").send(cached);

  try {
    const response = await fetch(target, {
      redirect: "manual",
      headers: {
        "User-Agent": "Euphoria-Scramjet/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    });

    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const loc = toAbsolute(response.headers.get("location"), target);
      return res.redirect(`/proxy?url=${encodeURIComponent(loc)}`);
    }

    const ctype = response.headers.get("content-type") || "";
    if (!ctype.includes("text/html")) {
      const buf = Buffer.from(await response.arrayBuffer());
      return res.type(ctype).send(buf);
    }

    let html = await response.text();

    html = html.replace(/<meta[^>]*content-security-policy[^>]*>/gi, "");
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");
    html = html.replace(/<head([^>]*)>/i, (m, g) => `<head${g}><base href="${target}">`);

    html = html.replace(/(href|src|srcset)=["']([^"']+)["']/gi, (m, a, v) => {
      if (/^(data:|javascript:|#)/i.test(v)) return m;
      const abs = toAbsolute(v, target);
      return abs ? `${a}="/proxy?url=${encodeURIComponent(abs)}"` : m;
    });

    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, v) => {
      if (/^data:/i.test(v)) return m;
      const abs = toAbsolute(v, target);
      return abs ? `url("/proxy?url=${encodeURIComponent(abs)}")` : m;
    });

    html = html.replace(/<script[^>]*src=["'][^"']*(analytics|doubleclick)[^"']*["'][^>]*><\/script>/gi, "");
    html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><style>img,video{max-width:100%;height:auto;}body{margin:0;}</style>`);

    setCached(target, html);
    StringStream.from(html).pipe(res);
  } catch (err) {
    res.status(500).send(`<div style="font-family:sans-serif;color:#fff;background:#000;padding:2rem;">Error: ${err.message}</div>`);
  }
});

app.listen(PORT, () => console.log(`✅ Euphoria Scramjet proxy running on ${PORT}`));