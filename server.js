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
function getCached(url) {
  const m = MEM_CACHE.get(url);
  if (m && Date.now() - m.t < CACHE_TTL) return m.html;
  const f = path.join(CACHE_DIR, cacheKey(url));
  if (fs.existsSync(f)) {
    const { html, t } = JSON.parse(fs.readFileSync(f, "utf8"));
    if (Date.now() - t < CACHE_TTL) {
      MEM_CACHE.set(url, { html, t });
      return html;
    }
  }
  return null;
}
function setCached(url, html) {
  MEM_CACHE.set(url, { html, t: Date.now() });
  fs.writeFileSync(path.join(CACHE_DIR, cacheKey(url)), JSON.stringify({ html, t: Date.now() }), "utf8");
}

function toAbs(u, base) {
  try { return new URL(u, base).href; } catch { return null; }
}

app.get("/proxy", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const target = raw.startsWith("http") ? raw : `https://${raw}`;

  const cached = getCached(target);
  if (cached) return res.type("html").send(cached);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const r = await fetch(target, {
      signal: controller.signal,
      redirect: "manual",
      headers: {
        "User-Agent": "Euphoria-Scramjet-Proxy/1.0",
        "Accept": "text/html,application/xhtml+xml"
      }
    });
    clearTimeout(timeout);

    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      const loc = toAbs(r.headers.get("location"), target);
      if (loc) return res.redirect(`/proxy?url=${encodeURIComponent(loc)}`);
    }

    const type = r.headers.get("content-type") || "";
    res.set("content-type", type);

    if (!type.includes("text/html")) {
      const buf = Buffer.from(await r.arrayBuffer());
      if (buf.length < 100_000) setCached(target, buf.toString("base64"));
      return res.send(buf);
    }

    let html = await r.text();
    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");
    html = html.replace(/<head([^>]*)>/i, (m,g)=>`<head${g}><base href="${target}">`);
    html = html.replace(/(href|src|srcset)=["']([^"']+)["']/gi,(m,a,v)=>{
      if (/^(data:|javascript:|#)/i.test(v)) return m;
      const abs = toAbs(v, target);
      if (!abs) return m;
      return `${a}="/proxy?url=${encodeURIComponent(abs)}"`;
    });
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi,(m,q,v)=>{
      if (/^data:/i.test(v)) return m;
      const abs = toAbs(v,target);
      return abs?`url("/proxy?url=${encodeURIComponent(abs)}")`:m;
    });
    html = html.replace(/<script[^>]*src=["'][^"']*(analytics|googletag|doubleclick)[^"']*["'][^>]*><\/script>/gi,"");
    html = html.replace(/<head([^>]*)>/i,(m,g)=>`<head${g}><style>
      body{margin:0;background:#0d0d0d;color:#eee;font-family:system-ui;}
      img,video,iframe{max-width:100%;height:auto;}
    </style>`);

    setCached(target, html);
    StringStream.from(html).pipe(res);
  } catch (e) {
    console.error("Proxy error:", e.message);
    res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;">Proxy error: ${e.message}</div>`);
  }
});

app.listen(PORT, () => console.log("✅ Proxy running on port", PORT));
