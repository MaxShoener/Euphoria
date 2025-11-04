// server.js
import express from "express";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import cors from "cors";
import pkg from "scramjet";
const { StringStream } = pkg;
import cookie from "cookie";

const app = express(); // <-- ensure app is defined
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

// In-memory session store for cookies
const SESSIONS = new Map();
function getSession(req) {
  let sid = req.headers["x-euphoria-session"];
  if (!sid) sid = Math.random().toString(36).slice(2);
  if (!SESSIONS.has(sid)) SESSIONS.set(sid, { cookies: new Map() });
  return { sid, data: SESSIONS.get(sid) };
}

// Proxy endpoint
app.get("/proxy", async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).send("Missing url");
  const target = raw.startsWith("http") ? raw : `https://${raw}`;

  const session = getSession(req);
  res.setHeader("x-euphoria-session", session.sid);

  const cached = getCached(target);
  if (cached) {
    res.setHeader("content-type", "text/html; charset=utf-8");
    return res.send(cached);
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    let cookieHeader = "";
    for (const [name, val] of session.data.cookies.entries()) {
      cookieHeader += `${name}=${val}; `;
    }

    const response = await fetch(target, {
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": req.headers["user-agent"] || "Euphoria-Scramjet-Proxy/1.0",
        "Accept": req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Cookie": cookieHeader
      }
    });

    clearTimeout(timeout);

    // Capture Set-Cookie headers
    const setCookies = response.headers.raw()["set-cookie"] || [];
    setCookies.forEach(sc => {
      const parsed = cookie.parse(sc);
      for (const key in parsed) session.data.cookies.set(key, parsed[key]);
    });

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

    html = html.replace(/<meta[^>]*http-equiv=["']?content-security-policy["']?[^>]*>/gi, "");
    html = html.replace(/\sintegrity=(["'])(.*?)\1/gi, "");
    html = html.replace(/\scrossorigin=(["'])(.*?)\1/gi, "");
    html = html.replace(/<head([^>]*)>/i, (m,g) => `<head${g}><base href="${target}"><style>img,video{max-width:100%;height:auto;}body{margin:0;background:#111;color:#fff;}</style>`);

    html = html.replace(/(href|src|srcset)=["']([^"']*)["']/gi, (m, attr, val) => {
      if (!val || /^(javascript:|data:|#)/i.test(val) || val.startsWith("/proxy?url=")) return m;
      const abs = toAbsolute(val, target);
      if (!abs) return m;
      return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
    });
    html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m,q,val) => {
      if (!val || /^data:/i.test(val)) return m;
      const abs = toAbsolute(val, target);
      if (!abs) return m;
      return `url("/proxy?url=${encodeURIComponent(abs)}")`;
    });

    setCached(target, html);
    StringStream.from(html).pipe(res);

  } catch (err) {
    console.error("Proxy error:", err && err.message ? err.message : String(err));
    res.status(500).send(`<div style="padding:2rem;color:#fff;background:#111;font-family:system-ui;">Proxy error: ${(err && err.message) || String(err)}</div>`);
  }
});

app.listen(PORT, () => console.log(`Euphoria Scramjet proxy listening on ${PORT}`));
