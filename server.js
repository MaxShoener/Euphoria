import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import { StringStream } from "scramjet";

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Lightweight cache ----
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes
const cache = new Map();
function getCache(url) {
  const entry = cache.get(url);
  if (entry && Date.now() - entry.time < CACHE_TTL) return entry.data;
  cache.delete(url);
  return null;
}
function setCache(url, data) {
  cache.set(url, { data, time: Date.now() });
  // Auto-cleanup every 5 mins
  if (cache.size > 200) {
    for (const [key, v] of cache.entries()) {
      if (Date.now() - v.time > CACHE_TTL) cache.delete(key);
    }
  }
}

// ---- Middleware ----
app.use(cors());
app.use(express.static("public"));

// ---- Proxy endpoint ----
app.get("/proxy", async (req, res) => {
  const targetURL = req.query.url;
  if (!targetURL) return res.status(400).send("Missing url parameter");

  // Try cache first
  const cached = getCache(targetURL);
  if (cached) return StringStream.from(cached).pipe(res);

  try {
    const response = await fetch(targetURL, {
      redirect: "manual",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const redirectURL = new URL(response.headers.get("location"), targetURL).href;
      return res.redirect(`/proxy?url=${encodeURIComponent(redirectURL)}`);
    }

    const contentType = response.headers.get("content-type") || "";
    res.set("content-type", contentType);

    if (contentType.includes("text/html")) {
      let html = await response.text();

      // Remove heavy scripts for safety/speed
      html = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "");

      // Re-link absolute resources through proxy
      html = html.replace(/(href|src|srcset)=["'](.*?)["']/gi, (m, attr, val) => {
        if (!val || val.startsWith("javascript:") || val.startsWith("/proxy?url=")) return m;
        try {
          const abs = new URL(val, targetURL).href;
          return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
        } catch {
          return m;
        }
      });

      html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, val) => {
        if (!val || val.startsWith("data:")) return m;
        try {
          const abs = new URL(val, targetURL).href;
          return `url("/proxy?url=${encodeURIComponent(abs)}")`;
        } catch {
          return m;
        }
      });

      // Inject viewport + CSS reset to stabilize layout
      html = html.replace(
        /<head([^>]*)>/i,
        `<head$1><meta name="viewport" content="width=device-width,initial-scale=1.0">
         <style>
         html,body{margin:0;padding:0;font-family:system-ui,sans-serif;}
         img,video,iframe{max-width:100%;height:auto;}
         *{box-sizing:border-box;}
         </style>`
      );

      // Cache the cleaned version
      setCache(targetURL, html);

      res.set(
        "Content-Security-Policy",
        "default-src * 'unsafe-inline' data: blob:;"
      );
      StringStream.from(html).pipe(res);
    } else {
      const buffer = await response.arrayBuffer();
      setCache(targetURL, Buffer.from(buffer));
      res.send(Buffer.from(buffer));
    }
  } catch (err) {
    console.error("Proxy error:", err.message);
    res.status(500).send(`<pre style="color:red;">Proxy error: ${err.message}</pre>`);
  }
});

app.listen(PORT, () => console.log(`🚀 Euphoria running on port ${PORT}`));
