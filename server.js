import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.static("public"));

const PORT = process.env.PORT || 8080;

// 🧠 Simple in-memory cache with TTL
const cache = new Map();
const CACHE_TTL = 60 * 1000; // 1 minute

function getCached(url) {
  const entry = cache.get(url);
  if (!entry) return null;
  const { data, time } = entry;
  if (Date.now() - time > CACHE_TTL) {
    cache.delete(url);
    return null;
  }
  return data;
}

function setCached(url, data) {
  cache.set(url, { data, time: Date.now() });
}

// 🌐 Proxy endpoint using Scramjet-like approach
app.get("/proxy", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send("Missing url parameter.");

  try {
    // ✅ Check cache
    const cached = getCached(targetUrl);
    if (cached) {
      console.log("Cache hit:", targetUrl);
      return res.send(cached);
    }

    console.log("Fetching:", targetUrl);
    const response = await fetch(targetUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
      },
    });

    let html = await response.text();

    // ✅ Fix CSP and relative pathing issues
    html = html
      .replace(/<head>/i, `<head><base href="${targetUrl}">`)
      .replace(/content-security-policy/gi, "x-content-security-policy")
      .replace(/integrity=/gi, "data-integrity=");

    // ✅ Cache the result
    setCached(targetUrl, html);

    res.send(html);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Error loading page.");
  }
});

app.listen(PORT, () => console.log(`🚀 Proxy running on port ${PORT}`));
