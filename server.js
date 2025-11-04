import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";  // ✅ CommonJS default import fix
const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// Simple in-memory cache (auto expires)
const cache = new Map();
const CACHE_TTL = 1000 * 60 * 5; // 5 minutes

function setCache(url, data) {
  cache.set(url, { data, timestamp: Date.now() });
}

function getCache(url) {
  const cached = cache.get(url);
  if (!cached) return null;
  if (Date.now() - cached.timestamp > CACHE_TTL) {
    cache.delete(url);
    return null;
  }
  return cached.data;
}

// Proxy route
app.get("/proxy", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send("Missing URL parameter.");

  const fullUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;

  // Check cache first
  const cached = getCache(fullUrl);
  if (cached) return res.send(cached);

  try {
    const response = await fetch(fullUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (Scramjet Proxy)" },
    });

    // Stream response with scramjet
    const stream = new StringStream();
    response.body.pipe(stream);

    let html = await stream.stringify().join("");

    // Optional content cleaning/tweaks for display consistency
    html = html
      .replace(/<head>/i, `<head><base href="${fullUrl}">`)
      .replace(/integrity=".*?"/g, "") // remove CSP integrity checks
      .replace(/crossorigin=".*?"/g, "");

    setCache(fullUrl, html);
    res.send(html);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Error loading page.");
  }
});

// Serve frontend
app.use(express.static("public"));

app.listen(PORT, () => {
  console.log(`✅ Euphoria proxy running on port ${PORT}`);
});
