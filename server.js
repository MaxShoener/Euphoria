import express from "express";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Basic cache to speed up repeated fetches
const cache = new Map();
const CACHE_TTL = 1000 * 60 * 5; // 5 min

function setCache(key, value) {
  cache.set(key, { value, time: Date.now() });
}
function getCache(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.time > CACHE_TTL) {
    cache.delete(key);
    return null;
  }
  return entry.value;
}

// Intercept /proxy requests and fetch target pages
app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target || !/^https?:\/\//i.test(target)) {
    return res.status(400).send("Invalid or missing URL.");
  }

  const cached = getCache(target);
  if (cached) {
    return res.status(200).send(cached);
  }

  try {
    const response = await fetch(target, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/119.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9"
      }
    });

    const text = await response.text();
    const proxied = text
      .replace(/(src|href)="\/(?!\/)/g, `$1="${target}/`)
      .replace(/integrity=".*?"/g, ""); // remove SRI blocks that break proxied loads

    setCache(target, proxied);
    res.status(200).send(proxied);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Error loading page: " + err.message);
  }
});

// Fallback route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`✅ Scramjet proxy running at http://localhost:${PORT}`);
});
