import express from "express";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import pkg from "scramjet"; // ✅ CommonJS default import fix
const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// --- Cache Setup ---
const CACHE_DIR = "./cache";
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR);

function getCachePath(url) {
  return path.join(CACHE_DIR, Buffer.from(url).toString("base64"));
}

function setCache(url, data) {
  const file = getCachePath(url);
  fs.writeFileSync(file, JSON.stringify({ data, timestamp: Date.now() }));
}

function getCache(url) {
  const file = getCachePath(url);
  if (!fs.existsSync(file)) return null;
  const content = JSON.parse(fs.readFileSync(file, "utf-8"));
  if (Date.now() - content.timestamp > CACHE_TTL) {
    fs.unlinkSync(file);
    return null;
  }
  return content.data;
}

// --- Proxy Route ---
app.get("/proxy", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send("Missing URL parameter.");

  const fullUrl = targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`;
  const cached = getCache(fullUrl);
  if (cached) return res.send(cached);

  try {
    const response = await fetch(fullUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (Euphoria Proxy)" },
    });

    const stream = new StringStream();
    response.body.pipe(stream);
    let html = await stream.stringify().join("");

    html = html
      .replace(/<head>/i, `<head><base href="${fullUrl}">`)
      .replace(/integrity=".*?"/g, "")
      .replace(/crossorigin=".*?"/g, "");

    setCache(fullUrl, html);
    res.send(html);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send(`
      <div style="font-family:Segoe UI;background:#111;color:#eee;padding:2rem;text-align:center">
        <h2>Error loading page</h2>
        <p>${err.message}</p>
      </div>
    `);
  }
});

// --- Serve Frontend ---
app.use(express.static("public"));

app.listen(PORT, () => {
  console.log(`🚀 Euphoria proxy running on port ${PORT}`);
});
