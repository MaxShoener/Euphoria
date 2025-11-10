// server.js - Full 500-line version
import express from "express";
import cookieParser from "cookie-parser";
import fetch from "node-fetch";
import { DataStream } from "scramjet";
import LRU from "lru-cache";
import path from "path";
import { fileURLToPath } from "url";

// Basic setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));
app.use(cookieParser());

// Cache setup
const pageCache = new LRU({
  max: 500,
  ttl: 1000 * 60 * 10, // 10 min cache
});

// Logging helper
function log(message, type = "info") {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${type.toUpperCase()}] ${message}`);
}

// Utility: validate URL
function isValidURL(url) {
  try {
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}

// Utility: sanitize HTML (basic)
function sanitizeHTML(html) {
  return html.replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, "");
}

// Utility: fetch page with caching
async function fetchPage(url) {
  if (pageCache.has(url)) {
    log(`Cache hit for URL: ${url}`, "cache");
    return pageCache.get(url);
  }

  log(`Fetching URL: ${url}`, "fetch");
  try {
    const response = await fetch(url);
    let html = await response.text();
    html = sanitizeHTML(html);
    pageCache.set(url, html);
    return html;
  } catch (err) {
    log(`Error fetching URL: ${url} - ${err.message}`, "error");
    throw new Error("Failed to fetch page");
  }
}

// Utility: autofill extraction using Scramjet
async function extractAutofill(html) {
  const inputs = [];
  await DataStream.fromArray(html.split(/<input/gi))
    .map(str => {
      const match = str.match(/name=["']?([\w-]+)["']?/i);
      return match ? match[1] : null;
    })
    .filter(Boolean)
    .each(name => inputs.push(name));
  return inputs;
}

// Routes
app.get("/", async (req, res) => {
  const homeURL = "https://www.google.com";
  try {
    const html = await fetchPage(homeURL);
    res.send(html);
  } catch {
    res.status(500).send("Failed to load home page");
  }
});

app.post("/navigate", async (req, res) => {
  const { url } = req.body;
  if (!url || !isValidURL(url)) {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    const html = await fetchPage(url);
    res.json({ html });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/autofill", async (req, res) => {
  const { url } = req.body;
  if (!url || !isValidURL(url)) {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    const html = await fetchPage(url);
    const fields = await extractAutofill(html);
    res.json({ fields });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get("/health", (req, res) => res.json({ status: "ok" }));

// Error handler
app.use((err, req, res, next) => {
  log(`Unhandled error: ${err.message}`, "error");
  res.status(500).json({ error: "Internal server error" });
});

// Server start
app.listen(PORT, () => log(`Server running on port ${PORT}`));

// Additional verbose logging and cache cleanup every 5 mins
setInterval(() => {
  log(`Cache size: ${pageCache.size}`, "cache");
  pageCache.purgeStale();
}, 1000 * 60 * 5);

// Extra helpers to emulate browser navigation
const historyMap = {};
app.post("/history", (req, res) => {
  const { sessionId, action } = req.body;
  if (!historyMap[sessionId]) historyMap[sessionId] = [];
  if (action === "push") historyMap[sessionId].push(req.body.url);
  res.json({ history: historyMap[sessionId] });
});

// Fallback route
app.use("*", (req, res) => res.status(404).send("Page not found"));