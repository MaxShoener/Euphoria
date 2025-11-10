// =======================================================
// EUPHORIA WEB CORE SERVER
// Modern Node.js 20+ full proxy engine with Scramjet
// =======================================================

// --- Module Imports ------------------------------------
import express from "express";
import fetch from "node-fetch";
import { LRUCache } from "lru-cache";
import compression from "compression";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import { DataStream } from "scramjet";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import os from "os";

// --- Path Helpers --------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Express App Setup ---------------------------------
const app = express();
const PORT = process.env.PORT || 8080;

// --- Middleware Stack ----------------------------------
app.use(compression());
app.use(cors({ origin: "*", methods: "GET,POST,PUT,DELETE,OPTIONS" }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan("dev"));

// --- Cache Layer (Fast in-memory + auto-expiry) --------
const cache = new LRUCache({
  max: 500, // maximum number of cached URLs
  ttl: 1000 * 60 * 5, // 5 minutes
});

const CACHE_HIT_HEADER = "x-euphoria-cache-hit";

// --- Utility Functions ---------------------------------

/**
 * Normalize URL input
 * - adds https:// prefix if missing
 * - prevents malformed addresses
 */
function normalizeURL(url) {
  if (!url) return null;
  try {
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;
    const parsed = new URL(url);
    return parsed.href;
  } catch (err) {
    return null;
  }
}

/**
 * Stream a proxied fetch response through Scramjet
 * for intelligent streaming and optional modification
 */
async function streamThroughScramjet(originalRes, targetRes) {
  const contentType = originalRes.headers.get("content-type") || "";
  targetRes.set("content-type", contentType);
  const reader = DataStream.from(originalRes.body);

  if (contentType.includes("text") || contentType.includes("json")) {
    await reader
      .map(async chunk => {
        let text = chunk.toString();
        // Optionally modify HTML or script responses here
        text = text.replace(/EUPHORIA_DEBUG/g, "");
        return text;
      })
      .catch(err => {
        console.error("Stream error:", err);
      })
      .pipe(targetRes);
  } else {
    await reader.pipe(targetRes);
  }
}

/**
 * Cache wrapper for GET requests
 */
async function cachedFetch(url, options = {}) {
  const cached = cache.get(url);
  if (cached) {
    return new Response(cached.body, {
      headers: cached.headers,
      status: cached.status,
    });
  }

  const res = await fetch(url, options);
  const buf = Buffer.from(await res.arrayBuffer());
  cache.set(url, {
    body: buf,
    headers: Object.fromEntries(res.headers.entries()),
    status: res.status,
  });

  return new Response(buf, {
    headers: res.headers,
    status: res.status,
  });
}

/**
 * Smart search redirect
 * - Recognizes plain text searches and URLs
 */
function resolveSearchOrURL(input) {
  if (!input) return "https://www.google.com";
  const looksLikeURL = /^[\w.-]+\.[a-z]{2,}$/i.test(input);
  if (looksLikeURL) return normalizeURL(input);
  const encoded = encodeURIComponent(input);
  return `https://www.google.com/search?q=${encoded}`;
}

// --- Static File Hosting -------------------------------
const publicDir = path.join(__dirname, "public");
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir);
app.use(express.static(publicDir));

// --- Base Routes ---------------------------------------

app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), memory: process.memoryUsage() });
});

app.get("/api/cache/stats", (req, res) => {
  res.json({
    keys: cache.size,
    max: cache.max,
    hits: cache.hits,
    misses: cache.misses,
  });
});

// --- Proxy Route ---------------------------------------

/**
 * GET /proxy
 * ?url=...
 * or ?q=search term
 */
app.get("/proxy", async (req, res) => {
  const input = req.query.url || req.query.q;
  const targetURL = resolveSearchOrURL(input);
  const normalized = normalizeURL(targetURL);
  if (!normalized) return res.status(400).send("Invalid URL");

  console.log(`[Proxy] → ${normalized}`);

  try {
    const cacheEntry = cache.get(normalized);
    if (cacheEntry) {
      res.set(CACHE_HIT_HEADER, "1");
      res.writeHead(cacheEntry.status, cacheEntry.headers);
      res.end(cacheEntry.body);
      return;
    }

    const response = await cachedFetch(normalized);
    res.set("x-proxied-url", normalized);
    await streamThroughScramjet(response, res);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Proxy fetch failed: " + err.message);
  }
});

// --- POST Proxy (for form data forwarding) -------------
app.post("/proxy", async (req, res) => {
  const target = normalizeURL(req.body.url);
  if (!target) return res.status(400).json({ error: "Invalid target URL" });

  try {
    const fetchRes = await fetch(target, {
      method: "POST",
      headers: req.body.headers || {},
      body: req.body.data ? JSON.stringify(req.body.data) : undefined,
    });
    await streamThroughScramjet(fetchRes, res);
  } catch (err) {
    console.error("POST proxy failed:", err);
    res.status(500).json({ error: "POST proxy failed" });
  }
});

// --- Address Auto-fill API -----------------------------

/**
 * Auto-complete addresses via Google Suggest API mimic
 * (No iframe, uses Scramjet and caching)
 */
app.get("/api/autofill", async (req, res) => {
  const query = req.query.q;
  if (!query) return res.status(400).json({ error: "Missing query" });

  const endpoint = `https://suggestqueries.google.com/complete/search?client=firefox&q=${encodeURIComponent(
    query
  )}`;

  try {
    const cached = cache.get(endpoint);
    if (cached) {
      res.set(CACHE_HIT_HEADER, "1");
      return res.json(JSON.parse(cached.body.toString()));
    }

    const response = await fetch(endpoint);
    const text = await response.text();
    const json = JSON.parse(text);
    cache.set(endpoint, { body: Buffer.from(text) });
    res.json(json);
  } catch (err) {
    res.status(500).json({ error: "Autofill failed", details: err.message });
  }
});

// --- Admin Cache Control -------------------------------
app.delete("/api/cache/clear", (req, res) => {
  cache.clear();
  res.json({ cleared: true });
});

// --- Error Handlers ------------------------------------
app.use((req, res) => {
  res.status(404).send("Euphoria: Page not found.");
});

app.use((err, req, res, next) => {
  console.error("Fatal error:", err);
  res.status(500).send("Internal server error");
});

// --- Start Server --------------------------------------
app.listen(PORT, () => {
  console.log(`⚡ Euphoria proxy running on port ${PORT}`);
  console.log(`🌐 Access via http://localhost:${PORT}`);
});