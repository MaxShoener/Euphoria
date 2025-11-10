// server.js
import express from "express";
import cookieParser from "cookie-parser";
import pkg from "scramjet";
const { DataStream } = pkg;
import { LRUCache } from "lru-cache";
import fetch from "node-fetch";

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));

// Simple LRU cache
const cache = new LRUCache({
  max: 500, // max 500 items
  ttl: 1000 * 60 * 5 // 5 minutes TTL
});

// Example route with caching
app.get("/api/data", async (req, res) => {
  const cacheKey = "data";

  if (cache.has(cacheKey)) {
    return res.json({ source: "cache", data: cache.get(cacheKey) });
  }

  try {
    // Example fetch, replace with your actual data source
    const response = await fetch("https://jsonplaceholder.typicode.com/todos/1");
    const data = await response.json();

    cache.set(cacheKey, data);
    res.json({ source: "fetch", data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch data" });
  }
});

// Example DataStream usage
app.get("/api/stream", async (req, res) => {
  const items = [1, 2, 3, 4, 5];

  DataStream.from(items)
    .map(x => x * 2)
    .reduce((acc, val) => acc + val, 0)
    .then(result => res.json({ result }))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Default route
app.get("/", (req, res) => {
  res.sendFile(`${process.cwd()}/public/index.html`);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});