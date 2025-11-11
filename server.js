import express from "express";
import http from "http";
import cors from "cors";
import { WebSocketServer } from "ws";
import { DataStream } from "scramjet";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import LRUCache from "lru-cache";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/* ------------------- INITIALIZATION ------------------- */
const app = express();
const server = http.createServer(app);
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* ------------------- CONFIG ------------------- */
const PORT = process.env.PORT || 3000;
const ANALYTICS_FILE = path.join(__dirname, "cache", "analytics.json");
const cache = new LRUCache({ max: 500, ttl: 1000 * 60 * 5 });

if (!fs.existsSync(path.dirname(ANALYTICS_FILE))) fs.mkdirSync(path.dirname(ANALYTICS_FILE), { recursive: true });
if (!fs.existsSync(ANALYTICS_FILE)) fs.writeFileSync(ANALYTICS_FILE, JSON.stringify({ requests: 0, errors: 0, totalTime: 0 }));

/* ------------------- HELPERS ------------------- */
function logAnalytics(success, ms) {
  const data = JSON.parse(fs.readFileSync(ANALYTICS_FILE, "utf8"));
  data.requests += 1;
  if (!success) data.errors += 1;
  data.totalTime += ms;
  fs.writeFileSync(ANALYTICS_FILE, JSON.stringify(data, null, 2));
}

function summarizeAnalytics() {
  const data = JSON.parse(fs.readFileSync(ANALYTICS_FILE, "utf8"));
  const avgTime = data.requests > 0 ? (data.totalTime / data.requests).toFixed(2) : 0;
  return { ...data, avgTime };
}

/* ------------------- HTTP PROXY ------------------- */
app.post("/api/fetch", async (req, res) => {
  const { url, method = "GET", headers = {}, body } = req.body;
  const cacheKey = `${method}:${url}`;
  const start = Date.now();

  try {
    if (cache.has(cacheKey)) {
      logAnalytics(true, Date.now() - start);
      return res.json({ cached: true, data: cache.get(cacheKey) });
    }

    const response = await fetch(url, {
      method,
      headers,
      body: method !== "GET" && body ? JSON.stringify(body) : undefined,
    });

    const contentType = response.headers.get("content-type");
    const data = contentType && contentType.includes("application/json")
      ? await response.json()
      : await response.text();

    cache.set(cacheKey, data);
    logAnalytics(true, Date.now() - start);
    res.json({ success: true, data });
  } catch (error) {
    console.error("Proxy error:", error);
    logAnalytics(false, Date.now() - start);
    res.status(500).json({ success: false, error: error.message });
  }
});

/* ------------------- STREAM ENDPOINT (Scramjet) ------------------- */
app.post("/api/stream", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "No URL provided" });

    const response = await fetch(url);
    const textStream = await response.text();

    const stream = DataStream.fromArray(textStream.split("\n"));
    res.setHeader("Content-Type", "text/plain");

    await stream
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .each(async (line) => res.write(line + "\n"))
      .run();

    res.end();
  } catch (error) {
    console.error("Stream error:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ------------------- ANALYTICS ------------------- */
app.get("/api/analytics", (req, res) => {
  res.json(summarizeAnalytics());
});

/* ------------------- WISP WEBSOCKET ------------------- */
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  if (req.url === "/wisp") {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
  } else {
    socket.destroy();
  }
});

wss.on("connection", (ws) => {
  console.log("🌀 Wisp client connected");

  ws.on("message", async (msg) => {
    try {
      const { url, method = "GET", headers = {}, body } = JSON.parse(msg);

      const response = await fetch(url, {
        method,
        headers,
        body: method !== "GET" && body ? JSON.stringify(body) : undefined,
      });

      const text = await response.text();
      ws.send(JSON.stringify({ url, data: text }));
    } catch (err) {
      ws.send(JSON.stringify({ error: err.message }));
    }
  });

  ws.on("close", () => console.log("❌ Wisp client disconnected"));
});

/* ------------------- FALLBACK ------------------- */
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* ------------------- START ------------------- */
server.listen(PORT, () => {
  console.log(`✅ Wisp Proxy Server running on port ${PORT}`);
});