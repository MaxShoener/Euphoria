import express from "express";
import { WebSocketServer } from "ws";
import http from "http";
import { DataStream } from "scramjet";
import fetch from "node-fetch";
import cors from "cors";
import LRUCache from "lru-cache";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const cache = new LRUCache({ max: 500, ttl: 1000 * 60 * 5 });

// Basic proxy endpoint
app.post("/api/fetch", async (req, res) => {
  try {
    const { url, method = "GET", headers = {}, body } = req.body;

    const cacheKey = `${method}:${url}`;
    if (cache.has(cacheKey)) {
      return res.json(cache.get(cacheKey));
    }

    const response = await fetch(url, {
      method,
      headers,
      body: method !== "GET" && body ? JSON.stringify(body) : undefined,
    });

    const contentType = response.headers.get("content-type");
    const isJSON = contentType && contentType.includes("application/json");
    const data = isJSON ? await response.json() : await response.text();

    cache.set(cacheKey, data);
    res.json({ success: true, data });
  } catch (error) {
    console.error("Proxy error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create HTTP server
const server = http.createServer(app);

// 🧩 Wisp-compatible WebSocket server
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  if (req.url === "/wisp") {
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  } else {
    socket.destroy();
  }
});

wss.on("connection", (ws) => {
  console.log("Wisp client connected");

  const stream = new DataStream();

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

  ws.on("close", () => {
    console.log("Wisp client disconnected");
    stream.end();
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () =>
  console.log(`✅ Wisp proxy server running on port ${PORT}`)
);