import express from "express";
import fetch from "node-fetch";
import cookieParser from "cookie-parser";
import { DataStream } from "scramjet";
import LRU from "lru-cache";
import { WebSocketServer } from "ws";
import { createServer } from "http";

const app = express();
const server = createServer(app);
const port = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.static("public"));

const cache = new LRU({ max: 50, ttl: 1000 * 60 * 5 });

function rewriteLinks(html, baseUrl) {
  return html.replace(/(href|src)=["']([^"'#]+)["']/gi, (match, attr, url) => {
    try {
      const fullUrl = new URL(url, baseUrl).toString();
      return `${attr}="/proxy?url=${encodeURIComponent(fullUrl)}"`;
    } catch {
      return match;
    }
  });
}

app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing url parameter");
  if (cache.has(url)) return res.send(cache.get(url));

  try {
    const response = await fetch(url, { redirect: "follow" });
    let html = await response.text();

    const processed = await new DataStream(html)
      .map(line => rewriteLinks(line, url))
      .reduce("", (acc, val) => acc + val);

    cache.set(url, processed);
    res.send(processed);
  } catch (err) {
    res.status(500).send(`Error fetching: ${err.message}`);
  }
});

// --- 🌀 WISP SERVER ENDPOINT ---
const wss = new WebSocketServer({ server, path: "/wisp/" });

wss.on("connection", (ws) => {
  console.log("WISP client connected");

  ws.on("message", async (msg) => {
    try {
      const data = JSON.parse(msg);
      const { url, method = "GET", headers = {}, body = null } = data;

      const res = await fetch(url, { method, headers, body });
      const text = await res.text();

      const rewritten = await new DataStream(text)
        .map(line => rewriteLinks(line, url))
        .reduce("", (acc, val) => acc + val);

      ws.send(JSON.stringify({
        status: res.status,
        headers: Object.fromEntries(res.headers),
        body: rewritten
      }));
    } catch (err) {
      ws.send(JSON.stringify({ error: err.message }));
    }
  });

  ws.on("close", () => console.log("WISP client disconnected"));
});

server.listen(port, () => console.log(`WISP proxy running on port ${port}`));