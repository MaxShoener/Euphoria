import express from "express";
import path from "path";
import { fileURLToPath } from "url";

// Import Ultraviolet Bare Server
import { createBareServer } from "ultraviolet/bare-server-node";
import http from "http";

// Import Scramjet (basic stream proxy example)
import { StringStream } from "scramjet";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 3000;

// Serve frontend
app.use(express.static(__dirname));

// Create Ultraviolet bare server
const bare = createBareServer("/bare/");

// Route: Proxy using Ultraviolet
app.get("/proxy/uv", (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing url parameter");
  res.redirect(`/bare/${encodeURIComponent(target)}`);
});

// Route: Proxy using Scramjet (basic passthrough)
app.get("/proxy/scramjet", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing url parameter");

  try {
    const response = await fetch(target);
    const body = await response.text();

    // Simple Scramjet stream
    await StringStream.from(body)
      .map(str => str.replace(/Euphoria/gi, "Euphoria Proxy")) // Example transform
      .pipe(res);
  } catch (err) {
    res.status(500).send("Scramjet proxy error: " + err.message);
  }
});

// Create HTTP server that handles both Express + Bare
const server = http.createServer((req, res) => {
  if (bare.shouldRoute(req)) {
    bare.routeRequest(req, res);
  } else {
    app(req, res);
  }
});

// WebSocket upgrade support for Bare
server.on("upgrade", (req, socket, head) => {
  if (bare.shouldRoute(req)) {
    bare.routeUpgrade(req, socket, head);
  } else {
    socket.destroy();
  }
});

server.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});