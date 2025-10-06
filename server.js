import express from "express";
import { createBareServer } from "ultraviolet/bare.js";
import { Scramjet } from "scramjet";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = createServer();

// Serve static frontend (index.html, css, etc.)
app.use(express.static(path.join(__dirname, "public")));

// Basic route for health checks or debugging
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Euphoria backend running" });
});

// Create Ultraviolet bare server
const bare = createBareServer({ server });

// Integrate Scramjet as a proxy handler
app.use("/scramjet", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing ?url parameter");

  try {
    const stream = await Scramjet.fetch(target);
    res.setHeader("Content-Type", "text/html");
    stream.pipe(res);
  } catch (err) {
    res.status(500).send("Scramjet proxy error: " + err.message);
  }
});

// Attach Express app to HTTP server
server.on("request", app);

// Handle Ultraviolet upgrade requests (for WebSocket, etc.)
server.on("upgrade", (req, socket, head) => {
  bare.handleUpgrade(req, socket, head);
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`✅ Euphoria backend running on port ${PORT}`);
});