import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createBareServer } from "ultraviolet/bare.js";
import { createServer as createHttpServer } from "http";
import * as scramjet from "scramjet";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Serve frontend
app.use(express.static(path.join(__dirname, "public")));

// Proxy mode management
let currentProxy = "uv";

app.get("/api/proxy-mode", (req, res) => {
  res.json({ current: currentProxy });
});

app.post("/api/proxy-mode/:mode", (req, res) => {
  const { mode } = req.params;
  if (mode === "uv" || mode === "scramjet") {
    currentProxy = mode;
    res.json({ success: true, mode });
  } else {
    res.status(400).json({ success: false, message: "Invalid proxy mode" });
  }
});

// UV Bare Server
const bare = createBareServer("/bare/");

// Create HTTP server that uses Express + UV
const server = createHttpServer((req, res) => {
  if (bare.shouldRoute(req)) {
    bare.routeRequest(req, res);
  } else {
    app(req, res);
  }
});

// Start
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 Current proxy: ${currentProxy}`);
});