import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createBareServer } from "ultraviolet/bare";
import scramjet from "scramjet";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve frontend (UI)
app.use(express.static(path.join(__dirname, "public")));

// Mode switch (default: UV)
let proxyMode = process.env.PROXY_MODE || "uv";

// Ultraviolet setup
let bareServer = createBareServer("/bare/");

// Scramjet setup (mock example)
function scramjetProxy(req, res) {
  res.send("Scramjet proxy is running (example placeholder)");
}

// Switch endpoint
app.get("/switch/:mode", (req, res) => {
  const { mode } = req.params;
  if (mode !== "uv" && mode !== "scramjet") {
    return res.status(400).send("Invalid mode");
  }
  proxyMode = mode;
  res.send(`Proxy mode switched to ${mode}`);
});

// Proxy route
app.use("/proxy", (req, res, next) => {
  if (proxyMode === "uv") {
    return bareServer.handleRequest(req, res);
  } else if (proxyMode === "scramjet") {
    return scramjetProxy(req, res);
  }
  next();
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});