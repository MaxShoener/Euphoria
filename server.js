import express from "express";
import fetch from "node-fetch";
import { pipeline } from "scramjet";
import path from "path";
import { fileURLToPath } from "url";

// Fix __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------
// Serve static frontend
// ---------------------------
app.use(express.static(__dirname));

// ---------------------------
// Scramjet API Example
// ---------------------------
app.get("/api", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: "No URL provided" });

  try {
    const pageContent = await fetch(targetUrl).then(r => r.text());

    const processed = await pipeline(
      pageContent.split("\n"),
      source => source.map(line => line.trim()).filter(line => line.length > 0),
      source => source.toArray()
    );

    res.json({ data: processed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------
// Ultraviolet Proxy
// ---------------------------
import { createBareServer } from "./node_modules/ultraviolet/bare/server/index.js";

const bare = createBareServer("/bare/");
app.use("/bare/", (req, res) => {
  bare.routeRequest(req, res);
});

// ---------------------------
// Start server
// ---------------------------
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`🌐 Ultraviolet proxy available at /bare/`);
  console.log(`⚡ Scramjet API available at /api?url=https://example.com`);
});