import express from "express";
import fetch from "node-fetch";
import { pipeline } from "scramjet";
import path from "path";
import { fileURLToPath } from "url";

// Fix __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import UV server files
import * as uv from "./node_modules/ultraviolet/index.js";

const app = express();
const PORT = process.env.PORT || 3000;

// Serve frontend
app.use(express.static("./"));

// API endpoint
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

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});