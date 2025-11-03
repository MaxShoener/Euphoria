import express from "express";
import { Stream } from "@scramjet/core";
import fetch from "node-fetch";

const app = express();
const PORT = process.env.PORT || 3000;

// Serve your static frontend (index.html, etc.)
app.use(express.static("public"));

// --- Simple Scramjet-powered proxy endpoint ---
app.use(express.json());

app.post("/proxy", async (req, res) => {
  try {
    const { url, method = "GET", headers = {}, body = null } = req.body;

    if (!url) {
      return res.status(400).json({ error: "Missing 'url' field" });
    }

    // Fetch remote resource
    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    // Stream through Scramjet for flexibility
    const readable = Stream.from(response.body);
    let result = "";

    await readable.each(chunk => {
      result += chunk.toString();
    });

    res.set("Content-Type", response.headers.get("content-type") || "text/plain");
    res.status(response.status).send(result);
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).json({ error: "Proxy failed", details: err.message });
  }
});

// Health check endpoint (useful for Koyeb)
app.get("/health", (_, res) => {
  res.json({ ok: true, name: "Euphoria", uptime: process.uptime() });
});

app.listen(PORT, () => {
  console.log(`🌐 Euphoria proxy running on port ${PORT}`);
});