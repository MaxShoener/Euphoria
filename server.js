import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS for all origins
app.use(cors());

// Parse JSON bodies
app.use(express.json());

// Serve static frontend
app.use(express.static("public"));

// Proxy endpoint
app.post("/proxy", async (req, res) => {
  try {
    const { url, method = "GET", headers = {}, body = null } = req.body;
    if (!url) return res.status(400).json({ error: "Missing 'url' field" });

    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    // Copy status and headers from remote response
    res.status(response.status);
    response.headers.forEach((value, key) => res.setHeader(key, value));

    // Stream the response directly to the client
    if (response.body) {
      response.body.pipe(res);
    } else {
      res.end();
    }
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).json({ error: "Proxy failed", details: err.message });
  }
});

// Health check
app.get("/health", (_, res) => {
  res.json({ ok: true, name: "Euphoria", uptime: process.uptime() });
});

// Start server
app.listen(PORT, () => console.log(`🌐 Euphoria proxy running on port ${PORT}`));