import express from "express";
import Scramjet from "scramjet"; // CommonJS module
import fetch from "node-fetch";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

app.post("/proxy", async (req, res) => {
  try {
    const { url, method = "GET", headers = {}, body = null } = req.body;
    if (!url) return res.status(400).json({ error: "Missing 'url' field' });

    const response = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });

    // Use StringStream for text responses
    const readable = Scramjet.StringStream.from(response.body);
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

app.get("/health", (_, res) => res.json({ ok: true, name: "Euphoria", uptime: process.uptime() }));

app.listen(PORT, () => console.log(`🌐 Euphoria proxy running on port ${PORT}`));