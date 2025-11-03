import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import { StringStream } from "scramjet";

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS for all origins
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Proxy GET endpoint for full-page rendering
app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing url parameter");

  try {
    const response = await fetch(url);
    res.status(response.status);
    response.headers.forEach((v, k) => res.setHeader(k, v));

    if (response.body) {
      // Stream HTML content through Scramjet
      StringStream.from(response.body)
        .pipe(res);
    } else {
      res.end();
    }
  } catch (err) {
    console.error("Proxy failed:", err);
    res.status(500).send("Proxy failed: " + err.message);
  }
});
  
// Health check
app.get("/health", (_, res) => res.json({ ok: true, name: "Euphoria", uptime: process.uptime() }));

app.listen(PORT, () => console.log(`🌐 Euphoria proxy running on port ${PORT}`));