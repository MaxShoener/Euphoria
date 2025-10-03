import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Ultraviolet } from "ultraviolet";
import { DataStream } from "scramjet";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Example proxy route using Ultraviolet + Scramjet
app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing url query parameter");

  try {
    // Fetch with Ultraviolet
    const response = await Ultraviolet.fetch(target);
    const buffer = await response.buffer();

    // Stream response via Scramjet
    const stream = new DataStream(buffer);
    stream.toArray().then(data => {
      res.setHeader("Content-Type", response.headers.get("content-type") || "text/plain");
      res.send(Buffer.concat(data));
    });
  } catch (err) {
    res.status(500).send("Proxy error: " + err.message);
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));