import express from "express";
import fetch from "node-fetch";
import { pipeline } from "scramjet";
import Ultraviolet from "ultraviolet";

const app = express();
const PORT = process.env.PORT || 3000;

// Serve the frontend
app.use(express.static("./"));

// API endpoint
app.get("/api", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: "No URL provided" });

  try {
    // Fetch the page content using Ultraviolet
    const pageContent = await Ultraviolet.fetch(targetUrl).then(r => r.text());

    // Split lines and process with Scramjet
    const processed = await pipeline(
      pageContent.split("\n"),
      source => source.map(line => line.trim()).filter(line => line.length > 0),
      source => source.toArray() // get as array
    );

    res.json({ data: processed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});