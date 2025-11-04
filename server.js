import express from "express";
import fetch from "node-fetch"; // fetch for Node.js
import { DataStream } from "scramjet";

const app = express();

// Serve static files
app.use(express.static("."));

app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("No URL provided");

  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error("Failed to load page");
    const html = await response.text();

    // Stream the HTML using Scramjet
    new DataStream([html])
      .toArray()
      .then(data => res.send(data.join("")));
  } catch (err) {
    res.status(500).send(`<h2 style="color:red;text-align:center;margin-top:50px;">Error loading page:<br>${err.message}</h2>`);
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
