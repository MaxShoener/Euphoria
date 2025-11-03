import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import pkg from "scramjet";
const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Main proxy route
app.get("/proxy", async (req, res) => {
  let url = req.query.url;
  if (!url) return res.status(400).send("Missing url");

  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  try {
    const response = await fetch(url);
    res.status(response.status);

    const contentType = response.headers.get("content-type") || "";
    res.setHeader("content-type", contentType);

    if (contentType.includes("text/html") && response.body) {
      let html = await response.text();

      // Rewrite all links, scripts, forms, images to go through proxy
      html = html.replace(/(href|src|action)=["'](?!https?:\/\/|\/\/)([^"']+)["']/gi, (m, attr, path) => {
        const absolute = new URL(path, url).href;
        return `${attr}="/proxy?url=${encodeURIComponent(absolute)}"`;
      });

      // Rewrite absolute HTTP URLs to go through proxy
      html = html.replace(/(href|src|action)=["'](https?:\/\/[^"']+)["']/gi, (m, attr, path) => {
        return `${attr}="/proxy?url=${encodeURIComponent(path)}"`;
      });

      res.send(html);
    } else if (response.body) {
      // Stream CSS, JS, images directly
      StringStream.from(response.body).pipe(res);
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

app.listen(PORT, () => console.log(`🌐 Euphoria running on port ${PORT}`));