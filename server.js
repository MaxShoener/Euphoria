import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";
import path from "path";
import { fileURLToPath } from "url";

const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static UI file
app.use(express.static(path.join(__dirname, "public")));

// In-memory cache for fast reloads
const cache = new Map();

// Stream-based proxy route
app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing 'url'");

  try {
    // Serve from cache if exists
    if (cache.has(target)) {
      const cached = cache.get(target);
      res.set("content-type", cached.contentType);
      StringStream.from(cached.body).pipe(res);
      return;
    }

    // Fetch the target page
    const response = await fetch(target, {
      headers: { "User-Agent": "Mozilla/5.0 (Euphoria Browser)" },
      redirect: "manual",
    });

    // Handle redirects
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const redirectURL = new URL(response.headers.get("location"), target).href;
      return res.redirect("/proxy?url=" + encodeURIComponent(redirectURL));
    }

    const contentType = response.headers.get("content-type") || "";
    res.set("content-type", contentType);

    if (contentType.includes("text/html")) {
      let html = await response.text();

      // Rewrite links to go through proxy
      html = html.replace(/(href|src)=["'](.*?)["']/gi, (match, attr, link) => {
        if (link.startsWith("javascript:")) return match;
        try {
          const abs = new URL(link, target).href;
          return attr + '="/proxy?url=' + encodeURIComponent(abs) + '"';
        } catch {
          return match;
        }
      });

      // Cache HTML for faster reloads
      cache.set(target, { body: html, contentType });

      StringStream.from(html).pipe(res);
    } else {
      // Non-HTML (images, scripts, etc.)
      response.body.pipe(res);
    }
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Error loading page.");
  }
});

// Start server
app.listen(PORT, () => console.log(`✨ Euphoria running on port ${PORT}`));
