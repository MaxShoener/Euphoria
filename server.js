import express from "express";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";
import zlib from "zlib";
import pkg from "scramjet";
const { StringStream } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Correctly serve index.html from /public
const indexPath = path.join(__dirname, "public", "index.html");
app.use(express.static(path.join(__dirname, "public")));

// Serve the UI (homepage)
app.get("/", (req, res) => {
  res.sendFile(indexPath, (err) => {
    if (err) {
      console.error("❌ Failed to serve index.html:", err);
      res.status(500).send("Failed to load UI");
    }
  });
});

// ✅ Proxy handler using Scramjet
app.get("/proxy", async (req, res) => {
  const targetURL = req.query.url;
  if (!targetURL) {
    return res.status(400).send("Missing 'url' query parameter");
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(targetURL, {
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
      },
    });

    clearTimeout(timeout);

    const contentType = response.headers.get("content-type") || "";
    res.set("content-type", contentType);

    // Handle redirects manually
    if (
      response.status >= 300 &&
      response.status < 400 &&
      response.headers.get("location")
    ) {
      const redirectURL = new URL(response.headers.get("location"), targetURL).href;
      return res.redirect(`/proxy?url=${encodeURIComponent(redirectURL)}`);
    }

    // Handle HTML rewriting for internal resources
    if (contentType.includes("text/html")) {
      let html = await response.text();

      // Rewrite href/src to pass through proxy
      html = html.replace(/(href|src)=["'](.*?)["']/gi, (m, a, u) => {
        if (!u || u.startsWith("data:") || u.startsWith("/proxy?url=")) return m;
        try {
          const abs = new URL(u, targetURL).href;
          return `${a}="/proxy?url=${encodeURIComponent(abs)}"`;
        } catch {
          return m;
        }
      });

      // Rewrite inline CSS url() patterns
      html = html.replace(/url\((['"]?)(.*?)\1\)/gi, (m, q, u) => {
        if (!u || u.startsWith("data:")) return m;
        try {
          const abs = new URL(u, targetURL).href;
          return `url("/proxy?url=${encodeURIComponent(abs)}")`;
        } catch {
          return m;
        }
      });

      // Compress & send
      const gz = zlib.createGzip();
      res.set("Content-Encoding", "gzip");
      StringStream.from(html).pipe(gz).pipe(res);
    } else {
      // Handle other types (e.g. images, scripts)
      const buf = await response.arrayBuffer();
      res.send(Buffer.from(buf));
    }
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Proxy error: " + err.message);
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Euphoria is running on port ${PORT}`);
});
