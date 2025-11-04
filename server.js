import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";
const { StringStream } = pkg;

const app = express();
const port = process.env.PORT || 3000;

app.use(express.static("public"));

// Proxy route with real-time streaming
app.get("/proxy", async (req, res) => {
  let url = req.query.url;
  if (!url) return res.status(400).send("Missing 'url' parameter");

  // Auto-add https if missing
  if (!url.startsWith("http")) url = "https://" + url;

  try {
    const response = await fetch(url, { redirect: "follow" });
    const contentType = response.headers.get("content-type") || "";

    res.set("content-type", contentType);

    if (contentType.includes("text/html")) {
      // Stream HTML as it arrives
      const bodyStream = StringStream.from(response.body);

      await bodyStream
        .map(line =>
          line
            // Rewrite href/src to proxy
            .replace(/(href|src)=["']([^"']+)["']/gi, (m, attr, link) => {
              if (link.startsWith("http") || link.startsWith("//")) {
                const abs = link.startsWith("//") ? "https:" + link : link;
                return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
              }
              return m;
            })
            // Inject spinner for images that are loading
            .replace(
              /<img /gi,
              '<img onload="this.style.opacity=1" style="opacity:0;transition:opacity 0.3s" '
            )
        )
        .pipe(res);

    } else {
      // Non-HTML content: pipe directly
      response.body.pipe(res);
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading page");
  }
});

// Start server
app.listen(port, () => console.log(`Euphoria proxy running at http://localhost:${port}`));
