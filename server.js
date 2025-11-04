// server.js
import express from "express";
import fetch from "node-fetch";
import scramjetPkg from "scramjet";
const { StringStream } = scramjetPkg;

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files (index.html, spinner, CSS, etc.)
app.use(express.static("public"));

// Helper: ensure URLs are absolute
function absoluteUrl(base, relative) {
  try {
    return new URL(relative, base).href;
  } catch {
    return relative;
  }
}

// Proxy endpoint: fully render pages with Scramjet
app.get("/proxy", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send("Missing URL");

  try {
    const response = await fetch(targetUrl);
    const body = await response.text();

    // Stream the page line by line
    await StringStream.from(body)
      .map(line =>
        // Replace all href/src URLs to route through our proxy
        line.replace(
          /(href|src)=["'](.*?)["']/gi,
          (_, attr, val) => `${attr}="/proxy?url=${encodeURIComponent(absoluteUrl(targetUrl, val))}"`
        )
      )
      .map(line =>
        // Optionally rewrite form actions to proxy
        line.replace(
          /<form\s+([^>]*?)action=["'](.*?)["']/gi,
          (_, attrs, val) => `<form ${attrs} action="/proxy?url=${encodeURIComponent(absoluteUrl(targetUrl, val))}"`
        )
      )
      .map(line =>
        // Optionally rewrite meta refresh redirects
        line.replace(
          /<meta\s+http-equiv=["']refresh["']\s+content=["'](\d+);\s*url=(.*?)["']/gi,
          (_, time, url) => `<meta http-equiv="refresh" content="${time}; url=/proxy?url=${encodeURIComponent(absoluteUrl(targetUrl, url))}"`
        )
      )
      .pipe(res);

  } catch (err) {
    res.status(500).send(`
      <html>
      <body style="font-family:sans-serif; background:#111; color:#fff; display:flex; justify-content:center; align-items:center; height:100vh;">
        <div>
          <h1>Error loading page</h1>
          <p>${err.message}</p>
          <p>URL: ${targetUrl}</p>
        </div>
      </body>
      </html>
    `);
  }
});

// Optional: search endpoint for your UI search bar
app.get("/search", (req, res) => {
  let query = req.query.q;
  if (!query) return res.redirect("/");

  // If it's a URL, auto add https://
  if (!query.startsWith("http://") && !query.startsWith("https://")) {
    query = "https://www.google.com/search?q=" + encodeURIComponent(query);
  }

  res.redirect("/proxy?url=" + encodeURIComponent(query));
});

app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
