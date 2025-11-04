import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";
const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));

// Redirect root requests like /search → /proxy?url=https://www.google.com/search...
app.get("/search", (req, res) => {
  const query = req.originalUrl.replace(/^\/+/, ""); // 'search?q=...'
  const url = `https://www.google.com/${query}`;
  res.redirect(`/proxy?url=${encodeURIComponent(url)}`);
});

// Proxy handler
app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing 'url'");

  try {
    const response = await fetch(target, {
      redirect: "manual",
      headers: { "User-Agent": "Mozilla/5.0 (Euphoria Proxy)" },
    });

    // Handle redirects
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const redirectURL = new URL(response.headers.get("location"), target).href;
      return res.redirect(`/proxy?url=${encodeURIComponent(redirectURL)}`);
    }

    const contentType = response.headers.get("content-type") || "";
    res.set("content-type", contentType);

    // Stream HTML live
    if (contentType.includes("text/html")) {
      const body = await response.text();

      const rewritten = body.replace(
        /(href|src)=["'](.*?)["']/gi,
        (match, attr, link) => {
          if (link.startsWith("javascript:")) return match;
          try {
            const abs = new URL(link, target).href;
            return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
          } catch {
            return match;
          }
        }
      );

      StringStream.from(rewritten).pipe(res);
    } else {
      // Stream other types (images, JS, CSS) directly
      response.body.pipe(res);
    }
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Proxy error: " + err.message);
  }
});

app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
