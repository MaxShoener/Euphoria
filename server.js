import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";

const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public")); // serve your index.html

// Home route
app.get("/", (req, res) => {
  res.sendFile("index.html", { root: "public" });
});

// Proxy route
app.get("/proxy", async (req, res) => {
  let targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send("Missing URL");

  // Add protocol if missing
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = "https://" + targetUrl;
  }

  try {
    const response = await fetch(targetUrl);
    const contentType = response.headers.get("content-type");

    // If HTML, stream through Scramjet to rewrite links/images
    if (contentType && contentType.includes("text/html")) {
      res.setHeader("Content-Type", "text/html; charset=UTF-8");

      const htmlStream = StringStream.from(response.body);

      htmlStream
        .map(line => {
          // Rewrite href/src to go through our proxy
          return line.replace(
            /(href|src)=["'](.*?)["']/gi,
            (match, attr, url) => {
              if (url.startsWith("data:") || url.startsWith("javascript:")) return match;
              const absUrl = new URL(url, targetUrl).toString();
              return `${attr}="/proxy?url=${encodeURIComponent(absUrl)}"`;
            }
          );
        })
        .pipe(res); // stream final HTML to client
    } else {
      // Non-HTML (images, scripts, etc.) just pipe directly
      response.body.pipe(res);
    }
  } catch (err) {
    res.status(500).send(`Error loading page: ${err.message}`);
  }
});

// Optional search route (auto Google search if not a URL)
app.get("/search", (req, res) => {
  let query = req.query.q;
  if (!query) return res.redirect("/");

  // Check if it's a valid URL
  if (!/^https?:\/\//i.test(query)) {
    query = "https://www.google.com/search?q=" + encodeURIComponent(query);
  }

  res.redirect("/proxy?url=" + encodeURIComponent(query));
});

app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
