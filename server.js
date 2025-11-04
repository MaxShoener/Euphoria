import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";
import path from "path";
import { fileURLToPath } from "url";

const { StringStream } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Serve index.html at root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Helper: determine if input is a URL or search query
function makeTarget(input) {
  if (!input) return "https://www.google.com";
  try {
    return new URL(input).href;
  } catch {
    return `https://www.google.com/search?q=${encodeURIComponent(input)}`;
  }
}

// Proxy route
app.get("/proxy", async (req, res) => {
  const input = req.query.url || req.query.q;
  const target = makeTarget(input);

  try {
    const response = await fetch(target, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
      },
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
      const stream = new StringStream(response.body);

      stream
        .map(line => {
          return line.replace(/(href|src)=["'](.*?)["']/gi, (match, attr, link) => {
            if (!link || link.startsWith("javascript:")) return match;
            try {
              const abs = new URL(link, target).href;
              return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
            } catch {
              return match;
            }
          });
        })
        .pipe(res);
    } else {
      response.body.pipe(res);
    }

  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Error loading page");
  }
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));
