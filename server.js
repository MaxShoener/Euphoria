import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";
const { StringStream } = pkg;
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "public")));

// Utility to check if input is a URL
function isUrl(input) {
  try {
    new URL(input.startsWith("http") ? input : `https://${input}`);
    return true;
  } catch {
    return false;
  }
}

// Auto search / redirect
app.get("/search", (req, res) => {
  const q = req.query.q;
  if (!q) return res.redirect("/");
  const url = isUrl(q) ? (q.startsWith("http") ? q : `https://${q}`) : `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  res.redirect(`/proxy?url=${encodeURIComponent(url)}`);
});

// Proxy streaming
app.get("/proxy", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send("Missing URL");

  try {
    const response = await fetch(url);
    const contentType = response.headers.get("content-type") || "";

    if (contentType.includes("text/html")) {
      res.setHeader("content-type", "text/html; charset=utf-8");

      const html = await response.text();

      // Stream HTML line by line
      const stream = StringStream.from(html)
        .map(line => 
          line.replace(/(href|src|action)=["']([^"']+)["']/gi, (match, attr, val) => {
            if (!val) return match;
            if (val.startsWith("http") || val.startsWith("//")) {
              return `${attr}="/proxy?url=${encodeURIComponent(val.startsWith("//") ? "https:" + val : val)}"`;
            } else if (val.startsWith("#") || val.startsWith("mailto:")) {
              return match;
            } else {
              try {
                const base = new URL(url);
                return `${attr}="/proxy?url=${encodeURIComponent(new URL(val, base).href)}"`;
              } catch {
                return match;
              }
            }
          })
        )
        .join("\n");

      await stream.pipe(res);
    } else {
      // Stream other resources (images, JS, CSS) directly
      response.body.pipe(res);
    }
  } catch (err) {
    res.status(500).send(`Error loading page: ${err}`);
  }
});

app.listen(PORT, () => {
  console.log(`Euphoria streaming proxy running on port ${PORT}`);
});
