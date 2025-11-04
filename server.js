import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";

const { StringStream } = pkg;
const app = express();
const port = process.env.PORT || 3000;

app.use(express.static("public"));

// Utility: normalize input
function normalizeInput(input) {
  input = input.trim();
  if (!input) return "https://www.google.com";
  // Auto add https
  if (!input.startsWith("http")) {
    if (input.includes(" ")) return `https://www.google.com/search?q=${encodeURIComponent(input)}`;
    return "https://" + input;
  }
  return input;
}

// Proxy endpoint: streams content progressively
app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing URL");

  try {
    const response = await fetch(url);
    if (!response.ok) return res.status(500).send("Failed to fetch");

    res.setHeader("Content-Type", "text/html");

    const text = await response.text();

    // Stream through Scramjet to rewrite links/images
    await StringStream.from(text)
      .map(line => {
        // Rewrite href/src to pass through proxy
        return line.replace(/(href|src)=["'](.*?)["']/gi, (match, attr, val) => {
          try {
            const abs = new URL(val, url).href;
            return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
          } catch {
            return match;
          }
        });
      })
      .toArray()
      .then(lines => res.send(lines.join("\n")));
  } catch (err) {
    res.status(500).send(`<h1>Error</h1><p>${err.message}</p>`);
  }
});

// Optional search endpoint (redirects to Google search)
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.redirect(`https://www.google.com/search?q=${encodeURIComponent(q)}`);
});

app.listen(port, () => console.log(`Euphoria server running on port ${port}`));
