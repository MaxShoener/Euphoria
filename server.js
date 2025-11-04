import express from "express";
import fetch from "node-fetch";
import { StringStream } from "scramjet";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, "public")));

app.get("/proxy", async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send("Missing url");

  try {
    const response = await fetch(targetUrl, { redirect: "follow" });
    const contentType = response.headers.get("content-type") || "";

    res.setHeader("Content-Type", contentType);

    // Only stream HTML for rewriting URLs
    if (contentType.includes("text/html")) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      let buffer = "";

      const stream = new StringStream();

      const pushChunk = async ({ value, done }) => {
        if (done) {
          if (buffer) stream.write(buffer);
          stream.end();
          return;
        }

        buffer += decoder.decode(value, { stream: true });

        // Rewrite src/href for proxying
        const rewritten = buffer.replace(
          /(href|src)=["']([^"']+)["']/gi,
          (match, attr, url) => {
            try {
              const abs = new URL(url, targetUrl).href;
              return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
            } catch (e) {
              return match;
            }
          }
        );

        stream.write(rewritten);
        buffer = "";
      };

      while (true) {
        const chunk = await reader.read();
        await pushChunk(chunk);
        if (chunk.done) break;
      }

      stream.pipe(res);
    } else {
      // Other content types
      response.body.pipe(res);
    }
  } catch (err) {
    res.status(500).send("Error loading page: " + err.message);
  }
});

// Serve index.html for root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
