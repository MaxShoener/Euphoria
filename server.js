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

function isUrl(input) {
  try {
    new URL(input.startsWith("http") ? input : `https://${input}`);
    return true;
  } catch {
    return false;
  }
}

app.get("/search", async (req, res) => {
  let q = req.query.q;
  if (!q) return res.redirect("/");

  let url = isUrl(q) ? (q.startsWith("http") ? q : `https://${q}`) : `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  res.redirect(`/proxy?url=${encodeURIComponent(url)}`);
});

app.get("/proxy", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send("Missing url");

  try {
    const response = await fetch(url);
    let contentType = response.headers.get("content-type") || "";

    if (contentType.includes("text/html")) {
      res.setHeader("content-type", "text/html; charset=utf-8");
      const text = await response.text();

      // Rewrite links, forms, and resources
      const rewritten = text.replace(/(href|src|action)=["']([^"']+)["']/gi, (match, attr, val) => {
        if (val.startsWith("http") || val.startsWith("//")) {
          return `${attr}="/proxy?url=${encodeURIComponent(val.startsWith("//") ? "https:" + val : val)}"`;
        } else if (val.startsWith("#") || val.startsWith("mailto:")) {
          return match;
        } else {
          const base = new URL(url);
          return `${attr}="/proxy?url=${encodeURIComponent(new URL(val, base).href)}"`;
        }
      });

      // Inject spinner script
      const finalHTML = rewritten.replace(
        /<body([^>]*)>/i,
        `<body$1>
        <div id="spinner" style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(255,255,255,0.8);display:flex;align-items:center;justify-content:center;z-index:9999;">
          <div class="loader"></div>
        </div>
        <style>
          .loader {
            border: 8px solid #f3f3f3;
            border-top: 8px solid #444;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        </style>
        <script>
          window.addEventListener('load', () => { const s=document.getElementById('spinner'); if(s) s.style.display='none'; });
        </script>`
      );

      res.send(finalHTML);
    } else {
      // Pass through non-HTML (images, JS, CSS)
      response.body.pipe(res);
    }
  } catch (err) {
    res.status(500).send(`Error loading page: ${err}`);
  }
});

app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});
