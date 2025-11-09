import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { DataStream } from "scramjet";
import { URL } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== Utility Functions =====
function sanitizeHTML(html) {
  if (!html || typeof html !== "string") return html;
  html = html.replace(
    /<script[^>]*src=(["'])(?:(?!\1).)*(?:analytics|gtag|googletagmanager|doubleclick|googlesyndication)(?:(?!\1).)*\1[^>]*><\/script>/gi,
    ""
  );
  html = html.replace(/<iframe[^>]*googlesyndication[^>]*><\/iframe>/gi, "");
  html = html.replace(/<meta http-equiv=["']refresh["'][^>]*>/gi, "");
  return html;
}

function normalizeUrl(input) {
  if (!input) return "";
  if (!/^https?:\/\//i.test(input)) input = "https://" + input;
  return input;
}

function rewriteHTML(baseUrl, html) {
  if (!html) return html;
  const origin = new URL(baseUrl).origin;

  html = html.replace(
    /href=(["'])(?!#)(?!javascript)(?!https?:\/\/)([^"'>]+)\1/gi,
    (m, q, link) => `href=${q}/proxy?url=${encodeURIComponent(new URL(link, origin).href)}${q}`
  );
  html = html.replace(
    /href=(["'])(https?:\/\/[^"']+)\1/gi,
    (m, q, link) => `href=${q}/proxy?url=${encodeURIComponent(link)}${q}`
  );
  html = html.replace(
    /src=(["'])(?!data:)(?!https?:\/\/)([^"'>]+)\1/gi,
    (m, q, src) => `src=${q}/asset?url=${encodeURIComponent(new URL(src, origin).href)}${q}`
  );
  html = html.replace(
    /src=(["'])(https?:\/\/[^"']+)\1/gi,
    (m, q, src) => `src=${q}/asset?url=${encodeURIComponent(src)}${q}`
  );
  return sanitizeHTML(html);
}

// ===== Routes =====

// Serve UI
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Proxy route for main HTML content (Scramjet streaming)
app.get("/proxy", async (req, res) => {
  try {
    let target = req.query.url;
    if (!target) return res.status(400).send("Missing ?url parameter");
    target = normalizeUrl(target);

    const response = await fetch(target, {
      redirect: "manual",
      headers: { "User-Agent": "Euphoria/2.0 Chrome/118.0" },
    });

    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const redirect = new URL(response.headers.get("location"), target).href;
      return res.redirect(`/proxy?url=${encodeURIComponent(redirect)}`);
    }

    const contentType = response.headers.get("content-type");
    res.setHeader("Content-Type", contentType || "text/html");

    if (contentType && contentType.includes("text/html")) {
      const stream = DataStream.from(response.body)
        .stringify()
        .each(chunk => chunk.replace(/<base[^>]*>/gi, ""))
        .map(chunk => rewriteHTML(target, chunk))
        .map(chunk => sanitizeHTML(chunk));

      await stream.pipe(res);
    } else {
      const buf = await response.arrayBuffer();
      res.end(Buffer.from(buf));
    }
  } catch (e) {
    console.error("Proxy error:", e);
    res.status(500).send("Proxy failure.");
  }
});

app.get("/asset", async (req, res) => {
  try {
    const target = normalizeUrl(req.query.url);
    const response = await fetch(target, { headers: { "User-Agent": "Euphoria/2.0 Chrome/118.0" } });
    const contentType = response.headers.get("content-type");
    res.setHeader("Content-Type", contentType || "application/octet-stream");
    const buf = await response.arrayBuffer();
    res.end(Buffer.from(buf));
  } catch (e) {
    console.error("Asset error:", e);
    res.status(500).send("Asset failure.");
  }
});

app.use((req, res) => res.status(404).send("Euphoria — page not found."));

app.listen(PORT, () => console.log(`🌐 Euphoria running on port ${PORT}`));