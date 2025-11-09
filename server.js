import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { URL } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// ===== Middleware =====
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== Helper Functions =====

// Sanitize HTML to prevent analytics/scripts from breaking rendering
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

// Normalize URLs
function normalizeUrl(inputUrl) {
  if (!inputUrl) return "";
  if (!/^https?:\/\//i.test(inputUrl)) {
    inputUrl = "https://" + inputUrl;
  }
  return inputUrl;
}

// Modify HTML links for proxy routing
function rewriteHTML(baseUrl, html) {
  if (!html) return html;
  const origin = new URL(baseUrl).origin;

  // Convert relative URLs to proxy URLs
  html = html.replace(
    /href=(["'])(?!#)(?!javascript)(?!https?:\/\/)([^"'>]+)\1/gi,
    (match, quote, link) => {
      const newLink = new URL(link, origin).href;
      return `href=${quote}/proxy?url=${encodeURIComponent(newLink)}${quote}`;
    }
  );

  html = html.replace(
    /href=(["'])(https?:\/\/[^"']+)\1/gi,
    (match, quote, link) => `href=${quote}/proxy?url=${encodeURIComponent(link)}${quote}`
  );

  html = html.replace(
    /src=(["'])(?!data:)(?!https?:\/\/)([^"'>]+)\1/gi,
    (match, quote, src) => {
      const newSrc = new URL(src, origin).href;
      return `src=${quote}/asset?url=${encodeURIComponent(newSrc)}${quote}`;
    }
  );

  html = html.replace(
    /src=(["'])(https?:\/\/[^"']+)\1/gi,
    (match, quote, src) => `src=${quote}/asset?url=${encodeURIComponent(src)}${quote}`
  );

  return sanitizeHTML(html);
}

// ===== Routes =====

// Home page (UI)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Proxy route for HTML/content
app.get("/proxy", async (req, res) => {
  try {
    let target = req.query.url;
    if (!target) return res.status(400).send("Missing ?url parameter");
    target = normalizeUrl(target);

    const response = await fetch(target, {
      redirect: "manual",
      headers: { "User-Agent": "Euphoria/1.0 Chrome/118.0" },
    });

    // Handle redirects manually
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const redirectUrl = new URL(response.headers.get("location"), target).href;
      return res.redirect(`/proxy?url=${encodeURIComponent(redirectUrl)}`);
    }

    const contentType = response.headers.get("content-type");
    res.setHeader("Content-Type", contentType || "text/html");

    if (contentType && contentType.includes("text/html")) {
      let html = await response.text();
      html = rewriteHTML(target, html);
      res.send(html);
    } else {
      const buffer = await response.arrayBuffer();
      res.end(Buffer.from(buffer));
    }
  } catch (err) {
    console.error("Proxy Error:", err);
    res.status(500).send("Proxy failed.");
  }
});

// Asset route (images, CSS, JS, etc.)
app.get("/asset", async (req, res) => {
  try {
    const target = normalizeUrl(req.query.url);
    const response = await fetch(target, { headers: { "User-Agent": "Euphoria/1.0 Chrome/118.0" } });

    const contentType = response.headers.get("content-type");
    res.setHeader("Content-Type", contentType || "application/octet-stream");

    const buffer = await response.arrayBuffer();
    res.end(Buffer.from(buffer));
  } catch (err) {
    console.error("Asset Error:", err);
    res.status(500).send("Asset load failed.");
  }
});

// ===== Default fallback =====
app.use((req, res) => {
  res.status(404).send("Euphoria — Page not found.");
});

// ===== Launch server =====
app.listen(PORT, () => {
  console.log(`🌐 Euphoria running on port ${PORT}`);
});