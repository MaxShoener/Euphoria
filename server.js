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

// Serve static files from public/
app.use(express.static(path.join(__dirname, "public")));

// Serve index.html at root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Optimized proxy route
app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing 'url'");

  try {
    const response = await fetch(target, {
      headers: { "User-Agent": "Mozilla/5.0 (Euphoria Browser)" },
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
      // Stream HTML line by line and rewrite links
      const stream = new StringStream(response.body);

      stream
        .map(line => {
          return line.replace(/(href|src)=["']
