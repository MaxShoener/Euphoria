// server.js
import express from "express";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import LRU from "lru-cache";
import fetch from "node-fetch"; // node-fetch v3 is ESM compatible
import pkg from "scramjet";      // CommonJS import
const { DataStream } = pkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// -------- Middleware --------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public"))); // serve index.html and assets

// -------- LRU Cache --------
const cache = new LRU({
  max: 500,
  ttl: 1000 * 60 * 5 // 5 minutes
});

// -------- Logging Middleware --------
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// -------- Routes --------

// Home route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Google login stub
app.get("/auth/google", async (req, res) => {
  try {
    // Example: redirect to Google OAuth (placeholder)
    res.redirect("https://accounts.google.com/o/oauth2/auth");
  } catch (err) {
    console.error("Google login error:", err);
    res.status(500).send("Error during Google login");
  }
});

// Cache example route
app.get("/data/:id", async (req, res) => {
  const { id } = req.params;
  if (cache.has(id)) {
    return res.json({ source: "cache", data: cache.get(id) });
  }

  try {
    // Example fetch (replace with real API)
    const response = await fetch(`https://jsonplaceholder.typicode.com/todos/${id}`);
    const data = await response.json();

    // Cache the response
    cache.set(id, data);

    res.json({ source: "api", data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch data" });
  }
});

// Scramjet example route
app.get("/stream", async (req, res) => {
  try {
    const data = [1, 2, 3, 4, 5];
    const stream = DataStream.fromArray(data)
      .map(x => x * 2);

    const result = [];
    await stream.each(x => result.push(x));

    res.json({ result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Stream failed" });
  }
});

// Cookie example
app.get("/set-cookie", (req, res) => {
  res.cookie("test", "hello", { maxAge: 1000 * 60 * 60 }); // 1 hour
  res.send("Cookie set!");
});

app.get("/get-cookie", (req, res) => {
  res.json(req.cookies);
});

// Fallback route
app.use((req, res) => {
  res.status(404).send("Page not found");
});

// -------- Start server --------
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});