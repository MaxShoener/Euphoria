// EUPHORIA v2 – Robust Non-Iframe Proxy
import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(cors());
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -----------------------------
// STATIC INDEX
// -----------------------------
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// -----------------------------
// VALIDATION + CLEANUP
// -----------------------------
function sanitizeURL(raw) {
    if (!raw) return null;

    try {
        const decoded = decodeURIComponent(raw);
        const url = decoded.trim();

        // Force https for safety
        if (!/^https?:\/\//i.test(url)) return "https://" + url;

        return url;
    } catch {
        return null;
    }
}

// -----------------------------
// MAIN PROXY ENDPOINT
// -----------------------------
app.get("/proxy", async (req, res) => {
    const raw = req.query.url;

    if (!raw) {
        return res.status(400).send("Missing ?url=");
    }

    const target = sanitizeURL(raw);
    if (!target) {
        return res.status(400).send("Invalid URL");
    }

    console.log("Proxy →", target);

    try {
        // Perform the proxied fetch
        const response = await fetch(target, {
            redirect: "follow",
            headers: {
                "User-Agent":
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1"
            }
        });

        // Handle redirect loops
        if (response.status >= 300 && response.status < 400) {
            const loc = response.headers.get("location");
            if (loc) {
                const absolute = new URL(loc, target).href;
                return res.redirect("/proxy?url=" + encodeURIComponent(absolute));
            }
        }

        const ct = response.headers.get("content-type") || "";
        res.setHeader("Content-Type", "text/plain; charset=utf-8");

        // Text / HTML
        if (ct.includes("text") || ct.includes("json")) {
            const text = await response.text();
            return res.send(text);
        }

        // Binary fallback (images, videos)
        const arrayBuffer = await response.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);

        res.setHeader("Content-Type", ct || "application/octet-stream");
        return res.send(buffer);

    } catch (err) {
        console.log("Proxy error:", err);
        return res.status(502).send("Proxy fetch failed: " + err.toString());
    }
});

// -----------------------------
// SERVER LISTEN
// -----------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Euphoria v2 Proxy running on port", PORT);
});