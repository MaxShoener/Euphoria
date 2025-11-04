import express from "express";
import puppeteer from "puppeteer";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

let browserPromise = puppeteer.launch({ headless: true });

app.post("/fetch", async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: "Missing 'url' field" });

  // auto prefix
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  try {
    const browser = await browserPromise;
    const page = await browser.newPage();
    page.setDefaultNavigationTimeout(120000); // 2 min timeout
    await page.goto(url, { waitUntil: "networkidle2" });

    const content = await page.content();
    await page.close();

    res.send(content);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch page", details: err.message });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
