import express from "express";
import puppeteer from "puppeteer-core";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static UI
app.use(express.static(__dirname));

// Proxy endpoint
app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing url");

  try {
    const browser = await puppeteer.launch({
      executablePath: "/usr/bin/chromium",
      args: ["--no-sandbox", "--disable-setuid-sandbox"]
    });

    const page = await browser.newPage();
    await page.goto(url, { waitUntil: "networkidle2", timeout: 30000 });
    const html = await page.content();
    await browser.close();

    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading page");
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
