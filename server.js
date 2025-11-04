import express from "express";
import puppeteer from "puppeteer";

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files (index.html)
app.use(express.static("public"));

let browser;

async function getBrowser() {
  if (!browser) {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"]
    });
  }
  return browser;
}

// Proxy route to render websites
app.get("/proxy", async (req, res) => {
  try {
    let url = req.query.url;
    if (!url) return res.status(400).send("Missing URL");
    if (!url.startsWith("http")) url = "https://" + url;

    const browser = await getBrowser();
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });

    await page.goto(url, { waitUntil: "networkidle2", timeout: 120000 });

    const content = await page.content();
    await page.close();

    res.send(content);
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to load page.");
  }
});

app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
