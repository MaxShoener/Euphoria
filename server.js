import express from "express";
import puppeteer from "puppeteer";

const app = express();
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

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

app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing URL");

  try {
    const browser = await getBrowser();
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.goto(url, { waitUntil: "networkidle2", timeout: 60000 });
    const content = await page.content();
    await page.close();
    res.send(content);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error loading page");
  }
});

app.get("/search", (req, res) => {
  const q = req.query.q;
  if (!q) return res.redirect("/");
  const googleURL = `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  res.redirect(`/proxy?url=${encodeURIComponent(googleURL)}`);
});

app.listen(8000, () => {
  console.log("Server running on port 8000");
});
