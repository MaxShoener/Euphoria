import express from "express";
import puppeteer from "puppeteer";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

let browser;

// Serve static files (index.html, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

// Launch Puppeteer browser
async function launchBrowser() {
  if (!browser) {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
      executablePath: puppeteer.executablePath(),
    });
  }
  return browser;
}

// Proxy endpoint to fetch any URL
app.get("/proxy", async (req, res) => {
  let { url } = req.query;

  if (!url) return res.status(400).json({ error: "Missing 'url' field" });

  if (!url.startsWith("http")) url = "https://" + url;

  try {
    const browser = await launchBrowser();
    const page = await browser.newPage();

    // Set viewport for consistent display
    await page.setViewport({ width: 1280, height: 800 });

    // Intercept requests to load images and resources
    await page.setRequestInterception(true);
    page.on("request", (req) => {
      if (["image", "stylesheet", "font", "script"].includes(req.resourceType())) {
        req.continue();
      } else {
        req.continue();
      }
    });

    await page.goto(url, { waitUntil: "networkidle2", timeout: 60000 });

    let content = await page.content();

    // Replace links and sources to proxy
    content = content.replace(
      /(href|src)=["'](.*?)["']/gi,
      (match, attr, val) => {
        if (val.startsWith("http") || val.startsWith("/")) {
          const absUrl = val.startsWith("http") ? val : new URL(val, url).href;
          return `${attr}="/proxy?url=${encodeURIComponent(absUrl)}"`;
        }
        return match;
      }
    );

    await page.close();
    res.send(content);
  } catch (err) {
    console.error(err);
    res.status(500).send(`
      <h2>Error loading page</h2>
      <p>${err.message}</p>
    `);
  }
});

// Auto-search endpoint
app.get("/search", (req, res) => {
  const { q } = req.query;
  if (!q) return res.redirect("/");
  const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(q)}`;
  res.redirect(`/proxy?url=${encodeURIComponent(searchUrl)}`);
});

// Home button shortcut (Google)
app.get("/home", (req, res) => {
  res.redirect("/proxy?url=" + encodeURIComponent("https://www.google.com"));
});

// Start server
app.listen(PORT, async () => {
  await launchBrowser();
  console.log(`Euphoria running on port ${PORT}`);
});
