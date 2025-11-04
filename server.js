// server.js
import express from 'express';
import puppeteer from 'puppeteer-core';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

let browser;

// Launch Puppeteer Core with system Chromium
(async () => {
  browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium-browser', // make sure Chromium is installed
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
})();

// Helper to render full page
async function renderPage(url) {
  if (!browser) throw new Error('Browser not initialized');
  const page = await browser.newPage();
  await page.setViewport({ width: 1366, height: 768 });
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 0 });
  const content = await page.content();
  await page.close();
  return content;
}

// Home page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Search proxy
app.get('/search', async (req, res) => {
  const query = req.query.q;
  if (!query) return res.redirect('/');
  const url = query.startsWith('http') ? query : `https://www.google.com/search?q=${encodeURIComponent(query)}`;
  try {
    const html = await renderPage(url);
    res.send(html);
  } catch (e) {
    res.status(500).send(`<h2>Error loading page</h2><p>${e.message}</p>`);
  }
});

// Arbitrary URL proxy
app.get('/url', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.redirect('/');
  try {
    const html = await renderPage(url);
    res.send(html);
  } catch (e) {
    res.status(500).send(`<h2>Error loading page</h2><p>${e.message}</p>`);
  }
});

// Clean shutdown
process.on('exit', async () => {
  if (browser) await browser.close();
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
