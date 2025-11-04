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

// Puppeteer browser instance
let browser;
(async () => {
  browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium-browser', // System Chromium path
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
})();

async function renderPage(url) {
  if (!browser) throw new Error('Browser not initialized');
  const page = await browser.newPage();
  await page.setViewport({ width: 1366, height: 768 });
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 0 });
  const html = await page.content();
  await page.close();
  return html;
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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

// Close browser on exit
process.on('exit', async () => {
  if (browser) await browser.close();
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
