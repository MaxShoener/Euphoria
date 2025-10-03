import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { HttpClient } from '@ultraviolet/http';
import { DataStream } from 'scramjet';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve frontend files
app.use(express.static(__dirname));

// Utility to flatten nested JSON
function flattenJson(obj, parentKey = '', result = {}) {
  for (const [key, value] of Object.entries(obj)) {
    const newKey = parentKey ? `${parentKey}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      flattenJson(value, newKey, result);
    } else {
      result[newKey] = value;
    }
  }
  return result;
}

// API endpoint using Ultraviolet + Scramjet
app.get('/api', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'Missing URL parameter' });

  try {
    const client = new HttpClient();
    const response = await client.get(targetUrl);
    const contentType = response.headers.get('content-type') || '';

    // JSON response
    if (contentType.includes('application/json')) {
      const jsonData = await response.json();

      // Flatten and remove empty/null values
      const processed = await new DataStream([jsonData])
        .map(item => flattenJson(item))
        .map(item => Object.fromEntries(Object.entries(item).filter(([_, v]) => v != null && v !== '')))
        .toArray();

      return res.json({ url: targetUrl, data: processed });
    }

    // Text response
    const text = await response.text();
    const processed = await new DataStream.StringStream(text)
      .lines()
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .toArray();

    res.json({ url: targetUrl, data: processed });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fallback route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));