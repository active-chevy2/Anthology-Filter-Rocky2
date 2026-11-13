const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 80;

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);

  // API endpoint to fetch target website HTML server-side
  if (parsedUrl.pathname === '/api/check') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    const targetUrl = parsedUrl.query.url;

    if (!targetUrl) {
      return res.end(JSON.stringify({ error: 'Missing URL parameter.' }));
    }

    try {
      const response = await fetch(targetUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; RelMeChecker/1.0)',
          'Accept': 'text/html,application/xhtml+xml'
        },
        redirect: 'follow'
      });

      const html = await response.text();
      return res.end(JSON.stringify({ html, status: response.status }));
    } catch (err) {
      return res.end(JSON.stringify({ error: `Failed to fetch site: ${err.message}` }));
    }
  }

  // Serve index.html for the root route
  if (parsedUrl.pathname === '/' || parsedUrl.pathname === '/index.html') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end('Error loading index.html');
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(content);
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`rel="me" checker running on port ${PORT}`);
});
