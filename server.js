const http = require('http');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const FETCH_TIMEOUT_MS = 10000;
const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 2 * 1024 * 1024; // 2 MB

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer'
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(payload));
}

function isBlockedIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b, c] = parts;

  if (a === 0) return true; // 0.0.0.0/8 (Current network)
  if (a === 10) return true; // 10.0.0.0/8 (Private)
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true; // 127.0.0.0/8 (Loopback)
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (Link-local / cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (Private)
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 (Private)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 (TEST-NET-2)
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 (TEST-NET-3)
  if (a >= 224) return true; // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)

  return false;
}

function isBlockedIp(rawIp) {
  const ip = rawIp.split('%')[0].toLowerCase();

  if (net.isIPv4(ip)) {
    return isBlockedIpv4(ip);
  }

  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return true;

    // IPv4-mapped IPv6 in dotted form (e.g. ::ffff:127.0.0.1)
    if (ip.startsWith('::ffff:') && ip.includes('.')) {
      return isBlockedIpv4(ip.slice(7));
    }

    // IPv4-mapped IPv6 in normalised hex form (e.g. ::ffff:7f00:1)
    const hexMapped = ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMapped) {
      const hi = parseInt(hexMapped[1], 16);
      const lo = parseInt(hexMapped[2], 16);
      const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isBlockedIpv4(ipv4);
    }

    const firstWordHex = ip.split(':')[0];
    if (firstWordHex) {
      const firstWord = parseInt(firstWordHex, 16);
      if (!Number.isNaN(firstWord)) {
        if ((firstWord & 0xfe00) === 0xfc00) return true; // fc00::/7 (Unique local)
        if ((firstWord & 0xffc0) === 0xfe80) return true; // fe80::/10 (Link-local)
        if ((firstWord & 0xff00) === 0xff00) return true; // ff00::/8 (Multicast)
      }
    }

    if (ip.startsWith('2001:db8:')) return true; // Documentation

    return false;
  }

  return true;
}

async function validateUrl(inputUrl) {
  let parsed;
  try {
    parsed = new URL(inputUrl);
  } catch {
    throw Object.assign(new Error('Invalid URL format.'), { statusCode: 400 });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw Object.assign(new Error('Only http:// and https:// URLs are allowed.'), { statusCode: 400 });
  }

  if (parsed.username || parsed.password) {
    throw Object.assign(new Error('URLs with embedded credentials are not allowed.'), { statusCode: 400 });
  }

  const bareHost = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!bareHost) {
    throw Object.assign(new Error('Missing hostname in URL.'), { statusCode: 400 });
  }

  if (net.isIP(bareHost)) {
    if (isBlockedIp(bareHost)) {
      throw Object.assign(new Error('Access to private or local IP addresses is blocked.'), { statusCode: 403 });
    }
    return parsed.href;
  }

  let records;
  try {
    records = await dns.lookup(bareHost, { all: true });
  } catch {
    throw Object.assign(new Error(`Could not resolve domain: ${bareHost}`), { statusCode: 502 });
  }

  if (!records || records.length === 0) {
    throw Object.assign(new Error(`No DNS records found for: ${bareHost}`), { statusCode: 502 });
  }

  for (const record of records) {
    if (isBlockedIp(record.address)) {
      throw Object.assign(new Error('Access to private or local network addresses is blocked.'), { statusCode: 403 });
    }
  }

  return parsed.href;
}

async function readResponseWithLimit(response, maxBytes) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let totalBytes = 0;
  let result = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maxBytes) {
      await reader.cancel();
      throw Object.assign(
        new Error(`Page exceeded the ${Math.round(maxBytes / (1024 * 1024))} MB size limit.`),
        { statusCode: 413 }
      );
    }
    result += decoder.decode(value, { stream: true });
  }

  result += decoder.decode();
  return result;
}

async function safeFetchHtml(initialUrl) {
  let currentUrl = initialUrl;

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    const safeUrl = await validateUrl(currentUrl);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      const response = await fetch(safeUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; RelMeChecker/1.1)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      });

      if (response.status >= 300 && response.status < 400) {
        if (response.body) await response.body.cancel();
        const location = response.headers.get('location');
        if (!location) {
          throw Object.assign(new Error('Redirect response missing Location header.'), { statusCode: 502 });
        }
        if (redirects === MAX_REDIRECTS) {
          throw Object.assign(new Error('Too many redirects.'), { statusCode: 502 });
        }
        currentUrl = new URL(location, safeUrl).href;
        continue;
      }

      const contentType = (response.headers.get('content-type') || '').toLowerCase();
      const isHtmlLike =
        !contentType ||
        contentType.includes('text/html') ||
        contentType.includes('application/xhtml+xml') ||
        contentType.includes('text/plain') ||
        contentType.includes('application/xml');

      if (!isHtmlLike) {
        if (response.body) await response.body.cancel();
        throw Object.assign(
          new Error(`Unsupported content type: ${contentType.split(';')[0]}`),
          { statusCode: 415 }
        );
      }

      const html = await readResponseWithLimit(response, MAX_HTML_BYTES);
      return {
        html,
        status: response.status,
        finalUrl: safeUrl
      };
    } catch (err) {
      if (err.name === 'AbortError') {
        throw Object.assign(new Error('Request timed out after 10 seconds.'), { statusCode: 504 });
      }
      if (err.statusCode) throw err;
      throw Object.assign(new Error(`Failed to fetch site: ${err.message}`), { statusCode: 502 });
    } finally {
      clearTimeout(timer);
    }
  }

  throw Object.assign(new Error('Too many redirects.'), { statusCode: 502 });
}

const server = http.createServer(async (req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Method Not Allowed');
  }

  let parsedReqUrl;
  try {
    parsedReqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch {
    res.writeHead(400, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }

  // Health check endpoint for Docker / Coolify
  if (parsedReqUrl.pathname === '/health') {
    return sendJson(res, 200, { status: 'ok' });
  }

  // API endpoint to fetch target website HTML server-side
  if (parsedReqUrl.pathname === '/api/check') {
    let targetUrl = (parsedReqUrl.searchParams.get('url') || '').trim();

    if (!targetUrl) {
      return sendJson(res, 400, { error: 'Missing URL parameter.' });
    }

    if (!/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(targetUrl)) {
      targetUrl = `https://${targetUrl}`;
    }

    try {
      const result = await safeFetchHtml(targetUrl);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, err.statusCode || 500, { error: err.message });
    }
  }

  // Serve index.html for the root route
  if (parsedReqUrl.pathname === '/' || parsedReqUrl.pathname === '/index.html') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(500, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('Error loading index.html');
      }
      res.writeHead(200, {
        ...SECURITY_HEADERS,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy':
          "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
      });
      return res.end(req.method === 'HEAD' ? undefined : content);
    });
    return;
  }

  res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`rel="me" checker running on port ${PORT}`);
});
