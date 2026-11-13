# HTML `rel="me"` Checker

A lightweight, self-hosted web application that inspects any public webpage for `<a>` and `<link>` elements containing `rel="me"`. Useful for verifying IndieWeb, Mastodon, and Fediverse profile links.

Built with zero external `npm` dependencies using native Node.js 20 APIs and vanilla HTML/CSS/JavaScript.

## Features

- **Server-Side Fetching:** Avoids browser CORS restrictions by fetching target HTML on the server.
- **Complete Tag Inspection:** Detects `rel="me"` (including multi-value attributes such as `rel="me nofollow"`) across both `<a>` and `<link>` elements.
- **Relative URL Resolution:** Resolves relative `href` paths against the final inspected URL after redirects.
- **Input Normalisation:** Automatically prepends `https://` if no scheme is entered and supports form submission via the **Enter** key.
- **One-Click Copy:** Copy any extracted `rel="me"` URL directly to your clipboard.
- **Responsive Dark/Light UI:** Adapts automatically to system colour scheme preferences.
- **Hardened Security:** Includes SSRF protection, redirect hop limits, response size caps, request timeouts, CSP headers, and XSS-safe DOM rendering.

## Project Structure

```text
.
├── .dockerignore
├── .env.example
├── docker-compose.yml
├── Dockerfile
├── index.html
├── README.md
└── server.js
```

## Quick Start (Docker Compose)

1. Copy the example environment file and adjust ports if needed:

   ```bash
   cp .env.example .env
   ```

2. Build and start the container:

   ```bash
   docker compose up -d --build
   ```

3. Open `http://localhost:8080` in your browser.

> **Reverse Proxy / PaaS Deployment (e.g. Coolify, Caddy, Nginx):** Point your proxy to container port `3000` (or whichever value you set for `CONTAINER_PORT`). A `/health` endpoint is built in for automated health checks.

## Running Locally (Without Docker)

Requires **Node.js 20** or newer.

```bash
PORT=3000 node server.js
```

Then visit `http://localhost:3000`.

## Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `HOST_PORT` | `8080` | Port exposed on the host machine by Docker Compose. |
| `CONTAINER_PORT` | `3000` | Internal port the Node.js server listens on inside the container. |
| `PORT` | `3000` | Application listening port when running `server.js` directly. |

## API Endpoints

### `GET /api/check`

Fetches the target webpage server-side and returns its raw HTML, HTTP status code, and final resolved URL.

**Query Parameters:**

- `url` (required): The website URL to inspect (e.g. `https://example.com`).

**Example Request:**

```bash
curl "http://localhost:8080/api/check?url=[https://example.com](https://example.com)"
```

**Success Response (`200 OK`):**

```json
{
  "html": "<!doctype html>...",
  "status": 200,
  "finalUrl": "[https://example.com/](https://example.com/)"
}
```

### `GET /health`

Returns `{"status":"ok"}` with HTTP `200` when the server is running.

## Security Details

- **SSRF Protection:** Only `http:` and `https:` protocols are permitted. Hostnames are resolved via DNS before connecting, and all loopback, private, link-local, CGNAT, multicast, and reserved IPv4/IPv6 ranges are blocked across initial requests and redirects.
- **Resource Limits:** Upstream requests time out after 10 seconds, follow at most 5 redirects, verify HTML/XML-compatible `Content-Type` headers, and abort if the response exceeds 2 MB.
- **XSS Prevention:** Extracted attributes and link text are rendered exclusively via safe DOM APIs (`textContent`) rather than `innerHTML`, and non-HTTP(S) schemes are prevented from rendering as clickable anchors.
- **Container Hardening:** Runs as the unprivileged `node` user with a read-only root filesystem and `no-new-privileges` enabled.
