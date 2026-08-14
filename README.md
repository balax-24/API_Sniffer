# API Sniffer Pro

> **Advanced API discovery panel for Chrome DevTools** — Live capture, cURL (standard & optimized), HAR 1.2 export, multi-language code generation, deep search, replay, and more.

![Version](https://img.shields.io/badge/version-2.1.0-blue)
![Manifest](https://img.shields.io/badge/manifest-v3-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

##  Overview

**API Sniffer Pro** is a powerful Chrome DevTools extension that transforms your browser into a professional API debugging and discovery tool. Built as a DevTools panel, it captures every network request in real-time and provides rich inspection, export, and analysis capabilities — all without leaving the browser.

Designed for **authorized testing, API development, security research, and debugging workflows**.

---

##  Features

###  Live Capture & Inspection
- **Real-time request logging** — See every XHR/fetch/WebSocket request as it happens
- **Smart filtering** — Filter by method, status, URL, domain, or custom regex
- **Sorting & pagination** — Sort by any column (sequence, method, status, domain, path, size, time) with 250-row pages
- **Request details panel** — Full request/response headers, query params, cookies, and formatted JSON bodies
- **Syntax highlighting** — Color-coded status codes, methods, and JSON

###  Export & Code Generation
| Format | Description |
|--------|-------------|
| **cURL (Standard)** | Full faithful reproduction with all headers |
| **cURL (Optimized)** | Cleaned noise headers, keeps only auth/content/relevant headers |
| **HAR 1.2** | Industry-standard archive format for sharing & tooling |
| **Multi-language** | Python (`requests`/`httpx`), Node (`fetch`/`axios`), Go, Java (`OkHttp`), C# (`HttpClient`), PowerShell, Rust (`reqwest`), PHP, Ruby, Swift (`URLSession`), Kotlin (`khttp`), Dart (`http`), R (`httr`) |

###  Deep Search
- Search **URLs** and **cached response bodies** via regex or plain text
- Configurable body caching (up to 1MB per request)
- Jump directly to matching requests

###  Replay & Testing
- **Single request replay** — Re-fire any captured request with one click
- **Selected batch replay** — Replay multiple requests sequentially
- **cURL copy-to-clipboard** — Instant terminal-ready commands

###  Advanced Controls
- **Deduplication view** — Collapse identical requests (same method + URL)
- **Favorites/Stars** — Mark important requests for quick access
- **Multi-select with bulk actions** — Copy, export, delete multiple entries
- **Host whitelist/blacklist** — Regex-based capture filtering
- **Auto-scroll & auto-start** — Hands-free capture sessions
- **Settings persistence** — All preferences saved to `localStorage`

###  Statistics Dashboard
- Request counts by method, status class (2xx/3xx/4xx/5xx)
- Domain breakdown, total bytes transferred
- Average/median/min/max latency
- Timeline sparkline visualization

###  Keyboard Shortcuts
| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + F` | Focus filter input |
| `Ctrl/Cmd + S` | Toggle recording |
| `1–6` | Switch tabs (Log, Detail, cURL, HAR, Stats, Settings) |
| `D` | Toggle deduplication view |
| `Esc` | Close modals |

---

##  Installation

### Option 1: Load Unpacked (Development)
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `v2` folder (containing `manifest.json`)
5. Open DevTools (`F12`) → Find **"API Sniffer"** tab in the panel drawer

### Option 2: Chrome Web Store (Coming Soon)
*Packaged release will be published to the Chrome Web Store.*
---

##  Usage Guide

### Getting Started
1. Open DevTools (`F12` or `Ctrl+Shift+I`)
2. Click the **»** (more tabs) button in the DevTools toolbar
3. Select **API Sniffer** from the dropdown
4. The panel opens — recording starts automatically (configurable in Settings)

### Capturing Requests
- **Start/Stop** — Click the green  Start / red ■ Stop buttons
- **Clear** —  Clear removes all captured entries
- **Filter** — Type in the filter box (supports regex: `api\/v\d+`)
- **Domain filter** — Quick-filter by domain via the dropdown

### Inspecting a Request
1. Click any row in the log table
2. Switch to the **Detail** tab (or press `2`)
3. View:
   - **Request**: Method, URL, Headers, Query Params, Cookies, Body
   - **Response**: Status, Headers, Body (auto-formatted JSON/XML/HTML)

### Exporting
| Tab | Shortcut | Exports |
|-----|----------|---------|
| **cURL** | `3` | Standard & optimized cURL for selected request |
| **HAR** | `4` | HAR 1.2 for single entry or all captured entries |
| **Code** | — | 15+ language snippets via the **Code** button in Detail |

### Deep Search
1. Click ** Search** in the toolbar
2. Enter regex or plain text (e.g., `accessToken\|apiKey\|Bearer`)
3. Results show URL matches and body matches (if body caching enabled)
4. Click a result to jump to that request

### Replay
- **Detail tab** → ** Replay** button re-fires the exact request
- **Bulk bar** (appears when multi-selecting) → **Replay Selected**

### Favorites
- Click the ★ column in the log table to star/unstar
- Filter to "★ Only" via the filter dropdown
---

##  Configuration (Settings Tab)

Access via ** Settings** button or press `6`.

### Capture Settings
| Setting | Default | Description |
|---------|---------|-------------|
| Auto-start recording |  On | Begin capturing immediately when panel opens |
| Max entries kept | 10,000 | Memory cap — oldest entries dropped first |
| Deduplicate identical requests | Off | Skip logging if method+URL+body match recent entry |
| Auto-scroll to newest |  On | Keep view pinned to latest request |
| Host whitelist (regex) | Empty | Only capture matching hosts (e.g., `api\.|example\.com`) |
| Host blacklist (regex) | Empty | Exclude matching hosts (e.g., `google-analytics|doubleclick`) |

### cURL Generation
| Setting | Default | Description |
|---------|---------|-------------|
| Noise headers to skip | `accept-encoding, content-length, sec-ch-ua*, sec-fetch-*, priority` | Headers removed from **both** standard & optimized cURL |
| Optimized keep-headers | `authorization, cookie, content-type, accept, accept-language, x-api-key, x-auth-token, x-csrf-token, referer, origin, user-agent, x-requested-with` | Only these headers kept in **optimized** mode |
| Default `--insecure` | Off | Add `-k` flag to skip TLS verification |
| Default single-line output | Off | Compact cURL without line continuations |

### Deep Search
| Setting | Default | Description |
|---------|---------|-------------|
| Cache response bodies | Off | Enable to search inside response bodies (memory intensive) |
| Max body chars cached | 50,000 | Truncate cached bodies to this length per request |

### Danger Zone
- **Wipe localStorage** — Clears all settings, favorites, and snapshots
---

##  Project Structure

```
v2/
├── manifest.json      # Manifest V3 configuration
├── devtools.html      # DevTools entry point
├── devtools.js        # Panel registration
├── panel.html         # Main panel UI (HTML + embedded CSS)
── panel.js           # Core logic (capture, UI, export, search, replay)
```

### Key Technical Details
- **Manifest V3** — Service worker compatible, no background page
- **DevTools Protocol** — Uses `chrome.devtools.network.onRequestFinished` for capture
- **HAR 1.2** — Full spec compliance with timings, headers, cookies, content
- **localStorage persistence** — Settings, favorites, and last session snapshot survive reloads
- **Zero dependencies** — Pure vanilla JS/HTML/CSS (~50KB total)

---

##  Development

### Prerequisites
- Chrome/Chromium 88+
- Basic knowledge of Chrome Extensions & DevTools Protocol

### Making Changes
1. Edit files in `v2/`
2. Go to `chrome://extensions/`
3. Click **Refresh** on the API Sniffer Pro card
4. Reopen DevTools panel to see changes

### Debugging
- Errors appear in a **red banner** at the top of the panel (click to copy)
- Check DevTools console for `[API Sniffer Pro]` logs
- `chrome.devtools.panels` API limitations apply (no `console.log` in devtools.js context)

---

##  Security & Ethics

> ** Important**: This tool captures **all** network traffic including authentication tokens, cookies, and sensitive data.

- **Use only on systems you own or have explicit authorization to test**
- **Never share HAR files or cURL commands containing secrets** without redacting them
- **Clear captured data** after testing sessions ( Clear button)
- **Disable body caching** when not actively searching to minimize memory exposure
- **Host blacklist** can exclude known tracking/analytics domains

The extension runs entirely locally — **no data leaves your browser**.

---

##  License

MIT License — See [LICENSE](LICENSE) for details.

---

##  Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Ideas for Contributions
- [ ] WebSocket frame capture & inspection
- [ ] GraphQL query/variables parsing
- [ ] Request/response diffing
- [ ] Export to Postman/Insomnia collections
- [ ] Custom header profiles for cURL
- [ ] Dark/light theme toggle (beyond current dark-only)
- [ ] i18n support

---

##  Acknowledgments

- Chrome DevTools Protocol & Extensions APIs
- HAR 1.2 Specification
- The open-source API testing community

---

##  Support

- **Issues**: [GitHub Issues](https://github.com/balax-24/API_Sniffer/issues)
- **Discussions**: [GitHub Discussions](https://github.com/balax-24/API_Sniffer/discussions)

---

<p align="center">
  <strong>Made with ❤️ for API developers and security researchers</strong>
</p>