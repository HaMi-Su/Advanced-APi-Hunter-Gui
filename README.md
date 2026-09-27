# 🔍 Advanced API Endpoint Finder & Deep Security Scanner 🚀

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GUI Framework](https://img.shields.io/badge/GUI-Tkinter-orange)
![Developer](https://img.shields.io/badge/Developer-Hami__Super__user-brightgreen)

An advanced Python-based GUI application designed for security researchers, penetration testers, and developers to discover hidden API endpoints, GraphQL routes, and dynamic AJAX requests from websites.

It combines **Dynamic Interception** (using Playwright headless browser automation) with a **Multithreaded Deep Static Scanner** (using regex-based parsing on HTML and external JS bundles).

---

## ✨ Features

- 🌐 **Dynamic Network Interception**: Captures runtime `fetch`, `XHR`, `WebSocket`, and `GraphQL` traffic directly from the browser context.
- ⚡ **Multi-engine Browser Fallback**: Automatically tries Chromium, system Chrome, and Microsoft Edge.
- 📜 **Deep Static Analysis**: Scans main HTML and multithreadedly fetches external JS bundles to parse endpoints using complex regex patterns.
- 🎯 **Interactive GUI**: Built using Tkinter with a clean two-tab interface for findings and live execution logs.
- 📋 **Context Menu**: Right-click to copy selected endpoint URLs directly to clipboard.
- 📊 **Export Capability**: Save all discovered endpoints along with Method, Type, and HTTP Status Code directly to a CSV file.

---

## 🛠️ Installation & Requirements

### Dependencies (`requirements.txt`)
- `requests>=2.31.0`
- `beautifulsoup4>=4.12.0`
- `playwright>=1.40.0`

### Setup Instructions

1. **Clone the Repository**:
   ```bash[
   https://github.com/HaMi-Su/Advanced-APi-Hunter-Gui.git
   cd api-endpoint-finder
    

---

## 👨‍💻 Developer Information

- **Developer:** Hami_Super_user
- **Role:** Security Researcher & Python Developer

---

## 💖 Donate & Support


- ☕ **Buy Me a Coffee:** [buymeacoffee.com/your_username](https://buymeacoffee.com/)
- 🪙 **Crypto / Wallet:** `0x1234567890abcdef...`

---

## ⚠️ Disclaimer

This tool is created for educational and authorized security assessment purposes only. Unauthorized testing against target websites without prior consent is strictly prohibited.
