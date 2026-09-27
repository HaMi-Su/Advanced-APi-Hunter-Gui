# 🔍 Advanced API Endpoint Finder & Deep Security Scanner 🚀

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GUI Framework](https://img.shields.io/badge/GUI-Tkinter-orange)

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

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone [https://github.com/your-username/api-endpoint-finder.git](https://github.com/your-username/api-endpoint-finder.git)
cd api-endpoint-finder
