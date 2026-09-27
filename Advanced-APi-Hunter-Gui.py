import asyncio
import csv
import queue
import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import requests
from bs4 import BeautifulSoup

# Check Playwright availability
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class AdvancedAPIFinderGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Advanced API Endpoint Finder & Deep Security Scanner")
        self.geometry("1020x720")
        self.minsize(880, 600)

        # Thread-safe Communication Queue
        self.log_queue = queue.Queue()
        self.is_running = False

        # Master Advanced API & Secret Regex Patterns
        self.api_patterns = [
            r'https?://[^\s\'"<>]+(?:/api/|/v\d+/|/graphql)[^\s\'"<>]*',
            r'https?://api\.[^\s\'"<>]+',
            r'["\'](/api/v\d+/[^\s\'"<>]+)["\']',
            r'["\'](/api/[^\s\'"<>]+)["\']',
            r'["\'](/v\d+/[^\s\'"<>]+)["\']',
            r'["\']([^\s\'"<>]+\.json(?:\?[^\s\'"<>]*)?)["\']',
            r'["\'](/graphql[^\s\'"]*)["\']',
            r'fetch\s*\(\s*["\']([^"\'\s]+)["\']',
            r'axios(?:\.get|\.post|\.put|\.delete|\.request)?\s*\(\s*["\']([^"\'\s]+)["\']',
            r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\'\s]+)["\']',
            r'endpoint\s*:\s*["\']([^"\'\s]+)["\']',
            r'url\s*:\s*["\']([^"\'\s]+)["\']'
        ]

        self._setup_ui()
        self._check_queue()

    def _setup_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Top Control Frame
        control_frame = ttk.LabelFrame(self, text=" Target & Scan Engine Configuration ", padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(control_frame, text="Target URL:").grid(row=0, column=0, sticky="w", padx=5)
        self.url_entry = ttk.Entry(control_frame, width=55)
        self.url_entry.insert(0, "https://tikup.me/en/download-caption/")
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=5)

        # Scan Mode Selections
        self.scan_mode = tk.StringVar(value="dynamic")
        
        ttk.Radiobutton(
            control_frame, text="Dynamic Interception (Playwright Browser)", variable=self.scan_mode, value="dynamic"
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=(5, 0))

        ttk.Radiobutton(
            control_frame, text="Deep Static Extraction (Multithreaded JS/HTML Scan)", variable=self.scan_mode, value="static"
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=(2, 0))

        # Control Action Buttons
        self.btn_start = ttk.Button(control_frame, text="Start Deep Scan", command=self.start_scan)
        self.btn_start.grid(row=0, column=2, padx=5)

        self.btn_stop = ttk.Button(control_frame, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_stop.grid(row=0, column=3, padx=5)

        self.btn_export = ttk.Button(control_frame, text="Export CSV", command=self.export_csv)
        self.btn_export.grid(row=0, column=4, padx=5)

        control_frame.columnconfigure(1, weight=1)

        # Progress Status
        status_frame = ttk.Frame(self, padding=(10, 2))
        status_frame.pack(fill="x")

        self.progress = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress.pack(fill="x", side="top", pady=2)

        self.lbl_status = ttk.Label(status_frame, text="Ready", font=("Helvetica", 9, "italic"))
        self.lbl_status.pack(side="left")

        # Display Tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Tab 1: Discovered Endpoints TreeView
        tab_results = ttk.Frame(notebook)
        notebook.add(tab_results, text="Discovered Endpoints")

        columns = ("method", "url", "type", "status")
        self.tree = ttk.Treeview(tab_results, columns=columns, show="headings", selectmode="extended")

        self.tree.heading("method", text="Method")
        self.tree.heading("url", text="API Endpoint URL")
        self.tree.heading("type", text="Type / Source")
        self.tree.heading("status", text="Status Code")

        self.tree.column("method", width=90, anchor="center")
        self.tree.column("url", width=620, anchor="w")
        self.tree.column("type", width=140, anchor="center")
        self.tree.column("status", width=90, anchor="center")

        tree_scroll = ttk.Scrollbar(tab_results, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        # Right-click context menu to copy URL
        self.tree_menu = tk.Menu(self, tearoff=0)
        self.tree_menu.add_command(label="Copy Endpoint URL", command=self._copy_selected_url)
        self.tree.bind("<Button-3>", self._show_context_menu)

        # Tab 2: Activity Logs Console
        tab_logs = ttk.Frame(notebook)
        notebook.add(tab_logs, text="Live Log Console")

        self.txt_log = tk.Text(tab_logs, wrap="word", font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4")
        log_scroll = ttk.Scrollbar(tab_logs, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=log_scroll.set)

        self.txt_log.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")

    def log(self, message):
        """Send logs to GUI queue from background threads safely."""
        self.log_queue.put(("LOG", message))

    def add_endpoint(self, method, url, res_type, status):
        """Send discovered API payload to GUI queue."""
        self.log_queue.put(("RESULT", (method, url, res_type, status)))

    def _check_queue(self):
        """Consume log/result events for non-blocking UI rendering."""
        while not self.log_queue.empty():
            msg_type, payload = self.log_queue.get()

            if msg_type == "LOG":
                self.txt_log.insert(tk.END, payload + "\n")
                self.txt_log.see(tk.END)
            elif msg_type == "RESULT":
                method, url, res_type, status = payload
                existing_urls = [self.tree.item(item)["values"][1] for item in self.tree.get_children()]
                if url not in existing_urls:
                    self.tree.insert("", tk.END, values=(method, url, res_type, status))
            elif msg_type == "STATUS":
                self.lbl_status.config(text=payload)
            elif msg_type == "FINISHED":
                self._reset_ui_state()

        self.after(100, self._check_queue)

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.tree_menu.post(event.x_root, event.y_root)

    def _copy_selected_url(self):
        selected = self.tree.selection()
        if selected:
            url = self.tree.item(selected[0])["values"][1]
            self.clipboard_clear()
            self.clipboard_append(url)
            messagebox.showinfo("Copied", "Endpoint URL copied to clipboard.")

    def export_csv(self):
        items = self.tree.get_children()
        if not items:
            messagebox.showwarning("No Data", "No endpoints discovered to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Method", "API Endpoint URL", "Type/Source", "Status Code"])
                    for item in items:
                        writer.writerow(self.tree.item(item)["values"])
                messagebox.showinfo("Success", f"Exported {len(items)} endpoints successfully!")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save file: {str(e)}")

    def start_scan(self):
        target_url = self.url_entry.get().strip()
        if not target_url.startswith(("http://", "https://")):
            messagebox.showerror("Invalid URL", "Please enter a valid target URL starting with http:// or https://")
            return

        mode = self.scan_mode.get()
        if mode == "dynamic" and not PLAYWRIGHT_AVAILABLE:
            messagebox.showerror("Dependency Error", "Playwright is missing. Install using:\npip install playwright && playwright install")
            return

        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.progress.start(10)

        # Reset Previous Run
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.txt_log.delete("1.0", tk.END)

        threading.Thread(target=self._run_scan_thread, args=(target_url, mode), daemon=True).start()

    def stop_scan(self):
        if self.is_running:
            self.is_running = False
            self.log("[!] Stop signal sent. Cleaning up background tasks...")
            self.lbl_status.config(text="Stopping...")

    def _reset_ui_state(self):
        self.is_running = False
        self.progress.stop()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.log_queue.put(("STATUS", "Idle"))

    def _run_scan_thread(self, target_url, mode):
        self.log_queue.put(("STATUS", f"Scanning: {target_url}"))
        self.log(f"[*] Starting {mode.upper()} scan on {target_url}")

        try:
            if mode == "dynamic":
                asyncio.run(self._deep_dynamic_scan(target_url))
            else:
                self._deep_static_scan(target_url)
        except Exception as e:
            self.log(f"[FATAL SCAN ERROR] {str(e)}")

        self.log("[*] Scan execution cycle completed.")
        self.log_queue.put(("FINISHED", None))

    # --- Deep Dynamic Engine (Playwright with Fallback & Interception) ---

    async def _deep_dynamic_scan(self, target_url):
        async with async_playwright() as p:
            self.log("[*] Initializing Playwright browser instance...")

            launch_args = [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled"
            ]

            browser = None
            # Launch Strategy: Downloaded Chromium -> Installed Chrome -> Installed Edge
            try:
                browser = await p.chromium.launch(headless=True, args=launch_args)
                self.log("[*] Successfully launched Playwright Chromium.")
            except Exception as e1:
                self.log(f"[!] Playwright Chromium launch failed ({str(e1)}). Trying local Chrome...")
                try:
                    browser = await p.chromium.launch(channel="chrome", headless=True, args=launch_args)
                    self.log("[*] Successfully launched System Chrome.")
                except Exception as e2:
                    self.log(f"[!] System Chrome launch failed ({str(e2)}). Trying Microsoft Edge...")
                    try:
                        browser = await p.chromium.launch(channel="msedge", headless=True, args=launch_args)
                        self.log("[*] Successfully launched MS Edge.")
                    except Exception as e3:
                        self.log(f"[FATAL] Could not launch any browser engine: {str(e3)}")
                        return

            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

            page = await context.new_page()

            # Network Response Hook
            async def handle_response(response):
                if not self.is_running:
                    return

                req = response.request
                res_type = req.resource_type
                url = response.url

                # Filtering criteria for API traffic
                if res_type in ["fetch", "xhr", "websocket", "eventsource"] or \
                   any(key in url.lower() for key in ["/api/", "api.", "/v1/", "/v2/", "/graphql", ".json"]):

                    self.add_endpoint(
                        method=req.method,
                        url=url,
                        res_type=res_type.upper(),
                        status=response.status
                    )
                    self.log(f"[FOUND DYNAMIC API] {req.method} -> {url} ({response.status})")

            page.on("response", handle_response)

            try:
                self.log("[*] Opening target page (DOM Content Loaded mode)...")
                # Prevents hanging indefinitely on continuous ping requests
                await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)

                self.log("[*] Waiting for initial AJAX/Fetch requests (4s)...")
                await page.wait_for_timeout(4000)

                # Simulate User Interaction (Scrolling & Button Clicks)
                self.log("[*] Simulating deep user interactions (Scrolls & Triggering Inputs)...")
                for i in range(3):
                    if not self.is_running:
                        break
                    await page.evaluate("window.scrollBy(0, 800)")
                    await page.wait_for_timeout(1500)

                # Attempt clicking visible dynamic buttons to trigger AJAX APIs
                buttons = await page.query_selector_all("button, input[type='submit']")
                self.log(f"[*] Triggering potential interactive UI elements ({len(buttons)} found)...")
                for btn in buttons[:5]:  # Limit to 5 elements to avoid stuck state
                    if not self.is_running:
                        break
                    try:
                        if await btn.is_visible():
                            await btn.click(timeout=1000)
                            await page.wait_for_timeout(1000)
                    except Exception:
                        pass

            except Exception as e:
                self.log(f"[DYNAMIC ENGINE ERROR] {str(e)}")
            finally:
                await browser.close()

    # --- Fast Parallel Deep Static Engine ---

    def _deep_static_scan(self, target_url):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        try:
            self.log("[*] Fetching primary HTML document...")
            res = requests.get(target_url, headers=headers, timeout=12)
            if res.status_code != 200:
                self.log(f"[!] Target returned non-200 HTTP status: {res.status_code}")

            html_text = res.text
            soup = BeautifulSoup(html_text, "html.parser")

            # 1. Inspect Main Document HTML & Inline Scripts
            self.log("[*] Parsing main HTML document & inline <script> blocks...")
            self._extract_regex_endpoints(html_text, target_url, "HTML Source")

            # 2. Extract external script assets
            script_urls = set()
            for s in soup.find_all("script", src=True):
                full_js_url = urljoin(target_url, s["src"])
                script_urls.add(full_js_url)

            self.log(f"[*] Extracted {len(script_urls)} external JS bundles. Starting multithreaded deep inspection...")

            # 3. Multithreaded inspection worker for JS assets
            def inspect_js_file(js_url):
                if not self.is_running:
                    return
                try:
                    js_res = requests.get(js_url, headers=headers, timeout=8)
                    if js_res.status_code == 200:
                        self.log(f"[*] Deep scanning bundle: {js_url.split('/')[-1]}")
                        self._extract_regex_endpoints(js_res.text, target_url, "JS Bundle")
                except requests.RequestException:
                    pass

            with ThreadPoolExecutor(max_workers=8) as executor:
                executor.map(inspect_js_file, script_urls)

        except Exception as e:
            self.log(f"[STATIC ENGINE ERROR] {str(e)}")

    def _extract_regex_endpoints(self, content, base_url, source_label):
        """Parse source text against all target API regex rules."""
        for pattern in self.api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                clean_path = match.strip("'\"")
                
                # Resolve full URL
                full_url = urljoin(base_url, clean_path)

                # Skip non-API visual static assets false positives
                if any(full_url.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".css", ".svg", ".woff", ".woff2", ".ico"]):
                    continue

                self.add_endpoint("GET/POST", full_url, source_label, "Static")
                self.log(f"[FOUND API] {full_url}")


if __name__ == "__main__":
    app = AdvancedAPIFinderGUI()
    app.mainloop()