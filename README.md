# CodeFlow Xray Panel 🌌

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Telegram Channel](https://img.shields.io/badge/Telegram-Channel-blue?style=flat&logo=telegram)](https://t.me/CodeFlowDevs)
[![Web App](https://img.shields.io/badge/Web%20App-Online-brightgreen?style=flat&logo=github)](https://codeflowprime.github.io/xray-toolkit/)

[فارسی (Persian)](README.fa.md)

---

A premium, fully client-side, browser-based clean IP scanner and bulk configuration engine designed for Xray/V2Ray protocols. Beautifully crafted with a dark/light responsive cosmic space theme, modern typography, glassmorphism UI elements, and interactive particle backgrounds.

> **Live Web App:** Run the scanner directly online at **[https://codeflowprime.github.io/xray-toolkit/](https://codeflowprime.github.io/xray-toolkit/)**

> **100% Static & Client-Side:** No database, no backend server, and no server-side processing required. Perfect for hosting on GitHub Pages, Cloudflare Pages, Vercel, or running directly on your computer.

---

## 🌟 Key Features

### 1. ⚡ Browser-Based IP Scanner
Scan CDN IP addresses directly from your browser without using external tools or servers.
- **CDN Providers:** Cloudflare, Arvancloud, Gcore, Fastly, or Custom CIDR ranges.
- **IP Range Checklist:** Dynamically select/deselect specific predefined IP ranges to target scans on preferred ranges.
- **Port Scanner:** Support for major HTTPS/HTTP ports (443, 8443, 2053, 2083, 2096, 80, 8080).
- **Anti-Censorship Filters:** Configurable minimum latency thresholds to filter out fake firewall resets (TCP RSTs).
- **Advanced 3-Phase Network Scanner (Discovery, Validation, Deep Scan):** Dynamically handles dynamic CIDR ranges of any size (from `/32` to `/8`) with mathematical capacity determination, applies Fair Subnet Sampling with budget redistribution to explore subnets, adaptively allocates resources based on quality scores (proportional + exploration pools), filters false-positive ISP resets, and performs a deep latency/stability scan on the top candidate IPs.
- **Multi-Test Stability Scan:** Perform multiple connection checks (1, 2, or 3 times) per IP to ensure zero packet loss and report average latencies.
- **Live Logging Console:** Watch the real-time breakdown of tested ranges and responses directly in the scanner console.
- **High Performance:** Multi-threaded architecture ($O(1)$ lookup matching) capable of generating and scanning up to **50,000** IP candidates instantly.
- **Live Metrics:** Real-time progress bar, latency display, and sortable results.
- **Exporting Options:** Copy working IPs, download as text file, or export directly to the Config Generator.

### 2. 🛠️ Bulk Config Generator / Modifier
Modify or generate hundreds of V2Ray/Xray configs in bulk using clean IP addresses.
- **Protocols Supported:** VLESS, VMESS, Trojan, and WireGuard.
- **Flexible Naming Styles:** Rename your configs dynamically (keep original, fixed custom prefix, sequential numeric suffixes, or random suffixes).
- **Input Methods:**
  - **IP Ranges (CIDR):** Generate configs sequentially from CIDR blocks.
  - **IP List:** Merge a base configuration with a list of clean IP endpoints.
  - **Config List:** Extract IPs from existing configs and merge them into a base configuration.
  - **SNI Spoof Mode:** Fast local SNI spoofing adjustments.
- **Easy Export:** Copy all generated configs or download them as a `.txt` file with one click.

### 3. 🎨 Premium UI/UX Design
- **Cosmic Space Background:** Dynamic drifting nebulae and starfield canvas animation.
- **Flexible Customization:** 4 accent colors (Rose, Blue, Emerald, Purple) and a fully unified Light/Dark mode switcher.
- **Offline Persistence:** Uses an offline-first caching mechanism using local storage, saving your preferences and configuration states.

---

## 🚀 How to Run

### Option A: Run Online (No Installation Required)
Simply open the online GitHub Pages web app:
👉 **[https://codeflowprime.github.io/xray-toolkit/](https://codeflowprime.github.io/xray-toolkit/)**

### Option B: Direct Local Execution
1. Download all files from this repository to your computer.
2. Locate the **`index.html`** file.
3. Double-click it to open it in any modern web browser.
4. The application runs entirely on your local machine with zero dependencies.

### Option C: Local Web Server (Optional)
If you prefer to run it via a local web server (e.g., to test on mobile devices connected to the same local network):
```bash
python3 -m http.server 8080
```
Open [http://localhost:8080](http://localhost:8080) in your browser.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Built By
Crafted with ❤️ by the **[CodeFlow Team](https://t.me/CodeFlowDevs)**. Join our Telegram channel for updates, tools, and discussions.
