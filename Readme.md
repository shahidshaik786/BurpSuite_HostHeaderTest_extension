# Burp Suite Extension – Host Header Repeater Variants

## 📌 Overview
This Burp Suite extension automates **Host Header Injection testing** by generating common variants of `Host` and proxy-related headers.  
Instead of manually editing requests each time, you can right-click a request in Burp and instantly send a full set of crafted variants to **Repeater** for analysis.

This helps penetration testers quickly identify:
- **Host Header Injection vulnerabilities**
- **Cache poisoning issues**
- **Open redirect misconfigurations**
- **Virtual host / upstream routing flaws**

---

## ⚡ Features
- Adds a **context menu** in Burp:  
  *“Send Host-Header Test Variants to Repeater”*.
- Generates multiple test cases automatically, including:
  - Replace `Host` with attacker value
  - Duplicate `Host` headers
  - Add `X-Forwarded-Host`, `X-Original-Host`, `X-Host`, `X-Forwarded-Server`
  - Add `Forwarded: for=…;host=…;proto=…`
  - Add `X-Forwarded-For` chain (`127.0.0.1, 10.0.0.1`)
  - Force `X-Forwarded-Proto: http`
  - Absolute-URL request line (`GET http://host/...`)
  - Trailing-dot hostnames (`example.com.`)
  - Alternate ports (`example.com:81`, `:8080`, etc.)
  - Remove `Host` header entirely
- Each variant appears in **Repeater** as a new tab, prefixed with `[HH]`.

---

## 🔧 Installation
1. Clone or download this repository.
2. Open **Burp Suite → Extender → Extensions**.
3. Click **Add**:
   - **Extension type:** Python
   - **Extension file:** `host_header_repeater_variants.py`
4. Confirm the extension loads (Burp Extender console shows:  
   `"[+] Host Header Repeater Variants loaded"`).

⚠️ Requires **Jython standalone JAR** configured in Burp Extender.

---

## 🚀 Usage
1. In Burp, capture or send a request to **Repeater / Proxy / Target**.
2. Right-click the request →  
   **Send Host-Header Test Variants to Repeater**.
3. Check **Repeater tabs**:  
   You’ll see `[HH]` prefixed requests, each with different Host/Header manipulations.
4. Compare responses:
   - Look for your injected host (`evil-attacker.example`) reflected in **response body**, **redirects**, or **headers**.
   - Check for status code changes, cache indicators, or misrouting.

---

## 🔍 What to Look For
- **Reflections**:  
  `Location`, `Content-Location`, `Set-Cookie`, HTML links containing your injected domain.
- **Redirects**:  
  If spoofed hosts cause 30x redirects.
- **Cache poisoning**:  
  Responses cached with your injected host value.
- **Protocol/port quirks**:  
  `X-Forwarded-Proto: http` causing insecure content, or alt-ports leading to bypass.

---

## 🛠 Customization
- Change the test domain inside the script:  
  ```python
  EVIL_HOST = "evil-attacker.example"
