# 🔐 Web Application Firewall (WAF)

A lightweight and customizable **Web Application Firewall** that acts as a **reverse proxy** to protect any backend web application from OWASP Top 10 vulnerabilities including **SQL Injection**, **XSS**, **SSTI**, **Host Header Injection**, and **JWT 'none' algorithm attacks**.

---

## 🚀 Features

✅ Acts as a **reverse proxy** for any backend web application  
✅ Detects and blocks **SQL Injection (SQLi)** attempts  
✅ Filters malicious **Cross-Site Scripting (XSS)** payloads  
✅ Prevents **Server-Side Template Injection (SSTI)**  
✅ Secures against **Host Header Injection** attacks  
✅ Validates and rejects **JWT tokens using `none` algorithm**  
✅ Provides **logging** and **alerting** for suspicious activity  
✅ Easy to configure, extend, and integrate

---

## 📌 Technologies Used

- **Python** / Node.js *(your actual stack)*
- **Flask** or **Express** *(depending on your choice)*
- **Regular Expressions (Regex)**
- **HTTP Proxying**
- **JWT Parsing and Validation**

---

## 🛡️ How It Works

1. Intercepts all incoming HTTP requests via reverse proxy
2. Applies multiple security filters on:
   - Query parameters
   - Headers
   - JWT tokens
   - Request body
3. Blocks or logs the request based on rule match
4. Forwards clean traffic to the actual backend server

---

## ⚙️ Setup & Installation

```bash
git clone https://github.com/yourusername/web-app-firewall.git
cd web-app-firewall
pip install -r requirements.txt
python app.py
