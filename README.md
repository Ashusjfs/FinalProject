# 🔒 Web Vulnerability Scanner

A Python-based automated scanner to detect common web application vulnerabilities such as **XSS**, **SQL Injection**, **CSRF**, and **Command Injection** via a simple Flask-powered web interface.

---

## 📌 Features

- 🔍 Detects:
  - Cross Site Scripting (XSS)
  - SQL Injection (SQLi)
  - CSRF (missing token check)
  - Command Injection
- 📄 JSON-based report logging
- 🖥️ Simple and styled HTML interface
- 📁 Exportable PDF project report included

---

## 🧰 Tools & Technologies

- Python 3
- Flask
- Requests
- BeautifulSoup
- FPDF
- HTML & CSS

---

## 🚀 Installation & Usage

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner

pip install -r requirements.txt

pip install flask requests beautifulsoup4 fpdf

python test.py


