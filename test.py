# web_vuln_scanner.py

from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
import re

app = Flask(__name__)

# --- Helper functions ---

def get_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def check_xss(url):
    forms = get_forms(url)
    js_script = "<script>alert(1)</script>"
    results = []
    for form in forms:
        form_details = get_form_details(form)
        data = {}
        for input in form_details["inputs"]:
            if input["name"]:
                data[input["name"]] = js_script
        target_url = urljoin(url, form_details["action"])
        if form_details["method"] == "post":
            res = requests.post(target_url, data=data)
        else:
            res = requests.get(target_url, params=data)
        if js_script in res.text:
            log_vulnerability("XSS", target_url, js_script)
            results.append(f"[+] XSS Found at {target_url}")
    return "\n".join(results) if results else "[-] No XSS detected."

def check_sqli(url):
    sqli_payloads = ["' OR '1'='1", "' OR 1=1 -- ", "\" OR \"1\"=\"1"]
    results = []
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in sqli_payloads:
            data = {}
            for input in form_details["inputs"]:
                if input["name"]:
                    data[input["name"]] = payload
            target_url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = requests.post(target_url, data=data)
            else:
                res = requests.get(target_url, params=data)
            if check_sqli_errors(res):
                log_vulnerability("SQLi", target_url, payload)
                results.append(f"[+] SQLi Found at {target_url} with payload: {payload}")
                break
    return "\n".join(results) if results else "[-] No SQLi detected."

def check_sqli_errors(response):
    errors = [
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
    ]
    for error in errors:
        if re.search(error, response.text, re.IGNORECASE):
            return True
    return False

def check_csrf(url):
    forms = get_forms(url)
    results = []
    for form in forms:
        form_details = get_form_details(form)
        has_csrf_token = any('csrf' in input['name'].lower() for input in form_details['inputs'] if input['name'])
        if not has_csrf_token and form_details['method'] == 'post':
            target_url = urljoin(url, form_details['action'])
            log_vulnerability("CSRF", target_url, "No CSRF token found in form")
            results.append(f"[+] CSRF vulnerability: No CSRF token found at {target_url}")
    return "\n".join(results) if results else "[-] No CSRF issues found."

def check_cli_injection(url):
    cli_payloads = ["; ls", "&& whoami", "| id"]
    results = []
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for payload in cli_payloads:
            data = {}
            for input in form_details["inputs"]:
                if input["name"]:
                    data[input["name"]] = payload
            target_url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = requests.post(target_url, data=data)
            else:
                res = requests.get(target_url, params=data)
            if "uid=" in res.text or "gid=" in res.text:
                log_vulnerability("Command Injection", target_url, payload)
                results.append(f"[+] Command Injection at {target_url} with payload: {payload}")
                break
    return "\n".join(results) if results else "[-] No CLI injection found."

def log_vulnerability(vuln_type, url, evidence):
    log = {
        "type": vuln_type,
        "url": url,
        "evidence": evidence,
        "severity": "High" if vuln_type in ["SQLi", "Command Injection"] else "Medium"
    }
    with open("scan_report.json", "a") as f:
        f.write(json.dumps(log, indent=2) + "\n")

# --- Flask Routes ---

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            xss_result = check_xss(url)
            sqli_result = check_sqli(url)
            csrf_result = check_csrf(url)
            cli_result = check_cli_injection(url)
            result = f"Scan Results for {url}:\n\n" + xss_result + "\n\n" + sqli_result + "\n\n" + csrf_result + "\n\n" + cli_result
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
