from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from urllib.parse import urlparse, unquote
import html

# --- Security Logic (reuse your functions, slightly refactored) ---

def html_encode(s):
    return html.escape(s)

def Check_SQLi(query):
    if not query:
        return False
    SQLi_patterns = [
        "'", '"', "--", "#", ";", " ", "exec", "select", "from", "where", "and", "or", "not", "in", "union"
    ]
    for sql in SQLi_patterns:
        if sql in query.lower():
            return True
        elif requests.utils.quote(sql) in query.lower():
            return True
    return False

def Check_XSS(query):
    if not query:
        return False
    xss_tags = [
        "<script", "<iframe", "<svg", "<object", "<embed", "<link", "<style", "javascript", "alert", "confirm", "prompt"
    ]
    dangerous_tag_attrs = {
        "<img": ["onerror", "onload"],
        "<a": ["onclick", "onmouseover"],
        "<body": ["onload", "onerror", "onresize"],
        "<video": ["onerror", "onload", "src"],
        "<audio": ["onerror", "onload", "src"],
        "<form": ["action", "onsubmit"],
        "<input": ["onfocus", "onblur", "onchange", "oninput", "value", "autofocus"],
        "<button": ["onclick", "onfocus", "autofocus"],
        "<marquee": ["onstart", "onfinish"],
        "<div": ["onclick", "onmouseover", "onmouseenter", "onmouseleave"],
        "<span": ["onclick", "onmouseover", "onmouseenter", "onmouseleave"],
        "<textarea": ["onfocus", "onblur", "onchange", "oninput", "autofocus"],
        "<select": ["onfocus", "onblur", "onchange", "autofocus"]
    }
    lower_query = query.lower()
    # Step 1: Block if any of the main XSS tags or their encodings are present
    for tag in xss_tags:
        if tag in lower_query:
            return True
        elif requests.utils.quote(tag) in lower_query:
            return True
    # Step 2: For each tag in dangerous_tag_attrs, only block if BOTH tag and at least one dangerous attribute are present
    for tag, attrs in dangerous_tag_attrs.items():
        tag_found = tag in lower_query or requests.utils.quote(tag) in lower_query
        if tag_found:
            for attr in attrs:
                if attr in lower_query or requests.utils.quote(attr) in lower_query:
                    return True
    return False

def Check_Header_Injection(headers):
    suspicious_headers = [
        "X-Real-IP",
        "X-Client-IP",
        "X-Forwarded",
        "X-Remote-Addr",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Server",
        "X-Forwarded-Port",
        "X-Forwarded-Proto",
        "X-Forwarded-Prefix",
    ]
    for header in suspicious_headers:
        if header in headers:
            return True
    return False

# --- Proxy Handler ---

BACKEND = "http://localhost:5000"  # Change to your backend app

class ProxyWAFHandler(BaseHTTPRequestHandler):
    def do_GET(self): # Runs when the request is a GET request
        # Parse and check query string
        parsed = urlparse(self.path)
        decoded_query = unquote(parsed.query)
        if Check_Header_Injection(self.headers) or Check_SQLi(decoded_query) or Check_XSS(decoded_query):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden by WAF")
            return

        # Log the allowed request using file module
        with open('log.txt', 'a', encoding='utf-8') as f:
            f.write(f"ALLOWED GET {self.path} | Headers: {dict(self.headers)}\n")
        # Forward request to backend
        url = BACKEND + self.path
        resp = requests.get(url, headers=self.headers)
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.content)

    def do_POST(self): # Runs when the request is a POST request
        # Similar logic for POST, with body forwarding
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        parsed = urlparse(self.path)
        decoded_query = unquote(parsed.query)
        if Check_Header_Injection(self.headers) or Check_SQLi(decoded_query) or Check_XSS(decoded_query):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden by WAF")
            return

        # Log the allowed request using file module
        with open('log.txt', 'a', encoding='utf-8') as f:
            f.write(f"ALLOWED POST {self.path} | Headers: {dict(self.headers)} | Body: {post_data[:500]}\n")
        url = BACKEND + self.path
        resp = requests.post(url, headers=self.headers, data=post_data)
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.content)

if __name__ == "__main__":
    server_address = ('', 8080)  # Listen on all interfaces, port 8080
    httpd = HTTPServer(server_address, ProxyWAFHandler)
    print("WAF Proxy running on port 8080, forwarding to", BACKEND)
    httpd.serve_forever()