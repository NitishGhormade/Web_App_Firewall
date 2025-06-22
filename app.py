from flask import Flask, request, abort, g
from urllib.parse import unquote, quote
import html

app = Flask(__name__)

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
        elif quote(sql) in query.lower():
            return True
    return False

def Check_XSS(query):
    if not query:
        return False
    xss_tags = [
        "<script", "<iframe", "<svg", "<object", "<embed", "<link", "<style", "javascript", "alert", "confirm", "prompt"
    ]
    # Blocked tags above; now handle specific attributes for other tags
    dangerous_tag_attrs = {
        "<img": ["onerror", "onload", "src", "style"],
        "<a": ["href", "onclick", "onmouseover"],
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
        elif quote(tag) in lower_query:
            return True
    # Step 2: For each tag in dangerous_tag_attrs, if tag and any dangerous attribute are present, block
    for tag, attrs in dangerous_tag_attrs.items():
        if tag in lower_query or quote(tag) in lower_query:
            for attr in attrs:
                if attr in lower_query or quote(attr) in lower_query:
                    return True
    return False

def Check_Header_Injection():
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
        if header in request.headers:
            return True
    return False

@app.before_request
def waf():
    encoded_query_string = request.query_string.decode() # Byte String Converted into a String using decode() :- b'1%27' => 1%27
    decoded_query_string = unquote(encoded_query_string) # decoded_query_string: 1'

    if Check_Header_Injection():
        abort(403)
    if Check_SQLi(decoded_query_string): # DO Changes in SQLi
        abort(403)
    if Check_XSS(decoded_query_string):
        abort(403)


@app.route('/')
def home():
    return html_encode("Hello, this is your web app!")

@app.route('/search')
def search():
    query = request.args.get('q')
    escaped_query = html_encode(query)
    return f"You searched for: {escaped_query}"

@app.route('/<path:any_path>')
def all_paths(any_path):
    escaped_path = html_encode(any_path)
    return f"You visited: /{escaped_path}"

if __name__ == '__main__':
    app.run(debug=True)