import re
from flask import Flask, request, abort

app = Flask(__name__)

# Simple pattern for SQL injection
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL meta-characters
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL meta-characters with =
    r"\w*((\%27)|(\'))(\s)*((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # ' or
    r"exec(\s|\+)+(s|x)p\w+",  # exec sp
]

def is_malicious(query):
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, query, re.IGNORECASE):
            return True
    return False

@app.before_request
def waf():
    # Check query string for malicious patterns
    query = request.query_string.decode()
    if is_malicious(query):
        abort(403)  # Forbidden

@app.route('/')
def home():
    return "Hello, this is your web app!"

if __name__ == '__main__':
    app.run(debug=True)