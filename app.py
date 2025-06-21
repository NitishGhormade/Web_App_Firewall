from flask import Flask, request, abort
from urllib.parse import unquote, quote

app = Flask(__name__)

def Check_SQLi(query):
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
        "<script", "<img", "<iframe", "<svg", "<object", "<embed", "<link", "<style"
    ]
    for tag in xss_tags:
        if tag in query.lower():
            return True
        elif quote(tag) in query.lower():
            return True
    return False

@app.before_request
def waf():
    encoded_query_string = request.query_string.decode() # Byte String Converted into a String using decode() :- b'1%27' => 1%27
    decoded_query_string = unquote(encoded_query_string) # decoded_query_string: 1'

    if Check_SQLi(decoded_query_string): # DO Changes in SQLi
        abort(403)
    if Check_XSS(decoded_query_string):
        abort(403)


@app.route('/')
def home():
    return "Hello, this is your web app!"

@app.route('/search')
def search():
    query = request.args.get('q')
    return f"You searched for: {query}"

@app.route('/<path:any_path>')
def all_paths(any_path):
    return f"You visited: /{any_path}"

if __name__ == '__main__':
    app.run(debug=True)