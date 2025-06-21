from flask import Flask, request, abort
from urllib.parse import unquote, quote

app = Flask(__name__)

def Check_SQLi(query):
    SQLi_patterns = [
        "'", "%27",  # single quote
        '"', "%22",   # double quote
        "--", "%2D%2D",  # comment
        "#", "%23",   # comment
        ";", "%3B",  # semicolon
        " ", "%20",  # space
        "exec", "%65%78%65%63",  # exec keyword (basic encoding)
        "select", "%73%65%6c%65%63%74",  # select keyword (basic encoding)
        "from", "%66%72%6f%6d",  # from keyword (basic encoding)
        "where", "%77%68%65%72%65",  # where keyword (basic encoding)
        "and", "%61%6e%64",  # and keyword (basic encoding)
        "or", "%6f%72",  # or keyword (basic encoding)
        "not", "%6e%6f%74",  # not keyword (basic encoding)
        "in", "%69%6e",  # in keyword (basic encoding)
        "union", "%75%6e%69%6f%6e",  # union keyword (basic encoding)
    ]
    for i in SQLi_patterns:
        if i in query.lower():
            return True
    return False

@app.before_request
def waf():
    raw_query = request.query_string.decode() # raw_query: 1%27
    encoded_query = unquote(raw_query) # encoded_query: 1'
    if Check_SQLi(raw_query) or Check_SQLi(encoded_query):
        abort(403)

@app.route('/')
def home():
    return "Hello, this is your web app!"

@app.route('/<path:any_path>')
def all_paths(any_path):
    return f"You visited: /{any_path}"

if __name__ == '__main__':
    app.run(debug=True)