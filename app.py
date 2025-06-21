from flask import Flask, request, abort

app = Flask(__name__)

def Check_SQLi(query):
    SQLi_patterns = [
    "'", "--", "#", ";", " or ", "exec"
]
    for i in SQLi_patterns:
        if i in query.lower():
            return True
    return False

@app.before_request
def waf():
    query = request.query_string.decode()
    if Check_SQLi(query):
        abort(403)


@app.route('/')
def home():
    return "Hello, this is your web app!"

@app.route('/<path:any_path>')
def all_paths(any_path):
    return f"You visited: /{any_path}"

if __name__ == '__main__':
    app.run(debug=True)