from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to the protected backend app!"

@app.route('/search')
def search():
    q = request.args.get('q', '')
    return f"You searched for: {escape(q)}"

@app.route('/echo', methods=['POST'])
def echo():
    data = request.get_data(as_text=True)
    return f"Echo: {data}"

if __name__ == '__main__':
    app.run(port=5000, debug=True)
