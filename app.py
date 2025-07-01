from flask import Flask, request, Response, jsonify, make_response
from markupsafe import escape
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a strong secret in production

# Helper: Check credentials
def check_auth(username, password):
    return username == 'admin' and password == 'password'

# JWT-required decorator
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    data = request.json or request.form
    username = data.get('username')
    password = data.get('password')
    if not check_auth(username, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = jwt.encode({
        'user': username,
    }, app.config['SECRET_KEY'], algorithm="HS256")
    resp = make_response(jsonify({'message': 'Login successful'}))
    resp.set_cookie('jwt', token, httponly=True, samesite='Lax')
    return resp

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

@app.route('/dashboard')
@jwt_required
def dashboard():
    token = request.cookies.get('jwt')
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        username = payload.get('user', 'Unknown')
    except Exception:
        username = 'Unknown'
    return f"Welcome to your dashboard, {escape(username)}!"

if __name__ == '__main__':
    app.run(port=5000, debug=True)
