from flask import Flask, render_template, redirect, url_for, request, session, jsonify, abort, send_file
from io import BytesIO
import sqlite3
from db import db
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.exc import OperationalError as SAOperationalError
import os
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from passlib.context import CryptContext
from passlib.exc import UnknownHashError


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///movies.db'  # Sử dụng SQLite cho đơn giản
app.config['JWT_SECRET_KEY'] = 'change_this_jwt_secret'  # replace in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
db.init_app(app)
login_manager = LoginManager(app)
JWTManager(app)
CORS(app, supports_credentials=True)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Import models
with app.app_context():
    from My_Model import User, Movie, Seat, Ticket

# Khai báo hàm user_loader cho Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Tạo trang chủ
@app.route('/')
def index():
    movies = Movie.query.all()  # Lấy tất cả phim từ cơ sở dữ liệu
    return render_template('index.html', movies=movies)

# Đăng ký người dùng mới
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash password for users registered via web form
        hashed_pw = pwd_context.hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        try:
            db.session.commit()
        except SAOperationalError as e:
            # If the user table lacks 'is_admin' column, add it and retry
            msg = str(e)
            if 'no column named is_admin' in msg or 'has no column named is_admin' in msg:
                try:
                    # Get DB file path from SQLAlchemy engine
                    engine_url = db.engine.url
                    db_path = engine_url.database if hasattr(engine_url, 'database') else None
                    if not db_path:
                        db_path = app.config.get('SQLALCHEMY_DATABASE_URI', '').replace('sqlite:///', '')
                    if db_path and os.path.exists(db_path):
                        conn = sqlite3.connect(db_path)
                        cur = conn.cursor()
                        cur.execute("ALTER TABLE user ADD COLUMN is_admin INTEGER DEFAULT 0")
                        conn.commit()
                        cur.close()
                        conn.close()
                        # retry commit
                        db.session.commit()
                        return redirect(url_for('login'))
                except Exception:
                    db.session.rollback()
                    raise
            # re-raise if not handled
            db.session.rollback()
            raise
        return redirect(url_for('login'))

    return render_template('register.html')

# API: register (returns JSON)
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg': 'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'user exists'}), 400
    hashed = pwd_context.hash(password)
    new_user = User(username=username, password=hashed)
    db.session.add(new_user)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'msg': 'db error'}), 500
    access_token = create_access_token(identity=new_user.id)
    refresh_token = create_refresh_token(identity=new_user.id)
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token, 'user': {'id': new_user.id, 'username': new_user.username}}), 201

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        verified = False
        if user:
            try:
                verified = pwd_context.verify(password, user.password)
            except UnknownHashError:
                # legacy/plaintext password stored; try direct compare and upgrade
                if user.password == password:
                    verified = True
                    try:
                        user.password = pwd_context.hash(password)
                        db.session.add(user)
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
        if user and verified:
            login_user(user)
            return redirect(url_for('index'))
        else:
            return 'Invalid credentials'

    return render_template('login.html')
# API: login -> return JWT
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'msg': 'username and password required'}), 400
    user = User.query.filter_by(username=username).first()
    if user and pwd_context.verify(password, user.password):
        token = create_access_token(identity=user.id)
        refresh = create_refresh_token(identity=user.id)
        return jsonify({'access_token': token, 'refresh_token': refresh, 'user': {'id': user.id, 'username': user.username}})
    return jsonify({'msg': 'Bad credentials'}), 401


# API: refresh access token
@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def api_refresh():
    user_id = get_jwt_identity()
    new_token = create_access_token(identity=user_id)
    return jsonify({'access_token': new_token})

# Đăng xuất người dùng
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Xem chi tiết phim và chọn ghế
@app.route('/movie/<int:movie_id>', methods=['GET', 'POST'])
@login_required
def movie_detail(movie_id):
    movie = Movie.query.get_or_404(movie_id)
    seats = Seat.query.filter_by(movie_id=movie.id).all()
    
    if request.method == 'POST':
        selected_seat_ids = request.form.getlist('seats')
        if not selected_seat_ids:
            return redirect(url_for('movie_detail', movie_id=movie.id))

        seat_objs = []
        seat_labels = []
        price_per_seat = 5.0  # cố định giá mỗi ghế; thay đổi theo yêu cầu

        # Kiểm tra và cập nhật trạng thái ghế
        for seat_id in selected_seat_ids:
            seat = Seat.query.get(int(seat_id))
            if not seat or seat.movie_id != movie.id:
                continue
            if seat.status != 'available':
                continue
            seat.status = 'booked'
            seat_objs.append(seat)
            seat_labels.append(seat.seat_number)

        if len(seat_objs) == 0:
            return redirect(url_for('movie_detail', movie_id=movie.id))

        # Tính tổng tiền và tạo Ticket
        total = price_per_seat * len(seat_objs)
        ticket = Ticket(user_id=current_user.id, movie_id=movie.id, seats=','.join(seat_labels), total_price=total)
        db.session.add(ticket)

        # Commit thay đổi ghế và ticket
        try:
            for s in seat_objs:
                db.session.add(s)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return redirect(url_for('movie_detail', movie_id=movie.id))

        return redirect(url_for('ticket_view', ticket_id=ticket.id))
    
    return render_template('movie_detail.html', movie=movie, seats=seats)


# API: list movies
@app.route('/api/movies', methods=['GET'])
def api_movies():
    movies = Movie.query.all()
    out = []
    for m in movies:
        out.append({'id': m.id, 'title': m.title, 'description': m.description, 'image': m.image})
    return jsonify(out)


# API: movie details and seats
@app.route('/api/movie/<int:movie_id>', methods=['GET'])
def api_movie_detail(movie_id):
    m = Movie.query.get_or_404(movie_id)
    seats = Seat.query.filter_by(movie_id=m.id).all()
    seats_out = [{'id': s.id, 'seat_number': s.seat_number, 'status': s.status} for s in seats]
    return jsonify({'id': m.id, 'title': m.title, 'description': m.description, 'image': m.image, 'seats': seats_out})
