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


# API: book seats (requires JWT)
@app.route('/api/book', methods=['POST'])
@jwt_required()
def api_book():
    data = request.get_json() or {}
    movie_id = data.get('movie_id')
    seat_ids = data.get('seat_ids') or []
    if not movie_id or not seat_ids:
        return jsonify({'msg': 'movie_id and seat_ids required'}), 400
    user_id = get_jwt_identity()
    movie = Movie.query.get_or_404(movie_id)
    seat_objs = []
    seat_labels = []
    price_per_seat = 5.0
    for sid in seat_ids:
        s = Seat.query.get(int(sid))
        if not s or s.movie_id != movie.id or s.status != 'available':
            continue
        s.status = 'booked'
        seat_objs.append(s)
        seat_labels.append(s.seat_number)
    if len(seat_objs) == 0:
        return jsonify({'msg': 'no seats available'}), 400
    total = price_per_seat * len(seat_objs)
    ticket = Ticket(user_id=user_id, movie_id=movie.id, seats=','.join(seat_labels), total_price=total)
    db.session.add(ticket)
    try:
        for s in seat_objs:
            db.session.add(s)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({'msg': 'db error'}), 500
    return jsonify({'ticket_id': ticket.id, 'total_price': ticket.total_price}), 201


# API: get ticket (JWT required)
@app.route('/api/ticket/<int:ticket_id>', methods=['GET'])
@jwt_required()
def api_ticket(ticket_id):
    user_id = get_jwt_identity()
    t = Ticket.query.get_or_404(ticket_id)
    if t.user_id != user_id:
        return jsonify({'msg': 'forbidden'}), 403
    return jsonify({'id': t.id, 'movie_id': t.movie_id, 'seats': t.seats, 'total_price': t.total_price})


@app.route('/ticket/<int:ticket_id>')
@login_required
def ticket_view(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.user_id != current_user.id:
        abort(403)
    # Lấy thông tin ghế dưới dạng list
    seat_list = ticket.seats.split(',') if ticket.seats else []
    return render_template('ticket.html', ticket=ticket, seat_list=seat_list)


@app.route('/ticket/<int:ticket_id>/pdf')
@login_required
def ticket_pdf(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if ticket.user_id != current_user.id:
        abort(403)

    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import A4
    except ImportError:
        return ("Missing dependency 'reportlab'. Install with: pip install reportlab", 500)

    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50
    c.setFont('Helvetica-Bold', 16)
    c.drawString(50, y, f"Vé xem phim - Mã vé: {ticket.id}")
    y -= 30
    c.setFont('Helvetica', 12)
    c.drawString(50, y, f"Người đặt: {ticket.user.username}")
    y -= 20
    c.drawString(50, y, f"Phim: {ticket.movie.title}")
    y -= 20
    c.drawString(50, y, f"Ghế: {ticket.seats}")
    y -= 20
    c.drawString(50, y, f"Tổng tiền: ${ticket.total_price:.2f}")
    y -= 20
    c.drawString(50, y, f"Thời gian: {ticket.created_at}")

    c.showPage()
    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"ticket_{ticket.id}.pdf", mimetype='application/pdf')


@app.route('/history')
@login_required
def history():
    # Hiển thị lịch sử vé của người hiện tại
    tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('history.html', tickets=tickets)


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    movies = Movie.query.all()
    users = User.query.all()
    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    return render_template('admin.html', movies=movies, users=users, tickets=tickets)


@app.route('/admin/movie/add', methods=['POST'])
@login_required
@admin_required
def admin_add_movie():
    title = request.form.get('title')
    description = request.form.get('description')
    image = request.form.get('image', '')
    if title and description:
        m = Movie(title=title, description=description, image=image)
        db.session.add(m)
        db.session.commit()
        # tạo ghế mẫu
        for i in range(1, 21):
            s = Seat(seat_number=f'A{i}', status='available', movie_id=m.id)
            db.session.add(s)
        db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/movie/edit/<int:movie_id>', methods=['POST'])
@login_required
@admin_required
def admin_edit_movie(movie_id):
    m = Movie.query.get_or_404(movie_id)
    title = request.form.get('title')
    description = request.form.get('description')
    image = request.form.get('image')
    if title:
        m.title = title
    if description is not None:
        m.description = description
    if image is not None:
        m.image = image
    db.session.add(m)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/movie/delete/<int:movie_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_movie(movie_id):
    m = Movie.query.get_or_404(movie_id)
    # xóa ghế và phim
    Seat.query.filter_by(movie_id=m.id).delete()
    db.session.delete(m)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/ticket/delete/<int:ticket_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_ticket(ticket_id):
    t = Ticket.query.get_or_404(ticket_id)
    # khi xóa vé, chuyển trạng thái ghế về available
    if t.seats:
        for sn in t.seats.split(','):
            seat = Seat.query.filter_by(movie_id=t.movie_id, seat_number=sn).first()
            if seat:
                seat.status = 'available'
                db.session.add(seat)
    db.session.delete(t)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/user/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_admin = not bool(u.is_admin)
    db.session.add(u)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


# Tạo database nếu chưa có
with app.app_context():
    # Ensure 'is_admin' column exists in user table (use sqlite3 directly to avoid SQLAlchemy schema cache issues)
    try:
        # Resolve sqlite file path from SQLALCHEMY_DATABASE_URI (expects sqlite:///movies.db)
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if db_uri.startswith('sqlite:///'):
            db_path = db_uri.replace('sqlite:///', '')
        else:
            db_path = 'movies.db'

        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute("PRAGMA table_info('user')")
                cols = [row[1] for row in cur.fetchall()]
                if 'is_admin' not in cols:
                    cur.execute("ALTER TABLE user ADD COLUMN is_admin INTEGER DEFAULT 0")
                    conn.commit()
                cur.close()
                conn.close()
            except Exception:
                # if migration fails, continue and let higher-level code show errors
                pass

    except Exception:
        pass

    db.create_all()

    # Seed data: thêm user, vài phim và ghế nếu database rỗng
    try:
        if User.query.count() == 0:
            demo_user = User(username='admin', password='admin', is_admin=True)
            db.session.add(demo_user)

        if Movie.query.count() == 0:
            movies_to_add = [
                Movie(title='Hành trình vũ trụ', description='Bộ phim khám phá không gian và những bí ẩn của vũ trụ.', image=''),
                Movie(title='Tình yêu mùa hè', description='Một câu chuyện lãng mạn nhẹ nhàng giữa hai người trẻ.', image=''),
                Movie(title='Hồi ức đêm mưa', description='Bí ẩn, hồi hộp và những quyết định thay đổi cuộc đời.', image='')
            ]
            db.session.add_all(movies_to_add)
            db.session.commit()  # commit để có id của movies

            # Tạo 20 ghế cho mỗi phim
            for m in Movie.query.all():
                existing = Seat.query.filter_by(movie_id=m.id).first()
                if not existing:
                    for i in range(1, 21):
                        seat_label = f'A{i}'
                        s = Seat(seat_number=seat_label, status='available', movie_id=m.id)
                        db.session.add(s)

        db.session.commit()
    except Exception:
        db.session.rollback()

if __name__ == '__main__':
    # Cho phép cấu hình host/port/debug qua biến môi trường để chạy trên LAN
    host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ('1', 'true', 'yes')

    # Thử lấy IP nội bộ của máy để in ra thông tin truy cập từ các máy khác trong cùng mạng
    try:
        import socket
        local_ip = socket.gethostbyname(socket.gethostname())
        # Nếu local_ip trả về 127.0.0.1, thử phương pháp khác
        if local_ip.startswith('127.'):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
    except Exception:
        local_ip = '127.0.0.1'

    print(f"Starting server on {host}:{port} (LAN access: http://{local_ip}:{port} )")
    app.run(host=host, port=port, debug=debug)
