import os, re, json, hmac, base64, hashlib, secrets, string
from datetime import datetime, timedelta
from functools import wraps
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "THIS_IS_SO_SECRET_FOR_2026_TUNU"),
    SQLALCHEMY_DATABASE_URI=os.getenv("DB_URL"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SEND_FILE_MAX_AGE_DEFAULT=2592000,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME="info.tunupublishers.com",
    MAIL_PASSWORD=os.getenv("M_P"),
    MAIL_DEFAULT_SENDER=("Tunu Publishers", "info.tunupublishers.com"),
    UPLOAD_FOLDER=os.path.join(app.root_path, "static")
)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# M-Pesa Configurations
CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY")
CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET")
SHORTCODE = os.getenv("MPESA_SHORTCODE")
PASSKEY = os.getenv("MPESA_PASSKEY")
BASE_URL = "https://sandbox.safaricom.co.ke" if os.getenv("MPESA_ENV", "sandbox") == "sandbox" else "https://api.safaricom.co.ke"

# Database & Extensions
db = SQLAlchemy(app)
mail = Mail(app)
migrate = Migrate(app, db)

def generate_id(prefix="STF", length=6):
    return f"{prefix}-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def format_phone(num):
    if not num: return None
    num = re.sub(r"\D", "", str(num))
    return f"254{num[1:]}" if num.startswith("0") else (f"254{num}" if num.startswith(("7", "1")) else num)

def generate_hmac_token(data):
    return hmac.new(app.config["SECRET_KEY"].encode(), json.dumps(data, sort_keys=True).encode(), hashlib.sha256).hexdigest()

def verify_hmac_token(data, token):
    if not token: return False
    return hmac.compare_digest(generate_hmac_token(data), token)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return redirect(url_for("login", next=request.path)) if not session.get("staff_id") else f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = db.session.get(Staff, session.get("staff_id")) if session.get("staff_id") else None
        if not u: return redirect(url_for("login"))
        if not (u.is_admin or u.is_super_admin): abort(401, description="Permission denied")
        return f(*args, **kwargs)
    return wrapper

def log_action(action, status_code=200, staff_id=None):
    try:
        db.session.add(Log(
            staff_id=staff_id, action=action, method=request.method, endpoint=request.path,
            ip=request.remote_addr, user_agent=request.headers.get("User-Agent"), status_code=status_code
        ))
        db.session.commit()
    except Exception as e: 
        print(f"Log error: {e}")
        db.session.rollback()

@app.after_request
def auto_log(response):
    # Skip logging system routes or static assets to avoid database bloat
    if request.path.startswith(("/static", "/book-cover")):
        return response
    try:
        db.session.add(Log(
            action=f"{request.method} {request.path}", method=request.method, endpoint=request.path,
            ip=request.remote_addr, user_agent=request.headers.get("User-Agent"), status_code=response.status_code
        ))
        db.session.commit()  
    except Exception: 
        db.session.rollback()
    return response

def send_mail(subject, recipients, html):
    mail.send(Message(subject=subject, recipients=recipients, html=html))

def get_access_token():
    res = requests.get(f"{BASE_URL}/oauth/v1/generate?grant_type=client_credentials", auth=(CONSUMER_KEY, CONSUMER_SECRET))
    if res.status_code != 200: raise Exception("Failed to obtain MPESA token.")
    return res.json()["access_token"]

def initiate_payment(order):
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    passwd = base64.b64encode(f"{SHORTCODE}{PASSKEY}{ts}".encode()).decode()
    

    token = generate_hmac_token({"order_id": order.id})
    callback_url = f"https://tunupublishers.com/mpesa/callback?order_id={order.id}&token={token}"
    
    payload = {
        "BusinessShortCode": SHORTCODE, "Password": passwd, "Timestamp": ts,
        "TransactionType": "CustomerPayBillOnline", "Amount": int(order.grand_total), "PartyA": format_phone(order.phone),
        "PartyB": SHORTCODE, "PhoneNumber": format_phone(order.phone),
        "CallBackURL": callback_url,
        "AccountReference": "Tunu Publishers", "TransactionDesc": f"Order {order.id}"
    }
    headers = {"Authorization": f"Bearer {get_access_token()}", "Content-Type": "application/json"}
    return requests.post(f"{BASE_URL}/mpesa/stkpush/v1/processrequest", json=payload, headers=headers).json()

class Staff(db.Model):
    id = db.Column(db.String(20), primary_key=True, default=lambda: generate_id("STF"))
    name = db.Column(db.String(512), nullable=False)
    email = db.Column(db.String(128), unique=True)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    location = db.Column(db.String(128), default="Nairobi")
    password = db.Column(db.String(1024), nullable=False, default=lambda: generate_password_hash("#TunuStaff2026"))
    added_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    added_by = db.Column(db.String(20), db.ForeignKey("staff.id"))
    edited_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    edited_by = db.Column(db.String(20), db.ForeignKey("staff.id"))
    deactivated_by = db.Column(db.String(20), db.ForeignKey("staff.id"))
    deactivated_at = db.Column(db.DateTime)
    must_change = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    tkv = db.Column(db.String(12), default=lambda: generate_id("T", 6))

    def to_dict(self):
        return {"id": self.id, "name": self.name, "email": self.email, "phone": self.phone, "location": self.location, "joined": self.added_at, "is_admin": self.is_admin, "is_active": self.is_active}

class Book(db.Model):
    id = db.Column(db.String(20), primary_key=True)
    title = db.Column(db.String(512), nullable=False)
    image = db.Column(db.String(1024), default="https://i.ibb.co/CKRYPD4p/image.png")
    slug = db.Column(db.String(120))
    audience, grade = db.Column(db.String(120)), db.Column(db.String(120))
    authors, blurb = db.Column(db.Text), db.Column(db.Text)
    added_by = db.Column(db.String(20), db.ForeignKey("staff.id"))
    edited_by = db.Column(db.String(20), db.ForeignKey("staff.id"))
    added_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    edited_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))
    deleted_at, deleted_by = db.Column(db.DateTime), db.Column(db.String(20), db.ForeignKey("staff.id"))
    discounted = db.Column(db.Boolean, default=False)
    oldPrice, newPrice = db.Column(db.Float, default=0), db.Column(db.Float, default=0)
    stars, sold, views = db.Column(db.Integer, default=0), db.Column(db.Integer, default=0), db.Column(db.Integer, default=0)
    is_deleted = db.Column(db.Boolean, default=False)

    def set_slug(self):
        self.slug = re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-") + f"_{self.id}"

    @property
    def image_url(self):
        if self.image.startswith(("http://", "https://", "/static/")):
            return self.image
        return url_for("book_cover", filename=self.image)

    def to_dict(self):
        return {"id": self.id, "title": self.title, "image": self.image_url, "slug": self.slug, "grade": self.grade, "audience": self.audience, "authors": self.authors, "blurb": self.blurb, "oldPrice": self.oldPrice, "newPrice": self.newPrice, "discounted": self.discounted, "stars": self.stars, "sold": self.sold, "views": self.views}

class Submission(db.Model):
    id = db.Column(db.String(20), primary_key=True, default=lambda: generate_id("SUB", 4))
    staff_id = db.Column(db.String(20), db.ForeignKey("staff.id"))
    staffName, institution_name, contact_person = db.Column(db.String(255)), db.Column(db.String(255)), db.Column(db.String(255))
    phone, email, category = db.Column(db.String(20)), db.Column(db.String(120)), db.Column(db.String(120))
    conversation_notes, challenges, saleComments = db.Column(db.Text), db.Column(db.Text), db.Column(db.Text)
    isSold = db.Column(db.Boolean, default=False)
    bookId = db.Column(db.String(20), db.ForeignKey("book.id"))
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    def to_dict(self):
        book = db.session.get(Book, self.bookId) if self.bookId else None
        return {"id": self.id, "staff": self.staffName, "institution": self.institution_name, "contact": self.contact_person, "phone": self.phone, "email": self.email, "category": self.category, "book": book.title if book else None, "sold": self.isSold, "notes": self.conversation_notes, "saleComments": self.saleComments, "submitted": self.submitted_at}

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.String(20), db.ForeignKey("staff.id"))
    action, method, endpoint = db.Column(db.String(255)), db.Column(db.String(10)), db.Column(db.String(255))
    ip, user_agent = db.Column(db.String(60)), db.Column(db.String(600))
    status_code = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    def to_dict(self):
        staff = db.session.get(Staff, self.staff_id) if self.staff_id else None
        return {"id": self.id, "staff": staff.name if staff else "Anonymous", "action": self.action, "method": self.method, "endpoint": self.endpoint, "status": self.status_code, "ip": self.ip, "time": self.timestamp}

class Order(db.Model):
    id = db.Column(db.String(50), primary_key=True, default=lambda: generate_id("ORD", 10))
    temp_id, data = db.Column(db.String(255)), db.Column(db.JSON)
    name, city, address = db.Column(db.String(255)), db.Column(db.String(255)), db.Column(db.String(500))
    email, phone = db.Column(db.String(255)), db.Column(db.String(20))
    grand_total = db.Column(db.Float, default=0)
    checkout_request_id = db.Column(db.String(120))
    status = db.Column(db.String(40), default="PENDING")
    created_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    def to_dict(self):
        return {"id": self.id, "name": self.name, "phone": self.phone, "email": self.email, "city": self.city, "address": self.address, "grand_total": self.grand_total, "status": self.status, "created": self.created_at, "items": self.data}

BOOKS_DATA = [
    {"title": "Fundo la Moyoni", "newPrice": 500, "oldPrice": 550, "image": "/static/books/fundo.jpeg", "audience": "General", "grade": "Adult", "authors": "Tunu Publishers"},
    {"title": "Fragments of Survival", "newPrice": 650, "oldPrice": 0, "image": "/static/books/fragments.jpeg", "audience": "General", "grade": "Adult", "authors": "Tunu Publishers"},
    {"title": "CBC English Grade 6", "newPrice": 700, "oldPrice": 850, "image": "/static/books/english6.jpeg", "audience": "Students", "grade": "Grade 6", "authors": "Tunu Publishers"}
]

@app.route("/")
def home():
    tot = db.session.query(db.func.sum(Book.stars)).filter_by(is_deleted=False).scalar() or 0
    newest = Book.query.filter_by(is_deleted=False).order_by(Book.added_at.desc()).limit(8).all()
    for bk in newest:
        bk.rating_percent = round((bk.stars / tot) * 100, 2) if tot else 0
    return render_template(
        "index.html", newest=newest,
        trending=Book.query.filter_by(is_deleted=False).order_by(Book.views.desc()).limit(6).all(),
        top_rated=Book.query.filter_by(is_deleted=False).order_by(Book.stars.desc()).limit(6).all(),
        best_selling=Book.query.filter_by(is_deleted=False).order_by(Book.sold.desc()).limit(6).all()
    )

@app.route("/books")
def books():
    bks = Book.query.filter_by(is_deleted=False).order_by(Book.added_at.desc()).paginate(page=request.args.get("page", 1, type=int), per_page=12, error_out=False)
    return render_template("books.html", books=bks.items, pagination=bks)

@app.route("/book/<string:slug>")
def book_detail(slug):
    book_id = slug.split('_')
    id = book_id[1]
    book = Book.query.filter_by(id=id, is_deleted=False).first_or_404()
    book.views += 1
    db.session.commit()
    return render_template("book.html", book=book, related=Book.query.filter(Book.id != book.id, Book.is_deleted == False).limit(4).all())

@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    bks = Book.query.filter(Book.is_deleted == False)
    if q:
        bks = bks.filter(Book.title.ilike(f"%{q}%") | Book.authors.ilike(f"%{q}%") | Book.grade.ilike(f"%{q}%") | Book.audience.ilike(f"%{q}%"))
    return render_template("search.html", books=bks.order_by(Book.views.desc()).all(), keyword=q)

@app.route("/cart")
def cart():
    return render_template("cart.html")

@app.route("/checkout")
def checkout():
    oid = request.args.get("order")
    if not oid: return redirect(url_for("cart"))
    order = db.session.get(Order, oid)
    if not order: return redirect(url_for("cart"))
    bks, subt = [], 0
    for item in (order.data or []):
        bk = db.session.get(Book, item["id"])
        if not bk: continue
        qty = int(item.get("qty", 1))
        tot = qty * bk.newPrice
        subt += tot
        bks.append({"book": bk, "qty": qty, "total": tot})
    return render_template("checkout.html", order=order, books=bks, subtotal=subt)

@app.route("/book-cover/<path:filename>")
def book_cover(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/base")
def base():
    return render_template('base.html')



@app.route("/create_dummy")
def create_dummy():
    admin = Staff.query.filter_by(id="ADM-0001").first()
    if not admin:
        admin = Staff(id="ADM-0001", name="Administrator", phone="0700000000", email="admin@tunupublishers.com", password=generate_password_hash("admin123"), is_admin=True)
        db.session.add(admin)
        db.session.commit()
    created = []
    for item in BOOKS_DATA:
        if Book.query.filter_by(title=item["title"]).first(): continue
        b_id = generate_id("BK")
        exists = Book.query.filter_by(id=b_id).first()
        if exists:
           b_id = generate_id("BK")
        bk = Book(id=b_id, title=item["title"], image=item["image"], grade=item["grade"], audience=item["audience"], authors=item["authors"], newPrice=item["newPrice"], oldPrice=item["oldPrice"], added_by=admin.id)
        db.session.add(bk)
        bk.set_slug()
        created.append(bk.title)
    db.session.commit()
    return jsonify({"created": created})

@app.route("/staff/login", methods=["GET", "POST"])
def login():
    if session.get("staff_id"): return redirect(url_for("dashboard"))
    if request.method == "GET": return render_template("login.html", next=request.args.get("next"))
    next_url, user, pwd = request.args.get("next"), request.form.get("username", "").strip(), request.form.get("password", "")
    if not user or not pwd: return render_template("login.html", error="All fields are required.")
    staff = Staff.query.filter((Staff.phone == user) | (Staff.email == user) | (Staff.id == user)).first()
    if not staff:
        log_action("Unknown login attempt", 401)
        return render_template("login.html", error="Invalid credentials.")
    if not staff.is_active:
        log_action(f"Disabled account login attempt ({staff.id})", 401, staff.id)
        return render_template("login.html", error="Your account has been disabled.")
    if not check_password_hash(staff.password, pwd):
        log_action(f"Invalid password ({staff.id})", 401, staff.id)
        return render_template("login.html", error="Invalid credentials.")
    session.update({"staff_id": staff.id})
    session.permanent = True
    log_action(f"{staff.name} logged in", 200, staff.id)
    if staff.must_change: return redirect(url_for("change_password"))
    return redirect(next_url or (url_for("admin_dashboard") if staff.is_admin or staff.is_super_admin else url_for("dashboard")))

@app.route("/staff/logout")
@login_required
def logout():
    staff = db.session.get(Staff, session.get("staff_id"))
    if staff: log_action(f"{staff.name} logged out", 200, staff.id)
    session.clear()
    return redirect(url_for("home"))

@app.route("/staff/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    staff = db.session.get(Staff, session["staff_id"])
    if request.method == "GET": return render_template("change_password.html")
    curr, new, conf = request.form.get("current"), request.form.get("new"), request.form.get("confirm")
    if not check_password_hash(staff.password, curr): return render_template("change_password.html", error="Current password is incorrect.")
    if len(new) < 6: return render_template("change_password.html", error="Password is too short.")
    if new != conf: return render_template("change_password.html", error="Passwords do not match.")
    staff.password, staff.must_change = generate_password_hash(new), False
    staff.edited_at, staff.edited_by = datetime.utcnow() + timedelta(hours=3), staff.id
    db.session.commit()
    log_action("Password changed", 200, staff.id)
    return redirect(url_for("dashboard"))

@app.route("/staff/register", methods=["GET", "POST"])
@login_required
@admin_required
def register_staff():
    admin = db.session.get(Staff, session["staff_id"])
    if request.method == "GET": return render_template("register.html")
    phone, email = request.form.get("phone"), request.form.get("email")
    if Staff.query.filter_by(phone=phone).first(): return render_template("register.html", error="Phone number already exists.")
    if email and Staff.query.filter_by(email=email).first(): return render_template("register.html", error="Email already exists.")
    staff = Staff(name=request.form.get("name"), phone=phone, email=email, location=request.form.get("location"), added_by=admin.id, password=generate_password_hash("#TunuStaff2026"), must_change=True)
    db.session.add(staff)
    db.session.commit()
    log_action(f"Created staff {staff.name}", 200, admin.id)
    return redirect(url_for("admin_dashboard"))

@app.route("/staff/dashboard")
@login_required
def dashboard():
    staff = db.session.get(Staff, session["staff_id"])
    return render_template(
        "dashboard.html", staff=staff,
        reports=Submission.query.filter_by(staff_id=staff.id).order_by(Submission.submitted_at.desc()).all(),
        reports_today=Submission.query.filter(Submission.staff_id == staff.id, db.func.date(Submission.submitted_at) == datetime.utcnow().date()).count(),
        reports_month=Submission.query.filter(Submission.staff_id == staff.id, Submission.submitted_at >= (datetime.utcnow() - timedelta(days=30))).count(),
        books=Book.query.filter_by(is_deleted=False).count()
    )

@app.route("/submit-report", methods=["POST"])
@login_required
def submit_report():
    staff = db.session.get(Staff, session["staff_id"])
    sub = Submission(
        staff_id=staff.id, staffName=staff.name, institution_name=request.form.get("institution_name"),
        contact_person=request.form.get("contact_person"), phone=request.form.get("phone"), email=request.form.get("email"),
        category=request.form.get("category"), conversation_notes=request.form.get("conversation_notes"),
        challenges=request.form.get("challenges"), saleComments=request.form.get("saleComments"),
        bookId=request.form.get("bookId"), isSold=bool(request.form.get("isSold"))
    )
    db.session.add(sub)
    db.session.commit()
    log_action(f"Submitted report ({sub.id})", 200, staff.id)
    return redirect(url_for("dashboard"))

@app.route("/cp")
@login_required
@admin_required
def admin_dashboard():
    adm = db.session.get(Staff, session["staff_id"])
    log_action("Visited Admin Dashboard", 200, adm.id)
    return render_template(
        "admin.html", admin=adm,
        total_books=Book.query.filter_by(is_deleted=False).count(),
        total_staff=Staff.query.filter_by(is_super_admin=False).count(),
        total_orders=Order.query.count(), total_reports=Submission.query.count(),
        recent_books=Book.query.filter_by(is_deleted=False).order_by(Book.added_at.desc()).limit(5).all(),
        recent_reports=Submission.query.order_by(Submission.submitted_at.desc()).limit(8).all(),
        recent_orders=Order.query.order_by(Order.created_at.desc()).limit(8).all(),
        recent_staff=Staff.query.filter_by(is_super_admin=False).order_by(Staff.added_at.desc()).limit(8).all(),
        monthly_reports=Submission.query.filter(Submission.submitted_at >= datetime.utcnow() - timedelta(days=30)).count()
    )

@app.route("/cp/staff")
@login_required
@admin_required
def staff_page():
    return render_template("staff.html", staff=Staff.query.filter_by(is_super_admin=False).order_by(Staff.name).all())

@app.route("/api/admin/edit_staff", methods=["POST"])
@login_required
@admin_required
def edit_staff():
    adm = db.session.get(Staff, session["staff_id"])
    data = request.get_json()
    staff = db.session.get(Staff, data.get("id"))
    if not staff: return jsonify({"error": "Staff not found."}), 404
    if staff.is_super_admin: return jsonify({"error": "Permission denied."}), 403
    for field in ["name", "email", "phone", "location", "is_admin"]:
        setattr(staff, field, data.get(field))
    staff.edited_by, staff.edited_at = adm.id, datetime.utcnow() + timedelta(hours=3)
    db.session.commit()
    log_action(f"Edited staff {staff.id}", 200, adm.id)
    return jsonify({"msg": "Staff updated successfully."})

@app.route("/api/admin/toggle_staff", methods=["POST"])
@login_required
@admin_required
def toggle_staff():
    adm = db.session.get(Staff, session["staff_id"])
    staff = db.session.get(Staff, request.get_json().get("staff_id"))
    if not staff: return jsonify({"error": "Staff not found."}), 404
    if staff.is_super_admin: return jsonify({"error": "Permission denied."}), 403
    staff.is_active = not staff.is_active
    staff.deactivated_at, staff.deactivated_by = datetime.utcnow() + timedelta(hours=3), adm.id
    db.session.commit()
    log_action(f"Toggled account {staff.id}", 200, adm.id)
    return jsonify({"msg": "Status updated."})

@app.route("/cp/reports")
@login_required
@admin_required
def reports_page():
    return render_template("reports.html", reports=Submission.query.order_by(Submission.submitted_at.desc()).all())

@app.route("/cp/orders")
@login_required
@admin_required
def orders_page():
    return render_template("orders.html", orders=Order.query.order_by(Order.created_at.desc()).all())

@app.route("/api/admin/order/status", methods=["POST"])
@login_required
@admin_required
def update_order_status():
    adm = db.session.get(Staff, session["staff_id"])
    data = request.get_json()
    order = db.session.get(Order, data.get("order_id"))
    if not order: return jsonify({"error": "Order not found."}), 404
    order.status = data.get("status")
    db.session.commit()
    log_action(f"Updated order {order.id} status", 200, adm.id)
    return jsonify({"msg": "Order updated."})

@app.route("/cp/logs")
@login_required
@admin_required
def logs_page():
    return render_template("logs.html", logs=Log.query.order_by(Log.timestamp.desc()).limit(1000).all())

@app.route("/cp/books")
@login_required
@admin_required
def books_admin():
    return render_template("admin_books.html", books=Book.query.filter_by(is_deleted=False).order_by(Book.added_at.desc()).all())

@app.route("/cp/books/new", methods=["GET", "POST"])
@login_required
@admin_required
def add_book():
    staff = db.session.get(Staff, session["staff_id"])
    if request.method == "GET": return render_template("add_book.html")
    img, fn = request.files.get("image"), "default.png"
    if img and img.filename:
        fn = f"{secrets.token_hex(10)}.{img.filename.rsplit('.', 1)[1].lower()}"
        img.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
    bk = Book(
        title=request.form.get("title"), authors=request.form.get("authors"), audience=request.form.get("audience"),
        grade=request.form.get("grade"), blurb=request.form.get("blurb"), oldPrice=float(request.form.get("oldPrice") or 0),
        newPrice=float(request.form.get("newPrice") or 0), image=fn, discounted=bool(request.form.get("discounted")), added_by=staff.id
    )
    bk.set_slug()
    db.session.add(bk)
    db.session.commit()
    log_action(f"Added book {bk.title}", 200, staff.id)
    return redirect(url_for("books_admin"))

@app.route("/cp/books/edit/<string:id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_book(id):
    staff = db.session.get(Staff, session["staff_id"])
    bk = Book.query.get_or_404(id)
    if request.method == "GET": return render_template("edit_book.html", book=bk)
    for fld in ["title", "authors", "grade", "audience", "blurb"]:
        setattr(bk, fld, request.form.get(fld))
    bk.oldPrice, bk.newPrice, bk.discounted = float(request.form.get("oldPrice") or 0), float(request.form.get("newPrice") or 0), bool(request.form.get("discounted"))
    img = request.files.get("image")
    if img and img.filename:
        fn = f"{secrets.token_hex(10)}.{img.filename.rsplit('.', 1)[1]}"
        img.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
        if bk.image and bk.image != "default.png":
            old = os.path.join(app.config["UPLOAD_FOLDER"], bk.image)
            if os.path.exists(old): os.remove(old)
        bk.image = fn
    bk.edited_at, bk.edited_by = datetime.utcnow() + timedelta(hours=3), staff.id
    bk.set_slug()
    db.session.commit()
    log_action(f"Edited book {bk.title}", 200, staff.id)
    return redirect(url_for("books_admin"))

@app.route("/api/admin/delete_book", methods=["POST"])
@login_required
@admin_required
def delete_book():
    staff = db.session.get(Staff, session["staff_id"])
    bk = db.session.get(Book, request.get_json().get("book_id"))
    if not bk: return jsonify({"error": "Book not found."}), 404
    bk.is_deleted, bk.deleted_at, bk.deleted_by = True, datetime.utcnow() + timedelta(hours=3), staff.id
    db.session.commit()
    log_action(f"Deleted {bk.title}", 200, staff.id)
    return jsonify({"msg": "Book deleted."})

@app.route("/api/admin/restore_book", methods=["POST"])
@login_required
@admin_required
def restore_book():
    staff = db.session.get(Staff, session["staff_id"])
    bk = db.session.get(Book, request.get_json().get("book_id"))
    if not bk: return jsonify({"error": "Book not found."}), 404
    bk.is_deleted, bk.deleted_at, bk.deleted_by = False, None, None
    db.session.commit()
    log_action(f"Restored {bk.title}", 200, staff.id)
    return jsonify({"msg": "Book restored."})

@app.route("/api/admin/book/rating", methods=["POST"])
@login_required
@admin_required
def update_rating():
    data = request.get_json()
    bk = db.session.get(Book, data.get("book_id"))
    if not bk: return jsonify({"error": "Book not found."}), 404
    bk.stars = max(0, min(5, int(data.get("rating", 0))))
    db.session.commit()
    return jsonify({"msg": "Rating updated.", "rating": bk.stars})

@app.route("/api/admin/book/discount", methods=["POST"])
@login_required
@admin_required
def toggle_discount():
    bk = db.session.get(Book, request.get_json().get("book_id"))
    if not bk: return jsonify({"error": "Book not found."}), 404
    bk.discounted = not bk.discounted
    db.session.commit()
    return jsonify({"discounted": bk.discounted})

@app.route("/api/upload-image", methods=["POST"])
@login_required
@admin_required
def upload_image():
    if "image" not in request.files: return jsonify({"error": "No image."}), 400
    img = request.files["image"]
    ext = img.filename.rsplit(".", 1)[-1].lower() if "." in img.filename else ""
    if ext not in ["jpg", "jpeg", "png", "webp"]: return jsonify({"error": "Unsupported image."}), 400
    fn = f"{secrets.token_hex(12)}.{ext}"
    img.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
    return jsonify({"path": fn, "url": url_for("book_cover", filename=fn)})

@app.route("/api/create-order", methods=["POST"])
def create_order():
    data = request.get_json()
    cart, items, total = data.get("cart", []), [], 0
    if not cart: return jsonify({"error": "Your cart is empty."}), 400
    for item in cart:
        bk = Book.query.filter_by(id=item["id"], is_deleted=False).first()
        if not bk: continue
        qty = max(int(item.get("qty", 1)), 1)
        amt = qty * bk.newPrice
        total += amt
        items.append({"id": bk.id, "title": bk.title, "qty": qty, "price": bk.newPrice, "total": amt})
    if not items: return jsonify({"error": "No valid books."}), 400
    order = Order(name=data["name"], email=data["email"], phone=format_phone(data["phone"]), city=data["city"], address=data["address"], data=items, grand_total=total)
    db.session.add(order)
    db.session.commit()
    return jsonify({"success": True, "order_id": order.id, "redirect": url_for("checkout", order=order.id)})

@app.route("/api/pay", methods=["POST"])
def pay():
    order = db.session.get(Order, request.get_json().get("order_id"))
    if not order: return jsonify({"error": "Order not found."}), 404
    if order.status == "PAID": return jsonify({"error": "Order already paid."}), 400
    res = initiate_payment(order)
    order.checkout_request_id = res.get("CheckoutRequestID")
    db.session.commit()
    return jsonify(res)

@app.route("/mpesa/callback", methods=["POST"])
def mpesa_callback():
    # SECURED: Verify cryptographically that the request originated via Tunu Publishers' STK push transaction
    token = request.args.get("token")
    order_id = request.args.get("order_id")
    if not token or not order_id or not verify_hmac_token({"order_id": order_id}, token):
        abort(403, description="Access Denied: Unverified transaction token.")
        
    try:
        cb = request.get_json()["Body"]["stkCallback"]
        order = db.session.get(Order, order_id)
        if not order: return jsonify({"ResultCode": 0})
        if cb["ResultCode"] == 0:
            order.status = "PAID"
            for item in order.data:
                bk = db.session.get(Book, item["id"])
                if bk: bk.sold += item["qty"]
            db.session.commit()
            send_mail("Payment Successful", [order.email], render_template("emails/payment.html", order=order))
        else:
            order.status = "FAILED"
            db.session.commit()
    except Exception as e: 
        print(f"Callback processing error: {e}")
        db.session.rollback()
    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})

@app.route("/track-order")
def track_order():
    return render_template("track.html", order=db.session.get(Order, request.args.get("id")) if request.args.get("id") else None)

@app.route("/api/order-status")
def order_status():
    order = db.session.get(Order, request.args.get("id"))
    if not order: return jsonify({"error": "Order not found."}), 404
    return jsonify({"status": order.status, "total": order.grand_total, "created": order.created_at, "items": order.data})

@app.route("/api/books/search")
def search_api():
    return jsonify([{"id": b.id, "title": b.title, "image": b.image_url, "price": b.newPrice, "slug": b.slug} for b in Book.query.filter(Book.is_deleted == False, Book.title.ilike(f"%{request.args.get('q', '')}%")).limit(10).all()])

@app.route("/api/book/<string:id>")
def quick_book(id):
    return jsonify(db.session.get(Book, id).to_dict())

@app.route("/api/newsletter", methods=["POST"])
def newsletter():
    if not request.json.get("email"): return jsonify({"error": "Email required."}), 400
    return jsonify({"success": True, "message": "Subscribed."})

def send_welcome_email(staff):
    send_mail("Welcome to Tunu Publishers", [staff.email], render_template("emails/welcome.html", staff=staff))

def send_purchase_email(order):
    send_mail("Your Order Receipt", [order.email], render_template("emails/payment.html", order=order))

def send_report_reminder():
    if datetime.utcnow().weekday() >= 5: return
    for mb in Staff.query.filter_by(is_active=True).all():
        if mb.email and not Submission.query.filter(Submission.staff_id == mb.id, db.func.date(Submission.submitted_at) == datetime.utcnow().date()).count():
            try: send_mail("Daily Report Reminder", [mb.email], render_template("emails/report_reminder.html", staff=mb))
            except Exception as e: print(e)

def send_weekend_wishes():
    if datetime.utcnow().weekday() != 5: return
    for mb in Staff.query.filter_by(is_active=True).all():
        if mb.email:
            try: send_mail("Happy Weekend", [mb.email], render_template("emails/weekend.html", staff=mb))
            except Exception: pass

@app.route("/api/send-reminders")
@login_required
@admin_required
def reminders():
    send_report_reminder()
    log_action("Sent report reminders", 200, session["staff_id"])
    return jsonify({"success": True})

@app.route("/api/send-weekend")
@login_required
@admin_required
def weekend():
    send_weekend_wishes()
    log_action("Sent weekend wishes", 200, session["staff_id"])
    return jsonify({"success": True})

@app.route("/api/test-email")
@login_required
def test_email():
    staff = db.session.get(Staff, session["staff_id"])
    if not staff.email: return jsonify({"error": "No email found."}), 400
    send_mail("Email Test", [staff.email], render_template("emails/test.html", staff=staff))
    return jsonify({"success": True})

@app.context_processor
def inject_globals():
    return {
        "current_staff": db.session.get(Staff, session["staff_id"]) if session.get("staff_id") else None,
        "current_year": datetime.utcnow().year,
        "book_count": Book.query.filter_by(is_deleted=False).count()
    }

@app.template_filter("currency")
def currency(val):
    return f"KSh {float(val):,.2f}"

@app.template_filter("datetime")
def datetime_filter(val):
    return val.strftime("%d %b %Y %I:%M %p") if val else ""

@app.template_filter("number")
def number_filter(val):
    return "{:,}".format(int(val))

@app.errorhandler(400)
def bad_request(e): return render_template("errors/400.html", error=e), 400

@app.errorhandler(401)
def unauthorized(e): return render_template("errors/401.html", error=e), 401

@app.errorhandler(403)
def forbidden(e): return render_template("errors/403.html", error=e), 403

@app.errorhandler(404)
def not_found(e): return render_template("errors/404.html", error=e), 404

@app.errorhandler(405)
def method_not_allowed(e): return render_template("errors/405.html", error=e), 405

@app.errorhandler(500)
def server_error(e):
    db.session.rollback()
    return render_template("errors/500.html", error=e), 500

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)