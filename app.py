import base64
from datetime import datetime, timedelta
from datetime import datetime, timedelta
from functools import wraps
from functools import wraps
import hashlib
import hmac
import json
import json
import os
import re
import secrets
import string
import traceback
from urllib.parse import quote

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask import redirect, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import requests
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "THIS_IS_SO_SECRET_FOR_2026_TUNU"),
    SQLALCHEMY_DATABASE_URI='sqlite:///tunu.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SEND_FILE_MAX_AGE_DEFAULT=2592000,
    MAIL_SERVER="mail.tunupublishers.com",
    MAIL_PORT= 465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME="noreply@tunupublishers.com",
    MAIL_PASSWORD=os.getenv("M_P"),
    MAIL_DEFAULT_SENDER=("Tunu Publishers", "noreply@tunupublishers.com"),
    UPLOAD_FOLDER=os.path.join(app.root_path, "static", "resources", "books" ,"covers"),
    GALLERY_FOLDER=os.path.join(app.root_path, "static", "resources", "gallery"),
    STORES_FOLDER=os.path.join(app.root_path, "static", "resources", "stores")
)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["GALLERY_FOLDER"], exist_ok=True)
os.makedirs(app.config["STORES_FOLDER"], exist_ok=True)


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
        staff_id = session.get("staff_id")

        if not staff_id:
            return redirect(url_for("login", next=request.path))

        staff = db.session.get(Staff, staff_id)

        if not staff:
            session.clear()
            return redirect(url_for("login"))

        if not staff.is_active:
            session.clear()
            return redirect(url_for("login"))

        if staff.must_change and request.endpoint != "change_password":
            return redirect(url_for("change_password"))

        return f(*args, **kwargs)

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
    if res.status_code != 200: raise Exception(f"Failed to obtain MPESA token. {res}")
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
    id = db.Column(db.String(20), primary_key=True, default=lambda: generate_id("BK"))
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
        title_slug = re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")
        self.slug = f"{title_slug}_{self.id}"

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

    temp_id = db.Column(db.String(255))
    data = db.Column(db.JSON)

    name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    phone = db.Column(db.String(20))

    county = db.Column(db.String(100))
    city = db.Column(db.String(255))
    address = db.Column(db.String(500))

    subtotal = db.Column(db.Float, default=0)
    discount = db.Column(db.Float, default=0)
    delivery_fee = db.Column(db.Float, default=0)
    grand_total = db.Column(db.Float, default=0)

    coupon_code = db.Column(db.String(50))

    checkout_request_id = db.Column(db.String(120))
    mpesa_receipt = db.Column(db.String(50))

    status = db.Column(
        db.String(40),
        default="PENDING"
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.utcnow() + timedelta(hours=3)
    )
    
class Coupon(db.Model):
    id = db.Column(db.String(50), primary_key=True, default=lambda: generate_id("CP", 10))
    code = db.Column(db.String(50), unique=True, nullable=False)

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.utcnow() + timedelta(hours=3)
    )

    expires_at = db.Column(db.DateTime, nullable=False)

    created_by = db.Column(db.String(20), db.ForeignKey("staff.id"))

    discount_type = db.Column(db.String(20), default="fixed")  
    discount_value = db.Column(db.Float, nullable=False)

    used = db.Column(db.Integer, default=0)
    max_uses = db.Column(db.Integer, default=1)

    used_orders = db.Column(db.Text)

    is_active = db.Column(db.Boolean, default=True)

class Store(db.Model):
    id = db.Column(db.String(20), primary_key=True, default=lambda: generate_id("ST"))
    name = db.Column(db.String(255), nullable=False)
    image = db.Column(db.String(1024), default="https://i.ibb.co/CKRYPD4p/image.png")
    city = db.Column(db.String(120))
    address = db.Column(db.Text)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    description = db.Column(db.Text)
    hours = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    is_active = db.Column(db.Boolean, default=True)
    added_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    @property
    def image_url(self):
        if self.image and self.image.startswith(("http://", "https://", "/static/")):
            return self.image
        return self.image or "https://i.ibb.co/CKRYPD4p/image.png"

    @property
    def maps_url(self):
        if self.latitude and self.longitude:
            return f"https://www.google.com/maps/search/?api=1&query={self.latitude},{self.longitude}"
        fallback_query = f"{self.name} {self.city or ''}"
        return f"https://www.google.com/maps/search/?api=1&query={quote(fallback_query)}"

    def to_dict(self):
        return {"id": self.id, "name": self.name, "image": self.image_url, "city": self.city, "address": self.address, "phone": self.phone, "email": self.email, "description": self.description, "hours": self.hours, "latitude": self.latitude, "longitude": self.longitude}

class GalleryImage(db.Model):
    id = db.Column(db.String(20), primary_key=True, default=lambda: generate_id("GAL"))
    image = db.Column(db.String(1024), nullable=False)
    caption = db.Column(db.String(255))
    category = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    added_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=3))

    @property
    def image_url(self):
        if self.image and self.image.startswith(("http://", "https://", "/static/")):
            return self.image
        return self.image or "https://i.ibb.co/CKRYPD4p/image.png"

    def to_dict(self):
        return {"id": self.id, "image": self.image_url, "caption": self.caption, "category": self.category}


NEAR_NAIROBI = {
    "Nairobi",
    "Kiambu",
    "Machakos",
    "Kajiado",
    "Muranga",
    "Kirinyaga",
    "Nyandarua",
    "Nyeri",
}

FAR = {
    "Nakuru",
    "Narok",
    "Laikipia",
    "Meru",
    "Embu",
    "Tharaka Nithi",
    "Makueni",
    "Kitui",
    "Bomet",
    "Kericho",
    "Nandi",
    "Uasin Gishu",
    "Elgeyo Marakwet",
    "Baringo",
    "Trans Nzoia",
    "Kakamega",
    "Bungoma",
    "Busia",
    "Kisumu",
    "Siaya",
    "Vihiga",
    "Homa Bay",
    "Migori",
    "Kisii",
    "Nyamira",
}


limiter = Limiter(
    key_func = get_remote_address,
    app=app,
    storage_uri = "memory://",
    default_limits=['200 per day', "50 per minute"]
)


def get_delivery_fee(county):
    county = county.strip()

    if county in NEAR_NAIROBI:
        return 200

    if county in FAR:
        return 300

    return 400

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
    stores = Store.query.all()
    return render_template(
        "index.html", newest=newest,
        stores=stores,
        trending=Book.query.filter_by(is_deleted=False).order_by(Book.views.desc()).limit(6).all(),
        top_rated=Book.query.filter_by(is_deleted=False).order_by(Book.stars.desc()).limit(6).all(),
        best_selling=Book.query.filter_by(is_deleted=False).order_by(Book.sold.desc()).limit(6).all()
    )

@app.route("/books")
@limiter.limit("10 per minute")
def books():
    q = Book.query.filter_by(is_deleted=False)

    cat = request.args.get("cat", "").strip()
    if cat:
        like = f"%{cat}%"
        q = q.filter(db.or_(Book.grade.ilike(like), Book.audience.ilike(like)))

    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(Book.title.ilike(like), Book.authors.ilike(like)))

    min_price = request.args.get("min_price", type=float)
    if min_price is not None:
        q = q.filter(Book.newPrice >= min_price)

    max_price = request.args.get("max_price", type=float)
    if max_price is not None:
        q = q.filter(Book.newPrice <= max_price)

    sort = request.args.get("sort", "newest")
    sort_map = {
        "newest": Book.added_at.desc(),
        "price_asc": Book.newPrice.asc(),
        "price_desc": Book.newPrice.desc(),
        "popular": Book.sold.desc(),
        "rating": Book.stars.desc(),
    }
    q = q.order_by(sort_map.get(sort, Book.added_at.desc()))

    bks = q.paginate(page=request.args.get("page", 1, type=int), per_page=12, error_out=False)
    
    labels = (
        db.session.query(
            Book.grade,
            func.count(Book.id).label("count")
        )
        .group_by(Book.grade)
        .order_by(Book.grade)
        .all()
    )
    
    return render_template(
        "books.html", books=bks.items, pagination=bks,
        cat=cat, search=search, sort=sort, min_price=min_price, max_price=max_price, labels=labels
    )

@app.route("/book/<string:book_slug>")
def book_detail(book_slug):
    slugged = book_slug.split('_')
    book_id = slugged[1]
    book = Book.query.filter_by(id=book_id, is_deleted=False).first_or_404()
    book.views += 1
    db.session.commit()
    return render_template("book.html", book=book, related=Book.query.filter(Book.id != book.id, Book.is_deleted == False).limit(4).all())


@app.route("/cart")
def cart():
    return render_template("cart.html")

@app.route("/checkout/<string:oid>")
def checkout(oid):
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
@limiter.limit("50 per minute")
def book_cover(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

FOLDERS = {
    "store": "STORE_FOLDER",
    "gallery": "GALLERY_FOLDER",
}

@app.route("/image/<string:folder>/<path:filename>")
@limiter.limit("50 per minute")
def get_image(folder, filename):
    config_key = FOLDERS.get(folder.lower())
    if not config_key:
        abort(404)

    return send_from_directory(
        app.config[config_key],
        filename
    )
    
@app.route("/base")
def base():
    return render_template('base.html')

@app.route("/api/coupons/active")
def active_coupons():
    now = datetime.utcnow() + timedelta(hours=3)
    coupons = Coupon.query.filter(
        Coupon.is_active == True,
        Coupon.expires_at > now,
        Coupon.used < Coupon.max_uses
    ).all()
    return jsonify({
        "coupons": [{
            "code": c.code,
            "discount_type": c.discount_type,
            "discount_value": c.discount_value
        } for c in coupons]
    })

@app.route("/api/validate-coupon")
def validate_coupon():
    code = request.args.get("code", "").strip().upper()
    if not code:
        return jsonify({"valid": False, "error": "No coupon code provided."}), 400
    coupon = Coupon.query.filter_by(code=code, is_active=True).first()
    if not coupon:
        return jsonify({"valid": False, "error": "Invalid coupon code."})
    if coupon.expires_at < datetime.utcnow() + timedelta(hours=3):
        return jsonify({"valid": False, "error": "Coupon has expired."})
    if coupon.used >= coupon.max_uses:
        return jsonify({"valid": False, "error": "Coupon usage limit reached."})
    return jsonify({
        "valid": True,
        "code": coupon.code,
        "discount_type": coupon.discount_type,
        "discount_value": coupon.discount_value
    })

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
        bk = Book(title=item["title"], image=item["image"], grade=item["grade"], audience=item["audience"], authors=item["authors"], newPrice=item["newPrice"], oldPrice=item["oldPrice"], added_by=admin.id)
        bk.set_slug()
        db.session.add(bk)
        created.append(bk.title)
    db.session.commit()
    return jsonify({"created": created})

@app.route("/staff/login", methods=["GET", "POST"])
def login():
    if session.get("staff_id"): return redirect(url_for("dashboard"))
    if request.method == "GET": return render_template("user/login.html", next=request.args.get("next"))
    next_url, user, pwd = request.args.get("next"), request.form.get("username", "").strip(), request.form.get("password", "")
    if not user or not pwd: return render_template("login.html", error="All fields are required.")
    staff = Staff.query.filter((Staff.phone == user) | (Staff.email == user) | (Staff.id == user)).first()
    if not staff:
        log_action("Unknown login attempt", 401)
        return render_template("user/login.html", error="Invalid credentials.")
    if not staff.is_active:
        log_action(f"Disabled account login attempt ({staff.id})", 401, staff.id)
        return render_template("login.html", error="Your account has been disabled.")
    if not check_password_hash(staff.password, pwd):
        log_action(f"Invalid password ({staff.id})", 401, staff.id)
        return render_template("user/login.html", error="Invalid credentials.")
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
    if request.method == "GET": return render_template("user/change_password.html")
    curr, new, conf = request.form.get("current"), request.form.get("new"), request.form.get("confirm")
    
    if not check_password_hash(staff.password, curr): return render_template("user/change_password.html", error="Current password is incorrect.")
    if len(new) < 6: return render_template("user/change_password.html", error="Password is too short.")
    if new != conf: return render_template("user/change_password.html", error="Passwords do not match.")
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
    if request.method == "GET": return render_template("user/register.html")
    phone, email = request.form.get("phone"), request.form.get("email")
    if Staff.query.filter_by(phone=phone).first(): return render_template("user/register.html", error="Phone number already exists.")
    if email and Staff.query.filter_by(email=email).first(): return render_template("user/register.html", error="Email already exists.")
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
        "user/dashboard.html", staff=staff,
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
    return render_template("system/logs.html", logs=Log.query.order_by(Log.timestamp.desc()).limit(1000).all())

@app.route("/cp/coupons")
@login_required
@admin_required
def coupons_page():
    return render_template("admin/coupons.html")

@app.route("/api/admin/coupons")
@login_required
@admin_required
def admin_api_coupons():
    q = Coupon.query
    search = request.args.get("q", "").strip()
    if search:
        q = q.filter(Coupon.code.ilike(f"%{search}%"))
    q = q.order_by(Coupon.created_at.desc())
    pg = q.paginate(page=request.args.get("page", 1, type=int), per_page=10, error_out=False)
    return jsonify({
        "items": [{
            "id": c.id,
            "code": c.code,
            "discount_type": c.discount_type,
            "discount_value": c.discount_value,
            "used": c.used,
            "max_uses": c.max_uses,
            "is_active": c.is_active,
            "expires_at": c.expires_at.strftime("%Y-%m-%d %H:%M") if c.expires_at else ""
        } for c in pg.items],
        "page": pg.page,
        "pages": pg.pages,
        "total": pg.total,
        "has_next": pg.has_next,
        "has_prev": pg.has_prev
    })

@app.route("/api/admin/coupon/create", methods=["POST"])
@login_required
@admin_required
def create_coupon():
    staff = db.session.get(Staff, session["staff_id"])
    data = request.get_json() or {}
    code = data.get("code", "").strip().upper()
    dtype = data.get("discount_type", "fixed")
    dval = float(data.get("discount_value") or 0)
    max_u = int(data.get("max_uses") or 1)
    expiry_str = data.get("expires_at", "")
    
    if not code or dval <= 0 or not expiry_str:
        return jsonify({"error": "Missing or invalid fields."}), 400
        
    if Coupon.query.filter_by(code=code).first():
        return jsonify({"error": "Coupon code already exists."}), 400
        
    try:
        expires_at = datetime.strptime(expiry_str, "%Y-%m-%dT%H:%M")
    except ValueError:
        try:
            expires_at = datetime.strptime(expiry_str, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid expiry date format."}), 400
            
    c = Coupon(
        id=generate_id("CP", 10),
        code=code,
        discount_type=dtype,
        discount_value=dval,
        max_uses=max_u,
        expires_at=expires_at,
        created_by=staff.id,
        is_active=True
    )
    db.session.add(c)
    db.session.commit()
    log_action(f"Created coupon {code}", 200, staff.id)
    return jsonify({"msg": "Coupon created successfully."})

@app.route("/api/admin/coupon/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_coupon():
    staff = db.session.get(Staff, session["staff_id"])
    data = request.get_json() or {}
    c = db.session.get(Coupon, data.get("coupon_id"))
    if not c:
        return jsonify({"error": "Coupon not found."}), 404
    c.is_active = not c.is_active
    db.session.commit()
    log_action(f"Toggled coupon {c.code}", 200, staff.id)
    return jsonify({"msg": "Coupon status updated.", "is_active": c.is_active})

@app.route("/api/admin/coupon/delete", methods=["POST"])
@login_required
@admin_required
def delete_coupon():
    staff = db.session.get(Staff, session["staff_id"])
    data = request.get_json() or {}
    c = db.session.get(Coupon, data.get("coupon_id"))
    if not c:
        return jsonify({"error": "Coupon not found."}), 404
    db.session.delete(c)
    db.session.commit()
    log_action(f"Deleted coupon {c.code}", 200, staff.id)
    return jsonify({"msg": "Coupon deleted successfully."})

@app.route("/cp/books")
@login_required
@admin_required
def books_admin():
    q = Book.query.filter_by(is_deleted=False)
 
    search_term = request.args.get("q", "").strip()
    if search_term:
        like = f"%{search_term}%"
        q = q.filter(db.or_(Book.title.ilike(like), Book.authors.ilike(like)))
 
    pagination = q.order_by(Book.added_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=10, error_out=False
    )
 
    return redirect(url_for(''))

@app.route("/cp/books/new", methods=["GET", "POST"])
@login_required
@admin_required
def add_book():
    staff = db.session.get(Staff, session["staff_id"])
    if request.method == "GET": return render_template("book/add_book.html")
    img, fn = request.files.get("image"), "default.png"
    if img and img.filename:
        fn = f"{secrets.token_hex(10)}.{img.filename.rsplit('.', 1)[1].lower()}"
        img.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
    bid = generate_id('BK')
    existing = Book.query.filter_by(id=bid).first()
    
    if existing:
        bid = generate_id('BK')
        
    bk = Book(id=bid,
        title=request.form.get("title"), authors=request.form.get("authors"), audience=request.form.get("audience"),
        grade=request.form.get("grade"), blurb=request.form.get("blurb"), oldPrice=float(request.form.get("oldPrice") or 0),
        newPrice=float(request.form.get("newPrice") or 0), image=fn, discounted=bool(request.form.get("discounted")), added_by=staff.id
    )
    db.session.add(bk)
    bk.set_slug()
    db.session.commit()
    log_action(f"Added book {bk.title}", 200, staff.id)
    return redirect(url_for("books_admin"))

@app.route("/cp/books/edit/<string:id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_book(id):
    staff = db.session.get(Staff, session["staff_id"])
    bk = Book.query.get_or_404(id)
    if request.method == "GET": return render_template("book/edit_book.html", book=bk)
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

@app.route("/api/admin/books")
@login_required
@admin_required
def admin_api_books():
    q = Book.query.filter_by(is_deleted=False)
    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(Book.title.ilike(like), Book.authors.ilike(like)))
    q = q.order_by(Book.added_at.desc())
    pg = q.paginate(page=request.args.get("page", 1, type=int), per_page=10, error_out=False)
    return jsonify({
        "items": [{"id": b.id, "title": b.title, "authors": b.authors, "grade": b.grade, "newPrice": b.newPrice, "image_url": b.image_url} for b in pg.items],
        "page": pg.page, "pages": pg.pages, "total": pg.total, "has_next": pg.has_next, "has_prev": pg.has_prev
    })

@app.route("/api/admin/orders")
@login_required
@admin_required
def admin_api_orders():
    q = Order.query
    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(Order.name.ilike(like), Order.phone.ilike(like), Order.id.ilike(like)))
    q = q.order_by(Order.created_at.desc())
    pg = q.paginate(page=request.args.get("page", 1, type=int), per_page=10, error_out=False)
    return jsonify({
        "items": [{"id": o.id, "name": o.name, "phone": o.phone, "city": o.city, "grand_total": o.grand_total, "status": o.status} for o in pg.items],
        "page": pg.page, "pages": pg.pages, "total": pg.total, "has_next": pg.has_next, "has_prev": pg.has_prev
    })

@app.route("/api/admin/staff-list")
@login_required
@admin_required
def admin_api_staff_list():
    q = Staff.query.filter_by(is_super_admin=False)
    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(Staff.name.ilike(like), Staff.phone.ilike(like), Staff.email.ilike(like)))
    q = q.order_by(Staff.added_at.desc())
    pg = q.paginate(page=request.args.get("page", 1, type=int), per_page=10, error_out=False)
    return jsonify({
        "items": [{"id": s.id, "name": s.name, "email": s.email, "phone": s.phone, "location": s.location, "is_admin": s.is_admin, "is_active": s.is_active} for s in pg.items],
        "page": pg.page, "pages": pg.pages, "total": pg.total, "has_next": pg.has_next, "has_prev": pg.has_prev
    })

@app.route("/api/admin/reports")
@login_required
@admin_required
def admin_api_reports():
    q = Submission.query
    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(db.or_(Submission.staffName.ilike(like), Submission.institution_name.ilike(like), Submission.contact_person.ilike(like)))
    q = q.order_by(Submission.submitted_at.desc())
    pg = q.paginate(page=request.args.get("page", 1, type=int), per_page=10, error_out=False)
    return jsonify({
        "items": [{
            "id": s.id, "staffName": s.staffName, "institution_name": s.institution_name,
            "contact_person": s.contact_person, "phone": s.phone, "conversation_notes": s.conversation_notes,
            "isSold": s.isSold, "submitted_at": s.submitted_at.strftime("%b %d, %Y") if s.submitted_at else ""
        } for s in pg.items],
        "page": pg.page, "pages": pg.pages, "total": pg.total, "has_next": pg.has_next, "has_prev": pg.has_prev
    })

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
    fn = f"{generate_id('IMG')}.{ext}"
    img.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
    return jsonify({"path": fn, "url": url_for("book_cover", filename=fn)})


@app.route("/about", methods=["GET"])
def about():
    return render_template('company/about.html')

@app.route("/contact-us", methods=["GET"])
def contact_us():
    return render_template('company/contact.html')



@app.post("/api/create-order")
def create_order():
    data = request.get_json(silent=True) or {}

    cart = data.get("cart", [])
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()
    county = data.get("county", "").strip()
    city = data.get("city", "").strip()
    address = data.get("address", "").strip()
    coupon_code = (data.get("coupon") or "").strip().upper()

    if not cart:
        return jsonify(success=False, error="Your cart is empty."), 400

    if not all([name, email, phone, county, city, address]):
        return jsonify(success=False, error="Please fill in all shipping details."), 400

    near = {
        "Nairobi", "Kiambu", "Machakos", "Kajiado",
        "Muranga", "Kirinyaga", "Nyandarua", "Nyeri"
    }

    far = {
        "Nakuru", "Narok", "Laikipia", "Meru", "Embu",
        "Tharaka Nithi", "Makueni", "Kitui",
        "Bomet", "Kericho", "Nandi",
        "Uasin Gishu", "Elgeyo Marakwet",
        "Baringo", "Trans Nzoia",
        "Kakamega", "Bungoma", "Busia",
        "Kisumu", "Siaya", "Vihiga",
        "Homa Bay", "Migori", "Kisii",
        "Nyamira"
    }

    if county in near:
        delivery_fee = 200
    elif county in far:
        delivery_fee = 300
    else:
        delivery_fee = 400

    subtotal = 0
    items = []

    for entry in cart:
        book = db.session.get(Book, entry.get("id"))

        if not book or book.is_deleted:
            return jsonify(
                success=False,
                error="One or more selected books no longer exist."
            ), 400

        qty = max(1, int(entry.get("qty", 1)))

        line_total = qty * book.newPrice

        subtotal += line_total

        items.append({
            "id": book.id,
            "title": book.title,
            "image": book.image_url,
            "price": book.newPrice,
            "qty": qty,
            "subtotal": line_total
        })

    coupon = None
    discount = 0

    if coupon_code:
        coupon = Coupon.query.filter_by(
            code=coupon_code,
            is_active=True
        ).first()

        if not coupon:
            return jsonify(success=False, error="Invalid coupon."), 400

        if coupon.expires_at < datetime.utcnow() + timedelta(hours=3):
            return jsonify(success=False, error="Coupon has expired."), 400

        if coupon.used >= coupon.max_uses:
            return jsonify(success=False, error="Coupon usage limit reached."), 400

        if coupon.discount_type == "percentage":
            discount = subtotal * (coupon.discount_value / 100)
        else:
            discount = coupon.discount_value

        discount = min(discount, subtotal)

    grand_total = subtotal - discount + delivery_fee

    order = Order(
        temp_id=generate_id("TMP", 8),
        data=items,
        name=name,
        email=email,
        phone=phone,
        city=city,
        address=address,
        subtotal=subtotal,
        discount=discount,
        delivery_fee=delivery_fee,
        grand_total=grand_total,
        coupon_code=coupon.code if coupon else None,
        status="PENDING"
    )

    db.session.add(order)
    db.session.flush()

    if coupon:
        coupon.used += 1

        used_orders = json.loads(coupon.used_orders or "[]")
        used_orders.append(order.id)
        coupon.used_orders = json.dumps(used_orders)

    db.session.commit()

    return jsonify(
        success=True,
        order_id=order.id,
        redirect=url_for("checkout", oid=order.id)
    )
    
@app.route("/api/pay", methods=["POST"])
@limiter.limit("1 per minute")
def pay():
    try:
        order = db.session.get(Order, request.get_json().get("order_id"))
        if not order: return jsonify({"error": "Order not found."}), 404
        if order.status == "PAID": return jsonify({"error": "Order already paid."}), 400
        res = initiate_payment(order)
        order.checkout_request_id = res.get("CheckoutRequestID")
        db.session.commit()
        send_purchase_email(order)
        return jsonify(res)
    except Exception as e:
        traceback.print_exc()
        print(str(e))
        return f"error occured: {str(e)}"

prefixes = (
    "/resources/books/covers/",
    "resources/books/covers/",
)


@app.route("/api/labels")
def get_labels():
    labels = (
        db.session.query(
            Book.grade,
            func.count(Book.id)
        )
        .group_by(Book.grade)
        .all()
    )

    return jsonify([
        {
            "label": grade,
            "count": count
        }
        for grade, count in labels
    ])

@app.route("/wishlist")
def wishlist():
    return render_template("wishlist.html")

@app.route("/api/books/batch")
def books_batch():
    ids = [i.strip() for i in request.args.get("ids", "").split(",") if i.strip()]
    if not ids:
        return jsonify({"items": []})
    books = Book.query.filter(Book.id.in_(ids), Book.is_deleted == False).all()
    return jsonify({"items": [
        {"id": b.id, "title": b.title, "image_url": b.image_url, "newPrice": b.newPrice,
         "oldPrice": b.oldPrice, "audience": b.audience, "authors": b.authors}
        for b in books
    ]})

@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    return redirect(url_for('books', q=query, sort='newest'))
            
@app.route("/clear-cache")
def clear_url_cache():
    changed = []

    books = Book.query.all()

    for book in books:
        if book.image:
            for prefix in prefixes:
                if book.image.startswith(prefix):
                    book.image = book.image[len(prefix):]
                    changed.append(book.title)
                    break

    db.session.commit()

    return jsonify({
        "updated": len(changed),
        "books": changed
    })
    
@app.route("/delivery-policy")
def delivery_policy():
    return render_template("delivery_policy.html")

@app.route("/mpesa/callback", methods=["POST"])
def mpesa_callback():
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
    id = request.args.get('id')
    order =  order=db.session.get(Order,id)
    if not id:
        return render_template('track.html')
    if not order:
       flash('Order not found. Please check again or contact support', 'error')
       return render_template("track.html")
    return render_template("track.html", order=order)
   

@app.route("/api/order-status")
@limiter.limit("12 per minute")
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
    print(os.getenv('M_P'))
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

@app.route("/stores")
def stores():
    q = Store.query.filter_by(is_active=True)
    search_term = request.args.get("q", "").strip()
    if search_term:
        like = f"%{search_term}%"
        q = q.filter(db.or_(Store.name.ilike(like), Store.city.ilike(like), Store.address.ilike(like)))
    stores_list = q.order_by(Store.city.asc(), Store.name.asc()).all()
    return render_template("stores/stores.html", stores=stores_list, search=search_term)

@app.route("/store/<string:store_name>")
def store_detail(store_name):
    sanitized = store_name.replace('-', ' ')
    store = Store.query.filter(db.func.lower(Store.name) == sanitized.lower(), Store.is_active == True).first_or_404()
    other_stores = Store.query.filter(Store.id != store.id, Store.is_active == True).order_by(Store.name.asc()).limit(4).all()
    return render_template("stores/store.html", store=store, other_stores=other_stores)


@app.route("/cp/stores")
@login_required
@admin_required
def stores_admin():
    q = Store.query
    search_term = request.args.get("q", "").strip()
    if search_term:
        like = f"%{search_term}%"
        q = q.filter(db.or_(Store.name.ilike(like), Store.city.ilike(like)))
    pagination = q.order_by(Store.added_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=10, error_out=False
    )
    return render_template("stores/admin.html", admin=db.session.get(Staff, session["staff_id"]),
                           stores=pagination.items, pagination=pagination, search=search_term)

@app.route("/cp/stores/new", methods=["POST"])
@login_required
@admin_required
def add_store():
    staff = db.session.get(Staff, session["staff_id"])
    img, fn = request.files.get("image"), None
    if img and img.filename:
        fn = f"{secrets.token_hex(10)}.{img.filename.rsplit('.', 1)[1].lower()}"
        img.save(os.path.join(app.config["STORES_FOLDER"], fn))

    store = Store(
        name=request.form.get("name"),
        city=request.form.get("city"),
        address=request.form.get("address"),
        phone=request.form.get("phone"),
        email=request.form.get("email"),
        hours=request.form.get("hours"),
        description=request.form.get("description"),
        latitude=float(request.form["latitude"]) if request.form.get("latitude") else None,
        longitude=float(request.form["longitude"]) if request.form.get("longitude") else None,
    )
    if fn:
        store.image = fn
    db.session.add(store)
    db.session.commit()
    log_action(f"Added store {store.name}", 200, staff.id)
    return redirect(url_for("stores_admin"))

@app.route("/cp/stores/edit/<string:id>", methods=["POST"])
@login_required
@admin_required
def edit_store(id):
    staff = db.session.get(Staff, session["staff_id"])
    store = Store.query.get_or_404(id)

    for fld in ["name", "city", "address", "phone", "email", "hours", "description"]:
        setattr(store, fld, request.form.get(fld))

    store.latitude = float(request.form["latitude"]) if request.form.get("latitude") else None
    store.longitude = float(request.form["longitude"]) if request.form.get("longitude") else None

    img = request.files.get("image")
    if img and img.filename:
        fn = f"{secrets.token_hex(10)}.{img.filename.rsplit('.', 1)[1].lower()}"
        img.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
        store.image = fn

    db.session.commit()
    log_action(f"Edited store {store.name}", 200, staff.id)
    return redirect(url_for("stores_admin"))

@app.route("/api/admin/toggle_store/<string:id>", methods=["POST"])
@login_required
@admin_required
def toggle_store(id):
    staff = db.session.get(Staff, session["staff_id"])
    store = Store.query.get_or_404(id)
    store.is_active = not store.is_active
    db.session.commit()
    log_action(f"Toggled visibility for store {store.name}", 200, staff.id)
    return redirect(url_for("stores_admin"))

@app.route("/api/admin/delete_store/<string:id>", methods=["POST"])
@login_required
@admin_required
def delete_store(id):
    staff = db.session.get(Staff, session["staff_id"])
    store = Store.query.get_or_404(id)
    log_action(f"Deleted store {store.name}", 200, staff.id)
    db.session.delete(store)
    db.session.commit()
    return redirect(url_for("stores_admin"))

@app.route("/gallery")
def gallery():
    category = request.args.get("cat", "").strip()
    q = GalleryImage.query.filter_by(is_active=True)
    if category:
        q = q.filter(GalleryImage.category.ilike(category))
    pagination = q.order_by(GalleryImage.added_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=24, error_out=False
    )
    categories = [c[0] for c in db.session.query(GalleryImage.category).filter(
        GalleryImage.category.isnot(None), GalleryImage.is_active == True
    ).distinct().all() if c[0]]
    return render_template("company/gallery.html", images=pagination.items, pagination=pagination, categories=categories, active_category=category)



@app.route("/cp/gallery")
@login_required
@admin_required
def gallery_admin():
    q = GalleryImage.query
    search_term = request.args.get("q", "").strip()
    if search_term:
        like = f"%{search_term}%"
        q = q.filter(db.or_(GalleryImage.caption.ilike(like), GalleryImage.category.ilike(like)))
    pagination = q.order_by(GalleryImage.added_at.desc()).paginate(
        page=request.args.get("page", 1, type=int), per_page=12, error_out=False
    )
    return render_template("admin/gallery.html", admin=db.session.get(Staff, session["staff_id"]),
                           images=pagination.items, pagination=pagination, search=search_term)

@app.route("/cp/gallery/new", methods=["POST"])
@login_required
@admin_required
def add_gallery_image():
    staff = db.session.get(Staff, session["staff_id"])
    img = request.files.get("image")
    if not img or not img.filename:
        flash("Please choose a photo to upload.", "error")
        return redirect(url_for("gallery_admin"))

    fn = f"{secrets.token_hex(10)}.{img.filename.rsplit('.', 1)[1].lower()}"
    img.save(os.path.join(app.config["GALLERY_FOLDER"], fn))

    photo = GalleryImage(
        image=fn,
        caption=request.form.get("caption", "").strip(),
        category=request.form.get("category", "").strip() or None
    )
    db.session.add(photo)
    db.session.commit()
    log_action("Uploaded gallery photo", 200, staff.id)
    return redirect(url_for("gallery_admin"))

@app.route("/cp/gallery/edit/<string:id>", methods=["POST"])
@login_required
@admin_required
def edit_gallery_image(id):
    staff = db.session.get(Staff, session["staff_id"])
    photo = GalleryImage.query.get_or_404(id)

    photo.caption = request.form.get("caption", "").strip()
    photo.category = request.form.get("category", "").strip() or None

    img = request.files.get("image")
    if img and img.filename:
        fn = f"{secrets.token_hex(10)}.{img.filename.rsplit('.', 1)[1].lower()}"
        img.save(os.path.join(app.config["UPLOAD_FOLDER"], fn))
        photo.image = fn

    db.session.commit()
    log_action("Edited gallery photo", 200, staff.id)
    return redirect(url_for("gallery_admin"))

@app.route("/api/admin/toggle_gallery/<string:id>", methods=["POST"])
@login_required
@admin_required
def toggle_gallery_image(id):
    staff = db.session.get(Staff, session["staff_id"])
    photo = GalleryImage.query.get_or_404(id)
    photo.is_active = not photo.is_active
    db.session.commit()
    log_action("Toggled visibility for a gallery photo", 200, staff.id)
    return redirect(url_for("gallery_admin"))

@app.route("/api/admin/delete_gallery/<string:id>", methods=["POST"])
@login_required
@admin_required
def delete_gallery_image(id):
    staff = db.session.get(Staff, session["staff_id"])
    photo = GalleryImage.query.get_or_404(id)
    log_action("Deleted a gallery photo", 200, staff.id)
    db.session.delete(photo)
    db.session.commit()
    return redirect(url_for("gallery_admin"))

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    print('iiiiiiiiiiiii')
    app.run(host="0.0.0.0", port=5000, debug=True)