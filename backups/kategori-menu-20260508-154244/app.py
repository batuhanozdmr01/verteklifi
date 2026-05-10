import os
import re
import json
import csv
import io
import shutil
import hmac
import hashlib
import binascii
import base64
import uuid
from functools import lru_cache
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy.exc import OperationalError
from datetime import datetime, timedelta

def load_env_file(path='.env'):
    if not os.path.exists(path):
        return

    with open(path, encoding='utf-8') as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    load_env_file()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cok-gizli-bir-anahtar-123')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///goktug.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'timeout': 30}}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

def generate_password_hash(password, method='pbkdf2:sha256', salt_length=16):
    if not password:
        raise ValueError("Password must not be empty.")
    parts = method.split(':')
    if len(parts) == 2 and parts == ['pbkdf2', 'sha256']:
        iterations = 260000
    elif len(parts) == 3 and parts[0] == 'pbkdf2' and parts[1] == 'sha256':
        iterations = int(parts[2])
    else:
        raise ValueError(f"Unsupported hash method '{method}'")

    salt = os.urandom(salt_length)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f"pbkdf2:sha256:{iterations}${binascii.hexlify(salt).decode('ascii')}${binascii.hexlify(hash_bytes).decode('ascii')}"


def check_password_hash(pwhash, password):
    if not pwhash or not password:
        return False
    try:
        method, algo, rest = pwhash.split(':', 2)
        if method != 'pbkdf2' or algo != 'sha256':
            return False

        iterations, salt_hex, hash_hex = rest.split('$', 2)
        iterations = int(iterations)
        salt = binascii.unhexlify(salt_hex)
        expected_hash = binascii.unhexlify(hash_hex)
        test_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return hmac.compare_digest(test_hash, expected_hash)
    except (ValueError, TypeError, binascii.Error):
        return False

# Modeller
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    ban_until = db.Column(db.DateTime, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    district = db.Column(db.String(100), nullable=True)
    neighborhood = db.Column(db.String(100), nullable=True)
    withdraw_count = db.Column(db.Integer, default=0)
    
    products = db.relationship('Product', backref='owner', foreign_keys='Product.owner_id', cascade="all, delete-orphan", lazy=True)
    bids = db.relationship('Bid', backref='user', cascade="all, delete-orphan", lazy=True)
    chat_messages = db.relationship('ChatMessage', backref='user', cascade="all, delete-orphan", lazy=True)
    favorites = db.relationship('Favorite', backref='user', cascade="all, delete-orphan", lazy=True)
    notifications = db.relationship('Notification', backref='user', cascade="all, delete-orphan", lazy=True)

    @property
    def is_banned(self):
        return self.ban_until is not None and self.ban_until > datetime.now()

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    max_price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)
    start_price = db.Column(db.Integer, nullable=False)
    current_bid = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(500)) # Ana resim
    image_urls = db.Column(db.Text) # JSON string for up to 5 images
    end_time = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner_name = db.Column(db.String(100))
    
    # status: 'pending_admin_approval', 'active', 'pending_seller_approval', 'pending_bidder_action', 'seller_info_confirmation', 'completed', 'cancelled'
    status = db.Column(db.String(50), default='active') 
    matched_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    bids = db.relationship('Bid', backref='product', cascade="all, delete-orphan", lazy=True)
    chat_messages = db.relationship('ChatMessage', backref='product', cascade="all, delete-orphan", lazy=True)
    favorites = db.relationship('Favorite', backref='product', cascade="all, delete-orphan", lazy=True)
    matched_user = db.relationship('User', foreign_keys=[matched_user_id])

class ProductExtra(db.Model):
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), primary_key=True)
    condition = db.Column(db.String(40), nullable=True)
    exchange_open = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Bid(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_name = db.Column(db.String(100))

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class PrivateMessageMeta(db.Model):
    message_id = db.Column(db.Integer, db.ForeignKey('private_message.id'), primary_key=True)
    kind = db.Column(db.String(40), nullable=False, index=True)
    target_product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    offered_product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)

    message = db.relationship('PrivateMessage', backref=db.backref('meta', uselist=False))
    target_product = db.relationship('Product', foreign_keys=[target_product_id])
    offered_product = db.relationship('Product', foreign_keys=[offered_product_id])

class PrivateConversationState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    partner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    deleted_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'partner_id', name='uq_private_conversation_state_user_partner'),
    )

class BlockedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    blocked_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('blocker_id', 'blocked_id', name='uq_blocked_user_pair'),
    )

class ExchangeOffer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    target_product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    offered_product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('private_message.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime, nullable=True)

class FeaturedProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False, unique=True, index=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='unique_user_product_favorite'),)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.String(300), nullable=False)
    notification_type = db.Column(db.String(40), default='info')
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    message_id = db.Column(db.Integer, db.ForeignKey('chat_message.id'), nullable=True)
    target_type = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(300), nullable=False)
    status = db.Column(db.String(20), default='open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class SiteSetting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.String(300), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    target_type = db.Column(db.String(40), nullable=True)
    target_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    note = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserModeration(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    chat_ban_until = db.Column(db.DateTime, nullable=True)
    phone_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    warning_count = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class UserProfile(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    image_url = db.Column(db.String(500), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ProductModeration(db.Model):
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), primary_key=True)
    is_hidden = db.Column(db.Boolean, default=False)
    image_flagged = db.Column(db.Boolean, default=False)
    reason = db.Column(db.String(300), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    rater_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rated_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('product_id', 'rater_id', 'rated_user_id', name='unique_sale_rating'),)

class Appeal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=True)
    message = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='open')
    admin_response = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

class ProxyBid(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    max_amount = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='unique_user_product_proxy_bid'),)

class SavedSearch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    query = db.Column(db.String(120), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    brand = db.Column(db.String(100), nullable=True)
    min_price = db.Column(db.Integer, nullable=True)
    max_price = db.Column(db.Integer, nullable=True)
    location = db.Column(db.String(120), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_notified_product_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ProductView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    viewer_key = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SaleProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), unique=True, nullable=False)
    contact_made = db.Column(db.Boolean, default=False)
    delivered = db.Column(db.Boolean, default=False)
    paid = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_product_participants(product):
    participants = {}
    for bid in sorted(product.bids, key=lambda b: b.timestamp or datetime.min):
        participant = participants.setdefault(bid.user_id, {
            "user_id": bid.user_id,
            "user_name": bid.user_name,
            "last_amount": bid.amount,
            "bid_count": 0
        })
        participant["user_name"] = bid.user_name
        participant["last_amount"] = max(participant["last_amount"], bid.amount)
        participant["bid_count"] += 1

    return sorted(participants.values(), key=lambda p: p["last_amount"], reverse=True)

def get_product_images(product):
    if not product.image_urls:
        return [product.image_url] if product.image_url else []

    try:
        images = json.loads(product.image_urls)
        if isinstance(images, list):
            return images
    except (TypeError, ValueError):
        pass

    return product.image_urls.split(',')

def format_product_location(product):
    owner = product.owner
    city = owner.city if owner else None
    district = owner.district if owner else None
    parts = [part for part in (city, district) if part]
    return " / ".join(parts) if parts else "Konum yok"

def get_product_status_label(status):
    labels = {
        "pending_admin_approval": "Onay bekliyor",
        "active": "Aktif",
        "pending_seller_approval": "Satıcı Onayı",
        "pending_bidder_action": "Alıcı Onayı",
        "seller_info_confirmation": "Bilgi Onayı",
        "completed": "Satıldı",
        "cancelled": "İptal"
    }
    return labels.get(status, status or "Aktif")

def repair_turkish_mojibake(value):
    if value is None:
        return value

    text = str(value)
    mojibake_markers = ('Ã', 'Ä', 'Å', 'Â', 'Ð', 'ð', 'Þ', 'þ', 'Ý', 'ý', '�', 'â‚º')

    def mojibake_score(candidate):
        return sum(candidate.count(marker) for marker in mojibake_markers)

    text = text.replace('â‚º', '₺')
    for _ in range(5):
        best = text
        best_score = mojibake_score(text)
        for encoding in ('cp1254', 'latin1', 'cp1252'):
            try:
                candidate = text.encode(encoding).decode('utf-8')
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            candidate = candidate.replace('â‚º', '₺')
            score = mojibake_score(candidate)
            if score < best_score:
                best = candidate
                best_score = score
        if best == text:
            break
        text = best
    return text

def create_notification(user_id, title, message, notification_type='info', product_id=None):
    if not user_id:
        return
    if notification_type in {'product', 'search'}:
        return

    db.session.add(Notification(
        user_id=user_id,
        title=repair_turkish_mojibake(title),
        message=repair_turkish_mojibake(message)[:300],
        notification_type=notification_type,
        product_id=product_id
    ))

def create_unique_unread_notification(user_id, title, message, notification_type='info', product_id=None):
    if not user_id:
        return
    if notification_type == 'private_message':
        return

    existing = Notification.query.filter_by(
        user_id=user_id,
        title=title,
        message=message[:300],
        notification_type=notification_type,
        product_id=product_id,
        is_read=False
    ).first()
    if existing:
        existing.created_at = datetime.utcnow()
        return

    create_notification(user_id, title, message, notification_type, product_id)

def notify_product_owner_message(product, sender):
    if not product or not sender or product.owner_id == sender.id:
        return

    create_unique_unread_notification(
        product.owner_id,
        "Yeni ilan mesajı",
        f"{sender.name}, {product.title} ilanına mesaj yazdı.",
        "chat",
        product.id
    )

def notify_product_watchers(product, sender_id, title=None, message=None, notification_type='chat'):
    sender = User.query.get(sender_id)
    notify_product_owner_message(product, sender)

def notify_favorite_watchers_bid(product, bidder, amount):
    if not product or not bidder:
        return
    favorite_user_ids = {
        favorite.user_id
        for favorite in Favorite.query.filter_by(product_id=product.id).all()
        if favorite.user_id not in {product.owner_id, bidder.id}
    }
    for user_id in favorite_user_ids:
        create_notification(
            user_id,
            "Favorindeki ilana teklif geldi",
            f"{product.title} ilanına {amount} TL teklif yapıldı.",
            "bid",
            product.id
        )

DEFAULT_SITE_SETTINGS = {
    "min_bid": "5",
    "bid_step": "5",
    "chat_spam_seconds": "5",
    "default_duration_days": "7",
    "max_images": "5",
    "maintenance_mode": "0"
}

def get_site_settings():
    settings = DEFAULT_SITE_SETTINGS.copy()
    for setting in SiteSetting.query.all():
        settings[setting.key] = setting.value
    default_duration_days = int(settings.get("default_duration_days", 7))
    if default_duration_days not in {1, 7, 30, 90, 180}:
        default_duration_days = 7

    return {
        "min_bid": int(settings.get("min_bid", 5)),
        "bid_step": int(settings.get("bid_step", 5)),
        "chat_spam_seconds": int(settings.get("chat_spam_seconds", 5)),
        "default_duration_days": default_duration_days,
        "max_images": int(settings.get("max_images", 5)),
        "maintenance_mode": settings.get("maintenance_mode", "0") == "1"
    }

def update_site_setting(key, value):
    setting = SiteSetting.query.get(key)
    if setting:
        setting.value = str(value)
    else:
        db.session.add(SiteSetting(key=key, value=str(value)))

def log_admin_action(action, target_type=None, target_id=None, detail=None):
    admin_id = current_user.id if current_user.is_authenticated else None
    db.session.add(AdminLog(
        admin_id=admin_id,
        action=repair_turkish_mojibake(action),
        target_type=target_type,
        target_id=target_id,
        detail=repair_turkish_mojibake(detail or "")[:500]
    ))

def calculate_user_risk(user):
    report_count = Report.query.filter(
        Report.status == 'open',
        Report.product_id.in_([product.id for product in user.products] or [-1])
    ).count()
    message_report_count = Report.query.join(ChatMessage, Report.message_id == ChatMessage.id).filter(
        Report.status == 'open',
        ChatMessage.user_id == user.id
    ).count()
    user_report_count = Report.query.filter(
        Report.status == 'open',
        Report.target_type == 'user',
        Report.reason.like(f"[USER:{user.id}]%")
    ).count()
    total_reports = report_count + message_report_count + user_report_count
    score = total_reports * 2 + (user.withdraw_count or 0)
    if user.is_banned or score >= 5:
        label = "Yüksek"
    elif score >= 2:
        label = "Orta"
    else:
        label = "Düşük"

    return {
        "label": label,
        "score": score,
        "report_count": total_reports,
        "withdraw_count": user.withdraw_count or 0
    }

def get_user_moderation(user_id):
    moderation = UserModeration.query.get(user_id)
    if not moderation:
        moderation = UserModeration(user_id=user_id)
        db.session.add(moderation)
    return moderation

def get_user_profile(user_id):
    profile = UserProfile.query.get(user_id)
    if not profile:
        profile = UserProfile(user_id=user_id)
        db.session.add(profile)
    return profile

def get_user_profile_image_url(user_id):
    profile = UserProfile.query.get(user_id)
    return profile.image_url if profile and profile.image_url else None

def get_product_moderation(product_id):
    moderation = ProductModeration.query.get(product_id)
    if not moderation:
        moderation = ProductModeration(product_id=product_id)
        db.session.add(moderation)
    return moderation

def get_product_extra(product_id):
    extra = ProductExtra.query.get(product_id)
    if not extra:
        extra = ProductExtra(product_id=product_id)
        db.session.add(extra)
    return extra

def is_chat_banned(user):
    moderation = UserModeration.query.get(user.id)
    return bool(moderation and moderation.chat_ban_until and moderation.chat_ban_until > datetime.now())

def get_user_rating_summary(user_id):
    ratings = Rating.query.filter_by(rated_user_id=user_id).all()
    if not ratings:
        return {"count": 0, "average": 0}
    average = round(sum(rating.score for rating in ratings) / len(ratings), 1)
    return {"count": len(ratings), "average": average}

def get_user_badges(user):
    moderation = UserModeration.query.get(user.id)
    rating = get_user_rating_summary(user.id)
    completed_sales = Product.query.filter_by(owner_id=user.id, status='completed').count()
    badges = []
    if moderation and moderation.phone_verified:
        badges.append({"label": "Telefon dogrulandi", "type": "verified"})
    if rating["count"] >= 3 and rating["average"] >= 4.5:
        badges.append({"label": "Guvenilir satici", "type": "trusted"})
    if completed_sales >= 5:
        badges.append({"label": f"{completed_sales} satis tamamlandi", "type": "sales"})
    if not badges and rating["count"]:
        badges.append({"label": f"{rating['average']} puan", "type": "rating"})
    return badges

def get_public_trust_summary(user):
    moderation = UserModeration.query.get(user.id)
    rating = get_user_rating_summary(user.id)
    completed_sales = Product.query.filter_by(owner_id=user.id, status='completed').count()
    active_products = Product.query.filter_by(owner_id=user.id, status='active').count()
    risk = calculate_user_risk(user)
    score = 40
    if moderation and moderation.phone_verified:
        score += 20
    if rating["count"]:
        score += min(20, int(rating["average"] * 4))
    if completed_sales:
        score += min(15, completed_sales * 3)
    if active_products:
        score += min(5, active_products)
    score -= min(25, risk["score"] * 5)
    score = max(0, min(100, score))
    if score >= 75:
        label = "Yüksek"
    elif score >= 50:
        label = "Orta"
    else:
        label = "Yeni / düşük veri"
    return {"score": score, "label": repair_turkish_mojibake(label)}

def get_public_trust_details(user):
    moderation = UserModeration.query.get(user.id)
    rating = get_user_rating_summary(user.id)
    completed_sales = Product.query.filter_by(owner_id=user.id, status='completed').count()
    active_products = Product.query.filter_by(owner_id=user.id, status='active').count()
    risk = calculate_user_risk(user)
    summary = get_public_trust_summary(user)
    positive = []
    warnings = []
    if moderation and moderation.phone_verified:
        positive.append("Telefon doğrulaması var.")
    else:
        warnings.append("Telefon doğrulaması yok.")
    if rating["count"]:
        positive.append(f"{rating['count']} yorumdan ortalama {rating['average']} puan.")
    else:
        warnings.append("Henüz puanlama verisi az.")
    if completed_sales:
        positive.append(f"{completed_sales} tamamlanan satış.")
    if active_products:
        positive.append(f"{active_products} aktif ilan.")
    if risk["report_count"]:
        warnings.append(f"{risk['report_count']} açık rapor dikkate alınıyor.")
    if risk["withdraw_count"]:
        warnings.append(f"{risk['withdraw_count']} işlemden vazgeçme kaydı var.")
    return {
        "score": summary["score"],
        "label": summary["label"],
        "rating": rating,
        "completedSales": completed_sales,
        "activeProducts": active_products,
        "reportCount": risk["report_count"],
        "withdrawCount": risk["withdraw_count"],
        "phoneVerified": bool(moderation and moderation.phone_verified),
        "positive": positive,
        "warnings": warnings
    }

def get_sale_progress(product_id):
    progress = SaleProgress.query.filter_by(product_id=product_id).first()
    if not progress:
        progress = SaleProgress(product_id=product_id)
        db.session.add(progress)
    return progress

def serialize_sale_progress(product_id):
    progress = SaleProgress.query.filter_by(product_id=product_id).first()
    return {
        "contact_made": bool(progress and progress.contact_made),
        "delivered": bool(progress and progress.delivered),
        "paid": bool(progress and progress.paid)
    }

def save_product_images(images):
    upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'products')
    os.makedirs(upload_dir, exist_ok=True)
    saved_images = []

    for image in images:
        if not isinstance(image, str) or not image.startswith('data:image/'):
            saved_images.append(image)
            continue

        try:
            header, encoded = image.split(',', 1)
            image_type = header.split(';', 1)[0].split('/', 1)[1].lower()
            extension = 'jpg' if image_type in {'jpeg', 'jpg'} else 'png' if image_type == 'png' else 'webp'
            image_bytes = base64.b64decode(encoded)
        except (ValueError, binascii.Error):
            continue

        filename = f"{uuid.uuid4().hex}.{extension}"
        with open(os.path.join(upload_dir, filename), 'wb') as image_file:
            image_file.write(image_bytes)
        saved_images.append(url_for('static', filename=f'uploads/products/{filename}'))

    return saved_images

def save_profile_image(image):
    if not isinstance(image, str) or not image.startswith('data:image/'):
        return None

    try:
        header, encoded = image.split(',', 1)
        image_type = header.split(';', 1)[0].split('/', 1)[1].lower()
        if image_type not in {'jpeg', 'jpg', 'png', 'webp'}:
            return None
        extension = 'jpg' if image_type in {'jpeg', 'jpg'} else image_type
        image_bytes = base64.b64decode(encoded)
    except (ValueError, binascii.Error):
        return None

    if len(image_bytes) > 3 * 1024 * 1024:
        return None

    upload_dir = os.path.join(app.root_path, 'static', 'uploads', 'profiles')
    os.makedirs(upload_dir, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.{extension}"
    with open(os.path.join(upload_dir, filename), 'wb') as image_file:
        image_file.write(image_bytes)
    return url_for('static', filename=f'uploads/profiles/{filename}')

def get_viewer_key():
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    if 'viewer_key' not in session:
        session['viewer_key'] = f"anon:{uuid.uuid4().hex}"
    return session['viewer_key']

def record_product_view(product):
    if current_user.is_authenticated and current_user.id == product.owner_id:
        return False

    viewer_key = get_viewer_key()
    since = datetime.utcnow() - timedelta(hours=6)
    existing = ProductView.query.filter(
        ProductView.product_id == product.id,
        ProductView.viewer_key == viewer_key,
        ProductView.created_at >= since
    ).first()
    if existing:
        return False

    db.session.add(ProductView(
        product_id=product.id,
        user_id=current_user.id if current_user.is_authenticated else None,
        viewer_key=viewer_key
    ))
    db.session.commit()
    return True

def saved_search_matches_product(saved_search, product):
    query = (saved_search.query or '').strip().lower()
    location = (saved_search.location or '').strip().lower()
    product_location = format_product_location(product).lower()
    if query and query not in (product.title or '').lower() and query not in (product.description or '').lower():
        return False
    if saved_search.category and saved_search.category != product.category:
        return False
    if saved_search.brand and saved_search.brand != product.brand:
        return False
    if saved_search.min_price is not None and product.current_bid < saved_search.min_price:
        return False
    if saved_search.max_price is not None and product.current_bid > saved_search.max_price:
        return False
    if location and location not in product_location:
        return False
    return True

def notify_saved_search_matches(product):
    searches = db.session.query(SavedSearch).filter_by(is_active=True).all()
    for saved_search in searches:
        if saved_search.user_id == product.owner_id or saved_search.last_notified_product_id == product.id:
            continue
        if saved_search_matches_product(saved_search, product):
            create_notification(
                saved_search.user_id,
                "Kayitli aramana uygun ilan",
                f"{saved_search.name}: {product.title}",
                "search",
                product.id
            )
            saved_search.last_notified_product_id = product.id

def is_product_visible_to_current_user(product):
    moderation = ProductModeration.query.get(product.id)
    if product.status == 'pending_admin_approval':
        if not current_user.is_authenticated:
            return False
        return is_admin_user() or product.owner_id == current_user.id
    if not moderation or not moderation.is_hidden:
        return True
    if not current_user.is_authenticated:
        return False
    return is_admin_user() or product.owner_id == current_user.id

def auto_moderate_user(user):
    risk = calculate_user_risk(user)
    moderation = get_user_moderation(user.id)
    changed = False
    if risk["report_count"] >= 3 and moderation.warning_count < 1:
        moderation.warning_count += 1
        create_notification(user.id, "Uyarı", "Hakkınızda gelen raporlar nedeniyle hesabınız izlemeye alındı.", "warning")
        changed = True
    if risk["report_count"] >= 5 and not is_chat_banned(user):
        moderation.chat_ban_until = datetime.now() + timedelta(days=7)
        create_notification(user.id, "Sohbet kısıtlandı", "Rapor yoğunluğu nedeniyle sohbetiniz 7 gün kısıtlandı.", "warning")
        changed = True
    return changed

BLOCKED_CHAT_EXACT_TERMS = {
    'amk', 'aq', 'oc', 'pic', 'got', 'ibne', 'kahpe', 'kaltak',
    'pezevenk', 'gavat', 'haysiyetsiz', 'karaktersiz', 'adi',
    'mal', 'salak', 'gerizekali', 'aptal', 'sik', 'bok', 'b0k',
    'puşt', 'pust', 'it', 'kopek', 'köpek', 'hayvan', 'dangalak',
    'angut', 'dingil', 'ezik', 'yavşak', 'yavsak', 'şerefsiz',
    'serefsiz', 'srefsiz', 'namussuz'
}

BLOCKED_CHAT_PREFIXES = (
    'orospu', 'siktir', 'sikik', 'siker', 'sikey', 'sikim',
    'sikis', 'sikiş', 'sikt', 'sikm', 'yarrak', 'yarak', 'amcik', 'amcık',
    'amina', 'amına', 'gotveren', 'götveren', 'anan', 'anneni',
    'anani', 'ananı', 'bacini', 'bacını', 'avrad', 'sülale',
    'sulale', 'seref', 'şeref', 'namus'
)

BLOCKED_CHAT_PHRASES = (
    'anani', 'ananı', 'anneni', 'ananin', 'ananın',
    'bacini', 'bacını', 'bacinin', 'bacının',
    'avradini', 'avradını', 'sulaleni', 'sülaleni'
)

@lru_cache(maxsize=1)
def load_external_profanity_terms():
    terms_path = os.path.join(app.root_path, 'data', 'profanity_tr.txt')
    if not os.path.exists(terms_path):
        return set()

    terms = set()
    with open(terms_path, encoding='utf-8-sig') as terms_file:
        for line in terms_file:
            term = line.strip()
            if term and not term.startswith('#'):
                terms.add(normalize_chat_text(term))
    return terms

def normalize_chat_text(text):
    replacements = str.maketrans({
        'ı': 'i',
        'İ': 'i',
        'ş': 's',
        'Ş': 's',
        'ğ': 'g',
        'Ğ': 'g',
        'ü': 'u',
        'Ü': 'u',
        'ö': 'o',
        'Ö': 'o',
        'ç': 'c',
        'Ç': 'c',
        '@': 'a',
        '4': 'a',
        '1': 'i',
        '!': 'i',
        '3': 'e',
        '0': 'o',
        '5': 's',
        '$': 's',
        '7': 't'
    })
    normalized = text.lower().translate(replacements)
    return re.sub(r'([a-z0-9])\1{2,}', r'\1', normalized)

def contains_blocked_chat_text(text):
    normalized = normalize_chat_text(text)
    compact = re.sub(r'[^a-z0-9]+', ' ', normalized)
    tokens = [token for token in compact.split() if token]
    squeezed = ''.join(tokens)
    candidates = tokens + ([squeezed] if squeezed else [])
    external_terms = load_external_profanity_terms()

    for candidate in candidates:
        if candidate in BLOCKED_CHAT_EXACT_TERMS:
            return True
        if any(candidate.startswith(prefix) for prefix in BLOCKED_CHAT_PREFIXES):
            return True
        if candidate in external_terms:
            return True

    if any(phrase in squeezed for phrase in BLOCKED_CHAT_PHRASES):
        return True
    if any(term and term in squeezed for term in external_terms if len(term) >= 3):
        return True

    return any(term in squeezed for term in {'amk', 'aq', 'oc'})

def cleanup_expired_products():
    expired_products = Product.query.filter(
        Product.status == 'active',
        Product.end_time <= datetime.now()
    ).all()

    if expired_products:
        for product in expired_products:
            db.session.delete(product)
        db.session.commit()

# API Rotaları
def ensure_configured_admin():
    try:
        admin_email = os.environ.get('ADMIN_EMAIL')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        admin_name = os.environ.get('ADMIN_NAME', 'Admin')

        if not admin_email or not admin_password:
            return

        admin_user = User.query.filter_by(email=admin_email).first()
        if admin_user:
            changed = False
            if admin_user.role != 'admin':
                admin_user.role = 'admin'
                changed = True
            if admin_user.name != admin_name:
                admin_user.name = admin_name
                changed = True
            if not check_password_hash(admin_user.password, admin_password):
                admin_user.password = generate_password_hash(admin_password, method='pbkdf2:sha256')
                changed = True
            if changed:
                db.session.commit()
            return

        new_admin = User(
            email=admin_email,
            name=admin_name,
            password=generate_password_hash(admin_password, method='pbkdf2:sha256'),
            role='admin'
        )
        db.session.add(new_admin)
        db.session.commit()
    except OperationalError:
        db.session.rollback()

def is_admin_user(user=None):
    user = user or current_user
    if not user or not user.is_authenticated:
        return False

    admin_email = os.environ.get('ADMIN_EMAIL')
    if admin_email and user.email != admin_email:
        return False

    return user.role == 'admin'

@app.before_request
def bootstrap_configured_admin():
    if not getattr(app, '_configured_admin_checked', False):
        db.create_all()
        ensure_configured_admin()
        app._configured_admin_checked = True
    if request.method in {'POST', 'DELETE', 'PATCH'} and request.path.startswith('/api/') and request.path != '/api/login':
        if get_site_settings()["maintenance_mode"] and not is_admin_user():
            return jsonify({"success": False, "message": "Site bakım modunda. Lütfen daha sonra tekrar deneyin."}), 503

@app.route('/api/products', methods=['GET'])
def get_products():
    cleanup_expired_products()
    products = Product.query.order_by(Product.id.desc()).all()
    favorite_product_ids = set()
    if current_user.is_authenticated:
        favorite_product_ids = {
            favorite.product_id
            for favorite in Favorite.query.filter_by(user_id=current_user.id).all()
        }
    output = []
    for p in products:
        if not is_product_visible_to_current_user(p):
            continue
        moderation = ProductModeration.query.get(p.id)
        extra = ProductExtra.query.get(p.id)
        owner_moderation = UserModeration.query.get(p.owner_id)
        owner_rating = get_user_rating_summary(p.owner_id)
        featured = is_featured_product(p.id)
        prod_data = {
            "id": p.id,
            "title": p.title,
            "category": p.category,
            "brand": p.brand,
            "maxPrice": p.max_price,
            "desc": p.description,
            "startPrice": p.start_price,
            "currentBid": p.current_bid,
            "img": p.image_url,
            "imgs": get_product_images(p),
            "endTime": p.end_time.timestamp() * 1000,
            "createdAt": p.created_at.timestamp() * 1000,
            "owner_id": p.owner_id,
            "owner_name": p.owner_name,
            "owner_profile_image": get_user_profile_image_url(p.owner_id),
            "owner_verified": bool(owner_moderation and owner_moderation.phone_verified),
            "owner_rating": owner_rating,
            "owner_badges": get_user_badges(p.owner),
            "owner_trust": get_public_trust_summary(p.owner),
            "location": format_product_location(p),
            "status": p.status,
            "statusLabel": get_product_status_label(p.status),
            "isFeatured": featured,
            "condition": extra.condition if extra and extra.condition else None,
            "exchangeOpen": bool(extra and extra.exchange_open),
            "isHidden": bool(moderation and moderation.is_hidden),
            "imageFlagged": bool(moderation and moderation.image_flagged),
            "matched_user_id": p.matched_user_id,
            "participants": get_product_participants(p),
            "bidCount": len(p.bids),
            "messageCount": len(p.chat_messages),
            "viewCount": ProductView.query.filter_by(product_id=p.id).count(),
            "favoriteCount": len(p.favorites),
            "isFavorite": p.id in favorite_product_ids
        }
        
        if current_user.is_authenticated:
            proxy = ProxyBid.query.filter_by(user_id=current_user.id, product_id=p.id, is_active=True).first()
            prod_data["myProxyMax"] = proxy.max_amount if proxy else None
            if p.status == 'completed' and is_admin_user():
                seller = User.query.get(p.owner_id)
                prod_data["seller_info"] = {
                    "phone": seller.phone,
                    "email": seller.email,
                    "location": f"{seller.city} / {seller.district} / {seller.neighborhood}"
                }
                prod_data["sale_progress"] = serialize_sale_progress(p.id)
        output.append(prod_data)
    output.sort(key=lambda item: (not item.get("isFeatured"), -item.get("createdAt", 0)))
    return jsonify(output)

def validate_bid_amount(product, amount, settings):
    if amount < settings["min_bid"]:
        return f"Teklif en az {settings['min_bid']} TL olmalidir."
    if amount % settings["bid_step"] != 0:
        return f"Teklifler {settings['bid_step']} TL ve katlari olmalidir."
    if amount < product.start_price:
        return f"Teklif baslangic fiyatindan ({product.start_price} TL) dusuk olamaz"
    if Bid.query.filter_by(product_id=product.id).count() > 0 and amount <= product.current_bid:
        return "Teklif mevcut fiyattan yuksek olmalidir"
    if amount > product.max_price:
        return f"Maksimum teklif siniri {product.max_price} TL"
    return None

def add_bid_to_product(product, user, amount, notification_title="Yeni teklif geldi"):
    db.session.add(Bid(amount=amount, user_id=user.id, product_id=product.id, user_name=user.name))
    product.current_bid = amount
    product.matched_user_id = user.id

    if product.owner_id != user.id:
        create_notification(
            product.owner_id,
            notification_title,
            f"{user.name}, {product.title} ilanina {amount} TL teklif verdi.",
            "bid",
            product.id
        )
    notify_favorite_watchers_bid(product, user, amount)

def recalculate_product_bid_state(product):
    top_bid = Bid.query.filter_by(product_id=product.id, is_active=True).order_by(Bid.amount.desc(), Bid.timestamp.asc()).first()
    if top_bid:
        product.current_bid = top_bid.amount
        product.matched_user_id = top_bid.user_id
    else:
        product.current_bid = product.start_price
        product.matched_user_id = None
    return top_bid

def next_valid_bid_amount(current_amount, max_amount, settings, product_max_price):
    step = settings["bid_step"]
    max_amount = min(max_amount, product_max_price)
    max_valid = max_amount - (max_amount % step)
    if max_valid <= current_amount:
        return None
    next_amount = ((current_amount // step) + 1) * step
    return min(next_amount, max_valid)

def process_auto_bids(product):
    settings = get_site_settings()
    for _ in range(20):
        proxy = ProxyBid.query.filter(
            ProxyBid.product_id == product.id,
            ProxyBid.is_active == True,
            ProxyBid.user_id != product.matched_user_id,
            ProxyBid.max_amount > product.current_bid
        ).order_by(ProxyBid.max_amount.desc(), ProxyBid.updated_at.asc()).first()
        if not proxy:
            break

        next_amount = next_valid_bid_amount(product.current_bid, proxy.max_amount, settings, product.max_price)
        if not next_amount:
            proxy.is_active = False
            continue

        proxy_user = User.query.get(proxy.user_id)
        if not proxy_user or proxy_user.is_banned:
            proxy.is_active = False
            continue

        add_bid_to_product(product, proxy_user, next_amount, "Otomatik teklif geldi")
        if next_amount >= proxy.max_amount or next_amount >= product.max_price:
            proxy.is_active = False

@app.route('/api/place_bid', methods=['POST'])
@login_required
def place_bid():
    if current_user.ban_until and current_user.ban_until > datetime.now():
        return jsonify({"success": False, "message": f"Hesabınız banlıdır."}), 403

    settings = get_site_settings()
    data = request.json or {}
    product_id = data.get('product_id')
    try:
        amount = int(data.get('amount'))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Geçerli bir teklif giriniz."}), 400

    if amount < settings["min_bid"]:
        return jsonify({"success": False, "message": f"Teklif en az {settings['min_bid']} TL olmalıdır."}), 400

    if amount % settings["bid_step"] != 0:
        return jsonify({"success": False, "message": f"Teklifler {settings['bid_step']} TL ve katları olmalıdır."}), 400

    product = Product.query.get(product_id)
    if not product or product.status != 'active':
        return jsonify({"success": False, "message": "Bu ürün şu an tekliflere kapalı"}), 400

    if product.end_time <= datetime.now():
        db.session.delete(product)
        db.session.commit()
        return jsonify({"success": False, "message": "Bu ilanın süresi dolduğu için kaldırıldı."}), 400

    if amount < product.start_price:
        return jsonify({"success": False, "message": f"Teklif başlangıç fiyatından ({product.start_price} ₺) düşük olamaz"}), 400

    # Mevcut teklifleri kontrol et
    existing_bids_count = Bid.query.filter_by(product_id=product.id).count()
    
    if existing_bids_count > 0 and amount <= product.current_bid:
        return jsonify({"success": False, "message": "Teklif mevcut fiyattan yüksek olmalıdır"}), 400

    if amount > product.max_price:
        return jsonify({"success": False, "message": f"Maksimum teklif sınırı {product.max_price} ₺"}), 400

    add_bid_to_product(product, current_user, amount, "Yeni teklif geldi")
    process_auto_bids(product)
    
    db.session.commit()

    return jsonify({"success": True, "current_bid": product.current_bid})

@app.route('/api/proxy_bid', methods=['POST'])
@login_required
def set_proxy_bid():
    data = request.json or {}
    product = Product.query.get(data.get('product_id'))
    try:
        max_amount = int(data.get('max_amount'))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Gecerli bir maksimum teklif giriniz."}), 400

    if not product or product.status != 'active':
        return jsonify({"success": False, "message": "Bu ilan otomatik teklife kapali."}), 400
    if product.owner_id == current_user.id:
        return jsonify({"success": False, "message": "Kendi ilaniniza otomatik teklif veremezsiniz."}), 400
    if max_amount <= product.current_bid:
        return jsonify({"success": False, "message": "Maksimum teklif mevcut fiyattan yuksek olmali."}), 400
    if max_amount > product.max_price:
        return jsonify({"success": False, "message": f"Maksimum teklif siniri {product.max_price} TL"}), 400

    proxy = ProxyBid.query.filter_by(user_id=current_user.id, product_id=product.id).first()
    if proxy:
        proxy.max_amount = max_amount
        proxy.is_active = True
    else:
        db.session.add(ProxyBid(user_id=current_user.id, product_id=product.id, max_amount=max_amount))

    settings = get_site_settings()
    next_amount = next_valid_bid_amount(product.current_bid, max_amount, settings, product.max_price)
    if next_amount and product.matched_user_id != current_user.id:
        add_bid_to_product(product, current_user, next_amount, "Otomatik teklif geldi")
        process_auto_bids(product)

    db.session.commit()
    return jsonify({"success": True, "current_bid": product.current_bid, "max_amount": max_amount})

@app.route('/api/product_view/<int:product_id>', methods=['POST'])
def track_product_view(product_id):
    product = Product.query.get(product_id)
    if not product or not is_product_visible_to_current_user(product):
        return jsonify({"success": False}), 404
    record_product_view(product)
    return jsonify({"success": True, "viewCount": ProductView.query.filter_by(product_id=product.id).count()})

@app.route('/api/saved_searches', methods=['GET', 'POST'])
@login_required
def saved_searches():
    if request.method == 'GET':
        searches = db.session.query(SavedSearch).filter_by(user_id=current_user.id, is_active=True).order_by(SavedSearch.created_at.desc()).all()
        return jsonify([{
            "id": search.id,
            "name": search.name,
            "query": search.query,
            "category": search.category,
            "brand": search.brand,
            "min_price": search.min_price,
            "max_price": search.max_price,
            "location": search.location
        } for search in searches])

    data = request.json or {}
    name = str(data.get('name') or data.get('query') or 'Kayitli arama').strip()[:120]
    search = SavedSearch(
        user_id=current_user.id,
        name=name or 'Kayitli arama',
        query=str(data.get('query') or '').strip()[:120] or None,
        category=str(data.get('category') or '').strip()[:100] or None,
        brand=str(data.get('brand') or '').strip()[:100] or None,
        location=str(data.get('location') or '').strip()[:120] or None
    )
    for key in ('min_price', 'max_price'):
        try:
            value = int(data.get(key)) if data.get(key) not in (None, '') else None
        except (TypeError, ValueError):
            value = None
        setattr(search, key, value)
    db.session.add(search)
    db.session.commit()
    return jsonify({"success": True, "id": search.id})

@app.route('/api/saved_searches/<int:search_id>', methods=['DELETE'])
@login_required
def delete_saved_search(search_id):
    search = db.session.query(SavedSearch).filter_by(id=search_id, user_id=current_user.id).first()
    if not search:
        return jsonify({"success": False}), 404
    search.is_active = False
    db.session.commit()
    return jsonify({"success": True})
@app.route('/api/sale_progress/<int:product_id>', methods=['POST'])
@login_required
def update_sale_progress(product_id):
    product = Product.query.get(product_id)
    if not product or product.status != 'completed':
        return jsonify({"success": False, "message": "Tamamlanmis satis bulunamadi."}), 404
    if current_user.id not in {product.owner_id, product.matched_user_id}:
        return jsonify({"success": False, "message": "Bu satisi guncelleyemezsiniz."}), 403

    data = request.json or {}
    progress = get_sale_progress(product.id)
    for field in ('contact_made', 'delivered', 'paid'):
        if field in data:
            setattr(progress, field, bool(data.get(field)))
    create_notification(
        product.matched_user_id if current_user.id == product.owner_id else product.owner_id,
        "Satis takibi guncellendi",
        f"{product.title} satis adimlari guncellendi.",
        "sale",
        product.id
    )
    db.session.commit()
    return jsonify({"success": True, "sale_progress": serialize_sale_progress(product.id)})

@app.route('/api/product_bids/<int:product_id>', methods=['GET'])
@login_required
def get_product_bids(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "Ürün bulunamadı"}), 404
    
    bids = Bid.query.filter_by(product_id=product_id).order_by(Bid.is_active.desc(), Bid.amount.desc()).all()
    output = []
    for b in bids:
        output.append({
            "id": b.id,
            "amount": b.amount,
            "user_name": b.user_name,
            "user_id": b.user_id,
            "timestamp": b.timestamp.strftime('%H:%M:%S'),
            "is_active": b.is_active,
            "can_withdraw": bool(b.is_active and b.user_id == current_user.id and product.status == 'active')
        })
    return jsonify(output)

@app.route('/api/withdraw_bid/<int:bid_id>', methods=['POST'])
@login_required
def withdraw_bid(bid_id):
    bid = Bid.query.get(bid_id)
    if not bid:
        return jsonify({"success": False, "message": "Teklif bulunamadı."}), 404
    if bid.user_id != current_user.id:
        return jsonify({"success": False, "message": "Sadece kendi teklifinizi geri çekebilirsiniz."}), 403
    if not bid.is_active:
        return jsonify({"success": False, "message": "Pasif teklif onaylanamaz."}), 400

    product = Product.query.get(bid.product_id)
    if not product or product.status != 'active':
        return jsonify({"success": False, "message": "Bu teklif artık geri çekilemez."}), 400
    bid.is_active = False
    current_user.withdraw_count = (current_user.withdraw_count or 0) + 1
    recalculate_product_bid_state(product)
    create_notification(
        product.owner_id,
        "Teklif geri çekildi",
        f"{current_user.name}, {product.title} ilanındaki teklifini geri çekti.",
        "bid",
        product.id
    )
    db.session.commit()
    return jsonify({"success": True, "current_bid": product.current_bid})

@app.route('/api/product_messages/<int:product_id>', methods=['GET'])
@login_required
def get_product_messages(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    if not is_product_visible_to_current_user(product):
        return jsonify({"success": False, "message": "İlan yayında değil."}), 404

    messages = ChatMessage.query.filter_by(product_id=product_id).order_by(ChatMessage.timestamp.asc()).limit(100).all()
    return jsonify([{
        "id": message.id,
        "message": message.message,
        "user_id": message.user_id,
        "user_name": message.user_name,
        "is_admin": is_admin_user(message.user),
        "timestamp": message.timestamp.strftime('%H:%M')
    } for message in messages])

@app.route('/api/product_messages', methods=['POST'])
@login_required
def add_product_message():
    settings = get_site_settings()
    data = request.json or {}
    product_id = data.get('product_id')
    message_text = str(data.get('message', '')).strip()

    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404

    if not message_text:
        return jsonify({"success": False, "message": "Mesaj yazmak zorundasınız."}), 400

    if len(message_text) > 500:
        return jsonify({"success": False, "message": "Mesaj en fazla 500 karakter olabilir."}), 400

    last_message = ChatMessage.query.filter_by(
        product_id=product.id,
        user_id=current_user.id
    ).order_by(ChatMessage.timestamp.desc()).first()
    if last_message:
        seconds_since_last_message = (datetime.utcnow() - last_message.timestamp).total_seconds()
        if seconds_since_last_message < settings["chat_spam_seconds"]:
            wait_seconds = max(1, int(settings["chat_spam_seconds"] - seconds_since_last_message))
            return jsonify({"success": False, "message": f"Spam koruması: {wait_seconds} saniye sonra tekrar yazabilirsiniz."}), 429

    if contains_blocked_chat_text(message_text):
        return jsonify({"success": False, "message": "Mesajınız uygunsuz kelime içerdiği için gönderilmedi."}), 400

    chat_message = ChatMessage(
        message=message_text,
        user_id=current_user.id,
        product_id=product.id,
        user_name=current_user.name
    )
    db.session.add(chat_message)
    notify_product_watchers(
        product,
        current_user.id,
        "Yeni sohbet mesajı",
        f"{product.title} ilanında yeni mesaj var.",
        "chat"
    )
    db.session.commit()

    return jsonify({"success": True})

def get_private_conversation_state(user_id, partner_id):
    return PrivateConversationState.query.filter_by(
        user_id=user_id,
        partner_id=partner_id
    ).first()

def is_user_blocked_between(first_user_id, second_user_id):
    return BlockedUser.query.filter(
        (
            (BlockedUser.blocker_id == first_user_id) & (BlockedUser.blocked_id == second_user_id)
        ) | (
            (BlockedUser.blocker_id == second_user_id) & (BlockedUser.blocked_id == first_user_id)
        )
    ).first()

def is_featured_product(product_id):
    featured = FeaturedProduct.query.filter_by(product_id=product_id, is_active=True).first()
    return bool(featured)

def serialize_private_conversation(partner, latest_message, deleted_at=None):
    unread_query = PrivateMessage.query.filter_by(
        sender_id=partner.id,
        receiver_id=current_user.id,
        is_read=False
    )
    if deleted_at:
        unread_query = unread_query.filter(PrivateMessage.created_at > deleted_at)
    unread_count = 1 if unread_query.first() else 0
    return {
        "user_id": partner.id,
        "user_name": partner.name,
        "last_message": latest_message.message,
        "last_at": latest_message.created_at.strftime('%d.%m.%Y %H:%M'),
        "unread_count": unread_count,
        "is_blocked": bool(is_user_blocked_between(current_user.id, partner.id))
    }

def get_private_conversations():
    messages = PrivateMessage.query.filter(
        (PrivateMessage.sender_id == current_user.id) | (PrivateMessage.receiver_id == current_user.id)
    ).order_by(PrivateMessage.created_at.desc()).all()
    deleted_map = {
        state.partner_id: state.deleted_at
        for state in PrivateConversationState.query.filter_by(user_id=current_user.id).all()
        if state.deleted_at
    }
    conversations = []
    seen_partner_ids = set()
    for message in messages:
        partner_id = message.receiver_id if message.sender_id == current_user.id else message.sender_id
        if partner_id in seen_partner_ids:
            continue
        deleted_at = deleted_map.get(partner_id)
        if deleted_at and message.created_at <= deleted_at:
            continue
        partner = User.query.get(partner_id)
        if not partner:
            continue
        seen_partner_ids.add(partner_id)
        conversations.append(serialize_private_conversation(partner, message, deleted_at))
    return conversations

@app.route('/api/private_conversations', methods=['GET'])
@login_required
def private_conversations():
    return jsonify(get_private_conversations())

@app.route('/api/private_messages/<int:user_id>', methods=['GET'])
@login_required
def get_private_messages(user_id):
    partner = User.query.get(user_id)
    if not partner:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    if partner.id == current_user.id:
        return jsonify({"success": False, "message": "Kendinize mesaj gönderemezsiniz."}), 400

    messages = PrivateMessage.query.filter(
        (
            (PrivateMessage.sender_id == current_user.id) & (PrivateMessage.receiver_id == partner.id)
        ) | (
            (PrivateMessage.sender_id == partner.id) & (PrivateMessage.receiver_id == current_user.id)
        )
    )
    state = get_private_conversation_state(current_user.id, partner.id)
    if state and state.deleted_at:
        messages = messages.filter(PrivateMessage.created_at > state.deleted_at)
    messages = messages.order_by(PrivateMessage.created_at.asc()).limit(100).all()
    mark_read_query = PrivateMessage.query.filter_by(
        sender_id=partner.id,
        receiver_id=current_user.id,
        is_read=False
    )
    if state and state.deleted_at:
        mark_read_query = mark_read_query.filter(PrivateMessage.created_at > state.deleted_at)
    mark_read_query.update({PrivateMessage.is_read: True}, synchronize_session=False)
    db.session.commit()
    message_meta_map = {
        meta.message_id: meta
        for meta in PrivateMessageMeta.query.filter(
            PrivateMessageMeta.message_id.in_([message.id for message in messages])
        ).all()
    } if messages else {}
    exchange_offer_map = {
        offer.message_id: offer
        for offer in ExchangeOffer.query.filter(
            ExchangeOffer.message_id.in_([message.id for message in messages])
        ).all()
    } if messages else {}
    exchange_product_ids = {
        product_id
        for meta in message_meta_map.values()
        for product_id in (meta.target_product_id, meta.offered_product_id)
        if product_id
    }
    exchange_product_map = {
        product.id: product
        for product in Product.query.filter(Product.id.in_(exchange_product_ids)).all()
    } if exchange_product_ids else {}
    blocked = is_user_blocked_between(current_user.id, partner.id)
    return jsonify({
        "partner": {"id": partner.id, "name": partner.name, "is_blocked": bool(blocked)},
        "messages": [{
            "id": message.id,
            "sender_id": message.sender_id,
            "receiver_id": message.receiver_id,
            "message": message.message,
            "created_at": message.created_at.strftime('%H:%M'),
            "exchange": ({
                "target_product_id": message_meta_map[message.id].target_product_id,
                "offered_product_id": message_meta_map[message.id].offered_product_id,
                "open_product_id": message_meta_map[message.id].offered_product_id or message_meta_map[message.id].target_product_id,
                "target_product": ({
                    "id": exchange_product_map[message_meta_map[message.id].target_product_id].id,
                    "title": exchange_product_map[message_meta_map[message.id].target_product_id].title,
                    "img": exchange_product_map[message_meta_map[message.id].target_product_id].image_url
                } if exchange_product_map.get(message_meta_map[message.id].target_product_id) else None),
                "offered_product": ({
                    "id": exchange_product_map[message_meta_map[message.id].offered_product_id].id,
                    "title": exchange_product_map[message_meta_map[message.id].offered_product_id].title,
                    "img": exchange_product_map[message_meta_map[message.id].offered_product_id].image_url
                } if exchange_product_map.get(message_meta_map[message.id].offered_product_id) else None),
                "offer_id": exchange_offer_map[message.id].id if exchange_offer_map.get(message.id) else None,
                "status": exchange_offer_map[message.id].status if exchange_offer_map.get(message.id) else None,
                "can_respond": bool(exchange_offer_map.get(message.id) and exchange_offer_map[message.id].receiver_id == current_user.id and exchange_offer_map[message.id].status == 'pending')
            } if message_meta_map.get(message.id) and message_meta_map[message.id].kind == 'exchange_offer' else None)
        } for message in messages]
    })

@app.route('/api/private_messages', methods=['POST'])
@login_required
def send_private_message():
    if is_chat_banned(current_user):
        return jsonify({"success": False, "message": "Sohbet kullanımınız geçici olarak kısıtlandı."}), 403

    settings = get_site_settings()
    data = request.json or {}
    receiver_id = data.get('receiver_id')
    message_text = str(data.get('message', '')).strip()
    receiver = User.query.get(receiver_id)
    if not receiver:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    if receiver.id == current_user.id:
        return jsonify({"success": False, "message": "Kendinize mesaj gönderemezsiniz."}), 400
    if not message_text:
        return jsonify({"success": False, "message": "Mesaj yazmak zorundasınız."}), 400
    if is_user_blocked_between(current_user.id, receiver.id):
        return jsonify({"success": False, "message": "Bu kullanıcıyla mesajlaşma engellenmiş."}), 403
    if len(message_text) > 500:
        return jsonify({"success": False, "message": "Mesaj en fazla 500 karakter olabilir."}), 400
    if contains_blocked_chat_text(message_text):
        return jsonify({"success": False, "message": "Mesajınız uygunsuz kelime içerdiği için gönderilmedi."}), 400

    last_message = PrivateMessage.query.filter_by(
        sender_id=current_user.id,
        receiver_id=receiver.id
    ).order_by(PrivateMessage.created_at.desc()).first()
    if last_message:
        seconds_since_last_message = (datetime.utcnow() - last_message.created_at).total_seconds()
        if seconds_since_last_message < settings["chat_spam_seconds"]:
            wait_seconds = max(1, int(settings["chat_spam_seconds"] - seconds_since_last_message))
            return jsonify({"success": False, "message": f"Spam koruması: {wait_seconds} saniye sonra tekrar yazabilirsiniz."}), 429

    db.session.add(PrivateMessage(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        message=message_text
    ))
    create_unique_unread_notification(
        receiver.id,
        "Yeni özel mesaj",
        f"{current_user.name} size mesaj gönderdi.",
        "private_message"
    )
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/exchange_offer', methods=['POST'])
@login_required
def send_exchange_offer():
    data = request.json or {}
    target_product = Product.query.get(data.get('product_id'))
    offered_product = Product.query.get(data.get('offered_product_id'))

    if not target_product or not is_product_visible_to_current_user(target_product):
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    if target_product.status != 'active':
        return jsonify({"success": False, "message": "Bu ilana şu an takas teklifi verilemez."}), 400
    if target_product.owner_id == current_user.id:
        return jsonify({"success": False, "message": "Kendi ilanınıza takas teklifi veremezsiniz."}), 400

    if is_user_blocked_between(current_user.id, target_product.owner_id):
        return jsonify({"success": False, "message": "Bu kullanıcıyla takas teklifi gönderilemez."}), 403

    target_extra = ProductExtra.query.get(target_product.id)
    if not target_extra or not target_extra.exchange_open:
        return jsonify({"success": False, "message": "Bu ilan takasa açık değil."}), 400

    if not offered_product or offered_product.owner_id != current_user.id:
        return jsonify({"success": False, "message": "Takas için kendi aktif ilanınızı seçmelisiniz."}), 400
    if offered_product.id == target_product.id or offered_product.status != 'active':
        return jsonify({"success": False, "message": "Takas için geçerli bir aktif ilan seçmelisiniz."}), 400

    message_text = (
        f"{current_user.name}, \"{target_product.title}\" ilanınızı "
        f"\"{offered_product.title}\" ilanıyla takas etmek istiyor."
    )
    private_message = PrivateMessage(
        sender_id=current_user.id,
        receiver_id=target_product.owner_id,
        message=message_text
    )
    db.session.add(private_message)
    db.session.flush()
    db.session.add(PrivateMessageMeta(
        message_id=private_message.id,
        kind='exchange_offer',
        target_product_id=target_product.id,
        offered_product_id=offered_product.id
    ))
    db.session.add(ExchangeOffer(
        sender_id=current_user.id,
        receiver_id=target_product.owner_id,
        target_product_id=target_product.id,
        offered_product_id=offered_product.id,
        message_id=private_message.id
    ))
    db.session.commit()
    return jsonify({
        "success": True,
        "owner_id": target_product.owner_id,
        "message": message_text
    })

@app.route('/api/private_conversations/<int:user_id>', methods=['DELETE'])
@login_required
def delete_private_conversation(user_id):
    partner = User.query.get(user_id)
    if not partner:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    if partner.id == current_user.id:
        return jsonify({"success": False, "message": "Bu sohbet silinemez."}), 400

    state = get_private_conversation_state(current_user.id, partner.id)
    if not state:
        state = PrivateConversationState(
            user_id=current_user.id,
            partner_id=partner.id
        )
        db.session.add(state)
    state.deleted_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/private_blocks/<int:user_id>', methods=['POST', 'DELETE'])
@login_required
def toggle_private_block(user_id):
    partner = User.query.get(user_id)
    if not partner:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    if partner.id == current_user.id:
        return jsonify({"success": False, "message": "Kendinizi engelleyemezsiniz."}), 400

    existing = BlockedUser.query.filter_by(blocker_id=current_user.id, blocked_id=partner.id).first()
    if request.method == 'DELETE':
        if existing:
            db.session.delete(existing)
            db.session.commit()
        return jsonify({"success": True, "is_blocked": False})

    if not existing:
        db.session.add(BlockedUser(blocker_id=current_user.id, blocked_id=partner.id))
        db.session.commit()
    return jsonify({"success": True, "is_blocked": True})

@app.route('/api/exchange_offers/<int:offer_id>/respond', methods=['POST'])
@login_required
def respond_exchange_offer(offer_id):
    offer = ExchangeOffer.query.get(offer_id)
    if not offer:
        return jsonify({"success": False, "message": "Takas teklifi bulunamadı."}), 404
    if offer.receiver_id != current_user.id:
        return jsonify({"success": False, "message": "Bu teklife yanıt veremezsiniz."}), 403
    if offer.status != 'pending':
        return jsonify({"success": False, "message": "Bu takas teklifi zaten yanıtlandı."}), 400

    action = (request.json or {}).get('action')
    if action not in {'accept', 'reject'}:
        return jsonify({"success": False, "message": "Geçersiz işlem."}), 400

    offer.status = 'accepted' if action == 'accept' else 'rejected'
    offer.responded_at = datetime.utcnow()
    target_product = Product.query.get(offer.target_product_id)
    offered_product = Product.query.get(offer.offered_product_id)
    status_text = "kabul etti" if offer.status == 'accepted' else "reddetti"
    message_text = (
        f"{current_user.name}, \"{target_product.title if target_product else 'ilan'}\" için "
        f"gönderdiğiniz takas teklifini {status_text}."
    )
    db.session.add(PrivateMessage(
        sender_id=current_user.id,
        receiver_id=offer.sender_id,
        message=message_text
    ))
    create_notification(
        offer.sender_id,
        "Takas teklifi yanıtlandı",
        message_text,
        "exchange",
        offer.target_product_id
    )
    db.session.commit()
    return jsonify({"success": True, "status": offer.status})

@app.route('/api/favorites/toggle', methods=['POST'])
@login_required
def toggle_favorite():
    data = request.json or {}
    product = Product.query.get(data.get('product_id'))
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    if is_chat_banned(current_user):
        return jsonify({"success": False, "message": "Sohbet kullanımınız geçici olarak kısıtlandı."}), 403

    favorite = Favorite.query.filter_by(user_id=current_user.id, product_id=product.id).first()
    if favorite:
        db.session.delete(favorite)
        is_favorite = False
    else:
        db.session.add(Favorite(user_id=current_user.id, product_id=product.id))
        is_favorite = True

    db.session.commit()
    return jsonify({
        "success": True,
        "isFavorite": is_favorite,
        "favoriteCount": Favorite.query.filter_by(product_id=product.id).count()
    })

@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    notifications_query = Notification.query.filter(
        Notification.user_id == current_user.id,
        Notification.notification_type != 'private_message'
    )
    notifications = notifications_query.order_by(Notification.created_at.desc()).limit(30).all()
    unread_count = notifications_query.filter(Notification.is_read == False).count()
    private_conversations = get_private_conversations()
    return jsonify({
        "unreadCount": unread_count,
        "messageUnreadCount": sum(1 for conversation in private_conversations if conversation["unread_count"]),
        "items": [{
            "id": notification.id,
            "title": repair_turkish_mojibake(notification.title),
            "message": repair_turkish_mojibake(notification.message),
            "type": notification.notification_type,
            "product_id": notification.product_id,
            "is_read": notification.is_read,
            "created_at": notification.created_at.strftime('%d.%m.%Y %H:%M')
        } for notification in notifications]
    })

@app.route('/api/notifications/read', methods=['POST'])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update(
        {Notification.is_read: True},
        synchronize_session=False
    )
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    favorites = Favorite.query.filter_by(user_id=current_user.id).order_by(Favorite.created_at.desc()).all()
    active_products = [product for product in current_user.products if product.status == 'active']
    completed_products = [product for product in current_user.products if product.status == 'completed']
    won_products = Product.query.filter_by(matched_user_id=current_user.id, status='completed').all()
    moderation = UserModeration.query.get(current_user.id)
    rating_summary = get_user_rating_summary(current_user.id)
    can_view_contact = is_admin_user()
    blocked_rows = BlockedUser.query.filter_by(blocker_id=current_user.id).order_by(BlockedUser.created_at.desc()).all()
    user_payload = {
        "id": current_user.id,
        "name": current_user.name,
        "profile_image": get_user_profile_image_url(current_user.id),
        "location": " / ".join(part for part in (current_user.city, current_user.district, current_user.neighborhood) if part),
        "phone_verified": bool(moderation and moderation.phone_verified),
        "chat_banned": is_chat_banned(current_user),
        "rating": rating_summary,
        "trust": get_public_trust_details(current_user),
        "can_view_contact": can_view_contact
    }
    if can_view_contact:
        user_payload.update({
            "email": current_user.email,
            "phone": current_user.phone
        })

    return jsonify({
        "user": user_payload,
        "stats": {
            "products": len(current_user.products),
            "activeProducts": len(active_products),
            "bids": len(current_user.bids),
            "favorites": len(favorites),
            "completedSales": len(completed_products),
            "completedPurchases": len(won_products)
        },
        "favorites": [{
            "id": favorite.product.id,
            "title": favorite.product.title,
            "currentBid": favorite.product.current_bid,
            "img": favorite.product.image_url,
            "statusLabel": get_product_status_label(favorite.product.status)
        } for favorite in favorites if favorite.product],
        "privateConversations": get_private_conversations(),
        "blockedUsers": [{
            "id": blocked.blocked_id,
            "name": User.query.get(blocked.blocked_id).name if User.query.get(blocked.blocked_id) else "Silinmiş kullanıcı",
            "created_at": blocked.created_at.strftime('%d.%m.%Y %H:%M')
        } for blocked in blocked_rows],
        "savedSearches": [{
            "id": search.id,
            "name": search.name,
            "query": search.query,
            "category": search.category,
            "brand": search.brand,
            "min_price": search.min_price,
            "max_price": search.max_price,
            "location": search.location
        } for search in db.session.query(SavedSearch).filter_by(user_id=current_user.id, is_active=True).order_by(SavedSearch.created_at.desc()).all()]
    })

@app.route('/api/my_orders', methods=['GET'])
@login_required
def get_my_orders():
    orders = Product.query.filter(
        Product.matched_user_id == current_user.id,
        Product.status.in_(['pending_bidder_action', 'seller_info_confirmation', 'completed'])
    ).order_by(Product.created_at.desc()).all()
    return jsonify({
        "success": True,
        "orders": [{
            "id": product.id,
            "title": product.title,
            "img": product.image_url,
            "seller": product.owner_name,
            "currentBid": product.current_bid,
            "status": product.status,
            "statusLabel": get_product_status_label(product.status),
            "createdAt": product.created_at.strftime('%d.%m.%Y'),
            "saleProgress": serialize_sale_progress(product.id) if product.status == 'completed' else None
        } for product in orders]
    })

@app.route('/api/profile/photo', methods=['POST'])
@login_required
def update_profile_photo():
    data = request.json or {}
    image_url = save_profile_image(data.get('image'))
    if not image_url:
        return jsonify({"success": False, "message": "Geçerli bir profil fotoğrafı seçin."}), 400

    profile = get_user_profile(current_user.id)
    profile.image_url = image_url
    db.session.commit()
    return jsonify({"success": True, "image_url": image_url})

@app.route('/api/profile/password', methods=['POST'])
@login_required
def update_profile_password():
    data = request.json or {}
    new_password = str(data.get('newPassword') or '')
    confirm_password = str(data.get('confirmPassword') or new_password)

    if len(new_password) < 6:
        return jsonify({"success": False, "message": "Yeni şifre en az 6 karakter olmalıdır."}), 400
    if len(new_password) > 128:
        return jsonify({"success": False, "message": "Yeni şifre en fazla 128 karakter olabilir."}), 400
    if new_password != confirm_password:
        return jsonify({"success": False, "message": "Yeni şifreler eşleşmiyor."}), 400
    if check_password_hash(current_user.password, new_password):
        return jsonify({"success": False, "message": "Yeni şifre mevcut şifreden farklı olmalıdır."}), 400

    current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()
    return jsonify({"success": True, "message": "Şifre güncellendi."})

@app.route('/api/users/<int:user_id>/public_profile', methods=['GET'])
@login_required
def get_public_user_profile(user_id):
    user = User.query.get(user_id)
    if not user or user.is_banned:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404

    active_products = [
        product for product in Product.query.filter_by(owner_id=user.id, status='active').order_by(Product.created_at.desc()).all()
        if is_product_visible_to_current_user(product)
    ]
    completed_sales = Product.query.filter_by(owner_id=user.id, status='completed').count()
    rating_summary = get_user_rating_summary(user.id)
    moderation = UserModeration.query.get(user.id)
    can_view_contact = is_admin_user()
    user_payload = {
        "id": user.id,
        "name": user.name,
        "profile_image": get_user_profile_image_url(user.id),
        "location": " / ".join(part for part in (user.city, user.district) if part),
        "phone_verified": bool(moderation and moderation.phone_verified),
        "rating": rating_summary,
        "badges": get_user_badges(user),
        "trust": get_public_trust_summary(user),
        "can_view_contact": can_view_contact,
        "is_blocked": bool(is_user_blocked_between(current_user.id, user.id))
    }
    if can_view_contact:
        user_payload.update({
            "email": user.email,
            "phone": user.phone
        })
    return jsonify({
        "success": True,
        "user": user_payload,
        "stats": {
            "activeProducts": len(active_products),
            "totalProducts": Product.query.filter_by(owner_id=user.id).count(),
            "completedSales": completed_sales,
            "ratingCount": rating_summary["count"]
        },
        "products": [{
            "id": product.id,
            "title": product.title,
            "currentBid": product.current_bid,
            "img": product.image_url,
            "location": format_product_location(product),
            "endTime": product.end_time.timestamp() * 1000,
            "statusLabel": get_product_status_label(product.status)
        } for product in active_products[:8]]
    })

@app.route('/api/users/<int:user_id>/trust_details', methods=['GET'])
@login_required
def get_user_trust_details(user_id):
    user = User.query.get(user_id)
    if not user or user.is_banned:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    return jsonify({
        "success": True,
        "user": {"id": user.id, "name": user.name},
        "trust": get_public_trust_details(user)
    })

@app.route('/api/report_product', methods=['POST'])
@login_required
def report_product():
    data = request.json or {}
    product = Product.query.get(data.get('product_id'))
    reason = str(data.get('reason', '')).strip()
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    if len(reason) < 5:
        return jsonify({"success": False, "message": "Rapor nedeni en az 5 karakter olmalıdır."}), 400

    db.session.add(Report(
        reporter_id=current_user.id,
        product_id=product.id,
        target_type='product',
        reason=reason[:300]
    ))
    auto_moderate_user(product.owner)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/report_user', methods=['POST'])
@login_required
def report_user():
    data = request.json or {}
    user = User.query.get(data.get('user_id'))
    reason = str(data.get('reason', '')).strip()
    if not user:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    if user.id == current_user.id:
        return jsonify({"success": False, "message": "Kendinizi şikayet edemezsiniz."}), 400
    if len(reason) < 5:
        return jsonify({"success": False, "message": "Şikayet nedeni en az 5 karakter olmalıdır."}), 400

    db.session.add(Report(
        reporter_id=current_user.id,
        target_type='user',
        reason=f"[USER:{user.id}] {user.name}: {reason[:260]}"
    ))
    auto_moderate_user(user)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/report_message', methods=['POST'])
@login_required
def report_message():
    data = request.json or {}
    message = ChatMessage.query.get(data.get('message_id'))
    reason = str(data.get('reason', '')).strip()
    if not message:
        return jsonify({"success": False, "message": "Mesaj bulunamadı."}), 404
    if len(reason) < 5:
        return jsonify({"success": False, "message": "Rapor nedeni en az 5 karakter olmalıdır."}), 400

    db.session.add(Report(
        reporter_id=current_user.id,
        product_id=message.product_id,
        message_id=message.id,
        target_type='message',
        reason=reason[:300]
    ))
    auto_moderate_user(message.user)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/approve_bid', methods=['POST'])
@login_required
def approve_bid():
    data = request.json
    bid_id = data.get('bid_id')
    bid = Bid.query.get(bid_id)
    if bid and not bid.is_active:
        return jsonify({"success": False, "message": "Pasif teklif onaylanamaz."}), 400
    
    if not bid:
        return jsonify({"success": False, "message": "Teklif bulunamadı"}), 404
        
    product = Product.query.get(bid.product_id)
    if not product or product.owner_id != current_user.id:
        return jsonify({"success": False, "message": "Yetkisiz işlem"}), 403
        
    if product.status != 'active':
        return jsonify({"success": False, "message": "Bu ürün zaten bir sürece girmiş"}), 400

    # Seçilen teklifi onayla ve süreci başlat
    product.matched_user_id = bid.user_id
    product.current_bid = bid.amount
    product.status = 'pending_bidder_action'
    create_notification(
        bid.user_id,
        "Teklifiniz seçildi",
        f"{product.title} ilanındaki teklifiniz satıcı tarafından seçildi.",
        "bid",
        product.id
    )
    
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/seller_respond', methods=['POST'])
@login_required
def seller_respond():
    data = request.json
    product_id = data.get('product_id')
    action = data.get('action')

    product = Product.query.get(product_id)
    if not product or product.owner_id != current_user.id:
        return jsonify({"success": False, "message": "Yetkisiz işlem"}), 403

    if product.status == 'pending_seller_approval':
        if action == 'approve':
            product.status = 'pending_bidder_action'
        else:
            rollback_match(product)
        db.session.commit()
        return jsonify({"success": True})
    
    elif product.status == 'seller_info_confirmation':
        if action == 'approve':
            product.status = 'completed'
            get_sale_progress(product.id)
            create_notification(
                product.matched_user_id,
                "Satış tamamlandı",
                f"{product.title} ilanında iletişim bilgileri paylaşıldı.",
                "sale",
                product.id
            )
        else:
            rollback_match(product)
        db.session.commit()
        return jsonify({"success": True})

    return jsonify({"success": False, "message": "Geçersiz durum"})

@app.route('/api/bidder_respond', methods=['POST'])
@login_required
def bidder_respond():
    data = request.json
    product_id = data.get('product_id')
    action = data.get('action')

    product = Product.query.get(product_id)
    if not product or product.matched_user_id != current_user.id:
        return jsonify({"success": False, "message": "Yetkisiz işlem"}), 403

    if action == 'continue':
        product.status = 'seller_info_confirmation'
        create_notification(
            product.owner_id,
            "Alıcı devam ediyor",
            f"{product.title} ilanında alıcı devam etmeyi onayladı.",
            "sale",
            product.id
        )
        db.session.commit()
        return jsonify({"success": True})
    
    elif action == 'withdraw':
        current_user.withdraw_count += 1
        is_banned = False
        if current_user.withdraw_count >= 3:
            current_user.ban_until = datetime.now() + timedelta(days=7)
            current_user.withdraw_count = 0
            is_banned = True
        
        rollback_match(product)
        create_notification(
            product.owner_id,
            "Alıcı vazgeçti",
            f"{product.title} ilanında seçilen alıcı ihaleden vazgeçti.",
            "sale",
            product.id
        )
        db.session.commit()
        return jsonify({"success": True, "banned": is_banned})

    return jsonify({"success": False, "message": "Geçersiz işlem"})

def rollback_match(product):
    # Mevcut teklifi iptal et (is_active = False)
    current_bid = Bid.query.filter_by(product_id=product.id, user_id=product.matched_user_id, is_active=True).order_by(Bid.amount.desc()).first()
    if current_bid:
        current_bid.is_active = False
    
    # Bir sonraki en yüksek aktif teklifi bul
    next_bid = Bid.query.filter_by(product_id=product.id, is_active=True).order_by(Bid.amount.desc()).first()
    
    if next_bid:
        # Bir önceki teklif verenle süreci baştan başlat
        product.matched_user_id = next_bid.user_id
        product.current_bid = next_bid.amount
        # Durumu tekrar aktif yap ki satıcı tekrar onaylayabilsin veya yeni teklifler gelsin
        product.status = 'active'
    else:
        # Başka teklif kalmadıysa ilanı tekrar aktif (herkese açık) yap
        product.matched_user_id = None
        product.current_bid = product.start_price
        product.status = 'active'

# Diğer Standart Rotalar
@app.route('/')
def index():
    settings = get_site_settings()
    active_announcement = Announcement.query.filter_by(is_active=True).order_by(Announcement.created_at.desc()).first()
    return render_template(
        'index.html',
        is_current_admin=is_admin_user(),
        site_settings=settings,
        maintenance_mode=settings["maintenance_mode"] and not is_admin_user(),
        active_announcement=active_announcement
    )

@app.route('/admin')
@login_required
def admin_panel():
    if not is_admin_user():
        flash("Admin yetkiniz yok!")
        return redirect(url_for('index'))

    cleanup_expired_products()
    
    users = User.query.all()
    stats = {
        "total_products": Product.query.count(),
        "total_bids": Bid.query.count(),
        "total_users": User.query.count(),
        "open_reports": Report.query.filter_by(status='open').count(),
        "pending_products": Product.query.filter_by(status='pending_admin_approval').count(),
        "open_appeals": Appeal.query.filter_by(status='open').count(),
        "featured_products": FeaturedProduct.query.filter_by(is_active=True).count(),
        "active_products": Product.query.filter_by(status='active').count(),
        "completed_products": Product.query.filter_by(status='completed').count(),
        "chat_messages": ChatMessage.query.count()
    }
    
    # User nesnelerine JSON serileştirme için gerekli alanları ekleyelim (templates/admin.html için)
    users_data = []
    for u in users:
        risk = calculate_user_risk(u)
        moderation = UserModeration.query.get(u.id)
        rating_summary = get_user_rating_summary(u.id)
        u_dict = {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "phone": u.phone,
            "profile_image": get_user_profile_image_url(u.id),
            "city": u.city,
            "district": u.district,
            "role": u.role,
            "is_banned": u.is_banned,
            "risk": risk,
            "badges": get_user_badges(u),
            "phone_verified": bool(moderation and moderation.phone_verified),
            "chat_banned": bool(moderation and moderation.chat_ban_until and moderation.chat_ban_until > datetime.now()),
            "warning_count": moderation.warning_count if moderation else 0,
            "rating": rating_summary,
            "saved_searches": db.session.query(SavedSearch).filter_by(user_id=u.id, is_active=True).count(),
            "notes": [{
                "id": note.id,
                "note": note.note,
                "created_at": note.created_at.strftime('%Y-%m-%d %H:%M')
            } for note in AdminNote.query.filter_by(user_id=u.id).order_by(AdminNote.created_at.desc()).limit(5).all()],
            "products": [{"id": p.id, "title": p.title, "start_price": p.start_price, "current_bid": p.current_bid, "views": ProductView.query.filter_by(product_id=p.id).count(), "favorites": len(p.favorites)} for p in u.products],
            "bids": [{"id": b.id, "amount": b.amount, "product_title": Product.query.get(b.product_id).title if Product.query.get(b.product_id) else "Silinmiş", "timestamp": b.timestamp.strftime('%Y-%m-%d %H:%M')} for b in u.bids]
        }
        users_data.append(u_dict)

    products_data = []
    for product in Product.query.order_by(Product.created_at.desc()).all():
        moderation = ProductModeration.query.get(product.id)
        products_data.append({
            "id": product.id,
            "title": product.title,
            "owner_name": product.owner_name,
            "current_bid": product.current_bid,
            "status": product.status,
            "status_label": get_product_status_label(product.status),
            "end_time": product.end_time.strftime('%Y-%m-%d %H:%M'),
            "remaining": "Doldu" if product.end_time <= datetime.now() else str(product.end_time - datetime.now()).split('.')[0],
            "bid_count": len(product.bids),
            "message_count": len(product.chat_messages),
            "view_count": ProductView.query.filter_by(product_id=product.id).count(),
            "favorite_count": len(product.favorites),
            "report_count": Report.query.filter_by(product_id=product.id, status='open').count(),
            "is_hidden": bool(moderation and moderation.is_hidden),
            "is_featured": is_featured_product(product.id),
            "image_flagged": bool(moderation and moderation.image_flagged),
            "moderation_reason": moderation.reason if moderation else ""
        })

    messages_data = []
    for message in ChatMessage.query.order_by(ChatMessage.timestamp.desc()).limit(100).all():
        messages_data.append({
            "id": message.id,
            "message": repair_turkish_mojibake(message.message),
            "user_id": message.user_id,
            "user_name": message.user_name,
            "is_admin": is_admin_user(message.user),
            "product_id": message.product_id,
            "product_title": repair_turkish_mojibake(message.product.title) if message.product else "Silinmiş ilan",
            "timestamp": message.timestamp.strftime('%Y-%m-%d %H:%M'),
            "report_count": Report.query.filter_by(message_id=message.id, status='open').count()
        })

    category_stats_map = {}
    for product in Product.query.all():
        stat = category_stats_map.setdefault(product.category, {
            "category": product.category,
            "product_count": 0,
            "bid_total": 0,
            "bid_count": 0
        })
        stat["product_count"] += 1
        stat["bid_total"] += sum(bid.amount for bid in product.bids)
        stat["bid_count"] += len(product.bids)
    category_stats = []
    for stat in category_stats_map.values():
        stat["average_bid"] = round(stat["bid_total"] / stat["bid_count"]) if stat["bid_count"] else 0
        category_stats.append(stat)
    category_stats.sort(key=lambda item: item["product_count"], reverse=True)

    daily_stats = []
    today = datetime.now().date()
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        start = datetime.combine(day, datetime.min.time())
        end = start + timedelta(days=1)
        daily_stats.append({
            "label": day.strftime('%d.%m'),
            "products": Product.query.filter(Product.created_at >= start, Product.created_at < end).count(),
            "bids": Bid.query.filter(Bid.timestamp >= start, Bid.timestamp < end).count()
        })
    max_daily_count = max([1] + [day["products"] for day in daily_stats] + [day["bids"] for day in daily_stats])

    admin_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(12).all()
    admin_tasks = []
    for product in Product.query.filter_by(status='pending_admin_approval').order_by(Product.created_at.desc()).limit(8).all():
        admin_tasks.append({
            "type": "product",
            "label": "İlan onayı",
            "title": repair_turkish_mojibake(product.title),
            "detail": f"{repair_turkish_mojibake(product.owner_name)} | {product.created_at.strftime('%Y-%m-%d %H:%M')}",
            "product_id": product.id,
            "severity": "orange"
        })
    for report in Report.query.filter(Report.status.in_(['open', 'reviewing'])).order_by(Report.created_at.desc()).limit(8).all():
        admin_tasks.append({
            "type": "report",
            "label": "Şikayet",
            "title": repair_turkish_mojibake(report.reason),
            "detail": f"{report.target_type} | {report.created_at.strftime('%Y-%m-%d %H:%M')}",
            "report_id": report.id,
            "severity": "red"
        })
    for appeal in Appeal.query.filter_by(status='open').order_by(Appeal.created_at.desc()).limit(6).all():
        appeal_user = User.query.get(appeal.user_id)
        admin_tasks.append({
            "type": "appeal",
            "label": "Destek / itiraz",
            "title": repair_turkish_mojibake(appeal.message),
            "detail": f"{appeal_user.name if appeal_user else 'Silinmiş kullanıcı'} | {appeal.created_at.strftime('%Y-%m-%d %H:%M')}",
            "appeal_id": appeal.id,
            "severity": "blue"
        })
    for notification in admin_notifications:
        admin_tasks.append({
            "type": "notification",
            "label": "Admin bildirimi",
            "title": repair_turkish_mojibake(notification.title),
            "detail": f"{repair_turkish_mojibake(notification.message)} | {notification.created_at.strftime('%Y-%m-%d %H:%M')}",
            "product_id": notification.product_id,
            "severity": "indigo"
        })
    admin_tasks = admin_tasks[:18]
        
    reports = Report.query.order_by(Report.created_at.desc()).limit(50).all()
    reports_data = []
    for report in reports:
        reporter = User.query.get(report.reporter_id)
        product = Product.query.get(report.product_id) if report.product_id else None
        message = ChatMessage.query.get(report.message_id) if report.message_id else None
        reported_user_id = message.user_id if message else (product.owner_id if product else None)
        if report.target_type == 'user':
            user_match = re.search(r'\[USER:(\d+)\]', report.reason or '')
            reported_user_id = int(user_match.group(1)) if user_match else None
        reports_data.append({
            "id": report.id,
            "target_type": report.target_type,
            "reason": repair_turkish_mojibake(report.reason),
            "status": report.status,
            "status_label": {
                "open": "Açık",
                "reviewing": "İncelemede",
                "resolved": "Kapandı",
                "rejected": "Reddedildi"
            }.get(report.status, report.status),
            "created_at": report.created_at.strftime('%Y-%m-%d %H:%M'),
            "reporter_name": reporter.name if reporter else "Silinmiş kullanıcı",
            "reported_user_id": reported_user_id,
            "product_id": report.product_id,
            "product_title": repair_turkish_mojibake(product.title) if product else ("Kullanıcı şikayeti" if report.target_type == 'user' else "Silinmiş ilan"),
            "message_id": report.message_id,
            "message_text": repair_turkish_mojibake(message.message) if message else None
        })

    logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(50).all()
    logs_data = []
    for log in logs:
        admin = User.query.get(log.admin_id) if log.admin_id else None
        logs_data.append({
            "id": log.id,
            "admin_name": admin.name if admin else "Sistem",
            "action": repair_turkish_mojibake(log.action),
            "target_type": log.target_type,
            "target_id": log.target_id,
            "detail": repair_turkish_mojibake(log.detail),
            "created_at": log.created_at.strftime('%Y-%m-%d %H:%M')
        })

    announcements = Announcement.query.order_by(Announcement.created_at.desc()).limit(10).all()
    announcements_data = [{
        "id": announcement.id,
        "title": repair_turkish_mojibake(announcement.title),
        "message": repair_turkish_mojibake(announcement.message),
        "is_active": announcement.is_active,
        "created_at": announcement.created_at.strftime('%Y-%m-%d %H:%M')
    } for announcement in announcements]

    appeals = Appeal.query.order_by(Appeal.created_at.desc()).limit(50).all()
    appeals_data = []
    for appeal in appeals:
        user = User.query.get(appeal.user_id)
        appeals_data.append({
            "id": appeal.id,
            "user_name": user.name if user else "Silinmiş kullanıcı",
            "message": repair_turkish_mojibake(appeal.message),
            "status": appeal.status,
            "admin_response": repair_turkish_mojibake(appeal.admin_response),
            "created_at": appeal.created_at.strftime('%Y-%m-%d %H:%M')
        })

    return render_template(
        'admin.html',
        users=users_data,
        stats=stats,
        reports=reports_data,
        products=products_data,
        messages=messages_data,
        category_stats=category_stats,
        daily_stats=daily_stats,
        max_daily_count=max_daily_count,
        admin_tasks=admin_tasks,
        settings=get_site_settings(),
        announcements=announcements_data,
        appeals=appeals_data,
        logs=logs_data,
        can_manage=is_admin_user()
    )

@app.route('/api/ban_user/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    if not is_admin_user(): return jsonify({"success": False}), 403
    user = User.query.get(user_id)
    if user:
        user.ban_until = datetime.now() + timedelta(days=7)
        log_admin_action("Kullanıcı banlandı", "user", user.id, user.email)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/unban_user/<int:user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    if not is_admin_user(): return jsonify({"success": False}), 403
    user = User.query.get(user_id)
    if user:
        user.ban_until = None
        log_admin_action("Kullanıcı banı kaldırıldı", "user", user.id, user.email)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/admin/quick_search')
@login_required
def admin_quick_search():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    query = str(request.args.get('q', '')).strip()
    if len(query) < 2:
        return jsonify({"success": True, "items": []})
    like = f"%{query}%"
    users = User.query.filter((User.name.ilike(like)) | (User.email.ilike(like))).order_by(User.id.desc()).limit(5).all()
    products = Product.query.filter(Product.title.ilike(like)).order_by(Product.id.desc()).limit(5).all()
    return jsonify({
        "success": True,
        "items": [{
            "type": "user",
            "id": user.id,
            "title": user.name,
            "subtitle": user.email,
            "status": "Banlı" if user.is_banned else "Aktif"
        } for user in users] + [{
            "type": "product",
            "id": product.id,
            "title": product.title,
            "subtitle": product.owner_name,
            "status": get_product_status_label(product.status)
        } for product in products]
    })

@app.route('/api/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not is_admin_user(): return jsonify({"success": False}), 403
    if user_id == current_user.id:
        return jsonify({"success": False, "message": "Kendi admin hesabınızı silemezsiniz."}), 400
    user = User.query.get(user_id)
    if user:
        log_admin_action("Kullanıcı silindi", "user", user.id, user.email)
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/delete_product/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404

    if not is_admin_user() and product.owner_id != current_user.id:
        return jsonify({"success": False, "message": "Sadece kendi ilanınızı silebilirsiniz."}), 403

    if is_admin_user():
        log_admin_action("İlan silindi", "product", product.id, product.title)
    db.session.delete(product)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/delete_bid/<int:bid_id>', methods=['DELETE'])
@login_required
def delete_bid(bid_id):
    if not is_admin_user(): return jsonify({"success": False}), 403
    bid = Bid.query.get(bid_id)
    if bid:
        product = Product.query.get(bid.product_id)
        log_admin_action("Teklif silindi", "bid", bid.id, f"{bid.user_name} - {bid.amount} TL")
        db.session.delete(bid)
        db.session.flush()
        if product and product.status == 'active':
            recalculate_product_bid_state(product)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/delete_message/<int:message_id>', methods=['DELETE'])
@login_required
def delete_message(message_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    message = ChatMessage.query.get(message_id)
    if message:
        log_admin_action("Mesaj silindi", "message", message.id, message.message)
        db.session.delete(message)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/resolve_report/<int:report_id>', methods=['POST'])
@login_required
def resolve_report(report_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    report = Report.query.get(report_id)
    if report:
        report.status = 'resolved'
        report.resolved_at = datetime.utcnow()
        report.resolved_by_id = current_user.id
        log_admin_action("Rapor kapatıldı", "report", report.id, report.reason)
        db.session.commit()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/bulk_resolve_reports', methods=['POST'])
@login_required
def bulk_resolve_reports():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    report_ids = (request.json or {}).get('report_ids', [])
    resolved_count = 0
    for report_id in report_ids:
        report = Report.query.get(report_id)
        if report and report.status in {'open', 'reviewing'}:
            report.status = 'resolved'
            report.resolved_at = datetime.utcnow()
            report.resolved_by_id = current_user.id
            resolved_count += 1
    log_admin_action("Toplu rapor kapatma", "report", None, f"{resolved_count} rapor kapatıldı")
    db.session.commit()
    return jsonify({"success": True, "resolved": resolved_count})

@app.route('/api/admin/report_status/<int:report_id>', methods=['POST'])
@login_required
def update_report_status(report_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    report = Report.query.get(report_id)
    if not report:
        return jsonify({"success": False, "message": "Rapor bulunamadı."}), 404
    status = (request.json or {}).get('status')
    if status not in {'open', 'reviewing', 'resolved', 'rejected'}:
        return jsonify({"success": False, "message": "Geçersiz rapor durumu."}), 400
    report.status = status
    if status in {'resolved', 'rejected'}:
        report.resolved_at = datetime.utcnow()
        report.resolved_by_id = current_user.id
    else:
        report.resolved_at = None
        report.resolved_by_id = None
    log_admin_action("Rapor durumu değişti", "report", report.id, status)
    db.session.commit()
    return jsonify({"success": True, "status": status})

@app.route('/api/admin/bulk_products', methods=['POST'])
@login_required
def bulk_products_action():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    data = request.json or {}
    product_ids = [int(product_id) for product_id in data.get('product_ids', []) if str(product_id).isdigit()]
    action = data.get('action')
    if action not in {'approve', 'reject', 'feature', 'unfeature', 'hide', 'show', 'delete'}:
        return jsonify({"success": False, "message": "Geçersiz toplu işlem."}), 400
    if not product_ids:
        return jsonify({"success": False, "message": "İlan seçilmedi."}), 400

    changed = 0
    reason = str(data.get('reason', '')).strip()[:300]
    for product in Product.query.filter(Product.id.in_(product_ids)).all():
        if action == 'approve' and product.status == 'pending_admin_approval':
            product.status = 'active'
            create_notification(product.owner_id, "İlan onaylandı", f"{product.title} ilanınız yayına alındı.", "admin", product.id)
            changed += 1
        elif action == 'reject' and product.status == 'pending_admin_approval':
            product.status = 'cancelled'
            moderation = get_product_moderation(product.id)
            moderation.reason = reason or "Toplu işlem ile reddedildi."
            create_notification(product.owner_id, "İlan reddedildi", f"{product.title} ilanınız admin tarafından reddedildi.", "admin", product.id)
            changed += 1
        elif action in {'feature', 'unfeature'}:
            featured = FeaturedProduct.query.filter_by(product_id=product.id).first()
            if not featured:
                featured = FeaturedProduct(product_id=product.id, is_active=(action == 'feature'))
                db.session.add(featured)
            else:
                featured.is_active = action == 'feature'
            changed += 1
        elif action in {'hide', 'show'}:
            moderation = get_product_moderation(product.id)
            moderation.is_hidden = action == 'hide'
            if reason:
                moderation.reason = reason
            changed += 1
        elif action == 'delete':
            db.session.delete(product)
            changed += 1

    log_admin_action("Toplu ilan işlemi", "product", None, f"{action}: {changed} ilan")
    db.session.commit()
    return jsonify({"success": True, "changed": changed})

@app.route('/api/admin_settings', methods=['POST'])
@login_required
def update_admin_settings():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    data = request.json or {}
    limits = {
        "min_bid": (1, 1000000),
        "bid_step": (1, 1000000),
        "chat_spam_seconds": (1, 120),
        "default_duration_days": (1, 180),
        "max_images": (1, 5)
    }
    for key, (minimum, maximum) in limits.items():
        try:
            value = int(data.get(key))
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": f"{key} geçerli değil."}), 400
        if value < minimum or value > maximum:
            return jsonify({"success": False, "message": f"{key} {minimum}-{maximum} aralığında olmalıdır."}), 400
        if key == "default_duration_days" and value not in {1, 7, 30, 90, 180}:
            return jsonify({"success": False, "message": "Varsayılan ilan süresi 1 gün, 7 gün, 1 ay, 3 ay veya 6 ay olmalıdır."}), 400
        update_site_setting(key, value)
    update_site_setting("maintenance_mode", "1" if data.get("maintenance_mode") else "0")
    log_admin_action("Site ayarları güncellendi", "settings", None, json.dumps(data, ensure_ascii=False))
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/admin_announcement', methods=['POST'])
@login_required
def save_admin_announcement():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    data = request.json or {}
    title = str(data.get('title', '')).strip()
    message = str(data.get('message', '')).strip()
    is_active = bool(data.get('is_active', True))
    if not title or not message:
        return jsonify({"success": False, "message": "Duyuru başlığı ve metni zorunludur."}), 400
    if is_active:
        Announcement.query.update({Announcement.is_active: False}, synchronize_session=False)
    announcement = Announcement(
        title=title[:120],
        message=message[:500],
        is_active=is_active,
        created_by_id=current_user.id
    )
    db.session.add(announcement)
    log_admin_action("Duyuru yayınlandı", "announcement", None, title)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/toggle_announcement/<int:announcement_id>', methods=['POST'])
@login_required
def toggle_announcement(announcement_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    announcement = Announcement.query.get(announcement_id)
    if not announcement:
        return jsonify({"success": False}), 404
    if not announcement.is_active:
        Announcement.query.update({Announcement.is_active: False}, synchronize_session=False)
    announcement.is_active = not announcement.is_active
    log_admin_action("Duyuru durumu değişti", "announcement", announcement.id, announcement.title)
    db.session.commit()
    return jsonify({"success": True, "is_active": announcement.is_active})

@app.route('/api/admin_note', methods=['POST'])
@login_required
def add_admin_note():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    data = request.json or {}
    note = str(data.get('note', '')).strip()
    user_id = data.get('user_id')
    product_id = data.get('product_id')
    if not note:
        return jsonify({"success": False, "message": "Not boş olamaz."}), 400
    admin_note = AdminNote(admin_id=current_user.id, user_id=user_id, product_id=product_id, note=note[:500])
    db.session.add(admin_note)
    log_admin_action("Admin notu eklendi", "user" if user_id else "product", user_id or product_id, note)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/toggle_chat_ban/<int:user_id>', methods=['POST'])
@login_required
def toggle_chat_ban(user_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False}), 404
    moderation = get_user_moderation(user_id)
    if moderation.chat_ban_until and moderation.chat_ban_until > datetime.now():
        moderation.chat_ban_until = None
        action = "Sohbet banı kaldırıldı"
    else:
        moderation.chat_ban_until = datetime.now() + timedelta(days=7)
        action = "Sohbet banı verildi"
        create_notification(user_id, "Sohbet kısıtlandı", "Sohbet kullanımınız 7 gün kısıtlandı.", "warning")
    log_admin_action(action, "user", user_id, user.email)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/admin/warn_user/<int:user_id>', methods=['POST'])
@login_required
def warn_user(user_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    data = request.json or {}
    message = str(data.get('message', '')).strip()[:300] or "Hesabınız admin tarafından uyarıldı. Lütfen site kurallarına dikkat edin."
    moderation = get_user_moderation(user_id)
    moderation.warning_count = (moderation.warning_count or 0) + 1
    create_notification(user_id, "Admin uyarısı", message, "warning")
    log_admin_action("Kullanıcı uyarıldı", "user", user_id, message)
    db.session.commit()
    return jsonify({"success": True, "warning_count": moderation.warning_count})

@app.route('/api/toggle_user_verification/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_verification(user_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    field = (request.json or {}).get('field')
    if field != 'phone_verified':
        return jsonify({"success": False, "message": "Geçersiz doğrulama alanı."}), 400
    moderation = get_user_moderation(user_id)
    setattr(moderation, field, not getattr(moderation, field))
    log_admin_action("Doğrulama değişti", "user", user_id, field)
    db.session.commit()
    return jsonify({"success": True, "value": getattr(moderation, field)})

@app.route('/api/admin/users/<int:user_id>/profile_photo', methods=['DELETE'])
@login_required
def admin_delete_user_profile_photo(user_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    profile = UserProfile.query.get(user_id)
    if profile:
        profile.image_url = None
    log_admin_action("Profil fotoğrafı kaldırıldı", "user", user_id, user.email)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/toggle_product_hidden/<int:product_id>', methods=['POST'])
@login_required
def toggle_product_hidden(product_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False}), 404
    data = request.json or {}
    moderation = get_product_moderation(product_id)
    moderation.is_hidden = not moderation.is_hidden
    moderation.reason = str(data.get('reason', '')).strip()[:300] or moderation.reason
    log_admin_action("İlan gizleme durumu değişti", "product", product_id, product.title)
    db.session.commit()
    return jsonify({"success": True, "is_hidden": moderation.is_hidden})

@app.route('/api/approve_product/<int:product_id>', methods=['POST'])
@login_required
def approve_product(product_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    if product.status != 'pending_admin_approval':
        return jsonify({"success": False, "message": "Bu ilan admin onayı beklemiyor."}), 400

    moderation = get_product_moderation(product_id)
    original_duration = product.end_time - (product.created_at or datetime.now())
    product.status = 'active'
    if original_duration.total_seconds() > 0:
        product.end_time = datetime.now() + original_duration
    moderation.is_hidden = False
    moderation.reason = ''
    notify_saved_search_matches(product)
    create_notification(
        product.owner_id,
        "İlan onaylandı",
        f"{product.title} ilanınız yayına alındı.",
        "admin",
        product.id
    )
    log_admin_action("İlan onaylandı", "product", product_id, product.title)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/reject_product/<int:product_id>', methods=['POST'])
@login_required
def reject_product(product_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    reason = str((request.json or {}).get('reason', '')).strip()[:300]
    product.status = 'cancelled'
    moderation = get_product_moderation(product_id)
    moderation.is_hidden = True
    moderation.reason = reason or "Admin tarafından reddedildi."
    create_notification(
        product.owner_id,
        "İlan reddedildi",
        f"{product.title} ilanınız admin tarafından reddedildi.",
        "admin",
        product.id
    )
    log_admin_action("İlan reddedildi", "product", product_id, moderation.reason)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/toggle_product_featured/<int:product_id>', methods=['POST'])
@login_required
def toggle_product_featured(product_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    featured = FeaturedProduct.query.filter_by(product_id=product.id).first()
    if featured:
        featured.is_active = not featured.is_active
    else:
        featured = FeaturedProduct(product_id=product.id, is_active=True)
        db.session.add(featured)
    log_admin_action("Öne çıkarma değişti", "product", product_id, product.title)
    db.session.commit()
    return jsonify({"success": True, "is_featured": featured.is_active})

@app.route('/api/request_product_featured/<int:product_id>', methods=['POST'])
@login_required
def request_product_featured(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    if product.owner_id != current_user.id:
        return jsonify({"success": False, "message": "Sadece kendi ilanınız için istek gönderebilirsiniz."}), 403
    if product.status != 'active':
        return jsonify({"success": False, "message": "Sadece yayındaki ilanlar öne çıkarılabilir."}), 400
    if is_featured_product(product.id):
        return jsonify({"success": False, "message": "Bu ilan zaten öne çıkarılmış."}), 400

    admin_users = [user for user in User.query.filter_by(role='admin').all() if is_admin_user(user)]
    for admin in admin_users:
        create_unique_unread_notification(
            admin.id,
            "Öne çıkarma isteği",
            f"{current_user.name}, {product.title} ilanının öne çıkarılmasını istiyor.",
            "admin",
            product.id
        )
    log_admin_action("Öne çıkarma isteği", "product", product.id, product.title)
    db.session.commit()
    return jsonify({"success": True, "message": "Öne çıkarma isteği admin onayına gönderildi."})

@app.route('/api/toggle_product_image_flag/<int:product_id>', methods=['POST'])
@login_required
def toggle_product_image_flag(product_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False}), 404
    moderation = get_product_moderation(product_id)
    moderation.image_flagged = not moderation.image_flagged
    log_admin_action("Görsel işaretleme değişti", "product", product_id, product.title)
    db.session.commit()
    return jsonify({"success": True, "image_flagged": moderation.image_flagged})

@app.route('/api/edit_product/<int:product_id>', methods=['POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
    if not is_admin_user() and product.owner_id != current_user.id:
        return jsonify({"success": False, "message": "Bu ilanı düzenleyemezsiniz."}), 403
    data = request.json or {}
    title = str(data.get('title', product.title)).strip()
    description = str(data.get('description', product.description or '')).strip()
    if not title:
        return jsonify({"success": False, "message": "Başlık boş olamaz."}), 400
    product.title = title[:200]
    product.description = description[:1000]
    if 'exchangeOpen' in data:
        extra = get_product_extra(product.id)
        extra.exchange_open = bool(data.get('exchangeOpen'))
    if is_admin_user():
        log_admin_action("İlan düzenlendi", "product", product.id, product.title)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/rate_sale', methods=['POST'])
@login_required
def rate_sale():
    data = request.json or {}
    product = Product.query.get(data.get('product_id'))
    try:
        score = int(data.get('score'))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Puan geçerli değil."}), 400
    if not product or product.status != 'completed':
        return jsonify({"success": False, "message": "Tamamlanmış satış bulunamadı."}), 404
    if current_user.id == product.owner_id:
        rated_user_id = product.matched_user_id
    elif current_user.id == product.matched_user_id:
        rated_user_id = product.owner_id
    else:
        return jsonify({"success": False, "message": "Bu satışı puanlayamazsınız."}), 403
    if score < 1 or score > 5:
        return jsonify({"success": False, "message": "Puan 1-5 arası olmalıdır."}), 400
    existing = Rating.query.filter_by(product_id=product.id, rater_id=current_user.id, rated_user_id=rated_user_id).first()
    if existing:
        existing.score = score
        existing.comment = str(data.get('comment', '')).strip()[:300]
    else:
        db.session.add(Rating(product_id=product.id, rater_id=current_user.id, rated_user_id=rated_user_id, score=score, comment=str(data.get('comment', '')).strip()[:300]))
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/appeal', methods=['POST'])
@login_required
def create_appeal():
    data = request.json or {}
    message = str(data.get('message', '')).strip()
    if len(message) < 10:
        return jsonify({"success": False, "message": "İtiraz metni en az 10 karakter olmalıdır."}), 400
    appeal = Appeal(user_id=current_user.id, report_id=data.get('report_id'), message=message[:500])
    db.session.add(appeal)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/resolve_appeal/<int:appeal_id>', methods=['POST'])
@login_required
def resolve_appeal(appeal_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    appeal = Appeal.query.get(appeal_id)
    if not appeal:
        return jsonify({"success": False}), 404
    data = request.json or {}
    appeal.status = data.get('status', 'resolved')
    appeal.admin_response = str(data.get('admin_response', '')).strip()[:500]
    appeal.resolved_at = datetime.utcnow()
    create_notification(appeal.user_id, "İtiraz yanıtlandı", appeal.admin_response or "İtirazınız incelendi.", "appeal")
    log_admin_action("İtiraz yanıtlandı", "appeal", appeal.id, appeal.admin_response)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/admin/export/<kind>')
@login_required
def export_admin_csv(kind):
    if not is_admin_user():
        return redirect(url_for('index'))
    output = io.StringIO()
    writer = csv.writer(output)
    if kind == 'users':
        writer.writerow(['id', 'name', 'email', 'phone', 'city', 'district', 'role', 'banned'])
        for user in User.query.order_by(User.id.asc()).all():
            writer.writerow([user.id, user.name, user.email, user.phone, user.city, user.district, user.role, user.is_banned])
    elif kind == 'products':
        writer.writerow(['id', 'title', 'owner', 'status', 'current_bid', 'end_time'])
        for product in Product.query.order_by(Product.id.asc()).all():
            writer.writerow([product.id, product.title, product.owner_name, product.status, product.current_bid, product.end_time])
    elif kind == 'bids':
        writer.writerow(['id', 'product_id', 'user_name', 'amount', 'timestamp'])
        for bid in Bid.query.order_by(Bid.id.asc()).all():
            writer.writerow([bid.id, bid.product_id, bid.user_name, bid.amount, bid.timestamp])
    else:
        return jsonify({"success": False, "message": "Geçersiz CSV türü."}), 404
    log_admin_action("CSV dışa aktarıldı", kind, None, kind)
    db.session.commit()
    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename={kind}.csv'}
    )

@app.route('/api/admin_backup', methods=['POST'])
@login_required
def create_admin_backup():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    source = os.path.join(app.instance_path, 'goktug.db')
    if not os.path.exists(source):
        return jsonify({"success": False, "message": "Veritabanı bulunamadı."}), 404
    backup_dir = os.path.join(app.root_path, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    filename = f"goktug-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    destination = os.path.join(backup_dir, filename)
    shutil.copy2(source, destination)
    log_admin_action("Veritabanı yedeği alındı", "backup", None, filename)
    db.session.commit()
    return jsonify({"success": True, "filename": filename})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json or {}
    email = str(data.get('email', '')).strip().lower()
    phone = str(data.get('phone', '')).strip()

    if not data.get('kvkkAccepted'):
        return jsonify({"success": False, "message": "KVKK aydınlatma metnini onaylamalısınız."}), 400

    # E-posta format kontrolü
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "message": "Geçersiz e-posta formatı"}), 400
    
    # Telefon format kontrolü (basit)
    if not re.match(r"^05[0-9]{9}$", phone):
        return jsonify({"success": False, "message": "Geçersiz telefon formatı (05xxxxxxxxx)"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Bu e-posta zaten kayıtlı"}), 400

    if User.query.filter_by(phone=phone).first():
        return jsonify({"success": False, "message": "Bu telefon zaten kayitli"}), 400

    new_user = User(
        email=email,
        name=str(data.get('name', '')).strip(),
        password=generate_password_hash(data.get('password'), method='pbkdf2:sha256'),
        phone=phone,
        city=data.get('city'),
        district=data.get('district'),
        neighborhood=data.get('neighborhood')
    )
    db.session.add(new_user)
    db.session.flush()
    moderation = get_user_moderation(new_user.id)
    moderation.phone_verified = False
    moderation.email_verified = False
    db.session.commit()
    login_user(new_user)
    return jsonify({"success": True})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    email = str(data.get('email', '')).strip().lower()
    user = User.query.filter_by(email=email).first()
    remember = data.get('remember', False)
    if user and check_password_hash(user.password, data.get('password')):
        if user.ban_until and user.ban_until > datetime.now():
            return jsonify({"success": False, "message": "Hesabınız banlıdır."}), 403
        login_user(user, remember=remember)
        return jsonify({"success": True, "redirect": "/admin" if is_admin_user(user) else None})
    return jsonify({"success": False, "message": "Hatalı giriş"}), 401

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/api/add_product', methods=['POST'])
@login_required
def add_product():
    data = request.json
    settings = get_site_settings()
    allowed_conditions = {'Yeni', 'Az kullanılmış', 'İyi durumda', 'Yıpranmış'}
    try:
        duration_days = int(data.get('durationDays') or data.get('duration') or settings["default_duration_days"])
    except (TypeError, ValueError):
        duration_days = settings["default_duration_days"]
    duration_days = duration_days if duration_days in {1, 7, 30, 90, 180} else settings["default_duration_days"]
    title = str(data.get('title', '')).strip()
    condition = str(data.get('condition', '')).strip()
    imgs = data.get('images', [])

    if not title or title.endswith('|'):
        return jsonify({"success": False, "message": "Ürün başlığı zorunludur."}), 400

    if not isinstance(imgs, list) or len(imgs) == 0:
        return jsonify({"success": False, "message": "En az bir fotoğraf eklemelisiniz."}), 400
    if len(imgs) > settings["max_images"]:
        return jsonify({"success": False, "message": f"En fazla {settings['max_images']} fotoğraf ekleyebilirsiniz."}), 400

    if condition not in allowed_conditions:
        return jsonify({"success": False, "message": "Ürün durumunu seçmelisiniz."}), 400

    try:
        start_price = int(data.get('startPrice'))
        max_price = int(data.get('maxPrice'))
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Geçerli bir başlangıç fiyatı giriniz."}), 400

    if data.get('startFromOne') and start_price != 1:
        return jsonify({"success": False, "message": "1 TL'den Başlat seçeneğinde başlangıç fiyatı sadece 1 TL olabilir."}), 400

    if start_price < 1:
        return jsonify({"success": False, "message": "Başlangıç fiyatı en az 1 TL olmalıdır."}), 400
    
    end_time = datetime.now() + timedelta(days=duration_days)
    
    saved_imgs = save_product_images(imgs)
    if not saved_imgs:
        return jsonify({"success": False, "message": "Fotograflar kaydedilemedi."}), 400
    primary_img = saved_imgs[0]
    all_imgs = json.dumps(saved_imgs)

    new_p = Product(
        title=title, category=data['category'], brand=data['brand'],
        max_price=max_price, description=data['desc'], start_price=start_price,
        current_bid=start_price, 
        image_url=primary_img,
        image_urls=all_imgs,
        end_time=end_time,
        owner_id=current_user.id, owner_name=current_user.name,
        status='pending_admin_approval'
    )
    db.session.add(new_p)
    db.session.flush()
    extra = get_product_extra(new_p.id)
    extra.condition = condition
    extra.exchange_open = bool(data.get('exchangeOpen'))
    moderation = get_product_moderation(new_p.id)
    moderation.is_hidden = True
    moderation.reason = "Admin onayı bekliyor."
    create_notification(
        current_user.id,
        "İlan onay bekliyor",
        f"{title} ilanınız admin onayından sonra yayına alınacak.",
        "product",
        new_p.id
    )
    db.session.commit()
    return jsonify({"success": True})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_configured_admin()
    app.run(debug=True)
