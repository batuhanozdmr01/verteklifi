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
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import text
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
app.json.sort_keys = False
app.jinja_env.policies['json.dumps_kwargs'] = {'sort_keys': False}

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
    address_detail = db.Column(db.String(300), nullable=True)
    address_privacy = db.Column(db.String(30), default='after_sale')
    availability_text = db.Column(db.String(200), nullable=True)
    payout_iban = db.Column(db.String(40), nullable=True)
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
    secure_purchase_enabled = db.Column(db.Boolean, default=False)
    shipping_payer = db.Column(db.String(20), default='buyer')
    shipping_desi = db.Column(db.Integer, nullable=True)
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

class FeaturedRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)
    payment_status = db.Column(db.String(30), default='pending')
    payment_amount = db.Column(db.Integer, default=0)
    paytr_amount_kurus = db.Column(db.Integer, default=0)
    admin_response = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    product = db.relationship('Product', foreign_keys=[product_id])
    user = db.relationship('User', foreign_keys=[user_id])

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
    value = db.Column(db.Text, nullable=False)
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
    buyer_received_confirmed = db.Column(db.Boolean, default=False)
    seller_payment_confirmed = db.Column(db.Boolean, default=False)
    shipping_status = db.Column(db.String(30), default='hazirlaniyor')
    shipping_carrier = db.Column(db.String(60), nullable=True)
    tracking_code = db.Column(db.String(120), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PaymentIntent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False, unique=True, index=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    status = db.Column(db.String(30), default='draft', index=True)
    provider = db.Column(db.String(30), default='paytr')
    provider_reference = db.Column(db.String(120), nullable=True)
    product_amount = db.Column(db.Integer, default=0)
    shipping_fee = db.Column(db.Integer, default=0)
    service_fee = db.Column(db.Integer, default=0)
    commission_fee = db.Column(db.Integer, default=0)
    buyer_total = db.Column(db.Integer, default=0)
    seller_gross = db.Column(db.Integer, default=0)
    seller_payout_amount = db.Column(db.Integer, default=0)
    seller_shipping_debt = db.Column(db.Integer, default=0)
    platform_total_fee = db.Column(db.Integer, default=0)
    paytr_amount_kurus = db.Column(db.Integer, default=0)
    shipping_payer = db.Column(db.String(20), default='buyer')
    shipping_carrier = db.Column(db.String(80), nullable=True)
    shipping_desi = db.Column(db.Integer, nullable=True)
    currency = db.Column(db.String(3), default='TRY')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PaymentTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payment_intent_id = db.Column(db.Integer, db.ForeignKey('payment_intent.id'), nullable=False, index=True)
    provider = db.Column(db.String(30), default='paytr')
    transaction_type = db.Column(db.String(30), default='payment')
    status = db.Column(db.String(30), default='created')
    amount = db.Column(db.Integer, default=0)
    provider_reference = db.Column(db.String(120), nullable=True)
    raw_payload = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PlatformFee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payment_intent_id = db.Column(db.Integer, db.ForeignKey('payment_intent.id'), nullable=False, index=True)
    fee_type = db.Column(db.String(40), nullable=False)
    payer = db.Column(db.String(20), default='buyer')
    amount = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ShippingCharge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payment_intent_id = db.Column(db.Integer, db.ForeignKey('payment_intent.id'), nullable=False, unique=True, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False, index=True)
    carrier = db.Column(db.String(80), nullable=True)
    desi = db.Column(db.Integer, nullable=True)
    payer = db.Column(db.String(20), default='buyer')
    amount = db.Column(db.Integer, default=0)
    status = db.Column(db.String(30), default='quoted')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SellerPayout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payment_intent_id = db.Column(db.Integer, db.ForeignKey('payment_intent.id'), nullable=False, unique=True, index=True)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    amount = db.Column(db.Integer, default=0)
    status = db.Column(db.String(30), default='pending')
    available_at = db.Column(db.DateTime, nullable=True)
    paid_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PaymentErrorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(40), default='payment')
    message = db.Column(db.String(300), nullable=False)
    payload = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    legacy_turkish_map = str.maketrans({
        'ţ': 'ş',
        'Ţ': 'Ş',
        'đ': 'ğ',
        'Đ': 'Ğ',
        'þ': 'ş',
        'Þ': 'Ş',
        'ý': 'ı',
        'Ý': 'İ'
    })
    mojibake_replacements = {
        'Ä±': 'ı',
        'Ä°': 'İ',
        'ÄŸ': 'ğ',
        'Äž': 'Ğ',
        'ÅŸ': 'ş',
        'Åž': 'Ş',
        'Ã¼': 'ü',
        'Ãœ': 'Ü',
        'Ã¶': 'ö',
        'Ã–': 'Ö',
        'Ã§': 'ç',
        'Ã‡': 'Ç',
        'â€œ': '"',
        'â€': '"',
        'â€™': "'",
        'â€˜': "'",
        'â€“': '-',
        'â€”': '-'
    }
    mojibake_markers = ('Ã', 'Ä', 'Å', 'Â', 'Ð', 'ð', 'Þ', 'þ', 'Ý', 'ý', 'ţ', 'Ţ', 'đ', 'Đ', '�', 'â‚º')

    def mojibake_score(candidate):
        return sum(candidate.count(marker) for marker in mojibake_markers)

    text = text.replace('â‚º', '₺')
    for bad, good in mojibake_replacements.items():
        text = text.replace(bad, good)
    text = text.translate(legacy_turkish_map)
    for _ in range(5):
        best = text
        best_score = mojibake_score(text)
        for encoding in ('cp1254', 'latin1', 'cp1252'):
            try:
                candidate = text.encode(encoding).decode('utf-8')
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            candidate = candidate.replace('â‚º', '₺')
            for bad, good in mojibake_replacements.items():
                candidate = candidate.replace(bad, good)
            candidate = candidate.translate(legacy_turkish_map)
            score = mojibake_score(candidate)
            if score < best_score:
                best = candidate
                best_score = score
        if best == text:
            break
        text = best
    return text.translate(legacy_turkish_map)

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
    "featured_price": "5",
    "maintenance_mode": "0",
    "payment_service_fee_fixed": "0",
    "payment_service_fee_percent": "0",
    "platform_commission_percent": "0",
    "buyer_auto_confirm_days": "3",
    "support_phone": "",
    "support_email": "",
    "support_instagram": "",
    "secure_shipping_carrier": "Yurtiçi Kargo",
    "secure_shipping_rates": json.dumps({
        "1": 65,
        "2": 75,
        "3": 85,
        "4": 95,
        "5": 110,
        "10": 160,
        "15": 220,
        "20": 280,
        "30": 390
    }, ensure_ascii=False),
    "kvkk_text": (
        "Bu platform, kullanıcıların ikinci el ürün ilanı paylaşması, teklif alması, takas teklifi göndermesi, "
        "favori oluşturması, özel mesajlaşması ve şikayet/destek talebi iletmesi için hizmet veren bir ilan ve "
        "iletişim platformudur.\n\n"
        "Kayıt sırasında paylaştığınız ad soyad, e-posta, telefon, şehir/ilçe/mahalle ve şifre bilgisi; hesabınızı "
        "oluşturmak, güvenli giriş sağlamak, üyeler arasında ilan, teklif, takas ve mesajlaşma süreçlerini yürütmek, "
        "kötüye kullanımı önlemek ve admin denetimini sağlamak amacıyla işlenir.\n\n"
        "İlan, fotoğraf, açıklama, teklif, favori, mesaj, şikayet, güven seviyesi, profil fotoğrafı ve işlem kayıtları; "
        "platformun çalışması, kullanıcı güvenliği, admin onayı/moderasyonu, uyuşmazlık ve destek süreçlerinin yürütülmesi "
        "için saklanabilir.\n\n"
        "Telefon ve e-posta bilgileriniz diğer kullanıcılara açık gösterilmez; yalnızca admin denetimi ve gerekli güvenlik "
        "süreçleri kapsamında görüntülenebilir. Satış, ödeme, teslimat ve ürün doğruluğu konularında sorumluluk alıcı ve "
        "satıcıya aittir.\n\n"
        "Kişisel verileriniz, yasal zorunluluklar dışında üçüncü kişilerle paylaşılmaz. Hesabınız ve verilerinizle ilgili "
        "taleplerinizi profilinizdeki destek/bize ulaşın alanlarından iletebilirsiniz."
    ),
    "sales_terms_text": (
        "Verteklifi güvenli alışveriş sürecinde alıcı ödemesi, ödeme kuruluşu ve platform kayıtları üzerinden takip edilir. "
        "Ödeme alındığında tutar satıcıya hemen aktarılmaz; teslimat, alıcı onayı ve itiraz süreci tamamlanana kadar güvenli işlem kaydı olarak bekletilir.\n\n"
        "Kargo ücreti ilanda seçilen ödeme tarafına göre alıcıdan tahsil edilebilir veya satıcı alacağından mahsup edilebilir. "
        "Alıcı teslim aldığı üründe sorun bildirirse ödeme aktarımı admin incelemesi sonuçlanana kadar durdurulabilir.\n\n"
        "Kullanıcılar satış, ödeme, kargo, iade ve itiraz süreçlerinde doğru bilgi vermekle yükümlüdür. Platform; komisyon, işlem ücreti, kargo ücreti ve satıcı aktarım tutarlarını işlem kayıtlarında gösterebilir."
    )
}

SHIPPING_CARRIERS = [
    "PTT Kargo",
    "Yurtiçi Kargo",
    "Aras Kargo",
    "MNG Kargo",
    "Sürat Kargo",
    "Trendyol Express",
    "Hepsijet",
    "Kolay Gelsin",
    "UPS Kargo",
    "DHL",
    "FedEx",
    "Diğer"
]

SHIPPING_TRACKING_URLS = {
    "PTT Kargo": "https://gonderitakip.ptt.gov.tr/",
    "Yurtiçi Kargo": "https://www.yurticikargo.com/tr/online-servisler/gonderi-sorgula",
    "Aras Kargo": "https://www.araskargo.com.tr/tr/kargo-takip",
    "MNG Kargo": "https://www.mngkargo.com.tr/gonderi-takip",
    "Sürat Kargo": "https://www.suratkargo.com.tr/KargoTakip",
    "Trendyol Express": "https://express.trendyol.com/gonderi-takip",
    "Hepsijet": "https://www.hepsijet.com/gonderi-takibi",
    "Kolay Gelsin": "https://www.kolaygelsin.com/gonderi-takibi",
    "UPS Kargo": "https://www.ups.com/track?loc=tr_TR",
    "DHL": "https://www.dhl.com/tr-tr/home/tracking.html",
    "FedEx": "https://www.fedex.com/tr-tr/tracking.html"
}

def safe_int(value, fallback, minimum=None, maximum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed

def parse_secure_shipping_rates(raw_rates):
    try:
        loaded = json.loads(raw_rates or "{}")
    except (TypeError, ValueError):
        loaded = {}
    if not isinstance(loaded, dict):
        loaded = {}
    rates = {}
    for key, value in loaded.items():
        desi = safe_int(key, 0, 0, 1000)
        price = safe_int(value, 0, 0, 1000000)
        if desi > 0 and price >= 0:
            rates[str(desi)] = price
    if not rates:
        return json.loads(DEFAULT_SITE_SETTINGS["secure_shipping_rates"])
    return dict(sorted(rates.items(), key=lambda item: int(item[0])))

def calculate_secure_shipping_fee(desi, rates):
    desi = safe_int(desi, 0, 0, 1000)
    if desi <= 0:
        return 0
    numeric_rates = sorted((int(key), int(value)) for key, value in rates.items())
    for rate_desi, price in numeric_rates:
        if desi <= rate_desi:
            return price
    return numeric_rates[-1][1] if numeric_rates else 0

def build_secure_payment_summary(product, extra=None, settings=None):
    extra = extra or get_product_extra(product.id)
    settings = settings or get_site_settings()
    secure_enabled = bool(extra and extra.secure_purchase_enabled)
    desi = extra.shipping_desi if secure_enabled and extra else None
    shipping_fee = calculate_secure_shipping_fee(desi, settings["secure_shipping_rates"]) if secure_enabled else 0
    shipping_payer = extra.shipping_payer if extra and extra.shipping_payer in {'buyer', 'seller'} else 'buyer'
    product_amount = int(product.current_bid or product.start_price or 0)
    service_fee = settings["payment_service_fee_fixed"] + round(product_amount * settings["payment_service_fee_percent"] / 100)
    commission_fee = round(product_amount * settings["platform_commission_percent"] / 100)
    buyer_total = product_amount + service_fee + (shipping_fee if shipping_payer == 'buyer' else 0)
    seller_shipping_debt = shipping_fee if shipping_payer == 'seller' else 0
    seller_payout_amount = max(0, product_amount - commission_fee - seller_shipping_debt)
    platform_total_fee = service_fee + commission_fee
    return {
        "enabled": secure_enabled,
        "carrier": settings["secure_shipping_carrier"],
        "desi": desi,
        "shippingFee": shipping_fee,
        "serviceFee": service_fee,
        "commissionFee": commission_fee,
        "shippingPayer": shipping_payer,
        "shippingPayerLabel": "Alıcı öder" if shipping_payer == 'buyer' else "Satıcı öder",
        "productAmount": product_amount,
        "buyerTotal": buyer_total,
        "sellerPayoutAmount": seller_payout_amount,
        "sellerShippingDebt": seller_shipping_debt,
        "platformTotalFee": platform_total_fee,
        "paytrAmountKurus": buyer_total * 100,
        "chargeRule": "Kargo ücreti alıcıdan tahsil edilir." if shipping_payer == 'buyer' else "Kargo ücreti satıcı bakiyesinden/kesintisinden alınır."
    }

def get_site_settings():
    settings = DEFAULT_SITE_SETTINGS.copy()
    for setting in SiteSetting.query.all():
        settings[setting.key] = setting.value
    default_duration_days = safe_int(settings.get("default_duration_days"), 7)
    if default_duration_days not in {1, 7, 30, 90, 180}:
        default_duration_days = 7

    secure_shipping_rates = parse_secure_shipping_rates(settings.get("secure_shipping_rates"))
    return {
        "min_bid": safe_int(settings.get("min_bid"), 5, 1, 1000000),
        "bid_step": safe_int(settings.get("bid_step"), 5, 1, 1000000),
        "chat_spam_seconds": safe_int(settings.get("chat_spam_seconds"), 5, 1, 120),
        "default_duration_days": default_duration_days,
        "max_images": safe_int(settings.get("max_images"), 5, 1, 5),
        "featured_price": safe_int(settings.get("featured_price"), 5, 0, 1000000),
        "payment_service_fee_fixed": safe_int(settings.get("payment_service_fee_fixed"), 0, 0, 1000000),
        "payment_service_fee_percent": safe_int(settings.get("payment_service_fee_percent"), 0, 0, 100),
        "platform_commission_percent": safe_int(settings.get("platform_commission_percent"), 0, 0, 100),
        "buyer_auto_confirm_days": safe_int(settings.get("buyer_auto_confirm_days"), 3, 1, 14),
        "maintenance_mode": settings.get("maintenance_mode", "0") == "1",
        "support_phone": repair_turkish_mojibake(settings.get("support_phone", "")),
        "support_email": repair_turkish_mojibake(settings.get("support_email", "")),
        "support_instagram": repair_turkish_mojibake(settings.get("support_instagram", "")),
        "secure_shipping_carrier": repair_turkish_mojibake(settings.get("secure_shipping_carrier", DEFAULT_SITE_SETTINGS["secure_shipping_carrier"]))[:80],
        "secure_shipping_rates": secure_shipping_rates,
        "secure_shipping_rates_text": json.dumps(secure_shipping_rates, ensure_ascii=False, indent=2),
        "kvkk_text": repair_turkish_mojibake(settings.get("kvkk_text", DEFAULT_SITE_SETTINGS["kvkk_text"])),
        "sales_terms_text": repair_turkish_mojibake(settings.get("sales_terms_text", DEFAULT_SITE_SETTINGS["sales_terms_text"]))
    }

def update_site_setting(key, value):
    setting = SiteSetting.query.get(key)
    if setting:
        setting.value = str(value)
    else:
        db.session.add(SiteSetting(key=key, value=str(value)))

def get_default_category_menu():
    try:
        with open(os.path.join(app.root_path, 'templates', 'index.html'), encoding='utf-8') as template_file:
            html = template_file.read()
        match = re.search(r'const\s+(?:fallbackCategoryData|categoryData)\s*=\s*\{([\s\S]*?)\n\s*\};\s*\n\s*const\s+(?:serverCategoryData|appState)', html)
        if not match:
            raise ValueError("Kategori bloğu bulunamadı.")
        menu = {}
        for category_match in re.finditer(r'"([^"]+)"\s*:\s*\[([\s\S]*?)\]\s*,?', match.group(1)):
            category_name = category_match.group(1)
            items = []
            for item_match in re.finditer(r'\{\s*name:\s*"([^"]+)"\s*,\s*maxPrice:\s*(\d+)\s*,\s*icon:\s*"([^"]+)"\s*\}', category_match.group(2)):
                items.append({
                    "name": item_match.group(1),
                    "maxPrice": int(item_match.group(2)),
                    "icon": item_match.group(3)
                })
            if items:
                menu[category_name] = items
        if menu:
            return menu
    except Exception:
        pass
    return {
        "Telefon": [{"name": "Apple", "maxPrice": 150000, "icon": "fa-mobile-alt"}, {"name": "Samsung", "maxPrice": 120000, "icon": "fa-mobile-alt"}, {"name": "Diğer", "maxPrice": 200000, "icon": "fa-mobile-alt"}],
        "Bilgisayar": [{"name": "Apple", "maxPrice": 250000, "icon": "fa-laptop"}, {"name": "Lenovo", "maxPrice": 150000, "icon": "fa-laptop"}, {"name": "Diğer", "maxPrice": 500000, "icon": "fa-laptop"}]
    }

def normalize_category_menu(menu):
    if isinstance(menu, list):
        menu = {
            str(entry.get('name') or '').strip(): entry.get('items') or []
            for entry in menu
            if isinstance(entry, dict)
        }
    if not isinstance(menu, dict):
        return None
    normalized = {}
    for category_name, items in menu.items():
        clean_category = repair_turkish_mojibake(str(category_name or '').strip())[:100]
        if not clean_category or not isinstance(items, list):
            continue
        clean_items = []
        seen_items = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            name = repair_turkish_mojibake(str(item.get('name') or '').strip())[:100]
            if not name or name.lower() in seen_items:
                continue
            try:
                max_price = int(item.get('maxPrice') or item.get('max_price') or 100000)
            except (TypeError, ValueError):
                max_price = 100000
            icon = re.sub(r'[^a-zA-Z0-9-]', '', str(item.get('icon') or 'fa-tags'))[:60] or 'fa-tags'
            clean_items.append({
                "name": name,
                "maxPrice": max(1, min(max_price, 10000000)),
                "icon": icon
            })
            seen_items.add(name.lower())
        if clean_items:
            normalized[clean_category] = clean_items[:80]
    return normalized

def get_category_menu():
    setting = SiteSetting.query.get("category_menu_json")
    if setting and setting.value:
        try:
            menu = normalize_category_menu(json.loads(setting.value))
            if menu:
                order_setting = SiteSetting.query.get("category_menu_order_json")
                if order_setting and order_setting.value:
                    try:
                        order = json.loads(order_setting.value)
                        if isinstance(order, list):
                            ordered_menu = {}
                            for category_name in order:
                                if category_name in menu:
                                    ordered_menu[category_name] = menu[category_name]
                            for category_name, items in menu.items():
                                if category_name not in ordered_menu:
                                    ordered_menu[category_name] = items
                            return ordered_menu
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass
                return menu
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return get_default_category_menu()

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
    duplicate_phone_count = User.query.filter(User.id != user.id, User.phone == user.phone).count() if user.phone else 0
    duplicate_address_count = 0
    if user.city and user.district and user.neighborhood and user.address_detail:
        duplicate_address_count = User.query.filter(
            User.id != user.id,
            User.city == user.city,
            User.district == user.district,
            User.neighborhood == user.neighborhood,
            User.address_detail == user.address_detail
        ).count()
    score = total_reports * 2 + (user.withdraw_count or 0) + duplicate_phone_count * 3 + duplicate_address_count * 2
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
        "withdraw_count": user.withdraw_count or 0,
        "duplicate_phone_count": duplicate_phone_count,
        "duplicate_address_count": duplicate_address_count
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

def get_user_reviews(user_id, limit=8):
    reviews = []
    for rating in Rating.query.filter_by(rated_user_id=user_id).order_by(Rating.created_at.desc()).limit(limit).all():
        rater = User.query.get(rating.rater_id)
        product = Product.query.get(rating.product_id)
        reviews.append({
            "id": rating.id,
            "score": rating.score,
            "comment": repair_turkish_mojibake(rating.comment or ""),
            "raterName": rater.name if rater else "Silinmiş kullanıcı",
            "raterImage": get_user_profile_image_url(rater.id) if rater else None,
            "productId": product.id if product else None,
            "productTitle": repair_turkish_mojibake(product.title) if product else "Silinmiş ilan",
            "createdAt": rating.created_at.strftime('%d.%m.%Y %H:%M')
        })
    return reviews

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
    if risk.get("duplicate_phone_count"):
        warnings.append(f"Aynı telefonla {risk['duplicate_phone_count']} başka hesap var.")
    if risk.get("duplicate_address_count"):
        warnings.append(f"Aynı tam adresle {risk['duplicate_address_count']} başka hesap var.")
    return {
        "score": summary["score"],
        "label": summary["label"],
        "rating": rating,
        "completedSales": completed_sales,
        "activeProducts": active_products,
        "reportCount": risk["report_count"],
        "withdrawCount": risk["withdraw_count"],
        "duplicatePhoneCount": risk.get("duplicate_phone_count", 0),
        "duplicateAddressCount": risk.get("duplicate_address_count", 0),
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
    settings = get_site_settings()
    sale_issue_open = Report.query.filter_by(product_id=product_id, target_type='sale').filter(
        Report.status.in_(['open', 'reviewing'])
    ).count() > 0
    auto_confirm_at = None
    if progress and progress.shipping_status == 'teslim_edildi' and not progress.buyer_received_confirmed:
        auto_confirm_at = progress.updated_at + timedelta(days=settings["buyer_auto_confirm_days"])
    return {
        "contact_made": bool(progress and progress.contact_made),
        "delivered": bool(progress and progress.delivered),
        "paid": bool(progress and progress.paid),
        "buyer_received_confirmed": bool(progress and progress.buyer_received_confirmed),
        "seller_payment_confirmed": bool(progress and progress.seller_payment_confirmed),
        "sale_issue_open": sale_issue_open,
        "shipping_status": (progress.shipping_status if progress and progress.shipping_status else 'hazirlaniyor'),
        "shipping_carrier": repair_turkish_mojibake(progress.shipping_carrier or "") if progress else "",
        "tracking_code": repair_turkish_mojibake(progress.tracking_code or "") if progress else "",
        "auto_confirm_at": auto_confirm_at.strftime('%d.%m.%Y %H:%M') if auto_confirm_at else None
    }

def get_or_create_payment_intent(product):
    if not product.matched_user_id:
        return None
    extra = get_product_extra(product.id)
    settings = get_site_settings()
    summary = build_secure_payment_summary(product, extra, settings)
    intent = PaymentIntent.query.filter_by(product_id=product.id).first()
    if not intent:
        intent = PaymentIntent(
            product_id=product.id,
            buyer_id=product.matched_user_id,
            seller_id=product.owner_id,
            status='pending',
            provider='paytr'
        )
        db.session.add(intent)
        db.session.flush()
    elif intent.status == 'draft':
        intent.status = 'pending'
    intent.buyer_id = product.matched_user_id
    intent.seller_id = product.owner_id
    intent.product_amount = summary["productAmount"]
    intent.shipping_fee = summary["shippingFee"]
    intent.service_fee = summary["serviceFee"]
    intent.commission_fee = summary["commissionFee"]
    intent.buyer_total = summary["buyerTotal"]
    intent.seller_gross = summary["productAmount"]
    intent.seller_payout_amount = summary["sellerPayoutAmount"]
    intent.seller_shipping_debt = summary["sellerShippingDebt"]
    intent.platform_total_fee = summary["platformTotalFee"]
    intent.paytr_amount_kurus = summary["paytrAmountKurus"]
    intent.shipping_payer = summary["shippingPayer"]
    intent.shipping_carrier = summary["carrier"]
    intent.shipping_desi = summary["desi"]
    intent.currency = 'TRY'

    ShippingCharge.query.filter_by(payment_intent_id=intent.id).delete()
    PlatformFee.query.filter_by(payment_intent_id=intent.id).delete()
    db.session.add(ShippingCharge(
        payment_intent_id=intent.id,
        product_id=product.id,
        carrier=summary["carrier"],
        desi=summary["desi"],
        payer=summary["shippingPayer"],
        amount=summary["shippingFee"],
        status='quoted'
    ))
    if summary["serviceFee"] > 0:
        db.session.add(PlatformFee(payment_intent_id=intent.id, fee_type='service_fee', payer='buyer', amount=summary["serviceFee"]))
    if summary["commissionFee"] > 0:
        db.session.add(PlatformFee(payment_intent_id=intent.id, fee_type='commission', payer='seller', amount=summary["commissionFee"]))

    payout = SellerPayout.query.filter_by(payment_intent_id=intent.id).first()
    if not payout:
        payout = SellerPayout(payment_intent_id=intent.id, seller_id=product.owner_id)
        db.session.add(payout)
    payout.seller_id = product.owner_id
    payout.amount = summary["sellerPayoutAmount"]
    payout.status = 'pending'
    if not PaymentTransaction.query.filter_by(payment_intent_id=intent.id, transaction_type='payment').first():
        db.session.add(PaymentTransaction(
            payment_intent_id=intent.id,
            provider='paytr',
            transaction_type='payment',
            status='created',
            amount=summary["buyerTotal"],
            raw_payload=json.dumps({
                "product_id": product.id,
                "paytr_amount_kurus": summary["paytrAmountKurus"],
                "note": "PayTR canlı entegrasyonunda token/callback bu kayda bağlanacak."
            }, ensure_ascii=False)
        ))
    return intent

def is_paytr_configured():
    return bool(os.environ.get('PAYTR_MERCHANT_ID') and os.environ.get('PAYTR_MERCHANT_KEY') and os.environ.get('PAYTR_MERCHANT_SALT'))

def get_public_base_url():
    configured_url = os.environ.get('PUBLIC_BASE_URL')
    if configured_url:
        return configured_url.rstrip('/')
    return request.host_url.rstrip('/')

def get_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    return (forwarded_for.split(',')[0].strip() or request.remote_addr or '127.0.0.1')[:39]

def ensure_payment_provider_reference(intent):
    if not intent.provider_reference:
        intent.provider_reference = f"VT{intent.id}{uuid.uuid4().hex[:12]}".upper()[:64]
        db.session.flush()
    return intent.provider_reference

def build_paytr_callback_hash(merchant_oid, status, total_amount):
    merchant_key = os.environ.get('PAYTR_MERCHANT_KEY', '').encode('utf-8')
    merchant_salt = os.environ.get('PAYTR_MERCHANT_SALT', '')
    token = f"{merchant_oid}{merchant_salt}{status}{total_amount}".encode('utf-8')
    return base64.b64encode(hmac.new(merchant_key, token, hashlib.sha256).digest()).decode('utf-8')

def mark_payment_success(intent, total_amount=None, raw_payload=None):
    if intent.status in {'paid', 'escrow', 'ready_for_payout', 'paid_out'}:
        return False
    intent.status = 'escrow'
    if total_amount is not None:
        try:
            intent.paytr_amount_kurus = int(total_amount)
            intent.buyer_total = round(int(total_amount) / 100)
        except (TypeError, ValueError):
            pass
    db.session.add(PaymentTransaction(
        payment_intent_id=intent.id,
        provider='paytr',
        transaction_type='callback',
        status='success',
        amount=intent.buyer_total,
        provider_reference=intent.provider_reference,
        raw_payload=json.dumps(raw_payload or {}, ensure_ascii=False)
    ))
    create_notification(
        intent.buyer_id,
        "Ödeme alındı",
        "Ödemeniz güvenli havuza geçti. Satıcı kargoya verebilir.",
        "payment",
        intent.product_id
    )
    create_notification(
        intent.seller_id,
        "Ödeme alındı",
        "Alıcının ödemesi güvenli havuza geçti. Kargo sürecini başlatabilirsiniz.",
        "payment",
        intent.product_id
    )
    return True

def mark_payment_failed(intent, raw_payload=None):
    intent.status = 'cancelled'
    db.session.add(PaymentTransaction(
        payment_intent_id=intent.id,
        provider='paytr',
        transaction_type='callback',
        status='failed',
        amount=intent.buyer_total,
        provider_reference=intent.provider_reference,
        raw_payload=json.dumps(raw_payload or {}, ensure_ascii=False)
    ))
    create_notification(
        intent.buyer_id,
        "Ödeme başarısız",
        "PayTR ödeme işlemi tamamlanamadı. Tekrar deneyebilirsiniz.",
        "payment",
        intent.product_id
    )

def serialize_payment_intent(product_id):
    intent = PaymentIntent.query.filter_by(product_id=product_id).first()
    if not intent:
        return None
    status_labels = {
        "draft": "Ödeme hazırlanıyor",
        "pending": "Ödeme bekleniyor",
        "paid": "Ödeme alındı",
        "escrow": "Para güvende",
        "ready_for_payout": "Satıcıya aktarılabilir",
        "paid_out": "Satıcıya aktarıldı",
        "refunded": "İade edildi",
        "cancelled": "İptal edildi"
    }
    return {
        "id": intent.id,
        "status": intent.status,
        "statusLabel": status_labels.get(intent.status, intent.status),
        "provider": intent.provider,
        "productAmount": intent.product_amount,
        "shippingFee": intent.shipping_fee,
        "serviceFee": intent.service_fee,
        "commissionFee": intent.commission_fee,
        "buyerTotal": intent.buyer_total,
        "sellerPayoutAmount": intent.seller_payout_amount,
        "sellerShippingDebt": intent.seller_shipping_debt,
        "platformTotalFee": intent.platform_total_fee,
        "paytrAmountKurus": intent.paytr_amount_kurus,
        "shippingPayer": intent.shipping_payer,
        "shippingCarrier": repair_turkish_mojibake(intent.shipping_carrier or ""),
        "shippingDesi": intent.shipping_desi,
        "currency": intent.currency
    }

def get_user_wallet_summary(user_id):
    seller_intents = PaymentIntent.query.filter_by(seller_id=user_id).all()
    buyer_intents = PaymentIntent.query.filter_by(buyer_id=user_id).all()
    payouts = SellerPayout.query.filter_by(seller_id=user_id).all()
    return {
        "pendingPayout": sum(payout.amount or 0 for payout in payouts if payout.status in {'pending', 'ready'}),
        "paidOut": sum(payout.amount or 0 for payout in payouts if payout.status == 'paid'),
        "salesGross": sum(intent.product_amount or 0 for intent in seller_intents),
        "commissionPaid": sum(intent.commission_fee or 0 for intent in seller_intents),
        "shippingDebt": sum(intent.seller_shipping_debt or 0 for intent in seller_intents),
        "purchaseTotal": sum(intent.buyer_total or 0 for intent in buyer_intents),
        "openPayments": sum(1 for intent in buyer_intents if intent.status in {'draft', 'pending'})
    }

def get_user_payment_rows(user_id, limit=8):
    intents = PaymentIntent.query.filter(
        (PaymentIntent.buyer_id == user_id) | (PaymentIntent.seller_id == user_id)
    ).order_by(PaymentIntent.created_at.desc()).limit(limit).all()
    rows = []
    for intent in intents:
        product = Product.query.get(intent.product_id)
        rows.append({
            "id": intent.id,
            "productId": intent.product_id,
            "productTitle": repair_turkish_mojibake(product.title) if product else "Silinmiş ilan",
            "role": "seller" if intent.seller_id == user_id else "buyer",
            "status": intent.status,
            "statusLabel": serialize_payment_intent(intent.product_id)["statusLabel"],
            "buyerTotal": intent.buyer_total,
            "sellerPayoutAmount": intent.seller_payout_amount,
            "platformTotalFee": intent.platform_total_fee,
            "createdAt": intent.created_at.strftime('%d.%m.%Y %H:%M')
        })
    return rows

def serialize_profile_product(product):
    payment = serialize_payment_intent(product.id)
    progress = serialize_sale_progress(product.id) if product.status == 'completed' else None
    return {
        "id": product.id,
        "title": repair_turkish_mojibake(product.title),
        "img": product.image_url,
        "currentBid": product.current_bid,
        "status": product.status,
        "statusLabel": get_product_status_label(product.status),
        "createdAt": product.created_at.strftime('%d.%m.%Y'),
        "buyerName": product.matched_user.name if product.matched_user else "",
        "sellerName": repair_turkish_mojibake(product.owner_name or ""),
        "payment": payment,
        "progress": progress
    }

def get_finance_summary():
    intents = PaymentIntent.query.all()
    payouts = SellerPayout.query.all()
    featured_requests = FeaturedRequest.query.all()
    return {
        "grossVolume": sum(intent.buyer_total or 0 for intent in intents),
        "productVolume": sum(intent.product_amount or 0 for intent in intents),
        "shippingVolume": sum(intent.shipping_fee or 0 for intent in intents),
        "serviceFees": sum(intent.service_fee or 0 for intent in intents),
        "commissionFees": sum(intent.commission_fee or 0 for intent in intents),
        "platformFees": sum(intent.platform_total_fee or 0 for intent in intents),
        "pendingPayout": sum(payout.amount or 0 for payout in payouts if payout.status in {'pending', 'ready'}),
        "paidOut": sum(payout.amount or 0 for payout in payouts if payout.status == 'paid'),
        "openPaymentCount": sum(1 for intent in intents if intent.status in {'draft', 'pending'}),
        "paidPaymentCount": sum(1 for intent in intents if intent.status in {'paid', 'escrow', 'ready_for_payout', 'paid_out'}),
        "featuredPendingAmount": sum(request.payment_amount or 0 for request in featured_requests if request.payment_status == 'pending'),
        "featuredPaidAmount": sum(request.payment_amount or 0 for request in featured_requests if request.payment_status == 'paid')
    }

def log_payment_error(source, message, payload=None):
    db.session.add(PaymentErrorLog(
        source=source[:40],
        message=repair_turkish_mojibake(str(message))[:300],
        payload=json.dumps(payload or {}, ensure_ascii=False)[:2000] if payload is not None else None
    ))

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
    if product.status in {'completed', 'cancelled'}:
        if not current_user.is_authenticated:
            return False
        return can_access_admin_panel() or product.owner_id == current_user.id or product.matched_user_id == current_user.id
    if product.status == 'pending_admin_approval':
        if not current_user.is_authenticated:
            return False
        return can_access_admin_panel() or product.owner_id == current_user.id
    if not moderation or not moderation.is_hidden:
        return True
    if not current_user.is_authenticated:
        return False
    return can_access_admin_panel() or product.owner_id == current_user.id

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

def load_external_profanity_terms_raw():
    terms_path = os.path.join(app.root_path, 'data', 'profanity_tr.txt')
    if not os.path.exists(terms_path):
        return []

    terms = []
    with open(terms_path, encoding='utf-8-sig') as terms_file:
        for line in terms_file:
            term = repair_turkish_mojibake(line.strip())
            if term and not term.startswith('#') and term not in terms:
                terms.append(term)
    return terms

def save_external_profanity_terms(terms):
    clean_terms = []
    seen = set()
    for term in terms:
        clean = repair_turkish_mojibake(str(term or '').strip())[:80]
        normalized = normalize_chat_text(clean)
        if not clean or not normalized or normalized in seen:
            continue
        clean_terms.append(clean)
        seen.add(normalized)

    data_dir = os.path.join(app.root_path, 'data')
    os.makedirs(data_dir, exist_ok=True)
    terms_path = os.path.join(data_dir, 'profanity_tr.txt')
    with open(terms_path, 'w', encoding='utf-8') as terms_file:
        terms_file.write('\n'.join(clean_terms))
        if clean_terms:
            terms_file.write('\n')
    load_external_profanity_terms.cache_clear()
    return clean_terms

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

def ensure_optional_database_columns():
    try:
        product_extra_columns = {row[1] for row in db.session.execute(text("PRAGMA table_info(product_extra)")).fetchall()}
        if 'secure_purchase_enabled' not in product_extra_columns:
            db.session.execute(text("ALTER TABLE product_extra ADD COLUMN secure_purchase_enabled BOOLEAN DEFAULT 0"))
        if 'shipping_payer' not in product_extra_columns:
            db.session.execute(text("ALTER TABLE product_extra ADD COLUMN shipping_payer VARCHAR(20) DEFAULT 'buyer'"))
        if 'shipping_desi' not in product_extra_columns:
            db.session.execute(text("ALTER TABLE product_extra ADD COLUMN shipping_desi INTEGER"))
        sale_columns = {row[1] for row in db.session.execute(text("PRAGMA table_info(sale_progress)")).fetchall()}
        if 'shipping_status' not in sale_columns:
            db.session.execute(text("ALTER TABLE sale_progress ADD COLUMN shipping_status VARCHAR(30) DEFAULT 'hazirlaniyor'"))
        if 'buyer_received_confirmed' not in sale_columns:
            db.session.execute(text("ALTER TABLE sale_progress ADD COLUMN buyer_received_confirmed BOOLEAN DEFAULT 0"))
        if 'seller_payment_confirmed' not in sale_columns:
            db.session.execute(text("ALTER TABLE sale_progress ADD COLUMN seller_payment_confirmed BOOLEAN DEFAULT 0"))
        if 'shipping_carrier' not in sale_columns:
            db.session.execute(text("ALTER TABLE sale_progress ADD COLUMN shipping_carrier VARCHAR(60)"))
        if 'tracking_code' not in sale_columns:
            db.session.execute(text("ALTER TABLE sale_progress ADD COLUMN tracking_code VARCHAR(120)"))
        user_columns = {row[1] for row in db.session.execute(text("PRAGMA table_info(user)")).fetchall()}
        if 'address_detail' not in user_columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN address_detail VARCHAR(300)"))
        if 'address_privacy' not in user_columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN address_privacy VARCHAR(30) DEFAULT 'after_sale'"))
        if 'availability_text' not in user_columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN availability_text VARCHAR(200)"))
        if 'payout_iban' not in user_columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN payout_iban VARCHAR(40)"))
        featured_request_columns = {row[1] for row in db.session.execute(text("PRAGMA table_info(featured_request)")).fetchall()}
        if 'payment_status' not in featured_request_columns:
            db.session.execute(text("ALTER TABLE featured_request ADD COLUMN payment_status VARCHAR(30) DEFAULT 'pending'"))
        if 'payment_amount' not in featured_request_columns:
            db.session.execute(text("ALTER TABLE featured_request ADD COLUMN payment_amount INTEGER DEFAULT 0"))
        if 'paytr_amount_kurus' not in featured_request_columns:
            db.session.execute(text("ALTER TABLE featured_request ADD COLUMN paytr_amount_kurus INTEGER DEFAULT 0"))
        db.session.commit()
    except OperationalError:
        db.session.rollback()

ADDRESS_API_BASE = "https://www.beterali.com/api/v1"

@lru_cache(maxsize=512)
def fetch_address_api(endpoint, query_string=""):
    url = f"{ADDRESS_API_BASE}/{endpoint}"
    if query_string:
        url = f"{url}?{query_string}"
    request_obj = Request(url, headers={"User-Agent": "verteklifi-address/1.0"})
    with urlopen(request_obj, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))

def first_address_value(item, keys):
    for key in keys:
        value = item.get(key)
        if value is not None and value != "":
            return value
    return None

def address_api_items(endpoint, params, collection_keys, code_keys, name_keys):
    try:
        payload = fetch_address_api(endpoint, urlencode(params))
        data = payload.get("data", {})
        items = []
        for key in collection_keys:
            items = data.get(key, [])
            if items:
                break
        return jsonify({
            "success": True,
            "source": "beterali",
            "items": [
                {"code": first_address_value(item, code_keys), "name": repair_turkish_mojibake(first_address_value(item, name_keys) or "")}
                for item in items
                if first_address_value(item, code_keys) is not None and first_address_value(item, name_keys)
            ]
        })
    except Exception:
        return jsonify({"success": False, "message": "Adres listesi şu an çekilemedi."}), 503

def can_view_sale_contact(product):
    return current_user.is_authenticated and current_user.id in {product.owner_id, product.matched_user_id} or is_admin_user()

def build_sale_seller_info(product):
    seller = User.query.get(product.owner_id)
    if not seller:
        return None
    can_view_detail_address = is_admin_user() or seller.address_privacy == 'after_sale'
    info = {
        "phone": seller.phone,
        "email": seller.email,
        "location": " / ".join(part for part in (seller.city, seller.district, seller.neighborhood) if part),
        "addressPrivacy": seller.address_privacy or 'after_sale',
        "availability": repair_turkish_mojibake(seller.availability_text or "")
    }
    if can_view_detail_address:
        info["addressDetail"] = repair_turkish_mojibake(seller.address_detail or "")
    return info

def build_sale_buyer_info(product):
    buyer = User.query.get(product.matched_user_id)
    if not buyer:
        return None
    return {
        "name": repair_turkish_mojibake(buyer.name or ""),
        "phone": buyer.phone,
        "email": buyer.email,
        "location": " / ".join(part for part in (buyer.city, buyer.district, buyer.neighborhood) if part),
        "addressDetail": repair_turkish_mojibake(buyer.address_detail or ""),
        "availability": repair_turkish_mojibake(buyer.availability_text or "")
    }

def is_admin_user(user=None):
    user = user or current_user
    if not user or not user.is_authenticated:
        return False

    admin_email = os.environ.get('ADMIN_EMAIL')
    if admin_email and user.email != admin_email:
        return False

    return user.role == 'admin'

def is_moderator_user(user=None):
    user = user or current_user
    return bool(user and user.is_authenticated and user.role == 'moderator')

def can_access_admin_panel(user=None):
    return is_admin_user(user) or is_moderator_user(user)

def can_moderate_content(user=None):
    return can_access_admin_panel(user)

@app.before_request
def bootstrap_configured_admin():
    if not getattr(app, '_configured_admin_checked', False):
        db.create_all()
        ensure_optional_database_columns()
        ensure_configured_admin()
        app._configured_admin_checked = True
    if request.method in {'POST', 'DELETE', 'PATCH'} and request.path.startswith('/api/') and request.path != '/api/login':
        if get_site_settings()["maintenance_mode"] and not can_access_admin_panel():
            return jsonify({"success": False, "message": "Site bakım modunda. Lütfen daha sonra tekrar deneyin."}), 503

@app.route('/api/products', methods=['GET'])
def get_products():
    cleanup_expired_products()
    products = Product.query.order_by(Product.id.desc()).all()
    settings = get_site_settings()
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
        secure_payment = build_secure_payment_summary(p, extra, settings)
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
            "securePurchase": secure_payment["enabled"],
            "shippingPayer": secure_payment["shippingPayer"],
            "shippingPayerLabel": secure_payment["shippingPayerLabel"],
            "shippingDesi": secure_payment["desi"],
            "secureShippingCarrier": secure_payment["carrier"],
            "secureShippingFee": secure_payment["shippingFee"],
            "securePaymentBuyerTotal": secure_payment["buyerTotal"],
            "securePaymentProductAmount": secure_payment["productAmount"],
            "securePaymentServiceFee": secure_payment["serviceFee"],
            "securePaymentCommissionFee": secure_payment["commissionFee"],
            "securePaymentPaytrAmountKurus": secure_payment["paytrAmountKurus"],
            "securePaymentSellerPayoutAmount": secure_payment["sellerPayoutAmount"],
            "securePaymentSellerShippingDebt": secure_payment["sellerShippingDebt"],
            "securePaymentPlatformTotalFee": secure_payment["platformTotalFee"],
            "securePaymentChargeRule": secure_payment["chargeRule"],
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
            can_rate = p.status == 'completed' and current_user.id in {p.owner_id, p.matched_user_id}
            if can_rate:
                rated_user_id = p.matched_user_id if current_user.id == p.owner_id else p.owner_id
                existing_rating = Rating.query.filter_by(
                    product_id=p.id,
                    rater_id=current_user.id,
                    rated_user_id=rated_user_id
                ).first()
                prod_data["canRate"] = True
                prod_data["myRating"] = {
                    "score": existing_rating.score,
                    "comment": repair_turkish_mojibake(existing_rating.comment or "")
                } if existing_rating else None
            if p.status == 'completed' and can_view_sale_contact(p):
                seller_info = build_sale_seller_info(p)
                if seller_info and current_user.id == p.matched_user_id and not is_admin_user():
                    seller_info = {
                        "phone": seller_info.get("phone"),
                        "email": seller_info.get("email")
                    }
                prod_data["seller_info"] = seller_info
                prod_data["sale_progress"] = serialize_sale_progress(p.id)
                prod_data["payment_intent"] = serialize_payment_intent(p.id)
            if p.status in {'seller_info_confirmation', 'completed'} and (current_user.id == p.owner_id or is_admin_user()):
                prod_data["buyer_info"] = build_sale_buyer_info(p)
        output.append(prod_data)
    output.sort(key=lambda item: (not item.get("isFeatured"), -item.get("createdAt", 0)))
    return jsonify(output)

@app.route('/api/address/cities', methods=['GET'])
def address_cities():
    return address_api_items('cities', {}, ['cities'], ['city_code', 'code', 'id'], ['city_name', 'name'])

@app.route('/api/address/districts', methods=['GET'])
def address_districts():
    city_code = str(request.args.get('city_code', '')).strip()
    if not city_code.isdigit():
        return jsonify({"success": False, "message": "İl seçmelisiniz."}), 400
    return address_api_items('districts', {"city_code": city_code}, ['districts'], ['district_code', 'districts_code', 'code', 'id'], ['district_name', 'districts_name', 'name'])

@app.route('/api/address/neighborhoods', methods=['GET'])
def address_neighborhoods():
    district_code = str(request.args.get('district_code', '')).strip()
    if not district_code.isdigit():
        return jsonify({"success": False, "message": "İlçe seçmelisiniz."}), 400
    return address_api_items('neighbourhoods', {"districts_code": district_code}, ['neighbourhoods', 'neighborhoods'], ['neighbourhood_code', 'neighborhood_code', 'code', 'id'], ['neighbourhood_name', 'neighborhood_name', 'name'])

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

DAILY_BID_PRODUCT_LIMIT = 10

def daily_bid_window_start():
    return datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

def validate_daily_bid_product_limit(user_id, product_id):
    day_start = daily_bid_window_start()
    already_bid_today = Bid.query.filter(
        Bid.user_id == user_id,
        Bid.product_id == product_id,
        Bid.timestamp >= day_start
    ).first()
    if already_bid_today:
        return None
    daily_product_count = db.session.query(Bid.product_id).filter(
        Bid.user_id == user_id,
        Bid.timestamp >= day_start
    ).distinct().count()
    if daily_product_count >= DAILY_BID_PRODUCT_LIMIT:
        return "Günlük teklif hakkınız dolmuştur."
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
        limit_message = validate_daily_bid_product_limit(proxy_user.id, product.id)
        if limit_message:
            proxy.is_active = False
            create_notification(
                proxy_user.id,
                "Günlük teklif hakkınız doldu",
                f"{product.title} ilanına otomatik teklif verilemedi. Günlük teklif hakkınız dolmuştur.",
                "bid",
                product.id
            )
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

    limit_message = validate_daily_bid_product_limit(current_user.id, product.id)
    if limit_message:
        return jsonify({"success": False, "message": limit_message}), 400

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
    limit_message = validate_daily_bid_product_limit(current_user.id, product.id)
    if limit_message:
        return jsonify({"success": False, "message": limit_message}), 400

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
    if current_user.id not in {product.owner_id, product.matched_user_id} and not is_admin_user():
        return jsonify({"success": False, "message": "Bu satisi guncelleyemezsiniz."}), 403

    data = request.json or {}
    progress = get_sale_progress(product.id)
    allowed_fields = set()
    if is_admin_user():
        allowed_fields = {'contact_made', 'delivered', 'paid', 'buyer_received_confirmed', 'seller_payment_confirmed'}
    elif current_user.id == product.owner_id:
        allowed_fields = {'contact_made', 'seller_payment_confirmed'}
    elif current_user.id == product.matched_user_id:
        allowed_fields = {'buyer_received_confirmed'}

    for field in allowed_fields:
        if field in data:
            setattr(progress, field, bool(data.get(field)))
    progress.delivered = bool(progress.delivered or progress.buyer_received_confirmed)
    progress.paid = bool(progress.paid or progress.seller_payment_confirmed)
    intent = PaymentIntent.query.filter_by(product_id=product.id).first()
    if intent:
        if progress.buyer_received_confirmed and intent.status in {'pending', 'paid', 'escrow'}:
            intent.status = 'ready_for_payout'
            payout = SellerPayout.query.filter_by(payment_intent_id=intent.id).first()
            if payout and payout.status == 'pending':
                payout.status = 'ready'
                payout.available_at = datetime.utcnow()
        if progress.seller_payment_confirmed:
            intent.status = 'paid_out'
            payout = SellerPayout.query.filter_by(payment_intent_id=intent.id).first()
            if payout:
                payout.status = 'paid'
                payout.paid_at = datetime.utcnow()
    if (is_admin_user() or current_user.id == product.owner_id) and data.get('shippingStatus') in {'hazirlaniyor', 'kargoda', 'teslim_edildi', 'iptal'}:
        progress.shipping_status = data.get('shippingStatus')
    if is_admin_user() or current_user.id == product.owner_id:
        if 'shippingCarrier' in data:
            progress.shipping_carrier = repair_turkish_mojibake(str(data.get('shippingCarrier') or '').strip())[:60] or None
        if 'trackingCode' in data:
            progress.tracking_code = repair_turkish_mojibake(str(data.get('trackingCode') or '').strip())[:120] or None
    create_notification(
        product.matched_user_id if current_user.id == product.owner_id else product.owner_id,
        "Satis takibi guncellendi",
        f"{product.title} satis adimlari guncellendi.",
        "sale",
        product.id
    )
    db.session.commit()
    return jsonify({"success": True, "sale_progress": serialize_sale_progress(product.id)})

@app.route('/api/payout/request', methods=['POST'])
@login_required
def request_seller_payout():
    if not current_user.payout_iban:
        return jsonify({"success": False, "message": "Para çekme talebi için profilinizde IBAN kayıtlı olmalıdır."}), 400
    payouts = SellerPayout.query.filter_by(seller_id=current_user.id, status='ready').all()
    if not payouts:
        return jsonify({"success": False, "message": "Aktarılabilir ödeme bulunamadı."}), 400
    total = sum(payout.amount or 0 for payout in payouts)
    for payout in payouts:
        payout.status = 'requested'
    admin_users = [user for user in User.query.filter_by(role='admin').all() if is_admin_user(user)]
    for admin in admin_users:
        create_unique_unread_notification(
            admin.id,
            "Satıcı ödeme talebi",
            f"{current_user.name}, {total} TL ödeme aktarımı talep etti.",
            "admin"
        )
    db.session.commit()
    return jsonify({"success": True, "requestedAmount": total})

@app.route('/api/sale_issue/<int:product_id>', methods=['POST'])
@login_required
def open_sale_issue(product_id):
    product = Product.query.get(product_id)
    if not product or product.status != 'completed':
        return jsonify({"success": False, "message": "Tamamlanmış satış bulunamadı."}), 404
    if current_user.id not in {product.owner_id, product.matched_user_id}:
        return jsonify({"success": False, "message": "Bu satış için sorun bildiremezsiniz."}), 403

    data = request.json or {}
    reason = repair_turkish_mojibake(str(data.get('reason', '')).strip())
    if len(reason) < 5:
        return jsonify({"success": False, "message": "Sorunu kısaca yazmalısınız."}), 400
    existing = Report.query.filter_by(
        reporter_id=current_user.id,
        product_id=product.id,
        target_type='sale'
    ).filter(Report.status.in_(['open', 'reviewing'])).first()
    if existing:
        return jsonify({"success": False, "message": "Bu satış için açık bir sorun bildiriminiz zaten var."}), 400

    report = Report(
        reporter_id=current_user.id,
        product_id=product.id,
        target_type='sale',
        reason=f"[SALE:{product.id}] {reason[:450]}"
    )
    db.session.add(report)
    other_user_id = product.owner_id if current_user.id == product.matched_user_id else product.matched_user_id
    if other_user_id:
        create_notification(
            other_user_id,
            "Satış sorunu bildirildi",
            f"{product.title} satışı için sorun bildirildi. Admin inceleyecek.",
            "warning",
            product.id
        )
    log_admin_action("Satış sorunu açıldı", "report", None, product.title)
    db.session.commit()
    return jsonify({"success": True, "sale_progress": serialize_sale_progress(product.id)})

@app.route('/api/shipping_label/<int:product_id>', methods=['GET'])
@login_required
def get_shipping_label(product_id):
    product = Product.query.get(product_id)
    if not product or product.status != 'completed':
        return jsonify({"success": False, "message": "Kargo etiketi için tamamlanmış satış gerekir."}), 404
    if current_user.id not in {product.owner_id, product.matched_user_id} and not can_access_admin_panel():
        return jsonify({"success": False, "message": "Yetkisiz işlem."}), 403
    intent = serialize_payment_intent(product.id) or {}
    return jsonify({
        "success": True,
        "label": {
            "productTitle": repair_turkish_mojibake(product.title),
            "carrier": intent.get("shippingCarrier") or "",
            "desi": intent.get("shippingDesi"),
            "buyer": build_sale_buyer_info(product),
            "seller": build_sale_seller_info(product),
            "note": "Anlaşmalı kargo API bağlanınca barkod ve etiket burada otomatik üretilecek."
        }
    })

@app.route('/api/payments/create/<int:product_id>', methods=['POST'])
@login_required
def create_payment(product_id):
    product = Product.query.get(product_id)
    if not product or product.status != 'completed':
        return jsonify({"success": False, "message": "Ödeme için tamamlanmış satış gerekir."}), 404
    if product.matched_user_id != current_user.id:
        return jsonify({"success": False, "message": "Bu ödeme sadece alıcı tarafından başlatılabilir."}), 403
    intent = get_or_create_payment_intent(product)
    if not intent:
        return jsonify({"success": False, "message": "Ödeme kaydı oluşturulamadı."}), 400
    merchant_oid = ensure_payment_provider_reference(intent)
    if intent.status in {'paid', 'escrow', 'ready_for_payout', 'paid_out'}:
        db.session.commit()
        return jsonify({"success": True, "alreadyPaid": True, "paymentIntent": serialize_payment_intent(product.id)})

    if not is_paytr_configured():
        intent.status = 'pending'
        db.session.commit()
        return jsonify({
            "success": True,
            "mockMode": True,
            "message": "PayTR anahtarları tanımlı değil. Test ödeme modu açık.",
            "paymentIntent": serialize_payment_intent(product.id)
        })

    base_url = get_public_base_url()
    user_basket = base64.b64encode(json.dumps([[product.title, f"{intent.buyer_total:.2f}", 1]], ensure_ascii=False).encode('utf-8')).decode('utf-8')
    payment_amount = str(intent.paytr_amount_kurus)
    merchant_id = os.environ.get('PAYTR_MERCHANT_ID')
    merchant_key = os.environ.get('PAYTR_MERCHANT_KEY', '').encode('utf-8')
    merchant_salt = os.environ.get('PAYTR_MERCHANT_SALT', '')
    user_ip = get_client_ip()
    email = current_user.email[:100]
    no_installment = os.environ.get('PAYTR_NO_INSTALLMENT', '0')
    max_installment = os.environ.get('PAYTR_MAX_INSTALLMENT', '0')
    currency = 'TL'
    test_mode = os.environ.get('PAYTR_TEST_MODE', '1')
    hash_str = f"{merchant_id}{user_ip}{merchant_oid}{email}{payment_amount}{user_basket}{no_installment}{max_installment}{currency}{test_mode}"
    paytr_token = base64.b64encode(hmac.new(merchant_key, (hash_str + merchant_salt).encode('utf-8'), hashlib.sha256).digest()).decode('utf-8')
    form = {
        "merchant_id": merchant_id,
        "user_ip": user_ip,
        "merchant_oid": merchant_oid,
        "email": email,
        "payment_amount": payment_amount,
        "paytr_token": paytr_token,
        "user_basket": user_basket,
        "debug_on": os.environ.get('PAYTR_DEBUG_ON', '1'),
        "no_installment": no_installment,
        "max_installment": max_installment,
        "user_name": current_user.name[:60],
        "user_address": (current_user.address_detail or current_user.city or "Adres")[:400],
        "user_phone": (current_user.phone or "05000000000")[:20],
        "merchant_ok_url": f"{base_url}/payment/success/{product.id}",
        "merchant_fail_url": f"{base_url}/payment/fail/{product.id}",
        "timeout_limit": os.environ.get('PAYTR_TIMEOUT_LIMIT', '30'),
        "currency": currency,
        "test_mode": test_mode,
        "lang": "tr"
    }
    try:
        request_obj = Request(
            "https://www.paytr.com/odeme/api/get-token",
            data=urlencode(form).encode('utf-8'),
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        with urlopen(request_obj, timeout=20) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except Exception as exc:
        log_payment_error('paytr_token', str(exc), {"product_id": product.id, "intent_id": intent.id})
        db.session.commit()
        return jsonify({"success": False, "message": f"PayTR bağlantısı kurulamadı: {exc}"}), 502
    if payload.get('status') != 'success':
        log_payment_error('paytr_token', payload.get('reason') or "PayTR token alınamadı.", payload)
        db.session.commit()
        return jsonify({"success": False, "message": payload.get('reason') or "PayTR token alınamadı.", "paytr": payload}), 400
    intent.status = 'pending'
    db.session.commit()
    return jsonify({
        "success": True,
        "mockMode": False,
        "token": payload.get('token'),
        "paymentUrl": f"https://www.paytr.com/odeme/guvenli/{payload.get('token')}",
        "paymentIntent": serialize_payment_intent(product.id)
    })

@app.route('/api/payments/status/<int:product_id>', methods=['GET'])
@login_required
def payment_status(product_id):
    product = Product.query.get(product_id)
    if not product or current_user.id not in {product.owner_id, product.matched_user_id} and not can_access_admin_panel():
        return jsonify({"success": False, "message": "Ödeme kaydı bulunamadı."}), 404
    return jsonify({
        "success": True,
        "productStatus": product.status,
        "paymentIntent": serialize_payment_intent(product.id),
        "saleProgress": serialize_sale_progress(product.id) if product.status == 'completed' else None,
        "unreadNotifications": Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    })

@app.route('/api/payments/mock_complete/<int:product_id>', methods=['POST'])
@login_required
def mock_complete_payment(product_id):
    if is_paytr_configured():
        return jsonify({"success": False, "message": "PayTR canlı ayarlıyken mock ödeme kapalıdır."}), 403
    product = Product.query.get(product_id)
    if not product or product.status != 'completed' or product.matched_user_id != current_user.id:
        return jsonify({"success": False, "message": "Test ödeme için geçerli satış bulunamadı."}), 404
    intent = get_or_create_payment_intent(product)
    ensure_payment_provider_reference(intent)
    changed = mark_payment_success(intent, intent.paytr_amount_kurus, {"mock": True, "merchant_oid": intent.provider_reference})
    db.session.commit()
    return jsonify({"success": True, "changed": changed, "paymentIntent": serialize_payment_intent(product.id)})

@app.route('/paytr/callback', methods=['POST'])
def paytr_callback():
    post = request.form.to_dict() or (request.json or {})
    merchant_oid = str(post.get('merchant_oid') or '')
    status = str(post.get('status') or '')
    total_amount = str(post.get('total_amount') or '')
    callback_hash = str(post.get('hash') or '')
    if not merchant_oid or not status or not total_amount:
        return "PAYTR notification failed: missing fields", 400
    if is_paytr_configured():
        expected_hash = build_paytr_callback_hash(merchant_oid, status, total_amount)
        if not hmac.compare_digest(expected_hash, callback_hash):
            log_payment_error('paytr_callback', 'bad hash', post)
            db.session.commit()
            return "PAYTR notification failed: bad hash", 400
    intent = PaymentIntent.query.filter_by(provider_reference=merchant_oid).first()
    if not intent:
        return "OK"
    if intent.status in {'escrow', 'ready_for_payout', 'paid_out'}:
        return "OK"
    if status == 'success':
        mark_payment_success(intent, total_amount, post)
    else:
        mark_payment_failed(intent, post)
    db.session.commit()
    return "OK"

@app.route('/payment/success/<int:product_id>')
def payment_success_page(product_id):
    return redirect(url_for('index', ilan=product_id, payment='success'))

@app.route('/payment/fail/<int:product_id>')
def payment_fail_page(product_id):
    return redirect(url_for('index', ilan=product_id, payment='failed'))

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
    return jsonify({"success": False, "message": "İlan sohbeti kapalı."}), 410

@app.route('/api/product_messages', methods=['POST'])
@login_required
def add_product_message():
    return jsonify({"success": False, "message": "İlan sohbeti kapalı."}), 410

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

@app.route('/api/notifications', methods=['DELETE'])
@login_required
def delete_notifications():
    deleted = Notification.query.filter(
        Notification.user_id == current_user.id,
        Notification.notification_type != 'private_message'
    ).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({"success": True, "deleted": deleted})

@app.route('/api/notifications/<int:notification_id>', methods=['DELETE'])
@login_required
def delete_notification(notification_id):
    notification = Notification.query.filter_by(
        id=notification_id,
        user_id=current_user.id
    ).first()
    if not notification or notification.notification_type == 'private_message':
        return jsonify({"success": False, "message": "Bildirim bulunamadı."}), 404

    db.session.delete(notification)
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
        "address_detail": repair_turkish_mojibake(current_user.address_detail or ""),
        "address_privacy": current_user.address_privacy or "after_sale",
        "availability": repair_turkish_mojibake(current_user.availability_text or ""),
        "payout_iban": repair_turkish_mojibake(current_user.payout_iban or ""),
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
        "reviews": get_user_reviews(current_user.id, 10),
        "wallet": get_user_wallet_summary(current_user.id),
        "payments": get_user_payment_rows(current_user.id, 10),
        "soldProducts": [serialize_profile_product(product) for product in sorted(completed_products, key=lambda item: item.created_at or datetime.min, reverse=True)],
        "boughtProducts": [serialize_profile_product(product) for product in sorted(won_products, key=lambda item: item.created_at or datetime.min, reverse=True)],
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
        Product.status.in_(['pending_bidder_action', 'seller_info_confirmation', 'completed', 'cancelled'])
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
            "saleProgress": serialize_sale_progress(product.id) if product.status == 'completed' else None,
            "paymentIntent": serialize_payment_intent(product.id) if product.status == 'completed' else None
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

@app.route('/api/profile/settings', methods=['POST'])
@login_required
def update_profile_settings():
    data = request.json or {}
    address_privacy = str(data.get('addressPrivacy') or '').strip()
    availability = repair_turkish_mojibake(str(data.get('availability') or '').strip())
    payout_iban = re.sub(r'\s+', '', repair_turkish_mojibake(str(data.get('payoutIban') or '').strip())).upper()
    if address_privacy not in {'after_sale', 'admin_only'}:
        return jsonify({"success": False, "message": "Adres gizlilik seçimi geçersiz."}), 400
    if payout_iban and (not payout_iban.startswith('TR') or len(payout_iban) != 26):
        return jsonify({"success": False, "message": "IBAN TR ile başlamalı ve 26 karakter olmalıdır."}), 400
    current_user.address_privacy = address_privacy
    current_user.availability_text = availability[:200] or None
    current_user.payout_iban = payout_iban or None
    db.session.commit()
    return jsonify({"success": True, "message": "Ayarlar kaydedildi."})

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
        "availability": repair_turkish_mojibake(user.availability_text or ""),
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
        } for product in active_products[:8]],
        "reviews": get_user_reviews(user.id, 8)
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
        "İhaleyi kazandınız",
        f"{product.title} ilanındaki teklifiniz satıcı tarafından kabul edildi. Devam etmek için onayınız bekleniyor.",
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
            get_or_create_payment_intent(product)
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
            "Alıcı adres paylaşımını onayladı",
            f"{product.title} ilanında alıcı devam etmeyi ve adres bilgilerinin paylaşılmasını onayladı.",
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
        is_current_admin=can_access_admin_panel(),
        site_settings=settings,
        paytr_configured=is_paytr_configured(),
        shipping_carriers=SHIPPING_CARRIERS,
        shipping_tracking_urls=SHIPPING_TRACKING_URLS,
        category_data=get_category_menu(),
        maintenance_mode=settings["maintenance_mode"] and not can_access_admin_panel(),
        active_announcement=active_announcement
    )

@app.route('/admin')
@login_required
def admin_panel():
    if not can_access_admin_panel():
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
        "featured_requests": FeaturedRequest.query.filter_by(status='pending').count(),
        "active_products": Product.query.filter_by(status='active').count(),
        "completed_products": Product.query.filter_by(status='completed').count(),
        "tracked_orders": Product.query.filter(
            Product.matched_user_id.isnot(None),
            Product.status.in_(['pending_bidder_action', 'seller_info_confirmation', 'completed', 'cancelled'])
        ).count(),
        "chat_messages": ChatMessage.query.count()
    }
    finance_summary = get_finance_summary()
    
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
            "neighborhood": u.neighborhood,
            "address_detail": u.address_detail,
            "address_privacy": u.address_privacy,
            "availability": repair_turkish_mojibake(u.availability_text or ""),
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

    shipping_labels = {
        "hazirlaniyor": "Hazırlanıyor",
        "kargoda": "Kargoda",
        "teslim_edildi": "Teslim edildi",
        "iptal": "İptal"
    }
    admin_orders = []
    order_products = Product.query.filter(
        Product.matched_user_id.isnot(None),
        Product.status.in_(['pending_bidder_action', 'seller_info_confirmation', 'completed', 'cancelled'])
    ).order_by(Product.created_at.desc()).limit(80).all()
    for product in order_products:
        buyer = User.query.get(product.matched_user_id) if product.matched_user_id else None
        progress = serialize_sale_progress(product.id)
        admin_orders.append({
            "id": product.id,
            "title": repair_turkish_mojibake(product.title),
            "seller_name": repair_turkish_mojibake(product.owner_name),
            "buyer_name": buyer.name if buyer else "Silinmiş kullanıcı",
            "amount": product.current_bid,
            "status": product.status,
            "status_label": get_product_status_label(product.status),
            "shipping_status": progress["shipping_status"],
            "shipping_label": shipping_labels.get(progress["shipping_status"], "Hazırlanıyor"),
            "shipping_carrier": progress["shipping_carrier"],
            "tracking_code": progress["tracking_code"],
            "progress": progress,
            "payment_intent": serialize_payment_intent(product.id),
            "created_at": product.created_at.strftime('%Y-%m-%d %H:%M'),
            "image": product.image_url
        })

    recent_payments = []
    for intent in PaymentIntent.query.order_by(PaymentIntent.created_at.desc()).limit(30).all():
        product = Product.query.get(intent.product_id)
        buyer = User.query.get(intent.buyer_id)
        seller = User.query.get(intent.seller_id)
        recent_payments.append({
            "id": intent.id,
            "product_id": intent.product_id,
            "product_title": repair_turkish_mojibake(product.title) if product else "Silinmiş ilan",
            "buyer_name": buyer.name if buyer else "Silinmiş alıcı",
            "seller_name": seller.name if seller else "Silinmiş satıcı",
            "status": intent.status,
            "status_label": serialize_payment_intent(intent.product_id)["statusLabel"],
            "buyer_total": intent.buyer_total,
            "seller_payout": intent.seller_payout_amount,
            "platform_fee": intent.platform_total_fee,
            "created_at": intent.created_at.strftime('%Y-%m-%d %H:%M')
        })
    payment_transactions = []
    for transaction in PaymentTransaction.query.order_by(PaymentTransaction.created_at.desc()).limit(30).all():
        intent = PaymentIntent.query.get(transaction.payment_intent_id)
        product = Product.query.get(intent.product_id) if intent else None
        payment_transactions.append({
            "id": transaction.id,
            "product_title": repair_turkish_mojibake(product.title) if product else "Silinmiş ödeme",
            "type": transaction.transaction_type,
            "status": transaction.status,
            "amount": transaction.amount,
            "created_at": transaction.created_at.strftime('%Y-%m-%d %H:%M')
        })
    payout_requests = []
    for payout in SellerPayout.query.filter(SellerPayout.status.in_(['requested', 'ready'])).order_by(SellerPayout.created_at.desc()).limit(30).all():
        seller = User.query.get(payout.seller_id)
        intent = PaymentIntent.query.get(payout.payment_intent_id)
        product = Product.query.get(intent.product_id) if intent else None
        payout_requests.append({
            "id": payout.id,
            "seller_name": seller.name if seller else "Silinmiş satıcı",
            "seller_iban": repair_turkish_mojibake(seller.payout_iban or "") if seller else "",
            "product_title": repair_turkish_mojibake(product.title) if product else "Silinmiş ilan",
            "amount": payout.amount,
            "status": payout.status,
            "created_at": payout.created_at.strftime('%Y-%m-%d %H:%M')
        })
    payment_errors = [{
        "id": error.id,
        "source": error.source,
        "message": repair_turkish_mojibake(error.message),
        "created_at": error.created_at.strftime('%Y-%m-%d %H:%M')
    } for error in PaymentErrorLog.query.order_by(PaymentErrorLog.created_at.desc()).limit(20).all()]

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
    for request_row in FeaturedRequest.query.filter_by(status='pending').order_by(FeaturedRequest.created_at.desc()).limit(8).all():
        product = Product.query.get(request_row.product_id)
        user = User.query.get(request_row.user_id)
        admin_tasks.append({
            "type": "featured_request",
            "label": "Öne çıkarma",
            "title": repair_turkish_mojibake(product.title) if product else "Silinmiş ilan",
            "detail": f"{user.name if user else 'Silinmiş kullanıcı'} | {request_row.created_at.strftime('%Y-%m-%d %H:%M')}",
            "featured_request_id": request_row.id,
            "product_id": request_row.product_id,
            "severity": "indigo"
        })
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
            "admin_role": admin.role if admin else "system",
            "admin_id": admin.id if admin else None,
            "action": repair_turkish_mojibake(log.action),
            "target_type": log.target_type,
            "target_id": log.target_id,
            "detail": repair_turkish_mojibake(log.detail),
            "created_at": log.created_at.strftime('%Y-%m-%d %H:%M')
        })

    moderator_performance = []
    for moderator in User.query.filter_by(role='moderator').order_by(User.name.asc()).all():
        mod_logs = AdminLog.query.filter_by(admin_id=moderator.id).all()
        moderator_performance.append({
            "id": moderator.id,
            "name": moderator.name,
            "email": moderator.email,
            "total": len(mod_logs),
            "product": sum(1 for log in mod_logs if log.target_type == 'product'),
            "report": sum(1 for log in mod_logs if log.target_type == 'report'),
            "user": sum(1 for log in mod_logs if log.target_type == 'user'),
            "last_action": max((log.created_at for log in mod_logs), default=None).strftime('%Y-%m-%d %H:%M') if mod_logs else "Henüz işlem yok"
        })
    moderator_performance.sort(key=lambda item: item["total"], reverse=True)

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

    featured_requests = []
    for request_row in FeaturedRequest.query.order_by(FeaturedRequest.created_at.desc()).limit(50).all():
        product = Product.query.get(request_row.product_id)
        user = User.query.get(request_row.user_id)
        featured_requests.append({
            "id": request_row.id,
            "product_id": request_row.product_id,
            "product_title": repair_turkish_mojibake(product.title) if product else "Silinmiş ilan",
            "user_name": user.name if user else "Silinmiş kullanıcı",
            "status": request_row.status,
            "payment_status": request_row.payment_status or "pending",
            "payment_amount": request_row.payment_amount or 0,
            "status_label": {
                "pending": "Bekliyor",
                "approved": "Onaylandı",
                "rejected": "Reddedildi"
            }.get(request_row.status, request_row.status),
            "admin_response": repair_turkish_mojibake(request_row.admin_response),
            "created_at": request_row.created_at.strftime('%Y-%m-%d %H:%M')
        })

    return render_template(
        'admin.html',
        users=users_data,
        stats=stats,
        reports=reports_data,
        products=products_data,
        admin_orders=admin_orders,
        finance_summary=finance_summary,
        recent_payments=recent_payments,
        payment_transactions=payment_transactions,
        payout_requests=payout_requests,
        payment_errors=payment_errors,
        paytr_status={
            "configured": is_paytr_configured(),
            "test_mode": os.environ.get('PAYTR_TEST_MODE', '1'),
            "callback_url": f"{get_public_base_url()}/paytr/callback"
        },
        messages=messages_data,
        category_stats=category_stats,
        daily_stats=daily_stats,
        max_daily_count=max_daily_count,
        admin_tasks=admin_tasks,
        settings=get_site_settings(),
        announcements=announcements_data,
        appeals=appeals_data,
        logs=logs_data,
        moderator_performance=moderator_performance,
        featured_requests=featured_requests,
        category_menu=get_category_menu(),
        shipping_carriers=SHIPPING_CARRIERS,
        can_manage=can_moderate_content(),
        can_admin_settings=is_admin_user()
    )

@app.route('/admin/categories')
@login_required
def admin_categories_panel():
    if not is_admin_user():
        flash("Admin yetkiniz yok!")
        return redirect(url_for('index'))
    category_menu = get_category_menu()
    return render_template(
        'admin_categories.html',
        category_menu=category_menu,
        category_count=len(category_menu),
        item_count=sum(len(items) for items in category_menu.values())
    )

@app.route('/api/ban_user/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    if not can_moderate_content(): return jsonify({"success": False}), 403
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
    if not can_moderate_content(): return jsonify({"success": False}), 403
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
    if not can_access_admin_panel():
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

@app.route('/api/admin/users/<int:user_id>/role', methods=['POST'])
@login_required
def update_user_role(user_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Kullanıcı bulunamadı."}), 404
    if user.id == current_user.id:
        return jsonify({"success": False, "message": "Kendi yetkinizi buradan değiştiremezsiniz."}), 400

    role = str((request.json or {}).get('role') or '').strip()
    if role not in {'user', 'moderator'}:
        return jsonify({"success": False, "message": "Geçersiz rol."}), 400
    if user.role == 'admin':
        return jsonify({"success": False, "message": "Admin hesabı moderatör panelinden değiştirilemez."}), 400

    old_role = user.role
    user.role = role
    log_admin_action("Kullanıcı rolü değişti", "user", user.id, f"{old_role} -> {role}")
    db.session.commit()
    return jsonify({"success": True, "role": role})

@app.route('/api/delete_product/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({"success": False, "message": "İlan bulunamadı."}), 404

    if not can_moderate_content() and product.owner_id != current_user.id:
        return jsonify({"success": False, "message": "Sadece kendi ilanınızı silebilirsiniz."}), 403

    if can_moderate_content():
        log_admin_action("İlan silindi", "product", product.id, product.title)
    db.session.delete(product)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/delete_bid/<int:bid_id>', methods=['DELETE'])
@login_required
def delete_bid(bid_id):
    if not can_moderate_content(): return jsonify({"success": False}), 403
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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

@app.route('/api/admin/orders/<int:product_id>', methods=['POST'])
@login_required
def update_admin_order(product_id):
    if not can_moderate_content():
        return jsonify({"success": False}), 403
    product = Product.query.get(product_id)
    if not product or not product.matched_user_id:
        return jsonify({"success": False, "message": "Takip edilecek sipariş bulunamadı."}), 404

    data = request.json or {}
    allowed_statuses = {'pending_bidder_action', 'seller_info_confirmation', 'completed', 'cancelled'}
    if data.get('status') in allowed_statuses:
        product.status = data.get('status')

    progress = get_sale_progress(product.id)
    for field in ('contact_made', 'delivered', 'paid', 'buyer_received_confirmed', 'seller_payment_confirmed'):
        if field in data:
            setattr(progress, field, bool(data.get(field)))
    progress.delivered = bool(progress.delivered or progress.buyer_received_confirmed)
    progress.paid = bool(progress.paid or progress.seller_payment_confirmed)
    if data.get('shippingStatus') in {'hazirlaniyor', 'kargoda', 'teslim_edildi', 'iptal'}:
        progress.shipping_status = data.get('shippingStatus')
    if 'shippingCarrier' in data:
        progress.shipping_carrier = repair_turkish_mojibake(str(data.get('shippingCarrier') or '').strip())[:60] or None
    if 'trackingCode' in data:
        progress.tracking_code = repair_turkish_mojibake(str(data.get('trackingCode') or '').strip())[:120] or None

    for user_id in {product.owner_id, product.matched_user_id}:
        if user_id:
            create_unique_unread_notification(
                user_id,
                "Sipariş takibi güncellendi",
                f"{product.title} için sipariş/takip durumu admin tarafından güncellendi.",
                "sale",
                product.id
            )
    log_admin_action("Sipariş takibi güncellendi", "order", product.id, product.title)
    db.session.commit()
    return jsonify({"success": True, "sale_progress": serialize_sale_progress(product.id), "status": product.status})

@app.route('/api/admin/payouts/<int:payout_id>', methods=['POST'])
@login_required
def admin_update_payout(payout_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    payout = SellerPayout.query.get(payout_id)
    if not payout:
        return jsonify({"success": False, "message": "Ödeme talebi bulunamadı."}), 404
    data = request.json or {}
    action = data.get('action')
    intent = PaymentIntent.query.get(payout.payment_intent_id)
    if action == 'approve':
        payout.status = 'paid'
        payout.paid_at = datetime.utcnow()
        if intent:
            intent.status = 'paid_out'
            db.session.add(PaymentTransaction(payment_intent_id=intent.id, provider='manual', transaction_type='seller_payout', status='paid', amount=payout.amount, raw_payload=json.dumps({"admin_id": current_user.id}, ensure_ascii=False)))
        create_notification(payout.seller_id, "Ödeme aktarıldı", f"{payout.amount} TL satıcı ödemeniz aktarıldı olarak işaretlendi.", "payment")
        log_admin_action("Satıcı ödemesi onaylandı", "payout", payout.id, str(payout.amount))
    elif action == 'reject':
        payout.status = 'ready'
        create_notification(payout.seller_id, "Ödeme talebi reddedildi", "Satıcı ödeme talebiniz admin tarafından tekrar beklemeye alındı.", "payment")
        log_admin_action("Satıcı ödeme talebi reddedildi", "payout", payout.id, str(payout.amount))
    else:
        return jsonify({"success": False, "message": "Geçersiz işlem."}), 400
    db.session.commit()
    return jsonify({"success": True, "status": payout.status})

@app.route('/api/admin/sale_dispute/<int:report_id>', methods=['POST'])
@login_required
def admin_sale_dispute(report_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    report = Report.query.get(report_id)
    if not report or report.target_type != 'sale' or not report.product_id:
        return jsonify({"success": False, "message": "Satış itirazı bulunamadı."}), 404
    data = request.json or {}
    decision = data.get('decision')
    product = Product.query.get(report.product_id)
    intent = PaymentIntent.query.filter_by(product_id=report.product_id).first()
    if not product or not intent:
        return jsonify({"success": False, "message": "Ödeme kaydı bulunamadı."}), 404
    amount = intent.buyer_total
    if decision == 'refund':
        intent.status = 'refunded'
        tx_status = 'refund'
    elif decision == 'release':
        intent.status = 'ready_for_payout'
        tx_status = 'release'
    elif decision == 'partial_refund':
        try:
            amount = int(data.get('amount') or 0)
        except (TypeError, ValueError):
            amount = 0
        if amount <= 0 or amount >= intent.buyer_total:
            return jsonify({"success": False, "message": "Geçerli bir kısmi iade tutarı girin."}), 400
        intent.status = 'ready_for_payout'
        intent.seller_payout_amount = max(0, intent.seller_payout_amount - amount)
        tx_status = 'partial_refund'
    else:
        return jsonify({"success": False, "message": "Geçersiz karar."}), 400
    payout = SellerPayout.query.filter_by(payment_intent_id=intent.id).first()
    if payout and decision != 'refund':
        payout.amount = intent.seller_payout_amount
        payout.status = 'ready'
        payout.available_at = datetime.utcnow()
    if payout and decision == 'refund':
        payout.status = 'cancelled'
        payout.amount = 0
    db.session.add(PaymentTransaction(payment_intent_id=intent.id, provider='manual', transaction_type='dispute', status=tx_status, amount=amount, raw_payload=json.dumps({"report_id": report.id, "decision": decision, "admin_id": current_user.id}, ensure_ascii=False)))
    report.status = 'resolved'
    create_notification(intent.buyer_id, "Satış itirazı sonuçlandı", f"{product.title} itirazı için admin kararı: {tx_status}.", "payment", product.id)
    create_notification(intent.seller_id, "Satış itirazı sonuçlandı", f"{product.title} itirazı için admin kararı: {tx_status}.", "payment", product.id)
    log_admin_action("Satış itirazı sonuçlandı", "report", report.id, decision)
    db.session.commit()
    return jsonify({"success": True, "decision": decision, "paymentIntent": serialize_payment_intent(product.id)})

@app.route('/api/admin/featured_requests/<int:request_id>', methods=['POST'])
@login_required
def resolve_featured_request(request_id):
    if not is_admin_user():
        return jsonify({"success": False}), 403
    featured_request = FeaturedRequest.query.get(request_id)
    if not featured_request:
        return jsonify({"success": False, "message": "Öne çıkarma talebi bulunamadı."}), 404

    data = request.json or {}
    status = data.get('status')
    if status not in {'approved', 'rejected'}:
        return jsonify({"success": False, "message": "Geçersiz talep durumu."}), 400

    product = Product.query.get(featured_request.product_id)
    if status == 'approved':
        if not product:
            return jsonify({"success": False, "message": "İlan bulunamadı."}), 404
        featured = FeaturedProduct.query.filter_by(product_id=product.id).first()
        if not featured:
            featured = FeaturedProduct(product_id=product.id, is_active=True)
            db.session.add(featured)
        else:
            featured.is_active = True
        featured_request.status = 'approved'
        featured_request.payment_status = featured_request.payment_status or 'pending'
        featured_request.admin_response = repair_turkish_mojibake(str(data.get('message') or 'Öne çıkarma talebiniz onaylandı.').strip())[:300]
        create_notification(
            featured_request.user_id,
            "Öne çıkarma onaylandı",
            f"{product.title} ilanınız öne çıkarıldı.",
            "admin",
            product.id
        )
        log_admin_action("Öne çıkarma talebi onaylandı", "featured_request", featured_request.id, product.title)
    else:
        featured_request.status = 'rejected'
        featured_request.payment_status = 'cancelled'
        featured_request.admin_response = repair_turkish_mojibake(str(data.get('message') or 'Öne çıkarma talebiniz reddedildi.').strip())[:300]
        create_notification(
            featured_request.user_id,
            "Öne çıkarma reddedildi",
            f"{product.title if product else 'İlan'} için öne çıkarma talebiniz reddedildi.",
            "admin",
            product.id if product else None
        )
        log_admin_action("Öne çıkarma talebi reddedildi", "featured_request", featured_request.id, product.title if product else None)

    featured_request.resolved_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"success": True, "status": featured_request.status})

@app.route('/api/admin/send_notification', methods=['POST'])
@login_required
def admin_send_notification():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    data = request.json or {}
    title = repair_turkish_mojibake(str(data.get('title') or '').strip())[:120]
    message = repair_turkish_mojibake(str(data.get('message') or '').strip())[:300]
    target = data.get('target') or 'all'
    if not title or not message:
        return jsonify({"success": False, "message": "Başlık ve mesaj zorunlu."}), 400

    users_query = User.query
    if target == 'user':
        try:
            user_id = int(data.get('user_id'))
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "Geçerli bir kullanıcı seçin."}), 400
        users_query = users_query.filter_by(id=user_id)
    elif target == 'admins':
        users_query = users_query.filter_by(role='admin')
    elif target != 'all':
        return jsonify({"success": False, "message": "Geçersiz hedef."}), 400

    sent = 0
    for user in users_query.all():
        create_notification(user.id, title, message, "admin")
        sent += 1
    log_admin_action("Admin bildirimi gönderildi", "notification", None, f"{target}: {sent} kullanıcı")
    db.session.commit()
    return jsonify({"success": True, "sent": sent})

@app.route('/api/admin/profanity_terms', methods=['POST'])
@login_required
def update_admin_profanity_terms():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    data = request.json or {}
    terms_value = data.get('terms')
    if isinstance(terms_value, str):
        terms = re.split(r'[\n,]+', terms_value)
    elif isinstance(terms_value, list):
        terms = terms_value
    else:
        terms = []
    saved_terms = save_external_profanity_terms(terms)
    log_admin_action("Yasaklı kelimeler güncellendi", "settings", None, f"{len(saved_terms)} özel kelime")
    db.session.commit()
    return jsonify({"success": True, "terms": saved_terms, "count": len(saved_terms)})

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
        "max_images": (1, 5),
        "featured_price": (0, 1000000),
        "payment_service_fee_fixed": (0, 1000000),
        "payment_service_fee_percent": (0, 100),
        "platform_commission_percent": (0, 100),
        "buyer_auto_confirm_days": (1, 14)
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
    raw_shipping_rates = str(data.get("secure_shipping_rates") or '').strip()
    if raw_shipping_rates:
        try:
            json.loads(raw_shipping_rates)
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "Kargo desi fiyatları geçerli JSON olmalıdır."}), 400
    parsed_shipping_rates = parse_secure_shipping_rates(raw_shipping_rates)
    if not parsed_shipping_rates:
        return jsonify({"success": False, "message": "En az bir desi fiyatı girmelisiniz."}), 400
    update_site_setting("secure_shipping_carrier", repair_turkish_mojibake(str(data.get("secure_shipping_carrier") or '').strip())[:80] or DEFAULT_SITE_SETTINGS["secure_shipping_carrier"])
    update_site_setting("secure_shipping_rates", json.dumps(parsed_shipping_rates, ensure_ascii=False))
    for key, max_length in {
        "support_phone": 80,
        "support_email": 120,
        "support_instagram": 120,
        "kvkk_text": 5000,
        "sales_terms_text": 5000
    }.items():
        value = repair_turkish_mojibake(str(data.get(key) or '').strip())[:max_length]
        update_site_setting(key, value)
    log_admin_action("Site ayarları güncellendi", "settings", None, json.dumps(data, ensure_ascii=False))
    db.session.commit()
    return jsonify({"success": True})

@app.route('/api/admin/category_menu', methods=['POST'])
@login_required
def save_category_menu():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    data = request.json or {}
    raw_menu = data.get('menu_entries') if data.get('menu_entries') is not None else data.get('menu')
    menu = normalize_category_menu(raw_menu)
    if not menu:
        return jsonify({"success": False, "message": "En az bir kategori ve alt kategori girmelisiniz."}), 400
    update_site_setting("category_menu_json", json.dumps(menu, ensure_ascii=False))
    update_site_setting("category_menu_order_json", json.dumps(list(menu.keys()), ensure_ascii=False))
    log_admin_action("Kategori menüsü güncellendi", "settings", None, f"{len(menu)} kategori")
    db.session.commit()
    return jsonify({"success": True, "menu": get_category_menu()})

@app.route('/api/admin/category_menu/reset', methods=['POST'])
@login_required
def reset_category_menu():
    if not is_admin_user():
        return jsonify({"success": False}), 403
    setting = SiteSetting.query.get("category_menu_json")
    if setting:
        db.session.delete(setting)
    order_setting = SiteSetting.query.get("category_menu_order_json")
    if order_setting:
        db.session.delete(order_setting)
    log_admin_action("Kategori menüsü varsayılana alındı", "settings", None, None)
    db.session.commit()
    return jsonify({"success": True, "menu": get_default_category_menu()})

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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    if not can_moderate_content():
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
    existing_request = FeaturedRequest.query.filter_by(
        product_id=product.id,
        user_id=current_user.id,
        status='pending'
    ).first()
    if existing_request:
        return jsonify({"success": False, "message": "Bu ilan için bekleyen öne çıkarma talebiniz var."}), 400

    settings = get_site_settings()
    featured_amount = settings["featured_price"]
    db.session.add(FeaturedRequest(
        product_id=product.id,
        user_id=current_user.id,
        payment_status='pending',
        payment_amount=featured_amount,
        paytr_amount_kurus=featured_amount * 100
    ))

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
    if not can_moderate_content():
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
    if not can_moderate_content() and product.owner_id != current_user.id:
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
    if 'securePurchase' in data:
        extra = get_product_extra(product.id)
        secure_purchase = bool(data.get('securePurchase'))
        shipping_payer = str(data.get('shippingPayer') or (extra.shipping_payer if not secure_purchase else '') or 'buyer').strip()
        if shipping_payer not in {'buyer', 'seller'}:
            return jsonify({"success": False, "message": "Kargoyu kimin ödeyeceğini seçmelisiniz."}), 400
        try:
            shipping_desi = int(data.get('shippingDesi') or 0)
        except (TypeError, ValueError):
            shipping_desi = 0
        if secure_purchase and shipping_desi < 1:
            return jsonify({"success": False, "message": "Kargo desisini seçmelisiniz."}), 400
        extra.secure_purchase_enabled = secure_purchase
        extra.shipping_payer = shipping_payer
        extra.shipping_desi = shipping_desi if secure_purchase else None
    if 'images' in data:
        images = data.get('images')
        if not isinstance(images, list):
            return jsonify({"success": False, "message": "Fotoğraf listesi geçerli değil."}), 400
        settings = get_site_settings()
        images = [image for image in images if isinstance(image, str) and image.strip()]
        if not images:
            return jsonify({"success": False, "message": "İlanda en az 1 fotoğraf olmalıdır."}), 400
        if len(images) > settings["max_images"]:
            return jsonify({"success": False, "message": f"En fazla {settings['max_images']} fotoğraf ekleyebilirsiniz."}), 400
        saved_images = save_product_images(images)
        if not saved_images:
            return jsonify({"success": False, "message": "Fotoğraflar kaydedilemedi."}), 400
        product.image_url = saved_images[0]
        product.image_urls = json.dumps(saved_images, ensure_ascii=False)
    if can_moderate_content():
        log_admin_action("İlan düzenlendi", "product", product.id, product.title)
    db.session.commit()
    return jsonify({"success": True, "images": get_product_images(product)})

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
    comment = repair_turkish_mojibake(str(data.get('comment', '')).strip())[:300]
    if existing:
        existing.score = score
        existing.comment = comment
    else:
        db.session.add(Rating(product_id=product.id, rater_id=current_user.id, rated_user_id=rated_user_id, score=score, comment=comment))
    create_unique_unread_notification(
        rated_user_id,
        "Yeni yorum aldınız",
        f"{current_user.name}, {product.title} işlemi için {score} yıldız verdi.",
        "rating",
        product.id
    )
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
    filename = f"verteklifi-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
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
    city = str(data.get('city', '')).strip()
    district = str(data.get('district', '')).strip()
    neighborhood = str(data.get('neighborhood', '')).strip()
    address_detail = str(data.get('addressDetail', '')).strip()

    if not data.get('kvkkAccepted'):
        return jsonify({"success": False, "message": "KVKK aydınlatma metnini onaylamalısınız."}), 400
    if not data.get('salesTermsAccepted'):
        return jsonify({"success": False, "message": "Satış ve ödeme şartlarını onaylamalısınız."}), 400

    # E-posta format kontrolü
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"success": False, "message": "Geçersiz e-posta formatı"}), 400
    
    # Telefon format kontrolü (basit)
    if not re.match(r"^05[0-9]{9}$", phone):
        return jsonify({"success": False, "message": "Geçersiz telefon formatı (05xxxxxxxxx)"}), 400

    if not city or not district or not neighborhood:
        return jsonify({"success": False, "message": "İl, ilçe ve mahalle seçmelisiniz."}), 400

    if len(address_detail) < 10:
        return jsonify({"success": False, "message": "Sokak, bina, daire gibi detay adresi yazmalısınız."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "message": "Bu e-posta zaten kayıtlı"}), 400

    if User.query.filter_by(phone=phone).first():
        return jsonify({"success": False, "message": "Bu telefon zaten kayitli"}), 400

    new_user = User(
        email=email,
        name=str(data.get('name', '')).strip(),
        password=generate_password_hash(data.get('password'), method='pbkdf2:sha256'),
        phone=phone,
        city=city[:100],
        district=district[:100],
        neighborhood=neighborhood[:100],
        address_detail=address_detail[:300]
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
    secure_purchase = bool(data.get('securePurchase'))
    shipping_payer = str(data.get('shippingPayer') or ('' if secure_purchase else 'buyer')).strip()
    try:
        shipping_desi = int(data.get('shippingDesi') or 0)
    except (TypeError, ValueError):
        shipping_desi = 0
    imgs = data.get('images', [])

    if not title or title.endswith('|'):
        return jsonify({"success": False, "message": "Ürün başlığı zorunludur."}), 400

    if not isinstance(imgs, list) or len(imgs) == 0:
        return jsonify({"success": False, "message": "En az bir fotoğraf eklemelisiniz."}), 400
    if len(imgs) > settings["max_images"]:
        return jsonify({"success": False, "message": f"En fazla {settings['max_images']} fotoğraf ekleyebilirsiniz."}), 400

    if condition not in allowed_conditions:
        return jsonify({"success": False, "message": "Ürün durumunu seçmelisiniz."}), 400
    if shipping_payer not in {'buyer', 'seller'}:
        return jsonify({"success": False, "message": "Kargoyu kimin ödeyeceğini seçmelisiniz."}), 400
    if secure_purchase and shipping_desi < 1:
        return jsonify({"success": False, "message": "Kargo desisini seçmelisiniz."}), 400

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
    extra.secure_purchase_enabled = secure_purchase
    extra.shipping_payer = shipping_payer
    extra.shipping_desi = shipping_desi if secure_purchase else None
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
        ensure_optional_database_columns()
        ensure_configured_admin()
    app.run(debug=True)
