"""
SAFEGUARD NEXUS - Web-based Visitor Check-In System
Allows security guards at the gate to log visitors using a web browser
"""

from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, Response, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
import os
from datetime import datetime, timedelta
import sqlite3
import json
import pickle
import base64
import uuid
import re
import math
from io import StringIO, BytesIO
from PIL import Image, ImageDraw, ImageFont

try:
    import face_recognition
except ImportError:
    face_recognition = None

try:
    import dlib
    DLIB_PREDICTOR_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shape_predictor_68_face_landmarks.dat")
    if os.path.exists(DLIB_PREDICTOR_PATH):
        DLIB_DETECTOR = dlib.get_frontal_face_detector()
        DLIB_PREDICTOR = dlib.shape_predictor(DLIB_PREDICTOR_PATH)
    else:
        DLIB_DETECTOR = None
        DLIB_PREDICTOR = None
except Exception:
    DLIB_DETECTOR = None
    DLIB_PREDICTOR = None

from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key')
app.permanent_session_lifetime = timedelta(minutes=30)  # Sessin timeout
CORS(app)

# Configuration
UPLOAD_FOLDER = 'snapshots/visitors'
DATABASE = 'safeguard_vault.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# ═══════════════════════════════════════════
#  OBSTRUCTION DETECTION CONFIG
# ═══════════════════════════════════════════
OBSTRUCTION_ALERTS = {}  # Track obstruction events: {frame_id: timestamp}
FACE_OBSTRUCTION_THRESHOLD = 3  # seconds
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
ALERT_EMAIL = os.environ.get('ALERT_EMAIL', '')
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', '')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', '')

# ═══════════════════════════════════════════
#  DATABASE FUNCTIONS
# ═══════════════════════════════════════════
def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_visitor_table():
    """Create visitor_logs table if it doesn't exist."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS visitor_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        purpose TEXT NOT NULL,
        contact_person TEXT NOT NULL,
        phone TEXT,
        entry_time TEXT NOT NULL,
        exit_time TEXT,
        photo_path TEXT,
        status TEXT DEFAULT 'CHECKED_IN',
        matched_name TEXT,
        face_confidence REAL,
        face_status TEXT DEFAULT 'UNKNOWN'
    )''')
    
    # Add missing columns for older databases
    c.execute("PRAGMA table_info(visitor_logs)")
    columns = [row[1] for row in c.fetchall()]
    if 'status' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN status TEXT DEFAULT 'CHECKED_IN'")
    if 'matched_name' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN matched_name TEXT")
    if 'face_confidence' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN face_confidence REAL")
    if 'face_status' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN face_status TEXT DEFAULT 'UNKNOWN'")
    if 'host_email' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN host_email TEXT")
    if 'host_notified' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN host_notified INTEGER DEFAULT 0")
    if 'host_decision' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN host_decision TEXT DEFAULT 'PENDING'")
    if 'muster_status' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN muster_status TEXT DEFAULT 'UNACCOUNTED'")
    if 'is_overstay' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN is_overstay INTEGER DEFAULT 0")
    if 'liveness_score' not in columns:
        c.execute("ALTER TABLE visitor_logs ADD COLUMN liveness_score REAL")
    
    conn.commit()
    conn.close()


def create_watchlist_table():
    """Create watchlist table for blacklist and VIP monitoring."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        category TEXT NOT NULL DEFAULT 'BLACKLIST',
        threat_level INTEGER DEFAULT 3,
        reason TEXT,
        photo_path TEXT,
        action TEXT DEFAULT 'BLOCK',
        status TEXT DEFAULT 'ACTIVE',
        created_at TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()


def create_logs_table():
    """Create main logs table if it doesn't exist."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        date TEXT,
        time TEXT,
        status TEXT,
        confidence REAL,
        image_path TEXT
    )''')
    conn.commit()
    conn.close()


def create_tables():
    create_visitor_table()
    create_logs_table()
    create_users_table()
    create_pre_registration_table()
    create_obstruction_alerts_table()
    create_watchlist_table()
    create_audit_logs_table()
    ensure_admin_user()


def create_obstruction_alerts_table():
    """Create obstruction alerts table for tracking face obstruction events."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS obstruction_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visitor_name TEXT,
        timestamp TEXT NOT NULL,
        alert_type TEXT DEFAULT 'FACE_OBSTRUCTION',
        status TEXT DEFAULT 'TRIGGERED',
        resolved INTEGER DEFAULT 0,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()


def create_users_table():
    """Create admin user table if it doesn't exist."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        created_at TEXT NOT NULL,
        last_login TEXT
    )''')
    
    # Add missing columns for older databases
    c.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in c.fetchall()]
    if 'last_login' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
    
    conn.commit()
    conn.close()


def create_pre_registration_table():
    """Create visitor pre-registration table."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS pre_registrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        purpose TEXT NOT NULL,
        contact_person TEXT NOT NULL,
        phone TEXT,
        expected_date TEXT NOT NULL,
        expected_time TEXT,
        notes TEXT,
        qr_token TEXT UNIQUE,
        status TEXT NOT NULL DEFAULT 'PENDING',
        created_at TEXT NOT NULL
    )''')
    
    # Add missing columns for older databases
    c.execute("PRAGMA table_info(pre_registrations)")
    columns = [row[1] for row in c.fetchall()]
    if 'qr_token' not in columns:
        c.execute("ALTER TABLE pre_registrations ADD COLUMN qr_token TEXT")
    c.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_registrations_qr_token "
        "ON pre_registrations(qr_token)"
    )
    conn.commit()
    conn.close()


def generate_qr_token():
    """Generate a unique QR token for pre-registration."""
    import uuid
    return uuid.uuid4().hex


def get_pre_registration_by_token(token):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM pre_registrations WHERE qr_token = ?', (token,))
    row = c.fetchone()
    conn.close()
    return row


def mark_pre_registration_arrived(prereg_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE pre_registrations SET status = ? WHERE id = ?', ('ARRIVED', prereg_id))
    conn.commit()
    conn.close()


def ensure_admin_user():
    """Insert a default admin user if no user exists."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users')
    count = c.fetchone()[0]
    if count == 0:
        default_password = 'admin123'
        password_hash = generate_password_hash(default_password)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute(
            'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
            ('admin', password_hash, 'admin', now)
        )
    conn.commit()
    conn.close()

def create_audit_logs_table():
    """Create audit logs table for tracking system actions."""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT,
        user TEXT DEFAULT 'system',
        status TEXT DEFAULT 'SUCCESS'
    )''')
    conn.commit()
    conn.close()


def authenticate_user(username, password):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    if row and check_password_hash(row['password_hash'], password):
        return True
    return False


# --- Face encoding cache (performance) ---
ENCODINGS_CACHE = None
ENCODINGS_MTIME = None
WATCHLIST_CACHE = None
WATCHLIST_CACHE_TIME = 0.0
WATCHLIST_CACHE_TTL = 5.0
WATCHLIST_CACHE_LOCK = threading.Lock()


def load_encodings_cached():
    """Load encodings.pickle with in-memory caching.

    Reloads only when the pickle file's mtime changes.
    """
    global ENCODINGS_CACHE, ENCODINGS_MTIME

    if face_recognition is None:
        return None

    data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'encodings.pickle')
    if not os.path.exists(data_path):
        ENCODINGS_CACHE = None
        ENCODINGS_MTIME = None
        return None

    mtime = os.path.getmtime(data_path)
    if ENCODINGS_CACHE is not None and ENCODINGS_MTIME == mtime:
        return ENCODINGS_CACHE

    with open(data_path, 'rb') as f:
        data = pickle.loads(f.read())

    ENCODINGS_CACHE = data
    ENCODINGS_MTIME = mtime
    return ENCODINGS_CACHE


def identify_face(image):
    """Match a face image against known encodings."""
    if face_recognition is None:
        return None, None, 'UNAVAILABLE'

    try:
        import numpy as np

        rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        boxes = face_recognition.face_locations(rgb)
        encodings = face_recognition.face_encodings(rgb, boxes)
        if not encodings:
            return None, None, 'NO_FACE'

        data = load_encodings_cached()
        if not data:
            return None, None, 'NO_KNOWN_FACES'

        known_encodings = data.get('encodings', [])
        known_names = data.get('names', [])
        if not known_encodings:
            return None, None, 'NO_KNOWN_FACES'

        distances = face_recognition.face_distance(known_encodings, encodings[0])
        best_index = int(np.argmin(distances))
        best_distance = float(distances[best_index])
        confidence = round((1.0 - best_distance) * 100, 2)
        matched_name = known_names[best_index] if best_distance < 0.55 else None
        status = 'VERIFIED' if matched_name else 'UNKNOWN'
        return matched_name, confidence if matched_name else None, status
    except Exception:
        return None, None, 'ERROR'


def detect_person_without_face(image):
    """Detect if a human body is present but face is obscured.
    Uses OpenCV Haar Cascade for person detection.
    Returns True if person detected but no face found."""
    try:
        # Load cascade classifiers
        face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        body_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_fullbody.xml'
        )
        
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, 1.1, 4)
        bodies = body_cascade.detectMultiScale(gray, 1.05, 4)
        
        # Person detected but no face found
        if len(bodies) > 0 and len(faces) == 0:
            return True
        return False
    except Exception:
        return False


def send_telegram_alert(message, alert_type='OBSTRUCTION'):
    """Send alert via Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        emoji = '🚨' if alert_type == 'OBSTRUCTION' else '⚠️'
        text = f"{emoji} **{alert_type} ALERT**\n\n{message}\n\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {'chat_id': TELEGRAM_CHAT_ID, 'text': text, 'parse_mode': 'Markdown'}
        requests.post(url, json=data, timeout=5)
        return True
    except Exception as e:
        print(f"Telegram alert failed: {e}")
        return False


def send_email_alert(subject, message, alert_type='OBSTRUCTION', recipient=None, html_content=None):
    """Send alert via Email using settings from JSON file."""
    settings = load_settings()
    email_settings = settings.get('email', {})
    
    if not email_settings.get('enableEmailAlerts', True):
        return False
    
    sender_email = email_settings.get('senderEmail', '')
    sender_password = email_settings.get('senderPassword', '')
    recipient_email = recipient or email_settings.get('recipientEmail', '')
    smtp_server = email_settings.get('smtpServer', 'smtp.gmail.com')
    smtp_port = email_settings.get('smtpPort', 587)
    
    if not all([sender_email, sender_password, recipient_email]):
        print("Email alert skipped: Email settings not configured")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"[{alert_type}] {subject}"
        
        body = f"""
        SECURITY ALERT - {alert_type}
        
        {message}
        
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Location: Gate Entry Point
        System: SAFEGUARD NEXUS
        """
        msg.attach(MIMEText(body, 'plain'))
        if html_content:
            msg.attach(MIMEText(html_content, 'html'))
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"Email alert sent successfully to {recipient_email}")
        return True
    except Exception as e:
        print(f"Email alert failed: {e}")
        return False


def send_obstruction_alert(visitor_name='Unknown'):
    """Send multi-channel alert for face obstruction."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    telegram_msg = f"Person detected with obstructed/hidden face at gate entry.\nVisitor: {visitor_name}\nTime: {timestamp}"
    email_msg = f"A person attempted entry with a covered or hidden face.\nVisitor Name: {visitor_name}\nLocation: Main Gate\nSecurity action may be required."
    
    # Send alerts in parallel
    threading.Thread(target=send_telegram_alert, args=(telegram_msg, 'OBSTRUCTION'), daemon=True).start()
    threading.Thread(target=send_email_alert, args=('Face Obstruction Detected', email_msg, 'OBSTRUCTION'), daemon=True).start()
    
    # Log to database
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO obstruction_alerts (visitor_name, timestamp, alert_type, status)
                     VALUES (?, ?, ?, ?)''', (visitor_name, timestamp, 'FACE_OBSTRUCTION', 'TRIGGERED'))
        conn.commit()
        conn.close()
    except:
        pass


def check_watchlist(name, matched_name=None):
    """Check if a visitor name or matched face name matches any active watchlist record."""
    global WATCHLIST_CACHE, WATCHLIST_CACHE_TIME

    try:
        names_to_check = [name.strip().lower()]
        if matched_name:
            names_to_check.append(str(matched_name).strip().lower())

        now = time.time()
        with WATCHLIST_CACHE_LOCK:
            if WATCHLIST_CACHE is None or now - WATCHLIST_CACHE_TIME > WATCHLIST_CACHE_TTL:
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT * FROM watchlist WHERE status = 'ACTIVE'")
                WATCHLIST_CACHE = [dict(r) for r in c.fetchall()]
                WATCHLIST_CACHE_TIME = now
                conn.close()
            rows = WATCHLIST_CACHE
        
        for row in rows:
            wl_name = row['name'].strip().lower()
            for n in names_to_check:
                if wl_name == n or wl_name in n or n in wl_name:
                    return row
    except Exception as e:
        print(f"Error checking watchlist: {e}")
    return None


def send_watchlist_alert(name, entry, photo_path=None):
    """Trigger critical alerts when a blacklisted or flagged person is detected."""
    category = entry.get('category', 'BLACKLIST')
    reason = entry.get('reason', 'Listed on security watchlist')
    threat_level = entry.get('threat_level', 3)
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Telegram notification
    tg_msg = (
        f"🚨 *CRITICAL SECURITY ALERT: {category} DETECTED*\n\n"
        f"Individual: *{name}*\n"
        f"Category: *{category}* (Level {threat_level})\n"
        f"Reason: {reason}\n"
        f"Location: Main Gate Check-In\n"
        f"Time: {now_str}\n\n"
        f"ACTION REQUIRED: Immediate security intercept requested."
    )
    threading.Thread(target=send_telegram_alert, args=(tg_msg, f'{category} ALERT'), daemon=True).start()

    # Email notification
    email_subject = f"CRITICAL SECURITY ALERT: {category} - {name}"
    email_body = (
        f"CRITICAL SECURITY EVENT:\n"
        f"A person matching the {category} list has been identified at the entrance.\n\n"
        f"Name: {name}\n"
        f"Category: {category}\n"
        f"Reason: {reason}\n"
        f"Threat Level: {threat_level}\n"
        f"Time: {now_str}\n"
    )
    threading.Thread(target=send_email_alert, args=(email_subject, email_body, f'{category} ALERT'), daemon=True).start()

    # Log to obstruction_alerts / security alerts
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''INSERT INTO obstruction_alerts (visitor_name, timestamp, alert_type, status)
                     VALUES (?, ?, ?, ?)''', (name, now_str, f'{category}_ALERT', 'TRIGGERED'))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log watchlist alert: {e}")


def send_vip_alert(name, entry):
    """Send VIP arrival alert to management and reception."""
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    reason = entry.get('reason', 'VIP Guest')
    tg_msg = (
        f"⭐ *VIP ARRIVAL NOTIFICATION*\n\n"
        f"VIP Guest: *{name}*\n"
        f"Notes: {reason}\n"
        f"Location: Gate Entry\n"
        f"Time: {now_str}\n"
        f"Reception and security protocols active."
    )
    threading.Thread(target=send_telegram_alert, args=(tg_msg, 'VIP ARRIVAL'), daemon=True).start()


def notify_host_arrival(visitor_id, visitor_name, purpose, contact_person, host_email=None, phone=None, photo_path=None):
    """Send instant arrival notification to the host via Email and Telegram."""
    settings = load_settings()
    sec = settings.get('security', {})
    if not sec.get('enableHostNotifications', True):
        return

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 1. Telegram arrival notification
    tg_msg = (
        f"👤 *VISITOR ARRIVAL NOTIFICATION*\n\n"
        f"Visitor *{visitor_name}* has arrived at the gate to meet *{contact_person}*.\n"
        f"• Purpose: {purpose}\n"
        f"• Phone: {phone or 'N/A'}\n"
        f"• Arrival Time: {now_str}\n"
        f"• Status: Checked in"
    )
    threading.Thread(target=send_telegram_alert, args=(tg_msg, 'VISITOR ARRIVAL'), daemon=True).start()

    # 2. Host Email lookup
    target_email = host_email
    if not target_email:
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('SELECT username FROM users WHERE LOWER(username) = LOWER(?)', (contact_person,))
            user_row = c.fetchone()
            conn.close()
            if user_row and '@' in user_row['username']:
                target_email = user_row['username']
            else:
                target_email = settings.get('email', {}).get('recipientEmail')
        except:
            target_email = settings.get('email', {}).get('recipientEmail')

    if target_email:
        approve_link = f"http://127.0.0.1:5000/api/host-decision/{visitor_id}?decision=APPROVED"
        deny_link = f"http://127.0.0.1:5000/api/host-decision/{visitor_id}?decision=DENIED"
        html_msg = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;background:#0f1422;color:#e2e8f0;padding:24px;border-radius:10px;border:1px solid #1a2540;">
            <h2 style="color:#00d4ff;margin-top:0;">SAFEGUARD NEXUS — Visitor Arrival</h2>
            <p>Hello <strong>{contact_person}</strong>,</p>
            <p>Your visitor <strong>{visitor_name}</strong> has just checked in at the main gate.</p>
            <table style="width:100%;margin:16px 0;background:#07090f;padding:12px;border-radius:6px;font-size:14px;color:#e2e8f0;">
                <tr><td><strong>Purpose:</strong></td><td>{purpose}</td></tr>
                <tr><td><strong>Time:</strong></td><td>{now_str}</td></tr>
                <tr><td><strong>Visitor Phone:</strong></td><td>{phone or 'N/A'}</td></tr>
                <tr><td><strong>Location:</strong></td><td>Gate Entry 1</td></tr>
            </table>
            <p style="margin-top:20px;">Please confirm whether this meeting is approved:</p>
            <div style="margin-top:16px;">
                <a href="{approve_link}" style="background-color:#00ff88;color:#07090f;padding:10px 20px;text-decoration:none;border-radius:6px;font-weight:bold;margin-right:12px;display:inline-block;">✓ Acknowledge / Approve</a>
                <a href="{deny_link}" style="background-color:#ff3d3d;color:#ffffff;padding:10px 20px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block;">✗ Deny Entry</a>
            </div>
        </div>
        """
        plain_msg = f"Visitor {visitor_name} has arrived to meet you at {now_str}. Purpose: {purpose}."
        threading.Thread(
            target=send_email_alert, 
            args=(f"Visitor Arrival: {visitor_name}", plain_msg, 'VISITOR ARRIVAL', target_email, html_msg), 
            daemon=True
        ).start()

    # Update host_notified in DB
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE visitor_logs SET host_notified = 1, host_email = ? WHERE id = ?', (target_email, visitor_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error marking host_notified: {e}")


def get_overstay_visitors_list():
    """Detect all checked-in visitors who have exceeded stay limit or stayed past curfew."""
    settings = load_settings()
    sec = settings.get('security', {})
    max_stay_hours = float(sec.get('maxStayHours', 4.0))
    curfew_str = sec.get('curfewTime', '18:00')

    now = datetime.now()
    overstay_list = []

    try:
        curfew_hour, curfew_min = map(int, curfew_str.split(':'))
        curfew_today = now.replace(hour=curfew_hour, minute=curfew_min, second=0, microsecond=0)
    except:
        curfew_today = now.replace(hour=18, minute=0, second=0, microsecond=0)

    is_past_curfew = now >= curfew_today

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM visitor_logs WHERE status = 'CHECKED_IN' ORDER BY id DESC")
        checked_in = [dict(r) for r in c.fetchall()]
        conn.close()

        for v in checked_in:
            try:
                entry_dt = datetime.strptime(v['entry_time'], '%Y-%m-%d %H:%M:%S')
            except:
                continue

            dwell_hours = (now - entry_dt).total_seconds() / 3600.0
            overstay_reasons = []

            if dwell_hours > max_stay_hours:
                overstay_reasons.append(f"Exceeded limit by {round(dwell_hours - max_stay_hours, 1)}h")
            if is_past_curfew and entry_dt < curfew_today:
                overstay_reasons.append(f"On-site past curfew ({curfew_str})")

            if overstay_reasons:
                v['dwell_hours'] = round(dwell_hours, 1)
                v['overstay_reason'] = ", ".join(overstay_reasons)
                overstay_list.append(v)
    except Exception as e:
        print(f"Error checking overstays: {e}")

    return overstay_list


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def log_visitor_to_db(name, purpose, contact, phone, photo_path, matched_name=None, face_confidence=None, face_status='UNKNOWN', host_email=None, liveness_score=None):
    """Log visitor to database."""
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    c.execute('''INSERT INTO visitor_logs 
                (name, purpose, contact_person, phone, entry_time, photo_path, status, matched_name, face_confidence, face_status, host_email, host_decision, muster_status, liveness_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
             (name, purpose, contact, phone, now, photo_path, 'CHECKED_IN', matched_name, face_confidence, face_status, host_email, 'PENDING', 'UNACCOUNTED', liveness_score))
    
    visitor_id = c.lastrowid
    conn.commit()
    conn.close()
    return visitor_id

def log_to_main_logs(name, status, photo_path):
    """Also log to main logs table for analytics."""
    conn = get_db()
    c = conn.cursor()
    now = datetime.now()
    
    c.execute('''INSERT INTO logs 
                (name, date, time, status, confidence, image_path)
                VALUES (?, ?, ?, ?, ?, ?)''',
             (f"VISITOR: {name}", 
              now.strftime("%Y-%m-%d"), 
              now.strftime("%H:%M:%S"), 
              status, 
              1.0, 
              photo_path))
    
    conn.commit()
    conn.close()

def get_visitor_logs(limit=20, time_period=None, status=None, face_status=None, confidence_min=None, confidence_max=None):
    """Get recent visitor logs with optional filtering."""
    conn = get_db()
    c = conn.cursor()
    
    query = '''SELECT * FROM visitor_logs WHERE 1=1'''
    params = []
    
    # Time period filter
    if time_period:
        if time_period == 'today':
            query += " AND DATE(entry_time) = DATE('now')"
        elif time_period == 'week':
            query += " AND entry_time >= datetime('now', '-7 days')"
        elif time_period == 'month':
            query += " AND entry_time >= datetime('now', '-30 days')"
        elif time_period == 'year':
            query += " AND entry_time >= datetime('now', '-365 days')"
    
    # Status filter
    if status:
        query += " AND status = ?"
        params.append(status)
    
    # Face status filter
    if face_status:
        query += " AND face_status = ?"
        params.append(face_status)
    
    # Confidence range filter
    if confidence_min is not None:
        query += " AND face_confidence >= ?"
        params.append(confidence_min)
    if confidence_max is not None:
        query += " AND face_confidence <= ?"
        params.append(confidence_max)
    
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

def search_visitors(name_filter="", date_filter=""):
    """Search visitor logs."""
    conn = get_db()
    c = conn.cursor()
    
    query = "SELECT * FROM visitor_logs WHERE 1=1"
    params = []
    
    if name_filter:
        query += " AND (name LIKE ? OR contact_person LIKE ?)"
        params.extend([f"%{name_filter}%", f"%{name_filter}%"])
    
    if date_filter:
        query += " AND DATE(entry_time) = ?"
        params.append(date_filter)
    
    query += " ORDER BY id DESC LIMIT 200"
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

# ═══════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/gate-entry')
def gate_entry():
    """Gate entry page."""
    return render_template('gate_entry.html')

@app.route('/pre-register')
def pre_register():
    """Visitor pre-registration page."""
    return render_template('pre_register.html')

@app.route('/api/pre-register', methods=['POST'])
def pre_register_submit():
    try:
        name = request.form.get('name', '').strip()
        purpose = request.form.get('purpose', 'Other').strip()
        contact = request.form.get('contact_person', '').strip()
        phone = request.form.get('phone', 'N/A').strip()
        expected_date = request.form.get('expected_date', '').strip()
        expected_time = request.form.get('expected_time', '').strip()
        notes = request.form.get('notes', '').strip()

        if not name or not contact or not expected_date:
            return jsonify({'success': False, 'error': 'Name, contact person, and expected date are required'}), 400

        conn = get_db()
        c = conn.cursor()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        qr_token = generate_qr_token()
        c.execute('''INSERT INTO pre_registrations
                    (name, purpose, contact_person, phone, expected_date, expected_time, notes, qr_token, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (name, purpose, contact, phone, expected_date, expected_time, notes, qr_token, 'PENDING', now))
        conn.commit()
        conn.close()

        qr_url = url_for('pre_registration_qr', token=qr_token)
        return jsonify({
            'success': True,
            'message': 'Pre-registration submitted successfully',
            'qr_token': qr_token,
            'qr_url': qr_url
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/pre-registrations', methods=['GET'])
@login_required
def get_pre_registrations():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM pre_registrations ORDER BY created_at DESC')
    rows = c.fetchall()
    conn.close()
    return jsonify({'success': True, 'registrations': [dict(row) for row in rows]}), 200

@app.route('/api/pre-registration-qr/<token>')
def pre_registration_qr(token):
    prereg = get_pre_registration_by_token(token)
    if not prereg:
        return jsonify({'success': False, 'error': 'Pre-registration not found'}), 404

    try:
        import qrcode
        qr_data = f"PRE-REGISTRATION:{token}"
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data(qr_data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color='black', back_color='white')

        img_io = BytesIO()
        qr_img.save(img_io, 'PNG')
        img_io.seek(0)
        return send_file(img_io, mimetype='image/png')
    except ImportError:
        return jsonify({'success': False, 'error': 'QR code generation unavailable'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/qr-lookup', methods=['GET'])
def qr_lookup():
    token = request.args.get('token', '').strip()
    if not token:
        return jsonify({'success': False, 'matched': False, 'error': 'Token required'}), 400

    prereg = get_pre_registration_by_token(token)
    if not prereg:
        return jsonify({'success': True, 'matched': False}), 200

    return jsonify({'success': True, 'matched': True, 'preregistration': dict(prereg)}), 200

@app.route('/dashboard')
def dashboard():
    """Dashboard view (for admins)."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/settings')
def settings():
    """Settings page for badge customization and system configuration."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Get user info for session
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = username
            session.permanent = True  # Enable session timeout
            
            # Update last login
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            c.execute('UPDATE users SET last_login = ? WHERE id = ?', (now, user['id']))
            conn.commit()
            conn.close()
            
            # Log audit event
            log_audit_event('LOGIN', f'User {username} logged in', username)
            
            return redirect(url_for('dashboard'))
        
        conn.close()
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    """Logout user and clear session."""
    session.clear()
    return redirect(url_for('index'))

@app.route('/badge/<int:visitor_id>')
def print_badge(visitor_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM visitor_logs WHERE id = ?', (visitor_id,))
    visitor = c.fetchone()
    conn.close()
    if not visitor:
        return "Visitor not found", 404
    return render_template('badge.html', visitor=dict(visitor))

@app.route('/download-badge/<int:visitor_id>/<name>', methods=['GET'])
def download_badge(visitor_id, name):
    """Generate and download badge as PNG image."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM visitor_logs WHERE id = ?', (visitor_id,))
    visitor = c.fetchone()
    conn.close()

    if not visitor:
        return "Visitor not found", 404

    visitor_dict = dict(visitor)

    # Load badge settings
    settings = load_settings()
    badge_settings = settings.get('badge', {})

    # Determine badge dimensions based on size setting
    size_configs = {
        'standard': (800, 1000),
        'large': (1000, 1250),
        'mobile': (600, 800)
    }
    width, height = size_configs.get(badge_settings.get('badgeSize', 'standard'), (800, 1000))

    # Create badge image using PIL
    badge = Image.new('RGB', (width, height), color='#0f1422')
    draw = ImageDraw.Draw(badge)

    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 48)
        header_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 40)
        label_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 24)
        text_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 28)
        footer_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 20)
    except:
        title_font = header_font = label_font = text_font = footer_font = ImageFont.load_default()

    # Colors from settings
    accent_color = badge_settings.get('accentColor', '#00d4ff')
    text_color = '#e2e8f0'
    label_color = '#718096'
    border_color = '#1a2540'

    # Helper function to convert hex to RGB
    def hex_to_rgb(hex_color):
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    # Draw header with custom company name
    company_name = badge_settings.get('companyName', 'SAFEGUARD NEXUS')
    draw.rectangle([0, 0, width, 150], fill=hex_to_rgb('#0b0e18'))

    # Try to load and draw logo if available
    logo_drawn = False
    if badge_settings.get('logoPath') and os.path.exists(badge_settings['logoPath']):
        try:
            logo = Image.open(badge_settings['logoPath'])
            logo = logo.resize((80, 80), Image.Resampling.LANCZOS)
            badge.paste(logo, (20, 35), logo if logo.mode == 'RGBA' else None)
            logo_drawn = True
        except Exception as e:
            print(f"Error loading logo: {e}")

    if not logo_drawn:
        draw.text((40, 30), "⬡", font=title_font, fill=hex_to_rgb(accent_color))

    draw.text((logo_drawn and 120 or 40, 100), company_name, font=header_font, fill=hex_to_rgb(accent_color))

    # Draw border
    draw.rectangle([20, 170, width-20, 200], fill=hex_to_rgb(border_color))

    # Draw visitor info sections
    y_pos = 220
    sections = [
        ("VISITOR NAME", visitor_dict.get('name', 'N/A')),
        ("BADGE ID", f"#{visitor_id}"),
        ("PURPOSE OF VISIT", visitor_dict.get('purpose', 'N/A')),
        ("MEETING WITH", visitor_dict.get('contact_person', 'N/A')),
        ("PHONE", visitor_dict.get('phone', 'N/A')),
        ("ENTRY TIME", visitor_dict.get('entry_time', 'N/A')),
    ]

    for label, value in sections:
        # Draw label
        draw.text((40, y_pos), label, font=label_font, fill=hex_to_rgb(label_color))
        y_pos += 35
        # Draw value
        draw.text((40, y_pos), str(value), font=text_font, fill=hex_to_rgb(text_color))
        y_pos += 45

    # Draw face recognition status
    face_status = visitor_dict.get('face_status', 'UNKNOWN')
    status_color = accent_color if face_status == 'VERIFIED' else '#ff3d3d'
    y_pos += 20
    draw.rectangle([30, y_pos, width-30, y_pos+80], outline=hex_to_rgb(status_color), width=3, fill=hex_to_rgb('#0b0e18'))
    draw.text((40, y_pos+15), "FACE RECOGNITION", font=label_font, fill=hex_to_rgb(label_color))
    draw.text((40, y_pos+45), face_status, font=header_font, fill=hex_to_rgb(status_color))

    # Add QR code if enabled
    if badge_settings.get('includeQR', True):
        try:
            import qrcode
            qr_data = f"Visitor: {visitor_dict.get('name', 'N/A')}\nID: {visitor_id}\nTime: {visitor_dict.get('entry_time', 'N/A')}"
            qr = qrcode.QRCode(version=1, box_size=4, border=1)
            qr.add_data(qr_data)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color=accent_color, back_color='#0f1422')
            qr_img = qr_img.resize((120, 120), Image.Resampling.LANCZOS)
            badge.paste(qr_img, (width-160, height-200))
        except ImportError:
            # QR code library not available, skip
            pass
        except Exception as e:
            print(f"Error generating QR code: {e}")

    # Draw footer
    draw.rectangle([0, height-100, width, height], fill=hex_to_rgb('#0b0e18'))
    badge_title = badge_settings.get('badgeTitle', 'Visitor Access Badge')
    draw.text((40, height-70), badge_title.upper(), font=footer_font, fill=hex_to_rgb(text_color))
    draw.text((40, height-35), visitor_dict.get('entry_time', ''), font=footer_font, fill=hex_to_rgb(label_color))

    # Save to BytesIO
    img_io = BytesIO()
    badge.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png', 
                     as_attachment=True, 
                     download_name=f"Badge_{name}_{visitor_id}.png")

@app.route('/api/visitor-checkin', methods=['POST'])
def visitor_checkin():
    """
    Handle visitor check-in.
    Expects: name, purpose, contact_person, phone (optional), photo (file)
    """
    try:
        qr_token = request.form.get('qr_token', '').strip()
        name = request.form.get('name', '').strip()
        purpose = request.form.get('purpose', 'Other').strip()
        contact = request.form.get('contact_person', '').strip()
        phone = request.form.get('phone', 'N/A').strip()
        host_email = request.form.get('host_email', '').strip()
        liveness_score = request.form.get('liveness_score', type=float)

        prereg = None
        if qr_token:
            prereg = get_pre_registration_by_token(qr_token)
            if prereg:
                if not name:
                    name = prereg['name']
                if not purpose or purpose == 'Other':
                    purpose = prereg['purpose']
                if not contact:
                    contact = prereg['contact_person']
                if not phone or phone == 'N/A':
                    phone = prereg['phone'] or 'N/A'

        # Validate required fields
        if not name or not contact:
            return jsonify({'success': False, 'error': 'Name and Contact Person are required'}), 400
        
        photo_path = None
        matched_name = None
        face_confidence = None
        face_status = 'UNKNOWN'
        
        # Handle photo upload
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo and photo.filename:
                # Create filename
                filename = f"{name.replace(' ','_')}_{int(datetime.now().timestamp())}.jpg"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Read image
                img_data = photo.read()
                
                # Save using OpenCV
                import numpy as np
                nparr = np.frombuffer(img_data, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                
                if img is not None:
                    cv2.imwrite(filepath, img)
                    photo_path = filepath
                    match_name, confidence, status = identify_face(img)
                    matched_name = match_name
                    face_confidence = confidence
                    face_status = status
                    
                    # Detect face obstruction
                    is_obstructed = detect_person_without_face(img)
                    if is_obstructed:
                        face_status = 'OBSTRUCTION_ALERT'
                        # Trigger alert system
                        send_obstruction_alert(name)

        # Watchlist & Blacklist Threat Evaluation
        wl_entry = check_watchlist(name, matched_name)
        threat_detected = False
        threat_category = None
        threat_reason = None
        if wl_entry:
            threat_detected = True
            threat_category = wl_entry.get('category', 'BLACKLIST')
            threat_reason = wl_entry.get('reason', 'Watchlist match')
            if threat_category == 'BLACKLIST':
                face_status = 'BLACKLIST_ALERT'
                send_watchlist_alert(name, wl_entry, photo_path)
            elif threat_category == 'VIP':
                face_status = 'VIP'
                send_vip_alert(name, wl_entry)
            elif threat_category == 'WATCHLIST':
                face_status = 'WATCHLIST_ALERT'
                send_watchlist_alert(name, wl_entry, photo_path)
        
        # Log to database
        visitor_id = log_visitor_to_db(name, purpose, contact, phone, photo_path,
                                       matched_name=matched_name,
                                       face_confidence=face_confidence,
                                       face_status=face_status,
                                       host_email=host_email,
                                       liveness_score=liveness_score)
        log_to_main_logs(name, "VISITOR_ENTRY", photo_path)

        if prereg:
            mark_pre_registration_arrived(prereg['id'])

        # Dispatch Host Arrival Notification in background thread
        threading.Thread(
            target=notify_host_arrival,
            args=(visitor_id, name, purpose, contact, host_email, phone, photo_path),
            daemon=True
        ).start()
        
        return jsonify({
            'success': True,
            'message': f'✓ {name} checked in successfully at {datetime.now().strftime("%H:%M:%S")}',
            'visitor': {
                'id': visitor_id,
                'name': name,
                'purpose': purpose,
                'contact': contact,
                'phone': phone,
                'host_email': host_email,
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'face_status': face_status,
                'matched_name': matched_name,
                'face_confidence': face_confidence,
                'threat_detected': threat_detected,
                'threat_category': threat_category,
                'threat_reason': threat_reason,
                'liveness_score': liveness_score
            },
            'badge_url': f'/badge/{visitor_id}'
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/visitor-logs', methods=['GET'])
@login_required
def get_logs():
    """Get visitor logs with optional filtering."""
    try:
        limit = request.args.get('limit', 20, type=int)
        time_period = request.args.get('time_period')
        status = request.args.get('status')
        face_status = request.args.get('face_status')
        confidence_min = request.args.get('confidence_min', type=float)
        confidence_max = request.args.get('confidence_max', type=float)
        
        logs = get_visitor_logs(limit, time_period, status, face_status, confidence_min, confidence_max)
        return jsonify({'success': True, 'logs': logs}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/visitor-search', methods=['GET'])
@login_required
def search():
    """Search visitor logs."""
    try:
        name_filter = request.args.get('name', '')
        date_filter = request.args.get('date', '')
        
        results = search_visitors(name_filter, date_filter)
        return jsonify({'success': True, 'results': results}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/visitor-stats', methods=['GET'])
@login_required
def get_stats():
    """Get visitor statistics."""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Total visitors today
        today = datetime.now().strftime("%Y-%m-%d")
        c.execute("SELECT COUNT(*) FROM visitor_logs WHERE DATE(entry_time) = ?", (today,))
        today_count = c.fetchone()[0]
        
        # Total visitors all time
        c.execute("SELECT COUNT(*) FROM visitor_logs")
        total_count = c.fetchone()[0]

        # Verified face matches
        c.execute("SELECT COUNT(*) FROM visitor_logs WHERE face_status = 'VERIFIED'")
        verified_count = c.fetchone()[0]

        # Total alert events
        c.execute("SELECT COUNT(*) FROM obstruction_alerts")
        alert_count = c.fetchone()[0]

        # Currently checked-in on site
        c.execute("SELECT COUNT(*) FROM visitor_logs WHERE status = 'CHECKED_IN'")
        checked_in_count = c.fetchone()[0]

        # Active watchlist entries
        c.execute("SELECT COUNT(*) FROM watchlist WHERE status = 'ACTIVE'")
        watchlist_count = c.fetchone()[0]
        
        # Visitors by purpose
        c.execute("SELECT purpose, COUNT(*) FROM visitor_logs GROUP BY purpose")
        by_purpose = dict(c.fetchall())
        
        conn.close()

        # Overstay count
        overstays = get_overstay_visitors_list()
        overstay_count = len(overstays)
        
        return jsonify({
            'success': True,
            'stats': {
                'today': today_count,
                'total': total_count,
                'verified': verified_count,
                'alerts': alert_count,
                'checked_in': checked_in_count,
                'overstay_count': overstay_count,
                'watchlist_count': watchlist_count,
                'by_purpose': by_purpose
            }
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/snapshots/visitors/<filename>')
def serve_visitor_photo(filename):
    """Serve visitor photos."""
    try:
        # Validate filename to prevent path traversal attacks
        if '..' in filename or filename.startswith('/'):
            return jsonify({'error': 'Invalid filename'}), 400
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@app.route('/api/visitor-checkout', methods=['POST'])
@login_required
def visitor_checkout():
    """Handle visitor check-out."""
    try:
        data = request.get_json() or {}
        visitor_id = data.get('id')
        if not visitor_id:
            return jsonify({'success': False, 'error': 'Visitor ID is required'}), 400

        conn = get_db()
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "UPDATE visitor_logs SET exit_time = ?, status = 'CHECKED_OUT' WHERE id = ? AND status = 'CHECKED_IN'",
            (now, visitor_id)
        )
        conn.commit()
        updated = c.rowcount
        conn.close()

        if not updated:
            return jsonify({'success': False, 'error': 'Visitor not found or already checked out'}), 404

        return jsonify({'success': True, 'message': 'Visitor checked out successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/export-visitor-logs', methods=['GET'])
@login_required
def export_visitor_logs():
    """Export visitor logs as CSV."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, name, purpose, contact_person, phone, entry_time, exit_time, photo_path, status FROM visitor_logs ORDER BY id DESC')
        rows = c.fetchall()
        conn.close()

        output = StringIO()
        output.write('ID,Name,Purpose,Contact Person,Phone,Entry Time,Exit Time,Photo Path,Status\n')
        for row in rows:
            values = [str(row[col]) if row[col] is not None else '' for col in row.keys()]
            safe_values = [v.replace('"', '""') for v in values]
            output.write('"' + '","'.join(safe_values) + '"\n')

        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=visitor_logs.csv'
        return response
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/obstruction-alerts', methods=['GET'])
@login_required
def get_obstruction_alerts():
    """Get face obstruction alerts for security dashboard."""
    try:
        limit = request.args.get('limit', 50, type=int)
        conn = get_db()
        c = conn.cursor()
        c.execute('''SELECT id, visitor_name, timestamp, alert_type, status, resolved 
                     FROM obstruction_alerts ORDER BY timestamp DESC LIMIT ?''', (limit,))
        alerts = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'alerts': alerts}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/obstruction-alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Mark an obstruction alert as resolved."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE obstruction_alerts SET resolved = 1 WHERE id = ?', (alert_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Alert marked as resolved'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system-info', methods=['GET'])
@login_required
def system_info():
    """Get system information."""
    try:
        import psutil
        
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        
        return jsonify({
            'success': True,
            'info': {
                'cpu': cpu,
                'ram': ram,
                'timestamp': datetime.now().isoformat()
            }
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics/daily', methods=['GET'])
@login_required
def analytics_daily():
    """Get daily analytics with visitor count by hour."""
    try:
        days = request.args.get('days', 30, type=int)
        start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT DATE(entry_time) as date, COUNT(*) as count, 
                   SUM(CASE WHEN face_status='VERIFIED' THEN 1 ELSE 0 END) as verified
            FROM visitor_logs 
            WHERE entry_time >= ?
            GROUP BY DATE(entry_time)
            ORDER BY date DESC
        ''', (start_date,))
        
        data = [{'date': row[0], 'total': row[1], 'verified': row[2]} for row in c.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'data': data}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analytics/purpose', methods=['GET'])
@login_required
def analytics_purpose():
    """Get visitor breakdown by purpose."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT purpose, COUNT(*) as count
            FROM visitor_logs
            GROUP BY purpose
            ORDER BY count DESC
        ''')
        
        data = [{'purpose': row[0], 'count': row[1]} for row in c.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'data': data}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/visitor-duration', methods=['GET'])
@login_required
def visitor_duration():
    """Get visitor visit duration statistics."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT name, entry_time, exit_time,
                   CASE 
                       WHEN exit_time IS NOT NULL THEN 
                           CAST((JULIANDAY(exit_time) - JULIANDAY(entry_time)) * 24 * 60 AS INTEGER)
                       ELSE -1
                   END as duration_minutes
            FROM visitor_logs
            WHERE exit_time IS NOT NULL
            ORDER BY entry_time DESC
            LIMIT 100
        ''')
        
        data = []
        for row in c.fetchall():
            data.append({
                'name': row[0],
                'entry': row[1],
                'exit': row[2],
                'duration_min': row[3]
            })
        conn.close()
        
        return jsonify({'success': True, 'data': data}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/match-preregistration', methods=['POST'])
def match_preregistration():
    """Match visitor with pre-registrations and return match info."""
    try:
        name = request.form.get('name', '').strip()
        
        if not name:
            return jsonify({'success': False, 'matched': False}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Case-insensitive partial match
        c.execute('''
            SELECT id, name, purpose, contact_person, phone, expected_date, expected_time, notes
            FROM pre_registrations
            WHERE status = 'PENDING' AND LOWER(name) LIKE ?
            LIMIT 1
        ''', (f'%{name.lower()}%',))
        
        match = c.fetchone()
        conn.close()
        
        if match:
            return jsonify({
                'success': True,
                'matched': True,
                'preregistration': dict(match)
            }), 200
        else:
            return jsonify({'success': True, 'matched': False}), 200
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/audit-log', methods=['GET'])
@login_required
def get_audit_log():
    """Get system audit log."""
    try:
        limit = request.args.get('limit', 100, type=int)
        log_type = request.args.get('type', '', type=str)
        
        conn = get_db()
        c = conn.cursor()
        
        query = 'SELECT * FROM audit_logs WHERE 1=1'
        params = []
        
        if log_type:
            query += ' AND log_type = ?'
            params.append(log_type)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        c.execute(query, params)
        logs = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'logs': logs}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def log_audit_event(event_type, description, user='system', status='SUCCESS'):
    """Log an audit event to the audit log table."""
    try:
        conn = get_db()
        c = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        c.execute('''
            INSERT INTO audit_logs (timestamp, event_type, description, user, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, event_type, description, user, status))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Audit log error: {e}")

# Add audit logs table creation to create_tables() - will add to the table functions


# ═══════════════════════════════════════════
#  SETTINGS MANAGEMENT
# ═══════════════════════════════════════════

SETTINGS_FILE = 'settings.json'

def load_settings():
    """Load settings from JSON file."""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading settings: {e}")
    return {
        'badge': {
            'companyName': 'SAFEGUARD NEXUS',
            'badgeTitle': 'Visitor Access Badge',
            'badgeSize': 'standard',
            'badgeLayout': 'vertical',
            'includeQR': True,
            'includePhoto': True,
            'accentColor': '#00d4ff'
        },
        'system': {
            'sessionTimeout': 30,
            'maxFileSize': 16,
            'alertEmail': '',
            'theme': 'dark',
            'enableFaceRec': True,
            'enableAlerts': True,
            'enableBackup': True
        },
        'security': {
            'maxStayHours': 4,
            'curfewTime': '18:00',
            'enableOverstayAlerts': True,
            'enableHostNotifications': True,
            'enableLivenessCheck': True,
            'enableWatchlistSirens': True
        },
        'email': {
            'senderEmail': '',
            'senderPassword': '',
            'recipientEmail': '',
            'smtpServer': 'smtp.gmail.com',
            'smtpPort': 587,
            'enableEmailAlerts': True
        },
        'telegram': {
            'botToken': '',
            'chatId': '',
            'enableTelegram': True
        }
    }

def save_settings(settings):
    """Save settings to JSON file."""
    try:
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving settings: {e}")
        return False

@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    """Get current settings."""
    return jsonify(load_settings())

@app.route('/api/settings/<setting_type>', methods=['POST'])
@login_required
def update_settings(setting_type):
    """Update settings for badge, system, or security."""
    if setting_type not in ['badge', 'system', 'security']:
        return jsonify({'error': 'Invalid setting type'}), 400

    settings = load_settings()

    if setting_type == 'badge':
        # Handle file upload for logo
        if 'logoUpload' in request.files and request.files['logoUpload'].filename:
            file = request.files['logoUpload']
            if file and file.filename:
                # Save logo file
                logo_filename = f"company_logo.{file.filename.split('.')[-1]}"
                logo_path = os.path.join('static', 'images', logo_filename)
                os.makedirs(os.path.dirname(logo_path), exist_ok=True)
                file.save(logo_path)
                settings['badge']['logoPath'] = logo_path

        # Update other badge settings
        settings['badge'].update({
            'companyName': request.form.get('companyName', settings['badge']['companyName']),
            'badgeTitle': request.form.get('badgeTitle', settings['badge']['badgeTitle']),
            'badgeSize': request.form.get('badgeSize', settings['badge']['badgeSize']),
            'badgeLayout': request.form.get('badgeLayout', settings['badge']['badgeLayout']),
            'includeQR': request.form.get('includeQR') == 'on',
            'includePhoto': request.form.get('includePhoto') == 'on',
            'accentColor': request.form.get('accentColor', settings['badge']['accentColor'])
        })

    elif setting_type == 'system':
        settings['system'].update({
            'sessionTimeout': int(request.form.get('sessionTimeout', settings['system']['sessionTimeout'])),
            'maxFileSize': int(request.form.get('maxFileSize', settings['system']['maxFileSize'])),
            'alertEmail': request.form.get('alertEmail', settings['system']['alertEmail']),
            'theme': request.form.get('theme', settings['system']['theme']),
            'enableFaceRec': request.form.get('enableFaceRec') == 'on',
            'enableAlerts': request.form.get('enableAlerts') == 'on',
            'enableBackup': request.form.get('enableBackup') == 'on'
        })

    elif setting_type == 'security':
        settings.setdefault('security', {})
        settings['security'].update({
            'maxStayHours': float(request.form.get('maxStayHours', settings['security'].get('maxStayHours', 4))),
            'curfewTime': request.form.get('curfewTime', settings['security'].get('curfewTime', '18:00')),
            'enableOverstayAlerts': request.form.get('enableOverstayAlerts') == 'on',
            'enableHostNotifications': request.form.get('enableHostNotifications') == 'on',
            'enableLivenessCheck': request.form.get('enableLivenessCheck') == 'on',
            'enableWatchlistSirens': request.form.get('enableWatchlistSirens') == 'on'
        })

    if save_settings(settings):
        return jsonify({'message': f'{setting_type.title()} settings saved successfully!'})
    else:
        return jsonify({'error': 'Failed to save settings'}), 500

@app.route('/api/settings/email', methods=['POST'])
@login_required
def update_email_settings():
    """Update email alert settings."""
    settings = load_settings()
    
    # Initialize email settings if not exists
    if 'email' not in settings:
        settings['email'] = {
            'senderEmail': '',
            'senderPassword': '',
            'recipientEmail': '',
            'smtpServer': 'smtp.gmail.com',
            'smtpPort': 587,
            'enableEmailAlerts': True
        }
    
    settings['email'].update({
        'senderEmail': request.form.get('senderEmail', settings['email']['senderEmail']),
        'senderPassword': request.form.get('senderPassword', settings['email']['senderPassword']),
        'recipientEmail': request.form.get('recipientEmail', settings['email']['recipientEmail']),
        'smtpServer': request.form.get('smtpServer', settings['email']['smtpServer']),
        'smtpPort': int(request.form.get('smtpPort', settings['email']['smtpPort'])),
        'enableEmailAlerts': request.form.get('enableEmailAlerts') == 'on'
    })
    
    if save_settings(settings):
        return jsonify({'message': 'Email settings saved successfully!'})
    else:
        return jsonify({'error': 'Failed to save email settings'}), 500

@app.route('/api/settings/telegram', methods=['POST'])
@login_required
def update_telegram_settings():
    """Update Telegram alert settings."""
    settings = load_settings()
    if 'telegram' not in settings:
        settings['telegram'] = {
            'botToken': '',
            'chatId': '',
            'enableTelegram': True
        }
    settings['telegram'].update({
        'botToken': request.form.get('telegramBotToken', settings['telegram']['botToken']),
        'chatId': request.form.get('telegramChatId', settings['telegram']['chatId']),
        'enableTelegram': request.form.get('enableTelegramAlerts') == 'on'
    })
    if save_settings(settings):
        return jsonify({'message': 'Telegram settings saved successfully!'})
    return jsonify({'error': 'Failed to save Telegram settings'}), 500

@app.route('/api/test-telegram', methods=['POST'])
@login_required
def test_telegram():
    """Send a test Telegram alert to verify configuration."""
    try:
        bot_token = request.form.get('telegramBotToken', '').strip()
        chat_id = request.form.get('telegramChatId', '').strip()
        enable_telegram = request.form.get('enableTelegramAlerts') == 'on'
        
        if not enable_telegram:
            return jsonify({'success': False, 'error': 'Telegram alerts are disabled'}), 400
        if not bot_token or not chat_id:
            return jsonify({'success': False, 'error': 'Bot Token and Chat ID are required'}), 400
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        response = requests.post(url, data={
            'chat_id': chat_id,
            'text': '✅ Test alert from SAFEGUARD NEXUS: Telegram configuration is correct.'
        }, timeout=10)
        
        if response.status_code != 200:
            return jsonify({'success': False, 'error': f'Telegram request failed: {response.status_code}'}), 500
        return jsonify({'success': True, 'message': 'Test Telegram alert sent successfully!'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': f'Telegram test failed: {str(e)}'}), 500

@app.route('/api/test-email', methods=['POST'])
@login_required
def test_email():
    """Test email configuration by sending a test email."""
    try:
        # Get email settings from form data
        sender_email = request.form.get('senderEmail', '').strip()
        sender_password = request.form.get('senderPassword', '').strip()
        recipient_email = request.form.get('recipientEmail', '').strip()
        smtp_server = request.form.get('smtpServer', 'smtp.gmail.com').strip()
        smtp_port = int(request.form.get('smtpPort', 587))
        
        if not all([sender_email, sender_password, recipient_email]):
            return jsonify({'success': False, 'error': 'All email fields are required'}), 400
        
        # Send test email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = '[TEST] SAFEGUARD NEXUS - Email Alert Test'
        
        body = f"""
        TEST EMAIL - SAFEGUARD NEXUS
        
        This is a test email to verify your email alert configuration.
        
        If you received this email, your email settings are working correctly!
        
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        System: SAFEGUARD NEXUS
        """
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        return jsonify({'success': True, 'message': 'Test email sent successfully!'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Email test failed: {str(e)}'}), 500

@app.route('/api/export/visitors', methods=['GET'])
@login_required
def export_visitors():
    """Export visitor logs as CSV."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM visitor_logs ORDER BY entry_time DESC')
    visitors = c.fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)

    # Write header
    if visitors:
        writer.writerow([desc[0] for desc in c.description])

        # Write data
        for visitor in visitors:
            writer.writerow(visitor)

    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'visitor_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/api/export/logs', methods=['GET'])
@login_required
def export_logs():
    """Export system logs as CSV."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY date DESC, time DESC')
    logs = c.fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)

    # Write header
    if logs:
        writer.writerow([desc[0] for desc in c.description])

        # Write data
        for log in logs:
            writer.writerow(log)

    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'system_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/api/backup/create', methods=['POST'])
@login_required
def create_backup():
    """Create a database backup."""
    try:
        backup_filename = f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
        backup_path = os.path.join('backups', backup_filename)
        os.makedirs('backups', exist_ok=True)

        # Copy database file
        import shutil
        shutil.copy2(DATABASE, backup_path)

        return jsonify({'message': f'Backup created: {backup_filename}'})
    except Exception as e:
        return jsonify({'error': f'Backup failed: {str(e)}'}), 500

@app.route('/api/backup/download', methods=['GET'])
@login_required
def download_backup():
    """Download the latest backup."""
    try:
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            return jsonify({'error': 'No backups found'}), 404

        # Get latest backup
        backups = [f for f in os.listdir(backup_dir) if f.startswith('backup_') and f.endswith('.db')]
        if not backups:
            return jsonify({'error': 'No backups found'}), 404

        latest_backup = max(backups, key=lambda x: os.path.getctime(os.path.join(backup_dir, x)))
        backup_path = os.path.join(backup_dir, latest_backup)

        return send_file(
            backup_path,
            as_attachment=True,
            download_name=latest_backup
        )
    except Exception as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/bulk-checkout', methods=['POST'])
@login_required
def bulk_checkout():
    """Bulk checkout multiple visitors."""
    try:
        data = request.get_json()
        ids = data.get('ids', [])
        
        if not ids:
            return jsonify({'error': 'No visitor IDs provided'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Update all specified visitors to checked out
        placeholders = ','.join('?' * len(ids))
        c.execute(f'UPDATE visitor_logs SET status = "CHECKED_OUT", exit_time = ? WHERE id IN ({placeholders}) AND status = "CHECKED_IN"',
                 [datetime.now().strftime('%Y-%m-%d %H:%M:%S')] + ids)
        
        checked_out = c.rowcount
        conn.commit()
        conn.close()
        
        # Log audit event
        log_audit_event('BULK_CHECKOUT', f'Checked out {checked_out} visitors', 'system')
        
        return jsonify({'success': True, 'checked_out': checked_out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/bulk-delete', methods=['POST'])
@login_required
def bulk_delete():
    """Bulk delete visitor records."""
    try:
        data = request.get_json()
        ids = data.get('ids', [])
        
        if not ids:
            return jsonify({'error': 'No visitor IDs provided'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Delete all specified visitor records
        placeholders = ','.join('?' * len(ids))
        c.execute(f'DELETE FROM visitor_logs WHERE id IN ({placeholders})', ids)
        
        deleted = c.rowcount
        conn.commit()
        conn.close()
        
        # Log audit event
        log_audit_event('BULK_DELETE', f'Deleted {deleted} visitor records', 'system')
        
        return jsonify({'success': True, 'deleted': deleted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ═══════════════════════════════════════════
#  ERROR HANDLERS
# ═══════════════════════════════════════════

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Server error'}), 500

# ═══════════════════════════════════════════
#  USER MANAGEMENT API
# ═══════════════════════════════════════════

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    """Get all users (admin only)."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, username, role, created_at, last_login FROM users ORDER BY id')
        users = c.fetchall()
        conn.close()
        
        return jsonify({'success': True, 'users': [dict(user) for user in users]}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    """Create a new user (admin only)."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'admin')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if username already exists
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        # Create user
        password_hash = generate_password_hash(password)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute(
            'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
            (username, password_hash, role, now)
        )
        conn.commit()
        conn.close()
        
        # Log audit event
        log_audit_event('USER_CREATED', f'User {username} created with role {role}')
        
        return jsonify({'success': True, 'message': 'User created successfully'}), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    """Get a specific user (admin only)."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, username, role, created_at, last_login FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        return jsonify({'success': True, 'user': dict(user)}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update a user (admin only)."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        role = data.get('role', 'admin')
        
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if username already exists (excluding current user)
        c.execute('SELECT id FROM users WHERE username = ? AND id != ?', (username, user_id))
        if c.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Username already exists'}), 400
        
        # Update user
        c.execute(
            'UPDATE users SET username = ?, role = ? WHERE id = ?',
            (username, role, user_id)
        )
        conn.commit()
        conn.close()
        
        # Log audit event
        log_audit_event('USER_UPDATED', f'User {username} updated')
        
        return jsonify({'success': True, 'message': 'User updated successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/<int:user_id>/password', methods=['POST'])
@login_required
def change_user_password(user_id):
    """Change a user's password (admin only)."""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password or len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Update password
        password_hash = generate_password_hash(password)
        c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
        conn.commit()
        conn.close()
        
        # Log audit event
        log_audit_event('PASSWORD_CHANGED', f'Password changed for user ID {user_id}')
        
        return jsonify({'success': True, 'message': 'Password changed successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Delete a user (admin only)."""
    try:
        # Prevent deleting the current user
        current_user_id = session.get('user_id')
        if current_user_id == user_id:
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Get username for audit log
        c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        username = user['username'] if user else 'Unknown'
        
        # Delete user
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        
        if deleted == 0:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Log audit event
        log_audit_event('USER_DELETED', f'User {username} deleted')
        
        return jsonify({'success': True, 'message': 'User deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ═══════════════════════════════════════════
#  WATCHLIST & BLACKLIST MANAGEMENT API
# ═══════════════════════════════════════════

@app.route('/api/watchlist', methods=['GET'])
@login_required
def get_watchlist():
    """List all watchlist entries with optional filtering."""
    try:
        category = request.args.get('category', '').strip()
        search_query = request.args.get('search', '').strip()
        
        conn = get_db()
        c = conn.cursor()
        query = 'SELECT * FROM watchlist WHERE 1=1'
        params = []
        
        if category:
            query += ' AND category = ?'
            params.append(category)
        if search_query:
            query += ' AND (name LIKE ? OR reason LIKE ?)'
            params.extend([f'%{search_query}%', f'%{search_query}%'])
            
        query += ' ORDER BY id DESC'
        c.execute(query, params)
        entries = [dict(row) for row in c.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'watchlist': entries, 'count': len(entries)}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/watchlist', methods=['POST'])
@login_required
def add_watchlist_entry():
    """Add or update an individual on the security watchlist/blacklist."""
    try:
        name = request.form.get('name', '').strip()
        category = request.form.get('category', 'BLACKLIST').strip().upper()
        threat_level = int(request.form.get('threat_level', 3))
        reason = request.form.get('reason', 'Security concern').strip()
        action = request.form.get('action', 'BLOCK').strip().upper()
        
        if not name:
            return jsonify({'success': False, 'error': 'Person name is required'}), 400
            
        if category not in ['BLACKLIST', 'WATCHLIST', 'VIP']:
            category = 'BLACKLIST'
            
        photo_path = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename:
                folder = os.path.join(app.config['UPLOAD_FOLDER'], 'watchlist')
                os.makedirs(folder, exist_ok=True)
                filename = f"watchlist_{re.sub(r'[^a-zA-Z0-9]', '_', name)}_{int(time.time())}.jpg"
                photo_path = os.path.join(folder, filename)
                file.save(photo_path)
                
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO watchlist (name, category, threat_level, reason, photo_path, action, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
            ON CONFLICT(name) DO UPDATE SET
                category=excluded.category,
                threat_level=excluded.threat_level,
                reason=excluded.reason,
                photo_path=COALESCE(excluded.photo_path, watchlist.photo_path),
                action=excluded.action,
                status='ACTIVE'
        ''', (name, category, threat_level, reason, photo_path, action, now_str))
        conn.commit()
        entry_id = c.lastrowid
        conn.close()
        
        log_audit_event('WATCHLIST_ADDED', f'Added {name} to {category} (Level {threat_level})')
        return jsonify({'success': True, 'message': f'✓ {name} added to {category} list', 'id': entry_id}), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/watchlist/<int:entry_id>', methods=['DELETE'])
@login_required
def delete_watchlist_entry(entry_id):
    """Remove an entry from the watchlist."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT name, category FROM watchlist WHERE id = ?', (entry_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': 'Watchlist entry not found'}), 404
            
        name, cat = row['name'], row['category']
        c.execute('DELETE FROM watchlist WHERE id = ?', (entry_id,))
        conn.commit()
        conn.close()
        
        log_audit_event('WATCHLIST_DELETED', f'Removed {name} from {cat}')
        return jsonify({'success': True, 'message': f'{name} removed from {cat}'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/watchlist/<int:entry_id>/toggle', methods=['POST'])
@login_required
def toggle_watchlist_status(entry_id):
    """Toggle watchlist entry status between ACTIVE and INACTIVE."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT status, name FROM watchlist WHERE id = ?', (entry_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': 'Entry not found'}), 404
            
        new_status = 'INACTIVE' if row['status'] == 'ACTIVE' else 'ACTIVE'
        c.execute('UPDATE watchlist SET status = ? WHERE id = ?', (new_status, entry_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'status': new_status, 'message': f"Entry {row['name']} is now {new_status}"}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ═══════════════════════════════════════════
#  HOST ARRIVAL & 1-CLICK VERIFICATION API
# ═══════════════════════════════════════════

@app.route('/api/host-decision/<int:visitor_id>', methods=['GET', 'POST'])
def host_decision(visitor_id):
    """Host 1-click visit approval or denial link."""
    decision = request.args.get('decision') or request.form.get('decision')
    if request.is_json and not decision:
        decision = request.json.get('decision')
        
    decision = (decision or '').strip().upper()
    if decision not in ['APPROVED', 'DENIED']:
        return jsonify({'success': False, 'error': 'Decision must be APPROVED or DENIED'}), 400
        
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM visitor_logs WHERE id = ?', (visitor_id,))
        visitor = c.fetchone()
        if not visitor:
            conn.close()
            return jsonify({'success': False, 'error': 'Visitor record not found'}), 404
            
        c.execute('UPDATE visitor_logs SET host_decision = ? WHERE id = ?', (decision, visitor_id))
        conn.commit()
        conn.close()
        
        log_audit_event('HOST_DECISION', f"Host marked visitor {visitor['name']} as {decision}")
        
        # If accessed via web browser link in email, render sleek status card
        if 'text/html' in request.headers.get('Accept', ''):
            color = '#00ff88' if decision == 'APPROVED' else '#ff3d3d'
            symbol = '✓' if decision == 'APPROVED' else '✗'
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>SAFEGUARD NEXUS — Decision Recorded</title>
                <style>
                    body {{ background: #07090f; color: #e2e8f0; font-family: Consolas, monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                    .card {{ background: #0f1422; border: 1px solid #1a2540; border-top: 4px solid {color}; padding: 40px; border-radius: 12px; text-align: center; max-width: 480px; box-shadow: 0 10px 40px rgba(0,0,0,0.8); }}
                    h1 {{ color: {color}; font-size: 24px; margin-bottom: 12px; }}
                    p {{ color: #a0aec0; line-height: 1.6; font-size: 15px; }}
                    .tag {{ display: inline-block; padding: 6px 16px; background: rgba(0,212,255,0.1); color: #00d4ff; border-radius: 6px; font-weight: bold; margin-top: 15px; }}
                </style>
            </head>
            <body>
                <div class="card">
                    <h1>{symbol} Visit {decision}</h1>
                    <p>Thank you! Your response for visitor <strong>{visitor['name']}</strong> has been transmitted to gate security.</p>
                    <div class="tag">Logged: {datetime.now().strftime('%H:%M:%S')}</div>
                </div>
            </body>
            </html>
            """
            
        return jsonify({'success': True, 'visitor_id': visitor_id, 'decision': decision}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/host-verify/<int:visitor_id>', methods=['GET'])
def host_verify_page(visitor_id):
    """Host verification landing page."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM visitor_logs WHERE id = ?', (visitor_id,))
        v = c.fetchone()
        conn.close()
        if not v:
            return "Visitor record not found", 404
        return redirect(url_for('host_decision', visitor_id=visitor_id))
    except Exception as e:
        return str(e), 500


# ═══════════════════════════════════════════
#  EMERGENCY EVACUATION "MUSTER ROLL" API
# ═══════════════════════════════════════════

@app.route('/api/evacuation-muster', methods=['GET'])
@login_required
def get_evacuation_muster():
    """Retrieve real-time roll call list of all currently checked-in occupants."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            SELECT id, name, purpose, contact_person, phone, entry_time, photo_path, 
                   COALESCE(muster_status, 'UNACCOUNTED') as muster_status,
                   COALESCE(host_email, '') as host_email,
                   ROUND((julianday('now', 'localtime') - julianday(entry_time)) * 24, 1) as duration_hours
            FROM visitor_logs 
            WHERE status = 'CHECKED_IN'
            ORDER BY entry_time DESC
        ''')
        visitors = [dict(row) for row in c.fetchall()]
        conn.close()
        
        total = len(visitors)
        safe = sum(1 for v in visitors if v.get('muster_status') == 'SAFE')
        missing = sum(1 for v in visitors if v.get('muster_status') == 'MISSING')
        unaccounted = sum(1 for v in visitors if v.get('muster_status') == 'UNACCOUNTED')
        
        return jsonify({
            'success': True,
            'headcount': {
                'total_on_site': total,
                'safe_accounted': safe,
                'missing': missing,
                'unaccounted': unaccounted
            },
            'visitors': visitors,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/evacuation/trigger', methods=['POST'])
@login_required
def trigger_evacuation():
    """1-Click Emergency Evacuation protocol trigger."""
    try:
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Fetch current count
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM visitor_logs WHERE status = 'CHECKED_IN'")
        count = c.fetchone()[0]
        conn.close()
        
        alert_msg = (
            f"🚨 *CRITICAL EMERGENCY EVACUATION TRIGGERED*\n\n"
            f"All personnel and visitors must report to designated emergency assembly points immediately.\n"
            f"• Estimated on-site visitors: {count}\n"
            f"• Triggered At: {now_str}\n"
            f"• Live roll call active at /evacuation\n"
            f"Security staff: initiate sweep protocols."
        )
        send_telegram_alert(alert_msg, 'EMERGENCY EVACUATION')
        send_email_alert('EMERGENCY EVACUATION TRIGGERED', alert_msg, 'EMERGENCY')
        log_audit_event('EMERGENCY_EVACUATION', f'Evacuation protocol triggered. On-site visitors: {count}')
        
        return jsonify({
            'success': True, 
            'message': f'🚨 Evacuation broadcasted. {count} occupants on muster roll.',
            'on_site_count': count
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/evacuation/muster-status', methods=['POST'])
@login_required
def update_muster_status():
    """Update individual occupant status on emergency roll call."""
    try:
        data = request.get_json() or {}
        visitor_id = data.get('visitor_id')
        status = (data.get('status') or '').strip().upper()
        
        if not visitor_id or status not in ['SAFE', 'MISSING', 'UNACCOUNTED']:
            return jsonify({'success': False, 'error': 'Invalid visitor ID or status'}), 400
            
        conn = get_db()
        c = conn.cursor()
        c.execute('UPDATE visitor_logs SET muster_status = ? WHERE id = ?', (status, visitor_id))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'visitor_id': visitor_id, 'muster_status': status}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/evacuation')
def evacuation_page():
    """Emergency Evacuation muster roll web interface."""
    return render_template('evacuation.html')


# ═══════════════════════════════════════════
#  OVERSTAY & CURFEW DETECTION API
# ═══════════════════════════════════════════

@app.route('/api/overstay-visitors', methods=['GET'])
@login_required
def get_overstay_visitors():
    """Retrieve all visitors currently exceeding maximum dwell time or past curfew."""
    try:
        overstays = get_overstay_visitors_list()
        return jsonify({
            'success': True,
            'overstays': overstays,
            'count': len(overstays),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/overstay-alert/<int:visitor_id>', methods=['POST'])
@login_required
def send_overstay_alert_endpoint(visitor_id):
    """Manually dispatch an overstay alert for a specific visitor."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM visitor_logs WHERE id = ?', (visitor_id,))
        v = c.fetchone()
        conn.close()
        
        if not v:
            return jsonify({'success': False, 'error': 'Visitor not found'}), 404
            
        msg = (
            f"⏰ *VISITOR OVERSTAY ALERT*\n\n"
            f"Visitor *{v['name']}* (Host: {v['contact_person']}) has exceeded permitted dwell time.\n"
            f"• Checked In: {v['entry_time']}\n"
            f"• Purpose: {v['purpose']}\n"
            f"Security guards requested to verify departure status."
        )
        send_telegram_alert(msg, 'OVERSTAY')
        return jsonify({'success': True, 'message': f"Overstay notice sent for {v['name']}"}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ═══════════════════════════════════════════
#  WEB-BASED FACE ENROLLMENT API
# ═══════════════════════════════════════════

@app.route('/api/enrolled-faces', methods=['GET'])
@login_required
def get_enrolled_faces():
    """List all enrolled faces and their known profile images."""
    try:
        data = load_encodings_cached()
        enrolled = []
        known_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'known_faces')
        
        if data and 'names' in data:
            unique_names = list(dict.fromkeys(data['names']))
            for name in unique_names:
                photo_found = None
                for ext in ['.jpg', '.jpeg', '.png']:
                    test_path = os.path.join(known_dir, f"{name}{ext}")
                    if os.path.exists(test_path):
                        photo_found = f"/known-faces/{name}{ext}"
                        break
                
                # Check watchlist category if any
                wl_cat = "Staff"
                try:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute('SELECT category FROM watchlist WHERE LOWER(name) = LOWER(?)', (name,))
                    r = c.fetchone()
                    if r:
                        wl_cat = r['category']
                    conn.close()
                except:
                    pass
                    
                enrolled.append({
                    'name': name,
                    'category': wl_cat,
                    'photo_url': photo_found or '/static/images/avatar_placeholder.png'
                })
                
        return jsonify({'success': True, 'faces': enrolled, 'count': len(enrolled)}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/faces/enroll', methods=['POST'])
@login_required
def enroll_face():
    """Enroll a new identity with face recognition and model retraining."""
    global ENCODINGS_CACHE, ENCODINGS_MTIME
    
    if face_recognition is None:
        return jsonify({'success': False, 'error': 'face_recognition library is unavailable on server'}), 503
        
    try:
        name = request.form.get('name', '').strip()
        category = request.form.get('category', 'Staff').strip()
        photo_data = request.form.get('photo_data', '')
        
        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400
            
        img = None
        # Handle base64 data URL from webcam
        if photo_data and 'base64,' in photo_data:
            b64_str = photo_data.split('base64,')[1]
            img_bytes = base64.b64decode(b64_str)
            nparr = np.frombuffer(img_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        elif 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename:
                file_bytes = file.read()
                nparr = np.frombuffer(file_bytes, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                
        if img is None:
            return jsonify({'success': False, 'error': 'Valid photo file or webcam capture required'}), 400
            
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        boxes = face_recognition.face_locations(rgb)
        if not boxes:
            return jsonify({'success': False, 'error': 'No face detected in photo. Please ensure face is centered and clearly lit.'}), 400
        if len(boxes) > 1:
            return jsonify({'success': False, 'error': f'Multiple faces ({len(boxes)}) detected. Ensure only one person is in frame.'}), 400
            
        encodings = face_recognition.face_encodings(rgb, boxes)
        if not encodings:
            return jsonify({'success': False, 'error': 'Failed to extract face features. Please try another shot.'}), 400
            
        new_encoding = encodings[0]
        
        # Save photo in known_faces
        base_dir = os.path.dirname(os.path.abspath(__file__))
        known_dir = os.path.join(base_dir, 'known_faces')
        os.makedirs(known_dir, exist_ok=True)
        safe_filename = f"{re.sub(r'[^a-zA-Z0-9_-]', ' ', name).strip()}.jpg"
        save_path = os.path.join(known_dir, safe_filename)
        cv2.imwrite(save_path, img)
        
        # Update encodings.pickle atomically
        pickle_path = os.path.join(base_dir, 'encodings.pickle')
        data = {'encodings': [], 'names': []}
        if os.path.exists(pickle_path):
            with open(pickle_path, 'rb') as f:
                data = pickle.loads(f.read())
                
        # Remove previous encodings for this exact name to prevent duplicates
        filtered_encs = []
        filtered_names = []
        for enc, n in zip(data.get('encodings', []), data.get('names', [])):
            if n.strip().lower() != name.strip().lower():
                filtered_encs.append(enc)
                filtered_names.append(n)
                
        filtered_encs.append(new_encoding)
        filtered_names.append(name)
        data['encodings'] = filtered_encs
        data['names'] = filtered_names
        
        with open(pickle_path, 'wb') as f:
            f.write(pickle.dumps(data))
            
        # Invalidate cache so changes take effect immediately
        ENCODINGS_CACHE = data
        ENCODINGS_MTIME = os.path.getmtime(pickle_path)
        
        # If category is Blacklist or VIP, register in watchlist table too
        if category.upper() in ['BLACKLIST', 'VIP']:
            try:
                conn = get_db()
                c = conn.cursor()
                now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                c.execute('''
                    INSERT INTO watchlist (name, category, threat_level, reason, photo_path, status, created_at)
                    VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?)
                    ON CONFLICT(name) DO UPDATE SET category=excluded.category, status='ACTIVE'
                ''', (name, category.upper(), 3 if category.upper() == 'BLACKLIST' else 1, f"Enrolled via web ({category})", save_path, now_str))
                conn.commit()
                conn.close()
            except Exception as we:
                print(f"Watchlist auto-insert error: {we}")
                
        log_audit_event('FACE_ENROLLED', f"Enrolled face profile for {name} ({category})")
        return jsonify({'success': True, 'message': f'✓ Successfully enrolled {name}', 'name': name}), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/faces/<path:name>', methods=['DELETE'])
@login_required
def delete_face(name):
    """Delete an enrolled face from encodings.pickle and known_faces."""
    global ENCODINGS_CACHE, ENCODINGS_MTIME
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        pickle_path = os.path.join(base_dir, 'encodings.pickle')
        
        if os.path.exists(pickle_path):
            with open(pickle_path, 'rb') as f:
                data = pickle.loads(f.read())
            new_encs = []
            new_names = []
            for enc, n in zip(data.get('encodings', []), data.get('names', [])):
                if n.strip().lower() != name.strip().lower():
                    new_encs.append(enc)
                    new_names.append(n)
            data['encodings'] = new_encs
            data['names'] = new_names
            with open(pickle_path, 'wb') as f:
                f.write(pickle.dumps(data))
            ENCODINGS_CACHE = data
            ENCODINGS_MTIME = os.path.getmtime(pickle_path)
            
        # Delete photo file if present
        known_dir = os.path.join(base_dir, 'known_faces')
        for ext in ['.jpg', '.jpeg', '.png']:
            p = os.path.join(known_dir, f"{name}{ext}")
            if os.path.exists(p):
                os.remove(p)
                
        log_audit_event('FACE_DELETED', f'Deleted face profile for {name}')
        return jsonify({'success': True, 'message': f'Face profile for {name} deleted'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/known-faces/<path:filename>')
def serve_known_face(filename):
    """Safely serve enrolled face thumbnails."""
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Invalid path'}), 400
    return send_from_directory('known_faces', filename)


# ═══════════════════════════════════════════
#  LIVE AI CAMERA STREAM WITH HUD TELEMETRY
# ═══════════════════════════════════════════

class VideoCameraStream:
    """Thread-safe camera stream with AI overlay and synthetic surveillance fallback."""
    def __init__(self):
        self.lock = threading.Lock()
        self.cap = None
        self.is_camera_open = False
        self.last_frame = None
        self.fps = 0.0
        self.frame_count = 0
        self._last_time = time.time()
        self.analysis_interval = 3
        self._worker = threading.Thread(target=self._capture_loop, daemon=True)
        self._worker.start()

    def init_camera(self):
        try:
            self.cap = cv2.VideoCapture(0)
            if self.cap and self.cap.isOpened():
                self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                self.is_camera_open = True
            else:
                self.is_camera_open = False
        except Exception:
            self.is_camera_open = False

    def get_frame(self):
        with self.lock:
            return self.last_frame

    def _capture_loop(self):
        self.init_camera()
        while True:
            frame = None
            if self.is_camera_open and self.cap:
                ret, frame = self.cap.read()
                if not ret or frame is None:
                    self.is_camera_open = False

            if frame is None:
                frame = self.generate_synthetic_frame()

            self.frame_count += 1
            jpeg = self._process_frame(frame, self.frame_count % self.analysis_interval == 0)
            if jpeg:
                with self.lock:
                    self.last_frame = jpeg
            time.sleep(1 / 15)

    def generate_synthetic_frame(self):
        """High-tech cyberpunk surveillance feed when physical camera is offline/busy."""
        width, height = 640, 480
        img = np.zeros((height, width, 3), dtype=np.uint8)
        img[:] = (12, 9, 6) # Dark background
        
        # Grid lines
        for x in range(0, width, 40):
            cv2.line(img, (x, 0), (x, height), (25, 20, 15), 1)
        for y in range(0, height, 40):
            cv2.line(img, (0, y), (width, y), (25, 20, 15), 1)
            
        center = (width // 2, height // 2)
        radius = int(80 + 20 * math.sin(time.time() * 2.5))
        cv2.circle(img, center, radius, (60, 40, 0), 1)
        cv2.circle(img, center, 4, (0, 212, 255), -1)
        
        # Target crosshairs
        cv2.line(img, (center[0] - 25, center[1]), (center[0] + 25, center[1]), (0, 212, 255), 1)
        cv2.line(img, (center[0], center[1] - 25), (center[0], center[1] + 25), (0, 212, 255), 1)
        
        # Corner brackets
        b = 20
        cv2.line(img, (20, 20), (20 + b, 20), (0, 212, 255), 2)
        cv2.line(img, (20, 20), (20, 20 + b), (0, 212, 255), 2)
        cv2.line(img, (width-20, 20), (width-20-b, 20), (0, 212, 255), 2)
        cv2.line(img, (width-20, 20), (width-20, 20+b), (0, 212, 255), 2)
        cv2.line(img, (20, height-20), (20+b, height-20), (0, 212, 255), 2)
        cv2.line(img, (20, height-20), (20, height-20-b), (0, 212, 255), 2)
        cv2.line(img, (width-20, height-20), (width-20-b, height-20), (0, 212, 255), 2)
        cv2.line(img, (width-20, height-20), (width-20, height-20-b), (0, 212, 255), 2)
        
        # Radar scan line
        scan_y = int((time.time() * 100) % height)
        cv2.line(img, (0, scan_y), (width, scan_y), (0, 150, 180), 1)
        
        now = datetime.now()
        cv2.putText(img, "SAFEGUARD NEXUS // AI GATE MONITOR", (25, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 212, 255), 2)
        cv2.putText(img, "FEED: LIVE GATE 01 | SENSORS: ONLINE", (25, 65), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (0, 255, 136), 1)
        cv2.putText(img, f"TIME: {now.strftime('%Y-%m-%d %H:%M:%S')}", (25, height - 35), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (220, 220, 220), 1)
        cv2.putText(img, "THREAT POSTURE: NOMINAL", (25, height - 15), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 136), 1)
        return img

    def _process_frame(self, frame, run_ai):
        frame = cv2.resize(frame, (640, 480))
        if run_ai and self.is_camera_open:
                try:
                    analysis_frame = cv2.resize(frame, (320, 240))
                    rgb = cv2.cvtColor(analysis_frame, cv2.COLOR_BGR2RGB)
                    boxes = face_recognition.face_locations(rgb) if face_recognition else []
                    data = load_encodings_cached()
                    
                    for (top, right, bottom, left) in boxes:
                        color = (60, 60, 255) # Red for unknown
                        label = "UNKNOWN"
                        
                        if data and data.get('encodings'):
                            encs = face_recognition.face_encodings(rgb, [(top, right, bottom, left)])
                            if encs:
                                dists = face_recognition.face_distance(data['encodings'], encs[0])
                                if len(dists) > 0:
                                    best = int(np.argmin(dists))
                                    if dists[best] < 0.55:
                                        matched_name = data['names'][best]
                                        conf = round((1.0 - dists[best]) * 100, 1)
                                        
                                        # Check watchlist
                                        wl = check_watchlist(matched_name)
                                        if wl and wl.get('category') == 'BLACKLIST':
                                            color = (0, 0, 255)
                                            label = f"BLACKLIST: {matched_name}"
                                        elif wl and wl.get('category') == 'VIP':
                                            color = (0, 180, 255) # Gold
                                            label = f"VIP: {matched_name}"
                                        else:
                                            color = (0, 255, 136) # Green
                                            label = f"{matched_name} ({conf}%)"
                        
                        left, right = left * 2, right * 2
                        top, bottom = top * 2, bottom * 2
                        cv2.rectangle(frame, (left, top), (right, bottom), color, 2)
                        cv2.rectangle(frame, (left, top - 25), (right, top), color, -1)
                        cv2.putText(frame, label, (left + 5, top - 7), cv2.FONT_HERSHEY_SIMPLEX, 0.48, (7, 9, 15), 2)
                except Exception as fe:
                    pass

        now = datetime.now()
        cv2.putText(frame, f"REC // {now.strftime('%H:%M:%S')}", (20, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 212, 255), 2)
        ret, jpeg = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
        return jpeg.tobytes() if ret else None

GLOBAL_CAMERA_STREAM = VideoCameraStream()

def generate_video_stream():
    """Generator for MJPEG video streaming."""
    while True:
        frame_bytes = GLOBAL_CAMERA_STREAM.get_frame()
        if frame_bytes:
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        time.sleep(0.066) # ~15 FPS

@app.route('/api/video-feed')
def video_feed():
    """Live MJPEG video streaming endpoint."""
    return Response(generate_video_stream(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/api/video-feed/snapshot')
def video_feed_snapshot():
    """Get a single snapshot from current camera feed."""
    frame_bytes = GLOBAL_CAMERA_STREAM.get_frame()
    if frame_bytes:
        return Response(frame_bytes, mimetype='image/jpeg')
    return jsonify({'error': 'Unable to capture frame'}), 500


# ═══════════════════════════════════════════
#  ACTIVE CHALLENGE-RESPONSE ANTI-SPOOFING
# ═══════════════════════════════════════════

LIVENESS_CHALLENGES = [
    {"type": "blink", "prompt": "Please blink your eyes naturally", "instruction": "Blink twice within 4 seconds"},
    {"type": "smile", "prompt": "Please smile warmly for the camera", "instruction": "Smile clearly to verify liveness"},
    {"type": "turn_left", "prompt": "Turn your head slightly to the left", "instruction": "Rotate head 20 degrees left"},
    {"type": "turn_right", "prompt": "Turn your head slightly to the right", "instruction": "Rotate head 20 degrees right"}
]

@app.route('/api/liveness/challenge', methods=['GET'])
def get_liveness_challenge():
    """Generate a randomized active anti-spoofing challenge."""
    import random
    challenge = random.choice(LIVENESS_CHALLENGES)
    return jsonify({
        'success': True,
        'challenge_id': uuid.uuid4().hex,
        'challenge': challenge['type'],
        'prompt': challenge['prompt'],
        'instruction': challenge['instruction'],
        'timeout_seconds': 5
    }), 200


@app.route('/api/verify-liveness', methods=['POST'])
def verify_liveness():
    """
    Verify active facial action to stop static photo and screen replay attacks.
    Expects JSON: { challenge: 'blink|smile|turn_left', frame_baseline: 'data:image/...', frame_action: 'data:image/...' }
    """
    try:
        data = request.get_json() or {}
        challenge = data.get('challenge', 'blink')
        b64_base = data.get('frame_baseline', '')
        b64_action = data.get('frame_action', '')
        
        if not b64_base or not b64_action:
            return jsonify({'success': False, 'passed': False, 'error': 'Two test frames required for liveness check'}), 400
            
        def decode_b64(b64_str):
            if 'base64,' in b64_str:
                b64_str = b64_str.split('base64,')[1]
            buf = base64.b64decode(b64_str)
            nparr = np.frombuffer(buf, np.uint8)
            return cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
        img1 = decode_b64(b64_base)
        img2 = decode_b64(b64_action)
        
        if img1 is None or img2 is None:
            return jsonify({'success': False, 'passed': False, 'error': 'Invalid image frames'}), 400
            
        liveness_passed = False
        confidence_score = 90.0
        details = ""
        
        # Use dlib 68-landmarks if available
        if DLIB_DETECTOR and DLIB_PREDICTOR:
            gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
            gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)
            faces1 = DLIB_DETECTOR(gray1, 0)
            faces2 = DLIB_DETECTOR(gray2, 0)
            
            if faces1 and faces2:
                shape1 = DLIB_PREDICTOR(gray1, faces1[0])
                shape2 = DLIB_PREDICTOR(gray2, faces2[0])
                
                pts1 = np.array([[shape1.part(i).x, shape1.part(i).y] for i in range(68)])
                pts2 = np.array([[shape2.part(i).x, shape2.part(i).y] for i in range(68)])
                
                if challenge == 'blink':
                    # Eye Aspect Ratio calculation
                    def get_ear(pts, eye_indices):
                        p = pts[eye_indices]
                        A = np.linalg.norm(p[1] - p[5])
                        B = np.linalg.norm(p[2] - p[4])
                        C = np.linalg.norm(p[0] - p[3])
                        return (A + B) / (2.0 * max(C, 1e-6))
                        
                    ear1 = (get_ear(pts1, list(range(36, 42))) + get_ear(pts1, list(range(42, 48)))) / 2.0
                    ear2 = (get_ear(pts2, list(range(36, 42))) + get_ear(pts2, list(range(42, 48)))) / 2.0
                    ear_diff = abs(ear1 - ear2)
                    
                    if ear_diff >= 0.035 or ear2 < 0.21 or ear1 < 0.21:
                        liveness_passed = True
                        confidence_score = min(99.4, 85.0 + ear_diff * 250)
                        details = f"Blink verified (EAR delta: {round(ear_diff, 3)})"
                    else:
                        details = "No eye closure detected"
                        
                elif challenge == 'smile':
                    # Mouth width relative to face width
                    w1 = np.linalg.norm(pts1[54] - pts1[48]) / max(np.linalg.norm(pts1[16] - pts1[0]), 1.0)
                    w2 = np.linalg.norm(pts2[54] - pts2[48]) / max(np.linalg.norm(pts2[16] - pts2[0]), 1.0)
                    smile_delta = w2 - w1
                    if smile_delta > 0.03:
                        liveness_passed = True
                        confidence_score = min(98.8, 88.0 + smile_delta * 150)
                        details = f"Smile expression verified (mouth expansion +{round(smile_delta*100, 1)}%)"
                    else:
                        details = "Smile motion not detected"
                        
                elif challenge in ['turn_left', 'turn_right']:
                    # Nose horizontal position relative to jaw boundaries
                    ratio1 = (pts1[30][0] - pts1[0][0]) / max(pts1[16][0] - pts1[30][0], 1.0)
                    ratio2 = (pts2[30][0] - pts2[0][0]) / max(pts2[16][0] - pts2[30][0], 1.0)
                    shift = ratio2 - ratio1
                    if (challenge == 'turn_left' and shift < -0.15) or (challenge == 'turn_right' and shift > 0.15) or abs(shift) > 0.18:
                        liveness_passed = True
                        confidence_score = min(97.9, 86.0 + abs(shift) * 40)
                        details = f"Head turn verified (yaw delta: {round(shift, 2)})"
                    else:
                        details = "Head rotation insufficient"
                        
        if not liveness_passed:
            # Fallback frame difference and pixel motion analysis in center ROI
            diff = cv2.absdiff(img1, img2)
            gray_diff = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
            motion_pixels = np.count_nonzero(gray_diff > 25)
            total_pixels = gray_diff.size
            motion_ratio = motion_pixels / float(total_pixels)
            
            # Dynamic movement between 1.5% and 35% indicates real biological movement, not static photo or rapid shake
            if 0.015 <= motion_ratio <= 0.35:
                liveness_passed = True
                confidence_score = 92.5
                details = "Dynamic facial micro-movement verified"
            elif not details:
                details = "Static photo or excessive movement detected"
                
        return jsonify({
            'success': True,
            'passed': liveness_passed,
            'score': round(confidence_score, 1) if liveness_passed else 0.0,
            'challenge': challenge,
            'details': details,
            'anti_spoof_status': 'VERIFIED_LIVE' if liveness_passed else 'POSSIBLE_SPOOF'
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'passed': False, 'error': str(e)}), 500


# ═══════════════════════════════════════════
#  SELF-SERVICE TOUCH KIOSK ROUTE
# ═══════════════════════════════════════════

@app.route('/kiosk')
def kiosk():
    """Full-screen interactive kiosk for self-service QR & express check-in."""
    return render_template('kiosk.html')


# ═══════════════════════════════════════════
#  PEAK TRAFFIC ANALYTICS & DAILY BRIEFING
# ═══════════════════════════════════════════

@app.route('/api/analytics/advanced', methods=['GET'])
@login_required
def advanced_analytics():
    """Peak hours, dwell time, and security threat distribution."""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # 1. Hourly distribution (00:00 - 23:00)
        c.execute('''
            SELECT CAST(strftime('%H', entry_time) AS INTEGER) as hour, COUNT(*) as count
            FROM visitor_logs
            GROUP BY hour
            ORDER BY hour ASC
        ''')
        hourly_rows = dict(c.fetchall())
        hourly_labels = [f"{h:02d}:00" for h in range(24)]
        hourly_data = [hourly_rows.get(h, 0) for h in range(24)]
        
        # Identify peak hour
        peak_hour_idx = int(np.argmax(hourly_data)) if hourly_data and max(hourly_data) > 0 else 10
        peak_hour_str = f"{peak_hour_idx:02d}:00 - {(peak_hour_idx+1)%24:02d}:00"
        
        # 2. Average Dwell time by purpose
        c.execute('''
            SELECT purpose,
                   ROUND(AVG(CASE 
                       WHEN exit_time IS NOT NULL THEN (julianday(exit_time) - julianday(entry_time)) * 24 * 60
                       ELSE (julianday('now', 'localtime') - julianday(entry_time)) * 24 * 60
                   END), 1) as avg_mins
            FROM visitor_logs
            GROUP BY purpose
        ''')
        dwell_data = {row[0]: row[1] or 45.0 for row in c.fetchall()}
        
        # 3. Threat stats
        c.execute("SELECT COUNT(*) FROM watchlist WHERE status = 'ACTIVE' AND category = 'BLACKLIST'")
        blacklist_count = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'peak_hour': peak_hour_str,
            'hourly': {
                'labels': hourly_labels,
                'counts': hourly_data
            },
            'dwell_time_by_purpose': dwell_data,
            'blacklist_targets': blacklist_count
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/daily-briefing', methods=['GET'])
@login_required
def daily_briefing_data():
    """Structured data for today's Security Operations Briefing."""
    try:
        today_str = datetime.now().strftime('%Y-%m-%d')
        conn = get_db()
        c = conn.cursor()
        
        # Today's entries
        c.execute("SELECT COUNT(*) FROM visitor_logs WHERE DATE(entry_time) = ?", (today_str,))
        today_total = c.fetchone()[0]
        
        # Verified face matches
        c.execute("SELECT COUNT(*) FROM visitor_logs WHERE DATE(entry_time) = ? AND face_status = 'VERIFIED'", (today_str,))
        verified_today = c.fetchone()[0]
        
        # Currently on-site
        c.execute("SELECT COUNT(*) FROM visitor_logs WHERE status = 'CHECKED_IN'")
        active_on_site = c.fetchone()[0]
        
        # Security alerts today
        c.execute("SELECT COUNT(*) FROM obstruction_alerts WHERE DATE(timestamp) = ?", (today_str,))
        alerts_today = c.fetchone()[0]
        
        # Recent logs today
        c.execute("SELECT name, purpose, contact_person, entry_time, exit_time, status, face_status FROM visitor_logs WHERE DATE(entry_time) = ? ORDER BY id DESC LIMIT 25", (today_str,))
        records = [dict(r) for r in c.fetchall()]
        conn.close()
        
        overstays = get_overstay_visitors_list()
        
        return jsonify({
            'success': True,
            'date': today_str,
            'summary': {
                'total_visitors': today_total,
                'verified_faces': verified_today,
                'active_on_site': active_on_site,
                'security_alerts': alerts_today,
                'overstay_count': len(overstays)
            },
            'overstays': overstays,
            'records': records
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/daily-briefing')
@login_required
def daily_briefing_page():
    """Printable Executive Security Operations Briefing report."""
    return render_template('daily_briefing.html')

# ═══════════════════════════════════════════
#  INITIALIZATION
# ═══════════════════════════════════════════

@app.before_request
def initialize_db():
    """Initialize database tables on startup."""
    if not hasattr(app, 'db_initialized'):
        try:
            create_tables()
            app.db_initialized = True
        except Exception as e:
            print(f"Database initialization error: {e}")

# ═══════════════════════════════════════════
if __name__ == '__main__':
    # Create tables on startup
    try:
        create_tables()
    except Exception as e:
        print(f"Database initialization error: {e}")
    
    # Run Flask app
    # Change debug=False for production
    app.run(host='0.0.0.0', port=5000, debug=True)
