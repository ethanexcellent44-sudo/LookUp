import face_recognition
import cv2
import pickle
import time
import threading
import subprocess
import os
import csv
import psutil
import numpy as np
import sqlite3
import importlib
import customtkinter as ctk
import dlib
import smtplib
import requests
import matplotlib.pyplot as plt
from tkinter.scrolledtext import ScrolledText
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from scipy.spatial import distance as dist
from PIL import Image, ImageTk, ImageDraw, ImageFilter
from datetime import datetime, timedelta
from tkinter import ttk, messagebox, filedialog
import tkinter as tk

# ══════════════════════════════════════════
#  DESIGN TOKENS  ── "NEXUS TERMINAL" Theme
# ══════════════════════════════════════════
THEME = {
    "bg":           "#07090f",
    "sidebar":      "#0b0e18",
    "card":         "#0f1422",
    "card_hover":   "#141929",
    "border":       "#1a2540",
    "accent":       "#00d4ff",
    "accent_dim":   "#004d5e",
    "success":      "#00ff88",
    "danger":       "#ff3d3d",
    "warning":      "#ffb700",
    "muted":        "#4a5568",
    "text":         "#e2e8f0",
    "text_dim":     "#718096",
    "font_mono":    "Consolas",
    "font_display": "Consolas",
}

THREAT_LEVELS = {
    0: ("NOMINAL",  "#00ff88", "▓▒░░░"),
    1: ("ELEVATED", "#e4b12f", "▓▓▒░░"),
    2: ("HIGH",     "#ff8c00", "▓▓▓▒░"),
    3: ("CRITICAL", "#ff3d3d", "▓▓▓▓▓"),
}

# ══════════════════════════════════════════════
#  1. ALERT MANAGER
# ══════════════════════════════════════════════
class AlertManager:
    def __init__(self):
        self.email_sender   = os.environ.get("SENDER_EMAIL", "")
        self.email_password = os.environ.get("SENDER_PASSWORD", "")
        self.email_receiver = os.environ.get("ALERT_EMAIL", "")
        self.tg_token       = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.tg_chat_id     = os.environ.get("TELEGRAM_CHAT_ID", "")

    def send_telegram(self, message):
        try:
            url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
            requests.post(url, data={"chat_id": self.tg_chat_id, "text": message}, timeout=10)
        except Exception as e:
            print(f"[TG] {e}")

    def send_email_with_evidence(self, subject, message, image_path):
        try:
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From']    = self.email_sender
            msg['To']      = self.email_receiver
            msg.attach(MIMEText(message))
            if image_path and os.path.exists(image_path):
                with open(image_path, 'rb') as f:
                    img = MIMEImage(f.read(), name=os.path.basename(image_path))
                    msg.attach(img)
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
                s.login(self.email_sender, self.email_password)
                s.send_message(msg)
        except Exception as e:
            print(f"[Email] {e}")

    def send_email_report(self, subject, message):
        try:
            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From']    = self.email_sender
            msg['To']      = self.email_receiver
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
                s.login(self.email_sender, self.email_password)
                s.send_message(msg)
        except Exception as e:
            print(f"[Email] {e}")

    def trigger_all_alerts(self, name, image_path=None):
        ts  = datetime.now().strftime("%H:%M:%S")
        msg = f"🛡️ SAFEGUARD ALERT: {name} detected at {ts}."
        threading.Thread(target=self.send_telegram,           args=(msg,),             daemon=True).start()
        threading.Thread(target=self.send_email_with_evidence,args=("Security Breach", msg, image_path), daemon=True).start()


# ══════════════════════════════════════════════
#  2. DATABASE
# ══════════════════════════════════════════════
class SafeguardDB:
    def __init__(self):
        self.conn = sqlite3.connect("safeguard_vault.db", check_same_thread=False)
        self._create_tables()

    def _create_tables(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, date TEXT, time TEXT, status TEXT,
            confidence REAL, image_path TEXT)''')
        self.conn.commit()

    def insert_log(self, name, status, conf, path):
        now = datetime.now()
        self.conn.execute(
            "INSERT INTO logs (name,date,time,status,confidence,image_path) VALUES (?,?,?,?,?,?)",
            (name, now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S"), status, conf, path))
        self.conn.commit()

    def get_weekly_stats(self):
        dates, counts = [], []
        for i in range(6, -1, -1):
            d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            cnt = self.conn.execute("SELECT COUNT(*) FROM logs WHERE date=?", (d,)).fetchone()[0]
            dates.append(d[-5:]); counts.append(cnt)
        return dates, counts

    def get_status_distribution(self):
        return self.conn.execute("SELECT status, COUNT(*) FROM logs GROUP BY status").fetchall()

    def get_summary_metrics(self):
        total  = self.conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        alerts = self.conn.execute("SELECT COUNT(*) FROM logs WHERE status='BREACH' OR name='UNKNOWN'").fetchone()[0]
        rate   = round(((total - alerts) / total * 100), 1) if total else 0
        return total, alerts, rate

    def get_hourly_activity(self):
        data   = dict(self.conn.execute("SELECT SUBSTR(time,1,2), COUNT(*) FROM logs GROUP BY SUBSTR(time,1,2)").fetchall())
        hours  = [f"{h:02d}" for h in range(24)]
        counts = [data.get(h, 0) for h in hours]
        return hours, counts

    def get_recent_logs(self, limit=8):
        return self.conn.execute(
            "SELECT name, time, status, confidence FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def search_logs(self, name_filter="", status_filter="ALL"):
        q = "SELECT id,name,date,time,status,confidence FROM logs WHERE 1=1"
        params = []
        if name_filter:
            q += " AND name LIKE ?"; params.append(f"%{name_filter}%")
        if status_filter != "ALL":
            q += " AND status=?"; params.append(status_filter)
        q += " ORDER BY id DESC LIMIT 200"
        return self.conn.execute(q, params).fetchall()

    def export_csv(self, filepath):
        rows = self.conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
        with open(filepath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID","Name","Date","Time","Status","Confidence","ImagePath"])
            w.writerows(rows)

    def check_watchlist(self, name):
        """Check if person is listed on the active watchlist or blacklist."""
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT category, threat_level, reason FROM watchlist WHERE status='ACTIVE' AND LOWER(name)=LOWER(?)", (name,))
            return cur.fetchone()
        except:
            return None


class LLMAssistant:
    def __init__(self, model_path="", device="cpu", compression=None):
        self.model_path = model_path or ""
        self.device = device
        self.compression = compression
        self.model = None
        self.tokenizer = None
        self.available = self._check_availability()
        if self.available and self.model_path:
            self.load_model(self.model_path)

    @staticmethod
    def _check_availability():
        return importlib.util.find_spec("airllm") is not None

    def load_model(self, model_path=""):
        if model_path:
            self.model_path = model_path
        if not self.available or not self.model_path:
            return False
        try:
            from airllm import AutoModel
            self.model = AutoModel.from_pretrained(
                self.model_path,
                device=self.device,
                compression=self.compression
            )
            self.tokenizer = getattr(self.model, "tokenizer", None)
            return self.model is not None and self.tokenizer is not None
        except Exception as e:
            print(f"[LLM] Failed to load model: {e}")
            self.model = None
            self.tokenizer = None
            return False

    def is_ready(self):
        return self.model is not None and self.tokenizer is not None

    def generate(self, prompt, max_new_tokens=256, temperature=0.0):
        if not self.is_ready():
            return None
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True,
                                     padding=True, max_length=1024)
            input_ids = inputs["input_ids"]
            outputs = self.model.generate(
                input_ids,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=False
            )
            text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            return text.strip()
        except Exception as e:
            print(f"[LLM] Generation error: {e}")
            return None


# ══════════════════════════════════════════════
#  3. ENGINE
# ══════════════════════════════════════════════════════
class SafeguardEngine:
    def __init__(self, data_path="encodings.pickle"):
        self.base_dir   = os.path.dirname(os.path.abspath(__file__))
        self.data_path  = os.path.join(self.base_dir, data_path)
        for folder in ["snapshots/verified","snapshots/strangers","known_faces"]:
            os.makedirs(os.path.join(self.base_dir, folder), exist_ok=True)
        self.db      = SafeguardDB()
        self.alerts  = AlertManager()
        self.detector  = dlib.get_frontal_face_detector()
        self.predictor = None
        self.load_encodings()
        # Object Detection Setup (YOLOv3)
        self.object_detection_enabled = True
        self.yolo_net = None
        self.yolo_classes = []
        self.yolo_output_layers = []
        # Config (editable in Settings)
        self.EYE_AR_THRESH        = 0.20
        self.CONFIDENCE_THRESHOLD = 0.50
        self.alert_cooldown_secs  = 300
        self.mask_detection_enabled = True
        self.mask_alert_cooldown_secs = 180
        self.camera_index         = 1
        self.camera_mode          = "single"  # single or all
        self.llm_enabled          = False
        self.llm_model_path       = ""
        self.llm_auto_report      = False
        self.llm                  = LLMAssistant()
        self.low_power_mode       = False
        # State
        self.blink_counter      = {}
        self.attendance_cooldown= {}
        self.alert_cooldown     = 0
        self.mask_alert_cooldown= 0
        self.running            = False
        self.threat_level       = 0   # 0-3
        self.face_count         = 0
        self.fps                = 0
        self._last_frame_time   = time.time()
        self.analysis_interval  = 3
        self.analysis_size      = (320, 240)

    def ensure_runtime_models(self):
        """Load heavyweight models only when the live monitor is opened."""
        if self.predictor is None:
            predictor_path = os.path.join(self.base_dir, "shape_predictor_68_face_landmarks.dat")
            if os.path.exists(predictor_path):
                self.predictor = dlib.shape_predictor(predictor_path)
        if self.yolo_net is None and self.object_detection_enabled:
            self.load_yolo_model()

    def load_encodings(self):
        if os.path.exists(self.data_path):
            with open(self.data_path, "rb") as f:
                self.data = pickle.loads(f.read())
        else:
            self.data = {"encodings": [], "names": []}

    def save_new_face(self, name, frame):
        img_path = os.path.join(self.base_dir, "known_faces", f"{name}.jpg")
        cv2.imwrite(img_path, frame)
        rgb  = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        boxes = face_recognition.face_locations(rgb)
        encs  = face_recognition.face_encodings(rgb, boxes)
        if encs:
            self.data["encodings"].append(encs[0])
            self.data["names"].append(name)
            with open(self.data_path, "wb") as f:
                f.write(pickle.dumps(self.data))
            return True
        return False

    def build_incident_prompt(self, logs):
        lines = []
        for entry in logs[-20:]:
            _, name, date, t, status, conf = entry
            lines.append(f"{date} {t} — {status} — {name} — {round(conf or 0, 1)}%")
        details = "\n".join(lines)
        prompt = (
            "You are a security operations analyst. "
            "Review the following security event log entries and produce a concise incident report. "
            "Describe the current threat posture, any repeated unknown or breach activity, "
            "and provide recommendations for follow-up actions.\n\n"
            "Log Entries:\n" + details +
            "\n\nGenerate a professional incident summary, keep it under 250 words."
        )
        return prompt

    def fallback_incident_summary(self, logs):
        total = len(logs)
        breaches = sum(1 for entry in logs if entry[4] in ("BREACH", "UNKNOWN", "MASK ALERT"))
        verified = sum(1 for entry in logs if entry[4] == "VERIFIED")
        unknown = sum(1 for entry in logs if entry[1] == "UNKNOWN")
        recommendations = []
        if breaches:
            recommendations.append("Investigate the latest breach events and verify suspicious object handling.")
        if self.mask_detection_enabled:
            recommendations.append("Maintain mask detection and review masked face alerts for possible disguise attempts.")
        if verified:
            recommendations.append("Continue logging verified access and rotate authorized face profiles regularly.")
        if not recommendations:
            recommendations.append("Continue monitoring the area and verify camera calibration.")
        summary = [
            f"Total events: {total}",
            f"Breach or unknown events: {breaches}",
            f"Verified access events: {verified}",
            f"Distinct unknown entries: {unknown}",
            "Recommendations:",
        ]
        summary.extend([f"- {item}" for item in recommendations])
        return "\n".join(summary)

    def generate_incident_report(self, logs=None):
        if logs is None:
            logs = self.db.search_logs()
        if not logs:
            return "No incident events available to summarize."
        if self.llm_enabled and self.llm_model_path and (
            self.llm.is_ready() or self.llm.load_model(self.llm_model_path)
        ):
            prompt = self.build_incident_prompt(logs)
            report = self.llm.generate(prompt, max_new_tokens=256)
            if report:
                return report
        return self.fallback_incident_summary(logs)

    def send_incident_report(self, logs=None):
        report = self.generate_incident_report(logs)
        if self.llm_auto_report and report:
            threading.Thread(target=self.alerts.send_email_report,
                             args=("Automated Security Incident Report", report),
                             daemon=True).start()
        return report

    def eye_aspect_ratio(self, eye):
        A = dist.euclidean(eye[1], eye[5])
        B = dist.euclidean(eye[2], eye[4])
        C = dist.euclidean(eye[0], eye[3])
        return (A + B) / (2.0 * C)

    def speak(self, text):
        threading.Thread(
            target=lambda: subprocess.run(
                ['espeak-ng', '-v', 'en-us+f2', '-s', '150', text],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
            daemon=True).start()

    def update_fps(self):
        now  = time.time()
        self.fps = round(1.0 / max(now - self._last_frame_time, 0.001))
        self._last_frame_time = now

    def detect_mask_or_face_cover(self, frame, shape):
        # Lower-face area around the nose and mouth
        bottom_face = np.vstack((shape[27:36], shape[48:68]))
        x1 = max(int(bottom_face[:, 0].min()) - 10, 0)
        y1 = max(int(bottom_face[:, 1].min()) - 10, 0)
        x2 = min(int(bottom_face[:, 0].max()) + 10, frame.shape[1] - 1)
        y2 = min(int(bottom_face[:, 1].max()) + 10, frame.shape[0] - 1)

        if x2 <= x1 or y2 <= y1:
            return False

        # Full lower half of the face to catch masks and coverings
        center_y = int((shape[27][1] + shape[8][1]) / 2)
        x3 = max(int(shape[0][0]) - 10, 0)
        y3 = center_y
        x4 = min(int(shape[16][0]) + 10, frame.shape[1] - 1)
        y4 = min(int(shape[8][1]) + 10, frame.shape[0] - 1)

        def low_detail_area(roi):
            if roi.size == 0:
                return False
            gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
            gray = cv2.GaussianBlur(gray, (7, 7), 0)
            edges = cv2.Canny(gray, 50, 150)
            edge_ratio = np.count_nonzero(edges) / float(edges.size + 1)
            variance = np.var(gray) / 255.0
            return edge_ratio < 0.018 or variance < 0.012

        lower_face_roi = frame[y1:y2, x1:x2]
        mid_face_roi   = frame[y3:y4, x3:x4]

        lower_face_low = low_detail_area(lower_face_roi)
        mid_face_low   = low_detail_area(mid_face_roi)

        return lower_face_low or mid_face_low

    def load_yolo_model(self):
        """Load YOLOv3 model for object detection."""
        try:
            config_path = os.path.join(self.base_dir, "yolov3.cfg")
            weights_path = os.path.join(self.base_dir, "yolov3.weights")
            classes_path = os.path.join(self.base_dir, "coco.names")

            if not all(os.path.exists(p) for p in [config_path, weights_path, classes_path]):
                print("[YOLO] Model files not found. Object detection disabled.")
                self.object_detection_enabled = False
                return

            self.yolo_net = cv2.dnn.readNetFromDarknet(config_path, weights_path)
            self.yolo_net.setPreferableBackend(cv2.dnn.DNN_BACKEND_OPENCV)
            self.yolo_net.setPreferableTarget(cv2.dnn.DNN_TARGET_CPU)
            layer_names = self.yolo_net.getLayerNames()
            self.yolo_output_layers = [layer_names[i - 1] for i in self.yolo_net.getUnconnectedOutLayers()]

            with open(classes_path, 'r') as f:
                self.yolo_classes = [line.strip() for line in f.readlines()]
        except Exception as e:
            print(f"[YOLO] Failed to load model: {e}")
            self.object_detection_enabled = False

    def detect_objects(self, frame):
        """Detect objects in frame using YOLO."""
        if not self.object_detection_enabled or self.yolo_net is None:
            return []

        height, width = frame.shape[:2]
        blob = cv2.dnn.blobFromImage(frame, 1/255.0, (416, 416), swapRB=True, crop=False)
        self.yolo_net.setInput(blob)

        outputs = self.yolo_net.forward(self.yolo_output_layers)

        boxes, confidences, class_ids = [], [], []
        for output in outputs:
            for detection in output:
                scores = detection[5:]
                class_id = np.argmax(scores)
                confidence = scores[class_id]
                if confidence > 0.5:  # Confidence threshold
                    center_x = int(detection[0] * width)
                    center_y = int(detection[1] * height)
                    w = int(detection[2] * width)
                    h = int(detection[3] * height)
                    x = int(center_x - w / 2)
                    y = int(center_y - h / 2)
                    boxes.append([x, y, w, h])
                    confidences.append(float(confidence))
                    class_ids.append(class_id)

        indices = cv2.dnn.NMSBoxes(boxes, confidences, 0.5, 0.4)
        detected_objects = []
        if len(indices) > 0:
            for i in indices.flatten():
                detected_objects.append({
                    'class': self.yolo_classes[class_ids[i]],
                    'confidence': confidences[i],
                    'box': boxes[i]
                })
        return detected_objects

    def detect_persons_and_objects(self, frame):
        """Hybrid approach: Use YOLO to detect persons first, then run face recognition on person ROIs."""
        if not self.object_detection_enabled or self.yolo_net is None:
            # Fallback to traditional face recognition if YOLO not available
            return self._traditional_face_recognition(frame)

        # Step 1: Run YOLO to detect all objects
        all_objects = self.detect_objects(frame)

        # Step 2: Separate persons from other objects
        persons = [obj for obj in all_objects if obj['class'] == 'person']
        suspicious_objects = [obj for obj in all_objects if obj['class'] in [
            'knife', 'gun', 'backpack', 'handbag', 'suitcase', 'bottle',
            'scissors', 'hammer', 'bat', 'umbrella', 'cell phone'
        ]]

        # Step 3: For each detected person, run face recognition on their ROI
        face_results = []
        for person in persons:
            x, y, w, h = person['box']

            # Extract person ROI with some padding
            padding = 20
            x1 = max(0, x - padding)
            y1 = max(0, y - padding)
            x2 = min(frame.shape[1], x + w + padding)
            y2 = min(frame.shape[0], y + h + padding)

            person_roi = frame[y1:y2, x1:x2]

            if person_roi.size == 0:
                continue

            # Run face recognition on this person ROI
            face_result = self._face_recognition_on_roi(person_roi, (x1, y1, x2, y2))
            if face_result:
                face_results.append(face_result)

        # Step 4: Check for suspicious objects near persons
        person_alerts = []
        for person in persons:
            px, py, pw, ph = person['box']
            person_center = (px + pw/2, py + ph/2)

            # Check if suspicious objects are near this person
            nearby_objects = []
            for obj in suspicious_objects:
                ox, oy, ow, oh = obj['box']
                obj_center = (ox + ow/2, oy + oh/2)

                # Calculate distance between centers
                distance = np.sqrt((person_center[0] - obj_center[0])**2 + (person_center[1] - obj_center[1])**2)

                # If object is within reasonable distance of person (e.g., 200 pixels)
                if distance < 200:
                    nearby_objects.append(obj)

            if nearby_objects:
                person_alerts.append({
                    'person': person,
                    'nearby_objects': nearby_objects
                })

        return {
            'face_results': face_results,
            'person_alerts': person_alerts,
            'all_objects': all_objects
        }

    def _face_recognition_on_roi(self, roi, offset):
        """Run face recognition on a specific region of interest."""
        if roi.size == 0:
            return None

        # Resize ROI for face detection (maintain aspect ratio)
        height, width = roi.shape[:2]
        max_size = 320
        if width > height:
            new_width = max_size
            new_height = int(height * max_size / width)
        else:
            new_height = max_size
            new_width = int(width * max_size / height)

        roi_small = cv2.resize(roi, (new_width, new_height))
        rgb_roi = cv2.cvtColor(roi_small, cv2.COLOR_BGR2RGB)

        # Detect faces in ROI
        face_locs = face_recognition.face_locations(rgb_roi)
        face_encs = face_recognition.face_encodings(rgb_roi, face_locs)

        if not face_encs:
            return None

        # Scale factor for coordinates
        scale_x = width / new_width
        scale_y = height / new_height

        results = []
        for (top, right, bottom, left), enc in zip(face_locs, face_encs):
            # Scale back to original ROI coordinates
            top = int(top * scale_y)
            right = int(right * scale_x)
            bottom = int(bottom * scale_y)
            left = int(left * scale_x)

            # Convert to global frame coordinates
            global_top = offset[1] + top
            global_right = offset[0] + right
            global_bottom = offset[1] + bottom
            global_left = offset[0] + left

            # Face recognition
            dists = face_recognition.face_distance(self.data["encodings"], enc)
            name = "UNKNOWN"; conf = 0
            if len(dists) > 0:
                best = np.argmin(dists)
                if dists[best] < self.CONFIDENCE_THRESHOLD:
                    name = self.data["names"][best]
                    conf = (1.0 - dists[best]) * 100

            results.append({
                'name': name,
                'confidence': conf,
                'box': (global_left, global_top, global_right, global_bottom),
                'encoding': enc
            })

        return results[0] if results else None

    def _traditional_face_recognition(self, frame):
        """Fallback to traditional face recognition when YOLO is not available."""
        small = cv2.resize(frame, (320, 240))
        rgb_small = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
        locs = face_recognition.face_locations(rgb_small)
        encs = face_recognition.face_encodings(rgb_small, locs)

        face_results = []
        scale = frame.shape[0] / small.shape[0]
        for (top, right, bottom, left), enc in zip(locs, encs):
            top = int(top * scale)
            right = int(right * scale)
            bottom = int(bottom * scale)
            left = int(left * scale)

            dists = face_recognition.face_distance(self.data["encodings"], enc)
            name = "UNKNOWN"; conf = 0
            if len(dists) > 0:
                best = np.argmin(dists)
                if dists[best] < self.CONFIDENCE_THRESHOLD:
                    name = self.data["names"][best]
                    conf = (1.0 - dists[best]) * 100

            face_results.append({
                'name': name,
                'confidence': conf,
                'box': (left, top, right, bottom),
                'encoding': enc
            })

        return {
            'face_results': face_results,
            'person_alerts': [],
            'all_objects': []
        }

    def calculate_threat_score(self):
        """Calculate threat score based on recent activity."""
        # Get last 24 hours of logs
        now = datetime.now()
        yesterday = now - timedelta(hours=24)
        recent_logs = self.db.conn.execute(
            "SELECT status, date, time FROM logs WHERE date >= ? ORDER BY id DESC",
            (yesterday.strftime("%Y-%m-%d"),)
        ).fetchall()

        breach_count = sum(1 for log in recent_logs if log[0] in ('BREACH', 'MASK ALERT'))
        total_count = len(recent_logs)

        # Time-based weighting (more recent = higher weight)
        threat_score = 0
        for log in recent_logs[:50]:  # Last 50 events
            status, date_str, time_str = log
            log_time = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
            hours_ago = (now - log_time).total_seconds() / 3600
            weight = max(0, 1 - hours_ago / 24)  # Linear decay over 24 hours
            if status in ('BREACH', 'MASK ALERT'):
                threat_score += weight * 10
            elif status == 'UNKNOWN':
                threat_score += weight * 5

        # Normalize to 0-100 scale
        threat_score = min(100, threat_score)
        return round(threat_score, 1)


# ══════════════════════════════════════════════
#  HELPER WIDGETS
# ══════════════════════════════════════════════
class NexusCard(ctk.CTkFrame):
    """Styled card with optional left-border accent."""
    def __init__(self, parent, accent_color=None, **kw):
        kw.setdefault("fg_color",      THEME["card"])
        kw.setdefault("corner_radius", 10)
        kw.setdefault("border_width",  1)
        kw.setdefault("border_color",  accent_color or THEME["border"])
        super().__init__(parent, **kw)


class PulsingDot(ctk.CTkCanvas):
    """Animated pulsing status dot."""
    def __init__(self, parent, color=THEME["success"], size=14, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=THEME["sidebar"], highlightthickness=0, **kw)
        self._color = color
        self._size  = size
        self._step  = 0
        self._draw()

    def _draw(self):
        self.delete("all")
        alpha = abs(np.sin(self._step * 0.15))
        r     = int(self._size * (0.35 + 0.15 * alpha))
        cx    = self._size // 2
        self.create_oval(cx-r, cx-r, cx+r, cx+r, fill=self._color, outline="")
        self._step += 1
        self.after(60, self._draw)


class ToastNotification:
    """Temporary popup banner at top-right."""
    def __init__(self, root, message, kind="info"):
        colors = {"info": THEME["accent"], "danger": THEME["danger"],
                  "success": THEME["success"], "warn": THEME["warning"]}
        color  = colors.get(kind, THEME["accent"])
        self.win = ctk.CTkToplevel(root)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.configure(fg_color=THEME["card"])
        sw = root.winfo_screenwidth(); sh = root.winfo_screenheight()
        w, h = 320, 64
        self.win.geometry(f"{w}x{h}+{sw-w-20}+{sh-h-60}")
        bar = ctk.CTkFrame(self.win, height=3, fg_color=color, corner_radius=0)
        bar.pack(fill="x", side="top")
        ctk.CTkLabel(self.win, text=message,
                     font=(THEME["font_mono"], 11), wraplength=300,
                     text_color=THEME["text"]).pack(padx=10, pady=8)
        self.win.after(3500, self.win.destroy)


# ══════════════════════════════════════════════
#  4. MAIN DASHBOARD
# ══════════════════════════════════════════════
class SafeguardDashboard(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("SAFEGUARD NEXUS  ·  v4.0")
        self.geometry("1440x920")
        self.minsize(1100, 700)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=THEME["bg"])
        self.engine = SafeguardEngine()
        self.cap    = None
        self.caps   = []
        self._processed_frame = None
        self._last_frame      = None
        self._video_thread    = None
        self._stop_event      = threading.Event()
        self._frame_lock      = threading.Lock()
        self._pending_events  = []
        self._active_nav = None
        self._show_login()
        # After IDs for cancellation
        self._video_after_id = None
        self._clock_after_id = None
        self._health_after_id = None
        self._activity_after_id = None
        self._reg_video_after_id = None
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ─── LOGIN ──────────────────────────────
    def _show_login(self):
        self._login_outer = ctk.CTkFrame(self, fg_color=THEME["bg"])
        self._login_outer.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Background grid lines (canvas)
        canvas = tk.Canvas(self._login_outer, bg=THEME["bg"], highlightthickness=0)
        canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        for x in range(0, 1440, 60):
            canvas.create_line(x, 0, x, 920, fill="#0d1420", width=1)
        for y in range(0, 920, 60):
            canvas.create_line(0, y, 1440, y, fill="#0d1420", width=1)

        box = NexusCard(self._login_outer, accent_color=THEME["accent"],
                        width=420, height=380)
        box.place(relx=0.5, rely=0.5, anchor="center")

        # Logo / Title
        ctk.CTkLabel(box, text="⬡ SAFEGUARD NEXUS",
                     font=(THEME["font_display"], 26, "bold"),
                     text_color=THEME["accent"]).pack(pady=(36, 4))
        ctk.CTkLabel(box, text="VISUAL INTELLIGENCE PLATFORM  v4.0",
                     font=(THEME["font_mono"], 11),
                     text_color=THEME["muted"]).pack()

        sep = ctk.CTkFrame(box, height=1, fg_color=THEME["border"])
        sep.pack(fill="x", padx=30, pady=20)

        ctk.CTkLabel(box, text="OPERATOR CREDENTIALS",
                     font=(THEME["font_mono"], 11),
                     text_color=THEME["text_dim"]).pack()

        self._pw_entry = ctk.CTkEntry(
            box, placeholder_text="Enter access code",
            show="●", width=280, height=44,
            font=(THEME["font_mono"], 13),
            fg_color=THEME["bg"], border_color=THEME["border"],
            text_color=THEME["text"])
        self._pw_entry.pack(pady=14)
        self._pw_entry.bind("<Return>", lambda e: self._check_login())

        ctk.CTkButton(
            box, text="AUTHENTICATE  →", width=280, height=44,
            font=(THEME["font_mono"], 13, "bold"),
            fg_color=THEME["accent_dim"], hover_color=THEME["accent"],
            text_color=THEME["accent"], border_width=1,
            border_color=THEME["accent"],
            command=self._check_login).pack(pady=4)

        ctk.CTkLabel(box, text="Authorized Personnel Only",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["muted"]).pack(pady=16)

    def _check_login(self):
        if self._pw_entry.get() == "admin123":
            self._login_outer.destroy()
            self._build_ui()
        else:
            ToastNotification(self, "⛔  Access Denied — Invalid Credentials", "danger")

    # ─── MAIN SHELL ─────────────────────────
    def _build_ui(self):
        # ── Top Header Bar ──
        self._header = ctk.CTkFrame(self, height=52, fg_color=THEME["sidebar"],
                                    corner_radius=0)
        self._header.pack(fill="x", side="top")
        ctk.CTkLabel(self._header, text="⬡  SAFEGUARD NEXUS",
                     font=(THEME["font_display"], 18, "bold"),
                     text_color=THEME["accent"]).pack(side="left", padx=20)
        ctk.CTkLabel(self._header, text="v4.0 · NEXUS TERMINAL",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["muted"]).pack(side="left", padx=0)

        # Live clock
        self._clock_lbl = ctk.CTkLabel(self._header, text="",
                                       font=(THEME["font_mono"], 12),
                                       text_color=THEME["text_dim"])
        self._clock_lbl.pack(side="right", padx=20)
        self._tick_clock()

        # Threat level badge in header
        self._threat_lbl = ctk.CTkLabel(
            self._header, text="● NOMINAL",
            font=(THEME["font_mono"], 11, "bold"),
            text_color=THEME["success"])
        self._threat_lbl.pack(side="right", padx=16)
        ctk.CTkLabel(self._header, text="THREAT:",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["muted"]).pack(side="right")

        # ── Layout ──
        body = ctk.CTkFrame(self, fg_color=THEME["bg"], corner_radius=0)
        body.pack(fill="both", expand=True)

        # Sidebar
        self._sidebar = ctk.CTkFrame(body, width=200, fg_color=THEME["sidebar"],
                                     corner_radius=0)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)
        self._build_sidebar()

        # Divider
        ctk.CTkFrame(body, width=1, fg_color=THEME["border"],
                     corner_radius=0).pack(side="left", fill="y")

        # Main content
        self._main = ctk.CTkScrollableFrame(body, fg_color=THEME["bg"],
                                            corner_radius=0,
                                            scrollbar_button_color=THEME["border"],
                                            scrollbar_button_hover_color=THEME["accent_dim"])
        self._main.pack(side="left", fill="both", expand=True)

        # Right panel (activity feed)
        ctk.CTkFrame(body, width=1, fg_color=THEME["border"],
                     corner_radius=0).pack(side="left", fill="y")
        self._right_panel = ctk.CTkFrame(body, width=220, fg_color=THEME["sidebar"],
                                         corner_radius=0)
        self._right_panel.pack(side="left", fill="y")
        self._right_panel.pack_propagate(False)
        self._build_activity_panel()

        # System health update
        self._update_health()
        self._show_scanner()

    def _build_sidebar(self):
        NAV = [
            ("⬡", "Live Monitor",   self._show_scanner),
            ("◈", "Analytics",      self._show_analytics),
            ("⊕", "Enroll Subject", self._show_registration),
            ("≡", "Audit Logs",     self._show_logs),
            ("⚙", "Settings",       self._show_settings),
        ]
        ctk.CTkFrame(self._sidebar, height=20, fg_color="transparent").pack()

        # System stats mini cards
        stats_card = ctk.CTkFrame(self._sidebar, fg_color=THEME["card"],
                                  corner_radius=8)
        stats_card.pack(fill="x", padx=12, pady=(0, 16))
        self._cpu_lbl = ctk.CTkLabel(stats_card, text="CPU  —",
                                     font=(THEME["font_mono"], 10),
                                     text_color=THEME["text_dim"])
        self._cpu_lbl.pack(anchor="w", padx=10, pady=(8, 2))
        self._cpu_bar = ctk.CTkProgressBar(stats_card, height=4,
                                           fg_color=THEME["border"],
                                           progress_color=THEME["accent"])
        self._cpu_bar.set(0)
        self._cpu_bar.pack(fill="x", padx=10, pady=(0, 4))
        self._ram_lbl = ctk.CTkLabel(stats_card, text="RAM  —",
                                     font=(THEME["font_mono"], 10),
                                     text_color=THEME["text_dim"])
        self._ram_lbl.pack(anchor="w", padx=10)
        self._ram_bar = ctk.CTkProgressBar(stats_card, height=4,
                                           fg_color=THEME["border"],
                                           progress_color=THEME["warning"])
        self._ram_bar.set(0)
        self._ram_bar.pack(fill="x", padx=10, pady=(0, 8))

        sep = ctk.CTkFrame(self._sidebar, height=1, fg_color=THEME["border"])
        sep.pack(fill="x", padx=12, pady=8)

        self._nav_buttons = {}
        for icon, label, cmd in NAV:
            btn = ctk.CTkButton(
                self._sidebar,
                text=f"  {icon}   {label}",
                anchor="w",
                font=(THEME["font_mono"], 12),
                height=42,
                fg_color="transparent",
                hover_color=THEME["card"],
                text_color=THEME["text_dim"],
                corner_radius=8,
                command=lambda c=cmd, l=label: self._nav_click(l, c))
            btn.pack(fill="x", padx=12, pady=2)
            self._nav_buttons[label] = btn

        # Shutdown at bottom
        ctk.CTkFrame(self._sidebar, fg_color="transparent").pack(expand=True)
        ctk.CTkButton(
            self._sidebar,
            text="  ⏻   Shutdown System",
            anchor="w",
            font=(THEME["font_mono"], 12),
            height=42,
            fg_color="transparent",
            hover_color="#3d0a0a",
            text_color=THEME["danger"],
            corner_radius=8,
            command=self.quit).pack(fill="x", padx=12, pady=16)

    def _set_active_nav(self, label):
        if self._active_nav:
            self._nav_buttons[self._active_nav].configure(
                fg_color="transparent", text_color=THEME["text_dim"])
        self._active_nav = label
        if label in self._nav_buttons:
            self._nav_buttons[label].configure(
                fg_color=THEME["accent_dim"], text_color=THEME["accent"])

    def _nav_click(self, label, cmd):
        self._set_active_nav(label)
        cmd()

    def _build_activity_panel(self):
        ctk.CTkLabel(self._right_panel, text="LIVE ACTIVITY",
                     font=(THEME["font_mono"], 11, "bold"),
                     text_color=THEME["accent"]).pack(pady=(16, 8), padx=14, anchor="w")
        sep = ctk.CTkFrame(self._right_panel, height=1, fg_color=THEME["border"])
        sep.pack(fill="x", padx=12)

        self._feed_frame = ctk.CTkScrollableFrame(
            self._right_panel, fg_color="transparent",
            scrollbar_button_color=THEME["border"])
        self._feed_frame.pack(fill="both", expand=True, padx=0)
        self._refresh_activity_feed()

    def _refresh_activity_feed(self):
        for w in self._feed_frame.winfo_children():
            w.destroy()
        rows = self.engine.db.get_recent_logs(12)
        for name, t, status, conf in rows:
            color  = THEME["success"] if status == "VERIFIED" else THEME["danger"]
            card   = ctk.CTkFrame(self._feed_frame, fg_color=THEME["card"],
                                  corner_radius=6)
            card.pack(fill="x", padx=10, pady=3)
            ctk.CTkLabel(card, text=f"● {name}",
                         font=(THEME["font_mono"], 11, "bold"),
                         text_color=color).pack(anchor="w", padx=8, pady=(6,0))
            ctk.CTkLabel(card,
                         text=f"{t}  ·  {status}  ·  {round(conf or 0)}%",
                         font=(THEME["font_mono"], 9),
                         text_color=THEME["muted"]).pack(anchor="w", padx=8, pady=(0,6))
        self._activity_after_id = self.after(5000, self._refresh_activity_feed)

    # ─── HELPERS ────────────────────────────
    def _clear_view(self):
        self.engine.running = False
        self._stop_event.set()
        if self._video_thread and self._video_thread.is_alive():
            self._video_thread.join(timeout=0.5)
        self._video_thread = None
        self._processed_frame = None
        self._last_frame      = None
        self._close_cameras()
        # Cancel pending after callbacks
        if self._video_after_id:
            self.after_cancel(self._video_after_id)
            self._video_after_id = None
        if self._clock_after_id:
            self.after_cancel(self._clock_after_id)
            self._clock_after_id = None
        if self._health_after_id:
            self.after_cancel(self._health_after_id)
            self._health_after_id = None
        if self._activity_after_id:
            self.after_cancel(self._activity_after_id)
            self._activity_after_id = None
        if self._reg_video_after_id:
            self.after_cancel(self._reg_video_after_id)
            self._reg_video_after_id = None
        for w in self._main.winfo_children():
            w.destroy()

    def _on_close(self):
        self._clear_view()
        self.destroy()

    def _close_cameras(self):
        cameras = []
        if self.cap is not None and self.cap not in self.caps:
            cameras.append(self.cap)
        cameras.extend(self.caps)
        for cap in cameras:
            try:
                cap.release()
            except Exception:
                pass
        self.cap = None
        self.caps = []

    def _detect_camera_options(self, max_index=4):
        options = []
        for idx in range(max_index + 1):
            cap = cv2.VideoCapture(idx)
            if cap.isOpened():
                options.append(f"Camera {idx}")
                cap.release()
        if not options:
            options = [f"Camera {i}" for i in range(max_index + 1)]
        options.append("All Cameras")
        return options

    def _open_camera(self, single_only=False):
        self._close_cameras()
        if self.engine.camera_mode == "all" and not single_only:
            for idx in range(0, 5):
                cap = cv2.VideoCapture(idx)
                if cap.isOpened():
                    self.caps.append(cap)
                else:
                    try:
                        cap.release()
                    except Exception:
                        pass
            if self.caps:
                self.cap = self.caps[0]
                self.engine.camera_index = 0
                return self.caps
            return []

        camera_indexes = [self.engine.camera_index]
        if self.engine.camera_index != 0:
            camera_indexes.append(0)
        for idx in camera_indexes:
            cap = cv2.VideoCapture(idx)
            if cap.isOpened():
                self.cap = cap
                self.engine.camera_index = idx
                self.engine.camera_mode = "single"
                return cap
            try:
                cap.release()
            except Exception:
                pass
        self.cap = None
        return None

    def _page_header(self, icon, title, subtitle=""):
        row = ctk.CTkFrame(self._main, fg_color="transparent")
        row.pack(fill="x", padx=30, pady=(24, 4))
        ctk.CTkLabel(row, text=f"{icon}  {title}",
                     font=(THEME["font_display"], 26, "bold"),
                     text_color=THEME["text"]).pack(side="left")
        if subtitle:
            ctk.CTkLabel(row, text=subtitle,
                         font=(THEME["font_mono"], 11),
                         text_color=THEME["muted"]).pack(side="left", padx=12, pady=6)
        ctk.CTkFrame(self._main, height=1, fg_color=THEME["border"]).pack(
            fill="x", padx=30, pady=(4, 20))

    def _tick_clock(self):
        self._clock_lbl.configure(
            text=datetime.now().strftime("%a %d %b  %H:%M:%S"))
        self._clock_after_id = self.after(1000, self._tick_clock)

    def _update_health(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self._cpu_lbl.configure(text=f"CPU  {cpu:.0f}%")
        self._ram_lbl.configure(text=f"RAM  {ram:.0f}%")
        self._cpu_bar.set(cpu / 100)
        self._ram_bar.set(ram / 100)
        self._cpu_bar.configure(
            progress_color=THEME["danger"] if cpu > 80 else THEME["accent"])
        self._ram_bar.configure(
            progress_color=THEME["danger"] if ram > 85 else THEME["warning"])
        self._health_after_id = self.after(2000, self._update_health)

    def _update_threat(self, level):
        level = max(0, min(3, level))
        self.engine.threat_level = level
        name, color, _ = THREAT_LEVELS[level]
        self._threat_lbl.configure(text=f"● {name}", text_color=color)

    def _toast(self, msg, kind="info"):
        ToastNotification(self, msg, kind)

    # ─── LIVE MONITOR ───────────────────────
    def _show_scanner(self):
        self._clear_view()
        self.engine.running = True
        self.engine.ensure_runtime_models()
        if self._active_nav != "Live Monitor":
            self._set_active_nav("Live Monitor")

        self._page_header("⬡", "Live Monitor", "Real-time biometric scanning")

        # HUD bar
        hud = ctk.CTkFrame(self._main, fg_color="transparent")
        hud.pack(fill="x", padx=30, pady=(0, 10))

        self._hud_faces = self._hud_stat(hud, "FACES", "0", THEME["accent"])
        self._hud_fps   = self._hud_stat(hud, "FPS",   "0", THEME["success"])
        self._hud_known = self._hud_stat(hud, "ENROLLED", str(len(set(self.engine.data["names"]))), THEME["warning"])
        self._hud_threat= self._hud_stat(hud, "THREAT", "NOMINAL", THEME["success"])

        # Video frame with border
        vid_outer = ctk.CTkFrame(self._main, fg_color=THEME["card"],
                                 border_width=1, border_color=THEME["accent_dim"],
                                 corner_radius=12)
        vid_outer.pack(padx=30, pady=4)
        self._video_label = ctk.CTkLabel(vid_outer, text="", width=640, height=480,
                                         fg_color="black", corner_radius=10)
        self._video_label.pack(padx=3, pady=3)

        # Control bar
        ctrl = ctk.CTkFrame(self._main, fg_color="transparent")
        ctrl.pack(pady=12)
        ctk.CTkButton(ctrl, text="⬡  Snapshot",
                      font=(THEME["font_mono"], 12),
                      fg_color=THEME["card"], hover_color=THEME["accent_dim"],
                      border_width=1, border_color=THEME["accent"],
                      text_color=THEME["accent"], width=130, height=38,
                      command=self._take_snapshot).pack(side="left", padx=6)
        self._scan_status = ctk.CTkLabel(ctrl,
                                         text="◉  SCANNING",
                                         font=(THEME["font_mono"], 11, "bold"),
                                         text_color=THEME["success"])
        self._scan_status.pack(side="left", padx=16)

        camera_result = self._open_camera()
        if not camera_result and self.cap is None:
            ctk.CTkLabel(self._main,
                         text="No camera detected. Check camera connection and settings.",
                         font=(THEME["font_mono"], 12),
                         text_color=THEME["danger"]).pack(padx=30, pady=20)
            return
        self._start_video_thread()
        self._update_video()

    def _start_video_thread(self):
        self._stop_event.clear()
        if self._video_thread and self._video_thread.is_alive():
            return
        self._video_thread = threading.Thread(target=self._video_loop, daemon=True)
        self._video_thread.start()

    def _video_loop(self):
        frame_number = 0
        while self.engine.running and not self._stop_event.is_set():
            frames = []
            if self.caps:
                for cap in self.caps:
                    ret, frame = cap.read()
                    if ret:
                        frames.append(frame)
            elif self.cap:
                ret, frame = self.cap.read()
                if ret:
                    frames.append(frame)

            if not frames:
                time.sleep(0.05)
                continue

            frame_number += 1
            if frame_number % self.engine.analysis_interval:
                time.sleep(0.005)
                continue

            try:
                processed = self._process_frame(frames)
            except Exception as e:
                print(f"[VideoLoop] frame processing failed: {e}")
                self._pending_events.append(("toast", "Video processing error. See console.", "danger"))
                processed = None

            with self._frame_lock:
                self._processed_frame = processed
                self._last_frame = processed.copy() if processed is not None else None

            time.sleep(0.01)

    def _process_frame(self, frames):
        if len(frames) == 1:
            frame = cv2.resize(frames[0], (640, 480))
        else:
            frame = self._concat_frames(frames, 640, 480)
            if frame is None:
                return None

        # Run recognition on a smaller image; the display remains 640x480.
        analysis_frame = cv2.resize(frame, self.engine.analysis_size)
        detection_results = self.engine.detect_persons_and_objects(analysis_frame)

        scale_x = frame.shape[1] / analysis_frame.shape[1]
        scale_y = frame.shape[0] / analysis_frame.shape[0]
        for face_result in detection_results['face_results']:
            left, top, right, bottom = face_result['box']
            face_result['box'] = (
                int(left * scale_x), int(top * scale_y),
                int(right * scale_x), int(bottom * scale_y))
        for obj in detection_results['all_objects']:
            x, y, width, height = obj['box']
            obj['box'] = (
                int(x * scale_x), int(y * scale_y),
                int(width * scale_x), int(height * scale_y))
        for alert in detection_results['person_alerts']:
            x, y, width, height = alert['person']['box']
            alert['person']['box'] = (int(x * scale_x), int(y * scale_y),
                                      int(width * scale_x), int(height * scale_y))
            for obj in alert['nearby_objects']:
                x, y, width, height = obj['box']
                obj['box'] = (int(x * scale_x), int(y * scale_y),
                              int(width * scale_x), int(height * scale_y))

        face_results = detection_results['face_results']
        person_alerts = detection_results['person_alerts']
        all_objects = detection_results['all_objects']

        self.engine.face_count = len(face_results)
        self.engine.update_fps()

        # Process face recognition results
        for face_result in face_results:
            name = face_result['name']
            conf = face_result['confidence']
            left, top, right, bottom = face_result['box']

            # Get facial landmarks for liveness detection
            shape = None
            ear = 0.0
            if self.engine.predictor is not None:
                rect = dlib.rectangle(left, top, right, bottom)
                shape = self.engine.predictor(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), rect)
                shape = np.array([[p.x, p.y] for p in shape.parts()])
                ear = (self.engine.eye_aspect_ratio(shape[36:42]) +
                       self.engine.eye_aspect_ratio(shape[42:48])) / 2.0

            if name not in self.engine.blink_counter:
                self.engine.blink_counter[name] = 0
            if ear < self.engine.EYE_AR_THRESH:
                self.engine.blink_counter[name] += 1
            is_live = self.engine.blink_counter[name] > 0

            # Mask detection
            covered = False
            if self.engine.mask_detection_enabled and not self.engine.low_power_mode and shape is not None:
                covered = self.engine.detect_mask_or_face_cover(frame, shape)
                if covered and (time.time() - self.engine.mask_alert_cooldown) > self.engine.mask_alert_cooldown_secs:
                    self.engine.mask_alert_cooldown = time.time()
                    path = os.path.join(self.engine.base_dir, "snapshots/strangers",
                                        f"masked_{int(time.time())}.jpg")
                    cv2.imwrite(path, frame)
                    self.engine.db.insert_log("MASKED FACE", "MASK ALERT", 0, path)
                    self.engine.alerts.trigger_all_alerts("MASKED/COVERED FACE", path)
                    self.engine.speak("Face covering detected")
                    self.engine.threat_level = 2
                    with self._frame_lock:
                        self._pending_events.append(("toast", "⚠  ALERT: Face covering detected!", "warning"))
                        self._pending_events.append(("threat", 2))

            if covered:
                name = "MASKED FACE"
                conf = 0
                is_live = False

            # Handle unknown persons
            if name == "UNKNOWN" and not covered and (time.time() - self.engine.alert_cooldown) > self.engine.alert_cooldown_secs:
                self.engine.alert_cooldown = time.time()
                path = os.path.join(self.engine.base_dir, "snapshots/strangers",
                                    f"intruder_{int(time.time())}.jpg")
                cv2.imwrite(path, frame)
                self.engine.db.insert_log("UNKNOWN", "BREACH", 0, path)

                # Check for suspicious objects near this unknown person
                suspicious_nearby = []
                for alert in person_alerts:
                    # Check if this face result corresponds to the alerted person
                    person_box = alert['person']['box']
                    face_center = ((left + right) / 2, (top + bottom) / 2)
                    person_center = (person_box[0] + person_box[2]/2, person_box[1] + person_box[3]/2)

                    distance = np.sqrt((face_center[0] - person_center[0])**2 + (face_center[1] - person_center[1])**2)
                    if distance < 100:  # Within 100 pixels, likely the same person
                        suspicious_nearby = alert['nearby_objects']
                        break

                if suspicious_nearby:
                    obj_list = ", ".join([f"{obj['class']} ({obj['confidence']:.1f})" for obj in suspicious_nearby])
                    alert_msg = f"UNKNOWN with suspicious objects: {obj_list}"
                    self.engine.alerts.trigger_all_alerts(alert_msg, path)
                    self.engine.speak("Suspicious object detected")
                    self.engine.db.insert_log("UNKNOWN", f"BREACH - {obj_list}", 0, path)
                else:
                    self.engine.alerts.trigger_all_alerts("UNKNOWN", path)
                    self.engine.speak("Unauthorized entry detected")

                self.engine.threat_level = 3
                with self._frame_lock:
                    self._pending_events.append(("toast", "⚠  BREACH: Unknown subject detected!", "danger"))
                    self._pending_events.append(("threat", 3))

            # Handle verified persons
            if is_live and name != "UNKNOWN":
                key = name
                if key not in self.engine.attendance_cooldown or \
                   (time.time() - self.engine.attendance_cooldown[key]) > 60:
                    self.engine.attendance_cooldown[key] = time.time()
                    path = f"snapshots/verified/{name}_{int(time.time())}.jpg"
                    cv2.imwrite(path, frame[top:bottom, left:right])
                    self.engine.db.insert_log(name, "VERIFIED", round(conf, 2), path)
                    self.engine.speak(f"Access granted for {name}")
                    self.engine.threat_level = 0
                    with self._frame_lock:
                        self._pending_events.append(("threat", 0))

            # Set bounding box color
            if name == "UNKNOWN":
                color_cv = (0, 0, 255)
            elif is_live:
                color_cv = (0, 220, 100)
            else:
                color_cv = (255, 160, 0)

            # Draw face bounding box and label
            pad = 6
            seg = 18
            tl = (left - pad, top - pad); br = (right + pad, bottom + pad)
            for (x1, y1), (x2, y2) in [
                (tl, (tl[0]+seg, tl[1])), (tl, (tl[0], tl[1]+seg)),
                ((br[0]-seg, tl[1]), (br[0], tl[1])), ((br[0], tl[1]), (br[0], tl[1]+seg)),
                ((tl[0], br[1]-seg), (tl[0], br[1])), ((tl[0], br[1]), (tl[0]+seg, br[1])),
                ((br[0]-seg, br[1]), (br[0], br[1])), ((br[0], br[1]-seg), (br[0], br[1])),
            ]:
                cv2.line(frame, (x1, y1), (x2, y2), color_cv, 2)

            label_text = f"{name}  {conf:.0f}%" if name != "UNKNOWN" else "UNKNOWN"
            cv2.rectangle(frame,
                          (left - pad, top - pad - 24),
                          (left - pad + len(label_text)*9 + 10, top - pad),
                          color_cv, -1)
            cv2.putText(frame, label_text,
                        (left - pad + 5, top - pad - 7),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1, cv2.LINE_AA)

        # Draw object bounding boxes (for visualization)
        for obj in all_objects:
            if obj['class'] != 'person':  # Don't draw person boxes again
                x, y, w, h = obj['box']
                color = (255, 255, 0) if obj['class'] in ['knife', 'gun', 'backpack', 'handbag', 'suitcase', 'bottle'] else (0, 255, 255)
                cv2.rectangle(frame, (x, y), (x+w, y+h), color, 2)
                cv2.putText(frame, f"{obj['class']} {obj['confidence']:.1f}",
                           (x, y-5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)

        # Draw person bounding boxes (different style)
        for obj in all_objects:
            if obj['class'] == 'person':
                x, y, w, h = obj['box']
                cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 255), 2)
                cv2.putText(frame, f"Person {obj['confidence']:.1f}",
                           (x, y-5), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 0, 255), 1)

        fps_text = f"FPS {self.engine.fps}"
        if self.engine.low_power_mode:
            fps_text += " (LP)"
        cv2.putText(frame, fps_text,
                    (10, 24), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                    (0, 212, 255), 1, cv2.LINE_AA)
        return frame

    def _update_video(self):
        with self._frame_lock:
            frame = self._processed_frame
            events = list(self._pending_events)
            self._pending_events.clear()

        for evt in events:
            if evt[0] == "toast":
                self._toast(evt[1], evt[2])
            elif evt[0] == "threat":
                self._update_threat(evt[1])

        if frame is not None:
            self._hud_faces.configure(text=str(self.engine.face_count))
            self._hud_fps.configure(text=str(self.engine.fps))
            img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            ctk_img = ctk.CTkImage(img, size=(640, 480))
            self._video_label.configure(image=ctk_img)
            self._video_label.image = ctk_img

        self._video_after_id = self.after(50, self._update_video)

    def _hud_stat(self, parent, label, value, color):
        card = ctk.CTkFrame(parent, fg_color=THEME["card"],
                            border_width=1, border_color=THEME["border"],
                            corner_radius=8, width=130, height=56)
        card.pack(side="left", padx=6)
        card.pack_propagate(False)
        ctk.CTkLabel(card, text=label,
                     font=(THEME["font_mono"], 9),
                     text_color=THEME["muted"]).pack(pady=(8, 0))
        lbl = ctk.CTkLabel(card, text=value,
                           font=(THEME["font_mono"], 15, "bold"),
                           text_color=color)
        lbl.pack()
        return lbl

    def _take_snapshot(self):
        if hasattr(self, "_last_frame") and self._last_frame is not None:
            path = os.path.join(self.engine.base_dir, "snapshots",
                                f"snap_{int(time.time())}.jpg")
            cv2.imwrite(path, self._last_frame)
            self._toast(f"📸  Snapshot saved: {os.path.basename(path)}", "success")

    def _concat_frames(self, frames, max_width=640, max_height=480):
        if not frames:
            return None
        if len(frames) == 1:
            return cv2.resize(frames[0], (max_width, max_height))

        # Calculate optimal grid layout
        num_frames = len(frames)
        if num_frames == 2:
            cols, rows = 2, 1
        elif num_frames <= 4:
            cols, rows = 2, 2
        elif num_frames <= 6:
            cols, rows = 3, 2
        else:
            cols, rows = 4, 2  # Max 8 cameras

        # Calculate tile size maintaining aspect ratio
        tile_width = max_width // cols
        tile_height = max_height // rows

        # Resize each frame to fit its tile while maintaining aspect ratio
        resized_frames = []
        for frame in frames:
            h, w = frame.shape[:2]
            aspect_ratio = w / h

            # Fit frame into tile while preserving aspect ratio
            if aspect_ratio > (tile_width / tile_height):
                # Frame is wider, fit by width
                new_w = tile_width
                new_h = int(tile_width / aspect_ratio)
            else:
                # Frame is taller, fit by height
                new_h = tile_height
                new_w = int(tile_height * aspect_ratio)

            # Center the frame in the tile
            resized = cv2.resize(frame, (new_w, new_h))

            # Create tile with black background
            tile = np.zeros((tile_height, tile_width, 3), dtype=np.uint8)
            x_offset = (tile_width - new_w) // 2
            y_offset = (tile_height - new_h) // 2
            tile[y_offset:y_offset+new_h, x_offset:x_offset+new_w] = resized
            resized_frames.append(tile)

        # Fill remaining slots with black tiles if needed
        while len(resized_frames) < cols * rows:
            black_tile = np.zeros((tile_height, tile_width, 3), dtype=np.uint8)
            resized_frames.append(black_tile)

        # Arrange tiles into grid
        grid_rows = []
        for i in range(rows):
            row_frames = resized_frames[i*cols:(i+1)*cols]
            if len(row_frames) > 1:
                grid_rows.append(cv2.hconcat(row_frames))
            else:
                grid_rows.append(row_frames[0])

        # Combine rows
        if len(grid_rows) > 1:
            final_frame = cv2.vconcat(grid_rows)
        else:
            final_frame = grid_rows[0]

        return final_frame

        A = dist.euclidean(eye[1], eye[5])
        B = dist.euclidean(eye[2], eye[4])
        C = dist.euclidean(eye[0], eye[3])
        return (A + B) / (2.0 * C)

    # ─── ANALYTICS ──────────────────────────
    def _show_analytics(self):
        self._clear_view()
        self._page_header("◈", "Security Analytics", "Intelligence overview")

        total, alerts, rate = self.engine.db.get_summary_metrics()
        threat_score = self.engine.calculate_threat_score()

        # Metric cards
        row = ctk.CTkFrame(self._main, fg_color="transparent")
        row.pack(fill="x", padx=30, pady=(0, 20))
        self._metric_card(row, "TOTAL SCANS",      str(total),    THEME["accent"],   0)
        self._metric_card(row, "BREACH ALERTS",    str(alerts),   THEME["danger"],   1)
        self._metric_card(row, "ACCURACY RATE",    f"{rate}%",    THEME["success"],  2)
        self._metric_card(row, "THREAT SCORE",     f"{threat_score}/100", 
                          THEME["danger"] if threat_score > 50 else THEME["warning"] if threat_score > 25 else THEME["success"], 3)
        row.grid_columnconfigure((0,1,2,3), weight=1)

        # Charts
        plt.rcParams.update({
            'text.color':       THEME["text"],
            'axes.labelcolor':  THEME["text_dim"],
            'xtick.color':      THEME["muted"],
            'ytick.color':      THEME["muted"],
            'figure.facecolor': THEME["card"],
            'axes.facecolor':   THEME["bg"],
            'axes.spines.top':  False,
            'axes.spines.right':False,
            'axes.spines.left': True,
            'axes.spines.bottom':True,
            'axes.edgecolor':   THEME["border"],
            'grid.color':       THEME["border"],
        })

        chart_row = ctk.CTkFrame(self._main, fg_color="transparent")
        chart_row.pack(fill="both", padx=30, pady=10)

        # Bar chart
        fig1, ax1 = plt.subplots(figsize=(6, 3.8))
        fig1.patch.set_facecolor(THEME["card"])
        dates, counts = self.engine.db.get_weekly_stats()
        bars = ax1.bar(dates, counts, color=THEME["accent_dim"],
                       edgecolor=THEME["accent"], linewidth=0.8)
        for bar, val in zip(bars, counts):
            if val:
                ax1.text(bar.get_x() + bar.get_width()/2, val + 0.1,
                         str(val), ha='center', va='bottom',
                         fontsize=9, color=THEME["text"])
        ax1.set_title("7-Day Access Logs", color=THEME["text"], pad=10, fontsize=12)
        ax1.set_xlabel("Date", fontsize=9)
        ax1.set_ylabel("Detections", fontsize=9)
        ax1.grid(axis="y", alpha=0.2)
        fig1.tight_layout()
        c1 = FigureCanvasTkAgg(fig1, master=chart_row)
        c1.get_tk_widget().config(bg=THEME["card"], highlightthickness=0)
        c1.get_tk_widget().grid(row=0, column=0, padx=(0,10), pady=5, sticky="nsew")

        # Pie chart
        fig2, ax2 = plt.subplots(figsize=(4.5, 3.8))
        fig2.patch.set_facecolor(THEME["card"])
        dist_data = self.engine.db.get_status_distribution()
        if dist_data:
            labels = [x[0] for x in dist_data]
            sizes  = [x[1] for x in dist_data]
            clrs   = [THEME["success"], THEME["danger"], THEME["warning"]][:len(labels)]
            wedges, texts, autotexts = ax2.pie(
                sizes, labels=labels, autopct='%1.0f%%',
                startangle=140, colors=clrs,
                wedgeprops={'edgecolor': THEME["bg"], 'linewidth': 2})
            for t in texts: t.set_color(THEME["text_dim"])
            for t in autotexts: t.set_color(THEME["bg"])
            ax2.set_title("Status Distribution", color=THEME["text"], pad=10, fontsize=12)
        fig2.tight_layout()
        c2 = FigureCanvasTkAgg(fig2, master=chart_row)
        c2.get_tk_widget().config(bg=THEME["card"], highlightthickness=0)
        c2.get_tk_widget().grid(row=0, column=1, padx=(0,0), pady=5, sticky="nsew")
        chart_row.grid_columnconfigure((0,1), weight=1)

        # Line chart
        fig3, ax3 = plt.subplots(figsize=(12, 3.2))
        fig3.patch.set_facecolor(THEME["card"])
        hrs, hr_counts = self.engine.db.get_hourly_activity()
        ax3.plot(hrs, hr_counts, marker='o', markersize=4,
                 linestyle='-', color=THEME["accent"], linewidth=2)
        ax3.fill_between(hrs, hr_counts, color=THEME["accent"], alpha=0.08)
        ax3.set_title("24-Hour Activity Pattern", color=THEME["text"], pad=10, fontsize=12)
        ax3.set_xlabel("Hour of Day", fontsize=9)
        ax3.set_ylabel("Scans", fontsize=9)
        ax3.grid(True, alpha=0.15)
        ax3.set_xticks(hrs[::2]); ax3.set_xticklabels(hrs[::2], fontsize=8)
        fig3.tight_layout()
        c3 = FigureCanvasTkAgg(fig3, master=self._main)
        c3.get_tk_widget().config(bg=THEME["card"], highlightthickness=0)
        c3.get_tk_widget().pack(padx=30, pady=(0, 24), fill="x")

        # Threat Score Prediction Chart
        fig4, ax4 = plt.subplots(figsize=(12, 3.2))
        fig4.patch.set_facecolor(THEME["card"])

        # Generate threat score trend (last 7 days)
        threat_trend = []
        for i in range(7):
            day = datetime.now() - timedelta(days=i)
            # Simple calculation based on breaches that day
            day_breaches = self.engine.db.conn.execute(
                "SELECT COUNT(*) FROM logs WHERE date=? AND status IN ('BREACH', 'MASK ALERT')",
                (day.strftime("%Y-%m-%d"),)
            ).fetchone()[0]
            threat_trend.append(day_breaches * 10)  # Scale to threat score

        threat_trend.reverse()  # Oldest to newest
        dates_labels = [(datetime.now() - timedelta(days=i)).strftime("%m/%d") for i in range(6, -1, -1)]

        ax4.plot(dates_labels, threat_trend, marker='s', markersize=5,
                 linestyle='-', color=THEME["danger"], linewidth=2)
        ax4.fill_between(dates_labels, threat_trend, color=THEME["danger"], alpha=0.1)

        # Add current threat score line
        ax4.axhline(y=threat_score, color=THEME["warning"], linestyle='--', linewidth=1.5,
                    label=f'Current: {threat_score}')
        ax4.legend(loc='upper right', fontsize=9)

        ax4.set_title("Threat Score Trend (7 Days)", color=THEME["text"], pad=10, fontsize=12)
        ax4.set_xlabel("Date", fontsize=9)
        ax4.set_ylabel("Threat Score", fontsize=9)
        ax4.grid(True, alpha=0.15)
        ax4.set_ylim(0, 100)
        fig4.tight_layout()
        c4 = FigureCanvasTkAgg(fig4, master=self._main)
        c4.get_tk_widget().config(bg=THEME["card"], highlightthickness=0)
        c4.get_tk_widget().pack(padx=30, pady=(0, 24), fill="x")

    def _metric_card(self, parent, label, value, color, col):
        card = ctk.CTkFrame(parent, fg_color=THEME["card"],
                            border_width=1, border_color=color,
                            corner_radius=10, height=100)
        card.grid(row=0, column=col, padx=8, sticky="nsew")
        card.grid_propagate(False)
        ctk.CTkLabel(card, text=label,
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["muted"]).pack(pady=(14, 2))
        ctk.CTkLabel(card, text=value,
                     font=(THEME["font_display"], 26, "bold"),
                     text_color=color).pack()

    # ─── ENROLLMENT ─────────────────────────
    def _show_registration(self):
        self._clear_view()
        self._page_header("⊕", "Subject Enrollment", "Register new biometric profile")

        outer = ctk.CTkFrame(self._main, fg_color="transparent")
        outer.pack(padx=30, fill="x")

        # Video preview
        vid_card = NexusCard(outer, accent_color=THEME["accent_dim"], width=640, height=400)
        vid_card.pack(side="left", padx=(0, 20))
        self._reg_video = ctk.CTkLabel(vid_card, text="", width=620, height=380,
                                       fg_color="black", corner_radius=8)
        self._reg_video.pack(padx=5, pady=5)

        # Form panel
        form = NexusCard(outer)
        form.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(form, text="NEW ENROLLMENT",
                     font=(THEME["font_mono"], 13, "bold"),
                     text_color=THEME["accent"]).pack(pady=(20, 4), padx=20, anchor="w")
        ctk.CTkLabel(form, text="Capture subject face from live feed",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["muted"]).pack(padx=20, anchor="w")

        ctk.CTkFrame(form, height=1, fg_color=THEME["border"]).pack(
            fill="x", padx=20, pady=14)

        ctk.CTkLabel(form, text="FULL NAME / ID",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["text_dim"]).pack(padx=20, anchor="w")
        self._name_entry = ctk.CTkEntry(
            form, placeholder_text="e.g. John Doe",
            height=42, font=(THEME["font_mono"], 12),
            fg_color=THEME["bg"], border_color=THEME["border"],
            text_color=THEME["text"])
        self._name_entry.pack(fill="x", padx=20, pady=8)

        ctk.CTkLabel(form, text="ROLE",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["text_dim"]).pack(padx=20, anchor="w")
        self._role_var = ctk.StringVar(value="Staff")
        ctk.CTkOptionMenu(form, values=["Staff","Student","Visitor","Admin"],
                          variable=self._role_var,
                          font=(THEME["font_mono"], 12),
                          fg_color=THEME["bg"],
                          button_color=THEME["border"],
                          text_color=THEME["text"]).pack(fill="x", padx=20, pady=8)

        self._enroll_status = ctk.CTkLabel(form, text="",
                                           font=(THEME["font_mono"], 11),
                                           text_color=THEME["success"])
        self._enroll_status.pack(padx=20, pady=4)

        ctk.CTkButton(
            form, text="⊕  CAPTURE & ENROLL",
            font=(THEME["font_mono"], 13, "bold"),
            height=44, fg_color=THEME["accent_dim"],
            hover_color=THEME["accent"],
            border_width=1, border_color=THEME["accent"],
            text_color=THEME["accent"],
            command=self._register_user).pack(fill="x", padx=20, pady=(16, 8))

        ctk.CTkButton(
            form, text="✕  Cancel",
            font=(THEME["font_mono"], 11),
            height=36, fg_color="transparent",
            hover_color="#3d0a0a",
            border_width=1, border_color=THEME["danger"],
            text_color=THEME["danger"],
            command=self._show_scanner).pack(fill="x", padx=20, pady=4)

        self.cap = self._open_camera(single_only=True)
        self._update_reg_video()

    def _update_reg_video(self):
        if self.cap:
            ret, frame = self.cap.read()
            if ret:
                # Draw guide box
                h, w = frame.shape[:2]
                cx, cy = w//2, h//2
                size   = min(w, h) // 3
                cv2.rectangle(frame,
                              (cx-size, cy-size), (cx+size, cy+size),
                              (0, 212, 255), 1)
                cv2.putText(frame, "Position face in frame",
                            (cx-size, cy-size-8),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0,212,255), 1)
                img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                self._reg_video.configure(image=ImageTk.PhotoImage(image=img))
                self._reg_current_frame = frame
            self._reg_video_after_id = self.after(50, self._update_reg_video)

    def _register_user(self):
        name = self._name_entry.get().strip()
        if not name:
            self._enroll_status.configure(
                text="⚠  Enter a name first", text_color=THEME["warning"])
            return
        if hasattr(self, "_reg_current_frame") and self.engine.save_new_face(name, self._reg_current_frame):
            self._enroll_status.configure(
                text=f"✓  {name} enrolled successfully", text_color=THEME["success"])
            self._name_entry.delete(0, 'end')
            self._toast(f"✓  {name} enrolled", "success")
        else:
            self._enroll_status.configure(
                text="✗  No face detected — try again", text_color=THEME["danger"])

    # ─── AUDIT LOGS ─────────────────────────
    def _show_logs(self):
        self._clear_view()
        self._page_header("≡", "Audit Logs", "Security event history")

        # Filter bar
        fbar = ctk.CTkFrame(self._main, fg_color=THEME["card"],
                            border_width=1, border_color=THEME["border"],
                            corner_radius=8)
        fbar.pack(fill="x", padx=30, pady=(0, 14))

        ctk.CTkLabel(fbar, text="SEARCH",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["muted"]).pack(side="left", padx=(16,4), pady=10)
        self._log_search = ctk.CTkEntry(
            fbar, placeholder_text="Name / ID ...",
            width=200, height=34,
            font=(THEME["font_mono"], 11),
            fg_color=THEME["bg"], border_color=THEME["border"],
            text_color=THEME["text"])
        self._log_search.pack(side="left", padx=6, pady=10)

        ctk.CTkLabel(fbar, text="STATUS",
                     font=(THEME["font_mono"], 10),
                     text_color=THEME["muted"]).pack(side="left", padx=(16,4))
        self._status_filter = ctk.StringVar(value="ALL")
        ctk.CTkOptionMenu(fbar, values=["ALL","VERIFIED","BREACH"],
                          variable=self._status_filter,
                          width=120, height=34,
                          font=(THEME["font_mono"], 11),
                          fg_color=THEME["bg"],
                          button_color=THEME["border"],
                          text_color=THEME["text"]).pack(side="left", padx=6)

        ctk.CTkButton(fbar, text="⌕  Filter",
                      width=90, height=34,
                      font=(THEME["font_mono"], 11),
                      fg_color=THEME["accent_dim"],
                      hover_color=THEME["accent"],
                      border_width=1, border_color=THEME["accent"],
                      text_color=THEME["accent"],
                      command=self._apply_log_filter).pack(side="left", padx=6)

        ctk.CTkButton(fbar, text="✎  Generate Report",
                      width=130, height=34,
                      font=(THEME["font_mono"], 11),
                      fg_color=THEME["accent_dim"],
                      hover_color=THEME["accent"],
                      border_width=1, border_color=THEME["accent"],
                      text_color=THEME["accent"],
                      command=self._generate_incident_report).pack(side="right", padx=6)

        ctk.CTkButton(fbar, text="⇩  Export CSV",
                      width=110, height=34,
                      font=(THEME["font_mono"], 11),
                      fg_color=THEME["card"],
                      hover_color=THEME["card_hover"],
                      border_width=1, border_color=THEME["border"],
                      text_color=THEME["text_dim"],
                      command=self._export_csv).pack(side="right", padx=16)

        # Table
        table_frame = ctk.CTkFrame(self._main, fg_color=THEME["card"],
                                   border_width=1, border_color=THEME["border"],
                                   corner_radius=8)
        table_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Nexus.Treeview",
                        background=THEME["card"],
                        foreground=THEME["text"],
                        fieldbackground=THEME["card"],
                        bordercolor=THEME["border"],
                        rowheight=32,
                        font=(THEME["font_mono"], 11))
        style.configure("Nexus.Treeview.Heading",
                        background=THEME["sidebar"],
                        foreground=THEME["accent"],
                        font=(THEME["font_mono"], 11, "bold"),
                        relief="flat")
        style.map("Nexus.Treeview",
                  background=[("selected", THEME["accent_dim"])],
                  foreground=[("selected", THEME["accent"])])

        cols = ("ID", "Name", "Date", "Time", "Status", "Confidence%")
        self._tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                  style="Nexus.Treeview")
        widths = [50, 160, 110, 90, 100, 110]
        for col, w in zip(cols, widths):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, anchor="center")
        self._tree.tag_configure("breach",   foreground=THEME["danger"])
        self._tree.tag_configure("verified", foreground=THEME["success"])

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._tree.pack(fill="both", expand=True, padx=1, pady=1)

        self._apply_log_filter()

    def _apply_log_filter(self):
        name_f   = self._log_search.get().strip() if hasattr(self,"_log_search") else ""
        status_f = self._status_filter.get() if hasattr(self,"_status_filter") else "ALL"
        for row in self._tree.get_children():
            self._tree.delete(row)
        for row in self.engine.db.search_logs(name_f, status_f):
            id_, name, date, t, status, conf = row
            tag = "breach" if status in ("BREACH","UNKNOWN") else "verified"
            self._tree.insert("", "end",
                              values=(id_, name, date, t, status, f"{round(conf or 0, 1)}%"),
                              tags=(tag,))

    def _generate_incident_report(self):
        name_f   = self._log_search.get().strip() if hasattr(self, "_log_search") else ""
        status_f = self._status_filter.get() if hasattr(self, "_status_filter") else "ALL"
        logs = self.engine.db.search_logs(name_f, status_f)
        report = self.engine.generate_incident_report(logs)
        self._show_report_modal(report)

    def _show_report_modal(self, report_text):
        modal = tk.Toplevel(self)
        modal.title("Incident Report")
        modal.geometry("760x520")
        modal.configure(bg=THEME["bg"])
        ctk.CTkLabel(modal, text="Incident Report", font=(THEME["font_display"], 18, "bold"),
                     text_color=THEME["accent"]).pack(pady=(16, 6))
        text_area = ScrolledText(modal, wrap="word", font=(THEME["font_mono"], 11),
                                 bg=THEME["card"], fg=THEME["text"], bd=0, relief="flat")
        text_area.pack(fill="both", expand=True, padx=16, pady=8)
        text_area.insert("1.0", report_text)
        text_area.configure(state="disabled")
        ctk.CTkButton(modal, text="Close", width=100, height=34,
                      command=modal.destroy,
                      fg_color=THEME["accent_dim"], hover_color=THEME["accent"],
                      border_width=1, border_color=THEME["accent"],
                      text_color=THEME["accent"]).pack(pady=(0, 16))

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files","*.csv")],
            initialfile=f"safeguard_logs_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")
        if path:
            self.engine.db.export_csv(path)
            self._toast(f"✓  Logs exported to {os.path.basename(path)}", "success")

    # ─── SETTINGS ───────────────────────────
    def _show_settings(self):
        self._clear_view()
        self._page_header("⚙", "System Settings", "Configure detection & alert parameters")

        def section(title):
            ctk.CTkLabel(self._main, text=title,
                         font=(THEME["font_mono"], 12, "bold"),
                         text_color=THEME["accent"]).pack(
                             anchor="w", padx=30, pady=(14, 4))
            ctk.CTkFrame(self._main, height=1, fg_color=THEME["border"]).pack(
                fill="x", padx=30, pady=(0,10))

        def field_row(parent, label, widget_fn):
            r = ctk.CTkFrame(parent, fg_color="transparent")
            r.pack(fill="x", padx=30, pady=4)
            ctk.CTkLabel(r, text=label, width=220, anchor="w",
                         font=(THEME["font_mono"], 11),
                         text_color=THEME["text_dim"]).pack(side="left")
            widget_fn(r).pack(side="left")
            return r

        # Detection
        section("DETECTION ENGINE")

        self._thresh_var = ctk.DoubleVar(value=self.engine.CONFIDENCE_THRESHOLD)
        self._ear_var    = ctk.DoubleVar(value=self.engine.EYE_AR_THRESH)
        selected_cam = f"Camera {self.engine.camera_index}" if self.engine.camera_mode == "single" else "All Cameras"
        self._cam_choice = ctk.StringVar(value=selected_cam)
        self._cd_var     = ctk.IntVar(value=self.engine.alert_cooldown_secs)

        def make_slider(var, from_, to, row_parent):
            frm = ctk.CTkFrame(row_parent, fg_color="transparent")
            sl  = ctk.CTkSlider(frm, from_=from_, to=to, variable=var, width=220,
                                button_color=THEME["accent"],
                                progress_color=THEME["accent_dim"],
                                fg_color=THEME["border"])
            sl.pack(side="left")
            lbl = ctk.CTkLabel(frm, text=f"{var.get():.2f}", width=50,
                               font=(THEME["font_mono"], 10),
                               text_color=THEME["text_dim"])
            lbl.pack(side="left", padx=8)
            def update(_): lbl.configure(text=f"{var.get():.2f}")
            sl.configure(command=update)
            return frm

        field_row(self._main, "Face Confidence Threshold",
                  lambda p: make_slider(self._thresh_var, 0.3, 0.9, p))
        field_row(self._main, "Eye Aspect Ratio (Liveness)",
                  lambda p: make_slider(self._ear_var, 0.10, 0.35, p))
        field_row(self._main, "Alert Cooldown (seconds)",
                  lambda p: ctk.CTkEntry(p, textvariable=self._cd_var,
                                          width=100, height=36,
                                          font=(THEME["font_mono"], 11),
                                          fg_color=THEME["bg"],
                                          border_color=THEME["border"],
                                          text_color=THEME["text"]))

        camera_options = self._detect_camera_options()
        field_row(self._main, "Camera",
                  lambda p: ctk.CTkOptionMenu(p, values=camera_options,
                                               variable=self._cam_choice,
                                               width=220, height=36,
                                               font=(THEME["font_mono"], 11),
                                               fg_color=THEME["bg"],
                                               button_color=THEME["border"],
                                               text_color=THEME["text"]))

        self._mask_toggle_var = ctk.BooleanVar(value=self.engine.mask_detection_enabled)
        self._mask_cd_var     = ctk.IntVar(value=self.engine.mask_alert_cooldown_secs)

        field_row(self._main, "Mask / Face Cover Detection",
                  lambda p: ctk.CTkSwitch(p, variable=self._mask_toggle_var,
                                           text="", onvalue=True, offvalue=False,
                                           button_color=THEME["accent"],
                                           progress_color=THEME["accent_dim"]))
        field_row(self._main, "Mask Alert Cooldown (sec)",
                  lambda p: ctk.CTkEntry(p, textvariable=self._mask_cd_var,
                                          width=100, height=36,
                                          font=(THEME["font_mono"], 11),
                                          fg_color=THEME["bg"],
                                          border_color=THEME["border"],
                                          text_color=THEME["text"]))

        self._obj_toggle_var = ctk.BooleanVar(value=self.engine.object_detection_enabled)

        field_row(self._main, "Object Detection (Strangers)",
                  lambda p: ctk.CTkSwitch(p, variable=self._obj_toggle_var,
                                           text="", onvalue=True, offvalue=False,
                                           button_color=THEME["accent"],
                                           progress_color=THEME["accent_dim"]))

        self._llm_toggle_var = ctk.BooleanVar(value=self.engine.llm_enabled)
        self._llm_model_var  = ctk.StringVar(value=self.engine.llm_model_path)
        self._llm_auto_report_var = ctk.BooleanVar(value=self.engine.llm_auto_report)

        field_row(self._main, "LLM Assistance",
                  lambda p: ctk.CTkSwitch(p, variable=self._llm_toggle_var,
                                           text="", onvalue=True, offvalue=False,
                                           button_color=THEME["accent"],
                                           progress_color=THEME["accent_dim"]))
        field_row(self._main, "LLM Model Path / Repo ID",
                  lambda p: ctk.CTkEntry(p, textvariable=self._llm_model_var,
                                          width=320, height=36,
                                          font=(THEME["font_mono"], 11),
                                          fg_color=THEME["bg"],
                                          border_color=THEME["border"],
                                          text_color=THEME["text"]))
        field_row(self._main, "Auto Email Incident Report",
                  lambda p: ctk.CTkSwitch(p, variable=self._llm_auto_report_var,
                                           text="", onvalue=True, offvalue=False,
                                           button_color=THEME["accent"],
                                           progress_color=THEME["accent_dim"]))

        # Alerts
        section("ALERT CHANNELS")

        self._email_var = ctk.StringVar(value=self.engine.alerts.email_receiver)
        self._tg_var    = ctk.StringVar(value=self.engine.alerts.tg_chat_id)

        field_row(self._main, "Alert Email Recipient",
                  lambda p: ctk.CTkEntry(p, textvariable=self._email_var,
                                          width=280, height=36,
                                          font=(THEME["font_mono"], 11),
                                          fg_color=THEME["bg"],
                                          border_color=THEME["border"],
                                          text_color=THEME["text"]))
        field_row(self._main, "Telegram Chat ID",
                  lambda p: ctk.CTkEntry(p, textvariable=self._tg_var,
                                          width=280, height=36,
                                          font=(THEME["font_mono"], 11),
                                          fg_color=THEME["bg"],
                                          border_color=THEME["border"],
                                          text_color=THEME["text"]))

        # System
        section("SYSTEM")
        db_path = os.path.join(self.engine.base_dir, "safeguard_vault.db")
        db_size  = f"{os.path.getsize(db_path)/1024:.1f} KB" if os.path.exists(db_path) else "N/A"
        enc_path = self.engine.data_path
        enc_size = f"{os.path.getsize(enc_path)/1024:.1f} KB" if os.path.exists(enc_path) else "N/A"
        for k, v in [("Database", db_size), ("Encodings File", enc_size),
                     ("Snapshots Dir", self.engine.base_dir)]:
            r = ctk.CTkFrame(self._main, fg_color="transparent")
            r.pack(fill="x", padx=30, pady=3)
            ctk.CTkLabel(r, text=k, width=220, anchor="w",
                         font=(THEME["font_mono"], 11),
                         text_color=THEME["text_dim"]).pack(side="left")
            ctk.CTkLabel(r, text=v,
                         font=(THEME["font_mono"], 11),
                         text_color=THEME["text"]).pack(side="left")

        # Save
        ctk.CTkButton(
            self._main,
            text="  ✓   Save Configuration",
            font=(THEME["font_mono"], 12, "bold"),
            height=44, width=220,
            fg_color=THEME["accent_dim"],
            hover_color=THEME["accent"],
            border_width=1, border_color=THEME["accent"],
            text_color=THEME["accent"],
            command=self._save_settings).pack(pady=24)

    def _save_settings(self):
        self.engine.CONFIDENCE_THRESHOLD   = self._thresh_var.get()
        self.engine.EYE_AR_THRESH          = self._ear_var.get()
        self.engine.alert_cooldown_secs    = self._cd_var.get()
        cam_choice = self._cam_choice.get()
        if cam_choice == "All Cameras":
            self.engine.camera_mode = "all"
        else:
            self.engine.camera_mode = "single"
            try:
                self.engine.camera_index = int(cam_choice.split()[1])
            except Exception:
                self.engine.camera_index = 0
        self.engine.alerts.email_receiver  = self._email_var.get()
        self.engine.alerts.tg_chat_id      = self._tg_var.get()
        self.engine.mask_detection_enabled = self._mask_toggle_var.get()
        self.engine.mask_alert_cooldown_secs = self._mask_cd_var.get()
        self.engine.object_detection_enabled = self._obj_toggle_var.get()
        self.engine.llm_enabled           = self._llm_toggle_var.get()
        self.engine.llm_model_path        = self._llm_model_var.get().strip()
        self.engine.llm_auto_report       = self._llm_auto_report_var.get()
        if self.engine.llm_enabled and self.engine.llm_model_path:
            threading.Thread(target=self.engine.llm.load_model,
                             args=(self.engine.llm_model_path,),
                             daemon=True).start()
        self._toast("✓  Settings saved", "success")


# ══════════════════════════════════════════════
if __name__ == "__main__":
    app = SafeguardDashboard()
    app.mainloop()