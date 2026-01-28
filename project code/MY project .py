# ---------------- NIDS Dashboard with Real-Time Monitoring - COMPLETE VERSION ----------------
# ✅ Real-time packet capture with interface selection
# ✅ Fully resizable GUI
# ✅ Attack detection with dashboard integration
# ✅ Database logging and attack report export
# ============================================================================
## ==================== IMPORTS SECTION ====================
# #PythonLibraries #ImportManagement #DependencyManagement
import asyncio # #AsyncIO #ConcurrentProgramming #NonBlockingIO
import aiohttp
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from PIL import Image, ImageTk, ImageDraw
import json
import sqlite3
from datetime import datetime, timedelta
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pygame
import os
from concurrent.futures import ThreadPoolExecutor
import gc
import threading
import subprocess
import sys
from collections import defaultdict
import time
import requests #HTTPRequests #APIClient #RESTful
# ==================== INITIALIZATION ====================
# #Initialization #Setup #Configuration

pygame.mixer.init()
executor = ThreadPoolExecutor(max_workers=5)

# ==================== OPTIMIZED: Pre-load sounds ====================
ALERT_SOUND = None
BACKGROUND_MUSIC_LOADED = False

def preload_sounds():

    global ALERT_SOUND, BACKGROUND_MUSIC_LOADED
    try:
        alert_path = os.path.join("sounds", "1.mp3")
        if os.path.exists(alert_path):
            ALERT_SOUND = pygame.mixer.Sound(alert_path)
            print("✅ Alert sound preloaded")

        music_path = os.path.join("sounds", "2.mp3")
        if os.path.exists(music_path):
            pygame.mixer.music.load(music_path)
            BACKGROUND_MUSIC_LOADED = True
            print("✅ Background music preloaded")
    except Exception as e:
        print(f"Warning: Could not preload sounds: {e}")

is_muted = False
API_URL = "http://20.174.2.116:8000/predict" # #APIEndpoint #MLModel #PredictionAPI

# Design constants
#UIDesign #ColorScheme #ThemeConfiguration
APP_W, APP_H = 1280, 760
BG_TOP = "#0a0e1a"
BG_BOTTOM = "#000000"
CARD = "#1a1f35"
CARD_ALT = "#252b42"
ACCENT_BTN = "#3b82f6"
ACCENT_BTN_H = "#60a5fa"
TEXT = "#f1f5f9"
MUTED = "#94a3b8"
COLOR_BENIGN = "#10b981"
COLOR_ATTACK = "#ef4444"
RESULT_BG = "#1e293b"
# ==================== SEVERITY CONFIGURATION ====================
# #SeverityLevels #ThreatClassification #ColorCoding
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#7f1d1d", "border": "#ef4444", "text": "#fca5a5", "icon_bg": "#991b1b"},
    "HIGH": {"bg": "#92400e", "border": "#f97316", "text": "#fed7aa", "icon_bg": "#c2410c"},
    "MEDIUM": {"bg": "#713f12", "border": "#fbbf24", "text": "#fef3c7", "icon_bg": "#92400e"},
    "LOW": {"bg": "#1e3a8a", "border": "#60a5fa", "text": "#bfdbfe", "icon_bg": "#1e40af"}
}
# ==================== ATTACK DEFINITIONS ====================
# #AttackTypes #ThreatDefinitions #SecurityPatterns
ATTACK_CONFIG = {
    "DDoS": {"severity": "CRITICAL", "icon": "⚠", "message": "Distributed Denial of Service attack detected", "action": "Network flooding in progress"},
    "DoS": {"severity": "HIGH", "icon": "⚠", "message": "Denial of Service attack detected", "action": "Service disruption attempt"},
    "Backdoor": {"severity": "CRITICAL", "icon": "🚪", "message": "Backdoor connection attempt detected", "action": "Unauthorized access attempt"},
    "Exploits": {"severity": "CRITICAL", "icon": "💥", "message": "Exploitation attempt detected", "action": "System vulnerability targeted"},
    "Bot": {"severity": "HIGH", "icon": "🤖", "message": "Bot activity detected", "action": "Automated malicious behavior"},
    "scanning": {"severity": "MEDIUM", "icon": "🔍", "message": "Port scanning activity detected", "action": "Network reconnaissance in progress"},
    "Generic": {"severity": "MEDIUM", "icon": "⚡", "message": "Suspicious network activity detected", "action": "Anomaly detected in traffic"}
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ==================== REAL-TIME MONITORING CONFIGURATION ====================
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
FLOW_INACTIVE_TIMEOUT = 8.0
FLOW_MAX_DURATION = 300.0
BENIGN_LABELS = ['benign', 'normal', 'legitimate', 'BENIGN', 'NORMAL', 'Benign']
# ==================== UTILITY FUNCTIONS ====================

def is_attack(prediction):
    """Check if prediction is an attack (not benign)"""
    if not prediction:
        return False
    pred_lower = str(prediction).lower().strip()
    return not any(benign in pred_lower for benign in [label.lower() for label in BENIGN_LABELS])

def make_flow_key(src, sport, dst, dport, proto):
    """Create normalized bidirectional flow key"""
    a = (src, sport if sport is not None else -1)
    b = (dst, dport if dport is not None else -1)
    if a <= b:
        return (proto, a[0], int(a[1]), b[0], int(b[1]))
    else:
        return (proto, b[0], int(b[1]), a[0], int(a[1]))
# ==================== FLOW CLASS ====================
class Flow:
    def __init__(self, src, sport, dst, dport, proto, ts, first_pkt_src, first_pkt_dst):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.proto = proto
        self.first_ts = ts
        self.last_ts = ts
        
        self.forward_src = first_pkt_src
        self.forward_dst = first_pkt_dst
        self.forward_sport = sport if first_pkt_src == src else dport
        self.forward_dport = dport if first_pkt_src == src else sport
        
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.tcp_win_max_fwd = 0
        
        self.lock = threading.Lock()
        self.pkt_count = 0

    def update(self, pkt_src, pkt_dst, payload_bytes, ts, tcp_win=None):
        with self.lock:
            self.last_ts = ts
            self.pkt_count += 1
            
            is_forward = (pkt_src == self.forward_src and pkt_dst == self.forward_dst)
            
            if is_forward:
                self.fwd_bytes += payload_bytes
                self.fwd_pkts += 1
                
                if tcp_win is not None and tcp_win > self.tcp_win_max_fwd:
                    self.tcp_win_max_fwd = tcp_win
            else:
                self.bwd_bytes += payload_bytes
                self.bwd_pkts += 1

    def duration_seconds(self):
        return max(0.0, self.last_ts - self.first_ts)

    def to_payload(self):
        dur_seconds = self.duration_seconds()
        
        payload = {
            "DURATION_IN": int(round(dur_seconds)),
            "FLOW_DURATION_MILLISECONDS": int(round(dur_seconds * 1000.0)),
            "IN_BYTES": int(self.fwd_bytes),
            "IN_PKTS": int(self.fwd_pkts),
            "OUT_BYTES": int(self.bwd_bytes),
            "TCP_WIN_MAX_IN": int(self.tcp_win_max_fwd)
        }
        return payload

    def get_display_info(self):
        proto_name = self.proto.upper()
        return (f"[{proto_name}] {self.forward_src}:{self.forward_sport} "
                f"→ {self.forward_dst}:{self.forward_dport}")

# ==================== OPTIMIZED DATABASE MANAGER ====================
# #DatabaseManagement #SQLite #DataPersistence #QueryOptimization

class DatabaseManager:
    def __init__(self, db_name="nids_data.db"):
        self.db_name = db_name
        self.conn = None
        self._init_connection()
        self._create_indexes()
        self._cache = {}
        self._cache_lock = threading.Lock()
        print("✅ Database initialized with indexes and caching")

    def _init_connection(self):
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=10000")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                prediction_class TEXT NOT NULL,
                is_attack INTEGER NOT NULL,
                duration_in INTEGER,
                flow_duration INTEGER,
                in_bytes INTEGER,
                in_pkts INTEGER,
                out_bytes INTEGER,
                tcp_win_max INTEGER
            )
        """)
        self.conn.commit()

    def _create_indexes(self):
        try:
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON detections(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_is_attack ON detections(is_attack)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_time ON detections(is_attack, timestamp)")
            self.conn.commit()
        except Exception as e:
            print(f"Warning: Could not create indexes: {e}")

    def add_detection(self, prediction_class, is_attack, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win_max):
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO detections (prediction_class, is_attack, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win_max)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (prediction_class, is_attack, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win_max))
        self.conn.commit()
        self._invalidate_cache()

    def _invalidate_cache(self):
        with self._cache_lock:
            self._cache.clear()

    def get_active_threats(self):
        cache_key = "active_threats"
        with self._cache_lock:
            if cache_key in self._cache:
                cached_time, cached_value = self._cache[cache_key]
                if (datetime.now() - cached_time).total_seconds() < 5:
                    return cached_value

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM detections 
            WHERE is_attack = 1 AND julianday('now') - julianday(timestamp) <= 1
        """)
        result = cursor.fetchone()[0]

        with self._cache_lock:
            self._cache[cache_key] = (datetime.now(), result)

        return result

    def get_attack_timeline_by_type(self, minutes=30):
        cache_key = f"timeline_{minutes}"
        with self._cache_lock:
            if cache_key in self._cache:
                cached_time, cached_value = self._cache[cache_key]
                if (datetime.now() - cached_time).total_seconds() < 10:
                    return cached_value

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket, prediction_class, COUNT(*) as count
            FROM detections 
            WHERE is_attack = 1 AND julianday('now') - julianday(timestamp) <= ?
            GROUP BY time_bucket, prediction_class
            ORDER BY time_bucket
        """, (minutes / (24.0 * 60.0),))
        result = cursor.fetchall()

        with self._cache_lock:
            self._cache[cache_key] = (datetime.now(), result)

        return result

    def get_all_detections(self, limit=100):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def get_recent_attacks_for_alerts(self, limit=20):
        cache_key = f"recent_attacks_{limit}"
        with self._cache_lock:
            if cache_key in self._cache:
                cached_time, cached_value = self._cache[cache_key]
                if (datetime.now() - cached_time).total_seconds() < 5:
                    return cached_value

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, prediction_class, is_attack
            FROM detections 
            WHERE is_attack = 1 AND julianday('now') - julianday(timestamp) <= 1
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        result = cursor.fetchall()

        with self._cache_lock:
            self._cache[cache_key] = (datetime.now(), result)

        return result

    def export_attacks_to_file(self, output_dir="attack_reports"):
        """Export all attacks to a text file with timestamp"""
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"Attack_Report_{timestamp}.txt"
            filepath = os.path.join(output_dir, filename)
            
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, prediction_class, duration_in, flow_duration, 
                       in_bytes, in_pkts, out_bytes, tcp_win_max
                FROM detections 
                WHERE is_attack = 1
                ORDER BY timestamp DESC
            """)
            attacks = cursor.fetchall()
            
            if not attacks:
                print("⚠ No attacks found to export")
                return None
            
            with open(filepath, 'w', encoding='utf-8') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("         ARGUSMIND - NETWORK INTRUSION DETECTION SYSTEM\n")
                f.write("                    ATTACK DETECTION REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Attacks Detected: {len(attacks)}\n")
                f.write(f"Database: {self.db_name}\n")
                f.write("\n" + "=" * 80 + "\n\n")
                
                # Parameters of each attack 
                for idx, attack in enumerate(attacks, 1):
                    attack_id, timestamp, attack_type, duration_in, flow_duration, \
                    in_bytes, in_pkts, out_bytes, tcp_win_max = attack
                    
                    f.write(f"[{idx}] ATTACK DETECTED\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"  Attack ID          : {attack_id}\n")
                    f.write(f"  Detection Time     : {timestamp}\n")
                    f.write(f"  Attack Type        : {attack_type.upper()}\n")
                    f.write(f"  Severity           : {self._get_severity(attack_type)}\n")
                    f.write("\n")
                    
                    f.write("  TRAFFIC STATISTICS:\n")
                    f.write(f"    Duration (seconds)     : {duration_in}\n")
                    f.write(f"    Flow Duration (ms)     : {flow_duration}\n")
                    f.write(f"    Incoming Bytes         : {in_bytes:,}\n")
                    f.write(f"    Incoming Packets       : {in_pkts}\n")
                    f.write(f"    Outgoing Bytes         : {out_bytes:,}\n")
                    f.write(f"    TCP Window Max         : {tcp_win_max}\n")
                    
                    if in_pkts > 0:
                        avg_packet_size = in_bytes / in_pkts
                        f.write(f"    Avg Packet Size (bytes): {avg_packet_size:.2f}\n")
                    
                    f.write("\n" + "=" * 80 + "\n\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("                         STATISTICAL SUMMARY\n")
                f.write("=" * 80 + "\n\n")
                
                attack_types = {}
                for attack in attacks:
                    attack_type = attack[2]
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                f.write("Attack Type Distribution:\n")
                f.write("-" * 40 + "\n")
                for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / len(attacks)) * 100
                    f.write(f"  {attack_type.ljust(20)} : {count:3d} ({percentage:5.1f}%)\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("                    END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            print(f"✅ Attack report exported successfully: {filepath}")
            return filepath
            
        except Exception as e:
            print(f"❌ Error exporting attacks: {e}")
            return None
    
    def _get_severity(self, attack_type):
        """Get severity level for attack type"""
        lower = attack_type.lower()
        if "ddos" in lower or "backdoor" in lower or "exploit" in lower:
            return "CRITICAL"
        elif "dos" in lower or "bot" in lower:
            return "HIGH"
        elif "scan" in lower:
            return "MEDIUM"
        else:
            return "LOW"


    def delete_database(self):
        try:
            if self.conn:
                self.conn.close()
            if os.path.exists(self.db_name):
                os.remove(self.db_name)
                return True
        except Exception as e:
            print(f"Error deleting database: {e}")
        return False
    
# ==================== OPTIMIZED AUDIO FUNCTIONS ====================

    # ==================== OPTIMIZED AUDIO FUNCTIONS ====================
def play_alert_tone():
    def _play_async():
        global ALERT_SOUND
        try:
            # The alert sound always plays, even when the music is paused.
            if ALERT_SOUND:  #  "and not is_muted"
                was_playing = pygame.mixer.music.get_busy()
                if was_playing:
                    pygame.mixer.music.pause()

                ALERT_SOUND.play()

                def resume_music():
                    if was_playing and not is_muted:  #  "and not is_muted" 
                        try:
                            pygame.mixer.music.unpause()
                        except:
                            pass

                threading.Timer(ALERT_SOUND.get_length(), resume_music).start()
        except Exception as e:
            print(f"Error playing alert: {e}")
            try:
                if not is_muted:  # "if not is_muted" 
                    pygame.mixer.music.unpause()
            except:
                pass

    threading.Thread(target=_play_async, daemon=True).start()

# ✅ Add these two functions here ↓↓↓

def toggle_mute():
    global is_muted
    is_muted = not is_muted
    # Separate the background music only (2.mp3)
    pygame.mixer.music.set_volume(0 if is_muted else 1.0)
    # Leave the alert sound playing normally
    return is_muted

def start_background_music():
    global BACKGROUND_MUSIC_LOADED
    try:
        if BACKGROUND_MUSIC_LOADED:
            pygame.mixer.music.play(-1)
            #If the sound is split, set the volume to 0.
            pygame.mixer.music.set_volume(0 if is_muted else 1.0)
    except Exception as e:
        print(f"Error playing music: {e}")

# ==================== OPTIMIZED GRADIENT BG ====================
class GradientBG(ctk.CTkCanvas):
    ...

# ==================== OPTIMIZED GRADIENT BG ====================
class GradientBG(ctk.CTkCanvas):
    def __init__(self, master, top=BG_TOP, bottom=BG_BOTTOM, **kw):
        super().__init__(master, highlightthickness=0, **kw)
        self._top = top
        self._bottom = bottom
        self._bg_img = None
        self._cached_size = (0, 0)
        self.bind("<Configure>", self._draw)

    def _draw(self, _evt=None):
        w = max(1, self.winfo_width())
        h = max(1, self.winfo_height())

        if abs(w - self._cached_size[0]) < 5 and abs(h - self._cached_size[1]) < 5 and self._bg_img:
            return

        self._cached_size = (w, h)
        self.delete("grad")

        try:
            img = Image.new("RGB", (w, h))
            draw = ImageDraw.Draw(img)
            r1, g1, b1 = self.winfo_rgb(self._top)
            r2, g2, b2 = self.winfo_rgb(self._bottom)
            r1 >>= 8; g1 >>= 8; b1 >>= 8
            r2 >>= 8; g2 >>= 8; b2 >>= 8
            for i in range(h):
                a = i / float(h - 1) if h > 1 else 0
                r = int(r1 + (r2 - r1) * a)
                g = int(g1 + (g2 - g1) * a)
                b = int(b1 + (b2 - b1) * a)
                draw.line([(0, i), (w, i)], fill=(r, g, b))
            self._bg_img = ImageTk.PhotoImage(img)
            self.create_image(0, 0, anchor="nw", image=self._bg_img, tags=("grad",))
        except:
            pass
# ==================== SIDEBAR NAVIGATION ====================
# #Navigation #Sidebar #MenuSystem
# ==================== SIDEBAR ====================
class Sidebar(ctk.CTkFrame):
    def __init__(self, master, on_nav, width=260):
        super().__init__(master, fg_color="#0d1117", corner_radius=0, width=260)
        self.on_nav = on_nav
        self._build()

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text="🛡", font=("Segoe UI", 24)).pack(anchor="w")
        ctk.CTkLabel(header, text="NIDS Panel", font=("Segoe UI", 16, "bold"), text_color=TEXT).pack(anchor="w", pady=(4, 0))
        ctk.CTkFrame(self, height=2, fg_color="#21262d").pack(fill="x", padx=12, pady=8)

        self.btn_dashboard = ctk.CTkButton(self, text="  📊  Dashboard", corner_radius=10, height=44,
            fg_color="transparent", hover_color="#161b22", border_width=1, border_color="#30363d",
            font=("Segoe UI", 12), anchor="w", command=lambda: self.on_nav("dashboard"))

        self.btn_nids = ctk.CTkButton(self, text="  🌐  NIDS Scan", corner_radius=10, height=44,
            fg_color="transparent", hover_color="#161b22", border_width=1, border_color="#30363d",
            font=("Segoe UI", 12), anchor="w", command=lambda: self.on_nav("nids"))
        
        self.btn_realtime = ctk.CTkButton(self, text="  🔴  Real-Time Monitor", corner_radius=10, height=44,
            fg_color="transparent", hover_color="#161b22", border_width=1, border_color="#30363d",
            font=("Segoe UI", 12), anchor="w", command=lambda: self.on_nav("realtime"))

        self.btn_dashboard.pack(fill="x", padx=12, pady=(12, 6))
        self.btn_nids.pack(fill="x", padx=12, pady=6)
        self.btn_realtime.pack(fill="x", padx=12, pady=6)
        ctk.CTkFrame(self, fg_color="transparent", height=20).pack(expand=True)

        self.btn_exit = ctk.CTkButton(self, text="⏻  Exit & Clear Data", corner_radius=10, height=44,
            fg_color="#ef4444", hover_color="#dc2626", border_width=1, border_color="#7f1d1d",
            font=("Segoe UI", 12, "bold"), anchor="center", command=lambda: self.on_nav("exit"))
        self.btn_exit.pack(fill="x", padx=12, pady=(0, 20), side="bottom")

    def set_active(self, key):
        for b in (self.btn_dashboard, self.btn_nids, self.btn_realtime):
            b.configure(fg_color="transparent", border_color="#30363d")
        if key == "dashboard":
            self.btn_dashboard.configure(fg_color="#0969da", border_color="#1f6feb")
        elif key == "nids":
            self.btn_nids.configure(fg_color="#0969da", border_color="#1f6feb")
        elif key == "realtime":
            self.btn_realtime.configure(fg_color="#0969da", border_color="#1f6feb")

# ==================== MINI LOADER ====================
class MiniLoader(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color="#0A0E1A")
        box = ctk.CTkFrame(self, fg_color=CARD, corner_radius=16, width=300, height=160, border_width=2, border_color="#0969da")
        box.place(relx=0.5, rely=0.5, anchor="center")
        self.icon_label = ctk.CTkLabel(box, text="⚡", font=("Segoe UI", 50), text_color="#0969da")
        self.icon_label.place(relx=0.5, rely=0.35, anchor="center")
        self.status_label = ctk.CTkLabel(box, text="Loading...", font=("Segoe UI", 14, "bold"), text_color=TEXT)
        self.status_label.place(relx=0.5, rely=0.7, anchor="center")
        self.is_active = False
        self.rotation = 0

    def start(self, text="Loading..."):
        self.status_label.configure(text=text)
        self.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.lift()
        self.update()
        self.is_active = True
        self.rotation = 0
        self._spin_icon()

    def _spin_icon(self):
        if not self.is_active:
            return
        icons = ["⚡", "🔄", "⚙", "🔵"]
        self.icon_label.configure(text=icons[self.rotation % len(icons)])
        self.rotation += 1
        self.after(150, self._spin_icon)

    def stop(self):
        self.is_active = False
        self.place_forget()

# ==================== DASHBOARD PAGE ====================
# #DashboardUI #StatisticsDisplay #ChartVisualization
class DashboardPage(ctk.CTkFrame):
    """Dashboard with all features"""
    def __init__(self, master, db_manager):
        super().__init__(master, fg_color="transparent")
        self.db = db_manager
        self.is_visible = False
        self.refresh_task = None
        self.fig = None
        self.ax = None
        self.canvas = None
        self._cached_threats = 0
        self._cached_timeline = []
        self._cache_timestamp = None
        self._is_first_load = True
        self._ui_built = False
        self._build()

    def _build(self):
        if self._ui_built:
            return
                    # Header

        header = ctk.CTkFrame(self, fg_color="transparent", height=80)
        header.pack(fill="x", padx=30, pady=(20, 10))
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(title_frame, text="🛡  Network Intrusion Detection System", font=("Segoe UI", 24, "bold"), text_color=TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(title_frame, text="Real-time threat monitoring and analysis", font=("Segoe UI", 12), text_color=MUTED, anchor="w").pack(anchor="w", pady=(4, 0))
                # Audio control

        audio_frame = ctk.CTkFrame(header, fg_color=CARD, corner_radius=10, border_width=1, border_color="#30363d")
        audio_frame.pack(side="right", padx=10)
        audio_content = ctk.CTkFrame(audio_frame, fg_color="transparent")
        audio_content.pack(padx=15, pady=10)
        self.audio_icon = ctk.CTkLabel(audio_content, text="🔊", font=("Segoe UI", 20))
        self.audio_icon.pack(side="left", padx=(0, 10))
        self.mute_switch = ctk.CTkSwitch(audio_content, text="", width=50, fg_color="#10b981", progress_color="#059669", button_color="white", button_hover_color="#f1f5f9", command=self._toggle_audio)
        self.mute_switch.pack(side="left")
        self.mute_switch.select()
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.pack(fill="x", padx=30, pady=10)
        self._create_stat_card(stats_frame)
        main_content = ctk.CTkFrame(self, fg_color="transparent")
        main_content.pack(fill="both", expand=True, padx=30, pady=10)
        left_column = ctk.CTkFrame(main_content, fg_color="transparent")
        left_column.pack(side="left", fill="both", expand=True, padx=(0, 10))
        right_column = ctk.CTkFrame(main_content, fg_color="transparent", width=480)
        right_column.pack(side="right", fill="both", padx=(10, 0))
        right_column.pack_propagate(False)
        self._create_security_alerts_section(right_column)
        self._create_graph_section(left_column)
        self._ui_built = True

    def _create_stat_card(self, parent):
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=12, border_width=1, border_color="#30363d", height=120)
        card.pack(fill="x", padx=10)
        icon_frame = ctk.CTkFrame(card, fg_color="#ef4444", corner_radius=10, width=50, height=50)
        icon_frame.place(x=20, y=35)
        ctk.CTkLabel(icon_frame, text="⚠", font=("Segoe UI", 20)).place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(card, text="Active Threats Detected", font=("Segoe UI", 11), text_color=MUTED, anchor="w").place(x=85, y=35)
        self.threats_value = ctk.CTkLabel(card, text="0", font=("Segoe UI", 32, "bold"), text_color=TEXT, anchor="w")
        self.threats_value.place(x=85, y=55)
        self.threats_change = ctk.CTkLabel(card, text="All Clear", font=("Segoe UI", 11), text_color=MUTED, anchor="e")
        self.threats_change.place(relx=0.95, y=45, anchor="e")

    def _create_graph_section(self, parent):
        graph_container = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14, border_width=1, border_color="#30363d")
        graph_container.pack(fill="both", expand=True)
        graph_header = ctk.CTkFrame(graph_container, fg_color="transparent")
        graph_header.pack(fill="x", padx=20, pady=(15, 10))
        ctk.CTkLabel(graph_header, text="Attack Detection Timeline", font=("Segoe UI", 16, "bold"), text_color="#06b6d4", anchor="w").pack(side="left")
        ctk.CTkButton(graph_header, text="🔄 Refresh", width=100, height=32, fg_color="#0969da", hover_color="#1f6feb", text_color="white", font=("Segoe UI", 11, "bold"), corner_radius=8, command=self.refresh_graph).pack(side="right", padx=5)
        ctk.CTkButton(graph_header, text="📊 View Data", width=100, height=32, fg_color="#10b981", hover_color="#059669", text_color="white", font=("Segoe UI", 11, "bold"), corner_radius=8, command=self.show_database_viewer).pack(side="right")
        self.graph_frame = ctk.CTkFrame(graph_container, fg_color="#0d1117", corner_radius=10)
        self.graph_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self._init_graph()

    def _init_graph(self):
        self.fig = Figure(figsize=(8, 3.8), dpi=90, facecolor='#0d1117')
        self.ax = self.fig.add_subplot(111, facecolor='#0d1117')
        self.canvas = FigureCanvasTkAgg(self.fig, self.graph_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
        self._update_graph_data()

    def _update_graph_data(self):
        timeline_data = self._cached_timeline if self._cached_timeline else self.db.get_attack_timeline_by_type(minutes=30)
        self._update_graph_with_data(timeline_data)

    def _update_graph_with_data(self, timeline_data):
        if timeline_data:
            time_dict = {}
            for time_bucket, pred_class, count in timeline_data:
                if time_bucket not in time_dict:
                    time_dict[time_bucket] = 0
                time_dict[time_bucket] += count
            times = sorted(time_dict.keys())
            display_times = [t.split()[1] if len(t.split()) > 1 else t for t in times]
            threat_counts = [time_dict[t] for t in times]
        else:
            now = datetime.now()
            display_times = [(now - timedelta(minutes=i*3)).strftime('%H:%M') for i in range(10, -1, -1)]
            threat_counts = [0] * 11
        self.ax.clear()
        if any(threat_counts):
            self.ax.plot(display_times, threat_counts, color='#ef4444', linewidth=3, marker='o', markersize=10, markerfacecolor='#ef4444', markeredgecolor='white', markeredgewidth=2, zorder=3)
        else:
            self.ax.text(0.5, 0.5, 'No attacks in last 30 minutes', ha='center', va='center', transform=self.ax.transAxes, color='#8b949e', fontsize=12)
        self.ax.set_facecolor('#0d1117')
        self.ax.grid(True, color='#1e293b', linestyle='--', linewidth=1, alpha=0.5, zorder=0)
        self.ax.spines['top'].set_visible(False)
        self.ax.spines['right'].set_visible(False)
        self.ax.spines['left'].set_color('#30363d')
        self.ax.spines['bottom'].set_color('#30363d')
        self.ax.tick_params(colors='#8b949e', labelsize=10)
        self.ax.set_xlabel('Time', color='#8b949e', fontsize=11, fontweight='bold')
        self.ax.set_ylabel('Detected Attacks', color='#8b949e', fontsize=11, fontweight='bold')
        plt.setp(self.ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
        self.fig.subplots_adjust(left=0.08, right=0.96, top=0.95, bottom=0.15)
        self.canvas.draw_idle()

    def _toggle_audio(self):
        is_muted = toggle_mute()
        self.audio_icon.configure(text="🔇" if is_muted else "🔊")

    def _create_security_alerts_section(self, parent):
        alerts_container = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14, border_width=1, border_color="#30363d")
        alerts_container.pack(fill="both", expand=True)
        alerts_header = ctk.CTkFrame(alerts_container, fg_color="transparent")
        alerts_header.pack(fill="x", padx=20, pady=(18, 12))
        ctk.CTkLabel(alerts_header, text="Security Alerts", font=("Segoe UI", 18, "bold"), text_color="#06b6d4", anchor="w").pack(side="left")
        self.critical_badge = ctk.CTkLabel(alerts_header, text="0", font=("Segoe UI", 12, "bold"), text_color="white", fg_color="#7f1d1d", corner_radius=14, padx=16, pady=6, width=55)
        self.critical_badge.pack(side="right")
        self.alerts_scroll = ctk.CTkScrollableFrame(alerts_container, fg_color="#0d1117", corner_radius=10, height=450)
        self.alerts_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))
# ==================== CONTINUATION OF DASHBOARD PAGE ====================
# #DashboardContinuation #SecurityAlerts #GraphVisualization

    def _refresh_security_alerts(self):
        for widget in self.alerts_scroll.winfo_children():
            widget.destroy()
        recent_attacks = self.db.get_recent_attacks_for_alerts(limit=20)
        if not recent_attacks:
            ctk.CTkLabel(self.alerts_scroll, text="✓ No security alerts", font=("Segoe UI", 13), text_color="#10b981").pack(pady=50)
            self.critical_badge.configure(text="0")
            return
        critical_count = sum(1 for a in recent_attacks if self._get_attack_severity(a[2]) == "CRITICAL")
        self.critical_badge.configure(text=str(critical_count))
        for attack in recent_attacks:
            self._create_alert_card(attack)

    def _get_attack_severity(self, attack_class):
        lower = attack_class.lower()
        if "ddos" in lower or "backdoor" in lower or "exploit" in lower:
            return "CRITICAL"
        elif "dos" in lower or "bot" in lower:
            return "HIGH"
        else:
            return "MEDIUM"

    def _create_alert_card(self, attack):
        attack_id, timestamp, attack_class, is_attack = attack
        attack_name = self._normalize_attack_name(attack_class)
        config = ATTACK_CONFIG.get(attack_name, ATTACK_CONFIG["Generic"])
        colors = SEVERITY_COLORS[config["severity"]]
        try:
            time_str = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').strftime('%H:%M:%S')
        except:
            time_str = timestamp.split()[1] if len(timestamp.split()) > 1 else timestamp
        alert_card = ctk.CTkFrame(self.alerts_scroll, fg_color=colors['bg'], corner_radius=12, border_width=2, border_color=colors['border'], height=140)
        alert_card.pack(fill="x", pady=8)
        content = ctk.CTkFrame(alert_card, fg_color="transparent")
        content.pack(fill="both", padx=18, pady=16)
        top_row = ctk.CTkFrame(content, fg_color="transparent")
        top_row.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(top_row, text=config["severity"], font=("Segoe UI", 10, "bold"), text_color="white", fg_color=colors['icon_bg'], corner_radius=8, padx=12, pady=4).pack(side="left")
        ctk.CTkLabel(top_row, text=f"🕐 {time_str}", font=("Segoe UI", 10), text_color=colors['text']).pack(side="right")
        attack_header = ctk.CTkFrame(content, fg_color="transparent")
        attack_header.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(attack_header, text=config["icon"], font=("Segoe UI", 24)).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(attack_header, text=f"{attack_name} Attack", font=("Segoe UI", 16, "bold"), text_color="white").pack(side="left")
        ctk.CTkLabel(content, text=config["message"], font=("Segoe UI", 11), text_color=colors['text'], anchor="w").pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(content, text=f"⚡ {config['action']}", font=("Segoe UI", 10), text_color=colors['text'], anchor="w").pack(fill="x")

    def _normalize_attack_name(self, attack_class):
        lower = attack_class.lower().strip()
        if "ddos" in lower: return "DDoS"
        elif "dos" in lower: return "DoS"
        elif "backdoor" in lower: return "Backdoor"
        elif "bot" in lower: return "Bot"
        elif "exploit" in lower: return "Exploits"
        elif "scan" in lower: return "scanning"
        else: return "Generic"

    def refresh_graph(self):
        executor.submit(self._background_refresh)

    def _background_refresh(self):
        try:
            threats = self.db.get_active_threats()
            timeline = self.db.get_attack_timeline_by_type(minutes=30)
            self._cached_threats = threats
            self._cached_timeline = timeline
            self._cache_timestamp = datetime.now()
            self.after(0, lambda: self._update_ui_data(threats))
        except:
            pass

    def _update_ui_data(self, threats):
        self.threats_value.configure(text=str(threats))
        if threats > 0:
            self.threats_change.configure(text="Last 24h", text_color="#ef4444")
        else:
            self.threats_change.configure(text="All Clear", text_color=MUTED)
        self._update_graph_data()
        self._refresh_security_alerts()

    def show_database_viewer(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Database Viewer")
        popup.geometry("900x500")
        popup.configure(fg_color="#0a0e1a")
        header = ctk.CTkFrame(popup, fg_color=CARD, height=60)
        header.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header, text="📊 Database Contents", font=("Segoe UI", 18, "bold"), text_color=TEXT).pack(side="left", padx=20, pady=15)
        detections = self.db.get_all_detections(limit=50)
        ctk.CTkLabel(header, text=f"Total Records: {len(detections)}", font=("Segoe UI", 12), text_color="#10b981").pack(side="right", padx=20, pady=15)
        scroll_frame = ctk.CTkScrollableFrame(popup, fg_color=CARD_ALT, width=860, height=350)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        if detections:
            headers = ["ID", "Timestamp", "Class", "Attack", "Duration", "Flow", "In Bytes", "In Pkts", "Out Bytes", "TCP Win"]
            header_row = ctk.CTkFrame(scroll_frame, fg_color=CARD)
            header_row.pack(fill="x", pady=(0, 5))
            for i, header in enumerate(headers):
                width = 60 if i == 0 else (150 if i == 1 else (100 if i == 2 else 70))
                ctk.CTkLabel(header_row, text=header, font=("Segoe UI", 10, "bold"), text_color="#06b6d4", width=width).pack(side="left", padx=5, pady=8)
            for detection in detections:
                row = ctk.CTkFrame(scroll_frame, fg_color="#1a1f35")
                row.pack(fill="x", pady=2)
                ctk.CTkLabel(row, text=str(detection[0]), width=60, anchor="w", text_color=TEXT, font=("Segoe UI", 9)).pack(side="left", padx=5, pady=5)
                ctk.CTkLabel(row, text=detection[1], width=150, anchor="w", text_color=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=5, pady=5)
                class_color = COLOR_ATTACK if detection[3] == 1 else COLOR_BENIGN
                ctk.CTkLabel(row, text=detection[2], width=100, anchor="w", text_color=class_color, font=("Segoe UI", 9, "bold")).pack(side="left", padx=5, pady=5)
                attack_text = "Yes" if detection[3] == 1 else "No"
                ctk.CTkLabel(row, text=attack_text, width=70, anchor="center", text_color=class_color, font=("Segoe UI", 9)).pack(side="left", padx=5, pady=5)
                for i in range(4, 10):
                    value = detection[i] if detection[i] is not None else "N/A"
                    ctk.CTkLabel(row, text=str(value), width=70, anchor="center", text_color=TEXT, font=("Segoe UI", 9)).pack(side="left", padx=5, pady=5)
        else:
            ctk.CTkLabel(scroll_frame, text="No detections found in database", font=("Segoe UI", 14), text_color=MUTED).pack(pady=50)
        ctk.CTkButton(popup, text="Close", width=150, height=40, fg_color="#ef4444", hover_color="#dc2626", font=("Segoe UI", 12, "bold"), command=popup.destroy).pack(pady=10)

    def show(self):
        self.is_visible = True
        if self._is_first_load or self._is_cache_expired():
            self._is_first_load = False
            executor.submit(self._background_refresh)
        else:
            self._display_cached_data()
        self.after(100, self._start_auto_refresh)

    def _is_cache_expired(self):
        if not self._cache_timestamp:
            return True
        age = (datetime.now() - self._cache_timestamp).total_seconds()
        return age > 10

    def _display_cached_data(self):
        self.threats_value.configure(text=str(self._cached_threats))
        if self._cached_threats > 0:
            self.threats_change.configure(text="Last 24h", text_color="#ef4444")
        else:
            self.threats_change.configure(text="All Clear", text_color=MUTED)
        if self._cached_timeline:
            self._update_graph_with_data(self._cached_timeline)
        self.after(10, self._refresh_security_alerts)

    def hide(self):
        self.is_visible = False
        self._stop_auto_refresh()

    def _start_auto_refresh(self):
        if self.refresh_task:
            self.after_cancel(self.refresh_task)
        self._schedule_refresh()

    def _stop_auto_refresh(self):
        if self.refresh_task:
            self.after_cancel(self.refresh_task)
            self.refresh_task = None

    def _schedule_refresh(self):
        if self.is_visible:
            executor.submit(self._background_refresh)
        self.refresh_task = self.after(30000, self._schedule_refresh)

    def cleanup(self):
        self._stop_auto_refresh()
        if self.fig:
            plt.close(self.fig)
        gc.collect()

# ==================== NIDS PAGE ====================
# #NIDSScanner #ManualClassification #PacketInput
class NIDSPage(ctk.CTkFrame):
    def __init__(self, master, db_manager):
        super().__init__(master, fg_color="transparent")
        self.db = db_manager
        self._build()

    def _build(self):
        wrapper = ctk.CTkFrame(self, fg_color=CARD, corner_radius=14, border_width=1, border_color="#30363d")
        wrapper.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.96)
        header = ctk.CTkFrame(wrapper, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(16, 0))
        ctk.CTkLabel(header, text="🌐", font=("Segoe UI", 24)).pack(side="left", padx=(0, 10))
        header_text_frame = ctk.CTkFrame(header, fg_color="transparent")
        header_text_frame.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(header_text_frame, text="Packet Classification", font=("Segoe UI", 20, "bold"), text_color=TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(header_text_frame, text="Analyze network packets for potential threats", text_color=MUTED, font=("Segoe UI", 11), anchor="w").pack(anchor="w", pady=(2, 0))
        content = ctk.CTkFrame(wrapper, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(12, 20))
        left = ctk.CTkFrame(content, fg_color=CARD_ALT, corner_radius=12, border_width=1, border_color="#30363d")
        left.place(relx=0, rely=0, relwidth=0.63, relheight=1)
        left_header = ctk.CTkFrame(left, fg_color="transparent", width=560, height=40)
        left_header.place(x=20, y=16)
        ctk.CTkLabel(left_header, text="⚡", font=("Segoe UI", 16)).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(left_header, text="Input Parameters", font=("Segoe UI", 14, "bold"), text_color=TEXT, anchor="w").pack(side="left")
                # Input fields - #InputFields #UserEntry
        y_start = 60
        spacing = 70
        ctk.CTkLabel(left, text="DURATION_IN", text_color=TEXT, font=("Segoe UI", 11, "bold"), anchor="w").place(x=24, y=y_start)
        self.entry_duration_in = ctk.CTkEntry(left, placeholder_text="e.g., 500", height=38, font=("Segoe UI", 11), width=260, border_width=1, border_color="#30363d")
        self.entry_duration_in.place(x=24, y=y_start + 26)
        self.entry_duration_in.insert(0, "500")
        ctk.CTkLabel(left, text="FLOW_DURATION_MILLISECONDS", text_color=TEXT, font=("Segoe UI", 11, "bold"), anchor="w").place(x=300, y=y_start)
        self.entry_flow_duration = ctk.CTkEntry(left, placeholder_text="e.g., 1000", height=38, font=("Segoe UI", 11), width=260, border_width=1, border_color="#30363d")
        self.entry_flow_duration.place(x=300, y=y_start + 26)
        self.entry_flow_duration.insert(0, "1000")
        ctk.CTkLabel(left, text="IN_BYTES", text_color=TEXT, font=("Segoe UI", 11, "bold"), anchor="w").place(x=24, y=y_start + spacing)
        self.entry_in_bytes = ctk.CTkEntry(left, placeholder_text="e.g., 1500", height=38, font=("Segoe UI", 11), width=260, border_width=1, border_color="#30363d")
        self.entry_in_bytes.place(x=24, y=y_start + spacing + 26)
        self.entry_in_bytes.insert(0, "1500")
        ctk.CTkLabel(left, text="IN_PKTS", text_color=TEXT, font=("Segoe UI", 11, "bold"), anchor="w").place(x=300, y=y_start + spacing)
        self.entry_in_pkts = ctk.CTkEntry(left, placeholder_text="e.g., 30", height=38, font=("Segoe UI", 11), width=260, border_width=1, border_color="#30363d")
        self.entry_in_pkts.place(x=300, y=y_start + spacing + 26)
        self.entry_in_pkts.insert(0, "30")
        ctk.CTkLabel(left, text="OUT_BYTES", text_color=TEXT, font=("Segoe UI", 11, "bold"), anchor="w").place(x=24, y=y_start + spacing * 2)
        self.entry_out_bytes = ctk.CTkEntry(left, placeholder_text="e.g., 5000", height=38, font=("Segoe UI", 11), width=260, border_width=1, border_color="#30363d")
        self.entry_out_bytes.place(x=24, y=y_start + spacing * 2 + 26)
        self.entry_out_bytes.insert(0, "5000")
        ctk.CTkLabel(left, text="TCP_WIN_MAX_IN", text_color=TEXT, font=("Segoe UI", 11, "bold"), anchor="w").place(x=300, y=y_start + spacing * 2)
        self.entry_tcp_win = ctk.CTkEntry(left, placeholder_text="e.g., 65535", height=38, font=("Segoe UI", 11), width=260, border_width=1, border_color="#30363d")
        self.entry_tcp_win.place(x=300, y=y_start + spacing * 2 + 26)
        self.entry_tcp_win.insert(0, "65535")
        self.btn_classify = ctk.CTkButton(left, text="🔍  Classify Packet", height=48, fg_color=ACCENT_BTN, hover_color=ACCENT_BTN_H, corner_radius=12, font=("Segoe UI", 13, "bold"), command=self._on_classify, width=536)
        self.btn_classify.place(x=24, y=y_start + spacing * 3 + 10)
        right = ctk.CTkFrame(content, fg_color=CARD_ALT, corner_radius=12, border_width=1, border_color="#30363d")
        right.place(relx=0.66, rely=0, relwidth=0.34, relheight=1)
        right_header = ctk.CTkFrame(right, fg_color="transparent", width=280, height=40)
        right_header.place(x=20, y=16)
        ctk.CTkLabel(right_header, text="📊", font=("Segoe UI", 16)).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(right_header, text="Classification Result", font=("Segoe UI", 14, "bold"), text_color=TEXT, anchor="w").pack(side="left")
        self.result_card = ctk.CTkFrame(right, fg_color=RESULT_BG, corner_radius=12, border_width=1, border_color="#30363d", width=280, height=420)
        self.result_card.place(x=20, y=55)
        self._show_initial_result()

    def _show_initial_result(self):
        for widget in self.result_card.winfo_children():
            widget.destroy()
        ctk.CTkLabel(self.result_card, text="📁", font=("Segoe UI", 36)).place(relx=0.5, rely=0.25, anchor="center")
        ctk.CTkLabel(self.result_card, text="No prediction yet", text_color=MUTED, font=("Segoe UI", 12)).place(relx=0.5, rely=0.45, anchor="center")
        ctk.CTkLabel(self.result_card, text="Enter packet details\nand click classify", text_color=MUTED, font=("Segoe UI", 9), justify="center").place(relx=0.5, rely=0.6, anchor="center")

    def _on_classify(self):
        try:
            duration_in = int(self.entry_duration_in.get() or "0")
            flow_duration = int(self.entry_flow_duration.get() or "0")
            in_bytes = int(self.entry_in_bytes.get() or "0")
            in_pkts = int(self.entry_in_pkts.get() or "0")
            out_bytes = int(self.entry_out_bytes.get() or "0")
            tcp_win = int(self.entry_tcp_win.get() or "0")
        except ValueError:
            self._show_error("Please enter valid numbers")
            return
        self._update_processing()
        self.btn_classify.configure(state="disabled")
        executor.submit(self._classify_threaded, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win)

    def _classify_threaded(self, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._classify_async_core(duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win))
            loop.close()
            if result:
                predicted_class = result.get("predicted_class", "Unknown")
                is_attack = 1 if predicted_class.lower() != "benign" else 0
                self.db.add_detection(predicted_class, is_attack, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win)
                self.after(0, lambda: self._show_result(predicted_class, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win))
        except Exception as e:
            self.after(0, lambda: self._show_error(f"Error: {str(e)}"))
        finally:
            self.after(0, lambda: self.btn_classify.configure(state="normal"))

    async def _classify_async_core(self, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win):
        payload = {"DURATION_IN": duration_in, "FLOW_DURATION_MILLISECONDS": flow_duration, "IN_BYTES": in_bytes, "IN_PKTS": in_pkts, "OUT_BYTES": out_bytes, "TCP_WIN_MAX_IN": tcp_win}
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(API_URL, json=payload) as response:
                response.raise_for_status()
                return await response.json()

    def _update_processing(self):
        for widget in self.result_card.winfo_children():
            widget.destroy()
        self.result_card.configure(fg_color=RESULT_BG, border_color="#30363d", border_width=1)
        ctk.CTkLabel(self.result_card, text="⏳", font=("Segoe UI", 36)).place(relx=0.5, rely=0.4, anchor="center")
        ctk.CTkLabel(self.result_card, text="Analyzing...", text_color=MUTED, font=("Segoe UI", 12)).place(relx=0.5, rely=0.6, anchor="center")

    def _show_error(self, message):
        for widget in self.result_card.winfo_children():
            widget.destroy()
        self.result_card.configure(fg_color="#7f1d1d", border_color="#ef4444", border_width=2)
        ctk.CTkLabel(self.result_card, text="❌", font=("Segoe UI", 48)).place(relx=0.5, rely=0.35, anchor="center")
        ctk.CTkLabel(self.result_card, text=message, font=("Segoe UI", 12, "bold"), text_color="white", wraplength=240).place(relx=0.5, rely=0.6, anchor="center")

    def _show_result(self, predicted_class, duration_in, flow_duration, in_bytes, in_pkts, out_bytes, tcp_win):
        for widget in self.result_card.winfo_children():
            widget.destroy()
        display_name = self._format_attack_name(predicted_class)
        if predicted_class.lower() == "benign":
            color = COLOR_BENIGN
            icon = "✅"
            border_color = "#10b981"
            text_color = "#d1fae5"
        else:
            color = COLOR_ATTACK
            icon = "🚨"
            border_color = "#ef4444"
            text_color = "#fee2e2"
            executor.submit(play_alert_tone)
        self.result_card.configure(fg_color=color, border_color=border_color, border_width=2)
        ctk.CTkLabel(self.result_card, text=icon, font=("Segoe UI", 48)).place(relx=0.5, rely=0.18, anchor="center")
        ctk.CTkLabel(self.result_card, text=display_name, font=("Segoe UI", 28, "bold"), text_color="white").place(relx=0.5, rely=0.38, anchor="center")
        ctk.CTkFrame(self.result_card, fg_color=text_color, width=220, height=2).place(relx=0.5, rely=0.52, anchor="center")
        details_frame = ctk.CTkFrame(self.result_card, fg_color="transparent", width=240)
        details_frame.place(relx=0.5, rely=0.73, anchor="center")
        details = [("Duration In:", f"{duration_in}"), ("Flow Duration:", f"{flow_duration} ms"), ("In Bytes:", f"{in_bytes}"), ("In Packets:", f"{in_pkts}"), ("Out Bytes:", f"{out_bytes}"), ("TCP Win Max:", f"{tcp_win}")]
        for label, value in details:
            row = ctk.CTkFrame(details_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=label, text_color=text_color, font=("Segoe UI", 9), anchor="w", width=90).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=value, text_color="white", font=("Segoe UI", 9, "bold"), anchor="e").pack(side="right", padx=5)

    def _format_attack_name(self, attack_class):
        attack_names = {"backdoor": "Backdoor Attack", "benign": "Benign", "bot": "Bot Attack", "ddos": "DDoS Attack", "dos": "DoS Attack", "exploits": "Exploits Attack", "generic": "Generic Attack", "scanning": "Port Scanning"}
        lower_class = attack_class.lower().strip()
        return attack_names.get(lower_class, attack_class.replace("_", " ").title())

    def show(self):
        pass

    def hide(self):
        pass

# ==================== REAL-TIME MONITORING PAGE ====================
# #RealTimeMonitoring #PacketCapture #LiveAnalysis #TSharkIntegration
class RealTimeMonitorPage(ctk.CTkFrame):
    """Real-time packet capture and monitoring with interface selection"""
    def __init__(self, master, db_manager):
        super().__init__(master, fg_color="transparent")
        self.db = db_manager
        self.is_monitoring = False
        self.tshark_process = None
        self.flows = {}
        self.flows_lock = threading.Lock()
        self.stats = {'total_flows': 0, 'attacks_detected': 0, 'benign_filtered': 0}
        self.stats_lock = threading.Lock()
        self.available_interfaces = []
        self.selected_interface = None
        self._build()
        self._load_interfaces()

    def _build(self):
        wrapper = ctk.CTkFrame(self, fg_color=CARD, corner_radius=14, border_width=1, border_color="#30363d")
        wrapper.place(relx=0.02, rely=0.02, relwidth=0.96, relheight=0.96)
        
        # Header
        header = ctk.CTkFrame(wrapper, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(16, 0))
        ctk.CTkLabel(header, text="🔴", font=("Segoe UI", 24)).pack(side="left", padx=(0, 10))
        header_text_frame = ctk.CTkFrame(header, fg_color="transparent")
        header_text_frame.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(header_text_frame, text="Real-Time Network Monitor", font=("Segoe UI", 20, "bold"), text_color=TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(header_text_frame, text="Live packet capture and attack detection", text_color=MUTED, font=("Segoe UI", 11), anchor="w").pack(anchor="w", pady=(2, 0))
        
        # Interface Selection Panel
        interface_panel = ctk.CTkFrame(wrapper, fg_color=CARD_ALT, corner_radius=12, border_width=1, border_color="#30363d", height=100)
        interface_panel.pack(fill="x", padx=20, pady=10)
        interface_panel.pack_propagate(False)
        
        interface_content = ctk.CTkFrame(interface_panel, fg_color="transparent")
        interface_content.pack(pady=15, padx=20, fill="both", expand=True)
        
        # Left side - Interface selector
        left_frame = ctk.CTkFrame(interface_content, fg_color="transparent")
        left_frame.pack(side="left", fill="both", expand=True)
        
        ctk.CTkLabel(left_frame, text="🌐 Network Interface:", font=("Segoe UI", 12, "bold"), 
                    text_color=TEXT, anchor="w").pack(anchor="w", pady=(0, 8))
        
        selector_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        selector_frame.pack(fill="x")
        
        self.interface_dropdown = ctk.CTkComboBox(
            selector_frame,
            values=["Loading interfaces..."],
            width=400,
            height=38,
            font=("Segoe UI", 11),
            dropdown_font=("Segoe UI", 10),
            fg_color="#161b22",
            border_color="#30363d",
            button_color="#0969da",
            button_hover_color="#1f6feb",
            state="readonly"
        )
        self.interface_dropdown.pack(side="left", padx=(0, 10))
        
        self.btn_refresh_interfaces = ctk.CTkButton(
            selector_frame,
            text="🔄",
            width=38,
            height=38,
            fg_color="#10b981",
            hover_color="#059669",
            font=("Segoe UI", 14),
            corner_radius=8,
            command=self._load_interfaces
        )
        self.btn_refresh_interfaces.pack(side="left")
        
        # Right side - Status indicator
        right_frame = ctk.CTkFrame(interface_content, fg_color="transparent")
        right_frame.pack(side="right", padx=(20, 0))
        
        self.status_indicator = ctk.CTkFrame(right_frame, fg_color="#1a1f35", corner_radius=10, 
                                            border_width=2, border_color="#30363d")
        self.status_indicator.pack()
        
        status_content = ctk.CTkFrame(self.status_indicator, fg_color="transparent")
        status_content.pack(padx=15, pady=10)
        
        self.status_icon = ctk.CTkLabel(status_content, text="⚪", font=("Segoe UI", 20))
        self.status_icon.pack(side="left", padx=(0, 10))
        
        self.status_label = ctk.CTkLabel(status_content, text="Idle", font=("Segoe UI", 13, "bold"), 
                                        text_color=MUTED)
        self.status_label.pack(side="left")
        
        # Control panel
        control_panel = ctk.CTkFrame(wrapper, fg_color=CARD_ALT, corner_radius=12, border_width=1, border_color="#30363d", height=70)
        control_panel.pack(fill="x", padx=20, pady=10)
        control_panel.pack_propagate(False)
        
        control_content = ctk.CTkFrame(control_panel, fg_color="transparent")
        control_content.pack(pady=15, padx=20)
                # Start/Stop Buttons - #ActionButtons #UserControls

        self.btn_start = ctk.CTkButton(control_content, text="▶  Start Monitoring", width=200, height=42, 
                                      fg_color="#10b981", hover_color="#059669", 
                                      font=("Segoe UI", 12, "bold"), corner_radius=10,
                                      command=self._start_monitoring)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ctk.CTkButton(control_content, text="⏸  Stop Monitoring", width=200, height=42,
                                     fg_color="#ef4444", hover_color="#dc2626",
                                     font=("Segoe UI", 12, "bold"), corner_radius=10,
                                     command=self._stop_monitoring, state="disabled")
        self.btn_stop.pack(side="left", padx=5)
        
        # Stats panel
        stats_frame = ctk.CTkFrame(wrapper, fg_color="transparent", height=90)
        stats_frame.pack(fill="x", padx=20, pady=5)
        
        self.stat_total = self._create_stat_box(stats_frame, "Total Flows", "0", "#3b82f6")
        self.stat_total.pack(side="left", fill="x", expand=True, padx=5)
        
        self.stat_attacks = self._create_stat_box(stats_frame, "Attacks Detected", "0", "#ef4444")
        self.stat_attacks.pack(side="left", fill="x", expand=True, padx=5)
        
        self.stat_benign = self._create_stat_box(stats_frame, "Benign Filtered", "0", "#10b981")
        self.stat_benign.pack(side="left", fill="x", expand=True, padx=5)
        
        # Log area
        log_frame = ctk.CTkFrame(wrapper, fg_color=CARD_ALT, corner_radius=12, border_width=1, border_color="#30363d")
        log_frame.pack(fill="both", expand=True, padx=20, pady=(5, 20))
        
        log_header = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_header.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(log_header, text="📋 Monitoring Log", font=("Segoe UI", 14, "bold"), 
                    text_color="#06b6d4").pack(side="left")
        
        self.btn_clear_log = ctk.CTkButton(log_header, text="🗑 Clear Log", width=100, height=32,
                                          fg_color="#64748b", hover_color="#475569",
                                          font=("Segoe UI", 10, "bold"), corner_radius=8,
                                          command=self._clear_log)
        self.btn_clear_log.pack(side="right")
        
        self.log_scroll = ctk.CTkScrollableFrame(log_frame, fg_color="#0d1117", corner_radius=10)
        self.log_scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self._log_message("⚡ System ready. Select an interface and click Start Monitoring.", "#06b6d4")

    def _create_stat_box(self, parent, title, value, color):
        box = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=10, border_width=1, border_color="#30363d", height=80)
        box.pack_propagate(False)
        ctk.CTkLabel(box, text=title, font=("Segoe UI", 10), text_color=MUTED).pack(pady=(10, 5))
        value_label = ctk.CTkLabel(box, text=value, font=("Segoe UI", 22, "bold"), text_color=color)
        value_label.pack()
        box.value_label = value_label # #DynamicLabel #UpdateableValue
        return box

    def _load_interfaces(self):
        """Load available network interfaces using tshark -D"""
        self.interface_dropdown.configure(values=["Loading..."])
        self.interface_dropdown.set("Loading...")
        self.btn_refresh_interfaces.configure(state="disabled")
        
        def _load_thread():
            try:
                result = subprocess.run(
                    [TSHARK_PATH, '-D'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
                )
                
                if result.returncode != 0:
                    self.after(0, lambda: self._log_message(f"❌ Error loading interfaces: {result.stderr}", "#ef4444"))
                    self.after(0, lambda: self.interface_dropdown.configure(values=["No interfaces found"]))
                    return
                
                interfaces = []
                interface_map = {}
                
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    # Parse format: "1. \Device\NPF_{GUID} (Interface Name)"
                    parts = line.split('.', 1)
                    if len(parts) == 2:
                        interface_num = parts[0].strip()
                        interface_info = parts[1].strip()
                        
                        # Extract interface name from parentheses if available
                        if '(' in interface_info and ')' in interface_info:
                            display_name = interface_info[interface_info.find('(')+1:interface_info.find(')')]
                        else:
                            display_name = interface_info[:50]  # Truncate if too long
                        
                        display_text = f"{interface_num}. {display_name}"
                        interfaces.append(display_text)
                        interface_map[display_text] = interface_num
                
                if not interfaces:
                    interfaces = ["No interfaces found"]
                    self.after(0, lambda: self._log_message("⚠ No network interfaces detected", "#fbbf24"))
                else:
                    self.after(0, lambda: self._log_message(f"✅ Found {len(interfaces)} network interface(s)", "#10b981"))
                
                self.available_interfaces = interface_map
                self.after(0, lambda: self.interface_dropdown.configure(values=interfaces))
                self.after(0, lambda: self.interface_dropdown.set(interfaces[0] if interfaces else "No interfaces"))
                
            except subprocess.TimeoutExpired:
                self.after(0, lambda: self._log_message("❌ Timeout while loading interfaces", "#ef4444"))
                self.after(0, lambda: self.interface_dropdown.configure(values=["Error: Timeout"]))
            except FileNotFoundError:
                self.after(0, lambda: self._log_message(f"❌ TShark not found at: {TSHARK_PATH}", "#ef4444"))
                self.after(0, lambda: self.interface_dropdown.configure(values=["TShark not found"]))
            except Exception as e:
                self.after(0, lambda: self._log_message(f"❌ Error: {str(e)}", "#ef4444"))
                self.after(0, lambda: self.interface_dropdown.configure(values=["Error loading"]))
            finally:
                self.after(0, lambda: self.btn_refresh_interfaces.configure(state="normal"))
        
        threading.Thread(target=_load_thread, daemon=True).start()

    def _start_monitoring(self):
        if self.is_monitoring:
            return
        
        # Get selected interface
        selected = self.interface_dropdown.get()
        
        if not selected or selected in ["Loading...", "No interfaces found", "TShark not found", "Error loading"]:
            self._log_message("❌ Please select a valid network interface", "#ef4444")
            return
        
        # Extract interface number
        if selected in self.available_interfaces:
            interface_num = self.available_interfaces[selected]
        else:
            self._log_message("❌ Invalid interface selection", "#ef4444")
            return
        
        # Check if TShark exists
        if not os.path.exists(TSHARK_PATH):
            self._log_message(f"❌ TShark not found at: {TSHARK_PATH}", "#ef4444")
            messagebox.showerror("Error", f"TShark not found at:\n{TSHARK_PATH}\n\nPlease install Wireshark.")
            return
        
        self.selected_interface = interface_num
        self.is_monitoring = True
        
        # Update UI
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.interface_dropdown.configure(state="disabled")
        self.btn_refresh_interfaces.configure(state="disabled")
        
        self.status_icon.configure(text="🟢")
        self.status_label.configure(text="Monitoring", text_color="#10b981")
        self.status_indicator.configure(border_color="#10b981")
        
        # Reset stats
        with self.stats_lock:
            self.stats = {'total_flows': 0, 'attacks_detected': 0, 'benign_filtered': 0}
        
        # Clear flows
        with self.flows_lock:
            self.flows.clear()
        
        # Log start
        self._log_message(f"▶ Monitoring started on interface: {selected}", "#10b981")
        self._log_message(f"🔍 Capturing packets... (Attacks will be displayed below)", "#06b6d4")
        
        # Start capture threads
        threading.Thread(target=self._capture_packets, args=(interface_num,), daemon=True).start()
        threading.Thread(target=self._cleaner_worker, daemon=True).start()
        threading.Thread(target=self._update_stats_ui, daemon=True).start()

    def _stop_monitoring(self):
        self.is_monitoring = False
        
        if self.tshark_process:
            try:
                self.tshark_process.terminate()
                self.tshark_process.wait(timeout=2)
            except:
                try:
                    self.tshark_process.kill()
                except:
                    pass
        with self.flows_lock:
            self.flows.clear()
        # Update UI
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.interface_dropdown.configure(state="readonly")
        self.btn_refresh_interfaces.configure(state="normal")
        
        self.status_icon.configure(text="🔴")
        self.status_label.configure(text="Stopped", text_color="#ef4444")
        self.status_indicator.configure(border_color="#ef4444")
        
        # Log stop
        self._log_message(f"⏸ Monitoring stopped. Total attacks detected: {self.stats['attacks_detected']}", "#ef4444")

    def _log_message(self, message, color="#94a3b8"):
        """Add a message to the log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        log_entry = ctk.CTkFrame(self.log_scroll, fg_color="transparent")
        log_entry.pack(fill="x", pady=2, padx=5)
        
        ctk.CTkLabel(log_entry, text=f"[{timestamp}]", font=("Consolas", 9), 
                    text_color="#64748b", width=70, anchor="w").pack(side="left", padx=(0, 5))
        
        ctk.CTkLabel(log_entry, text=message, font=("Segoe UI", 10), 
                    text_color=color, anchor="w").pack(side="left", fill="x", expand=True)
        
        # Auto-scroll to bottom
        self.log_scroll._parent_canvas.yview_moveto(1.0)

    def _clear_log(self):
        """Clear all log entries"""
        for widget in self.log_scroll.winfo_children():
            widget.destroy()
        self._log_message("🗑 Log cleared", "#64748b")

    def _capture_packets(self, interface):
        """Start TShark capture"""
        cmd = [
            TSHARK_PATH,
            '-i', interface,
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'ip.len',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'ip.proto',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tcp.window_size_value',
            '-e', 'tcp.len',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'udp.length',
            '-E', 'separator=|',
            '-E', 'occurrence=f',
            '-l'
        ]
        
        try:
            self.tshark_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1, universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            for line in self.tshark_process.stdout:
                if not self.is_monitoring:
                    break
                if line.strip():
                    self._process_packet(line)
                    
        except Exception as e:
            self.after(0, lambda: self._log_message(f"❌ Capture error: {str(e)}", "#ef4444"))
            self.after(0, self._stop_monitoring)

    def _process_packet(self, line):
        """Process individual packet"""
        try:
            fields = line.strip().split('|')
            if len(fields) < 5:
                return
            
            ts_str = fields[0].strip()
            ip_len_str = fields[1].strip()
            src = fields[2].strip()
            dst = fields[3].strip()
            ip_proto_str = fields[4].strip()
            
            if not (src and dst and ts_str and ip_proto_str):
                return
            
            ts = float(ts_str)
            ip_proto = int(ip_proto_str)
            
            # TCP
            if ip_proto == 6 and len(fields) >= 9:
                proto = "tcp"
                sport_str = fields[5].strip()
                dport_str = fields[6].strip()
                tcp_win_str = fields[7].strip()
                tcp_payload_str = fields[8].strip()
                
                if not (sport_str and dport_str):
                    return
                
                sport = int(sport_str)
                dport = int(dport_str)
                tcp_win = int(tcp_win_str) if tcp_win_str else None
                payload_bytes = int(tcp_payload_str) if tcp_payload_str and tcp_payload_str != '0' else 0
                
            # UDP
            elif ip_proto == 17 and len(fields) >= 12:
                proto = "udp"
                sport_str = fields[9].strip()
                dport_str = fields[10].strip()
                udp_len_str = fields[11].strip()
                
                if not (sport_str and dport_str):
                    return
                
                sport = int(sport_str)
                dport = int(dport_str)
                tcp_win = None
                
                if udp_len_str:
                    udp_total = int(udp_len_str)
                    payload_bytes = max(0, udp_total - 8)
                else:
                    payload_bytes = 0
            else:
                return
            
            # Flow management
            key = make_flow_key(src, sport, dst, dport, proto)
            
            with self.flows_lock:
                if key not in self.flows:
                    self.flows[key] = Flow(src, sport, dst, dport, proto, ts, 
                                         first_pkt_src=src, first_pkt_dst=dst)
                flow = self.flows[key]
            
            flow.update(src, dst, payload_bytes, ts, tcp_win)
            
        except Exception as e:
            pass  # Silently ignore packet parsing errors

    def _cleaner_worker(self):
        """Flush inactive flows and send to API"""
        while self.is_monitoring:
            now = time.time()
            to_send = []
            
            with self.flows_lock:
                for k, flow in list(self.flows.items()):
                    inactive = (now - flow.last_ts) > FLOW_INACTIVE_TIMEOUT
                    too_long = flow.duration_seconds() > FLOW_MAX_DURATION
                    
                    if inactive or too_long:
                        to_send.append((k, flow))
                        del self.flows[k]
            
            for k, flow in to_send:
                self._analyze_flow(flow)
            
            time.sleep(1.0)

    def _analyze_flow(self, flow):
        """Send flow to API and log if attack"""
        if not self.is_monitoring:
            return
        payload = flow.to_payload()
        conn_info = flow.get_display_info()
        
        with self.stats_lock:
            self.stats['total_flows'] += 1
        
        try:
            resp = requests.post(API_URL, json=payload, timeout=8)
            data = resp.json()
            
            pred = (data.get("predicted_class") or 
                   data.get("prediction", {}).get("predicted_class") or
                   "UNKNOWN")
            
            if is_attack(pred):
                with self.stats_lock:
                    self.stats['attacks_detected'] += 1
                
                # Add to database
                self.db.add_detection(pred, 1, payload['DURATION_IN'], 
                                     payload['FLOW_DURATION_MILLISECONDS'],
                                     payload['IN_BYTES'], payload['IN_PKTS'],
                                     payload['OUT_BYTES'], payload['TCP_WIN_MAX_IN'])
                
                # Log attack in UI
                self.after(0, lambda p=pred, c=conn_info, pl=payload: self._log_attack_detailed(p, c, pl))
                
                # Play alert
                executor.submit(play_alert_tone)
            else:
                with self.stats_lock:
                    self.stats['benign_filtered'] += 1
            
        except requests.exceptions.Timeout:
            pass  # Silently ignore timeouts
        except Exception as e:
            pass  # Silently ignore API errors

    def _log_attack_detailed(self, attack_type, conn_info, payload):
        """Add detailed attack entry to log"""
        attack_name = self._normalize_attack_name(attack_type)
        config = ATTACK_CONFIG.get(attack_name, ATTACK_CONFIG["Generic"])
        colors = SEVERITY_COLORS[config["severity"]]
        
        # Add colored log entry
        log_entry = ctk.CTkFrame(self.log_scroll, fg_color=colors['bg'], corner_radius=8, 
                                border_width=2, border_color=colors['border'])
        log_entry.pack(fill="x", pady=4, padx=5)
        
        content = ctk.CTkFrame(log_entry, fg_color="transparent")
        content.pack(fill="both", padx=10, pady=8)
        
        # Header
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(0, 4))
        
        ctk.CTkLabel(header, text=f"{config['icon']} {attack_name} Attack Detected", 
                    font=("Segoe UI", 11, "bold"), text_color="white").pack(side="left")
        
        time_str = datetime.now().strftime('%H:%M:%S')
        ctk.CTkLabel(header, text=f"🕐 {time_str}", font=("Segoe UI", 8), 
                    text_color=colors['text']).pack(side="right")
        
        # Connection info
        ctk.CTkLabel(content, text=conn_info, font=("Segoe UI", 9), 
                    text_color=colors['text'], anchor="w").pack(fill="x", pady=2)
        
        # Stats
        stats_text = (f"Duration: {payload['DURATION_IN']}s | "
                     f"In: {payload['IN_BYTES']} bytes ({payload['IN_PKTS']} pkts) | "
                     f"Out: {payload['OUT_BYTES']} bytes")
        ctk.CTkLabel(content, text=stats_text, font=("Segoe UI", 8), 
                    text_color=colors['text'], anchor="w").pack(fill="x")
        
        # Auto-scroll to bottom
        self.log_scroll._parent_canvas.yview_moveto(1.0)

    def _normalize_attack_name(self, attack_class):
        lower = attack_class.lower().strip()
        if "ddos" in lower: return "DDoS"
        elif "dos" in lower: return "DoS"
        elif "backdoor" in lower: return "Backdoor"
        elif "bot" in lower: return "Bot"
        elif "exploit" in lower: return "Exploits"
        elif "scan" in lower: return "scanning"
        else: return "Generic"

    def _update_stats_ui(self):
        """Update statistics display"""
        while self.is_monitoring:
            with self.stats_lock:
                total = self.stats['total_flows']
                attacks = self.stats['attacks_detected']
                benign = self.stats['benign_filtered']
            
            self.after(0, lambda t=total: self.stat_total.value_label.configure(text=str(t)))
            self.after(0, lambda a=attacks: self.stat_attacks.value_label.configure(text=str(a)))
            self.after(0, lambda b=benign: self.stat_benign.value_label.configure(text=str(b)))
            
            time.sleep(2)

    def show(self):
        pass

    def hide(self):
        if self.is_monitoring:
            self._stop_monitoring()

# ==================== Splash & Login Classes ====================
# ==================== Splash & Login Classes ====================
class Splash(ctk.CTkFrame):
    def __init__(self, master, on_complete, load_callback=None):
        super().__init__(master, fg_color="#0a0e1a")
        self.on_complete = on_complete
        self.load_callback = load_callback
        self.progress = 0
        self.loading_stage = 0
        self._build()
        self.after(200, self._start_loading)

    def _build(self):
        container = ctk.CTkFrame(self, fg_color="transparent", width=600, height=400)
        container.place(relx=0.5, rely=0.5, anchor="center")
        icon_frame = ctk.CTkFrame(container, fg_color="#0969da", corner_radius=60, width=100, height=100)
        icon_frame.place(relx=0.5, rely=0.25, anchor="center")
        ctk.CTkLabel(icon_frame, text="🛡", font=("Segoe UI", 50)).place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(container, text="ArgusMind", font=("Segoe UI", 40, "bold"), text_color=TEXT).place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(container, text="Intelligent Network Vigilance", font=("Segoe UI", 14), text_color=MUTED).place(relx=0.5, rely=0.62, anchor="center")
        self.progress_bar = ctk.CTkProgressBar(container, width=400, height=8, progress_color="#0969da", fg_color="#1a1f35", corner_radius=4)
        self.progress_bar.place(relx=0.5, rely=0.75, anchor="center")
        self.progress_bar.set(0)
        self.status_label = ctk.CTkLabel(container, text="Initializing...", font=("Segoe UI", 11), text_color=MUTED)
        self.status_label.place(relx=0.5, rely=0.82, anchor="center")

    def _start_loading(self):
        """Start the loading process with page initialization"""
        self._animate()

    def _animate(self):
        if self.progress < 100:
            self.progress += 2
            self.progress_bar.set(self.progress / 100)
            
            # Stage 1: Loading modules (0-25%)
            if self.progress <= 25:
                if self.loading_stage == 0:
                    self.status_label.configure(text="Loading modules...")
                    self.loading_stage = 1
            
            # Stage 2: Database connection (25-40%)
            elif self.progress <= 40:
                if self.loading_stage == 1:
                    self.status_label.configure(text="Connecting to database...")
                    self.loading_stage = 2
            
            # Stage 3: Initialize Dashboard (40-60%)
            elif self.progress <= 60:
                if self.loading_stage == 2:
                    self.status_label.configure(text="Initializing Dashboard...")
                    if self.load_callback:
                        self.load_callback("dashboard")
                    self.loading_stage = 3
            
            # Stage 4: Initialize NIDS (60-80%)
            elif self.progress <= 80:
                if self.loading_stage == 3:
                    self.status_label.configure(text="Initializing NIDS Scanner...")
                    if self.load_callback:
                        self.load_callback("nids")
                    self.loading_stage = 4
            
            # Stage 5: Initialize Real-Time Monitor (80-95%)
            elif self.progress <= 95:
                if self.loading_stage == 4:
                    self.status_label.configure(text="Initializing Real-Time Monitor...")
                    if self.load_callback:
                        self.load_callback("realtime")
                    self.loading_stage = 5
            
            # Stage 6: Final touches (95-100%)
            else:
                if self.loading_stage == 5:
                    self.status_label.configure(text="Almost ready...")
                    self.loading_stage = 6
            
            self.after(25, self._animate)
        else:
            self.status_label.configure(text="Ready!", text_color="#10b981")
            self.after(500, self.on_complete)

class LoginPage(ctk.CTkFrame):
    def __init__(self, master, on_login):
        super().__init__(master, fg_color="#0a0e1a")
        self.on_login = on_login
        self._build()

    def _build(self):
        # Left half (Dashboard)
        left_panel = ctk.CTkFrame(self, fg_color="transparent")
        left_panel.pack(side="left", fill="both", expand=True)
        icon_container = ctk.CTkFrame(left_panel, fg_color="#0969da", width=120, height=120, corner_radius=60)
        icon_container.pack(pady=(100, 20))
        icon_container.pack_propagate(False)  #  This line is very important
        ctk.CTkLabel(icon_container, text="🛡", font=("Segoe UI", 60), text_color="white").place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(left_panel, text="ArgusMind", font=("Segoe UI", 42, "bold"), text_color=TEXT).pack(pady=(10, 5))
        ctk.CTkLabel(left_panel, text="Intelligent Network Vigilance", font=("Segoe UI", 14), text_color=MUTED).pack(pady=(0, 20))

        features = [
            ("🔒", "Secure Authentication", "Multi-layer security protocol"),
            ("📊", "Real-Time Analytics", "Live threat monitoring and detection"),
            ("🚨", "Attack Detection", "Advanced ML-powered classification")
        ]
        for icon, title, desc in features:
           # Card with shadow effect and hover
            feature_card = ctk.CTkFrame(left_panel, fg_color=CARD,corner_radius=15,border_width=2,border_color="#30363d")
            feature_card.pack(fill="x", padx=20, pady=10)
            inner_padding = ctk.CTkFrame(feature_card,fg_color="transparent") 
            inner_padding.pack(fill="both", padx=15, pady=15)

# Content frame
            content = ctk.CTkFrame(inner_padding,fg_color="transparent")
            content.pack(fill="x")
            ctk.CTkLabel(content, text=icon, font=("Segoe UI", 24)).pack(side="left", padx=(8, 24))
            text_frame = ctk.CTkFrame(content, fg_color="transparent")
            text_frame.pack(side="left", fill="both", expand=True)
            ctk.CTkLabel(text_frame, text=title, font=("Segoe UI", 13, "bold"), text_color=TEXT, anchor="w").pack(anchor="w")
            ctk.CTkLabel(text_frame, text=desc, font=("Segoe UI", 10), text_color=MUTED, anchor="w").pack(anchor="w")

        #Right half (Login)
        right_panel = ctk.CTkFrame(self, fg_color=CARD)
        right_panel.pack(side="left", fill="both", expand=True)

        login_card = ctk.CTkFrame(right_panel, fg_color=CARD_ALT, corner_radius=20, border_width=2, border_color="#30363d", width=480, height=500)
        login_card.pack(expand=True, pady=50)
        login_card.pack_propagate(False)

        ctk.CTkLabel(login_card, text="Welcome Back", font=("Segoe UI", 28, "bold"), text_color=TEXT).pack(pady=(28, 5))
        ctk.CTkLabel(login_card, text="Please login to your account", font=("Segoe UI", 12), text_color=MUTED).pack(pady=(0, 20))

        form_frame = ctk.CTkFrame(login_card, fg_color="transparent", width=400, height=250)
        form_frame.pack(pady=(0, 0))
        ctk.CTkLabel(form_frame, text="Username", font=("Segoe UI", 12, "bold"), text_color=TEXT, anchor="w").pack(anchor="w", pady=(0, 8))
        self.username_entry = ctk.CTkEntry(form_frame, placeholder_text="Enter your username", height=50, width=400, font=("Segoe UI", 13), border_width=2, border_color="#30363d", fg_color="#161b22")
        self.username_entry.pack(pady=(0, 20))
        ctk.CTkLabel(form_frame, text="Password", font=("Segoe UI", 12, "bold"), text_color=TEXT, anchor="w").pack(anchor="w", pady=(0, 8))
        self.password_entry = ctk.CTkEntry(form_frame, placeholder_text="Enter your password", show="●", height=50, width=400, font=("Segoe UI", 13), border_width=2, border_color="#30363d", fg_color="#161b22")
        self.password_entry.pack(pady=(0, 25))
        self.username_entry.bind("<Return>", lambda e: self._attempt_login())
        self.password_entry.bind("<Return>", lambda e: self._attempt_login())
        self.login_btn = ctk.CTkButton(form_frame, text="Login", height=50, width=400, corner_radius=12, fg_color="#0969da", hover_color="#1f6feb", font=("Segoe UI", 14, "bold"), command=self._attempt_login)
        self.login_btn.pack()
        ctk.CTkLabel(login_card, text="Default credentials: admin / admin", font=("Segoe UI", 10), text_color=MUTED).pack(side="bottom", pady=16)

    def _attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if username == "admin" and password == "admin":
            self.login_btn.configure(text="✓ Success!", fg_color="#10b981")
            self.after(500, lambda: self.on_login(username))
        else:
            self.login_btn.configure(text="✗ Invalid Credentials", fg_color="#ef4444")
            self.after(1500, lambda: self.login_btn.configure(text="Login", fg_color="#0969da"))

# ==================== Main App ====================
# ==================== Main App ====================
class MainApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ArgusMind - Intelligent Network Vigilance")
        self.geometry(f"{APP_W}x{APP_H}")
        self.minsize(1000, 650)
        self.configure(fg_color="#0a0e1a")
        preload_sounds()
        self.db = DatabaseManager()
        self.bg = GradientBG(self, top=BG_TOP, bottom=BG_BOTTOM)
        self.bg.pack(fill="both", expand=True)
        self.sidebar = Sidebar(self.bg, on_nav=self._navigate, width=260)
        self.sidebar.place_forget() 
        self.content = ctk.CTkFrame(self.bg, fg_color="#0a0e1a")
        self.content.place(x=0, y=0, relwidth=1, relheight=1)  

        self.mini_loader = MiniLoader(self.content)
        self.splash = Splash(self.content, on_complete=self._show_login, load_callback=self._preload_page)
        self.login = LoginPage(self.content, on_login=self._on_login)
        
        # Initialize pages as None - will be created during splash
        self.dashboard = None
        self.nids = None
        self.realtime = None
        
        self._show_widget(self.splash)
        self.current_page = None
        
        print("🚀 Application started - Pages will be preloaded during splash screen")

    def _preload_page(self, page_name):
        """Preload pages in the background during splash screen"""
        try:
            if page_name == "dashboard" and self.dashboard is None:
                print("⏳ Preloading Dashboard...")
                self.dashboard = DashboardPage(self.content, self.db)
                print("✅ Dashboard preloaded successfully")
                
            elif page_name == "nids" and self.nids is None:
                print("⏳ Preloading NIDS Scanner...")
                self.nids = NIDSPage(self.content, self.db)
                print("✅ NIDS Scanner preloaded successfully")
                
            elif page_name == "realtime" and self.realtime is None:
                print("⏳ Preloading Real-Time Monitor...")
                self.realtime = RealTimeMonitorPage(self.content, self.db)
                print("✅ Real-Time Monitor preloaded successfully")
                
        except Exception as e:
            print(f"❌ Error preloading {page_name}: {e}")

    def _show_widget(self, widget):
        for w in [self.splash, self.login, self.dashboard, self.nids, self.realtime]:
            if w:
                w.place_forget()
        if widget:
            widget.place(relx=0, rely=0, relwidth=1, relheight=1)

    def _show_login(self):
        print("✅ All pages preloaded - Showing login screen")
        self._show_widget(self.login)

    def _on_login(self, username):
        print(f"👤 User logged in: {username}")
        self.sidebar.place(x=0, y=0, relheight=1) 
        self.content.place(x=260, y=0, relwidth=1-260/APP_W, relheight=1)  
        
        # Since pages are already preloaded, directly show dashboard
        self.after(50, self._show_dashboard_after_login)

    def _show_dashboard_after_login(self):
        """Show dashboard immediately since it's already preloaded"""
        print("📊 Displaying Dashboard (already preloaded)...")
        
        # Show a brief loader for smooth transition
        self.mini_loader.start("Loading Dashboard...")
        self.update()
        
        self.after(300, self._finish_login_to_dashboard)

    def _finish_login_to_dashboard(self):
        self._show_widget(self.dashboard)
        self.update_idletasks()
        self.after(100, self._complete_login)

    def _complete_login(self):
        self.mini_loader.stop()
        self.sidebar.set_active("dashboard")
        self.current_page = self.dashboard
        self.dashboard.show()
        start_background_music()
        print("✅ Dashboard displayed - System ready")

    def _navigate(self, key):
        if key == "exit":
            self._handle_exit()
            return

        if key == "dashboard" and self.current_page == self.dashboard:
            return
        if key == "nids" and self.current_page == self.nids:
            return
        if key == "realtime" and self.current_page == self.realtime:
            return

        self.sidebar.btn_dashboard.configure(state="disabled")
        self.sidebar.btn_nids.configure(state="disabled")
        self.sidebar.btn_realtime.configure(state="disabled")

        if key == "dashboard":
            if self.current_page and hasattr(self.current_page, 'hide'):
                self.current_page.hide()
                self.current_page.place_forget()
            self.mini_loader.start("Loading Dashboard...")
            self.mini_loader.lift()
            self.update_idletasks()
            self.after(100, self._load_dashboard_safe)

        elif key == "nids":
            if self.current_page and hasattr(self.current_page, 'hide'):
                self.current_page.hide()
                self.current_page.place_forget()
            self.mini_loader.start("Loading NIDS Scanner...")
            self.mini_loader.lift()
            self.update_idletasks()
            self.after(100, self._load_nids_safe)

        elif key == "realtime":
            if self.current_page and hasattr(self.current_page, 'hide'):
                self.current_page.hide()
                self.current_page.place_forget()
            self.mini_loader.start("Loading Real-Time Monitor...")
            self.mini_loader.lift()
            self.update_idletasks()
            self.after(100, self._load_realtime_safe)

    def _load_dashboard_safe(self):
        try:
            # Dashboard is already preloaded, just show it
            self._show_widget(self.dashboard)
            self.update_idletasks()
            self.after(50, self._finalize_dashboard)
        except Exception as e:
            print(f"Error loading dashboard: {e}")
            self.mini_loader.stop()
            self._enable_nav_buttons()

    def _finalize_dashboard(self):
        try:
            self.mini_loader.stop()
            self.sidebar.set_active("dashboard")
            self.current_page = self.dashboard
            self.dashboard.show()
            self._enable_nav_buttons()
        except Exception as e:
            print(f"Error finalizing dashboard: {e}")
            self._enable_nav_buttons()

    def _load_nids_safe(self):
        try:
            # NIDS is already preloaded, just show it
            self._show_widget(self.nids)
            self.update_idletasks()
            self.after(50, self._finalize_nids)
        except Exception as e:
            print(f"Error loading NIDS: {e}")
            self.mini_loader.stop()
            self._enable_nav_buttons()

    def _finalize_nids(self):
        try:
            self.mini_loader.stop()
            self.sidebar.set_active("nids")
            self.current_page = self.nids
            self.nids.show()
            self._enable_nav_buttons()
        except Exception as e:
            print(f"Error finalizing NIDS: {e}")
            self._enable_nav_buttons()

    def _load_realtime_safe(self):
        try:
            # Real-time monitor is already preloaded, just show it
            self._show_widget(self.realtime)
            self.update_idletasks()
            self.after(50, self._finalize_realtime)
        except Exception as e:
            print(f"Error loading real-time monitor: {e}")
            self.mini_loader.stop()
            self._enable_nav_buttons()

    def _finalize_realtime(self):
        try:
            self.mini_loader.stop()
            self.sidebar.set_active("realtime")
            self.current_page = self.realtime
            self.realtime.show()
            self._enable_nav_buttons()
        except Exception as e:
            print(f"Error finalizing real-time monitor: {e}")
            self._enable_nav_buttons()

    def _enable_nav_buttons(self):
        self.sidebar.btn_dashboard.configure(state="normal")
        self.sidebar.btn_nids.configure(state="normal")
        self.sidebar.btn_realtime.configure(state="normal")

    def _handle_exit(self):
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM detections WHERE is_attack = 1")
        attack_count = cursor.fetchone()[0]
    
        if attack_count > 0:
            result = messagebox.askyesnocancel(
                "Confirm Exit",
                f"Found {attack_count} attack(s) in database.\n\n"
                "Would you like to export attack report before exiting?\n\n"
                "Yes = Export report & delete database\n"
                "No = Delete database without exporting\n"
                "Cancel = Return to application"
        )
        
            if result is None:  # Cancel
                return
        
            if result:  # Yes - Export then delete
                exported_file = self.db.export_attacks_to_file()
            
                if exported_file:
                    messagebox.showinfo(
                        "Report Exported", 
                        f"Attack report saved successfully!\n\n"
                        f"File: {os.path.basename(exported_file)}\n"
                        f"Location: {os.path.dirname(exported_file)}\n\n"
                        "Database will now be deleted."
                    )
                else:
                    messagebox.showwarning(
                        "Export Failed",
                        "Failed to export attack report.\n"
                        "Database will still be deleted."
                    )
                
                # delete database
                if self.db.delete_database():
                    messagebox.showinfo("Success", "Database deleted successfully!")
                else:
                    messagebox.showerror("Error", "Failed to delete database")
            
            else:  # No - Delete without exporting
                if self.db.delete_database():
                    messagebox.showinfo("Success", "Database deleted successfully!")
                else:
                    messagebox.showerror("Error", "Failed to delete database")
        
        else:
            result = messagebox.askyesno(
                "Confirm Exit",
                "No attacks detected in current session.\n\n"
                "Delete database before exiting?"
            )
            
            if result:
                if self.db.delete_database():
                    messagebox.showinfo("Success", "Database deleted successfully!")
                else:
                    messagebox.showerror("Error", "Failed to delete database")
        
        try:
            pygame.mixer.music.stop()
            pygame.mixer.quit()
        except:
            pass
        
        try:
            if self.dashboard:
                self.dashboard.cleanup()
        except:
            pass
        
        try:
            if self.realtime and self.realtime.is_monitoring:
                self.realtime._stop_monitoring()
        except:
            pass
        
        self.quit()
        self.destroy()

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
