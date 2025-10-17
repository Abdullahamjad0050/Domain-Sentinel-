#!/usr/bin/env python3
"""
Domain Sentinel — VirusTotal Domain Reputation Checker (PyQt6)
v1.6.0 (Based on user request)

CHANGES IMPLEMENTED:
- Renamed application to "Domain Sentinel"
- Updated "How to Use" guide to be more comprehensive
- Adjusted vertical splitter for a 1:1 ratio between results and logs
- Made footer background more visible in both themes
- Preserved existing v1.5.0 functionality as requested
"""

from __future__ import annotations

import base64
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

import requests
from PyQt6.QtCore import (
    QObject, Qt, QTimer, pyqtSignal, QUrl, QSettings, QEvent
)
from PyQt6.QtGui import QDesktopServices, QAction, QTextOption
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QProgressBar, QTextEdit, QMessageBox, QSpinBox, QFrame,
    QLineEdit, QListWidget, QSplitter, QMenu, QCheckBox, QMenuBar, QSizePolicy,
    QTabWidget, QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView
)

# Optional secure storage
KEYRING_AVAILABLE = True
try:
    import keyring  # pip install keyring
except Exception:
    KEYRING_AVAILABLE = False
    keyring = None  # type: ignore

# Optional matplotlib for dashboard
MATPLOTLIB_OK = True
try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
except Exception:
    MATPLOTLIB_OK = False
    FigureCanvas = object  # type: ignore
    Figure = object  # type: ignore

SERVICE_NAME = "DomainSentinel"
ACCOUNT_NAME = "default"

# VT API
BASE_URL = "https://www.virustotal.com/api/v3/domains"
def _build_headers(api_key: str) -> Dict[str, str]:
    return {"x-apikey": api_key, "User-Agent": "domain-sentinel/1.6.0"}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

# ---------- Themes (QSS) ----------
SCROLLBAR_QSS_DARK = """
QScrollBar:vertical {
    background: #0b0f14; width: 12px; margin: 2px 0 2px 0; border: 1px solid #1f2a36; border-radius: 6px;
}
QScrollBar::handle:vertical { background: #223040; min-height: 24px; border-radius: 6px; }
QScrollBar::handle:vertical:hover { background: #2c3e52; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #0b0f14; height: 12px; margin: 0 2px 0 2px; border: 1px solid #1f2a36; border-radius: 6px;
}
QScrollBar::handle:horizontal { background: #223040; min-width: 24px; border-radius: 6px; }
QScrollBar::handle:horizontal:hover { background: #2c3e52; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
"""
SCROLLBAR_QSS_LIGHT = """
QScrollBar:vertical {
    background: #fafafa; width: 12px; margin: 2px 0 2px 0; border: 1px solid #e6e6e6; border-radius: 6px;
}
QScrollBar::handle:vertical { background: #c9ced8; min-height: 24px; border-radius: 6px; }
QScrollBar::handle:vertical:hover { background: #b9c0cd; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #fafafa; height: 12px; margin: 0 2px 0 2px; border: 1px solid #e6e6e6; border-radius: 6px;
}
QScrollBar::handle:horizontal { background: #c9ced8; min-width: 24px; border-radius: 6px; }
QScrollBar::handle:horizontal:hover { background: #b9c0cd; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
"""

DARK_QSS_CORE = """
QWidget { background: #0e1116; color: #d7e0ea; }
QLineEdit, QTextEdit, QListWidget, QTableWidget {
    background: #0b0f14; color: #d7e0ea;
    border: 1px solid #1f2a36; border-radius: 8px; padding: 6px;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0f9dff, stop:1 #6b5bff);
    color: white; padding: 8px 12px; border-radius: 10px; font-weight: 600;
}
QPushButton:disabled { background: rgba(80,80,80,0.25); color: #888; }
QProgressBar {
    background: #081018; border: 1px solid #1d2630; border-radius: 10px; text-align: center; height: 18px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00f2a7, stop:1 #00a3ff);
    border-radius: 10px;
}
QLabel { font-weight: 500; }
#footerbar { background: #1f2a36; border-top: 1px solid #2c3e52; }
#footerlabel { color: #9fb3c8; font-size: 13px; }
.card { border: 1px solid #1f2a36; border-radius: 10px; padding: 10px; background: #0b0f14; }
.badge { border-radius: 14px; padding: 4px 10px; font-weight: 700; }
.badge-good { background: rgba(34,197,94,0.18); color: #7ef08f; }
.badge-warn { background: rgba(234,179,8,0.18); color: #ffd580; }
.badge-bad  { background: rgba(239,68,68,0.18); color: #ff7b7b; }
.badge-info { background: rgba(37,99,235,0.18); color: #9fd0ff; }
"""

LIGHT_QSS_CORE = """
QWidget { background: #f6f7fb; color: #1c1f26; }
QLineEdit, QTextEdit, QListWidget, QTableWidget {
    background: #ffffff; color: #20232a;
    border: 1px solid #dfe5ee; border-radius: 8px; padding: 6px;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2d77ff, stop:1 #7a5cff);
    color: white; padding: 8px 12px; border-radius: 10px; font-weight: 600;
}
QPushButton:disabled { background: rgba(150,150,150,0.25); color: #888; }
QProgressBar {
    background: #edf1f7; border: 1px solid #dfe5ee; border-radius: 10px; text-align: center; height: 18px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #06b6d4);
    border-radius: 10px;
}
QLabel { font-weight: 600; }
#footerbar { background: #e6eaf1; border-top: 1px solid #c9ced8; }
#footerlabel { color: #475569; font-size: 13px; }
.card { border: 1px solid #dfe5ee; border-radius: 10px; padding: 10px; background: #ffffff; }
.badge { border-radius: 14px; padding: 4px 10px; font-weight: 700; }
.badge-good { background: rgba(16,185,129,0.18); color: #166534; }
.badge-warn { background: rgba(234,179,8,0.18); color: #92400e; }
.badge-bad  { background: rgba(239,68,68,0.18); color: #7f1d1d; }
.badge-info { background: rgba(37,99,235,0.18); color: #0b3c99; }
"""

DARK_QSS = DARK_QSS_CORE + SCROLLBAR_QSS_DARK
LIGHT_QSS = LIGHT_QSS_CORE + SCROLLBAR_QSS_LIGHT

# ---------- Signals ----------
class WorkerSignals(QObject):
    log = pyqtSignal(str, str)
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    result = pyqtSignal(str, dict)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

# ---------- VT Worker ----------
class ScannerWorker:
    def __init__(self, domains: Iterable[str], api_key: str, delay_seconds: int, signals: WorkerSignals) -> None:
        all_input = [s.strip() for s in domains if s and s.strip()]
        self.original_total = len(all_input)
        self.domains = [d for d in dict.fromkeys(all_input)]
        self.api_key = api_key.strip()
        self.delay = max(0, int(delay_seconds))
        self.signals = signals
        self._stop = False
        self._pause = False
        self._lock = threading.Lock()
        self._session = requests.Session()
        self._session.headers.update(_build_headers(self.api_key))

    def stop(self):
        with self._lock: self._stop = True
    def pause(self, value: bool):
        with self._lock: self._pause = value
    def paused(self) -> bool:
        with self._lock: return self._pause
    def should_stop(self) -> bool:
        with self._lock: return self._stop

    def _respect_rate_limit(self, domain: str, retry_after: Optional[str]) -> bool:
        extra = f" Retry after {retry_after}s." if retry_after else ""
        self.signals.log.emit(f"⏳ <b>{domain}</b> – Rate limit reached. Waiting…{extra}", "warn")
        sleep_time = int(retry_after) if (retry_after and retry_after.isdigit()) else max(self.delay, 15)
        for _ in range(max(1, sleep_time) * 10):
            if self.should_stop(): return False
            time.sleep(0.1)
        return True

    def run(self):
        try:
            valid_domains = [d for d in self.domains if _DOMAIN_RE.match(d)]
            invalid = sorted(set(self.domains) - set(valid_domains))
            for d in invalid:
                self.signals.log.emit(f"❗ Skipping invalid domain: <b>{d}</b>", "warn")
            unique_total = len(valid_domains)
            duplicates_skipped = self.original_total - len(set(self.domains))
            total = unique_total
            if total == 0:
                self.signals.error.emit("No valid domains to scan.")
                return
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs("history", exist_ok=True)
            outpath = os.path.join("history", f"domain_reputation_{ts}.csv")
            fieldnames = ["domain", "malicious", "suspicious", "harmless", "undetected", "reputation"]
            buckets = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
            processed = 0
            break_outer = False
            with open(outpath, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(fieldnames)
                for i, domain in enumerate(valid_domains, start=1):
                    if self.should_stop():
                        processed = i - 1
                        self.signals.log.emit(f"<i>⏹ Stopped by user at {i-1}/{total}.</i>", "warn")
                        break
                    while self.paused() and not self.should_stop():
                        self.signals.status.emit("Paused")
                        time.sleep(0.2)
                    if self.should_stop():
                        processed = i - 1
                        self.signals.log.emit(f"<i>⏹ Stopped by user at {i-1}/{total}.</i>", "warn")
                        break
                    self.signals.status.emit(f"Checking {domain} ({i}/{total})")
                    self.signals.log.emit(f"🔍 Checking <b>{domain}</b>…", "info")
                    while True:
                        if self.should_stop(): break_outer = True; break
                        try:
                            resp = self._session.get(f"{BASE_URL}/{domain}", timeout=30)
                        except requests.RequestException as exc:
                            self.signals.log.emit(f"❌ <b>{domain}</b> – Network error: {exc}", "error")
                            break
                        if resp.status_code == 429:
                            if not self._respect_rate_limit(domain, resp.headers.get("Retry-After")):
                                break_outer = True; break
                            continue
                        if resp.status_code != 200:
                            self.signals.log.emit(f"❌ <b>{domain}</b> – API error {resp.status_code}", "error")
                            break
                        data = resp.json()
                        attrs = (data.get("data", {}) or {}).get("attributes", {}) or {}
                        stats = attrs.get("last_analysis_stats", {}) or {}
                        malicious = int(stats.get("malicious", 0))
                        suspicious = int(stats.get("suspicious", 0))
                        harmless  = int(stats.get("harmless", 0))
                        undetected = int(stats.get("undetected", 0))
                        reputation = attrs.get("reputation", "")
                        if malicious > 0:
                            buckets["malicious"] += 1; level = "bad"
                        elif suspicious > 0:
                            buckets["suspicious"] += 1; level = "warn"
                        elif harmless > 0:
                            buckets["harmless"] += 1; level = "good"
                        else:
                            buckets["undetected"] += 1; level = "info"
                        html = (f'🧪 <b>{domain}</b> — Malicious: {malicious} • Suspicious: {suspicious} • Harmless: {harmless} • Undetected: {undetected} • Reputation: {reputation}')
                        writer.writerow([domain, malicious, suspicious, harmless, undetected, reputation])
                        self.signals.result.emit(domain, attrs)
                        self.signals.log.emit(html, level)
                        break
                    if break_outer:
                        processed = max(processed, i - 1); break
                    processed = i
                    self.signals.progress.emit(int((i / total) * 100))
                    if i != total: time.sleep(self.delay)
            summary = {"original_input": self.original_total, "unique_valid": unique_total, "duplicates_skipped": duplicates_skipped, "processed_domains": processed, "queued_domains": total, "malicious": buckets["malicious"], "suspicious": buckets["suspicious"], "harmless":  buckets["harmless"], "undetected": buckets["undetected"], "output_file": outpath}
            self.signals.finished.emit(summary)
        except Exception as e:
            self.signals.error.emit(f"Scan failed: {e}")
        finally:
            try: self._session.close()
            except Exception: pass

# ---------- Main UI ----------
class VTWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Domain Sentinel")
        self.setWindowFlag(Qt.WindowType.WindowMinimizeButtonHint, True)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.settings = QSettings("AsharLabs", "DomainSentinel")
        self.domains: List[str] = []
        self.domain_data: Dict[str, dict] = {}
        self.worker: Optional[ScannerWorker] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.signals = WorkerSignals()
        self._pulse_state = 0
        self.dark_mode = bool(self.settings.value("dark_mode", True, bool))
        self.fullscreen_mode = False
        self.compact_mode = bool(self.settings.value("compact_mode", False, bool))
        self.last_pcap_packets: Optional[int] = None
        self.last_pcap_unique_domains: Optional[int] = None
        self.last_pcap_top5: List[Tuple[str,int]] = []
        self._build_ui()
        self._connect_signals()
        self._apply_theme(self.dark_mode)
        self._apply_compact(self.compact_mode)
        geo = self.settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)
        self.installEventFilter(self)

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setSpacing(10)
        outer.setContentsMargins(12, 10, 12, 12)

        # Menu bar
        self.menubar = QMenuBar()
        key_menu = self.menubar.addMenu("API Key")
        self.act_show_key = QAction("Show saved key (masked)", self)
        self.act_clear_key = QAction("Clear saved key", self)
        self.act_toggle_plain_fallback = QAction("Allow plaintext fallback (NOT recommended)", self)
        self.act_toggle_plain_fallback.setCheckable(True)
        allow_plain = bool(self.settings.value("allow_plain_fallback", False, bool))
        self.act_toggle_plain_fallback.setChecked(allow_plain)
        key_menu.addAction(self.act_show_key); key_menu.addAction(self.act_clear_key); key_menu.addSeparator(); key_menu.addAction(self.act_toggle_plain_fallback)
        export_menu = self.menubar.addMenu("Export")
        self.act_export_whois_all = QAction("WHOIS of all domains (.txt)", self)
        export_menu.addAction(self.act_export_whois_all)
        view_menu = self.menubar.addMenu("View")
        self.act_toggle_compact = QAction("Compact mode", self)
        self.act_toggle_compact.setCheckable(True)
        self.act_toggle_compact.setChecked(self.compact_mode)
        view_menu.addAction(self.act_toggle_compact)
        outer.addWidget(self.menubar)

        # Top controls
        top = QHBoxLayout(); top.setSpacing(8)
        self.load_btn = QPushButton("Load Domains")
        self.load_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        top.addWidget(self.load_btn)
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("VirusTotal API key (or VT_API_KEY env)")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setMinimumWidth(240)
        self.api_key_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        top.addWidget(self.api_key_input, stretch=1)
        self.save_key_chk = QCheckBox("Save API key securely")
        top.addWidget(self.save_key_chk)
        prefill, saved_flag = self._load_api_key()
        if prefill: self.api_key_input.setText(prefill)
        self.save_key_chk.setChecked(bool(saved_flag))
        top.addWidget(QLabel("Delay (s):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 600)
        self.delay_spin.setValue(int(self.settings.value("delay", 15)))
        self.delay_spin.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        top.addWidget(self.delay_spin)
        self.start_btn = QPushButton("Start"); self.pause_btn = QPushButton("Pause"); self.stop_btn = QPushButton("Stop")
        self.pause_btn.setEnabled(False)
        for b in (self.start_btn, self.pause_btn, self.stop_btn):
            b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed); top.addWidget(b)
        self.stop_btn.setEnabled(False)
        self.theme_btn = QPushButton("🌙 Dark")
        self.theme_btn.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        top.addWidget(self.theme_btn)
        self.compact_btn = QPushButton("Compact")
        self.compact_btn.setToolTip("Toggle compact / full view")
        top.addWidget(self.compact_btn)
        top.addStretch()
        outer.addLayout(top)

        # ---- Main Application Tab Widget ----
        self.main_application_tabs = QTabWidget()
        
        # Build the pages for the main tabs
        self._build_pcap_tab()
        self._build_howto_tab()
        vt_inspector_widget = self._build_vt_inspector_page() # This creates the main analysis view

        # Add pages to the main tab widget
        self.main_application_tabs.addTab(self.tab_pcap, "PCAP Analyzer")
        self.main_application_tabs.addTab(vt_inspector_widget, "VirusTotal Inspector")
        self.main_application_tabs.addTab(self.tab_howto, "How to Use")
        
        outer.addWidget(self.main_application_tabs, stretch=1)

        # Footer
        footer_bar = QFrame(); footer_bar.setObjectName("footerbar")
        footer_layout = QHBoxLayout(footer_bar); footer_layout.setContentsMargins(12,10,12,10)
        self.footer_label = QLabel('Made in Pakistan 🇵🇰 • GitHub: yourname • v1.6.0'); self.footer_label.setObjectName("footerlabel")
        self.footer_label.setWordWrap(True)
        footer_layout.addWidget(self.footer_label)
        footer_bar.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        outer.addWidget(footer_bar)

    def _build_vt_inspector_page(self) -> QWidget:
        """Creates the container widget for the main VT analysis UI."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)

        # Main splitter (LEFT | RIGHT)
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_splitter.setChildrenCollapsible(False)
        self.main_splitter.setHandleWidth(10)
        layout.addWidget(self.main_splitter, stretch=1)

        # Left panel: domain list
        left_w = QWidget()
        left = QVBoxLayout(left_w); left.setContentsMargins(0, 0, 8, 0)
        title = QLabel("Scanned Domains"); title.setWordWrap(True)
        left.addWidget(title)
        self.search_box = QLineEdit(); self.search_box.setPlaceholderText("Search domains…")
        left.addWidget(self.search_box)
        self.domain_list = QListWidget()
        self.domain_list.setSelectionMode(self.domain_list.SelectionMode.SingleSelection)
        self.domain_list.setMinimumWidth(220)
        self.domain_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.domain_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        left.addWidget(self.domain_list, stretch=1)
        self.main_splitter.addWidget(left_w)
        self.main_splitter.setStretchFactor(0, 2)

        # Right panel: vertical splitter (tabs top, log+summary bottom)
        right_w = QWidget()
        right = QVBoxLayout(right_w); right.setContentsMargins(0,0,0,0)
        status_row = QHBoxLayout()
        self.status_label = QLabel("Idle — load a domain list to begin.")
        self.status_label.setWordWrap(True)
        status_row.addWidget(self.status_label, stretch=1)
        self.pulse = QFrame(); self.pulse.setFixedSize(14, 14); self.pulse.setStyleSheet("background: rgba(100,255,200,0.18); border-radius: 7px;")
        status_row.addWidget(self.pulse)
        right.addLayout(status_row)
        self.progress = QProgressBar(); self.progress.setRange(0,100); self.progress.setValue(0)
        right.addWidget(self.progress)
        self.vsplit = QSplitter(Qt.Orientation.Vertical)
        self.vsplit.setChildrenCollapsible(False); self.vsplit.setHandleWidth(10)
        right.addWidget(self.vsplit, stretch=1)
        tabs_container = QWidget()
        tc_layout = QVBoxLayout(tabs_container); tc_layout.setContentsMargins(0,0,0,0)
        self.tabs = QTabWidget() # This is now the INNER tab widget for results
        self.tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        tc_layout.addWidget(self.tabs)
        self.vsplit.addWidget(tabs_container)
        
        # Build the inner result tabs
        self._build_about_tab()
        self._build_overview_tab()
        self._build_whois_tab()
        self._build_cert_tab()
        self._build_dns_tab()
        self._build_popularity_tab()
        self._build_raw_tab()
        self._build_dashboard_tab()

        # Bottom: Log + Summary
        bottom_container = QWidget()
        bc_layout = QVBoxLayout(bottom_container); bc_layout.setContentsMargins(0,0,0,0)
        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setMinimumHeight(100)
        self.log.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.log.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        bc_layout.addWidget(self.log, stretch=1)
        bottom_row = QHBoxLayout()
        self.summary_label = QLabel("Summary will appear here after scan."); self.summary_label.setWordWrap(True)
        bottom_row.addWidget(self.summary_label)
        bc_layout.addLayout(bottom_row)
        self.vsplit.addWidget(bottom_container)
        # --- CHANGE: Set splitter ratio to 1:1 ---
        self.vsplit.setStretchFactor(0, 1); self.vsplit.setStretchFactor(1, 1)
        self.main_splitter.addWidget(right_w)
        self.main_splitter.setStretchFactor(1, 5)

        return page

    # ----- Build individual tabs -----
    def _build_about_tab(self):
        self.tab_about = QWidget()
        ab = QVBoxLayout(self.tab_about); ab.setContentsMargins(10,10,10,10)
        # --- CHANGE: Updated app name ---
        name_lbl = QLabel("<div style='font-size:20px;font-weight:800;'>Domain Sentinel</div>")
        made_lbl = QLabel("<div style='font-size:14px;'>Made in Pakistan 🇵🇰</div>")
        ab.addWidget(name_lbl); ab.addWidget(made_lbl); ab.addStretch()
        self.tabs.addTab(self.tab_about, "About")

    def _build_overview_tab(self):
        self.tab_overview = QWidget(); ov = QVBoxLayout(self.tab_overview); ov.setContentsMargins(6,6,6,6)
        self.banner = QFrame(); banner_lay = QHBoxLayout(self.banner); banner_lay.setContentsMargins(10,8,10,8)
        self.domain_title = QLabel("—"); self.domain_title.setStyleSheet("font-size:18px; font-weight:800;")
        banner_lay.addWidget(self.domain_title); banner_lay.addStretch()
        self.badge_mal = QLabel("Malicious: 0"); self.badge_mal.setProperty("class","badge badge-bad")
        self.badge_sus = QLabel("Suspicious: 0"); self.badge_sus.setProperty("class","badge badge-warn")
        self.badge_har = QLabel("Harmless: 0");  self.badge_har.setProperty("class","badge badge-good")
        self.badge_und = QLabel("Undetected: 0"); self.badge_und.setProperty("class","badge badge-info")
        for b in (self.badge_mal, self.badge_sus, self.badge_har, self.badge_und):
            b.setStyleSheet(""); banner_lay.addWidget(b)
        ov.addWidget(self.banner)
        rep_row = QHBoxLayout()
        self.rep_label = QLabel("Reputation: —"); self.votes_label = QLabel("Votes: —")
        rep_row.addWidget(self.rep_label); rep_row.addStretch(); rep_row.addWidget(self.votes_label)
        ov.addLayout(rep_row)
        self.spectrum_bar = QFrame(); spec_l = QHBoxLayout(self.spectrum_bar); spec_l.setContentsMargins(0,6,0,6)
        self.seg_har = QFrame(); self.seg_har.setFixedHeight(14); self.seg_har.setStyleSheet("border-radius:7px;")
        self.seg_sus = QFrame(); self.seg_sus.setFixedHeight(14); self.seg_sus.setStyleSheet("border-radius:7px;")
        self.seg_mal = QFrame(); self.seg_mal.setFixedHeight(14); self.seg_mal.setStyleSheet("border-radius:7px;")
        self.seg_und = QFrame(); self.seg_und.setFixedHeight(14); self.seg_und.setStyleSheet("border-radius:7px;")
        spec_l.addWidget(self.seg_har); spec_l.addWidget(self.seg_sus); spec_l.addWidget(self.seg_mal); spec_l.addWidget(self.seg_und)
        ov.addWidget(self.spectrum_bar)
        self.findings_card = QFrame(); self.findings_card.setProperty("class","card")
        f_l = QVBoxLayout(self.findings_card); f_l.setContentsMargins(10,8,10,8)
        f_l.addWidget(QLabel("Top Findings"))
        self.findings_text = QTextEdit(); self.findings_text.setReadOnly(True); self.findings_text.setMinimumHeight(120)
        self.findings_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.findings_text.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        f_l.addWidget(self.findings_text)
        ov.addWidget(self.findings_card, stretch=1)
        self.tabs.addTab(self.tab_overview, "Overview")

    def _build_whois_tab(self):
        self.tab_whois = QWidget(); wv = QVBoxLayout(self.tab_whois); wv.setContentsMargins(6,6,6,6)
        self.whois_summary = QFrame(); wg = QGridLayout(self.whois_summary); wg.setContentsMargins(10,8,10,8)
        self.lbl_registrar = QLabel("Registrar: —"); self.lbl_country = QLabel("Country: —")
        self.lbl_created = QLabel("Created: —"); self.lbl_expires = QLabel("Expires: —")
        wg.addWidget(self.lbl_registrar,0,0); wg.addWidget(self.lbl_country,0,1)
        wg.addWidget(self.lbl_created,1,0); wg.addWidget(self.lbl_expires,1,1)
        wv.addWidget(self.whois_summary)
        whois_row = QHBoxLayout()
        self.btn_toggle_whois = QPushButton("Show full WHOIS"); whois_row.addStretch(); whois_row.addWidget(self.btn_toggle_whois)
        wv.addLayout(whois_row)
        self.whois_text = QTextEdit(); self.whois_text.setReadOnly(True); self.whois_text.setVisible(False)
        self.whois_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.whois_text.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        wv.addWidget(self.whois_text, stretch=1)
        self.tabs.addTab(self.tab_whois, "WHOIS")

    def _build_cert_tab(self):
        self.tab_cert = QWidget(); cv = QVBoxLayout(self.tab_cert); cv.setContentsMargins(6,6,6,6)
        self.cert_card = QFrame(); cg = QGridLayout(self.cert_card); cg.setContentsMargins(10,8,10,8)
        self.lbl_issuer = QLabel("Issuer CN: —"); self.lbl_subject = QLabel("Subject CN: —")
        self.lbl_valid = QLabel("Valid: — → —"); self.lbl_fpr = QLabel("SHA256: —")
        cg.addWidget(self.lbl_issuer,0,0); cg.addWidget(self.lbl_subject,0,1)
        cg.addWidget(self.lbl_valid,1,0); cg.addWidget(self.lbl_fpr,1,1)
        cv.addWidget(self.cert_card); cv.addStretch()
        self.tabs.addTab(self.tab_cert, "Certificate")

    def _build_dns_tab(self):
        self.tab_dns = QWidget(); dv = QVBoxLayout(self.tab_dns); dv.setContentsMargins(6,6,6,6)
        self.dns_table = QTableWidget(0, 3)
        self.dns_table.setHorizontalHeaderLabels(["Type", "Value", "TTL"])
        self.dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.dns_table.verticalHeader().setVisible(False)
        self.dns_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.dns_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        dv.addWidget(self.dns_table, stretch=1)
        self.tabs.addTab(self.tab_dns, "DNS")

    def _build_popularity_tab(self):
        self.tab_pop = QWidget(); pv = QVBoxLayout(self.tab_pop); pv.setContentsMargins(6,6,6,6)
        self.pop_table = QTableWidget(0, 2)
        self.pop_table.setHorizontalHeaderLabels(["Source", "Rank"])
        self.pop_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pop_table.verticalHeader().setVisible(False)
        self.pop_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.pop_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        pv.addWidget(self.pop_table, stretch=1)
        self.tabs.addTab(self.tab_pop, "Popularity")

    def _build_raw_tab(self):
        self.tab_raw = QWidget(); rv = QVBoxLayout(self.tab_raw); rv.setContentsMargins(6,6,6,6)
        self.raw_json = QTextEdit(); self.raw_json.setReadOnly(True)
        self.raw_json.setWordWrapMode(QTextOption.WrapMode.NoWrap)
        self.raw_json.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        rv.addWidget(self.raw_json, stretch=1)
        self.tabs.addTab(self.tab_raw, "Raw JSON")

    def _build_howto_tab(self):
        self.tab_howto = QWidget(); hv = QVBoxLayout(self.tab_howto); hv.setContentsMargins(10,10,10,10)
        txt = QTextEdit(); txt.setReadOnly(True)
        # --- CHANGE: Expanded "How to Use" content ---
        txt.setHtml("""
        <h2>How to Use Domain Sentinel</h2>
        <p><b>Purpose:</b> Quickly analyze domains from PCAP files and triage them with VirusTotal.</p>
        
        <h3>Workflow</h3>
        <ol>
            <li>Navigate to the <b>PCAP Analyzer</b> tab and extract domains from a capture file.</li>
            <li>Double-click domains in the PCAP table to send them to the <b>VirusTotal Inspector</b> tab.</li>
            <li>Alternatively, load a prepared list of domains using the <b>Load Domains</b> button.</li>
            <li>Enter your API key and click <b>Start</b> to begin scanning.</li>
            <li>Review results in the inner tabs (Overview, WHOIS, DNS, etc.) and the Threat Dashboard.</li>
        </ol>

        <h3>1. Prerequisites: Installing tshark</h3>
        <p>The PCAP Analyzer requires <b>tshark</b>, the command-line tool for Wireshark.</p>
        <ul>
            <li>Download and install Wireshark from <a href='https://www.wireshark.org/'>wireshark.org</a>.</li>
            <li>During installation, ensure the option to "Add Wireshark to the system PATH" is checked.</li>
            <li>After installation, you can verify it's working by opening a terminal or command prompt and typing <code>tshark -v</code>.</li>
        </ul>

        <h3>2. Getting a VirusTotal API Key</h3>
        <p>This tool requires a free VirusTotal Community API key.</p>
        <ul>
            <li>Sign up for a free account at <a href='https://www.virustotal.com/gui/join-us'>virustotal.com</a>.</li>
            <li>Once logged in, find your API key in the user menu under "API Key".</li>
            <li>Copy the key and paste it into the API key field in the application. Check "Save API key securely" for convenience.</li>
            <li><b>Important:</b> Free public keys have a rate limit (typically 4 lookups per minute). Set the "Delay" to <b>15-20 seconds</b> to avoid hitting this limit.</li>
        </ul>

        <h3>3. Interpreting Results</h3>
        <p>The "Overview" tab shows the analysis statistics. For example, "Malicious: 5" means that 5 different antivirus vendors on VirusTotal flagged the domain as malicious. A higher number indicates a stronger consensus that the domain is dangerous.</p>
        <ul>
            <li><b>Malicious:</b> Confirmed malicious by security vendors. Investigate immediately.</li>
            <li><b>Suspicious:</b> Potentially harmful, but not confirmed. Requires further analysis.</li>
            <li><b>Harmless:</b> Confirmed clean by security vendors.</li>
            <li><b>Undetected:</b> No vendor has classified this domain yet.</li>
        </ul>

        <h3>4. Troubleshooting</h3>
        <ul>
            <li><b>"tshark not found" error:</b> This means tshark is not installed or not in your system's PATH. Re-install Wireshark and ensure the PATH option is selected.</li>
            <li><b>"API error 429":</b> You have exceeded your API rate limit. Increase the "Delay (s)" value and wait a few minutes before trying again.</li>
            <li><b>Network Errors:</b> Ensure you have a stable internet connection and that your firewall is not blocking the application from reaching the VirusTotal API.</li>
        </ul>
        """)
        hv.addWidget(txt, stretch=1)

    def _build_pcap_tab(self):
        self.tab_pcap = QWidget()
        lay = QVBoxLayout(self.tab_pcap); lay.setContentsMargins(10,10,10,10)
        ctr = QHBoxLayout()
        self.pcap_path_edit = QLineEdit(); self.pcap_path_edit.setPlaceholderText("Choose a PCAP file…")
        ctr.addWidget(self.pcap_path_edit, stretch=1)
        self.btn_browse_pcap = QPushButton("Browse"); self.btn_run_pcap = QPushButton("Extract")
        self.btn_export_pcap_txt = QPushButton("Export TXT"); self.btn_export_pcap_csv = QPushButton("Export CSV")
        for b in (self.btn_browse_pcap, self.btn_run_pcap, self.btn_export_pcap_txt, self.btn_export_pcap_csv):
            ctr.addWidget(b)
        lay.addLayout(ctr)
        sm = QHBoxLayout()
        self.lbl_pcap_packets = QLabel("Packets: —"); self.lbl_pcap_unique = QLabel("Unique domains: —"); self.lbl_pcap_top = QLabel("Top 5: —")
        for w in (self.lbl_pcap_packets, self.lbl_pcap_unique, self.lbl_pcap_top): sm.addWidget(w)
        sm.addStretch(); lay.addLayout(sm)
        self.pcap_table = QTableWidget(0, 4)
        self.pcap_table.setHorizontalHeaderLabels(["Host IP", "Domain", "Protocol", "Count"])
        self.pcap_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pcap_table.verticalHeader().setVisible(False)
        self.pcap_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.pcap_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.pcap_table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        lay.addWidget(self.pcap_table, stretch=1)
        self.pcap_table.itemDoubleClicked.connect(self._pcap_row_to_vt)

    def _build_dashboard_tab(self):
        self.tab_dash = QWidget()
        lay = QVBoxLayout(self.tab_dash); lay.setContentsMargins(10,10,10,10)
        top_row = QHBoxLayout()
        self.lbl_dash_stats = QLabel("Packets: —   |   VT scanned domains: —")
        top_row.addWidget(self.lbl_dash_stats); top_row.addStretch()
        lay.addLayout(top_row)
        mid = QHBoxLayout()
        if MATPLOTLIB_OK:
            self.fig = Figure(figsize=(4,3)); self.canvas = FigureCanvas(self.fig)
            mid.addWidget(self.canvas, stretch=2)
        else:
            self.canvas = None; warn = QLabel("matplotlib not installed — chart unavailable.")
            mid.addWidget(warn, stretch=2)
        right = QVBoxLayout()
        self.tbl_topflag = QTableWidget(0, 3)
        self.tbl_topflag.setHorizontalHeaderLabels(["Domain", "Malicious", "Suspicious"])
        self.tbl_topflag.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tbl_topflag.verticalHeader().setVisible(False)
        self.tbl_topflag.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        right.addWidget(QLabel("Top flagged domains")); right.addWidget(self.tbl_topflag, stretch=1)
        mid.addLayout(right, stretch=3)
        lay.addLayout(mid, stretch=1)
        self.tabs.addTab(self.tab_dash, "Threat Dashboard")

    # ----- Signal connections -----
    def _connect_signals(self):
        self.act_show_key.triggered.connect(self._show_saved_key_masked)
        self.act_clear_key.triggered.connect(self._clear_saved_key)
        self.act_toggle_plain_fallback.toggled.connect(self._toggle_plain_fallback)
        self.act_export_whois_all.triggered.connect(self._export_whois_all)
        self.act_toggle_compact.toggled.connect(self._toggle_compact_from_menu)
        self.load_btn.clicked.connect(self.load_domains)
        self.start_btn.clicked.connect(self.start_scan)
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.compact_btn.clicked.connect(self.toggle_compact)
        self.save_key_chk.stateChanged.connect(self._on_save_chk_changed)
        self.search_box.textChanged.connect(self._filter_domains)
        self.domain_list.currentTextChanged.connect(self._show_domain_details)
        self.domain_list.itemDoubleClicked.connect(self._open_vt_page)
        self.domain_list.customContextMenuRequested.connect(self._context_menu)
        self.signals.log.connect(self.append_log)
        self.signals.progress.connect(self.update_progress)
        self.signals.status.connect(self.update_status)
        self.signals.result.connect(self._store_and_index_result)
        self.signals.finished.connect(self.scan_finished)
        self.signals.error.connect(self.show_error)
        self.pulse_timer = QTimer(self); self.pulse_timer.setInterval(400)
        self.pulse_timer.timeout.connect(self._animate_pulse); self.pulse_timer.start()
        self.btn_toggle_whois.clicked.connect(self._toggle_whois_visibility)
        self.btn_browse_pcap.clicked.connect(self._browse_pcap)
        self.btn_run_pcap.clicked.connect(self._run_pcap_extract)
        self.btn_export_pcap_txt.clicked.connect(lambda: self._export_pcap_table(as_csv=False))
        self.btn_export_pcap_csv.clicked.connect(lambda: self._export_pcap_table(as_csv=True))

    # ----- Theme & compact view -----
    def _apply_theme(self, dark: bool):
        self.setStyleSheet((DARK_QSS if dark else LIGHT_QSS))
        self.theme_btn.setText("☀️ Light" if dark else "🌙 Dark")
        if dark:
            self.seg_har.setStyleSheet("background:#22c55e; border-radius:7px;")
            self.seg_sus.setStyleSheet("background:#ffd580; border-radius:7px;")
            self.seg_mal.setStyleSheet("background:#ff7b7b; border-radius:7px;")
            self.seg_und.setStyleSheet("background:#9fd0ff; border-radius:7px;")
        else:
            self.seg_har.setStyleSheet("background:#166534; border-radius:7px;")
            self.seg_sus.setStyleSheet("background:#92400e; border-radius:7px;")
            self.seg_mal.setStyleSheet("background:#7f1d1d; border-radius:7px;")
            self.seg_und.setStyleSheet("background:#0b3c99; border-radius:7px;")
        self.settings.setValue("dark_mode", dark)
        self._update_dashboard_chart()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self._apply_theme(self.dark_mode)

    def _apply_compact(self, compact: bool):
        sz = 10 if compact else 12
        self.setStyleSheet(self.styleSheet() + f" * {{ font-size: {sz}px; }}")
        self.compact_btn.setText("Full View" if compact else "Compact")
        self.settings.setValue("compact_mode", compact)

    def toggle_compact(self):
        self.compact_mode = not self.compact_mode
        self._apply_compact(self.compact_mode)
        self.act_toggle_compact.setChecked(self.compact_mode)

    def _toggle_compact_from_menu(self, checked: bool):
        self.compact_mode = bool(checked)
        self._apply_compact(self.compact_mode)

    # ----- Window / WM behavior -----
    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_F11:
            if not self.fullscreen_mode: self.showFullScreen(); self.fullscreen_mode = True
            else: self.showNormal(); self.fullscreen_mode = False
        else: super().keyPressEvent(event)

    def eventFilter(self, obj, ev):
        if obj is self and ev.type() == QEvent.Type.Show:
            QTimer.singleShot(0, lambda: self.setWindowState(self.windowState() | Qt.WindowState.WindowActive))
        return super().eventFilter(obj, ev)

    # ----- Secure key helpers -----
    def _toggle_plain_fallback(self, checked: bool): self.settings.setValue("allow_plain_fallback", bool(checked))
    def _save_api_key_keyring(self, key: str) -> bool:
        if not KEYRING_AVAILABLE: return False
        try: keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, key); return True
        except Exception: return False
    def _load_api_key_keyring(self) -> Optional[str]:
        if not KEYRING_AVAILABLE: return None
        try: return keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
        except Exception: return None
    def _delete_api_key_keyring(self) -> bool:
        if not KEYRING_AVAILABLE: return False
        try: keyring.delete_password(SERVICE_NAME, ACCOUNT_NAME); return True
        except Exception: return False
    def _save_api_key_plain(self, key: str):
        self.settings.setValue("api_key_obf", base64.b64encode(key.encode("utf-8")).decode("ascii"))
    def _load_api_key_plain(self) -> Optional[str]:
        blob = self.settings.value("api_key_obf", "")
        if not blob: return None
        try: return base64.b64decode(blob.encode("ascii")).decode("utf-8")
        except Exception: return None
    def _delete_api_key_plain(self): self.settings.remove("api_key_obf")
    def _load_api_key(self):
        key = self._load_api_key_keyring()
        if key: return key, True
        key = self._load_api_key_plain()
        if key: return key, True
        env = os.getenv("VT_API_KEY", "")
        if env: return env, False
        return None, False
    def _on_save_chk_changed(self, state: int):
        checked = (state == Qt.CheckState.Checked)
        key = self.api_key_input.text().strip()
        if not key:
            if checked: QMessageBox.information(self, "API Key", "Enter a key first, then tick Save."); self.save_key_chk.setChecked(False)
            return
        if checked:
            if self._save_api_key_keyring(key): self.append_log("🔐 API key saved to OS keychain.", "info"); self._delete_api_key_plain(); return
            allow_plain = bool(self.settings.value("allow_plain_fallback", False, bool))
            if allow_plain: self._save_api_key_plain(key); self.append_log("⚠️ Saved API key in app settings (NOT secure).", "warn"); return
            self.append_log("⚠️ Could not access keyring. Enable 'Allow plaintext fallback' or install 'keyring'.", "warn"); self.save_key_chk.setChecked(False)
        else:
            ok1 = self._delete_api_key_keyring(); self._delete_api_key_plain()
            if ok1: self.append_log("🗑️ API key cleared from OS keychain.", "info")
            else:   self.append_log("🗑️ API key cleared from app settings (if present).", "info")
    def _show_saved_key_masked(self):
        key = self._load_api_key_keyring() or self._load_api_key_plain()
        if not key: QMessageBox.information(self, "API Key", "No API key saved."); return
        masked = key[:4] + "…" + key[-4:] if len(key) > 8 else "•" * len(key)
        QMessageBox.information(self, "API Key", f"Saved key: {masked}")
    def _clear_saved_key(self):
        self._delete_api_key_keyring(); self._delete_api_key_plain()
        if hasattr(self, "save_key_chk"): self.save_key_chk.setChecked(False)
        QMessageBox.information(self, "API Key", "Saved key cleared.")

    # ----- Actions (Load/Scan/Stop etc.) -----
    def load_domains(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Domain List", "", "Text Files (*.txt);;All Files (*)")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                self.domains = [line.strip() for line in f if line.strip()]
            self.status_label.setText(f"Loaded {len(self.domains)} domains.")
            self.append_log(f"<i>📂 Loaded {len(self.domains)} domains from <b>{os.path.basename(path)}</b></i>", "info")
            self.progress.setValue(0); self.summary_label.setText("Summary will appear here after scan.")
            self.domain_data.clear(); self.domain_list.clear()
        except Exception as e: self.show_error(f"Failed to load file: {e}")

    def start_scan(self):
        if not self.domains: QMessageBox.warning(self, "No domains", "Please load a domain file first."); return
        if self.worker_thread and self.worker_thread.is_alive(): QMessageBox.warning(self, "Scan running", "A scan is still stopping. Please wait a moment."); return
        self.start_btn.setEnabled(False); self.pause_btn.setEnabled(True); self.stop_btn.setEnabled(True); self.pause_btn.setText("Pause")
        delay = int(self.delay_spin.value()); self.settings.setValue("delay", delay)
        api_key = self.api_key_input.text().strip() or os.getenv("VT_API_KEY", "").strip()
        if not api_key:
            QMessageBox.warning(self, "API key missing", "Enter an API key or set VT_API_KEY environment variable.")
            self.start_btn.setEnabled(True); self.pause_btn.setEnabled(False); self.stop_btn.setEnabled(False); return
        if self.save_key_chk.isChecked(): self._on_save_chk_changed(Qt.CheckState.Checked)
        self.append_log("<i>🚀 Starting scan…</i>", "info")
        self.worker = ScannerWorker(self.domains, api_key, delay, self.signals)
        self.worker_thread = threading.Thread(target=self.worker.run, daemon=True)
        self.worker_thread.start()

    def toggle_pause(self):
        if not self.worker: return
        is_paused = not self.worker.paused()
        self.worker.pause(is_paused)
        self.pause_btn.setText("Resume" if is_paused else "Pause")
        self.append_log(f"<i>{'⏸ Paused' if is_paused else '▶ Resumed'}</i>", "info")

    def stop_scan(self):
        if self.worker: self.worker.stop()
        self.append_log("<i>⏹ Requested to stop scan…</i>", "warn")
        self.start_btn.setEnabled(True)

    def _filter_domains(self, text: str):
        t = text.lower().strip()
        for i in range(self.domain_list.count()):
            self.domain_list.item(i).setHidden(t not in self.domain_list.item(i).text().lower())
    def _open_vt_page(self, item): QDesktopServices.openUrl(QUrl(f"https://www.virustotal.com/gui/domain/{item.text()}"))
    def _context_menu(self, pos):
        it = self.domain_list.itemAt(pos)
        if not it: return
        domain = it.text(); menu = QMenu(self)
        act_copy_json = menu.addAction("Copy JSON details"); act_open_vt = menu.addAction("Open in VirusTotal")
        act = menu.exec(self.domain_list.mapToGlobal(pos))
        if act == act_copy_json:
            QApplication.clipboard().setText(json.dumps(self.domain_data.get(domain, {}), indent=2))
            self.append_log(f"📋 Copied JSON for <b>{domain}</b>", "info")
        elif act == act_open_vt: self._open_vt_page(it)

    def append_log(self, html_message: str, level: str):
        color_map = {"good": "#166534" if not self.dark_mode else "#7ef08f", "warn": "#92400e" if not self.dark_mode else "#ffd580", "bad": "#7f1d1d" if not self.dark_mode else "#ff7b7b", "info": "#0b3c99" if not self.dark_mode else "#9fd0ff", "error": "#7f1d1d" if not self.dark_mode else "#ff7b7b"}
        color = color_map.get(level, "#1c1f26" if not self.dark_mode else "#d7e0ea")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.append(f'<div style="margin:3px 0;"><span style="color:#7c8a97; font-size:10px;">[{ts}]</span> <span style="color:{color};">{html_message}</span></div>')
        self._update_dashboard_chart()

    def update_progress(self, percent: int): self.progress.setValue(percent)
    def update_status(self, text: str): self.status_label.setText(text)
    def _store_and_index_result(self, domain: str, attrs: dict):
        self.domain_data[domain] = attrs
        if not any(self.domain_list.item(i).text() == domain for i in range(self.domain_list.count())):
            self.domain_list.addItem(domain)
        cur = self.domain_list.currentItem().text() if self.domain_list.currentItem() else None
        if cur == domain: self._show_domain_details(domain)
        self._update_dashboard_tables()
    def _show_domain_details(self, domain: str):
        a = self.domain_data.get(domain) or {}
        stats = (a.get("last_analysis_stats") or {}); results = (a.get("last_analysis_results") or {})
        reputation = a.get("reputation", "—"); votes = a.get("total_votes") or {}; whois = a.get("whois") or ""
        pop = a.get("popularity_ranks") or {}; cert = a.get("last_https_certificate") or {}; dns = a.get("last_dns_records") or []
        cert_iss = (cert.get("issuer") or {}); cert_sub = (cert.get("subject") or {}); cert_val = (cert.get("validity") or {}); fpr = cert.get("fingerprint_sha256", "—")
        self.domain_title.setText(domain)
        mal, sus, har, und = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)), int(stats.get("harmless", 0)), int(stats.get("undetected", 0))
        self.badge_mal.setText(f"Malicious: {mal}"); self.badge_sus.setText(f"Suspicious: {sus}"); self.badge_har.setText(f"Harmless: {har}"); self.badge_und.setText(f"Undetected: {und}")
        self.rep_label.setText(f"Reputation: {reputation}"); self.votes_label.setText(f"Votes: harmless {int((votes or {}).get('harmless',0))}, malicious {int((votes or {}).get('malicious',0))}")
        spec_layout: QHBoxLayout = self.spectrum_bar.layout()
        spec_layout.setStretch(0, max(1, har)); spec_layout.setStretch(1, max(1, sus)); spec_layout.setStretch(2, max(1, mal)); spec_layout.setStretch(3, max(1, und))
        for seg, val in ((self.seg_har, har), (self.seg_sus, sus), (self.seg_mal, mal), (self.seg_und, und)): seg.setVisible(val > 0)
        findings_lines = []
        if isinstance(results, dict):
            for eng, r in results.items():
                cat = r.get("category"); res = r.get("result")
                if cat in ("malicious", "suspicious", "harmless"):
                    findings_lines.append(f"{eng}: {cat}{(' — ' + res) if res else ''}")
                if len(findings_lines) >= 12: break
        self.findings_text.setPlainText("\n".join(findings_lines) if findings_lines else "—")
        self.lbl_registrar.setText(f"Registrar: {a.get('registrar', '—')}"); self.lbl_country.setText(f"Country: {self._extract_whois_country(whois) or '—'}")
        self.lbl_created.setText(f"Created: {a.get('creation_date', '—')}"); self.lbl_expires.setText(f"Expires: {self._extract_whois_expiry(whois) or '—'}")
        self.whois_text.setPlainText(whois if whois else "—")
        self.lbl_issuer.setText(f"Issuer CN: {str(cert_iss.get('CN','—'))}"); self.lbl_subject.setText(f"Subject CN: {str(cert_sub.get('CN','—'))}")
        self.lbl_valid.setText(f"Valid: {str(cert_val.get('not_before','—'))} → {str(cert_val.get('not_after','—'))}"); self.lbl_fpr.setText(f"SHA256: {fpr if fpr else '—'}")
        self.dns_table.setRowCount(0)
        for rec in dns:
            row = self.dns_table.rowCount(); self.dns_table.insertRow(row)
            self.dns_table.setItem(row, 0, QTableWidgetItem(str(rec.get("type","")))); self.dns_table.setItem(row, 1, QTableWidgetItem(str(rec.get("value",""))))
            self.dns_table.setItem(row, 2, QTableWidgetItem(str(rec.get("ttl", "")) if rec.get("ttl") is not None else ""))
        self.pop_table.setRowCount(0)
        if isinstance(pop, dict):
            for src, obj in pop.items():
                rank = obj.get("rank") if isinstance(obj, dict) else None
                row = self.pop_table.rowCount(); self.pop_table.insertRow(row)
                self.pop_table.setItem(row, 0, QTableWidgetItem(str(src))); self.pop_table.setItem(row, 1, QTableWidgetItem(str(rank) if rank is not None else ""))
        self.raw_json.setPlainText(json.dumps(a, indent=2) if a else "{}")
        self._update_dashboard_tables()

    def _toggle_whois_visibility(self):
        vis = not self.whois_text.isVisible(); self.whois_text.setVisible(vis)
        self.btn_toggle_whois.setText("Hide full WHOIS" if vis else "Show full WHOIS")

    @staticmethod
    def _extract_whois_country(whois: str) -> Optional[str]:
        if not whois: return None
        whois_lower = whois.lower()
        search_keys = ("registrant country:", "administrative country:", "technical country:", "country:")
        for key in search_keys:
            i = whois_lower.find(key)
            if i != -1:
                line = whois[i:].splitlines()[0]; parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip(): return parts[1].strip()
        return None

    @staticmethod
    def _extract_whois_expiry(whois: str) -> Optional[str]:
        if not whois: return None
        for key in ("Expiry date:", "Registry Expiry Date:", "Expiration Time:", "Registrar Registration Expiration Date:"):
            i = whois.find(key)
            if i != -1:
                line = whois[i:].splitlines()[0]; parts = line.split(":", 1)
                if len(parts) == 2: return parts[1].strip()
        return None

    def scan_finished(self, summary: dict):
        self.start_btn.setEnabled(True); self.pause_btn.setEnabled(False); self.stop_btn.setEnabled(False)
        self.progress.setValue(100); self.status_label.setText("Scan Finished ✅")
        self.worker = None; self.worker_thread = None
        s = (f"Input: {summary.get('original_input',0)}   |   Unique valid: {summary.get('unique_valid',0)}   |   "
             f"Duplicates skipped: {summary.get('duplicates_skipped',0)}   |   Processed: {summary.get('processed_domains', 0)}/{summary.get('queued_domains', 0)}   |   "
             f"Malicious: {summary.get('malicious', 0)}   |   Suspicious: {summary.get('suspicious', 0)}   |   "
             f"Harmless: {summary.get('harmless', 0)}   |   Undetected: {summary.get('undetected', 0)}   |   "
             f"CSV: {summary.get('output_file', 'N/A')}")
        self.summary_label.setText(s)
        self.append_log("<b>=== Summary (per-domain) ===</b>", "info"); self.append_log(s, "info")
        self._update_dashboard_chart(); self._update_dashboard_tables()

    def show_error(self, message: str):
        QMessageBox.critical(self, "Error", message)
        self.append_log(f"❌ <b>Error</b>: {message}", "error")
        self.start_btn.setEnabled(True); self.pause_btn.setEnabled(False); self.stop_btn.setEnabled(False)
        self.worker = None; self.worker_thread = None

    def _animate_pulse(self):
        self._pulse_state = (self._pulse_state + 1) % 6
        alpha = 30 + self._pulse_state * 30
        color = f"rgba(80,200,255,{alpha/255:.2f})" if self.dark_mode else f"rgba(16,185,129,{alpha/255:.2f})"
        self.pulse.setStyleSheet(f"background:{color}; border-radius:7px;")

    def _export_whois_all(self):
        if self.domain_list.count() == 0: QMessageBox.information(self, "Export WHOIS", "No domains in the list."); return
        path, _ = QFileDialog.getSaveFileName(self, "Save WHOIS for all domains", "whois_all.txt", "Text Files (*.txt)")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"Domain Sentinel — WHOIS Export\nGenerated: {ts}\n\n")
                for i in range(self.domain_list.count()):
                    domain = self.domain_list.item(i).text(); attrs = self.domain_data.get(domain, {})
                    whois = attrs.get("whois") or ""; f.write(f"=== {domain} ===\n")
                    if whois: f.write(whois.strip() + "\n\n")
                    else: f.write("(WHOIS not available yet — domain not scanned or no WHOIS returned.)\n\n")
            QMessageBox.information(self, "Export WHOIS", f"Saved WHOIS for {self.domain_list.count()} domains to:\n{path}")
        except Exception as e: self.show_error(f"Failed to export WHOIS: {e}")

    def _browse_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if path: self.pcap_path_edit.setText(path)

    def _run_pcap_extract(self):
        path = self.pcap_path_edit.text().strip()
        if not path or not os.path.exists(path): QMessageBox.warning(self, "PCAP", "Please choose a valid PCAP file."); return
        if not shutil.which("tshark"): QMessageBox.warning(self, "tshark not found", "Please install tshark (Wireshark CLI). See 'How to Use' tab for details."); return
        self.append_log(f"🧪 Parsing PCAP: <b>{os.path.basename(path)}</b>", "info")
        rows, total_packets, uniq_domains, top5 = self._extract_domains_with_tshark(path)
        self.pcap_table.setRowCount(0)
        for ip, dom, proto, cnt in rows:
            r = self.pcap_table.rowCount(); self.pcap_table.insertRow(r)
            self.pcap_table.setItem(r, 0, QTableWidgetItem(ip))
            item_dom = QTableWidgetItem(dom); item_dom.setToolTip(dom)
            self.pcap_table.setItem(r, 1, item_dom)
            proto_item = QTableWidgetItem(proto); proto_item.setToolTip(f"Extracted via {proto}")
            self.pcap_table.setItem(r, 2, proto_item)
            self.pcap_table.setItem(r, 3, QTableWidgetItem(str(cnt)))
        self.last_pcap_packets = total_packets; self.last_pcap_unique_domains = uniq_domains; self.last_pcap_top5 = top5
        self.lbl_pcap_packets.setText(f"Packets: {total_packets if total_packets is not None else '—'}")
        self.lbl_pcap_unique.setText(f"Unique domains: {uniq_domains}")
        self.lbl_pcap_top.setText("Top 5: " + (", ".join([f"{d}({c})" for d,c in top5]) if top5 else "—"))
        self.append_log(f"✅ PCAP parsed — {uniq_domains} unique domains.", "good"); self._update_dashboard_stats()

    def _extract_domains_with_tshark(self, pcap_path: str) -> Tuple[List[Tuple[str,str,str,int]], Optional[int], int, List[Tuple[str,int]]]:
        def run(cmd: List[str]) -> List[str]:
            try: return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8", "ignore").splitlines()
            except subprocess.CalledProcessError as e: self.append_log(f"tshark error: {e.output.decode('utf-8','ignore')}", "warn"); return []
        dns_lines = run(["tshark", "-r", pcap_path, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"])
        http_lines = run(["tshark", "-r", pcap_path, "-Y", "http.request", "-T", "fields", "-e", "ip.src", "-e", "http.host"])
        tls_lines = run(["tshark", "-r", pcap_path, "-Y", "tls.handshake.extensions_server_name", "-T", "fields", "-e", "ip.src", "-e", "tls.handshake.extensions_server_name"])
        total_packets = None
        for ln in run(["tshark", "-r", pcap_path, "-q", "-z", "io,stat,0"])[::-1]:
            if "frames:" in ln:
                try: total_packets = int(ln.split("frames:")[-1].strip()); break
                except Exception: pass
        counts: Dict[Tuple[str,str,str], int] = {}
        def add(lines: List[str], proto: str):
            for ln in lines:
                parts = ln.split("\t") if "\t" in ln else ln.split()
                if len(parts) < 2: continue
                ip, dom = parts[0].strip(), parts[1].strip().lower().rstrip(".")
                if ip and dom: counts[(ip, dom, proto)] = counts.get((ip, dom, proto), 0) + 1
        add(dns_lines, "DNS"); add(http_lines, "HTTP"); add(tls_lines, "TLS")
        rows = sorted(list((ip, dom, proto, cnt) for (ip, dom, proto), cnt in counts.items()), key=lambda x: (-x[3], x[0], x[1], x[2]))
        domain_total: Dict[str,int] = {}
        for (_, dom, _, cnt) in rows: domain_total[dom] = domain_total.get(dom, 0) + cnt
        return rows, total_packets, len(domain_total), sorted(domain_total.items(), key=lambda kv: kv[1], reverse=True)[:5]

    def _pcap_row_to_vt(self, item: QTableWidgetItem):
        r = item.row(); dom = self.pcap_table.item(r, 1).text()
        if not any(self.domain_list.item(i).text() == dom for i in range(self.domain_list.count())):
            self.domain_list.addItem(dom)
        items = self.domain_list.findItems(dom, Qt.MatchFlag.MatchExactly)
        if items: self.domain_list.setCurrentItem(items[0])
        self.main_application_tabs.setCurrentIndex(1) # Switch to "VirusTotal Inspector" tab
        self.append_log(f"➡️ Sent <b>{dom}</b> to VT tab. Start scan to retrieve reputation.", "info")

    def _export_pcap_table(self, as_csv: bool):
        if self.pcap_table.rowCount() == 0: QMessageBox.information(self, "Export", "No PCAP results to export."); return
        default = "pcap_domains.csv" if as_csv else "pcap_domains.txt"
        path, _ = QFileDialog.getSaveFileName(self, "Export PCAP Domains", default, "CSV (*.csv);;Text (*.txt)")
        if not path: return
        try:
            if as_csv:
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f); w.writerow(["Host IP","Domain","Protocol","Count"])
                    for r in range(self.pcap_table.rowCount()): w.writerow([self.pcap_table.item(r,c).text() for c in range(4)])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    for r in range(self.pcap_table.rowCount()): f.write(f"{self.pcap_table.item(r, 1).text()}\n")
            QMessageBox.information(self, "Export", f"Saved to:\n{path}")
        except Exception as e: self.show_error(f"Export failed: {e}")

    def _update_dashboard_stats(self):
        scanned = len(self.domain_data); pkt = self.last_pcap_packets if self.last_pcap_packets is not None else "—"
        self.lbl_dash_stats.setText(f"Packets: {pkt}   |   VT scanned domains: {scanned}")
    def _compute_vt_buckets(self):
        mal=sus=har=und=0
        for a in self.domain_data.values():
            stats = a.get("last_analysis_stats", {}) or {}
            m, s, h = int(stats.get("malicious",0)), int(stats.get("suspicious",0)), int(stats.get("harmless",0))
            if m > 0: mal += 1
            elif s > 0: sus += 1
            elif h > 0: har += 1
            else: und += 1
        return mal, sus, har, und
    def _update_dashboard_chart(self):
        self._update_dashboard_stats()
        if not MATPLOTLIB_OK or not hasattr(self, "fig"): return
        mal, sus, har, und = self._compute_vt_buckets()
        values = [int(mal), int(sus), int(har), int(und)]; total = sum(values)
        self.fig.clear(); ax = self.fig.add_subplot(111)
        if total <= 0:
            ax.text(0.5, 0.5, "No data yet", ha="center", va="center", fontsize=12)
            ax.set_axis_off(); ax.set_title("Domain Status (per-domain buckets)"); self.canvas.draw_idle(); return
        ax.pie(values, labels=["Malicious","Suspicious","Harmless","Undetected"], autopct=lambda p: f"{int(round(p/100.0*total))}", startangle=90)
        ax.axis("equal"); ax.set_title("Domain Status (per-domain buckets)"); self.canvas.draw_idle()
    def _update_dashboard_tables(self):
        top = []
        for dom, a in self.domain_data.items():
            st = a.get("last_analysis_stats", {}) or {}
            m, s = int(st.get("malicious",0)), int(st.get("suspicious",0))
            if m > 0 or s > 0: top.append((dom, m, s))
        top.sort(key=lambda x: (-x[1], -x[2], x[0]))
        self.tbl_topflag.setRowCount(0)
        for dom, m, s in top[:20]:
            r = self.tbl_topflag.rowCount(); self.tbl_topflag.insertRow(r)
            self.tbl_topflag.setItem(r, 0, QTableWidgetItem(dom)); self.tbl_topflag.setItem(r, 1, QTableWidgetItem(str(m))); self.tbl_topflag.setItem(r, 2, QTableWidgetItem(str(s)))

    def closeEvent(self, event):
        if self.worker: self.worker.stop()
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("dark_mode", self.dark_mode)
        self.settings.setValue("delay", int(self.delay_spin.value()))
        self.settings.setValue("compact_mode", self.compact_mode)
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = VTWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
