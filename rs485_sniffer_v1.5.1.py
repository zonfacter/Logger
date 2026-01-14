#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RS485 Sniffer v1.5.1 - HausBus
Features: Plugin system, HEX/STRING send, Start-byte, Config file
PyInstaller compatible: Works as .py and as .exe with external plugins
"""

import serial
import serial.tools.list_ports
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import queue
from typing import Optional, Dict, Any, Deque
from collections import deque
import sys
import time
import json
import os

__version__ = "1.5.1"

# =============================================================================
# PATH CONFIGURATION - PyInstaller compatible
# =============================================================================
def get_base_dir() -> str:
    """
    Get the base directory for the application.
    Works both for .py execution and PyInstaller .exe
    """
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller bundle (.exe)
        return os.path.dirname(sys.executable)
    else:
        # Running as normal Python script
        return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()
PLUGIN_DIR = os.path.join(BASE_DIR, "plugins")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

# Ensure plugin directory exists
if not os.path.exists(PLUGIN_DIR):
    os.makedirs(PLUGIN_DIR, exist_ok=True)

# Add plugin directory to Python path for imports
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

print(f"[RS485 Sniffer] Base directory: {BASE_DIR}")
print(f"[RS485 Sniffer] Plugin directory: {PLUGIN_DIR}")
print(f"[RS485 Sniffer] Config file: {CONFIG_FILE}")

# Try to import plugin system
try:
    from plugin_api import PluginManager, PluginBase
    PLUGINS_AVAILABLE = True
    print("[RS485 Sniffer] Plugin API loaded successfully")
except ImportError as e:
    PLUGINS_AVAILABLE = False
    print(f"[RS485 Sniffer] Plugin API not found - plugins disabled: {e}")


class ConfigManager:
    """Manages application configuration."""
    
    DEFAULT_CONFIG = {
        "port": "",
        "baudrate": "115200",
        "parity": "None",
        "stopbits": "1",
        "delimiter": "0D0A",
        "start_byte": "",
        "timeout_ms": 50,
        "frame_mode": "both",
        "show_hex": True,
        "show_ascii": True,
        "autoscroll": True,
        "send_mode": "hex",
        "plugins": {}
    }
    
    def __init__(self, filename: str = None):
        # Use global CONFIG_FILE if no filename specified
        self.filename = filename if filename else CONFIG_FILE
        self.config = self.DEFAULT_CONFIG.copy()
        self.load()
    
    def load(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    self.config.update(loaded)
                print(f"[Config] Loaded from {self.filename}")
            except Exception as e:
                print(f"[Config] Error loading: {e}")
    
    def save(self):
        try:
            with open(self.filename, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            print(f"[Config] Saved to {self.filename}")
        except Exception as e:
            print(f"[Config] Error saving: {e}")
    
    def get(self, key: str, default=None):
        return self.config.get(key, default)
    
    def set(self, key: str, value):
        self.config[key] = value

class BusStatistics:
    """Track bus load and statistics."""
    
    def __init__(self, baudrate: int = 115200, bits_per_byte: int = 10):
        self.baudrate = baudrate
        self.bits_per_byte = bits_per_byte
        self.reset()
    
    def reset(self):
        self.start_time = time.time()
        self.total_bytes = 0
        self.total_frames = 0
        self.bytes_history: Deque = deque(maxlen=100)
        self.peak_load = 0.0
        self.peak_bytes_per_sec = 0
        self.last_sample_time = time.time()
        self.bytes_since_last_sample = 0
    
    def set_baudrate(self, baudrate: int):
        self.baudrate = baudrate
    
    def set_bits_per_byte(self, bits: int):
        self.bits_per_byte = bits
    
    def add_bytes(self, count: int):
        self.total_bytes += count
        self.bytes_since_last_sample += count
    
    def add_frame(self):
        self.total_frames += 1
    
    def sample(self):
        now = time.time()
        elapsed = now - self.last_sample_time
        if elapsed > 0:
            bps = self.bytes_since_last_sample / elapsed
            self.bytes_history.append(bps)
            if bps > self.peak_bytes_per_sec:
                self.peak_bytes_per_sec = bps
            load = self.calculate_load(bps)
            if load > self.peak_load:
                self.peak_load = load
        self.bytes_since_last_sample = 0
        self.last_sample_time = now
    
    def calculate_load(self, bps: float) -> float:
        if self.baudrate <= 0:
            return 0.0
        return min(100.0, (bps * self.bits_per_byte / self.baudrate) * 100.0)
    
    def get_current_load(self) -> float:
        if not self.bytes_history:
            return 0.0
        return self.calculate_load(sum(self.bytes_history) / len(self.bytes_history))
    
    def get_current_bps(self) -> float:
        if not self.bytes_history:
            return 0.0
        return sum(self.bytes_history) / len(self.bytes_history)
    
    def get_runtime(self) -> float:
        return time.time() - self.start_time


class RS485Sniffer:
    """RS485 Sniffer with plugin support."""
    
    BAUD_RATES = ["9600", "19200", "38400", "57600", "115200",
                  "230400", "250000", "460800", "500000", "921600", "1000000"]
    
    STOPBITS_MAP = {"1": serial.STOPBITS_ONE, "1.5": serial.STOPBITS_ONE_POINT_FIVE, "2": serial.STOPBITS_TWO}
    
    MODE_RAW = "raw"
    MODE_DELIMITER = "delimiter"
    MODE_TIMEOUT = "timeout"
    MODE_BOTH = "both"

    def __init__(self, gui):
        self.gui = gui
        self.ser = None
        self.running = False
        self.thread = None
        self.logfile = None
        self.rx_queue = queue.Queue()
        
        self.frame_mode = self.MODE_BOTH
        self.delimiter = b"\x0D\x0A"
        self.start_byte = None
        self.timeout_ms = 50
        self.show_ascii = True
        self.show_hex = True
        
        self.stats = BusStatistics()
        
        # Plugin manager
        if PLUGINS_AVAILABLE:
            self.plugin_manager = PluginManager(PLUGIN_DIR)
        else:
            self.plugin_manager = None

    def get_timestamp(self):
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def set_delimiter(self, hexstr):
        hexstr = hexstr.replace(" ", "").upper()
        if len(hexstr) == 0:
            self.delimiter = b""
            return True
        if len(hexstr) % 2 != 0:
            return False
        try:
            self.delimiter = bytes.fromhex(hexstr)
            return True
        except:
            return False

    def set_start_byte(self, hexstr):
        hexstr = hexstr.replace(" ", "").upper()
        if len(hexstr) == 0:
            self.start_byte = None
            return True
        try:
            self.start_byte = bytes.fromhex(hexstr)
            return True
        except:
            return False

    def set_timeout(self, ms):
        self.timeout_ms = max(1, min(10000, ms))

    def set_mode(self, mode):
        self.frame_mode = mode

    def format_frame(self, data, incomplete=False):
        ts = self.get_timestamp()
        parts = [f"{ts} RX [{len(data):4d}]"]
        
        if self.show_hex:
            hex_str = " ".join(f"{b:02X}" for b in data)
            parts.append(hex_str)
        
        if self.show_ascii:
            asc = ""
            for b in data:
                if 32 <= b < 127:
                    asc += chr(b)
                elif b == 0x0D:
                    asc += "\\r"
                elif b == 0x0A:
                    asc += "\\n"
                else:
                    asc += "."
            parts.append(f"| {asc}")
        
        if incomplete:
            parts.append("(incomplete)")
        
        result = " ".join(parts)
        
        # Notify plugins
        if self.plugin_manager:
            result = self.plugin_manager.notify_frame_received(ts, data, result)
        
        return result

    def open_logfile(self):
        fn = filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("CSV", "*.csv")])
        if fn:
            self.logfile = open(fn, "w", encoding="utf-8")
            self.gui.queue_msg(f"Log: {fn}")

    def write_log(self, text):
        if self.logfile:
            self.logfile.write(text + "\n")
            self.logfile.flush()

    def start(self):
        if self.running:
            return

        try:
            baudrate = int(self.gui.baud_var.get())
        except:
            self.gui.queue_msg("Ungueltige Baudrate!")
            return

        port = self.gui.port_var.get()
        if not port:
            self.gui.queue_msg("Kein Port!")
            return

        stopbits_str = self.gui.stopbits_var.get()
        stopbits = self.STOPBITS_MAP.get(stopbits_str, serial.STOPBITS_ONE)
        parity_str = self.gui.parity_var.get()
        
        bits = 1 + 8
        bits += 0 if parity_str == "None" else 1
        bits += {"1": 1, "1.5": 1.5, "2": 2}.get(stopbits_str, 1)
        
        self.stats.reset()
        self.stats.set_baudrate(baudrate)
        self.stats.set_bits_per_byte(int(bits))

        try:
            self.ser = serial.Serial(
                port=port, baudrate=baudrate, bytesize=serial.EIGHTBITS,
                parity=self.gui.parity_map[parity_str], stopbits=stopbits, timeout=0.001)
        except serial.SerialException as e:
            self.gui.queue_msg(f"Fehler: {e}")
            return

        self.running = True
        self.thread = threading.Thread(target=self.reader_thread, daemon=True)
        self.thread.start()
        self.gui.set_running(True)
        self.gui.queue_msg(f"Gestartet @ {baudrate} baud")
        
        if self.plugin_manager:
            self.plugin_manager.notify_start()

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        if self.ser:
            try:
                self.ser.close()
            except:
                pass
            self.ser = None
        if self.logfile:
            self.logfile.close()
            self.logfile = None
        self.gui.set_running(False)
        self.gui.queue_msg(f"Gestoppt | {self.stats.total_bytes} Bytes, {self.stats.total_frames} Frames")
        
        if self.plugin_manager:
            self.plugin_manager.notify_stop()

    def reader_thread(self):
        buffer = b""
        last_rx = time.perf_counter()
        in_frame = False if self.start_byte else True
        
        while self.running:
            try:
                if not self.ser or not self.ser.is_open:
                    break
                waiting = self.ser.in_waiting
                data = self.ser.read(waiting) if waiting > 0 else b""
            except:
                break

            if data:
                last_rx = time.perf_counter()
                self.stats.add_bytes(len(data))
                
                if self.frame_mode == self.MODE_RAW:
                    for byte in data:
                        line = self.format_frame(bytes([byte]))
                        self.rx_queue.put(line)
                        self.stats.add_frame()
                    continue
                
                # Process with start byte detection
                for byte in data:
                    b = bytes([byte])
                    
                    # Check for start byte
                    if self.start_byte and not in_frame:
                        if b == self.start_byte[:1]:
                            in_frame = True
                            buffer = b
                        continue
                    
                    buffer += b
                
                # Check delimiter
                if self.frame_mode in (self.MODE_DELIMITER, self.MODE_BOTH) and self.delimiter:
                    while self.delimiter in buffer:
                        idx = buffer.index(self.delimiter) + len(self.delimiter)
                        frame = buffer[:idx]
                        buffer = buffer[idx:]
                        line = self.format_frame(frame)
                        self.rx_queue.put(line)
                        self.write_log(line)
                        self.stats.add_frame()
                        in_frame = False if self.start_byte else True
                        last_rx = time.perf_counter()
            
            # Timeout check
            if self.frame_mode in (self.MODE_TIMEOUT, self.MODE_BOTH):
                if buffer:
                    elapsed = (time.perf_counter() - last_rx) * 1000
                    if elapsed >= self.timeout_ms:
                        line = self.format_frame(buffer)
                        self.rx_queue.put(line)
                        self.write_log(line)
                        self.stats.add_frame()
                        buffer = b""
                        in_frame = False if self.start_byte else True
                        last_rx = time.perf_counter()
            
            if not data:
                time.sleep(0.001)

        if buffer:
            self.rx_queue.put(self.format_frame(buffer, True))

    def send_data(self):
        if not self.ser or not self.ser.is_open:
            self.gui.queue_msg("Port nicht offen!")
            return
        
        text = self.gui.send_var.get()
        mode = self.gui.send_mode_var.get()
        
        try:
            if mode == "hex":
                raw = text.replace(" ", "")
                data = bytes.fromhex(raw)
            else:  # string/ascii
                data = text.encode("utf-8")
            
            self.ser.write(data)
            ts = self.get_timestamp()
            hex_str = " ".join(f"{b:02X}" for b in data)
            self.gui.queue_msg(f"{ts} TX [{len(data):4d}] {hex_str}")
            
            if self.plugin_manager:
                for p in self.plugin_manager.plugins.values():
                    if p.enabled:
                        p.on_frame_sent(ts, data)
        except Exception as e:
            self.gui.queue_msg(f"TX Fehler: {e}")


class StatisticsWindow:
    """Separate window for bus statistics."""
    
    def __init__(self, parent, sniffer):
        self.sniffer = sniffer
        self.window = tk.Toplevel(parent)
        self.window.title("Bus-Statistik")
        self.window.geometry("400x350")
        self.build_gui()
        self.update_stats()
    
    def build_gui(self):
        lf = ttk.LabelFrame(self.window, text="Aktuelle Auslastung")
        lf.pack(fill="x", padx=10, pady=5)
        
        self.load_var = tk.StringVar(value="0.0%")
        ttk.Label(lf, textvariable=self.load_var, font=("Consolas", 24, "bold")).pack(pady=5)
        self.load_bar = ttk.Progressbar(lf, length=350, mode="determinate")
        self.load_bar.pack(pady=5)
        
        rf = ttk.LabelFrame(self.window, text="Datenrate")
        rf.pack(fill="x", padx=10, pady=5)
        self.rate_var = tk.StringVar(value="0 Bytes/s")
        self.frames_var = tk.StringVar(value="0 Frames/s")
        ttk.Label(rf, textvariable=self.rate_var, font=("Consolas", 16)).pack()
        ttk.Label(rf, textvariable=self.frames_var, font=("Consolas", 12)).pack()
        
        sf = ttk.LabelFrame(self.window, text="Gesamt")
        sf.pack(fill="x", padx=10, pady=5)
        self.total_var = tk.StringVar()
        self.peak_var = tk.StringVar()
        ttk.Label(sf, textvariable=self.total_var, font=("Consolas", 10)).pack(anchor="w", padx=10)
        ttk.Label(sf, textvariable=self.peak_var, font=("Consolas", 10)).pack(anchor="w", padx=10)
        
        ttk.Button(self.window, text="Reset", command=self.sniffer.stats.reset).pack(pady=10)
    
    def update_stats(self):
        if not self.window.winfo_exists():
            return
        s = self.sniffer.stats
        s.sample()
        load = s.get_current_load()
        self.load_var.set(f"{load:.1f}%")
        self.load_bar["value"] = load
        self.rate_var.set(f"{s.get_current_bps():.0f} Bytes/s")
        rt = s.get_runtime()
        fps = s.total_frames / rt if rt > 0 else 0
        self.frames_var.set(f"{fps:.1f} Frames/s")
        self.total_var.set(f"Bytes: {s.total_bytes:,} | Frames: {s.total_frames:,} | Zeit: {rt:.0f}s")
        self.peak_var.set(f"Peak: {s.peak_load:.1f}% | {s.peak_bytes_per_sec:.0f} B/s")
        self.window.after(200, self.update_stats)


class PluginManagerWindow:
    """Window for managing plugins."""
    
    def __init__(self, parent, sniffer):
        self.sniffer = sniffer
        self.window = tk.Toplevel(parent)
        self.window.title("Plugin Manager")
        self.window.geometry("500x400")
        self.build_gui()
        self.refresh_list()
    
    def build_gui(self):
        # Plugin list
        lf = ttk.LabelFrame(self.window, text="Verfuegbare Plugins")
        lf.pack(fill="both", expand=True, padx=10, pady=5)
        
        cols = ("Name", "Version", "Status")
        self.tree = ttk.Treeview(lf, columns=cols, show="headings", height=10)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=150)
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Buttons
        bf = ttk.Frame(self.window)
        bf.pack(fill="x", padx=10, pady=5)
        ttk.Button(bf, text="Aktivieren", command=self.enable_plugin).pack(side="left", padx=5)
        ttk.Button(bf, text="Deaktivieren", command=self.disable_plugin).pack(side="left", padx=5)
        ttk.Button(bf, text="Neu laden", command=self.reload_plugins).pack(side="left", padx=5)
        ttk.Button(bf, text="Aktualisieren", command=self.refresh_list).pack(side="right", padx=5)
    
    def refresh_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if not self.sniffer.plugin_manager:
            return
        
        # Show loaded plugins
        for name, plugin in self.sniffer.plugin_manager.plugins.items():
            status = "Aktiv" if plugin.enabled else "Inaktiv"
            self.tree.insert("", "end", values=(plugin.info.name, plugin.info.version, status), tags=(name,))
        
        # Show discovered but not loaded
        discovered = self.sniffer.plugin_manager.discover_plugins()
        loaded = set(self.sniffer.plugin_manager.plugins.keys())
        for name in discovered:
            if name not in loaded:
                self.tree.insert("", "end", values=(name, "?", "Nicht geladen"), tags=(name,))
    
    def enable_plugin(self):
        sel = self.tree.selection()
        if sel:
            name = self.tree.item(sel[0])["tags"][0]
            if name in self.sniffer.plugin_manager.plugins:
                self.sniffer.plugin_manager.plugins[name].enabled = True
            else:
                self.sniffer.plugin_manager.load_plugin(name)
            self.refresh_list()
    
    def disable_plugin(self):
        sel = self.tree.selection()
        if sel:
            name = self.tree.item(sel[0])["tags"][0]
            if name in self.sniffer.plugin_manager.plugins:
                self.sniffer.plugin_manager.plugins[name].enabled = False
            self.refresh_list()
    
    def reload_plugins(self):
        if self.sniffer.plugin_manager:
            for name in list(self.sniffer.plugin_manager.plugins.keys()):
                self.sniffer.plugin_manager.unload_plugin(name)
            for name in self.sniffer.plugin_manager.discover_plugins():
                self.sniffer.plugin_manager.load_plugin(name)
        self.refresh_list()


class SnifferGUI:
    """Main GUI with plugin support."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"RS485 Sniffer v{__version__}")
        self.root.geometry("1050x750")
        
        self.config = ConfigManager()
        self.sniffer = RS485Sniffer(self)
        self.msg_queue = queue.Queue()
        self.stats_window = None
        self.plugin_window = None
        
        self.parity_map = {
            "None": serial.PARITY_NONE, "Even": serial.PARITY_EVEN,
            "Odd": serial.PARITY_ODD, "Mark": serial.PARITY_MARK, "Space": serial.PARITY_SPACE
        }
        
        # Variables
        self.port_var = tk.StringVar(value=self.config.get("port", ""))
        self.baud_var = tk.StringVar(value=self.config.get("baudrate", "115200"))
        self.parity_var = tk.StringVar(value=self.config.get("parity", "None"))
        self.stopbits_var = tk.StringVar(value=self.config.get("stopbits", "1"))
        self.delimiter_var = tk.StringVar(value=self.config.get("delimiter", "0D0A"))
        self.start_byte_var = tk.StringVar(value=self.config.get("start_byte", ""))
        self.timeout_var = tk.StringVar(value=str(self.config.get("timeout_ms", 50)))
        self.mode_var = tk.StringVar(value=self.config.get("frame_mode", "both"))
        self.show_hex_var = tk.BooleanVar(value=self.config.get("show_hex", True))
        self.show_ascii_var = tk.BooleanVar(value=self.config.get("show_ascii", True))
        self.autoscroll_var = tk.BooleanVar(value=self.config.get("autoscroll", True))
        self.send_var = tk.StringVar()
        self.send_mode_var = tk.StringVar(value=self.config.get("send_mode", "hex"))
        self.load_var = tk.StringVar(value="Load: 0%")
        self.rate_var = tk.StringVar(value="0 B/s")
        
        self.build_gui()
        self.init_plugins()
        self.poll_queues()
        self.update_status()
        self.apply_settings()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def queue_msg(self, text):
        self.msg_queue.put(text)

    def on_close(self):
        self.save_config()
        self.sniffer.stop()
        self.root.destroy()

    def save_config(self):
        self.config.set("port", self.port_var.get())
        self.config.set("baudrate", self.baud_var.get())
        self.config.set("parity", self.parity_var.get())
        self.config.set("stopbits", self.stopbits_var.get())
        self.config.set("delimiter", self.delimiter_var.get())
        self.config.set("start_byte", self.start_byte_var.get())
        self.config.set("timeout_ms", int(self.timeout_var.get() or 50))
        self.config.set("frame_mode", self.mode_var.get())
        self.config.set("show_hex", self.show_hex_var.get())
        self.config.set("show_ascii", self.show_ascii_var.get())
        self.config.set("autoscroll", self.autoscroll_var.get())
        self.config.set("send_mode", self.send_mode_var.get())
        self.config.save()

    def init_plugins(self):
        if not self.sniffer.plugin_manager:
            return
        self.sniffer.plugin_manager.set_references(self, self.sniffer)
        discovered = self.sniffer.plugin_manager.discover_plugins()
        for name in discovered:
            self.sniffer.plugin_manager.load_plugin(name)
        # Create plugin tabs
        for name, plugin in self.sniffer.plugin_manager.plugins.items():
            tab = plugin.create_tab(self.notebook)
            if tab:
                self.notebook.add(tab, text=plugin.info.name)

    def refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo["values"] = ports
        if ports and not self.port_var.get():
            self.port_combo.current(0)

    def apply_settings(self):
        self.sniffer.set_delimiter(self.delimiter_var.get())
        self.sniffer.set_start_byte(self.start_byte_var.get())
        try:
            self.sniffer.set_timeout(int(self.timeout_var.get()))
        except:
            pass
        self.sniffer.set_mode(self.mode_var.get())
        self.sniffer.show_hex = self.show_hex_var.get()
        self.sniffer.show_ascii = self.show_ascii_var.get()

    def open_stats(self):
        if not self.stats_window or not self.stats_window.window.winfo_exists():
            self.stats_window = StatisticsWindow(self.root, self.sniffer)

    def open_plugins(self):
        if not self.plugin_window or not self.plugin_window.window.winfo_exists():
            self.plugin_window = PluginManagerWindow(self.root, self.sniffer)

    def build_gui(self):
        # Menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Datei", menu=file_menu)
        file_menu.add_command(label="Log speichern", command=self.sniffer.open_logfile)
        file_menu.add_command(label="Config speichern", command=self.save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Beenden", command=self.on_close)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Statistik", command=self.open_stats)
        tools_menu.add_command(label="Plugin Manager", command=self.open_plugins)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Main tab
        main_tab = ttk.Frame(self.notebook)
        self.notebook.add(main_tab, text="Sniffer")
        
        # Connection frame
        conn = ttk.LabelFrame(main_tab, text="Verbindung")
        conn.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(conn, text="Port:").grid(row=0, column=0, padx=2)
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo = ttk.Combobox(conn, textvariable=self.port_var, values=ports, width=12)
        if ports and not self.port_var.get():
            self.port_combo.current(0)
        self.port_combo.grid(row=0, column=1, padx=2)
        ttk.Button(conn, text="R", width=2, command=self.refresh_ports).grid(row=0, column=2)
        
        ttk.Label(conn, text="Baud:").grid(row=0, column=3, padx=2)
        ttk.Combobox(conn, textvariable=self.baud_var, values=RS485Sniffer.BAUD_RATES, width=10).grid(row=0, column=4)
        
        ttk.Label(conn, text="Parity:").grid(row=0, column=5, padx=2)
        ttk.Combobox(conn, textvariable=self.parity_var, values=list(self.parity_map.keys()), width=6, state="readonly").grid(row=0, column=6)
        
        ttk.Label(conn, text="Stop:").grid(row=0, column=7, padx=2)
        ttk.Combobox(conn, textvariable=self.stopbits_var, values=["1", "1.5", "2"], width=4, state="readonly").grid(row=0, column=8)

        # Framing frame
        frm = ttk.LabelFrame(main_tab, text="Frame-Erkennung")
        frm.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(frm, text="Modus:").grid(row=0, column=0, padx=2)
        for i, (val, txt) in enumerate([("delimiter", "Delimiter"), ("timeout", "Timeout"), ("both", "Beides"), ("raw", "RAW")]):
            ttk.Radiobutton(frm, text=txt, variable=self.mode_var, value=val, command=self.apply_settings).grid(row=0, column=i+1, padx=3)
        
        ttk.Label(frm, text="Start:").grid(row=0, column=6, padx=2)
        ttk.Entry(frm, textvariable=self.start_byte_var, width=6).grid(row=0, column=7)
        
        ttk.Label(frm, text="Delim:").grid(row=0, column=8, padx=2)
        ttk.Entry(frm, textvariable=self.delimiter_var, width=8).grid(row=0, column=9)
        
        ttk.Label(frm, text="Timeout:").grid(row=0, column=10, padx=2)
        ttk.Entry(frm, textvariable=self.timeout_var, width=5).grid(row=0, column=11)
        ttk.Label(frm, text="ms").grid(row=0, column=12)
        
        ttk.Button(frm, text="Anwenden", command=self.apply_settings).grid(row=0, column=13, padx=5)

        # Display options
        disp = ttk.LabelFrame(main_tab, text="Anzeige")
        disp.pack(fill="x", padx=5, pady=2)
        
        ttk.Checkbutton(disp, text="Hex", variable=self.show_hex_var, command=self.apply_settings).pack(side="left", padx=5)
        ttk.Checkbutton(disp, text="ASCII", variable=self.show_ascii_var, command=self.apply_settings).pack(side="left", padx=5)
        ttk.Checkbutton(disp, text="Autoscroll", variable=self.autoscroll_var).pack(side="left", padx=5)
        
        ttk.Label(disp, text="Presets:").pack(side="left", padx=10)
        for txt, st, delim in [("CRLF", "", "0D0A"), ("LF", "", "0A"), ("0xFE", "FE", "")]:
            ttk.Button(disp, text=txt, width=5, command=lambda s=st, d=delim: self.set_preset(s, d)).pack(side="left", padx=2)

        # Text display
        txt_frame = ttk.Frame(main_tab)
        txt_frame.pack(fill="both", expand=True, padx=5, pady=2)
        
        sb_y = ttk.Scrollbar(txt_frame, orient="vertical")
        sb_y.pack(side="right", fill="y")
        sb_x = ttk.Scrollbar(txt_frame, orient="horizontal")
        sb_x.pack(side="bottom", fill="x")
        
        self.text = tk.Text(txt_frame, wrap="none", font=("Consolas", 9), yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        self.text.pack(fill="both", expand=True)
        sb_y.config(command=self.text.yview)
        sb_x.config(command=self.text.xview)
        
        self.text.tag_configure("tx", foreground="blue")
        self.text.tag_configure("error", foreground="red")
        self.text.tag_configure("info", foreground="gray")

        # Status bar
        status = ttk.Frame(main_tab)
        status.pack(fill="x", padx=5)
        self.status_var = tk.StringVar(value="Bereit")
        ttk.Label(status, textvariable=self.status_var, width=40, anchor="w").pack(side="left")
        ttk.Label(status, textvariable=self.load_var, width=12).pack(side="right")
        ttk.Label(status, textvariable=self.rate_var, width=12).pack(side="right")
        self.mini_bar = ttk.Progressbar(status, length=100, mode="determinate")
        self.mini_bar.pack(side="right", padx=5)

        # Control buttons
        btn = ttk.Frame(main_tab)
        btn.pack(fill="x", padx=5, pady=5)
        
        self.start_btn = ttk.Button(btn, text="Start", command=self.sniffer.start, width=10)
        self.start_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(btn, text="Stop", command=self.sniffer.stop, width=10, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        ttk.Button(btn, text="Clear", command=lambda: self.text.delete("1.0", tk.END), width=8).pack(side="left", padx=2)
        ttk.Button(btn, text="Statistik", command=self.open_stats, width=10).pack(side="left", padx=2)
        ttk.Button(btn, text="Plugins", command=self.open_plugins, width=10).pack(side="left", padx=2)

        # Send frame
        snd = ttk.LabelFrame(main_tab, text="Senden")
        snd.pack(fill="x", padx=5, pady=5)
        
        ttk.Radiobutton(snd, text="HEX", variable=self.send_mode_var, value="hex").pack(side="left", padx=5)
        ttk.Radiobutton(snd, text="STRING", variable=self.send_mode_var, value="string").pack(side="left", padx=5)
        ttk.Entry(snd, textvariable=self.send_var, width=60, font=("Consolas", 10)).pack(side="left", padx=5, pady=5)
        ttk.Button(snd, text="SEND", command=self.sniffer.send_data).pack(side="left", padx=5)

    def set_preset(self, start, delim):
        if start:
            self.start_byte_var.set(start)
        if delim:
            self.delimiter_var.set(delim)
        self.apply_settings()

    def update_status(self):
        s = self.sniffer.stats
        s.sample()
        self.load_var.set(f"Load: {s.get_current_load():.1f}%")
        self.rate_var.set(f"{s.get_current_bps():.0f} B/s")
        self.mini_bar["value"] = s.get_current_load()
        self.root.after(200, self.update_status)

    def poll_queues(self):
        updated = False
        try:
            for _ in range(100):
                line = self.sniffer.rx_queue.get_nowait()
                tag = "error" if "[ERROR]" in line else None
                self.text.insert(tk.END, line + "\n", tag)
                updated = True
        except queue.Empty:
            pass
        try:
            for _ in range(20):
                msg = self.msg_queue.get_nowait()
                tag = "tx" if "TX" in msg else ("error" if "Fehler" in msg else "info")
                self.text.insert(tk.END, msg + "\n", tag)
                self.status_var.set(msg)
                updated = True
        except queue.Empty:
            pass
        if updated and self.autoscroll_var.get():
            self.text.see(tk.END)
        self.root.after(30, self.poll_queues)

    def set_running(self, running):
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")
        self.status_var.set("Laeuft..." if running else "Gestoppt")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    print(f"RS485 Sniffer v{__version__}")
    print("Features: Plugins, HEX/STRING, Start-Byte, Config")
    SnifferGUI().run()
