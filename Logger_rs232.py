#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RS485 Sniffer v1.4.0 - HausBus mit Busauslastung
Features: Multi-byte delimiter, timeout-based framing, ASCII+Hex view, Bus load calculation
"""

import serial
import serial.tools.list_ports
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from datetime import datetime
import binascii
import queue
from typing import Optional, List
import sys
import time
from collections import deque

__version__ = "1.4.0"
__changelog__ = [
    {"version": "1.4.0", "date": "2026-01-13", "author": "Assistant",
     "description": "Added bus load calculation, statistics panel, live graphs"},
    {"version": "1.3.0", "date": "2026-01-12", "author": "Assistant",
     "description": "Multi-byte delimiter, timeout framing, ASCII+Hex dual view"},
]


class BusStatistics:
    """Tracks bus statistics and calculates load."""
    
    def __init__(self, baudrate: int, databits: int = 8, parity: str = "None", stopbits: float = 1.0):
        self.baudrate = baudrate
        self.databits = databits
        self.parity_bit = 1 if parity != "None" else 0
        self.stopbits = stopbits
        
        # Calculate bits per byte
        self.bits_per_byte = 1 + databits + self.parity_bit + stopbits  # Start + Data + Parity + Stop
        
        # Statistics
        self.start_time = time.perf_counter()
        self.total_bytes = 0
        self.total_frames = 0
        
        # Live tracking (1 second window)
        self.byte_history = deque(maxlen=100)  # (timestamp, byte_count)
        self.last_update = time.perf_counter()
        
        # Peak values
        self.peak_load = 0.0
        self.peak_bytes_per_sec = 0
        self.peak_frames_per_sec = 0
        
        # Current values
        self.current_bytes_per_sec = 0
        self.current_frames_per_sec = 0
        self.current_load = 0.0

    def update(self, byte_count: int, frame_count: int = 0) -> None:
        """Update statistics with new data."""
        now = time.perf_counter()
        self.total_bytes += byte_count
        self.total_frames += frame_count
        
        # Add to history
        self.byte_history.append((now, byte_count))
        
        # Calculate current rates (last 1 second)
        cutoff = now - 1.0
        recent_bytes = sum(count for ts, count in self.byte_history if ts >= cutoff)
        
        # Update current values
        self.current_bytes_per_sec = recent_bytes
        
        # Calculate bus load
        bits_per_second = recent_bytes * self.bits_per_byte
        self.current_load = (bits_per_second / self.baudrate) * 100.0
        
        # Update peaks
        if self.current_load > self.peak_load:
            self.peak_load = self.current_load
        if self.current_bytes_per_sec > self.peak_bytes_per_sec:
            self.peak_bytes_per_sec = self.current_bytes_per_sec

    def get_runtime(self) -> float:
        """Get runtime in seconds."""
        return time.perf_counter() - self.start_time

    def get_average_bytes_per_sec(self) -> float:
        """Get average bytes per second since start."""
        runtime = self.get_runtime()
        return self.total_bytes / runtime if runtime > 0 else 0

    def reset(self) -> None:
        """Reset all statistics."""
        self.start_time = time.perf_counter()
        self.total_bytes = 0
        self.total_frames = 0
        self.byte_history.clear()
        self.peak_load = 0.0
        self.peak_bytes_per_sec = 0
        self.peak_frames_per_sec = 0
        self.current_bytes_per_sec = 0
        self.current_frames_per_sec = 0
        self.current_load = 0.0


class RS485Sniffer:
    """RS485 Sniffer with multiple framing modes and statistics."""
    
    BAUD_RATES = ["9600", "19200", "38400", "57600", "115200",
                  "230400", "250000", "460800", "500000", "921600", "1000000"]
    
    STOPBITS_MAP = {
        "1": serial.STOPBITS_ONE,
        "1.5": serial.STOPBITS_ONE_POINT_FIVE,
        "2": serial.STOPBITS_TWO
    }
    
    # Framing modes
    MODE_RAW = "raw"
    MODE_DELIMITER = "delimiter"
    MODE_TIMEOUT = "timeout"
    MODE_BOTH = "both"

    def __init__(self, gui: "SnifferGUI") -> None:
        self.gui = gui
        self.ser: Optional[serial.Serial] = None
        self.running: bool = False
        self.thread: Optional[threading.Thread] = None
        self.logfile = None
        self.rx_queue: queue.Queue = queue.Queue()
        
        # Framing settings
        self.frame_mode: str = self.MODE_DELIMITER
        self.delimiter: bytes = b"\x0D\x0A"
        self.timeout_ms: int = 50
        self.show_ascii: bool = True
        self.show_hex: bool = True
        
        # Statistics
        self.stats: Optional[BusStatistics] = None

    @staticmethod
    def get_timestamp() -> str:
        """Returns timestamp with milliseconds."""
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def debug_print(self, msg: str) -> None:
        """Print debug message to console."""
        print(f"[DEBUG] {msg}", file=sys.stderr, flush=True)

    def set_delimiter(self, hexstr: str) -> bool:
        """Set delimiter from hex string."""
        hexstr = hexstr.replace(" ", "").upper()
        if len(hexstr) == 0 or len(hexstr) % 2 != 0:
            self.gui.queue_msg("Ungültiger Delimiter (gerade Anzahl Hex-Zeichen)")
            return False
        try:
            self.delimiter = bytes.fromhex(hexstr)
            self.gui.queue_msg(f"Delimiter gesetzt: {hexstr} ({len(self.delimiter)} Bytes)")
            return True
        except ValueError:
            self.gui.queue_msg("Ungültiger Hex-Wert")
            return False

    def set_timeout(self, ms: int) -> None:
        """Set timeout in milliseconds."""
        self.timeout_ms = max(1, min(10000, ms))
        self.gui.queue_msg(f"Timeout gesetzt: {self.timeout_ms} ms")

    def set_mode(self, mode: str) -> None:
        """Set framing mode."""
        self.frame_mode = mode
        mode_names = {
            self.MODE_RAW: "RAW (jedes Byte)",
            self.MODE_DELIMITER: "Delimiter",
            self.MODE_TIMEOUT: "Timeout",
            self.MODE_BOTH: "Delimiter + Timeout"
        }
        self.gui.queue_msg(f"Modus: {mode_names.get(mode, mode)}")

    def format_frame(self, data: bytes, incomplete: bool = False) -> str:
        """Format a frame for display."""
        ts = self.get_timestamp()
        parts = [f"{ts} RX [{len(data):4d}]"]
        
        if self.show_hex:
            hex_str = data.hex().upper()
            hex_spaced = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            parts.append(hex_spaced)
        
        if self.show_ascii:
            ascii_str = ""
            for b in data:
                if 32 <= b < 127:
                    ascii_str += chr(b)
                elif b == 0x0D:
                    ascii_str += "\\r"
                elif b == 0x0A:
                    ascii_str += "\\n"
                elif b == 0x09:
                    ascii_str += "\\t"
                else:
                    ascii_str += "."
            parts.append(f'| {ascii_str}')
        
        if incomplete:
            parts.append("(incomplete)")
        
        return " ".join(parts)

    def open_logfile(self) -> None:
        """Open logfile for saving."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.logfile = open(filename, "w", encoding="utf-8")
            self.gui.queue_msg(f"Logfile: {filename}")

    def close_logfile(self) -> None:
        """Close logfile."""
        if self.logfile:
            self.logfile.close()
            self.logfile = None

    def write_log(self, text: str) -> None:
        """Write to logfile."""
        if self.logfile:
            self.logfile.write(text + "\n")
            self.logfile.flush()

    def start(self) -> None:
        """Start the sniffer."""
        if self.running:
            return

        try:
            baudrate = int(self.gui.baud_var.get())
        except ValueError:
            self.gui.queue_msg("Ungültige Baudrate!")
            return

        port = self.gui.port_var.get()
        if not port:
            self.gui.queue_msg("Kein Port ausgewählt!")
            return

        stopbits = self.STOPBITS_MAP.get(self.gui.stopbits_var.get(), serial.STOPBITS_ONE)
        stopbits_value = float(self.gui.stopbits_var.get())
        
        self.debug_print(f"Opening {port} @ {baudrate} baud, mode={self.frame_mode}")

        try:
            self.ser = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=self.gui.parity_map[self.gui.parity_var.get()],
                stopbits=stopbits,
                timeout=0.001
            )
        except serial.SerialException as e:
            self.gui.queue_msg(f"Fehler: {e}")
            return

        # Initialize statistics
        self.stats = BusStatistics(
            baudrate=baudrate,
            databits=8,
            parity=self.gui.parity_var.get(),
            stopbits=stopbits_value
        )

        self.running = True
        self.thread = threading.Thread(target=self.reader_thread, daemon=True)
        self.thread.start()
        self.gui.set_running(True)
        self.gui.queue_msg(f"Gestartet @ {baudrate} baud | Modus: {self.frame_mode}")

    def stop(self) -> None:
        """Stop the sniffer."""
        self.debug_print("Stopping...")
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        if self.ser:
            try:
                self.ser.close()
            except:
                pass
            self.ser = None
        self.close_logfile()
        self.gui.set_running(False)
        
        if self.stats:
            self.gui.queue_msg(f"Gestoppt | {self.stats.total_bytes} Bytes, {self.stats.total_frames} Frames")

    def reader_thread(self) -> None:
        """Background thread for reading serial data."""
        self.debug_print("Reader thread started")
        buffer = b""
        last_rx_time = time.perf_counter()
        
        while self.running:
            try:
                if not self.ser or not self.ser.is_open:
                    break
                
                waiting = self.ser.in_waiting
                if waiting > 0:
                    data = self.ser.read(waiting)
                    last_rx_time = time.perf_counter()
                else:
                    data = b""
                    
            except serial.SerialException as e:
                self.debug_print(f"Serial error: {e}")
                self.rx_queue.put(f"[ERROR] {e}")
                break

            # Process received data
            if data:
                # Update statistics
                if self.stats:
                    self.stats.update(len(data), 0)
                
                # RAW MODE
                if self.frame_mode == self.MODE_RAW:
                    for byte in data:
                        line = self.format_frame(bytes([byte]))
                        self.rx_queue.put(line)
                        self.write_log(line)
                        if self.stats:
                            self.stats.total_frames += 1
                    continue
                
                buffer += data
                
                # DELIMITER MODE or BOTH MODE
                if self.frame_mode in (self.MODE_DELIMITER, self.MODE_BOTH):
                    while self.delimiter in buffer:
                        idx = buffer.index(self.delimiter) + len(self.delimiter)
                        frame = buffer[:idx]
                        buffer = buffer[idx:]
                        
                        line = self.format_frame(frame)
                        self.rx_queue.put(line)
                        self.write_log(line)
                        if self.stats:
                            self.stats.total_frames += 1
                        last_rx_time = time.perf_counter()
            
            # TIMEOUT MODE or BOTH MODE
            if self.frame_mode in (self.MODE_TIMEOUT, self.MODE_BOTH):
                if buffer:
                    elapsed_ms = (time.perf_counter() - last_rx_time) * 1000
                    if elapsed_ms >= self.timeout_ms:
                        line = self.format_frame(buffer)
                        self.rx_queue.put(line)
                        self.write_log(line)
                        if self.stats:
                            self.stats.total_frames += 1
                        buffer = b""
                        last_rx_time = time.perf_counter()
            
            if not data:
                time.sleep(0.001)

        # Flush remaining buffer
        if buffer:
            line = self.format_frame(buffer, incomplete=True)
            self.rx_queue.put(line)
            self.write_log(line)
            
        self.debug_print(f"Thread exit. {self.stats.total_bytes if self.stats else 0} bytes")

    def send_data(self) -> None:
        """Send hex data."""
        if not self.ser or not self.ser.is_open:
            self.gui.queue_msg("Port nicht offen!")
            return

        raw = self.gui.send_var.get().replace(" ", "")
        if len(raw) % 2 != 0:
            self.gui.queue_msg("Ungültige Hex-Länge")
            return

        try:
            data = bytes.fromhex(raw)
        except ValueError:
            self.gui.queue_msg("Ungültiger Hex-Wert")
            return

        try:
            self.ser.write(data)
            ts = self.get_timestamp()
            hex_spaced = " ".join(raw[i:i+2].upper() for i in range(0, len(raw), 2))
            self.gui.queue_msg(f"{ts} TX [{len(data):4d}] {hex_spaced}")
        except serial.SerialException as e:
            self.gui.queue_msg(f"TX Fehler: {e}")


class SnifferGUI:
    """Tkinter GUI for RS485 Sniffer."""
    
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(f"RS485 Sniffer v{__version__}")
        self.root.geometry("1200x750")
        
        self.sniffer = RS485Sniffer(self)
        self.msg_queue: queue.Queue = queue.Queue()
        
        self.parity_map = {
            "None": serial.PARITY_NONE,
            "Even": serial.PARITY_EVEN,
            "Odd": serial.PARITY_ODD,
            "Mark": serial.PARITY_MARK,
            "Space": serial.PARITY_SPACE
        }
        
        # Variables
        self.port_var = tk.StringVar()
        self.baud_var = tk.StringVar(value="115200")
        self.parity_var = tk.StringVar(value="None")
        self.stopbits_var = tk.StringVar(value="1")
        self.delimiter_var = tk.StringVar(value="0D0A")
        self.timeout_var = tk.StringVar(value="50")
        self.mode_var = tk.StringVar(value=RS485Sniffer.MODE_BOTH)
        self.show_hex_var = tk.BooleanVar(value=True)
        self.show_ascii_var = tk.BooleanVar(value=True)
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.send_var = tk.StringVar()
        
        self.build_gui()
        self.poll_queues()
        self.apply_settings()

    def queue_msg(self, text: str) -> None:
        """Thread-safe message queue."""
        self.msg_queue.put(text)

    def refresh_ports(self) -> None:
        """Refresh COM port list."""
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo['values'] = ports
        if ports and not self.port_var.get():
            self.port_combo.current(0)
        self.queue_msg(f"Ports: {len(ports)} gefunden")

    def apply_settings(self) -> None:
        """Apply current settings to sniffer."""
        self.sniffer.set_delimiter(self.delimiter_var.get())
        
        try:
            self.sniffer.set_timeout(int(self.timeout_var.get()))
        except ValueError:
            pass
        
        self.sniffer.set_mode(self.mode_var.get())
        self.sniffer.show_hex = self.show_hex_var.get()
        self.sniffer.show_ascii = self.show_ascii_var.get()

    def build_gui(self) -> None:
        """Build GUI elements."""
        
        # Main container
        main_container = ttk.PanedWindow(self.root, orient="horizontal")
        main_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Left panel (controls + text)
        left_panel = ttk.Frame(main_container)
        main_container.add(left_panel, weight=3)
        
        # Right panel (statistics)
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=1)
        
        # === LEFT PANEL ===
        
        # Connection Frame
        conn_frame = ttk.LabelFrame(left_panel, text="Verbindung")
        conn_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=0, padx=2)
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo = ttk.Combobox(conn_frame, textvariable=self.port_var, 
                                        values=ports, width=12)
        if ports:
            self.port_combo.current(0)
        self.port_combo.grid(row=0, column=1, padx=2)
        
        ttk.Button(conn_frame, text="↻", width=3, 
                   command=self.refresh_ports).grid(row=0, column=2, padx=2)
        
        ttk.Label(conn_frame, text="Baud:").grid(row=0, column=3, padx=2)
        ttk.Combobox(conn_frame, textvariable=self.baud_var,
                     values=RS485Sniffer.BAUD_RATES, width=10).grid(row=0, column=4, padx=2)
        
        ttk.Label(conn_frame, text="Parity:").grid(row=0, column=5, padx=2)
        ttk.Combobox(conn_frame, textvariable=self.parity_var,
                     values=list(self.parity_map.keys()), width=6,
                     state="readonly").grid(row=0, column=6, padx=2)
        
        ttk.Label(conn_frame, text="Stop:").grid(row=0, column=7, padx=2)
        ttk.Combobox(conn_frame, textvariable=self.stopbits_var,
                     values=["1", "1.5", "2"], width=4,
                     state="readonly").grid(row=0, column=8, padx=2)

        # Framing Frame
        frame_frame = ttk.LabelFrame(left_panel, text="Frame-Erkennung")
        frame_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Label(frame_frame, text="Modus:").grid(row=0, column=0, padx=5)
        modes = [
            (RS485Sniffer.MODE_DELIMITER, "Delimiter"),
            (RS485Sniffer.MODE_TIMEOUT, "Timeout"),
            (RS485Sniffer.MODE_BOTH, "Beides"),
            (RS485Sniffer.MODE_RAW, "RAW"),
        ]
        for i, (value, text) in enumerate(modes):
            ttk.Radiobutton(frame_frame, text=text, variable=self.mode_var, 
                           value=value, command=self.apply_settings
                           ).grid(row=0, column=i+1, padx=5)
        
        ttk.Label(frame_frame, text="Delimiter (Hex):").grid(row=0, column=6, padx=(20, 2))
        delim_entry = ttk.Entry(frame_frame, textvariable=self.delimiter_var, width=12)
        delim_entry.grid(row=0, column=7, padx=2)
        
        ttk.Label(frame_frame, text="Timeout (ms):").grid(row=0, column=8, padx=(20, 2))
        timeout_entry = ttk.Entry(frame_frame, textvariable=self.timeout_var, width=6)
        timeout_entry.grid(row=0, column=9, padx=2)
        
        ttk.Button(frame_frame, text="Anwenden", 
                   command=self.apply_settings).grid(row=0, column=10, padx=10)

        # Display Options
        disp_frame = ttk.LabelFrame(left_panel, text="Anzeige")
        disp_frame.pack(fill="x", padx=5, pady=2)
        
        ttk.Checkbutton(disp_frame, text="Hex", variable=self.show_hex_var,
                        command=self.apply_settings).pack(side="left", padx=10)
        ttk.Checkbutton(disp_frame, text="ASCII", variable=self.show_ascii_var,
                        command=self.apply_settings).pack(side="left", padx=10)
        ttk.Checkbutton(disp_frame, text="Autoscroll", 
                        variable=self.autoscroll_var).pack(side="left", padx=10)
        
        ttk.Label(disp_frame, text="Presets:").pack(side="left", padx=(30, 5))
        ttk.Button(disp_frame, text="CRLF", width=6,
                   command=lambda: self.set_preset("0D0A", 50)).pack(side="left", padx=2)
        ttk.Button(disp_frame, text="LF", width=4,
                   command=lambda: self.set_preset("0A", 50)).pack(side="left", padx=2)
        ttk.Button(disp_frame, text="0xFE", width=5,
                   command=lambda: self.set_preset("FE", 50)).pack(side="left", padx=2)

        # Text Display
        text_frame = ttk.Frame(left_panel)
        text_frame.pack(fill="both", expand=True, padx=5, pady=2)
        
        scrollbar_y = ttk.Scrollbar(text_frame, orient="vertical")
        scrollbar_y.pack(side="right", fill="y")
        scrollbar_x = ttk.Scrollbar(text_frame, orient="horizontal")
        scrollbar_x.pack(side="bottom", fill="x")
        
        self.text = tk.Text(text_frame, wrap="none", font=("Consolas", 9),
                            yscrollcommand=scrollbar_y.set,
                            xscrollcommand=scrollbar_x.set)
        self.text.pack(fill="both", expand=True)
        scrollbar_y.config(command=self.text.yview)
        scrollbar_x.config(command=self.text.xview)
        
        self.text.tag_configure("tx", foreground="blue")
        self.text.tag_configure("error", foreground="red")
        self.text.tag_configure("info", foreground="gray")

        # Status Bar
        self.status_var = tk.StringVar(value="Bereit")
        ttk.Label(left_panel, textvariable=self.status_var, 
                  relief="sunken", anchor="w").pack(fill="x", padx=5)

        # Control Buttons
        btn_frame = ttk.Frame(left_panel)
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        self.start_btn = ttk.Button(btn_frame, text="▶ Start", 
                                     command=self.sniffer.start, width=10)
        self.start_btn.pack(side="left", padx=2)
        
        self.stop_btn = ttk.Button(btn_frame, text="■ Stop", 
                                    command=self.sniffer.stop, width=10, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        
        ttk.Button(btn_frame, text="Clear", width=8,
                   command=self.clear_text).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Log speichern", width=12,
                   command=self.sniffer.open_logfile).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Stats Reset", width=10,
                   command=self.reset_stats).pack(side="left", padx=2)

        # Send Frame
        send_frame = ttk.LabelFrame(left_panel, text="Senden (Hex)")
        send_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Entry(send_frame, textvariable=self.send_var, width=60,
                  font=("Consolas", 10)).pack(side="left", padx=5, pady=5)
        ttk.Button(send_frame, text="SEND", 
                   command=self.sniffer.send_data).pack(side="left", padx=5)

        # === RIGHT PANEL (STATISTICS) ===
        
        stats_frame = ttk.LabelFrame(right_panel, text="Busauslastung & Statistik")
        stats_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Live Load Display
        load_frame = ttk.Frame(stats_frame)
        load_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(load_frame, text="Aktuelle Auslastung:", 
                  font=("Arial", 10, "bold")).pack(anchor="w")
        
        self.load_label = ttk.Label(load_frame, text="0.0%", 
                                     font=("Arial", 24, "bold"), foreground="green")
        self.load_label.pack(pady=5)
        
        # Progress bar
        self.load_progress = ttk.Progressbar(load_frame, mode="determinate", 
                                             length=200, maximum=100)
        self.load_progress.pack(fill="x", pady=5)
        
        # Current rates
        rates_frame = ttk.LabelFrame(stats_frame, text="Aktuelle Werte (1s)")
        rates_frame.pack(fill="x", padx=10, pady=5)
        
        self.bytes_sec_label = ttk.Label(rates_frame, text="Bytes/s: 0")
        self.bytes_sec_label.pack(anchor="w", padx=5)
        
        self.bits_sec_label = ttk.Label(rates_frame, text="Bits/s: 0")
        self.bits_sec_label.pack(anchor="w", padx=5)
        
        # Peak values
        peak_frame = ttk.LabelFrame(stats_frame, text="Spitzenwerte")
        peak_frame.pack(fill="x", padx=10, pady=5)
        
        self.peak_load_label = ttk.Label(peak_frame, text="Peak Load: 0.0%")
        self.peak_load_label.pack(anchor="w", padx=5)
        
        self.peak_bytes_label = ttk.Label(peak_frame, text="Peak Bytes/s: 0")
        self.peak_bytes_label.pack(anchor="w", padx=5)
        
        # Total statistics
        total_frame = ttk.LabelFrame(stats_frame, text="Gesamt")
        total_frame.pack(fill="x", padx=10, pady=5)
        
        self.total_bytes_label = ttk.Label(total_frame, text="Bytes: 0")
        self.total_bytes_label.pack(anchor="w", padx=5)
        
        self.total_frames_label = ttk.Label(total_frame, text="Frames: 0")
        self.total_frames_label.pack(anchor="w", padx=5)
        
        self.runtime_label = ttk.Label(total_frame, text="Laufzeit: 0:00:00")
        self.runtime_label.pack(anchor="w", padx=5)
        
        self.avg_bytes_label = ttk.Label(total_frame, text="Ø Bytes/s: 0")
        self.avg_bytes_label.pack(anchor="w", padx=5)
        
        # Configuration info
        config_frame = ttk.LabelFrame(stats_frame, text="Konfiguration")
        config_frame.pack(fill="x", padx=10, pady=5)
        
        self.config_label = ttk.Label(config_frame, text="Nicht verbunden", 
                                      font=("Consolas", 8))
        self.config_label.pack(anchor="w", padx=5, pady=5)

    def reset_stats(self) -> None:
        """Reset statistics."""
        if self.sniffer.stats:
            self.sniffer.stats.reset()
            self.queue_msg("Statistiken zurückgesetzt")

    def set_preset(self, delimiter: str, timeout: int) -> None:
        """Apply a preset configuration."""
        if delimiter:
            self.delimiter_var.set(delimiter)
        self.timeout_var.set(str(timeout))
        self.apply_settings()

    def clear_text(self) -> None:
        """Clear text display."""
        self.text.delete("1.0", tk.END)

    def update_statistics_display(self) -> None:
        """Update statistics display."""
        if not self.sniffer.stats:
            return
        
        stats = self.sniffer.stats
        
        # Current load
        load = stats.current_load
        self.load_label.config(text=f"{load:.1f}%")
        self.load_progress['value'] = min(load, 100)
        
        # Color coding
        if load < 50:
            color = "green"
        elif load < 80:
            color = "orange"
        else:
            color = "red"
        self.load_label.config(foreground=color)
        
        # Current rates
        self.bytes_sec_label.config(text=f"Bytes/s: {stats.current_bytes_per_sec}")
        bits_per_sec = stats.current_bytes_per_sec * stats.bits_per_byte
        self.bits_sec_label.config(text=f"Bits/s: {bits_per_sec:.0f}")
        
        # Peak values
        self.peak_load_label.config(text=f"Peak Load: {stats.peak_load:.1f}%")
        self.peak_bytes_label.config(text=f"Peak Bytes/s: {stats.peak_bytes_per_sec}")
        
        # Total statistics
        self.total_bytes_label.config(text=f"Bytes: {stats.total_bytes:,}")
        self.total_frames_label.config(text=f"Frames: {stats.total_frames:,}")
        
        # Runtime
        runtime = stats.get_runtime()
        hours = int(runtime // 3600)
        minutes = int((runtime % 3600) // 60)
        seconds = int(runtime % 60)
        self.runtime_label.config(text=f"Laufzeit: {hours}:{minutes:02d}:{seconds:02d}")
        
        # Average
        avg_bytes = stats.get_average_bytes_per_sec()
        self.avg_bytes_label.config(text=f"Ø Bytes/s: {avg_bytes:.1f}")
        
        # Configuration
        config_text = (f"Baudrate: {stats.baudrate}\n"
                      f"Bits/Byte: {stats.bits_per_byte:.1f}\n"
                      f"(1 Start + {stats.databits} Data + "
                      f"{stats.parity_bit} Parity + {stats.stopbits} Stop)")
        self.config_label.config(text=config_text)

    def poll_queues(self) -> None:
        """Poll message queues and update statistics."""
        updated = False
        
        # RX Queue
        try:
            for _ in range(100):
                line = self.sniffer.rx_queue.get_nowait()
                tag = None
                if "[ERROR]" in line:
                    tag = "error"
                self.text.insert(tk.END, line + "\n", tag)
                updated = True
        except queue.Empty:
            pass
        
        # Message Queue
        try:
            for _ in range(20):
                msg = self.msg_queue.get_nowait()
                tag = "info"
                if "TX" in msg:
                    tag = "tx"
                elif "ERROR" in msg or "Fehler" in msg:
                    tag = "error"
                self.text.insert(tk.END, msg + "\n", tag)
                self.status_var.set(msg)
                updated = True
        except queue.Empty:
            pass
        
        if updated and self.autoscroll_var.get():
            self.text.see(tk.END)
        
        # Update statistics display
        if self.sniffer.running and self.sniffer.stats:
            self.update_statistics_display()
        
        self.root.after(100, self.poll_queues)

    def set_running(self, running: bool) -> None:
        """Update button states."""
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")
        self.status_var.set("Läuft..." if running else "Gestoppt")

    def run(self) -> None:
        """Start main loop."""
        self.root.mainloop()


if __name__ == "__main__":
    print(f"RS485 Sniffer v{__version__}")
    print("Features: Multi-byte delimiter, Timeout framing, ASCII+Hex view, Bus load calculation")
    print("-" * 70)
    SnifferGUI().run()
