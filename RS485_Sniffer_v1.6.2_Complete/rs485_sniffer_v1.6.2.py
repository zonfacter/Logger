#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RS485 Sniffer v1.6.0
====================

A professional RS485/Serial bus analyzer with plugin support.

New in v1.6.0:
- Integrated Statistics Panel (Frames, Bytes, Errors, Uptime)
- Enhanced Send Panel with HEX/ASCII mode, Preview, Start/End Byte config
- Log Export with format selection (.txt, .csv, .log)
- Start/End Byte configuration in Settings (optional)
- Improved UI layout

Author: RS485 Sniffer Team
License: MIT
Python: 3.7+ (Windows 7 compatible with Python 3.9)
"""

__version__ = "1.6.2"
__author__ = "RS485 Sniffer Team"

# =============================================================================
# CHANGELOG
# =============================================================================
__changelog__ = """
v1.6.2 (2025-01-14):
    - Added: Newline display mode options (dots/symbols/escape/hidden)
    - Added: Settings UI for ASCII display options with live preview
    - Added: Display mode lock (newline options disabled in HEX mode)
    - Added: TAB character handling in ASCII display
    - Improved: CR+LF combined handling for cleaner display

v1.6.1 (2025-01-14):
    - Added: Plugin Manager UI tab (enable/disable/version info)
    - Added: Telegram length display in terminal (e.g., "RX (128B):")
    - Fixed: Plugin loading - improved class detection
    - Fixed: Plugin path handling for imports
    - Added: Open Plugins Folder button
    - Added: Refresh Plugins button

v1.6.0 (2025-01-14):
    - Added: Integrated Statistics Panel (RX/TX frames, bytes, errors, uptime)
    - Added: Enhanced Send Panel with live preview
    - Added: Log Export with format selection (.txt, .csv, .log)
    - Added: Start/End Byte configuration in Settings
    - Added: Statistics reset button
    - Improved: Send Panel UI with Mode selector and framing options
    - Improved: Status bar shows live statistics

v1.5.2 (2025-01-13):
    - Fixed: HEX input parsing with parse_hex_input()
    - Fixed: Frame building with build_frame_bytes()
    - Fixed: UTF-8 encoding issues on Windows 7

v1.5.1 (2025-01-12):
    - Fixed: Plugin loading with proper imports
    - Added: Plugin API v1.2

v1.5.0 (2025-01-11):
    - Added: Plugin system with HausBus and RFLink support
    - Added: Device registry for discovered devices
"""

# =============================================================================
# IMPORTS
# =============================================================================

import sys
import os
import time
import threading
import queue
import logging
import json
import re
import csv
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Callable
from pathlib import Path
from abc import ABC, abstractmethod

# Tkinter imports
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

# Serial import
try:
    import serial
    import serial.tools.list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False
    print("[WARNING] pyserial not installed. Install with: pip install pyserial")


# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logging(log_file: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
    """Setup application logging."""
    logger = logging.getLogger("RS485Sniffer")
    logger.setLevel(level)
    
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class SerialConfig:
    """Serial port configuration."""
    port: str = ""
    baudrate: int = 9600
    bytesize: int = 8
    parity: str = "N"
    stopbits: float = 1.0
    timeout: float = 0.1
    
    # Framing options
    start_byte: int = 0x02  # STX
    end_byte: int = 0x03    # ETX
    use_framing: bool = False  # Whether to add start/end bytes to outgoing
    
    # Display options
    display_mode: str = "hex"  # hex, ascii, both
    timestamp_format: str = "%H:%M:%S.%f"
    
    # Auto-scroll
    auto_scroll: bool = True
    
    # Buffer size
    max_buffer_size: int = 10000


@dataclass
class Statistics:
    """Communication statistics."""
    rx_frames: int = 0
    tx_frames: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    def reset(self):
        """Reset all statistics."""
        self.rx_frames = 0
        self.tx_frames = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.errors = 0
        self.start_time = time.time()
    
    @property
    def uptime(self) -> str:
        """Get formatted uptime string."""
        elapsed = time.time() - self.start_time
        return str(timedelta(seconds=int(elapsed)))
    
    @property
    def total_frames(self) -> int:
        return self.rx_frames + self.tx_frames
    
    @property
    def total_bytes(self) -> int:
        return self.rx_bytes + self.tx_bytes


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def parse_hex_input(input_string: str) -> Tuple[bool, bytes, str]:
    """
    Parse hex input string to bytes.
    
    Supports formats:
    - "48 65 6C 6C 6F" (space separated)
    - "48656C6C6F" (continuous)
    - "0x48 0x65" (with 0x prefix)
    - "48,65,6C" (comma separated)
    
    Returns: (success, bytes_data, error_message)
    """
    if not input_string:
        return False, b'', "Empty input"
    
    # Remove common prefixes and separators
    cleaned = input_string.strip()
    cleaned = cleaned.replace('0x', '').replace('0X', '')
    cleaned = cleaned.replace(',', ' ').replace(';', ' ')
    cleaned = cleaned.replace('-', ' ').replace(':', ' ')
    
    # Split by whitespace or process as continuous hex
    if ' ' in cleaned:
        parts = cleaned.split()
    else:
        # Split into pairs
        parts = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]
    
    try:
        result = bytes([int(p, 16) for p in parts if p])
        return True, result, ""
    except ValueError as e:
        return False, b'', f"Invalid hex: {e}"


def build_frame_bytes(data: str, start_byte: int = None, 
                      end_byte: int = None, use_framing: bool = False) -> bytes:
    """
    Build frame bytes from ASCII string with optional framing.
    
    Args:
        data: ASCII string to convert
        start_byte: Optional start byte (e.g., 0x02 STX)
        end_byte: Optional end byte (e.g., 0x03 ETX)
        use_framing: Whether to add start/end bytes
    
    Returns: bytes object
    """
    # Convert ASCII to bytes (safe for Windows 7)
    try:
        payload = data.encode('ascii', errors='replace')
    except Exception:
        payload = bytes([ord(c) if ord(c) < 128 else ord('?') for c in data])
    
    if use_framing:
        result = bytearray()
        if start_byte is not None:
            result.append(start_byte & 0xFF)
        result.extend(payload)
        if end_byte is not None:
            result.append(end_byte & 0xFF)
        return bytes(result)
    
    return payload


def format_bytes_hex(data: bytes, separator: str = " ") -> str:
    """Format bytes as hex string."""
    return separator.join(f"{b:02X}" for b in data)


def format_bytes_ascii(data: bytes, newline_mode: str = "dots") -> str:
    """
    Format bytes as ASCII string with configurable newline handling.
    
    Args:
        data: Bytes to format
        newline_mode: How to display CR/LF characters
            - "dots": Replace with dots (default)
            - "symbols": Use Unicode symbols (↵ for CRLF, ␍ ␊ for single)
            - "escape": Show as \r\n
            - "hidden": Don't show CR/LF at all
    
    Returns:
        Formatted ASCII string
    """
    result = []
    i = 0
    while i < len(data):
        b = data[i]
        
        if 32 <= b < 127:
            # Printable ASCII
            result.append(chr(b))
        elif b == 0x0D:  # CR (Carriage Return)
            if newline_mode == "dots":
                result.append('.')
            elif newline_mode == "symbols":
                # Check if followed by LF for combined symbol
                if i + 1 < len(data) and data[i + 1] == 0x0A:
                    result.append('↵')
                    i += 1  # Skip the LF
                else:
                    result.append('␍')
            elif newline_mode == "escape":
                if i + 1 < len(data) and data[i + 1] == 0x0A:
                    result.append('\\r\\n')
                    i += 1  # Skip the LF
                else:
                    result.append('\\r')
            elif newline_mode == "hidden":
                pass  # Don't add anything
        elif b == 0x0A:  # LF (Line Feed) - standalone
            if newline_mode == "dots":
                result.append('.')
            elif newline_mode == "symbols":
                result.append('␊')
            elif newline_mode == "escape":
                result.append('\\n')
            elif newline_mode == "hidden":
                pass
        elif b == 0x09:  # TAB
            if newline_mode == "dots":
                result.append('.')
            elif newline_mode == "symbols":
                result.append('→')
            elif newline_mode == "escape":
                result.append('\\t')
            elif newline_mode == "hidden":
                result.append(' ')  # Replace with space
        else:
            # Other non-printable
            result.append('.')
        
        i += 1
    
    return ''.join(result)


def format_timestamp(fmt: str = "%H:%M:%S.%f") -> str:
    """Get formatted timestamp."""
    now = datetime.now()
    result = now.strftime(fmt)
    # Truncate microseconds to 3 digits
    if '.%f' in fmt:
        result = result[:-3]
    return result


# =============================================================================
# SERIAL SNIFFER CORE
# =============================================================================

class SerialSniffer:
    """
    Core serial sniffer class.
    
    Handles serial port communication in a separate thread.
    """
    
    def __init__(self, config: SerialConfig):
        self.config = config
        self.serial: Optional[serial.Serial] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.rx_queue: queue.Queue = queue.Queue()
        self.tx_queue: queue.Queue = queue.Queue()
        self.stats = Statistics()
        self._lock = threading.Lock()
    
    def connect(self) -> Tuple[bool, str]:
        """Connect to serial port."""
        if not SERIAL_AVAILABLE:
            return False, "pyserial not installed"
        
        try:
            self.serial = serial.Serial(
                port=self.config.port,
                baudrate=self.config.baudrate,
                bytesize=self.config.bytesize,
                parity=self.config.parity,
                stopbits=self.config.stopbits,
                timeout=self.config.timeout
            )
            self.stats.reset()
            logger.info(f"Connected to {self.config.port} @ {self.config.baudrate}")
            return True, f"Connected to {self.config.port}"
        except serial.SerialException as e:
            logger.error(f"Connection failed: {e}")
            return False, str(e)
    
    def disconnect(self) -> None:
        """Disconnect from serial port."""
        self.stop()
        if self.serial and self.serial.is_open:
            self.serial.close()
            logger.info("Disconnected")
        self.serial = None
    
    def start(self) -> bool:
        """Start reading thread."""
        if not self.serial or not self.serial.is_open:
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
        logger.info("Sniffer started")
        return True
    
    def stop(self) -> None:
        """Stop reading thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        logger.info("Sniffer stopped")
    
    def _read_loop(self) -> None:
        """Main reading loop (runs in thread)."""
        buffer = bytearray()
        
        while self.running and self.serial and self.serial.is_open:
            try:
                # Check for data to send
                while not self.tx_queue.empty():
                    try:
                        data = self.tx_queue.get_nowait()
                        self._send_data(data)
                    except queue.Empty:
                        break
                
                # Read available data
                if self.serial.in_waiting > 0:
                    data = self.serial.read(self.serial.in_waiting)
                    if data:
                        timestamp = format_timestamp(self.config.timestamp_format)
                        with self._lock:
                            self.stats.rx_bytes += len(data)
                            self.stats.rx_frames += 1
                        self.rx_queue.put((timestamp, data, "RX"))
                else:
                    time.sleep(0.01)  # Prevent busy loop
                    
            except serial.SerialException as e:
                logger.error(f"Serial error: {e}")
                with self._lock:
                    self.stats.errors += 1
                self.rx_queue.put((format_timestamp(), str(e).encode(), "ERROR"))
                break
            except Exception as e:
                logger.error(f"Read error: {e}")
                with self._lock:
                    self.stats.errors += 1
    
    def _send_data(self, data: bytes) -> bool:
        """Send data to serial port."""
        if not self.serial or not self.serial.is_open:
            return False
        
        try:
            self.serial.write(data)
            self.serial.flush()
            timestamp = format_timestamp(self.config.timestamp_format)
            with self._lock:
                self.stats.tx_bytes += len(data)
                self.stats.tx_frames += 1
            self.rx_queue.put((timestamp, data, "TX"))
            return True
        except serial.SerialException as e:
            logger.error(f"Send error: {e}")
            with self._lock:
                self.stats.errors += 1
            return False
    
    def send(self, data: bytes) -> None:
        """Queue data for sending."""
        self.tx_queue.put(data)
    
    def get_stats(self) -> Statistics:
        """Get current statistics (thread-safe copy)."""
        with self._lock:
            return Statistics(
                rx_frames=self.stats.rx_frames,
                tx_frames=self.stats.tx_frames,
                rx_bytes=self.stats.rx_bytes,
                tx_bytes=self.stats.tx_bytes,
                errors=self.stats.errors,
                start_time=self.stats.start_time
            )
    
    def reset_stats(self) -> None:
        """Reset statistics."""
        with self._lock:
            self.stats.reset()


# =============================================================================
# PLUGIN API (Embedded for standalone use)
# =============================================================================

@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    version: str
    author: str = ""
    description: str = ""


@dataclass
class FrameField:
    """Decoded frame field."""
    name: str
    value: Any
    unit: str = ""
    description: str = ""


@dataclass
class DecodedFrame:
    """Decoded frame result."""
    valid: bool
    protocol: str = ""
    frame_type: str = ""
    fields: List[FrameField] = field(default_factory=list)
    raw_data: bytes = b''
    summary: str = ""
    error: str = ""


class PluginBase(ABC):
    """Base class for plugins."""
    
    def __init__(self):
        self._gui = None
        self._sniffer = None
    
    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """Return plugin info."""
        pass
    
    def on_load(self, gui, sniffer) -> bool:
        """Called when plugin is loaded."""
        self._gui = gui
        self._sniffer = sniffer
        return True
    
    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        pass
    
    def on_frame_received(self, timestamp: str, data: bytes, 
                          formatted: str) -> Optional[DecodedFrame]:
        """Process received frame."""
        return None
    
    def create_tab(self, notebook) -> Optional[ttk.Frame]:
        """Create plugin tab."""
        return None
    
    def log(self, message: str) -> None:
        """Log message."""
        logger.info(f"[{self.info.name}] {message}")


class PluginManager:
    """Manages plugin loading and lifecycle."""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, PluginBase] = {}
    
    def discover_plugins(self) -> List[str]:
        """Discover available plugins."""
        found = []
        plugin_path = Path(self.plugin_dir)
        
        if not plugin_path.exists():
            plugin_path.mkdir(parents=True, exist_ok=True)
            return found
        
        for item in plugin_path.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                found.append(item.name)
        
        return found
    
    def load_plugin(self, name: str) -> Optional[PluginBase]:
        """Load a plugin by name."""
        try:
            # Add plugin dir to path
            plugin_path = str(Path(self.plugin_dir).absolute())
            if plugin_path not in sys.path:
                sys.path.insert(0, plugin_path)
            
            # Also add parent dir for plugin_api imports
            parent_path = str(Path(".").absolute())
            if parent_path not in sys.path:
                sys.path.insert(0, parent_path)
            
            # Import plugin module
            import importlib
            
            # Try to reload if already imported
            if name in sys.modules:
                del sys.modules[name]
            
            module = importlib.import_module(name)
            
            # Find plugin class - check for 'info' property and required methods
            for attr_name in dir(module):
                if attr_name.startswith('_'):
                    continue
                    
                attr = getattr(module, attr_name)
                
                # Check if it's a class
                if not isinstance(attr, type):
                    continue
                
                # Check if it has the required plugin interface
                if hasattr(attr, 'info') and hasattr(attr, 'on_load'):
                    try:
                        # Try to instantiate
                        plugin = attr()
                        
                        # Verify it has info property
                        if hasattr(plugin, 'info') and hasattr(plugin.info, 'name'):
                            self.plugins[name] = plugin
                            logger.info(f"[PluginManager] Loaded: {plugin.info.name} v{plugin.info.version}")
                            return plugin
                    except Exception as inst_err:
                        logger.debug(f"[PluginManager] Could not instantiate {attr_name}: {inst_err}")
                        continue
            
            logger.warning(f"[PluginManager] No valid plugin class found in {name}")
            return None
            
        except ImportError as e:
            logger.error(f"[PluginManager] Import error for {name}: {e}")
            return None
        except Exception as e:
            logger.error(f"[PluginManager] Error loading {name}: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
    
    def load_all(self) -> int:
        """Load all discovered plugins."""
        count = 0
        for name in self.discover_plugins():
            if self.load_plugin(name):
                count += 1
        return count
    
    def unload_all(self) -> None:
        """Unload all plugins."""
        for plugin in self.plugins.values():
            try:
                plugin.on_unload()
            except Exception as e:
                logger.error(f"Error unloading plugin: {e}")
        self.plugins.clear()
    
    def get_all(self) -> List[PluginBase]:
        """Get all loaded plugins."""
        return list(self.plugins.values())


# =============================================================================
# MAIN GUI APPLICATION
# =============================================================================

class RS485SnifferGUI:
    """
    Main GUI application for RS485 Sniffer.
    
    Features:
    - Serial port configuration and connection
    - Real-time data display (HEX/ASCII)
    - Send panel with HEX/ASCII mode and framing
    - Statistics panel
    - Log export (.txt, .csv, .log)
    - Plugin support
    """
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"RS485 Sniffer v{__version__}")
        self.root.geometry("1200x800")
        self.root.minsize(900, 600)
        
        # Configuration
        self.config = SerialConfig()
        self.sniffer: Optional[SerialSniffer] = None
        self.running = False
        
        # Statistics
        self.stats = Statistics()
        
        # Message queue for thread-safe GUI updates
        self.msg_queue: queue.Queue = queue.Queue()
        
        # Terminal buffer for export
        self.terminal_buffer: List[Dict[str, Any]] = []
        
        # Plugin manager
        self.plugin_manager = PluginManager()
        
        # Variables
        self._init_variables()
        
        # Build GUI
        self._build_gui()
        
        # Load plugins
        self._load_plugins()
        
        # Start update loop
        self._update_loop()
        
        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _init_variables(self) -> None:
        """Initialize tkinter variables."""
        # Connection
        self.port_var = tk.StringVar()
        self.baudrate_var = tk.StringVar(value="9600")
        self.bytesize_var = tk.StringVar(value="8")
        self.parity_var = tk.StringVar(value="N")
        self.stopbits_var = tk.StringVar(value="1")
        
        # Display
        self.display_mode_var = tk.StringVar(value="hex")
        self.auto_scroll_var = tk.BooleanVar(value=True)
        self.newline_mode_var = tk.StringVar(value="dots")  # dots, symbols, escape, hidden
        
        # Send
        self.send_var = tk.StringVar()
        self.send_mode_var = tk.StringVar(value="hex")
        self.use_framing_var = tk.BooleanVar(value=False)
        self.start_byte_var = tk.StringVar(value="02")
        self.end_byte_var = tk.StringVar(value="03")
        
        # Status
        self.status_var = tk.StringVar(value="Disconnected")
    
    def _build_gui(self) -> None:
        """Build the main GUI."""
        # Main container
        main_frame = ttk.Frame(self.root, padding=5)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top: Connection and Settings
        self._build_connection_frame(main_frame)
        
        # Middle: Main content (Terminal + Panels)
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Left: Terminal
        self._build_terminal_frame(content_frame)
        
        # Right: Side panels (Statistics, Send)
        self._build_side_panels(content_frame)
        
        # Bottom: Status bar
        self._build_status_bar(main_frame)
        
        # Notebook for plugins
        self._build_plugin_notebook(main_frame)
    
    def _build_connection_frame(self, parent: ttk.Frame) -> None:
        """Build connection settings frame."""
        frame = ttk.LabelFrame(parent, text="Connection", padding=5)
        frame.pack(fill=tk.X, pady=(0, 5))
        
        # Row 1: Port and Baudrate
        row1 = ttk.Frame(frame)
        row1.pack(fill=tk.X, pady=2)
        
        # Port
        ttk.Label(row1, text="Port:").pack(side=tk.LEFT, padx=(0, 5))
        self.port_combo = ttk.Combobox(row1, textvariable=self.port_var, width=15)
        self.port_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(row1, text="↻", width=3, 
                   command=self._refresh_ports).pack(side=tk.LEFT, padx=(0, 15))
        
        # Baudrate
        ttk.Label(row1, text="Baudrate:").pack(side=tk.LEFT, padx=(0, 5))
        baud_combo = ttk.Combobox(row1, textvariable=self.baudrate_var, width=10,
                                   values=["300", "1200", "2400", "4800", "9600", 
                                          "19200", "38400", "57600", "115200", "230400"])
        baud_combo.pack(side=tk.LEFT, padx=(0, 15))
        
        # Data bits
        ttk.Label(row1, text="Data:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Combobox(row1, textvariable=self.bytesize_var, width=5,
                     values=["5", "6", "7", "8"]).pack(side=tk.LEFT, padx=(0, 15))
        
        # Parity
        ttk.Label(row1, text="Parity:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Combobox(row1, textvariable=self.parity_var, width=5,
                     values=["N", "E", "O", "M", "S"]).pack(side=tk.LEFT, padx=(0, 15))
        
        # Stop bits
        ttk.Label(row1, text="Stop:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Combobox(row1, textvariable=self.stopbits_var, width=5,
                     values=["1", "1.5", "2"]).pack(side=tk.LEFT, padx=(0, 15))
        
        # Connect/Disconnect buttons
        self.connect_btn = ttk.Button(row1, text="Connect", 
                                       command=self._toggle_connection)
        self.connect_btn.pack(side=tk.RIGHT, padx=5)
        
        # Settings button
        ttk.Button(row1, text="⚙ Settings", 
                   command=self._show_settings).pack(side=tk.RIGHT, padx=5)
        
        # Refresh ports on start
        self._refresh_ports()
    
    def _build_terminal_frame(self, parent: ttk.Frame) -> None:
        """Build terminal display frame."""
        frame = ttk.LabelFrame(parent, text="Terminal", padding=5)
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Toolbar
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # Display mode
        ttk.Label(toolbar, text="Display:").pack(side=tk.LEFT, padx=(0, 5))
        mode_combo = ttk.Combobox(toolbar, textvariable=self.display_mode_var,
                                   values=["hex", "ascii", "both"], width=8, state="readonly")
        mode_combo.pack(side=tk.LEFT, padx=(0, 15))
        
        # Auto-scroll
        ttk.Checkbutton(toolbar, text="Auto-scroll", 
                        variable=self.auto_scroll_var).pack(side=tk.LEFT, padx=(0, 15))
        
        # Clear button
        ttk.Button(toolbar, text="Clear", 
                   command=self._clear_terminal).pack(side=tk.LEFT, padx=(0, 5))
        
        # Export button
        ttk.Button(toolbar, text="💾 Export Log", 
                   command=self._export_log).pack(side=tk.LEFT, padx=(0, 5))
        
        # Terminal text widget
        self.terminal = scrolledtext.ScrolledText(
            frame, 
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="#ffffff"
        )
        self.terminal.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for colors
        self.terminal.tag_configure("rx", foreground="#4ec9b0")      # Cyan for RX
        self.terminal.tag_configure("tx", foreground="#dcdcaa")      # Yellow for TX
        self.terminal.tag_configure("error", foreground="#f14c4c")   # Red for errors
        self.terminal.tag_configure("info", foreground="#569cd6")    # Blue for info
        self.terminal.tag_configure("timestamp", foreground="#808080")  # Gray for timestamp
    
    def _build_side_panels(self, parent: ttk.Frame) -> None:
        """Build side panels (Statistics + Send)."""
        side_frame = ttk.Frame(parent, width=350)
        side_frame.pack(side=tk.RIGHT, fill=tk.Y)
        side_frame.pack_propagate(False)
        
        # Statistics Panel
        self._build_statistics_panel(side_frame)
        
        # Send Panel
        self._build_send_panel(side_frame)
    
    def _build_statistics_panel(self, parent: ttk.Frame) -> None:
        """Build statistics panel."""
        frame = ttk.LabelFrame(parent, text="📊 Statistics", padding=10)
        frame.pack(fill=tk.X, pady=(0, 5))
        
        # Grid layout for stats
        stats_grid = ttk.Frame(frame)
        stats_grid.pack(fill=tk.X)
        
        # RX Stats
        ttk.Label(stats_grid, text="RX Frames:", 
                  font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", pady=2)
        self.rx_frames_label = ttk.Label(stats_grid, text="0", 
                                          font=("Consolas", 10, "bold"))
        self.rx_frames_label.grid(row=0, column=1, sticky="e", padx=(10, 20), pady=2)
        
        ttk.Label(stats_grid, text="RX Bytes:", 
                  font=("Segoe UI", 9)).grid(row=0, column=2, sticky="w", pady=2)
        self.rx_bytes_label = ttk.Label(stats_grid, text="0", 
                                         font=("Consolas", 10, "bold"))
        self.rx_bytes_label.grid(row=0, column=3, sticky="e", pady=2)
        
        # TX Stats
        ttk.Label(stats_grid, text="TX Frames:", 
                  font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", pady=2)
        self.tx_frames_label = ttk.Label(stats_grid, text="0", 
                                          font=("Consolas", 10, "bold"))
        self.tx_frames_label.grid(row=1, column=1, sticky="e", padx=(10, 20), pady=2)
        
        ttk.Label(stats_grid, text="TX Bytes:", 
                  font=("Segoe UI", 9)).grid(row=1, column=2, sticky="w", pady=2)
        self.tx_bytes_label = ttk.Label(stats_grid, text="0", 
                                         font=("Consolas", 10, "bold"))
        self.tx_bytes_label.grid(row=1, column=3, sticky="e", pady=2)
        
        # Errors and Uptime
        ttk.Label(stats_grid, text="Errors:", 
                  font=("Segoe UI", 9)).grid(row=2, column=0, sticky="w", pady=2)
        self.errors_label = ttk.Label(stats_grid, text="0", 
                                       font=("Consolas", 10, "bold"), foreground="red")
        self.errors_label.grid(row=2, column=1, sticky="e", padx=(10, 20), pady=2)
        
        ttk.Label(stats_grid, text="Uptime:", 
                  font=("Segoe UI", 9)).grid(row=2, column=2, sticky="w", pady=2)
        self.uptime_label = ttk.Label(stats_grid, text="0:00:00", 
                                       font=("Consolas", 10, "bold"))
        self.uptime_label.grid(row=2, column=3, sticky="e", pady=2)
        
        # Reset button
        ttk.Button(frame, text="Reset Statistics", 
                   command=self._reset_statistics).pack(pady=(10, 0))

    
    def _build_send_panel(self, parent: ttk.Frame) -> None:
        """Build enhanced send panel with preview."""
        frame = ttk.LabelFrame(parent, text="📤 Send Data", padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Mode selection
        mode_frame = ttk.Frame(frame)
        mode_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Label(mode_frame, text="Mode:").pack(side=tk.LEFT, padx=(0, 5))
        mode_combo = ttk.Combobox(mode_frame, textvariable=self.send_mode_var,
                                   values=["hex", "ascii"], width=8, state="readonly")
        mode_combo.pack(side=tk.LEFT, padx=(0, 10))
        mode_combo.bind("<<ComboboxSelected>>", lambda e: self._update_send_preview())
        
        # Framing checkbox
        ttk.Checkbutton(mode_frame, text="Add Framing", 
                        variable=self.use_framing_var,
                        command=self._update_send_preview).pack(side=tk.LEFT, padx=(10, 0))
        
        # Start/End byte configuration
        framing_frame = ttk.Frame(frame)
        framing_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(framing_frame, text="Start Byte (hex):").pack(side=tk.LEFT, padx=(0, 5))
        start_entry = ttk.Entry(framing_frame, textvariable=self.start_byte_var, width=5)
        start_entry.pack(side=tk.LEFT, padx=(0, 15))
        start_entry.bind("<KeyRelease>", lambda e: self._update_send_preview())
        
        ttk.Label(framing_frame, text="End Byte (hex):").pack(side=tk.LEFT, padx=(0, 5))
        end_entry = ttk.Entry(framing_frame, textvariable=self.end_byte_var, width=5)
        end_entry.pack(side=tk.LEFT)
        end_entry.bind("<KeyRelease>", lambda e: self._update_send_preview())
        
        # Data input
        ttk.Label(frame, text="Data:").pack(anchor="w", pady=(5, 2))
        
        self.send_entry = ttk.Entry(frame, textvariable=self.send_var, font=("Consolas", 10))
        self.send_entry.pack(fill=tk.X, pady=(0, 5))
        self.send_entry.bind("<Return>", lambda e: self._send_data())
        self.send_entry.bind("<KeyRelease>", lambda e: self._update_send_preview())
        
        # Preview
        preview_frame = ttk.LabelFrame(frame, text="Preview (HEX)", padding=5)
        preview_frame.pack(fill=tk.X, pady=5)
        
        self.preview_label = ttk.Label(preview_frame, text="", 
                                        font=("Consolas", 9), foreground="#569cd6")
        self.preview_label.pack(fill=tk.X)
        
        # Send buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Send", 
                   command=self._send_data).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Send + Clear", 
                   command=self._send_and_clear).pack(side=tk.LEFT, padx=(0, 5))
        
        # Quick send buttons
        quick_frame = ttk.LabelFrame(frame, text="Quick Send", padding=5)
        quick_frame.pack(fill=tk.X, pady=(10, 0))
        
        quick_btns = ttk.Frame(quick_frame)
        quick_btns.pack(fill=tk.X)
        
        # Common control characters
        quick_commands = [
            ("ACK", "06"),
            ("NAK", "15"),
            ("ENQ", "05"),
            ("EOT", "04"),
            ("STX", "02"),
            ("ETX", "03"),
        ]
        
        for name, hex_val in quick_commands:
            ttk.Button(quick_btns, text=name, width=5,
                       command=lambda h=hex_val: self._quick_send(h)).pack(side=tk.LEFT, padx=2)
    
    def _build_status_bar(self, parent: ttk.Frame) -> None:
        """Build status bar."""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Connection status
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                       font=("Segoe UI", 9))
        self.status_label.pack(side=tk.LEFT)
        
        # Separator
        ttk.Separator(status_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        # Quick stats in status bar
        self.statusbar_stats = ttk.Label(status_frame, 
                                          text="RX: 0 | TX: 0 | Errors: 0",
                                          font=("Consolas", 9))
        self.statusbar_stats.pack(side=tk.LEFT)
        
        # Version
        ttk.Label(status_frame, text=f"v{__version__}", 
                  font=("Segoe UI", 8)).pack(side=tk.RIGHT)
    
    def _build_plugin_notebook(self, parent: ttk.Frame) -> None:
        """Build plugin notebook with Plugin Manager tab."""
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=False, pady=(5, 0))
        
        # Add Plugin Manager tab first
        self._build_plugin_manager_tab()
    
    def _build_plugin_manager_tab(self) -> None:
        """Build Plugin Manager tab."""
        frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(frame, text="🔌 Plugin Manager")
        
        # Header
        header = ttk.Frame(frame)
        header.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header, text="Plugin Manager", 
                  font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)
        
        ttk.Button(header, text="↻ Refresh", 
                   command=self._refresh_plugins).pack(side=tk.RIGHT, padx=5)
        ttk.Button(header, text="📁 Open Plugins Folder", 
                   command=self._open_plugins_folder).pack(side=tk.RIGHT, padx=5)
        
        # Plugin list with Treeview
        columns = ("name", "version", "author", "status", "description")
        self.plugin_tree = ttk.Treeview(frame, columns=columns, show="headings", height=6)
        
        # Column headers
        self.plugin_tree.heading("name", text="Plugin Name")
        self.plugin_tree.heading("version", text="Version")
        self.plugin_tree.heading("author", text="Author")
        self.plugin_tree.heading("status", text="Status")
        self.plugin_tree.heading("description", text="Description")
        
        # Column widths
        self.plugin_tree.column("name", width=150)
        self.plugin_tree.column("version", width=80)
        self.plugin_tree.column("author", width=100)
        self.plugin_tree.column("status", width=80)
        self.plugin_tree.column("description", width=300)
        
        self.plugin_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.plugin_tree.yview)
        self.plugin_tree.configure(yscrollcommand=scrollbar.set)
        
        # Button frame
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        
        self.enable_btn = ttk.Button(btn_frame, text="✓ Enable", 
                                      command=self._enable_plugin, state=tk.DISABLED)
        self.enable_btn.pack(side=tk.LEFT, padx=5)
        
        self.disable_btn = ttk.Button(btn_frame, text="✗ Disable", 
                                       command=self._disable_plugin, state=tk.DISABLED)
        self.disable_btn.pack(side=tk.LEFT, padx=5)
        
        # Bind selection
        self.plugin_tree.bind("<<TreeviewSelect>>", self._on_plugin_select)
        
        # Plugin status tracking
        self.plugin_status: Dict[str, bool] = {}
        
        # Populate list
        self._populate_plugin_list()
    
    def _populate_plugin_list(self) -> None:
        """Populate plugin list."""
        # Clear existing
        for item in self.plugin_tree.get_children():
            self.plugin_tree.delete(item)
        
        # Add discovered plugins
        discovered = self.plugin_manager.discover_plugins()
        
        for name in discovered:
            plugin = self.plugin_manager.plugins.get(name)
            
            if plugin:
                # Loaded plugin
                info = plugin.info
                status = "✓ Loaded"
                self.plugin_status[name] = True
                self.plugin_tree.insert("", tk.END, iid=name, values=(
                    info.name, info.version, info.author, status, info.description
                ))
            else:
                # Discovered but not loaded
                status = "○ Available"
                self.plugin_status[name] = False
                self.plugin_tree.insert("", tk.END, iid=name, values=(
                    name, "?", "?", status, "(Not loaded)"
                ))
    
    def _on_plugin_select(self, event) -> None:
        """Handle plugin selection."""
        selection = self.plugin_tree.selection()
        if selection:
            name = selection[0]
            is_loaded = self.plugin_status.get(name, False)
            
            self.enable_btn.configure(state=tk.NORMAL if not is_loaded else tk.DISABLED)
            self.disable_btn.configure(state=tk.NORMAL if is_loaded else tk.DISABLED)
        else:
            self.enable_btn.configure(state=tk.DISABLED)
            self.disable_btn.configure(state=tk.DISABLED)
    
    def _enable_plugin(self) -> None:
        """Enable selected plugin."""
        selection = self.plugin_tree.selection()
        if not selection:
            return
        
        name = selection[0]
        plugin = self.plugin_manager.load_plugin(name)
        
        if plugin:
            try:
                plugin.on_load(self, self.sniffer)
                tab = plugin.create_tab(self.notebook)
                if tab:
                    self.notebook.add(tab, text=plugin.info.name)
                
                self._log_message(f"Plugin enabled: {plugin.info.name}", "info")
                self._populate_plugin_list()
            except Exception as e:
                self._log_message(f"Plugin error: {e}", "error")
        else:
            self._log_message(f"Failed to load plugin: {name}", "error")
    
    def _disable_plugin(self) -> None:
        """Disable selected plugin."""
        selection = self.plugin_tree.selection()
        if not selection:
            return
        
        name = selection[0]
        plugin = self.plugin_manager.plugins.get(name)
        
        if plugin:
            try:
                plugin.on_unload()
                del self.plugin_manager.plugins[name]
                
                # Remove tab (find by name)
                for tab_id in self.notebook.tabs():
                    if self.notebook.tab(tab_id, "text") == plugin.info.name:
                        self.notebook.forget(tab_id)
                        break
                
                self._log_message(f"Plugin disabled: {plugin.info.name}", "info")
                self._populate_plugin_list()
            except Exception as e:
                self._log_message(f"Plugin error: {e}", "error")
    
    def _refresh_plugins(self) -> None:
        """Refresh plugin list."""
        self._populate_plugin_list()
        self._log_message("Plugin list refreshed", "info")
    
    def _open_plugins_folder(self) -> None:
        """Open plugins folder in file explorer."""
        import subprocess
        import platform
        
        plugins_path = Path("plugins").absolute()
        plugins_path.mkdir(exist_ok=True)
        
        try:
            if platform.system() == "Windows":
                os.startfile(str(plugins_path))
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(plugins_path)])
            else:
                subprocess.run(["xdg-open", str(plugins_path)])
        except Exception as e:
            self._log_message(f"Could not open folder: {e}", "error")
    
    def _load_plugins(self) -> None:
        """Initialize plugin system and auto-load enabled plugins."""
        # Discover available plugins
        discovered = self.plugin_manager.discover_plugins()
        logger.info(f"[PluginManager] Discovered {len(discovered)} plugins: {discovered}")
        
        # Auto-load all discovered plugins
        for name in discovered:
            plugin = self.plugin_manager.load_plugin(name)
            if plugin:
                try:
                    plugin.on_load(self, self.sniffer)
                    tab = plugin.create_tab(self.notebook)
                    if tab:
                        self.notebook.add(tab, text=plugin.info.name)
                    logger.info(f"[PluginManager] Initialized: {plugin.info.name}")
                except Exception as e:
                    logger.error(f"[PluginManager] Error initializing {name}: {e}")
        
        # Update plugin list in manager
        if hasattr(self, 'plugin_tree'):
            self._populate_plugin_list()
    
    # =========================================================================
    # SETTINGS DIALOG
    # =========================================================================
    
    def _show_settings(self) -> None:
        """Show settings dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Framing tab
        framing_frame = ttk.Frame(notebook, padding=10)
        notebook.add(framing_frame, text="Framing")
        
        ttk.Label(framing_frame, text="Frame Framing Configuration",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Use framing checkbox
        ttk.Checkbutton(framing_frame, text="Add Start/End bytes to outgoing frames",
                        variable=self.use_framing_var).pack(anchor="w", pady=5)
        
        # Start byte
        start_frame = ttk.Frame(framing_frame)
        start_frame.pack(fill=tk.X, pady=5)
        ttk.Label(start_frame, text="Start Byte (hex):", width=20).pack(side=tk.LEFT)
        ttk.Entry(start_frame, textvariable=self.start_byte_var, width=10).pack(side=tk.LEFT)
        ttk.Label(start_frame, text="(e.g., 02 = STX)").pack(side=tk.LEFT, padx=10)
        
        # End byte
        end_frame = ttk.Frame(framing_frame)
        end_frame.pack(fill=tk.X, pady=5)
        ttk.Label(end_frame, text="End Byte (hex):", width=20).pack(side=tk.LEFT)
        ttk.Entry(end_frame, textvariable=self.end_byte_var, width=10).pack(side=tk.LEFT)
        ttk.Label(end_frame, text="(e.g., 03 = ETX)").pack(side=tk.LEFT, padx=10)
        
        # Common presets
        preset_frame = ttk.LabelFrame(framing_frame, text="Presets", padding=5)
        preset_frame.pack(fill=tk.X, pady=10)
        
        presets = [
            ("STX/ETX", "02", "03"),
            ("SOH/EOT", "01", "04"),
            ("None", "", ""),
        ]
        
        for name, start, end in presets:
            ttk.Button(preset_frame, text=name, width=10,
                       command=lambda s=start, e=end: self._apply_framing_preset(s, e)
                       ).pack(side=tk.LEFT, padx=5)
        
        # Display tab
        display_frame = ttk.Frame(notebook, padding=10)
        notebook.add(display_frame, text="Display")
        
        ttk.Label(display_frame, text="Display Settings",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Display mode
        mode_frame = ttk.Frame(display_frame)
        mode_frame.pack(fill=tk.X, pady=5)
        ttk.Label(mode_frame, text="Display Mode:", width=20).pack(side=tk.LEFT)
        self._display_mode_combo = ttk.Combobox(mode_frame, textvariable=self.display_mode_var,
                     values=["hex", "ascii", "both"], width=10, 
                     state="readonly")
        self._display_mode_combo.pack(side=tk.LEFT)
        self._display_mode_combo.bind("<<ComboboxSelected>>", 
                                       lambda e: self._update_newline_options_state())
        
        # Auto-scroll
        ttk.Checkbutton(display_frame, text="Auto-scroll terminal",
                        variable=self.auto_scroll_var).pack(anchor="w", pady=5)
        
        # Separator
        ttk.Separator(display_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # === ASCII Display Options ===
        ttk.Label(display_frame, text="ASCII Display Options",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Newline Mode
        newline_frame = ttk.Frame(display_frame)
        newline_frame.pack(fill=tk.X, pady=5)
        ttk.Label(newline_frame, text="Newline Display:", width=20).pack(side=tk.LEFT)
        self._newline_mode_combo = ttk.Combobox(newline_frame, 
                                                 textvariable=self.newline_mode_var,
                                                 values=["dots", "symbols", "escape", "hidden"],
                                                 width=10, state="readonly")
        self._newline_mode_combo.pack(side=tk.LEFT)
        self._newline_mode_combo.bind("<<ComboboxSelected>>", 
                                       lambda e: self._update_newline_preview())
        
        # Description label
        self._newline_desc_var = tk.StringVar()
        ttk.Label(display_frame, textvariable=self._newline_desc_var,
                  font=("Segoe UI", 8), foreground="gray").pack(anchor="w", pady=(0, 5))
        
        # Lock info label
        self._newline_lock_label = ttk.Label(display_frame, text="",
                                              font=("Segoe UI", 8), foreground="orange")
        self._newline_lock_label.pack(anchor="w")
        
        # Preview frame
        preview_frame = ttk.LabelFrame(display_frame, text="Preview (CR LF = 0D 0A)", padding=5)
        preview_frame.pack(fill=tk.X, pady=10)
        
        self._newline_preview_var = tk.StringVar()
        ttk.Label(preview_frame, textvariable=self._newline_preview_var,
                  font=("Consolas", 10)).pack(anchor=tk.W)
        
        # Initialize preview and state
        self._update_newline_preview()
        self._update_newline_options_state()
        
        # Close button
        ttk.Button(dialog, text="Close", 
                   command=dialog.destroy).pack(pady=10)
    
    def _apply_framing_preset(self, start: str, end: str) -> None:
        """Apply framing preset."""
        self.start_byte_var.set(start)
        self.end_byte_var.set(end)
        self._update_send_preview()
    
    def _update_newline_preview(self) -> None:
        """Update newline mode preview and description."""
        mode = self.newline_mode_var.get()
        
        # Update description
        descriptions = {
            "dots": "CR/LF shown as dots (..) - compact view",
            "symbols": "CR/LF shown as ↵ or ␍␊ - visual indicators",
            "escape": "CR/LF shown as \\r\\n - escape sequences",
            "hidden": "CR/LF not shown - clean text only",
        }
        
        # Update preview
        previews = {
            "dots": "Hello..World",
            "symbols": "Hello↵World",
            "escape": "Hello\\r\\nWorld",
            "hidden": "HelloWorld",
        }
        
        if hasattr(self, '_newline_desc_var'):
            self._newline_desc_var.set(descriptions.get(mode, ""))
        if hasattr(self, '_newline_preview_var'):
            self._newline_preview_var.set(previews.get(mode, "Hello..World"))
    
    def _update_newline_options_state(self) -> None:
        """Update newline options availability based on display mode."""
        display_mode = self.display_mode_var.get()
        
        if hasattr(self, '_newline_mode_combo') and hasattr(self, '_newline_lock_label'):
            if display_mode == "hex":
                # Disable newline options for HEX-only mode
                self._newline_mode_combo.configure(state="disabled")
                self._newline_lock_label.configure(
                    text="⚠️ Newline options disabled in HEX-only mode"
                )
            else:
                # Enable newline options for ASCII or Both mode
                self._newline_mode_combo.configure(state="readonly")
                self._newline_lock_label.configure(text="")
        
        self._update_newline_preview()

    
    # =========================================================================
    # CONNECTION METHODS
    # =========================================================================
    
    def _refresh_ports(self) -> None:
        """Refresh available serial ports."""
        if not SERIAL_AVAILABLE:
            self.port_combo['values'] = ["pyserial not installed"]
            return
        
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo['values'] = ports
        
        if ports and not self.port_var.get():
            self.port_var.set(ports[0])
    
    def _toggle_connection(self) -> None:
        """Toggle connection state."""
        if self.running:
            self._disconnect()
        else:
            self._connect()
    
    def _connect(self) -> None:
        """Connect to serial port."""
        if not SERIAL_AVAILABLE:
            messagebox.showerror("Error", "pyserial not installed")
            return
        
        # Update config from UI
        self.config.port = self.port_var.get()
        self.config.baudrate = int(self.baudrate_var.get())
        self.config.bytesize = int(self.bytesize_var.get())
        self.config.parity = self.parity_var.get()
        self.config.stopbits = float(self.stopbits_var.get())
        
        # Create sniffer
        self.sniffer = SerialSniffer(self.config)
        
        # Connect
        success, msg = self.sniffer.connect()
        if not success:
            messagebox.showerror("Connection Error", msg)
            self.sniffer = None
            return
        
        # Start
        if self.sniffer.start():
            self.running = True
            self.connect_btn.configure(text="Disconnect")
            self.status_var.set(f"Connected: {self.config.port} @ {self.config.baudrate}")
            self._log_message(f"Connected to {self.config.port}", "info")
            
            # Update plugins
            for plugin in self.plugin_manager.get_all():
                plugin._sniffer = self.sniffer
    
    def _disconnect(self) -> None:
        """Disconnect from serial port."""
        if self.sniffer:
            self.sniffer.disconnect()
            self.sniffer = None
        
        self.running = False
        self.connect_btn.configure(text="Connect")
        self.status_var.set("Disconnected")
        self._log_message("Disconnected", "info")
    
    # =========================================================================
    # SEND METHODS
    # =========================================================================
    
    def _update_send_preview(self) -> None:
        """Update send preview."""
        input_text = self.send_var.get().strip()
        mode = self.send_mode_var.get()
        use_framing = self.use_framing_var.get()
        
        if not input_text:
            self.preview_label.configure(text="(empty)")
            return
        
        try:
            # Parse start/end bytes
            start_byte = None
            end_byte = None
            
            if use_framing:
                start_str = self.start_byte_var.get().strip()
                end_str = self.end_byte_var.get().strip()
                
                if start_str:
                    start_byte = int(start_str, 16)
                if end_str:
                    end_byte = int(end_str, 16)
            
            # Build preview bytes
            if mode == "hex":
                success, data, error = parse_hex_input(input_text)
                if not success:
                    self.preview_label.configure(text=f"Error: {error}")
                    return
                
                # Add framing if enabled
                if use_framing:
                    result = bytearray()
                    if start_byte is not None:
                        result.append(start_byte)
                    result.extend(data)
                    if end_byte is not None:
                        result.append(end_byte)
                    data = bytes(result)
            else:
                # ASCII mode
                data = build_frame_bytes(input_text, start_byte, end_byte, use_framing)
            
            # Format preview
            preview = format_bytes_hex(data)
            self.preview_label.configure(text=preview)
            
        except Exception as e:
            self.preview_label.configure(text=f"Error: {e}")
    
    def _send_data(self) -> None:
        """Send data from input field."""
        if not self.sniffer or not self.running:
            self._log_message("Not connected", "error")
            return
        
        input_text = self.send_var.get().strip()
        if not input_text:
            return
        
        mode = self.send_mode_var.get()
        use_framing = self.use_framing_var.get()
        
        try:
            # Parse start/end bytes
            start_byte = None
            end_byte = None
            
            if use_framing:
                start_str = self.start_byte_var.get().strip()
                end_str = self.end_byte_var.get().strip()
                
                if start_str:
                    start_byte = int(start_str, 16)
                if end_str:
                    end_byte = int(end_str, 16)
            
            # Build data bytes
            if mode == "hex":
                success, data, error = parse_hex_input(input_text)
                if not success:
                    self._log_message(f"HEX parse error: {error}", "error")
                    return
                
                # Add framing if enabled
                if use_framing:
                    result = bytearray()
                    if start_byte is not None:
                        result.append(start_byte)
                    result.extend(data)
                    if end_byte is not None:
                        result.append(end_byte)
                    data = bytes(result)
            else:
                # ASCII mode
                data = build_frame_bytes(input_text, start_byte, end_byte, use_framing)
            
            # Send
            self.sniffer.send(data)
            
        except Exception as e:
            self._log_message(f"Send error: {e}", "error")
    
    def _send_and_clear(self) -> None:
        """Send data and clear input."""
        self._send_data()
        self.send_var.set("")
        self._update_send_preview()
    
    def _quick_send(self, hex_value: str) -> None:
        """Quick send a hex value."""
        if not self.sniffer or not self.running:
            self._log_message("Not connected", "error")
            return
        
        try:
            data = bytes([int(hex_value, 16)])
            self.sniffer.send(data)
        except Exception as e:
            self._log_message(f"Quick send error: {e}", "error")
    
    def send_bytes(self, data: bytes) -> None:
        """Send raw bytes (for plugins)."""
        if self.sniffer and self.running:
            self.sniffer.send(data)
    
    # =========================================================================
    # LOG EXPORT
    # =========================================================================
    
    def _export_log(self) -> None:
        """Export terminal log to file."""
        if not self.terminal_buffer:
            messagebox.showinfo("Export", "No data to export")
            return
        
        # Ask for format
        format_dialog = tk.Toplevel(self.root)
        format_dialog.title("Export Format")
        format_dialog.geometry("300x150")
        format_dialog.transient(self.root)
        format_dialog.grab_set()
        
        ttk.Label(format_dialog, text="Select export format:",
                  font=("Segoe UI", 10)).pack(pady=10)
        
        format_var = tk.StringVar(value="txt")
        
        formats = [
            ("Text File (.txt)", "txt"),
            ("CSV File (.csv)", "csv"),
            ("Log File (.log)", "log"),
        ]
        
        for text, value in formats:
            ttk.Radiobutton(format_dialog, text=text, value=value,
                           variable=format_var).pack(anchor="w", padx=20)
        
        def do_export():
            format_dialog.destroy()
            self._do_export(format_var.get())
        
        ttk.Button(format_dialog, text="Export", 
                   command=do_export).pack(pady=10)
    
    def _do_export(self, format_type: str) -> None:
        """Perform the actual export."""
        # File dialog
        filetypes = {
            "txt": [("Text Files", "*.txt")],
            "csv": [("CSV Files", "*.csv")],
            "log": [("Log Files", "*.log")],
        }
        
        default_name = f"rs485_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format_type}"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=filetypes.get(format_type, [("All Files", "*.*")]),
            initialfile=default_name
        )
        
        if not filename:
            return
        
        try:
            if format_type == "csv":
                self._export_csv(filename)
            else:
                self._export_text(filename, format_type)
            
            messagebox.showinfo("Export", f"Log exported to:\n{filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
    
    def _export_text(self, filename: str, format_type: str) -> None:
        """Export as text or log file."""
        with open(filename, 'w', encoding='utf-8') as f:
            # Header
            f.write(f"RS485 Sniffer Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'=' * 60}\n\n")
            
            for entry in self.terminal_buffer:
                timestamp = entry.get('timestamp', '')
                direction = entry.get('direction', '')
                data_hex = entry.get('data_hex', '')
                data_ascii = entry.get('data_ascii', '')
                
                if format_type == "log":
                    f.write(f"[{timestamp}] [{direction}] {data_hex}\n")
                else:
                    f.write(f"{timestamp} {direction}: {data_hex}  |  {data_ascii}\n")
    
    def _export_csv(self, filename: str) -> None:
        """Export as CSV file."""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Timestamp', 'Direction', 'Data (HEX)', 'Data (ASCII)', 'Bytes'])
            
            for entry in self.terminal_buffer:
                writer.writerow([
                    entry.get('timestamp', ''),
                    entry.get('direction', ''),
                    entry.get('data_hex', ''),
                    entry.get('data_ascii', ''),
                    entry.get('byte_count', 0)
                ])

    
    # =========================================================================
    # UPDATE LOOP & TERMINAL
    # =========================================================================
    
    def _update_loop(self) -> None:
        """Main update loop for GUI."""
        # Process messages from queue
        self._process_messages()
        
        # Update statistics
        self._update_statistics()
        
        # Process sniffer data
        if self.sniffer and self.running:
            self._process_sniffer_data()
        
        # Schedule next update
        self.root.after(50, self._update_loop)
    
    def _process_messages(self) -> None:
        """Process messages from internal queue."""
        while not self.msg_queue.empty():
            try:
                msg, tag = self.msg_queue.get_nowait()
                self._append_terminal(msg, tag)
            except queue.Empty:
                break
    
    def _process_sniffer_data(self) -> None:
        """Process data from sniffer."""
        while not self.sniffer.rx_queue.empty():
            try:
                timestamp, data, direction = self.sniffer.rx_queue.get_nowait()
                self._display_data(timestamp, data, direction)
            except queue.Empty:
                break
    
    def _display_data(self, timestamp: str, data: bytes, direction: str) -> None:
        """Display received/sent data in terminal."""
        # Format data
        data_hex = format_bytes_hex(data)
        data_ascii = format_bytes_ascii(data, self.newline_mode_var.get())
        
        # Store in buffer for export
        self.terminal_buffer.append({
            'timestamp': timestamp,
            'direction': direction,
            'data_hex': data_hex,
            'data_ascii': data_ascii,
            'byte_count': len(data),
            'raw': data
        })
        
        # Limit buffer size
        if len(self.terminal_buffer) > self.config.max_buffer_size:
            self.terminal_buffer = self.terminal_buffer[-self.config.max_buffer_size:]
        
        # Format for display
        display_mode = self.display_mode_var.get()
        
        if display_mode == "hex":
            display_data = data_hex
        elif display_mode == "ascii":
            display_data = data_ascii
        else:  # both
            display_data = f"{data_hex}  |  {data_ascii}"
        
        # Determine tag
        if direction == "RX":
            tag = "rx"
        elif direction == "TX":
            tag = "tx"
        else:
            tag = "error"
        
        # Build line with length
        byte_count = len(data)
        line = f"[{timestamp}] {direction} ({byte_count:3d}B): {display_data}\n"
        
        # Append to terminal
        self._append_terminal(line, tag)
        
        # Notify plugins
        for plugin in self.plugin_manager.get_all():
            try:
                result = plugin.on_frame_received(timestamp, data, display_data)
                if result and result.valid:
                    # Display decoded info
                    self._append_terminal(f"  └─ {result.summary}\n", "info")
            except Exception as e:
                logger.error(f"Plugin error: {e}")
    
    def _append_terminal(self, text: str, tag: str = None) -> None:
        """Append text to terminal."""
        self.terminal.configure(state=tk.NORMAL)
        
        if tag:
            self.terminal.insert(tk.END, text, tag)
        else:
            self.terminal.insert(tk.END, text)
        
        # Auto-scroll
        if self.auto_scroll_var.get():
            self.terminal.see(tk.END)
        
        self.terminal.configure(state=tk.DISABLED)
    
    def _log_message(self, message: str, tag: str = "info") -> None:
        """Log a message to terminal."""
        timestamp = format_timestamp()
        self.msg_queue.put((f"[{timestamp}] {message}\n", tag))
    
    def _clear_terminal(self) -> None:
        """Clear terminal."""
        self.terminal.configure(state=tk.NORMAL)
        self.terminal.delete(1.0, tk.END)
        self.terminal.configure(state=tk.DISABLED)
        self.terminal_buffer.clear()
    
    # =========================================================================
    # STATISTICS
    # =========================================================================
    
    def _update_statistics(self) -> None:
        """Update statistics display."""
        if self.sniffer and self.running:
            stats = self.sniffer.get_stats()
            
            # Update labels
            self.rx_frames_label.configure(text=str(stats.rx_frames))
            self.rx_bytes_label.configure(text=str(stats.rx_bytes))
            self.tx_frames_label.configure(text=str(stats.tx_frames))
            self.tx_bytes_label.configure(text=str(stats.tx_bytes))
            self.errors_label.configure(text=str(stats.errors))
            self.uptime_label.configure(text=stats.uptime)
            
            # Update status bar
            self.statusbar_stats.configure(
                text=f"RX: {stats.rx_frames} ({stats.rx_bytes}B) | "
                     f"TX: {stats.tx_frames} ({stats.tx_bytes}B) | "
                     f"Errors: {stats.errors}"
            )
    
    def _reset_statistics(self) -> None:
        """Reset statistics."""
        if self.sniffer:
            self.sniffer.reset_stats()
        
        # Reset labels
        self.rx_frames_label.configure(text="0")
        self.rx_bytes_label.configure(text="0")
        self.tx_frames_label.configure(text="0")
        self.tx_bytes_label.configure(text="0")
        self.errors_label.configure(text="0")
        self.uptime_label.configure(text="0:00:00")
        
        self._log_message("Statistics reset", "info")
    
    # =========================================================================
    # CLEANUP
    # =========================================================================
    
    def _on_close(self) -> None:
        """Handle window close."""
        if self.running:
            self._disconnect()
        
        # Unload plugins
        self.plugin_manager.unload_all()
        
        self.root.destroy()
    
    # =========================================================================
    # PUBLIC API (for plugins)
    # =========================================================================
    
    def queue_msg(self, message: str, tag: str = "info") -> None:
        """Queue a message for display (thread-safe)."""
        self._log_message(message, tag)
    
    def get_config(self) -> SerialConfig:
        """Get current configuration."""
        return self.config


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    # Check for pyserial
    if not SERIAL_AVAILABLE:
        print("WARNING: pyserial not installed!")
        print("Install with: pip install pyserial")
    
    # Create main window
    root = tk.Tk()
    
    # Set theme
    try:
        root.tk.call("source", "azure.tcl")
        root.tk.call("set_theme", "dark")
    except Exception:
        pass  # Theme not available
    
    # Create application
    app = RS485SnifferGUI(root)
    
    # Run
    root.mainloop()


if __name__ == "__main__":
    main()
