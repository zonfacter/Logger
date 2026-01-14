"""
HausBus Protocol Plugin for RS485 Sniffer v1.6.1
=================================================

Decodes HausBus home automation protocol messages.

Author: RS485 Sniffer Team
Version: 1.1.0
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict
from datetime import datetime

__version__ = "1.1.0"


# =============================================================================
# PLUGIN DATA CLASSES (standalone)
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


# =============================================================================
# HAUSBUS PROTOCOL DEFINITIONS
# =============================================================================

# Message types
MSG_TYPES = {
    0x00: "Discovery",
    0x01: "Ping",
    0x02: "Pong",
    0x10: "Get Status",
    0x11: "Status Response",
    0x20: "Set Output",
    0x21: "Output Confirm",
    0x30: "Get Config",
    0x31: "Config Response",
    0x40: "Set Config",
    0x41: "Config Confirm",
    0xF0: "Error",
    0xFF: "Broadcast",
}

# Device types
DEVICE_TYPES = {
    0x01: "Switch Module",
    0x02: "Dimmer Module",
    0x03: "Shutter Module",
    0x04: "Sensor Module",
    0x05: "Input Module",
    0x10: "Gateway",
    0x20: "Display",
}


# =============================================================================
# HAUSBUS PLUGIN
# =============================================================================

class HausBusPlugin:
    """
    HausBus Protocol Plugin.
    
    Decodes HausBus home automation protocol.
    Frame format: STX LEN DST SRC TYPE DATA... CRC ETX
    """
    
    STX = 0x02
    ETX = 0x03
    
    def __init__(self):
        self._gui = None
        self._sniffer = None
        self._devices: Dict[int, Dict] = {}
        self._message_count = 0
        self._error_count = 0
        self._tab = None
        self._tree = None
        self._log_text = None
    
    @property
    def info(self) -> PluginInfo:
        """Return plugin info."""
        return PluginInfo(
            name="HausBus",
            version=__version__,
            author="RS485 Sniffer Team",
            description="HausBus home automation protocol decoder"
        )
    
    def on_load(self, gui, sniffer) -> bool:
        """Called when plugin is loaded."""
        self._gui = gui
        self._sniffer = sniffer
        self._log(f"HausBus Plugin v{__version__} loaded")
        return True
    
    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        self._devices.clear()
        self._log("HausBus Plugin unloaded")
    
    def on_frame_received(self, timestamp: str, data: bytes, 
                          formatted: str) -> Optional[DecodedFrame]:
        """Process received frame."""
        if len(data) < 6:
            return None
        
        # Check for HausBus frame (STX ... ETX)
        if data[0] != self.STX or data[-1] != self.ETX:
            return None
        
        return self._decode_hausbus(data)
    
    def _decode_hausbus(self, data: bytes) -> DecodedFrame:
        """Decode HausBus frame."""
        try:
            # Frame: STX LEN DST SRC TYPE DATA... CRC ETX
            if len(data) < 6:
                return DecodedFrame(valid=False, error="Frame too short")
            
            length = data[1]
            dst_addr = data[2]
            src_addr = data[3]
            msg_type = data[4]
            payload = data[5:-2] if len(data) > 6 else b''
            crc = data[-2]
            
            # Verify CRC (simple XOR)
            calc_crc = 0
            for b in data[1:-2]:
                calc_crc ^= b
            
            crc_valid = (calc_crc == crc)
            
            # Get message type name
            msg_name = MSG_TYPES.get(msg_type, f"Unknown (0x{msg_type:02X})")
            
            fields = [
                FrameField("Length", length),
                FrameField("Destination", f"0x{dst_addr:02X}"),
                FrameField("Source", f"0x{src_addr:02X}"),
                FrameField("Type", msg_name),
                FrameField("CRC", "OK" if crc_valid else "FAIL"),
            ]
            
            # Decode payload based on message type
            if msg_type == 0x11 and len(payload) >= 2:  # Status Response
                device_type = payload[0]
                status = payload[1]
                fields.append(FrameField("Device Type", 
                              DEVICE_TYPES.get(device_type, f"0x{device_type:02X}")))
                fields.append(FrameField("Status", f"0x{status:02X}"))
            
            elif msg_type == 0x20 and len(payload) >= 2:  # Set Output
                channel = payload[0]
                value = payload[1]
                fields.append(FrameField("Channel", channel))
                fields.append(FrameField("Value", f"{value} ({value*100//255}%)"))
            
            # Update device registry
            self._update_device(src_addr, msg_type, fields)
            
            self._message_count += 1
            if not crc_valid:
                self._error_count += 1
            
            # Build summary
            summary = f"HausBus [{msg_name}] {src_addr:02X}→{dst_addr:02X}"
            
            # Log to plugin tab
            self._log_message(data, fields, crc_valid)
            
            return DecodedFrame(
                valid=True,
                protocol="HausBus",
                frame_type=msg_name,
                fields=fields,
                raw_data=data,
                summary=summary
            )
            
        except Exception as e:
            return DecodedFrame(valid=False, error=str(e))
    
    def _update_device(self, addr: int, msg_type: int, fields: List[FrameField]) -> None:
        """Update device in registry."""
        if addr not in self._devices:
            self._devices[addr] = {
                'address': f"0x{addr:02X}",
                'type': "Unknown",
                'last_seen': "",
                'messages': 0
            }
        
        self._devices[addr]['last_seen'] = datetime.now().strftime("%H:%M:%S")
        self._devices[addr]['messages'] += 1
        
        # Update tree if available
        if self._tree:
            self._update_tree()
    
    def _update_tree(self) -> None:
        """Update device tree view."""
        if not self._tree:
            return
        
        # Clear existing
        for item in self._tree.get_children():
            self._tree.delete(item)
        
        # Add devices
        for addr, device in self._devices.items():
            values = (
                device['address'],
                device['type'],
                device['last_seen'],
                device['messages']
            )
            self._tree.insert("", tk.END, values=values)
    
    def _log_message(self, data: bytes, fields: List[FrameField], crc_ok: bool) -> None:
        """Log message to plugin tab."""
        if not self._log_text:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        hex_str = ' '.join(f"{b:02X}" for b in data)
        
        self._log_text.configure(state=tk.NORMAL)
        
        tag = "valid" if crc_ok else "error"
        self._log_text.insert(tk.END, f"[{timestamp}] {hex_str}\n", tag)
        
        # Add decoded fields
        for f in fields:
            self._log_text.insert(tk.END, f"  {f.name}: {f.value}\n", "field")
        
        self._log_text.insert(tk.END, "\n")
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)
        
        # Update stats
        if hasattr(self, '_stats_label') and self._stats_label:
            self._stats_label.configure(
                text=f"Messages: {self._message_count} | Devices: {len(self._devices)} | Errors: {self._error_count}"
            )
    
    def _log(self, message: str) -> None:
        """Log to main application."""
        import logging
        logging.info(f"[HausBus] {message}")
    
    def create_tab(self, notebook) -> Optional[ttk.Frame]:
        """Create plugin tab."""
        self._tab = ttk.Frame(notebook, padding=10)
        
        # Header
        header = ttk.Frame(self._tab)
        header.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header, text="HausBus Protocol Decoder", 
                  font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        
        ttk.Label(header, text=f"v{__version__}", 
                  font=("Segoe UI", 9)).pack(side=tk.RIGHT)
        
        # Paned window
        paned = ttk.PanedWindow(self._tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left: Device list
        left_frame = ttk.LabelFrame(paned, text="Discovered Devices", padding=5)
        paned.add(left_frame, weight=1)
        
        columns = ("address", "type", "last_seen", "messages")
        self._tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=8)
        
        self._tree.heading("address", text="Address")
        self._tree.heading("type", text="Type")
        self._tree.heading("last_seen", text="Last Seen")
        self._tree.heading("messages", text="Messages")
        
        self._tree.column("address", width=80)
        self._tree.column("type", width=100)
        self._tree.column("last_seen", width=80)
        self._tree.column("messages", width=70)
        
        self._tree.pack(fill=tk.BOTH, expand=True)
        
        # Right: Message log
        right_frame = ttk.LabelFrame(paned, text="Message Log", padding=5)
        paned.add(right_frame, weight=2)
        
        self._log_text = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            height=10
        )
        self._log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags
        self._log_text.tag_configure("valid", foreground="#4ec9b0")
        self._log_text.tag_configure("error", foreground="#f14c4c")
        self._log_text.tag_configure("field", foreground="#9cdcfe")
        
        # Stats frame
        stats_frame = ttk.Frame(self._tab)
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        self._stats_label = ttk.Label(stats_frame, 
                                       text="Messages: 0 | Devices: 0 | Errors: 0")
        self._stats_label.pack(side=tk.LEFT)
        
        ttk.Button(stats_frame, text="Clear", 
                   command=self._clear_log).pack(side=tk.RIGHT)
        
        return self._tab
    
    def _clear_log(self) -> None:
        """Clear message log."""
        if self._log_text:
            self._log_text.configure(state=tk.NORMAL)
            self._log_text.delete(1.0, tk.END)
            self._log_text.configure(state=tk.DISABLED)


# Export for plugin discovery
__all__ = ['HausBusPlugin']
