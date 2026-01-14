"""
RFLink Protocol Plugin for RS485 Sniffer v1.6.1
================================================

Decodes RFLink gateway protocol messages.

Author: RS485 Sniffer Team
Version: 1.1.0
"""

import re
import tkinter as tk
from tkinter import ttk, scrolledtext
from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict
from datetime import datetime

__version__ = "1.1.0"


# =============================================================================
# PLUGIN DATA CLASSES (standalone - no external imports needed)
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
# RFLINK PLUGIN
# =============================================================================

class RFLinkPlugin:
    """
    RFLink Protocol Plugin.
    
    Decodes messages from RFLink RF gateway.
    Format: 20;XX;Protocol;ID=xxxx;FIELD=value;...
    """
    
    def __init__(self):
        self._gui = None
        self._sniffer = None
        self._devices: Dict[str, Dict] = {}
        self._message_count = 0
        self._tab = None
        self._tree = None
        self._log_text = None
    
    @property
    def info(self) -> PluginInfo:
        """Return plugin info."""
        return PluginInfo(
            name="RFLink",
            version=__version__,
            author="RS485 Sniffer Team",
            description="RFLink RF Gateway protocol decoder"
        )
    
    def on_load(self, gui, sniffer) -> bool:
        """Called when plugin is loaded."""
        self._gui = gui
        self._sniffer = sniffer
        self._log(f"RFLink Plugin v{__version__} loaded")
        return True
    
    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        self._devices.clear()
        self._log("RFLink Plugin unloaded")
    
    def on_frame_received(self, timestamp: str, data: bytes, 
                          formatted: str) -> Optional[DecodedFrame]:
        """Process received frame."""
        try:
            # Try to decode as ASCII
            text = data.decode('ascii', errors='ignore').strip()
            
            # Check for RFLink format: 20;XX;...
            if not text.startswith('20;'):
                return None
            
            return self._decode_rflink(text, data)
            
        except Exception as e:
            return DecodedFrame(valid=False, error=str(e))
    
    def _decode_rflink(self, text: str, raw: bytes) -> DecodedFrame:
        """Decode RFLink message."""
        parts = text.split(';')
        
        if len(parts) < 3:
            return DecodedFrame(valid=False, error="Invalid RFLink format")
        
        # Parse header
        # 20;XX;Protocol;ID=xxxx;...
        seq_num = parts[1] if len(parts) > 1 else "?"
        protocol = parts[2] if len(parts) > 2 else "Unknown"
        
        fields = [
            FrameField("Sequence", seq_num),
            FrameField("Protocol", protocol),
        ]
        
        # Parse key=value pairs
        device_id = None
        for part in parts[3:]:
            if '=' in part:
                key, value = part.split('=', 1)
                
                # Special handling for common fields
                if key == "ID":
                    device_id = value
                    fields.append(FrameField("Device ID", value))
                elif key == "TEMP":
                    # Temperature in 0.1°C
                    try:
                        temp = int(value, 16) / 10.0
                        fields.append(FrameField("Temperature", f"{temp:.1f}", "°C"))
                    except:
                        fields.append(FrameField("Temperature", value))
                elif key == "HUM":
                    fields.append(FrameField("Humidity", value, "%"))
                elif key == "BARO":
                    fields.append(FrameField("Barometer", value, "hPa"))
                elif key == "CMD":
                    fields.append(FrameField("Command", value))
                elif key == "SWITCH":
                    fields.append(FrameField("Switch", value))
                else:
                    fields.append(FrameField(key, value))
        
        # Update device registry
        if device_id:
            self._update_device(protocol, device_id, fields)
        
        self._message_count += 1
        
        # Build summary
        summary = f"RFLink [{protocol}]"
        if device_id:
            summary += f" ID:{device_id}"
        
        # Log to plugin tab
        self._log_message(text, fields)
        
        return DecodedFrame(
            valid=True,
            protocol="RFLink",
            frame_type=protocol,
            fields=fields,
            raw_data=raw,
            summary=summary
        )
    
    def _update_device(self, protocol: str, device_id: str, fields: List[FrameField]) -> None:
        """Update device in registry."""
        key = f"{protocol}_{device_id}"
        
        self._devices[key] = {
            'protocol': protocol,
            'id': device_id,
            'last_seen': datetime.now().strftime("%H:%M:%S"),
            'fields': {f.name: f.value for f in fields}
        }
        
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
        for key, device in self._devices.items():
            values = (
                device['protocol'],
                device['id'],
                device['last_seen'],
                str(device.get('fields', {}))[:50]
            )
            self._tree.insert("", tk.END, values=values)
    
    def _log_message(self, raw: str, fields: List[FrameField]) -> None:
        """Log message to plugin tab."""
        if not self._log_text:
            return
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self._log_text.configure(state=tk.NORMAL)
        self._log_text.insert(tk.END, f"[{timestamp}] {raw}\n", "raw")
        
        # Add decoded fields
        for f in fields:
            if f.unit:
                self._log_text.insert(tk.END, f"  {f.name}: {f.value} {f.unit}\n", "field")
            else:
                self._log_text.insert(tk.END, f"  {f.name}: {f.value}\n", "field")
        
        self._log_text.insert(tk.END, "\n")
        self._log_text.see(tk.END)
        self._log_text.configure(state=tk.DISABLED)
    
    def _log(self, message: str) -> None:
        """Log to main application."""
        import logging
        logging.info(f"[RFLink] {message}")
    
    def create_tab(self, notebook) -> Optional[ttk.Frame]:
        """Create plugin tab."""
        self._tab = ttk.Frame(notebook, padding=10)
        
        # Header
        header = ttk.Frame(self._tab)
        header.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header, text="RFLink Protocol Decoder", 
                  font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        
        ttk.Label(header, text=f"v{__version__}", 
                  font=("Segoe UI", 9)).pack(side=tk.RIGHT)
        
        # Paned window
        paned = ttk.PanedWindow(self._tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left: Device list
        left_frame = ttk.LabelFrame(paned, text="Discovered Devices", padding=5)
        paned.add(left_frame, weight=1)
        
        columns = ("protocol", "id", "last_seen", "data")
        self._tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=8)
        
        self._tree.heading("protocol", text="Protocol")
        self._tree.heading("id", text="Device ID")
        self._tree.heading("last_seen", text="Last Seen")
        self._tree.heading("data", text="Data")
        
        self._tree.column("protocol", width=100)
        self._tree.column("id", width=80)
        self._tree.column("last_seen", width=80)
        self._tree.column("data", width=150)
        
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
        self._log_text.tag_configure("raw", foreground="#4ec9b0")
        self._log_text.tag_configure("field", foreground="#9cdcfe")
        
        # Stats frame
        stats_frame = ttk.Frame(self._tab)
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        self._stats_label = ttk.Label(stats_frame, text="Messages: 0 | Devices: 0")
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
__all__ = ['RFLinkPlugin']
