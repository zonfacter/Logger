"""
RFLink Plugin v1.1.0
RFLink Gateway protocol decoder for RS485 Sniffer.

RFLink is a RF gateway that communicates via serial.
Format: 20;XX;Protocol;ID=XXXX;SWITCH=XX;CMD=ON;

Changelog:
- v1.1.0: Fixed import for plugin_api v1.2 (removed ProtocolDecoder dependency)
- v1.0.0: Initial version
"""

import time
import re
import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugin_api import PluginBase, PluginInfo, DecodedFrame, FrameField


# =============================================================================
# RFLink Protocol Constants
# =============================================================================

RFLINK_PROTOCOLS = {
    'Oregon TempHygro': 'Temperature/Humidity Sensor',
    'Oregon Rain': 'Rain Gauge',
    'Oregon Wind': 'Wind Sensor',
    'Oregon UV': 'UV Sensor',
    'Alecto V1': 'Weather Station',
    'Alecto V3': 'Weather Station',
    'LaCrosse': 'Weather Sensor',
    'DKW2012': 'Weather Station',
    'Cresta': 'Weather Sensor',
    'NewKaku': 'Switch/Dimmer',
    'Kaku': 'Switch',
    'HomeEasy': 'Switch/Dimmer',
    'FA500': 'Smoke Detector',
    'X10': 'X10 Device',
    'Blyss': 'Switch',
    'Conrad': 'Switch',
    'Kambrook': 'Switch',
    'SelectPlus': 'Doorbell',
    'Byron': 'Doorbell',
    'Pir': 'Motion Sensor',
    'Smoke': 'Smoke Detector',
}


# =============================================================================
# RFLink Device Registry
# =============================================================================

@dataclass
class RFLinkDevice:
    """RFLink device information."""
    protocol: str
    device_id: str
    name: str = ""
    last_seen: float = 0.0
    last_data: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def key(self) -> str:
        return f"{self.protocol}_{self.device_id}"
    
    @property
    def protocol_name(self) -> str:
        return RFLINK_PROTOCOLS.get(self.protocol, self.protocol)
    
    def __str__(self) -> str:
        return f"{self.protocol}:{self.device_id}"


class RFLinkRegistry:
    """Registry for discovered RFLink devices."""
    
    def __init__(self):
        self.devices: Dict[str, RFLinkDevice] = {}
    
    def register(self, protocol: str, device_id: str, 
                 data: Dict[str, Any] = None) -> RFLinkDevice:
        key = f"{protocol}_{device_id}"
        
        if key not in self.devices:
            self.devices[key] = RFLinkDevice(
                protocol=protocol,
                device_id=device_id
            )
        
        device = self.devices[key]
        device.last_seen = time.time()
        if data:
            device.last_data.update(data)
        
        return device
    
    def get(self, protocol: str, device_id: str) -> Optional[RFLinkDevice]:
        key = f"{protocol}_{device_id}"
        return self.devices.get(key)
    
    def get_all(self) -> List[RFLinkDevice]:
        return list(self.devices.values())
    
    def clear(self):
        self.devices.clear()


# =============================================================================
# RFLink Decoder
# =============================================================================

class RFLinkDecoder:
    """
    Decoder for RFLink protocol messages.
    
    RFLink format: 20;XX;Protocol;Field=Value;Field=Value;...
    
    Examples:
    - 20;2A;Oregon TempHygro;ID=1A2D;TEMP=00c3;HUM=50;BAT=OK;
    - 20;01;NewKaku;ID=0123abcd;SWITCH=1;CMD=ON;
    """
    
    # Pattern for RFLink messages
    PATTERN = re.compile(r'^20;([0-9A-Fa-f]{2});([^;]+);(.*)$')
    
    def __init__(self, registry: RFLinkRegistry):
        self.registry = registry
        self.sequence = 0
    
    def decode(self, data: bytes) -> Optional[DecodedFrame]:
        """Decode RFLink message from bytes."""
        # Try to decode as ASCII/UTF-8
        try:
            text = data.decode('ascii', errors='replace').strip()
        except Exception:
            return None
        
        return self.decode_text(text)
    
    def decode_text(self, text: str) -> Optional[DecodedFrame]:
        """Decode RFLink message from text."""
        # Remove newlines
        text = text.strip()
        
        # Match RFLink pattern
        match = self.PATTERN.match(text)
        if not match:
            return None
        
        seq_hex = match.group(1)
        protocol = match.group(2)
        fields_str = match.group(3)
        
        # Parse sequence number
        try:
            seq = int(seq_hex, 16)
        except ValueError:
            seq = 0
        
        # Parse fields
        parsed_fields = []
        field_data = {}
        device_id = ""
        
        for part in fields_str.split(';'):
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Convert known fields
                converted_value = self._convert_value(key, value)
                field_data[key] = converted_value
                
                parsed_fields.append(FrameField(
                    name=key,
                    value=converted_value,
                    description=self._get_field_description(key)
                ))
                
                if key == 'ID':
                    device_id = value
        
        # Register device
        if device_id:
            self.registry.register(protocol, device_id, field_data)
        
        # Build summary
        summary = self._build_summary(protocol, device_id, field_data)
        
        return DecodedFrame(
            valid=True,
            protocol="RFLink",
            frame_type=protocol,
            fields=parsed_fields,
            raw_data=text.encode('ascii', errors='replace'),
            summary=summary
        )
    
    def _convert_value(self, key: str, value: str) -> Any:
        """Convert field value to appropriate type."""
        key_upper = key.upper()
        
        # Temperature (hex, divide by 10, can be negative)
        if key_upper == 'TEMP':
            try:
                temp = int(value, 16)
                # Check for negative (high bit set in 12-bit value)
                if temp > 0x7FF:
                    temp = temp - 0x1000
                return temp / 10.0
            except ValueError:
                return value
        
        # Humidity (decimal)
        if key_upper == 'HUM':
            try:
                return int(value)
            except ValueError:
                return value
        
        # Battery status
        if key_upper == 'BAT':
            return value.upper()
        
        # Switch/Button number
        if key_upper in ('SWITCH', 'BUTTON'):
            try:
                return int(value)
            except ValueError:
                return value
        
        # Command
        if key_upper == 'CMD':
            return value.upper()
        
        # Dimmer level
        if key_upper == 'DIMLEVEL':
            try:
                return int(value)
            except ValueError:
                return value
        
        # Rain (hex, mm)
        if key_upper == 'RAIN':
            try:
                return int(value, 16) / 10.0
            except ValueError:
                return value
        
        # Wind speed (hex, km/h)
        if key_upper in ('WINSP', 'WINGS'):
            try:
                return int(value, 16) / 10.0
            except ValueError:
                return value
        
        # Wind direction (degrees)
        if key_upper == 'WINDIR':
            try:
                return int(value)
            except ValueError:
                return value
        
        return value
    
    def _get_field_description(self, key: str) -> str:
        """Get description for field."""
        descriptions = {
            'ID': 'Device ID',
            'TEMP': 'Temperature (°C)',
            'HUM': 'Humidity (%)',
            'BAT': 'Battery Status',
            'SWITCH': 'Switch Number',
            'CMD': 'Command',
            'DIMLEVEL': 'Dim Level (0-15)',
            'RAIN': 'Rain (mm)',
            'WINSP': 'Wind Speed (km/h)',
            'WINGS': 'Wind Gust (km/h)',
            'WINDIR': 'Wind Direction (°)',
            'UV': 'UV Index',
            'BARO': 'Barometric Pressure',
        }
        return descriptions.get(key.upper(), '')
    
    def _build_summary(self, protocol: str, device_id: str, 
                       data: Dict[str, Any]) -> str:
        """Build human-readable summary."""
        parts = [f"[RFLink] {protocol}"]
        
        if device_id:
            parts.append(f"ID:{device_id}")
        
        # Add key values
        if 'TEMP' in data:
            parts.append(f"Temp:{data['TEMP']}°C")
        if 'HUM' in data:
            parts.append(f"Hum:{data['HUM']}%")
        if 'CMD' in data:
            parts.append(f"Cmd:{data['CMD']}")
        if 'SWITCH' in data:
            parts.append(f"Sw:{data['SWITCH']}")
        if 'BAT' in data:
            parts.append(f"Bat:{data['BAT']}")
        
        return ' '.join(parts)
    
    def encode_command(self, protocol: str, device_id: str, 
                       switch: int, cmd: str) -> str:
        """
        Encode command to send to RFLink.
        
        Format: 10;Protocol;ID;Switch;CMD;
        """
        return f"10;{protocol};{device_id};{switch};{cmd};\n"


# =============================================================================
# RFLink Plugin
# =============================================================================

class RFLinkPlugin(PluginBase):
    """
    RFLink Gateway Plugin for RS485 Sniffer.
    
    Decodes RFLink protocol messages and provides device management.
    """
    
    def __init__(self):
        super().__init__()
        self._info = PluginInfo(
            name="RFLink",
            version="1.1.0",
            author="RS485 Sniffer",
            description="RFLink RF Gateway protocol decoder"
        )
        self.registry = RFLinkRegistry()
        self.decoder = RFLinkDecoder(self.registry)
        self.tab = None
        self.device_tree = None
        self.detail_text = None
        self.cmd_protocol = None
        self.cmd_id = None
        self.cmd_switch = None
        self.cmd_action = None
    
    @property
    def info(self) -> PluginInfo:
        return self._info
    
    def on_load(self, gui, sniffer) -> bool:
        self._gui = gui
        self._sniffer = sniffer
        self.log("Plugin loaded")
        return True
    
    def on_unload(self) -> None:
        self.log("Plugin unloaded")
    
    def on_frame_received(self, timestamp: str, data: bytes, 
                          formatted: str) -> Optional[DecodedFrame]:
        """Process received frame."""
        decoded = self.decoder.decode(data)
        if decoded and decoded.valid:
            if self.device_tree:
                self._update_device_tree()
        return decoded
    
    def create_tab(self, notebook) -> Optional[ttk.Frame]:
        """Create plugin tab in notebook."""
        self.tab = ttk.Frame(notebook)
        
        # Main paned window
        paned = ttk.PanedWindow(self.tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left: Device list
        left_frame = ttk.LabelFrame(paned, text="Discovered Devices")
        paned.add(left_frame, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(left_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="Refresh", 
                   command=self._update_device_tree).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Clear", 
                   command=self._clear_devices).pack(side=tk.LEFT, padx=2)
        
        # Device tree
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("id", "last_value", "last_seen")
        self.device_tree = ttk.Treeview(tree_frame, columns=columns, 
                                        show="headings", height=15)
        
        self.device_tree.heading("id", text="Device ID")
        self.device_tree.heading("last_value", text="Last Value")
        self.device_tree.heading("last_seen", text="Last Seen")
        
        self.device_tree.column("id", width=120)
        self.device_tree.column("last_value", width=150)
        self.device_tree.column("last_seen", width=80)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, 
                                  command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_select)
        
        # Right: Details and Control
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)
        
        # Details
        detail_frame = ttk.LabelFrame(right_frame, text="Device Details")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.detail_text = tk.Text(detail_frame, height=10, width=40)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Control panel
        control_frame = ttk.LabelFrame(right_frame, text="Send Command")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Protocol
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(row1, text="Protocol:", width=10).pack(side=tk.LEFT)
        self.cmd_protocol = ttk.Combobox(row1, width=20)
        self.cmd_protocol['values'] = list(RFLINK_PROTOCOLS.keys())
        self.cmd_protocol.pack(side=tk.LEFT, padx=5)
        
        # Device ID
        row2 = ttk.Frame(control_frame)
        row2.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(row2, text="Device ID:", width=10).pack(side=tk.LEFT)
        self.cmd_id = ttk.Entry(row2, width=22)
        self.cmd_id.pack(side=tk.LEFT, padx=5)
        
        # Switch
        row3 = ttk.Frame(control_frame)
        row3.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(row3, text="Switch:", width=10).pack(side=tk.LEFT)
        self.cmd_switch = ttk.Spinbox(row3, from_=1, to=16, width=5)
        self.cmd_switch.pack(side=tk.LEFT, padx=5)
        
        # Action buttons
        row4 = ttk.Frame(control_frame)
        row4.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(row4, text="ON", width=8,
                   command=lambda: self._send_cmd("ON")).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4, text="OFF", width=8,
                   command=lambda: self._send_cmd("OFF")).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4, text="ALLON", width=8,
                   command=lambda: self._send_cmd("ALLON")).pack(side=tk.LEFT, padx=2)
        ttk.Button(row4, text="ALLOFF", width=8,
                   command=lambda: self._send_cmd("ALLOFF")).pack(side=tk.LEFT, padx=2)
        
        return self.tab
    
    def _update_device_tree(self):
        """Update device tree view."""
        if not self.device_tree:
            return
        
        # Clear existing
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Group by protocol
        by_protocol: Dict[str, List[RFLinkDevice]] = {}
        for device in self.registry.get_all():
            if device.protocol not in by_protocol:
                by_protocol[device.protocol] = []
            by_protocol[device.protocol].append(device)
        
        # Add to tree
        for protocol in sorted(by_protocol.keys()):
            # Protocol parent
            parent = self.device_tree.insert(
                "", tk.END,
                values=(protocol, "", ""),
                iid=f"proto_{protocol}",
                open=True
            )
            
            # Devices
            for device in by_protocol[protocol]:
                # Format last value
                last_val = ""
                if 'TEMP' in device.last_data:
                    last_val = f"T:{device.last_data['TEMP']}°C"
                elif 'CMD' in device.last_data:
                    last_val = f"Cmd:{device.last_data['CMD']}"
                
                last_seen = datetime.fromtimestamp(
                    device.last_seen
                ).strftime("%H:%M:%S")
                
                self.device_tree.insert(
                    parent, tk.END,
                    values=(device.device_id, last_val, last_seen),
                    iid=device.key
                )
    
    def _clear_devices(self):
        """Clear device registry."""
        self.registry.clear()
        self._update_device_tree()
        self.log("Device list cleared")
    
    def _on_device_select(self, event):
        """Handle device selection."""
        selection = self.device_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        
        if item_id.startswith("proto_"):
            # Protocol selected
            protocol = item_id.replace("proto_", "")
            self._show_protocol_info(protocol)
        else:
            # Device selected
            self._show_device_details(item_id)
    
    def _show_protocol_info(self, protocol: str):
        """Show protocol information."""
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, f"Protocol: {protocol}\n")
        self.detail_text.insert(tk.END, "=" * 30 + "\n\n")
        
        desc = RFLINK_PROTOCOLS.get(protocol, "Unknown protocol")
        self.detail_text.insert(tk.END, f"Type: {desc}\n\n")
        
        # Count devices
        count = sum(1 for d in self.registry.get_all() if d.protocol == protocol)
        self.detail_text.insert(tk.END, f"Devices: {count}\n")
    
    def _show_device_details(self, key: str):
        """Show device details."""
        device = self.registry.devices.get(key)
        if not device:
            return
        
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, f"Device: {device}\n")
        self.detail_text.insert(tk.END, "=" * 30 + "\n\n")
        self.detail_text.insert(tk.END, f"Protocol: {device.protocol}\n")
        self.detail_text.insert(tk.END, f"Type: {device.protocol_name}\n")
        self.detail_text.insert(tk.END, f"ID: {device.device_id}\n\n")
        
        self.detail_text.insert(tk.END, "Last Data:\n")
        for key, value in device.last_data.items():
            self.detail_text.insert(tk.END, f"  {key}: {value}\n")
        
        ts = datetime.fromtimestamp(device.last_seen).strftime('%Y-%m-%d %H:%M:%S')
        self.detail_text.insert(tk.END, f"\nLast Seen: {ts}\n")
        
        # Fill command fields
        self.cmd_protocol.set(device.protocol)
        self.cmd_id.delete(0, tk.END)
        self.cmd_id.insert(0, device.device_id)
    
    def _send_cmd(self, action: str):
        """Send command to device."""
        protocol = self.cmd_protocol.get()
        device_id = self.cmd_id.get()
        switch = self.cmd_switch.get()
        
        if not protocol or not device_id:
            self.log("Error: Protocol and Device ID required")
            return
        
        try:
            switch_num = int(switch)
        except ValueError:
            switch_num = 1
        
        # Build command
        cmd = self.decoder.encode_command(protocol, device_id, switch_num, action)
        
        # Send as ASCII
        if self._gui and hasattr(self._gui, 'send_bytes'):
            data = cmd.encode('ascii')
            self._gui.send_bytes(data)
            self.log(f"Sent: {cmd.strip()}")
        else:
            self.log("Error: Cannot send - not connected")


# Export
__all__ = ['RFLinkPlugin']
