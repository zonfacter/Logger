"""
HausBus Plugin v1.1.0
ASCII-based HausBus protocol for RS485 Sniffer.
Format: FD <device_id>.<type>.<instance>.<command>.<params> FE
"""

import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugin_api import PluginBase, PluginInfo, DecodedFrame, FrameField


START_BYTE = 0xFD
END_BYTE = 0xFE

DEVICE_TYPES = {
    'TMP': 'Temperature Sensor',
    'RHD': 'Humidity Sensor',
    'BRS': 'Brightness Sensor',
    'DIM': 'Dimmer',
    'OUT': 'Output Module',
    'BTN': 'Button',
    'SYS': 'System',
}

COMMANDS = {
    'STATUS': 'Status Report',
    'gSTATUS': 'Get Status',
    'rSTATUS': 'Status Response',
    'SET_CFG': 'Set Config',
    'GET_CFG': 'Get Config',
    'rCFG': 'Config Response',
}


@dataclass
class HausBusDevice:
    device_id: int
    device_type: str = ""
    instance: int = 1
    name: str = ""
    last_seen: float = 0.0
    last_value: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def type_name(self) -> str:
        return DEVICE_TYPES.get(self.device_type, self.device_type)
    
    def __str__(self) -> str:
        return f"{self.device_id}.{self.device_type}.{self.instance}"


class DeviceRegistry:
    def __init__(self):
        self.devices: Dict[str, HausBusDevice] = {}
    
    def get_key(self, device_id: int, device_type: str, instance: int) -> str:
        return f"{device_id}.{device_type}.{instance}"
    
    def register(self, device_id: int, device_type: str, instance: int, 
                 value: str = "") -> HausBusDevice:
        key = self.get_key(device_id, device_type, instance)
        if key not in self.devices:
            self.devices[key] = HausBusDevice(
                device_id=device_id,
                device_type=device_type,
                instance=instance
            )
        device = self.devices[key]
        device.last_seen = time.time()
        if value:
            device.last_value = value
        return device
    
    def get(self, device_id: int, device_type: str, instance: int) -> Optional[HausBusDevice]:
        key = self.get_key(device_id, device_type, instance)
        return self.devices.get(key)
    
    def get_all(self) -> List[HausBusDevice]:
        return list(self.devices.values())
    
    def clear(self):
        self.devices.clear()


class HausBusDecoder:
    def __init__(self, registry: DeviceRegistry):
        self.registry = registry
    
    def decode(self, data: bytes) -> Optional[DecodedFrame]:
        if len(data) < 3:
            return None
        
        if data[0] != START_BYTE or data[-1] != END_BYTE:
            return None
        
        payload = data[1:-1]
        
        try:
            text = payload.decode('ascii', errors='replace')
        except Exception:
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error="ASCII decode failed",
                raw_data=data
            )
        
        parts = text.split('.')
        if len(parts) < 4:
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error=f"Invalid format: {text}",
                raw_data=data
            )
        
        try:
            device_id = int(parts[0])
            device_type = parts[1]
            instance = int(parts[2])
            command = parts[3]
            params = '.'.join(parts[4:]) if len(parts) > 4 else ""
        except ValueError as e:
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error=f"Parse error: {e}",
                raw_data=data
            )
        
        self.registry.register(device_id, device_type, instance, params)
        
        fields = [
            FrameField(name="device_id", value=device_id),
            FrameField(name="type", value=device_type, 
                      description=DEVICE_TYPES.get(device_type, "Unknown")),
            FrameField(name="instance", value=instance),
            FrameField(name="command", value=command, 
                      description=COMMANDS.get(command, "Unknown")),
        ]
        
        if params:
            fields.append(FrameField(name="params", value=params))
        
        type_name = DEVICE_TYPES.get(device_type, device_type)
        cmd_name = COMMANDS.get(command, command)
        summary = f"{device_id}.{type_name}.{instance} {cmd_name}"
        if params:
            summary += f" = {params}"
        
        return DecodedFrame(
            valid=True,
            protocol="HausBus",
            frame_type=command,
            fields=fields,
            raw_data=data,
            summary=summary
        )
    
    def encode(self, device_id: int, device_type: str, instance: int,
               command: str, params: str = "") -> bytes:
        if params:
            text = f"{device_id}.{device_type}.{instance}.{command}.{params}"
        else:
            text = f"{device_id}.{device_type}.{instance}.{command}"
        
        # WICHTIG: bytes([]) statt chr().encode() um UTF-8 zu vermeiden!
        frame = bytes([START_BYTE]) + text.encode('ascii') + bytes([END_BYTE])
        return frame


class HausBusPlugin(PluginBase):
    def __init__(self):
        super().__init__()
        self._info = PluginInfo(
            name="HausBus",
            version="1.1.0",
            author="RS485 Sniffer",
            description="HausBus ASCII protocol decoder"
        )
        self.registry = DeviceRegistry()
        self.decoder = HausBusDecoder(self.registry)
        self.tab = None
        self.device_tree = None
        self.detail_text = None
        self.cmd_entry = None
    
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
        decoded = self.decoder.decode(data)
        if decoded and decoded.valid:
            if self.device_tree:
                self._update_device_tree()
        return decoded
    
    def create_tab(self, notebook) -> Optional[ttk.Frame]:
        self.tab = ttk.Frame(notebook)
        
        paned = ttk.PanedWindow(self.tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left: Device list
        left_frame = ttk.LabelFrame(paned, text="Devices")
        paned.add(left_frame, weight=1)
        
        toolbar = ttk.Frame(left_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="Scan", 
                   command=self._start_scan).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Clear", 
                   command=self._clear_devices).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Refresh", 
                   command=self._update_device_tree).pack(side=tk.LEFT, padx=2)
        
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("type", "instance", "value", "last_seen")
        self.device_tree = ttk.Treeview(tree_frame, columns=columns, 
                                        show="headings", height=15)
        
        self.device_tree.heading("type", text="Type")
        self.device_tree.heading("instance", text="Inst")
        self.device_tree.heading("value", text="Value")
        self.device_tree.heading("last_seen", text="Last Seen")
        
        self.device_tree.column("type", width=100)
        self.device_tree.column("instance", width=50)
        self.device_tree.column("value", width=100)
        self.device_tree.column("last_seen", width=80)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, 
                                  command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_select)
        
        # Right: Details
        right_frame = ttk.LabelFrame(paned, text="Details")
        paned.add(right_frame, weight=1)
        
        cmd_frame = ttk.Frame(right_frame)
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(cmd_frame, text="Command:").pack(side=tk.LEFT)
        self.cmd_entry = ttk.Entry(cmd_frame, width=30)
        self.cmd_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(cmd_frame, text="Send", 
                   command=self._send_command).pack(side=tk.LEFT)
        
        self.detail_text = tk.Text(right_frame, height=20, width=40)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        return self.tab
    
    def _start_scan(self):
        frame = self.decoder.encode(0xFF, "SYS", 1, "gSTATUS")
        if self._gui and hasattr(self._gui, 'send_bytes'):
            self._gui.send_bytes(frame)
            self.log("Network scan started")
        else:
            self.log("Error: send_bytes not available")
    
    def _clear_devices(self):
        self.registry.clear()
        self._update_device_tree()
        self.log("Device list cleared")
    
    def _update_device_tree(self):
        if not self.device_tree:
            return
        
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        devices_by_id: Dict[int, List[HausBusDevice]] = {}
        for device in self.registry.get_all():
            if device.device_id not in devices_by_id:
                devices_by_id[device.device_id] = []
            devices_by_id[device.device_id].append(device)
        
        for device_id in sorted(devices_by_id.keys()):
            parent = self.device_tree.insert(
                "", tk.END, 
                values=(f"Device {device_id}", "", "", ""),
                iid=f"dev_{device_id}",
                open=True
            )
            
            for device in devices_by_id[device_id]:
                last_seen = datetime.fromtimestamp(
                    device.last_seen
                ).strftime("%H:%M:%S")
                self.device_tree.insert(
                    parent, tk.END,
                    values=(device.type_name, 
                           device.instance,
                           device.last_value,
                           last_seen),
                    iid=str(device)
                )
    
    def _on_device_select(self, event):
        selection = self.device_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        if item_id.startswith("dev_"):
            device_id = int(item_id.replace("dev_", ""))
            self._show_device_group(device_id)
        else:
            self._show_device_details(item_id)
    
    def _show_device_group(self, device_id: int):
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, f"Device ID: {device_id}\n")
        self.detail_text.insert(tk.END, "=" * 30 + "\n\n")
        
        for device in self.registry.get_all():
            if device.device_id == device_id:
                self.detail_text.insert(tk.END, 
                    f"{device.type_name} #{device.instance}\n")
                self.detail_text.insert(tk.END, 
                    f"  Value: {device.last_value}\n")
                ts = datetime.fromtimestamp(device.last_seen).strftime('%H:%M:%S')
                self.detail_text.insert(tk.END, f"  Last: {ts}\n\n")
    
    def _show_device_details(self, key: str):
        parts = key.split('.')
        if len(parts) != 3:
            return
        
        device_id = int(parts[0])
        device_type = parts[1]
        instance = int(parts[2])
        
        device = self.registry.get(device_id, device_type, instance)
        if not device:
            return
        
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, f"Device: {device}\n")
        self.detail_text.insert(tk.END, "=" * 30 + "\n\n")
        self.detail_text.insert(tk.END, f"Type: {device.type_name}\n")
        self.detail_text.insert(tk.END, f"Instance: {device.instance}\n")
        self.detail_text.insert(tk.END, f"Value: {device.last_value}\n")
        ts = datetime.fromtimestamp(device.last_seen).strftime('%Y-%m-%d %H:%M:%S')
        self.detail_text.insert(tk.END, f"Last Seen: {ts}\n")
        
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, f"{device_id}.{device_type}.{instance}.gSTATUS")
    
    def _send_command(self):
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
        
        # WICHTIG: bytes([]) statt chr().encode()!
        frame = bytes([START_BYTE]) + cmd.encode('ascii') + bytes([END_BYTE])
        
        if self._gui and hasattr(self._gui, 'send_bytes'):
            self._gui.send_bytes(frame)
            self.log(f"Sent: {cmd}")
        else:
            self.log("Error: Cannot send")


# Export
__all__ = ['HausBusPlugin']
