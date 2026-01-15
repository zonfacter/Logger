"""
HausBus Plugin v1.2.0
ASCII-based HausBus protocol for RS485 Sniffer.
Format: FD <device_id>.<type>.<instance>.<command>.<params> FE

CHANGELOG:
v1.2.0 (2025-01-15):
  - CRITICAL FIX: Added frame buffering to handle fragmented/multiple frames
  - Fixed: Multiple telegrams in single chunk now properly parsed
  - Added: Frame statistics (valid, invalid, buffer status)
  - Added: Debug logging for frame detection
  - Improved: Device registry with better tracking

v1.1.0 (2025-01-14):
  - Initial plugin version
  - Basic HausBus protocol decoding
  - Device registry and GUI tab
"""

import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

# Try to import from parent (when used as plugin)
try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from plugin_api import PluginBase, PluginInfo, DecodedFrame, FrameField
except ImportError:
    # Fallback: Define locally if plugin_api not available
    from dataclasses import dataclass
    from abc import ABC, abstractmethod
    
    @dataclass
    class PluginInfo:
        name: str
        version: str
        author: str = ""
        description: str = ""
    
    @dataclass
    class FrameField:
        name: str
        value: Any
        description: str = ""
    
    @dataclass
    class DecodedFrame:
        valid: bool
        protocol: str
        frame_type: str = ""
        fields: List[FrameField] = field(default_factory=list)
        raw_data: bytes = b""
        summary: str = ""
        error: str = ""
    
    class PluginBase(ABC):
        def __init__(self):
            self._gui = None
            self._sniffer = None
        
        @property
        @abstractmethod
        def info(self) -> PluginInfo:
            pass
        
        def on_load(self, gui, sniffer) -> bool:
            self._gui = gui
            self._sniffer = sniffer
            return True
        
        def on_unload(self) -> None:
            pass
        
        def on_frame_received(self, timestamp: str, data: bytes, 
                              formatted: str) -> Optional[DecodedFrame]:
            return None
        
        def create_tab(self, notebook) -> Optional[ttk.Frame]:
            return None


# Protocol constants
START_BYTE = 0xFD  # 253
END_BYTE = 0xFE    # 254

# Maximum frame size (prevent buffer overflow)
MAX_FRAME_SIZE = 256
MAX_BUFFER_SIZE = 1024

# Device type definitions
DEVICE_TYPES = {
    'TMP': 'Temperature Sensor',
    'RHD': 'Humidity Sensor',
    'BRS': 'Brightness Sensor',
    'DIM': 'Dimmer',
    'OUT': 'Output Module',
    'BTN': 'Button',
    'SYS': 'System',
    'SW': 'Switch',
    'LED': 'LED Controller',
    'IR': 'IR Receiver',
    'MOT': 'Motion Sensor',
}

# Command definitions
COMMANDS = {
    'STATUS': 'Status Report',
    'gSTATUS': 'Get Status',
    'rSTATUS': 'Status Response',
    'SET_CFG': 'Set Config',
    'GET_CFG': 'Get Config',
    'rCFG': 'Config Response',
    'SET': 'Set Value',
    'GET': 'Get Value',
    'ON': 'Turn On',
    'OFF': 'Turn Off',
    'TOGGLE': 'Toggle',
}

# Logger for this plugin
logger = logging.getLogger("HausBus")


@dataclass
class HausBusDevice:
    """Represents a discovered HausBus device."""
    device_id: int
    device_type: str = ""
    instance: int = 1
    name: str = ""
    last_seen: float = 0.0
    last_value: str = ""
    message_count: int = 0
    config: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def type_name(self) -> str:
        return DEVICE_TYPES.get(self.device_type, self.device_type)
    
    @property
    def key(self) -> str:
        return f"{self.device_id}.{self.device_type}.{self.instance}"
    
    def __str__(self) -> str:
        return self.key


class DeviceRegistry:
    """Registry for discovered HausBus devices."""
    
    def __init__(self):
        self.devices: Dict[str, HausBusDevice] = {}
        self._lock = False  # Simple lock for thread safety
    
    def get_key(self, device_id: int, device_type: str, instance: int) -> str:
        return f"{device_id}.{device_type}.{instance}"
    
    def register(self, device_id: int, device_type: str, instance: int, 
                 value: str = "", command: str = "") -> HausBusDevice:
        """Register or update a device."""
        key = self.get_key(device_id, device_type, instance)
        
        if key not in self.devices:
            self.devices[key] = HausBusDevice(
                device_id=device_id,
                device_type=device_type,
                instance=instance
            )
            logger.info(f"[Registry] New device discovered: {key}")
        
        device = self.devices[key]
        device.last_seen = time.time()
        device.message_count += 1
        
        if value:
            device.last_value = value
        
        return device
    
    def get(self, device_id: int, device_type: str, instance: int) -> Optional[HausBusDevice]:
        key = self.get_key(device_id, device_type, instance)
        return self.devices.get(key)
    
    def get_all(self) -> List[HausBusDevice]:
        return list(self.devices.values())
    
    def get_by_type(self, device_type: str) -> List[HausBusDevice]:
        return [d for d in self.devices.values() if d.device_type == device_type]
    
    def clear(self):
        self.devices.clear()
        logger.info("[Registry] Cleared all devices")
    
    @property
    def count(self) -> int:
        return len(self.devices)


class HausBusDecoder:
    """
    Decoder for HausBus protocol with frame buffering.
    
    Handles:
    - Fragmented frames (data arriving in multiple chunks)
    - Multiple frames in single chunk
    - Frame validation and error recovery
    """
    
    def __init__(self, registry: DeviceRegistry):
        self.registry = registry
        self._buffer = bytearray()
        
        # Statistics
        self.stats = {
            'frames_valid': 0,
            'frames_invalid': 0,
            'frames_incomplete': 0,
            'bytes_processed': 0,
            'buffer_overflows': 0,
        }
    
    def decode(self, data: bytes) -> Optional[DecodedFrame]:
        """
        Decode incoming data. Returns first valid frame found.
        
        This method buffers data and extracts complete frames.
        Call get_pending_frames() after to get additional frames.
        """
        # Add new data to buffer
        self._buffer.extend(data)
        self.stats['bytes_processed'] += len(data)
        
        # Prevent buffer overflow
        if len(self._buffer) > MAX_BUFFER_SIZE:
            logger.warning(f"[Decoder] Buffer overflow, clearing ({len(self._buffer)} bytes)")
            self._buffer.clear()
            self.stats['buffer_overflows'] += 1
            return None
        
        # Try to extract a complete frame
        return self._extract_frame()
    
    def _extract_frame(self) -> Optional[DecodedFrame]:
        """Extract and decode a complete frame from buffer."""
        
        # Find START_BYTE
        start_idx = -1
        for i, b in enumerate(self._buffer):
            if b == START_BYTE:
                start_idx = i
                break
        
        if start_idx == -1:
            # No start byte found, clear buffer
            if len(self._buffer) > 0:
                logger.debug(f"[Decoder] No START_BYTE, discarding {len(self._buffer)} bytes")
            self._buffer.clear()
            return None
        
        # Discard bytes before START_BYTE
        if start_idx > 0:
            discarded = bytes(self._buffer[:start_idx])
            logger.debug(f"[Decoder] Discarding {start_idx} bytes before START: {discarded.hex()}")
            self._buffer = self._buffer[start_idx:]
        
        # Find END_BYTE
        end_idx = -1
        for i in range(1, len(self._buffer)):
            if self._buffer[i] == END_BYTE:
                end_idx = i
                break
        
        if end_idx == -1:
            # No end byte yet, wait for more data
            self.stats['frames_incomplete'] += 1
            logger.debug(f"[Decoder] Waiting for END_BYTE, buffer: {len(self._buffer)} bytes")
            return None
        
        # Extract complete frame
        frame = bytes(self._buffer[:end_idx + 1])
        self._buffer = self._buffer[end_idx + 1:]
        
        logger.debug(f"[Decoder] Extracted frame: {frame.hex()} ({len(frame)} bytes)")
        
        # Decode the frame
        return self._decode_frame(frame)
    
    def _decode_frame(self, frame: bytes) -> Optional[DecodedFrame]:
        """Decode a complete frame."""
        
        # Validate frame structure
        if len(frame) < 3:
            self.stats['frames_invalid'] += 1
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error="Frame too short",
                raw_data=frame
            )
        
        if frame[0] != START_BYTE or frame[-1] != END_BYTE:
            self.stats['frames_invalid'] += 1
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error="Invalid frame markers",
                raw_data=frame
            )
        
        # Extract payload (between START and END)
        payload = frame[1:-1]
        
        # Decode as ASCII
        try:
            text = payload.decode('ascii')
        except UnicodeDecodeError:
            self.stats['frames_invalid'] += 1
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error="ASCII decode failed",
                raw_data=frame
            )
        
        # Parse format: device_id.type.instance.command[.params]
        parts = text.split('.')
        if len(parts) < 4:
            self.stats['frames_invalid'] += 1
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error=f"Invalid format: {text}",
                raw_data=frame
            )
        
        try:
            device_id = int(parts[0])
            device_type = parts[1]
            instance = int(parts[2])
            command = parts[3]
            params = '.'.join(parts[4:]) if len(parts) > 4 else ""
        except ValueError as e:
            self.stats['frames_invalid'] += 1
            return DecodedFrame(
                valid=False,
                protocol="HausBus",
                error=f"Parse error: {e}",
                raw_data=frame
            )
        
        # Register device
        self.registry.register(device_id, device_type, instance, params, command)
        self.stats['frames_valid'] += 1
        
        # Build decoded frame
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
        
        # Build summary
        type_name = DEVICE_TYPES.get(device_type, device_type)
        cmd_name = COMMANDS.get(command, command)
        summary = f"[HausBus] {device_id}.{type_name}.{instance} {cmd_name}"
        if params:
            summary += f" = {params}"
        
        logger.debug(f"[Decoder] Valid frame: {summary}")
        
        return DecodedFrame(
            valid=True,
            protocol="HausBus",
            frame_type=command,
            fields=fields,
            raw_data=frame,
            summary=summary
        )
    
    def has_pending_data(self) -> bool:
        """Check if buffer has potential pending frames."""
        return START_BYTE in self._buffer and END_BYTE in self._buffer
    
    def get_pending_frames(self) -> List[DecodedFrame]:
        """Extract all pending frames from buffer."""
        frames = []
        while self.has_pending_data():
            frame = self._extract_frame()
            if frame:
                frames.append(frame)
            else:
                break
        return frames
    
    def clear_buffer(self):
        """Clear the receive buffer."""
        self._buffer.clear()
    
    @property
    def buffer_size(self) -> int:
        return len(self._buffer)
    
    def encode(self, device_id: int, device_type: str, instance: int,
               command: str, params: str = "") -> bytes:
        """Encode a HausBus command to bytes."""
        if params:
            text = f"{device_id}.{device_type}.{instance}.{command}.{params}"
        else:
            text = f"{device_id}.{device_type}.{instance}.{command}"
        
        # Build frame with raw bytes (NOT UTF-8!)
        frame = bytes([START_BYTE]) + text.encode('ascii') + bytes([END_BYTE])
        return frame


class HausBusPlugin(PluginBase):
    """
    HausBus Protocol Plugin for RS485 Sniffer.
    
    Features:
    - Automatic device discovery via passive sniffing
    - Frame buffering for fragmented/multiple telegrams
    - Device registry with statistics
    - Command sending capability
    """
    
    def __init__(self):
        super().__init__()
        self._info = PluginInfo(
            name="HausBus",
            version="1.2.0",
            author="RS485 Sniffer",
            description="HausBus ASCII protocol decoder with frame buffering"
        )
        self.registry = DeviceRegistry()
        self.decoder = HausBusDecoder(self.registry)
        
        # GUI elements
        self.tab = None
        self.device_tree = None
        self.detail_text = None
        self.cmd_entry = None
        self.stats_label = None
        self.buffer_label = None
        
        # Pending frames for multi-frame processing
        self._pending_frames: List[DecodedFrame] = []
    
    @property
    def info(self) -> PluginInfo:
        return self._info
    
    def on_load(self, gui, sniffer) -> bool:
        self._gui = gui
        self._sniffer = sniffer
        logger.info("[HausBus] Plugin loaded v1.2.0")
        return True
    
    def on_unload(self) -> None:
        self.decoder.clear_buffer()
        logger.info("[HausBus] Plugin unloaded")
    
    def on_frame_received(self, timestamp: str, data: bytes, 
                          formatted: str) -> Optional[DecodedFrame]:
        """
        Process received data. Handles buffering and multi-frame extraction.
        """
        # Decode first frame
        decoded = self.decoder.decode(data)
        
        # Check for additional frames in buffer
        additional = self.decoder.get_pending_frames()
        if additional:
            self._pending_frames.extend(additional)
            logger.debug(f"[HausBus] {len(additional)} additional frames extracted")
        
        # Update GUI if we have valid frames
        if decoded and decoded.valid:
            self._update_device_tree()
            self._update_stats()
        
        for frame in additional:
            if frame.valid:
                self._update_device_tree()
        
        return decoded
    
    def get_pending_frames(self) -> List[DecodedFrame]:
        """Get and clear pending frames from multi-frame processing."""
        frames = self._pending_frames.copy()
        self._pending_frames.clear()
        return frames
    
    def create_tab(self, notebook) -> Optional[ttk.Frame]:
        """Create the HausBus plugin tab."""
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
        
        ttk.Button(toolbar, text="Scan", 
                   command=self._start_scan).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Clear", 
                   command=self._clear_devices).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Refresh", 
                   command=self._update_device_tree).pack(side=tk.LEFT, padx=2)
        
        # Statistics label
        self.stats_label = ttk.Label(toolbar, text="Frames: 0 valid, 0 invalid")
        self.stats_label.pack(side=tk.RIGHT, padx=5)
        
        # Device tree
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("id", "type", "instance", "value", "count", "last_seen")
        self.device_tree = ttk.Treeview(tree_frame, columns=columns, 
                                        show="headings", height=15)
        
        self.device_tree.heading("id", text="ID")
        self.device_tree.heading("type", text="Type")
        self.device_tree.heading("instance", text="Inst")
        self.device_tree.heading("value", text="Value")
        self.device_tree.heading("count", text="Msgs")
        self.device_tree.heading("last_seen", text="Last Seen")
        
        self.device_tree.column("id", width=60)
        self.device_tree.column("type", width=80)
        self.device_tree.column("instance", width=40)
        self.device_tree.column("value", width=100)
        self.device_tree.column("count", width=50)
        self.device_tree.column("last_seen", width=80)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, 
                                  command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_select)
        
        # Right: Details and Command
        right_frame = ttk.LabelFrame(paned, text="Device Details")
        paned.add(right_frame, weight=1)
        
        # Command frame
        cmd_frame = ttk.LabelFrame(right_frame, text="Send Command")
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Device ID
        row1 = ttk.Frame(cmd_frame)
        row1.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(row1, text="Device ID:").pack(side=tk.LEFT)
        self.device_id_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.device_id_var, width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(row1, text="Type:").pack(side=tk.LEFT)
        self.type_var = tk.StringVar()
        type_combo = ttk.Combobox(row1, textvariable=self.type_var, width=8,
                                  values=list(DEVICE_TYPES.keys()))
        type_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(row1, text="Inst:").pack(side=tk.LEFT)
        self.instance_var = tk.StringVar(value="1")
        ttk.Entry(row1, textvariable=self.instance_var, width=5).pack(side=tk.LEFT, padx=5)
        
        # Command
        row2 = ttk.Frame(cmd_frame)
        row2.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(row2, text="Command:").pack(side=tk.LEFT)
        self.cmd_var = tk.StringVar()
        cmd_combo = ttk.Combobox(row2, textvariable=self.cmd_var, width=12,
                                 values=list(COMMANDS.keys()))
        cmd_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(row2, text="Params:").pack(side=tk.LEFT)
        self.params_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.params_var, width=15).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(row2, text="Send", command=self._send_command).pack(side=tk.RIGHT, padx=5)
        
        # Detail text
        detail_frame = ttk.LabelFrame(right_frame, text="Device Info")
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.detail_text = tk.Text(detail_frame, height=10, width=40, 
                                   state=tk.DISABLED, font=("Consolas", 9))
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buffer status
        buffer_frame = ttk.Frame(right_frame)
        buffer_frame.pack(fill=tk.X, padx=5, pady=5)
        self.buffer_label = ttk.Label(buffer_frame, text="Buffer: 0 bytes")
        self.buffer_label.pack(side=tk.LEFT)
        ttk.Button(buffer_frame, text="Clear Buffer", 
                   command=self._clear_buffer).pack(side=tk.RIGHT)
        
        return self.tab
    
    def _update_device_tree(self):
        """Update the device tree with current registry."""
        if not self.device_tree:
            return
        
        try:
            # Remember selection
            selected = self.device_tree.selection()
            selected_key = None
            if selected:
                item = self.device_tree.item(selected[0])
                if item['values']:
                    selected_key = f"{item['values'][0]}.{item['values'][1]}.{item['values'][2]}"
            
            # Clear tree
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            
            # Add devices sorted by ID
            devices = sorted(self.registry.get_all(), key=lambda d: (d.device_id, d.device_type))
            for device in devices:
                last_seen = datetime.fromtimestamp(device.last_seen).strftime("%H:%M:%S")
                values = (
                    device.device_id,
                    device.device_type,
                    device.instance,
                    device.last_value[:20] if device.last_value else "",
                    device.message_count,
                    last_seen
                )
                item_id = self.device_tree.insert("", tk.END, values=values)
                
                # Restore selection
                if selected_key and device.key == selected_key:
                    self.device_tree.selection_set(item_id)
        except Exception as e:
            logger.error(f"[HausBus] Error updating tree: {e}")
    
    def _update_stats(self):
        """Update statistics display."""
        if self.stats_label:
            stats = self.decoder.stats
            text = f"Frames: {stats['frames_valid']} valid, {stats['frames_invalid']} invalid"
            self.stats_label.config(text=text)
        
        if self.buffer_label:
            self.buffer_label.config(text=f"Buffer: {self.decoder.buffer_size} bytes")
    
    def _on_device_select(self, event):
        """Handle device selection."""
        selected = self.device_tree.selection()
        if not selected:
            return
        
        item = self.device_tree.item(selected[0])
        values = item['values']
        if not values:
            return
        
        device_id, device_type, instance = values[0], values[1], values[2]
        device = self.registry.get(device_id, device_type, instance)
        
        if device:
            # Update command fields
            self.device_id_var.set(str(device.device_id))
            self.type_var.set(device.device_type)
            self.instance_var.set(str(device.instance))
            
            # Update detail text
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete("1.0", tk.END)
            
            info = f"Device: {device.key}\n"
            info += f"Type: {device.type_name}\n"
            info += f"Last Value: {device.last_value}\n"
            info += f"Messages: {device.message_count}\n"
            info += f"Last Seen: {datetime.fromtimestamp(device.last_seen).strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            self.detail_text.insert("1.0", info)
            self.detail_text.config(state=tk.DISABLED)
    
    def _send_command(self):
        """Send a HausBus command."""
        try:
            device_id = int(self.device_id_var.get())
            device_type = self.type_var.get()
            instance = int(self.instance_var.get())
            command = self.cmd_var.get()
            params = self.params_var.get()
            
            if not device_type or not command:
                messagebox.showwarning("HausBus", "Please enter device type and command")
                return
            
            # Encode command
            frame = self.decoder.encode(device_id, device_type, instance, command, params)
            
            # Send via sniffer
            if self._sniffer and hasattr(self._sniffer, 'send'):
                self._sniffer.send(frame)
                logger.info(f"[HausBus] Sent: {frame.hex()}")
            else:
                messagebox.showwarning("HausBus", "Sniffer not connected")
        
        except ValueError as e:
            messagebox.showerror("HausBus", f"Invalid input: {e}")
        except Exception as e:
            messagebox.showerror("HausBus", f"Send error: {e}")
    
    def _start_scan(self):
        """Start a network scan by sending gSTATUS to broadcast."""
        scan_commands = [
            (0, "TMP", 1, "gSTATUS"),
            (0, "RHD", 1, "gSTATUS"),
            (0, "BRS", 1, "gSTATUS"),
            (0, "OUT", 210, "gSTATUS"),
            (0, "DIM", 1, "gSTATUS"),
        ]
        
        if self._sniffer and hasattr(self._sniffer, 'send'):
            for device_id, device_type, instance, command in scan_commands:
                frame = self.decoder.encode(device_id, device_type, instance, command)
                self._sniffer.send(frame)
            logger.info("[HausBus] Network scan sent")
        else:
            messagebox.showwarning("HausBus", "Sniffer not connected")
    
    def _clear_devices(self):
        """Clear the device registry."""
        self.registry.clear()
        self._update_device_tree()
        logger.info("[HausBus] Device registry cleared")
    
    def _clear_buffer(self):
        """Clear the decoder buffer."""
        self.decoder.clear_buffer()
        self._update_stats()
        logger.info("[HausBus] Buffer cleared")


# Plugin entry point
def get_plugin():
    return HausBusPlugin()


# Allow standalone testing
if __name__ == "__main__":
    print("HausBus Plugin v1.2.0")
    print("This plugin should be loaded by RS485 Sniffer")
    
    # Test decoder
    decoder = HausBusDecoder(DeviceRegistry())
    
    # Test data
    test_data = bytes.fromhex("FD35323133 2E544D502E312E5354415455532E31382C3236FE")
    result = decoder.decode(test_data)
    if result:
        print(f"Decoded: {result.summary}")
