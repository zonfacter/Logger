"""
HausBus Protocol Plugin v1.0.0
Plugin for RS485 Sniffer to decode HausBus protocol frames.
"""

from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import struct
import logging

# Import from plugin API
try:
    from plugin_api import PluginBase, PluginInfo, DecodedFrame, FrameField
except ImportError:
    from .plugin_api import PluginBase, PluginInfo, DecodedFrame, FrameField

# Import protocol components
try:
    from protocol import (
        HausBusProtocol, HausBusFrame, ObjectId, ClassId,
        CLASS_NAMES, CLASS_FUNCTIONS, parse_params_for_class
    )
    from device_registry import DeviceRegistry, Device, DeviceObject
except ImportError:
    from .protocol import (
        HausBusProtocol, HausBusFrame, ObjectId, ClassId,
        CLASS_NAMES, CLASS_FUNCTIONS, parse_params_for_class
    )
    from .device_registry import DeviceRegistry, Device, DeviceObject


LOGGER = logging.getLogger("plugin.hausbus")


class HausBusPlugin(PluginBase):
    """
    HausBus Protocol Plugin for RS485 Sniffer.
    
    Decodes HausBus frames and provides device discovery,
    command generation, and protocol analysis.
    """
    
    @classmethod
    def get_info(cls) -> PluginInfo:
        return PluginInfo(
            name="HausBus Protocol",
            version="1.0.0",
            author="RS485 Sniffer Team",
            description="Decoder for HausBus home automation protocol",
            protocol_name="HausBus",
            min_frame_size=13,
            max_frame_size=256,
            supports_encoding=True,
            supports_device_discovery=True,
            config_schema={
                "show_raw_data": {
                    "type": "bool",
                    "default": False,
                    "description": "Show raw hex data in decoded output"
                },
                "auto_discover": {
                    "type": "bool",
                    "default": True,
                    "description": "Automatically discover devices from traffic"
                },
                "data_directory": {
                    "type": "str",
                    "default": "./hausbus_data",
                    "description": "Directory for device registry data"
                },
                "sender_device_id": {
                    "type": "int",
                    "default": 9998,
                    "description": "Device ID to use when sending commands"
                }
            }
        )
    
    def __init__(self):
        super().__init__()
        self._protocol: Optional[HausBusProtocol] = None
        self._registry: Optional[DeviceRegistry] = None
        self._config: Dict[str, Any] = {}
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin with configuration."""
        try:
            self._config = config
            
            sender_id = config.get("sender_device_id", 9998)
            self._protocol = HausBusProtocol(sender_device_id=sender_id)
            
            if config.get("auto_discover", True):
                from pathlib import Path
                data_dir = Path(config.get("data_directory", "./hausbus_data"))
                self._registry = DeviceRegistry(data_dir=data_dir)
            
            LOGGER.info(f"HausBus plugin initialized with sender_id={sender_id}")
            return True
            
        except Exception as e:
            LOGGER.exception(f"Failed to initialize HausBus plugin: {e}")
            return False
    
    def shutdown(self) -> None:
        """Cleanup on shutdown."""
        if self._registry:
            try:
                self._registry.save_devices()
            except Exception as e:
                LOGGER.exception(f"Error saving device registry: {e}")
    
    def can_decode(self, data: bytes) -> Tuple[bool, float]:
        """
        Check if data looks like a HausBus frame.
        Returns (can_decode, confidence).
        """
        if len(data) < 13:
            return False, 0.0
        
        confidence = 0.3
        
        control_byte = data[0]
        if control_byte <= 0x0F:
            confidence += 0.1
        
        try:
            data_length = struct.unpack("<H", data[10:12])[0]
            expected_total = 12 + data_length
            
            if len(data) == expected_total:
                confidence += 0.3
            elif len(data) >= expected_total:
                confidence += 0.2
        except:
            pass
        
        if len(data) >= 6:
            sender_class = data[5]
            if sender_class in CLASS_NAMES:
                confidence += 0.2
        
        if len(data) >= 10:
            receiver_class = data[9]
            if receiver_class in CLASS_NAMES:
                confidence += 0.1
        
        return confidence >= 0.5, min(confidence, 1.0)
    
    def decode(self, data: bytes, timestamp: Optional[datetime] = None) -> Optional[DecodedFrame]:
        """Decode a HausBus frame."""
        if self._protocol is None:
            return None
        
        frame = self._protocol.decode(data)
        if frame is None:
            return None
        
        if not frame.valid:
            return DecodedFrame(
                protocol="HausBus",
                valid=False,
                error_message=frame.error_msg,
                raw_data=data,
                timestamp=timestamp or datetime.now()
            )
        
        if self._registry and self._config.get("auto_discover", True):
            try:
                self._registry.update_device_from_frame(
                    frame.sender, frame.function_id, frame.params
                )
            except Exception as e:
                LOGGER.debug(f"Registry update error: {e}")
        
        fields = [
            FrameField("Control", f"0x{frame.control_byte:02X}", 0, 1),
            FrameField("MsgCounter", str(frame.msg_counter), 1, 1),
            FrameField("Sender", str(frame.sender), 2, 4),
            FrameField("Receiver", str(frame.receiver), 6, 4),
            FrameField("DataLength", str(frame.data_length), 10, 2),
            FrameField("Function", f"{frame.function_name} (0x{frame.function_id:02X})", 12, 1),
        ]
        
        if frame.params:
            parsed = parse_params_for_class(
                frame.sender.class_id, frame.function_id, frame.params
            )
            if parsed:
                params_str = ", ".join(f"{k}={v}" for k, v in parsed.items())
            else:
                params_str = frame.params.hex(" ").upper()
            fields.append(FrameField("Params", params_str, 13, len(frame.params)))
        
        summary = f"{frame.function_type}: {frame.sender} -> {frame.receiver} [{frame.function_name}]"
        
        return DecodedFrame(
            protocol="HausBus",
            valid=True,
            summary=summary,
            fields=fields,
            raw_data=data,
            timestamp=timestamp or datetime.now(),
            metadata={
                "frame_type": frame.function_type,
                "sender_device": frame.sender.device_id,
                "receiver_device": frame.receiver.device_id,
                "sender_class": frame.sender.class_name,
                "receiver_class": frame.receiver.class_name,
                "function_id": frame.function_id,
                "function_name": frame.function_name,
            }
        )
    
    def encode(self, command: str, params: Dict[str, Any]) -> Optional[bytes]:
        """
        Encode a command to HausBus frame.
        
        Supported commands:
        - ping: {device_id: int}
        - get_module_id: {device_id: int, index: int}
        - get_remote_objects: {device_id: int}
        - get_configuration: {device_id: int, class_id: int, instance_id: int}
        - dimmer_set_brightness: {device_id: int, instance_id: int, brightness: int, duration: int}
        - rgb_set_color: {device_id: int, instance_id: int, red: int, green: int, blue: int, duration: int}
        - shutter_command: {device_id: int, instance_id: int, command: str, position: int}
        """
        if self._protocol is None:
            return None
        
        try:
            if command == "ping":
                return self._protocol.create_ping(
                    device_id=params["device_id"],
                    instance_id=params.get("instance_id", 1)
                )
            
            elif command == "get_module_id":
                return self._protocol.create_get_module_id(
                    device_id=params["device_id"],
                    index=params.get("index", 0)
                )
            
            elif command == "get_remote_objects":
                return self._protocol.create_get_remote_objects(
                    device_id=params["device_id"]
                )
            
            elif command == "get_configuration":
                return self._protocol.create_get_configuration(
                    device_id=params["device_id"],
                    class_id=params["class_id"],
                    instance_id=params["instance_id"]
                )
            
            elif command == "dimmer_set_brightness":
                return self._protocol.create_dimmer_set_brightness(
                    device_id=params["device_id"],
                    instance_id=params["instance_id"],
                    brightness=params["brightness"],
                    duration=params.get("duration", 0)
                )
            
            elif command == "rgb_set_color":
                return self._protocol.create_rgb_set_color(
                    device_id=params["device_id"],
                    instance_id=params["instance_id"],
                    red=params["red"],
                    green=params["green"],
                    blue=params["blue"],
                    duration=params.get("duration", 0)
                )
            
            elif command == "shutter_command":
                return self._protocol.create_shutter_command(
                    device_id=params["device_id"],
                    instance_id=params["instance_id"],
                    command=params["command"],
                    position=params.get("position", 0)
                )
            
            elif command == "raw":
                receiver = ObjectId(
                    device_id=params["device_id"],
                    class_id=params["class_id"],
                    instance_id=params["instance_id"]
                )
                raw_params = bytes.fromhex(params.get("params_hex", ""))
                return self._protocol.encode(
                    receiver=receiver,
                    function_id=params["function_id"],
                    params=raw_params
                )
            
            else:
                LOGGER.warning(f"Unknown command: {command}")
                return None
                
        except KeyError as e:
            LOGGER.error(f"Missing parameter for command '{command}': {e}")
            return None
        except Exception as e:
            LOGGER.exception(f"Error encoding command '{command}': {e}")
            return None
    
    def get_available_commands(self) -> List[Dict[str, Any]]:
        """Return list of available commands with their parameters."""
        return [
            {
                "name": "ping",
                "description": "Ping a device",
                "params": {"device_id": "int"}
            },
            {
                "name": "get_module_id",
                "description": "Get module identification",
                "params": {"device_id": "int", "index": "int (optional)"}
            },
            {
                "name": "get_remote_objects",
                "description": "Discover all objects on a device",
                "params": {"device_id": "int"}
            },
            {
                "name": "get_configuration",
                "description": "Get object configuration",
                "params": {"device_id": "int", "class_id": "int", "instance_id": "int"}
            },
            {
                "name": "dimmer_set_brightness",
                "description": "Set dimmer brightness",
                "params": {
                    "device_id": "int",
                    "instance_id": "int",
                    "brightness": "int (0-200)",
                    "duration": "int (optional, ms)"
                }
            },
            {
                "name": "rgb_set_color",
                "description": "Set RGB color",
                "params": {
                    "device_id": "int",
                    "instance_id": "int",
                    "red": "int (0-255)",
                    "green": "int (0-255)",
                    "blue": "int (0-255)",
                    "duration": "int (optional, ms)"
                }
            },
            {
                "name": "shutter_command",
                "description": "Control shutter",
                "params": {
                    "device_id": "int",
                    "instance_id": "int",
                    "command": "str (moveUp/moveDown/stop/setPosition)",
                    "position": "int (optional, 0-100)"
                }
            },
        ]
    
    def get_discovered_devices(self) -> List[Dict[str, Any]]:
        """Return list of discovered devices."""
        if self._registry is None:
            return []
        
        result = []
        for device in self._registry.get_all_devices():
            result.append({
                "device_id": device.device_id,
                "name": device.name or device.module_name or f"Device {device.device_id}",
                "firmware": device.firmware_version,
                "online": device.online,
                "last_seen": device.last_seen.isoformat(),
                "object_count": device.object_count,
                "objects": [
                    {
                        "class_id": obj.object_id.class_id,
                        "class_name": obj.class_name,
                        "instance_id": obj.object_id.instance_id,
                        "name": obj.name,
                        "last_event": obj.last_event,
                    }
                    for obj in device.objects.values()
                ]
            })
        return result
    
    def get_device_details(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific device."""
        if self._registry is None:
            return None
        
        device = self._registry.get_device(device_id)
        if device is None:
            return None
        
        return device.to_dict()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Return plugin statistics."""
        stats = {
            "protocol": "HausBus",
            "version": self.get_info().version,
        }
        
        if self._registry:
            devices = self._registry.get_all_devices()
            stats["total_devices"] = len(devices)
            stats["online_devices"] = sum(1 for d in devices if d.online)
            stats["total_objects"] = sum(d.object_count for d in devices)
            
            class_counts: Dict[str, int] = {}
            for device in devices:
                for obj in device.objects.values():
                    name = obj.class_name
                    class_counts[name] = class_counts.get(name, 0) + 1
            stats["objects_by_class"] = class_counts
        
        return stats


def get_plugin_class():
    """Entry point for plugin discovery."""
    return HausBusPlugin
