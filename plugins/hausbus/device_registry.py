"""
HausBus Device Registry v1.0.0
Manages discovered devices, their objects, and configurations.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path
import json
import logging
import threading

from .protocol import ObjectId, ClassId, CLASS_NAMES

LOGGER = logging.getLogger("hausbus.registry")


@dataclass
class DeviceObject:
    """Represents a single object (feature) on a device."""
    object_id: ObjectId
    name: str = ""
    configuration: Dict[str, Any] = field(default_factory=dict)
    status: Dict[str, Any] = field(default_factory=dict)
    last_seen: datetime = field(default_factory=datetime.now)
    last_event: str = ""
    
    @property
    def class_name(self) -> str:
        return self.object_id.class_name
    
    @property
    def unique_id(self) -> str:
        return f"{self.object_id.device_id}_{self.object_id.class_id}_{self.object_id.instance_id}"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.object_id.device_id,
            "class_id": self.object_id.class_id,
            "instance_id": self.object_id.instance_id,
            "class_name": self.class_name,
            "name": self.name,
            "configuration": self.configuration,
            "status": self.status,
            "last_seen": self.last_seen.isoformat(),
            "last_event": self.last_event,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceObject":
        obj_id = ObjectId(
            device_id=data.get("device_id", 0),
            class_id=data.get("class_id", 0),
            instance_id=data.get("instance_id", 0)
        )
        return cls(
            object_id=obj_id,
            name=data.get("name", ""),
            configuration=data.get("configuration", {}),
            status=data.get("status", {}),
            last_seen=datetime.fromisoformat(data.get("last_seen", datetime.now().isoformat())),
            last_event=data.get("last_event", ""),
        )


@dataclass
class Device:
    """Represents a HausBus device with multiple objects."""
    device_id: int
    name: str = ""
    firmware_version: str = ""
    module_name: str = ""
    objects: Dict[str, DeviceObject] = field(default_factory=dict)
    last_seen: datetime = field(default_factory=datetime.now)
    online: bool = False
    
    def add_object(self, obj: DeviceObject) -> None:
        key = f"{obj.object_id.class_id}_{obj.object_id.instance_id}"
        self.objects[key] = obj
        self.last_seen = datetime.now()
    
    def get_object(self, class_id: int, instance_id: int) -> Optional[DeviceObject]:
        key = f"{class_id}_{instance_id}"
        return self.objects.get(key)
    
    def get_objects_by_class(self, class_id: int) -> List[DeviceObject]:
        return [obj for obj in self.objects.values() if obj.object_id.class_id == class_id]
    
    @property
    def object_count(self) -> int:
        return len(self.objects)
    
    @property
    def class_summary(self) -> str:
        classes: Dict[str, int] = {}
        for obj in self.objects.values():
            name = obj.class_name
            classes[name] = classes.get(name, 0) + 1
        return ", ".join(f"{count}x {name}" for name, count in classes.items())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "firmware_version": self.firmware_version,
            "module_name": self.module_name,
            "objects": {k: v.to_dict() for k, v in self.objects.items()},
            "last_seen": self.last_seen.isoformat(),
            "online": self.online,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Device":
        device = cls(
            device_id=data.get("device_id", 0),
            name=data.get("name", ""),
            firmware_version=data.get("firmware_version", ""),
            module_name=data.get("module_name", ""),
            last_seen=datetime.fromisoformat(data.get("last_seen", datetime.now().isoformat())),
            online=data.get("online", False),
        )
        for key, obj_data in data.get("objects", {}).items():
            device.objects[key] = DeviceObject.from_dict(obj_data)
        return device


class DeviceRegistry:
    """Central registry for all discovered HausBus devices."""
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path("./data")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.devices: Dict[int, Device] = {}
        self._lock = threading.RLock()
        self._listeners: List[callable] = []
        self._load_devices()
    
    def add_listener(self, callback: callable) -> None:
        self._listeners.append(callback)
    
    def remove_listener(self, callback: callable) -> None:
        if callback in self._listeners:
            self._listeners.remove(callback)
    
    def _notify_listeners(self, event: str, device_id: int, data: Any = None) -> None:
        for listener in self._listeners:
            try:
                listener(event, device_id, data)
            except Exception as e:
                LOGGER.exception(f"Listener error: {e}")
    
    def get_device(self, device_id: int) -> Optional[Device]:
        with self._lock:
            return self.devices.get(device_id)
    
    def get_or_create_device(self, device_id: int) -> Device:
        with self._lock:
            if device_id not in self.devices:
                self.devices[device_id] = Device(device_id=device_id)
                self._notify_listeners("device_added", device_id)
            return self.devices[device_id]
    
    def update_device_from_frame(self, sender: ObjectId, function_id: int, params: bytes) -> None:
        with self._lock:
            device = self.get_or_create_device(sender.device_id)
            device.last_seen = datetime.now()
            device.online = True
            
            obj = device.get_object(sender.class_id, sender.instance_id)
            if obj is None:
                obj = DeviceObject(object_id=sender)
                device.add_object(obj)
                self._notify_listeners("object_added", sender.device_id, sender)
            
            obj.last_seen = datetime.now()
            
            if sender.class_id == ClassId.CONTROLLER and function_id == 128:
                name_end = params.find(0)
                if name_end > 0:
                    device.module_name = params[:name_end].decode("ascii", errors="replace")
                    remaining = params[name_end+1:]
                    if len(remaining) >= 7:
                        major = remaining[4]
                        minor = remaining[5]
                        device.firmware_version = f"{major}.{minor}"
            
            elif sender.class_id == ClassId.CONTROLLER and function_id == 129:
                for i in range(0, len(params), 4):
                    if i + 4 <= len(params):
                        remote_obj = ObjectId.from_bytes(params[i:i+4])
                        if device.get_object(remote_obj.class_id, remote_obj.instance_id) is None:
                            device.add_object(DeviceObject(object_id=remote_obj))
            
            elif function_id == 128:
                from .protocol import parse_params_for_class
                obj.configuration = parse_params_for_class(sender.class_id, function_id, params)
            
            elif function_id == 129:
                from .protocol import parse_params_for_class
                obj.status = parse_params_for_class(sender.class_id, function_id, params)
            
            elif 200 <= function_id <= 254:
                from .protocol import CLASS_FUNCTIONS
                class_funcs = CLASS_FUNCTIONS.get(sender.class_id, {})
                obj.last_event = class_funcs.get(function_id, f"Event_{function_id}")
                self._notify_listeners("event", sender.device_id, {
                    "object": sender,
                    "event": obj.last_event,
                    "params": params,
                })
            
            self._notify_listeners("device_updated", sender.device_id)
    
    def get_all_devices(self) -> List[Device]:
        with self._lock:
            return list(self.devices.values())
    
    def get_devices_with_class(self, class_id: int) -> List[Device]:
        with self._lock:
            return [
                d for d in self.devices.values()
                if any(obj.object_id.class_id == class_id for obj in d.objects.values())
            ]
    
    def set_device_offline(self, device_id: int) -> None:
        with self._lock:
            if device_id in self.devices:
                self.devices[device_id].online = False
                self._notify_listeners("device_offline", device_id)
    
    def clear(self) -> None:
        with self._lock:
            self.devices.clear()
            self._notify_listeners("registry_cleared", 0)
    
    def save_devices(self) -> None:
        with self._lock:
            devices_file = self.data_dir / "devices.json"
            data = {
                "version": "1.0",
                "saved_at": datetime.now().isoformat(),
                "devices": {str(k): v.to_dict() for k, v in self.devices.items()}
            }
            with open(devices_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            LOGGER.info(f"Saved {len(self.devices)} devices to {devices_file}")
    
    def _load_devices(self) -> None:
        devices_file = self.data_dir / "devices.json"
        if not devices_file.exists():
            return
        
        try:
            with open(devices_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for key, device_data in data.get("devices", {}).items():
                device = Device.from_dict(device_data)
                device.online = False
                self.devices[device.device_id] = device
            
            LOGGER.info(f"Loaded {len(self.devices)} devices from {devices_file}")
        except Exception as e:
            LOGGER.exception(f"Error loading devices: {e}")
    
    def export_all_configs(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": "1.0",
                "exported_at": datetime.now().isoformat(),
                "devices": {str(k): v.to_dict() for k, v in self.devices.items()}
            }
    
    def import_configs(self, data: Dict[str, Any]) -> int:
        with self._lock:
            count = 0
            for key, device_data in data.get("devices", {}).items():
                device = Device.from_dict(device_data)
                self.devices[device.device_id] = device
                count += 1
            self._notify_listeners("registry_imported", 0, count)
            return count
