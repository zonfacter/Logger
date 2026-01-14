"""
HausBus Protocol Handler v1.0.0
Frame encoding/decoding based on PyHausBus specification.

Frame Structure (RS485):
    [ControlByte][MsgCounter][SenderObjectId:4][ReceiverObjectId:4][DataLength:2][FunctionId][Params...]

ObjectId Structure (4 bytes, Little-Endian):
    Bits 0-7:   InstanceId
    Bits 8-15:  ClassId  
    Bits 16-31: DeviceId

FunctionId Ranges:
    0-127:   Commands (requests)
    128-199: Results (responses)
    200-254: Events
    255:     Error
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
from enum import IntEnum
import struct
import logging

LOGGER = logging.getLogger("hausbus.protocol")


# =============================================================================
# Constants
# =============================================================================

class FunctionIdRange(IntEnum):
    """FunctionId classification ranges."""
    COMMAND_START = 0
    COMMAND_END = 127
    RESULT_START = 128
    RESULT_END = 199
    EVENT_START = 200
    EVENT_END = 254
    ERROR = 255


class ClassId(IntEnum):
    """Known HausBus ClassIds from PyHausBus."""
    CONTROLLER = 0
    BUTTON = 5
    SHUTTER = 10
    DIMMER = 17
    LOGICAL_BUTTON = 20
    RGB_DIMMER = 22
    LED = 23
    ANALOG_INPUT = 30
    DIGITAL_INPUT = 40
    DIGITAL_OUTPUT = 50
    TEMPERATURE = 60
    HUMIDITY = 61
    BRIGHTNESS = 62


CLASS_NAMES: Dict[int, str] = {
    0: "Controller",
    5: "Button",
    10: "Shutter",
    17: "Dimmer",
    20: "LogicalButton",
    22: "RGBDimmer",
    23: "LED",
    30: "AnalogInput",
    40: "DigitalInput",
    50: "DigitalOutput",
    60: "Temperature",
    61: "Humidity",
    62: "Brightness",
}


# Controller FunctionIds
CONTROLLER_FUNCTIONS: Dict[int, str] = {
    0: "generateRandomDeviceId",
    1: "reset",
    2: "getModuleId",
    3: "getRemoteObjects",
    4: "getUnusedMemory",
    5: "getConfiguration",
    6: "setConfiguration",
    7: "readMemory",
    8: "writeMemory",
    9: "writeRules",
    10: "readRules",
    127: "ping",
    128: "ModuleId",
    129: "RemoteObjects",
    130: "UnusedMemory",
    131: "Configuration",
    132: "MemoryData",
    133: "MemoryStatus",
    134: "RulesData",
    199: "pong",
    200: "evTime",
    201: "evNewDeviceId",
    202: "evStarted",
    203: "evWatchDog",
    255: "evError",
}

# Dimmer FunctionIds
DIMMER_FUNCTIONS: Dict[int, str] = {
    0: "getConfiguration",
    1: "setConfiguration",
    2: "getStatus",
    3: "on",
    4: "off",
    5: "setBrightness",
    6: "start",
    7: "stop",
    128: "Configuration",
    129: "Status",
    200: "evOff",
    201: "evOn",
    255: "evError",
}

# RGBDimmer FunctionIds
RGB_DIMMER_FUNCTIONS: Dict[int, str] = {
    0: "getConfiguration",
    1: "setConfiguration",
    2: "getStatus",
    3: "on",
    4: "off",
    5: "setColor",
    6: "setBrightness",
    128: "Configuration",
    129: "Status",
    200: "evOff",
    201: "evOn",
    255: "evError",
}

# LogicalButton FunctionIds
LOGICAL_BUTTON_FUNCTIONS: Dict[int, str] = {
    0: "getConfiguration",
    1: "setConfiguration",
    2: "getStatus",
    128: "Configuration",
    129: "Status",
    200: "evFree",
    201: "evPressed",
    202: "evHoldStart",
    203: "evHoldEnd",
    204: "evClicked",
    205: "evDoubleClicked",
    255: "evError",
}

# Shutter FunctionIds
SHUTTER_FUNCTIONS: Dict[int, str] = {
    0: "getConfiguration",
    1: "setConfiguration",
    2: "getStatus",
    3: "moveUp",
    4: "moveDown",
    5: "stop",
    6: "setPosition",
    128: "Configuration",
    129: "Status",
    200: "evClosed",
    201: "evOpen",
    202: "evPosition",
    255: "evError",
}

# Button FunctionIds
BUTTON_FUNCTIONS: Dict[int, str] = {
    0: "getConfiguration",
    1: "setConfiguration",
    2: "getStatus",
    128: "Configuration",
    129: "Status",
    200: "evFree",
    201: "evPressed",
    202: "evCovered",
    255: "evError",
}

# Map ClassId to function dictionary
CLASS_FUNCTIONS: Dict[int, Dict[int, str]] = {
    ClassId.CONTROLLER: CONTROLLER_FUNCTIONS,
    ClassId.BUTTON: BUTTON_FUNCTIONS,
    ClassId.SHUTTER: SHUTTER_FUNCTIONS,
    ClassId.DIMMER: DIMMER_FUNCTIONS,
    ClassId.LOGICAL_BUTTON: LOGICAL_BUTTON_FUNCTIONS,
    ClassId.RGB_DIMMER: RGB_DIMMER_FUNCTIONS,
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ObjectId:
    """HausBus ObjectId representation."""
    device_id: int = 0
    class_id: int = 0
    instance_id: int = 0
    
    @classmethod
    def from_int(cls, value: int) -> "ObjectId":
        """Create ObjectId from 32-bit integer (Little-Endian format)."""
        return cls(
            device_id=(value >> 16) & 0xFFFF,
            class_id=(value >> 8) & 0xFF,
            instance_id=value & 0xFF
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "ObjectId":
        """Create ObjectId from 4 bytes (Little-Endian)."""
        if len(data) < 4:
            raise ValueError("ObjectId requires 4 bytes")
        value = struct.unpack("<I", data[:4])[0]
        return cls.from_int(value)
    
    def to_int(self) -> int:
        """Convert to 32-bit integer."""
        return (self.device_id << 16) | (self.class_id << 8) | self.instance_id
    
    def to_bytes(self) -> bytes:
        """Convert to 4 bytes (Little-Endian)."""
        return struct.pack("<I", self.to_int())
    
    @property
    def class_name(self) -> str:
        """Get human-readable class name."""
        return CLASS_NAMES.get(self.class_id, f"Unknown({self.class_id})")
    
    def __str__(self) -> str:
        return f"{self.device_id:04X}:{self.class_name}:{self.instance_id}"
    
    def __repr__(self) -> str:
        return f"ObjectId(dev={self.device_id}, cls={self.class_id}, inst={self.instance_id})"


@dataclass
class HausBusFrame:
    """Decoded HausBus frame."""
    control_byte: int = 0
    msg_counter: int = 0
    sender: ObjectId = field(default_factory=ObjectId)
    receiver: ObjectId = field(default_factory=ObjectId)
    function_id: int = 0
    params: bytes = b""
    raw_data: bytes = b""
    valid: bool = True
    error_msg: str = ""
    
    @property
    def function_name(self) -> str:
        """Get human-readable function name based on sender's class."""
        class_funcs = CLASS_FUNCTIONS.get(self.sender.class_id, {})
        if self.function_id in class_funcs:
            return class_funcs[self.function_id]
        class_funcs = CLASS_FUNCTIONS.get(self.receiver.class_id, {})
        return class_funcs.get(self.function_id, f"Func_{self.function_id}")
    
    @property
    def function_type(self) -> str:
        """Classify function type: Command, Result, Event, or Error."""
        if self.function_id <= FunctionIdRange.COMMAND_END:
            return "Command"
        elif self.function_id <= FunctionIdRange.RESULT_END:
            return "Result"
        elif self.function_id <= FunctionIdRange.EVENT_END:
            return "Event"
        else:
            return "Error"
    
    @property
    def data_length(self) -> int:
        """Total data length (FunctionId + params)."""
        return 1 + len(self.params)
    
    def __str__(self) -> str:
        return (
            f"[{self.function_type}] {self.sender} -> {self.receiver}: "
            f"{self.function_name}({self.params.hex() if self.params else ''})"
        )


# =============================================================================
# Protocol Decoder
# =============================================================================

class HausBusProtocol:
    """HausBus RS485 Protocol encoder/decoder."""
    
    MIN_FRAME_SIZE = 13
    HOMESERVER_DEVICE_ID = 9998
    HOMESERVER_OBJECT_ID = (HOMESERVER_DEVICE_ID << 16) | (0 << 8) | 1
    
    def __init__(self, sender_device_id: int = 9998):
        self.sender_device_id = sender_device_id
        self.msg_counter = 0
    
    def decode(self, data: bytes) -> Optional[HausBusFrame]:
        """Decode raw bytes into HausBusFrame."""
        if len(data) < self.MIN_FRAME_SIZE:
            return HausBusFrame(
                raw_data=data,
                valid=False,
                error_msg=f"Frame too short: {len(data)} < {self.MIN_FRAME_SIZE}"
            )
        
        try:
            offset = 0
            control_byte = data[offset]
            offset += 1
            msg_counter = data[offset]
            offset += 1
            sender = ObjectId.from_bytes(data[offset:offset+4])
            offset += 4
            receiver = ObjectId.from_bytes(data[offset:offset+4])
            offset += 4
            data_length = struct.unpack("<H", data[offset:offset+2])[0]
            offset += 2
            
            if offset + data_length > len(data):
                return HausBusFrame(
                    raw_data=data,
                    valid=False,
                    error_msg=f"Data length mismatch: expected {data_length}, available {len(data) - offset}"
                )
            
            function_id = data[offset]
            offset += 1
            params = data[offset:offset + data_length - 1] if data_length > 1 else b""
            
            return HausBusFrame(
                control_byte=control_byte,
                msg_counter=msg_counter,
                sender=sender,
                receiver=receiver,
                function_id=function_id,
                params=params,
                raw_data=data,
                valid=True
            )
            
        except Exception as e:
            LOGGER.exception("Frame decode error")
            return HausBusFrame(
                raw_data=data,
                valid=False,
                error_msg=str(e)
            )
    
    def encode(
        self,
        receiver: ObjectId,
        function_id: int,
        params: bytes = b"",
        sender: Optional[ObjectId] = None,
        control_byte: int = 0
    ) -> bytes:
        """Encode a HausBus frame."""
        if sender is None:
            sender = ObjectId(
                device_id=self.sender_device_id,
                class_id=0,
                instance_id=1
            )
        
        self.msg_counter = (self.msg_counter + 1) & 0xFF
        
        frame = bytearray()
        frame.append(control_byte)
        frame.append(self.msg_counter)
        frame.extend(sender.to_bytes())
        frame.extend(receiver.to_bytes())
        data_length = 1 + len(params)
        frame.extend(struct.pack("<H", data_length))
        frame.append(function_id)
        frame.extend(params)
        
        return bytes(frame)
    
    def create_ping(self, device_id: int, instance_id: int = 1) -> bytes:
        """Create a ping command for a device."""
        receiver = ObjectId(device_id=device_id, class_id=ClassId.CONTROLLER, instance_id=instance_id)
        return self.encode(receiver, 127)
    
    def create_get_module_id(self, device_id: int, index: int = 0) -> bytes:
        """Create getModuleId command."""
        receiver = ObjectId(device_id=device_id, class_id=ClassId.CONTROLLER, instance_id=1)
        return self.encode(receiver, 2, bytes([index]))
    
    def create_get_remote_objects(self, device_id: int) -> bytes:
        """Create getRemoteObjects command to discover all objects on a device."""
        receiver = ObjectId(device_id=device_id, class_id=ClassId.CONTROLLER, instance_id=1)
        return self.encode(receiver, 3)
    
    def create_get_configuration(self, device_id: int, class_id: int, instance_id: int) -> bytes:
        """Create getConfiguration command for any object."""
        receiver = ObjectId(device_id=device_id, class_id=class_id, instance_id=instance_id)
        func_id = 0 if class_id != ClassId.CONTROLLER else 5
        return self.encode(receiver, func_id)
    
    def create_dimmer_set_brightness(
        self, 
        device_id: int, 
        instance_id: int, 
        brightness: int, 
        duration: int = 0
    ) -> bytes:
        """Create setBrightness command for Dimmer."""
        receiver = ObjectId(device_id=device_id, class_id=ClassId.DIMMER, instance_id=instance_id)
        params = bytes([brightness]) + struct.pack("<H", duration)
        return self.encode(receiver, 5, params)
    
    def create_rgb_set_color(
        self,
        device_id: int,
        instance_id: int,
        red: int,
        green: int,
        blue: int,
        duration: int = 0
    ) -> bytes:
        """Create setColor command for RGBDimmer."""
        receiver = ObjectId(device_id=device_id, class_id=ClassId.RGB_DIMMER, instance_id=instance_id)
        params = bytes([red, green, blue]) + struct.pack("<H", duration)
        return self.encode(receiver, 5, params)
    
    def create_shutter_command(
        self,
        device_id: int,
        instance_id: int,
        command: str,
        position: int = 0
    ) -> bytes:
        """Create Shutter command (moveUp, moveDown, stop, setPosition)."""
        receiver = ObjectId(device_id=device_id, class_id=ClassId.SHUTTER, instance_id=instance_id)
        
        commands = {
            "moveUp": (3, b""),
            "moveDown": (4, b""),
            "stop": (5, b""),
            "setPosition": (6, bytes([position])),
        }
        
        func_id, params = commands.get(command, (5, b""))
        return self.encode(receiver, func_id, params)


def format_frame_for_display(frame: HausBusFrame, show_raw: bool = False) -> str:
    """Format a frame for GUI display."""
    lines = []
    
    type_indicator = {
        "Command": "[CMD]",
        "Result": "[RSP]",
        "Event": "[EVT]",
        "Error": "[ERR]"
    }.get(frame.function_type, "[???]")
    
    lines.append(f"{type_indicator} {frame.sender} -> {frame.receiver}")
    lines.append(f"  Function: {frame.function_name} (0x{frame.function_id:02X})")
    
    if frame.params:
        lines.append(f"  Params: {frame.params.hex(' ').upper()}")
    
    if show_raw:
        lines.append(f"  Raw: {frame.raw_data.hex(' ').upper()}")
    
    return "\n".join(lines)


def parse_params_for_class(class_id: int, function_id: int, params: bytes) -> Dict[str, Any]:
    """Parse parameters based on class and function."""
    result = {}
    
    if class_id == ClassId.DIMMER:
        if function_id == 128:
            if len(params) >= 5:
                result = {
                    "mode": params[0],
                    "fadingTime": params[1],
                    "dimmingTime": params[2],
                    "dimmingRangeStart": params[3],
                    "dimmingRangeEnd": params[4],
                }
        elif function_id == 129:
            if len(params) >= 1:
                result = {"brightness": params[0]}
        elif function_id == 201:
            if len(params) >= 3:
                result = {
                    "brightness": params[0],
                    "duration": struct.unpack("<H", params[1:3])[0],
                }
    
    elif class_id == ClassId.RGB_DIMMER:
        if function_id == 128:
            if len(params) >= 6:
                result = {
                    "minBrightness": params[0],
                    "maxBrightness": params[1],
                    "fadeTime": struct.unpack("<H", params[2:4])[0],
                    "pwmFrequency": struct.unpack("<H", params[4:6])[0],
                }
        elif function_id == 129:
            if len(params) >= 3:
                result = {
                    "red": params[0],
                    "green": params[1],
                    "blue": params[2],
                }
        elif function_id == 201:
            if len(params) >= 5:
                result = {
                    "red": params[0],
                    "green": params[1],
                    "blue": params[2],
                    "duration": struct.unpack("<H", params[3:5])[0],
                }
    
    elif class_id == ClassId.CONTROLLER:
        if function_id == 128:
            name_end = params.find(0)
            if name_end > 0:
                result["name"] = params[:name_end].decode("ascii", errors="replace")
                remaining = params[name_end+1:]
                if len(remaining) >= 7:
                    result["size"] = struct.unpack("<I", remaining[0:4])[0]
                    result["majorRelease"] = remaining[4]
                    result["minorRelease"] = remaining[5]
                    result["firmwareId"] = remaining[6]
        elif function_id == 129:
            objects = []
            for i in range(0, len(params), 4):
                if i + 4 <= len(params):
                    obj_id = ObjectId.from_bytes(params[i:i+4])
                    objects.append(str(obj_id))
            result["objects"] = objects
    
    elif class_id == ClassId.SHUTTER:
        if function_id == 128:
            if len(params) >= 8:
                result = {
                    "runTimeUp": struct.unpack("<H", params[0:2])[0],
                    "runTimeDown": struct.unpack("<H", params[2:4])[0],
                    "tiltTime": struct.unpack("<H", params[4:6])[0],
                    "options": params[6],
                    "position": params[7] if len(params) > 7 else 0,
                }
        elif function_id == 129:
            if len(params) >= 2:
                result = {
                    "position": params[0],
                    "direction": params[1],
                }
    
    return result
