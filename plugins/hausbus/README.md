# HausBus Plugin v1.0.0

Protocol decoder plugin for RS485 Sniffer to decode HausBus home automation protocol.

## Installation

1. Copy the `hausbus_plugin` folder to the `plugins/` directory of RS485 Sniffer
2. Restart RS485 Sniffer
3. The plugin will be automatically detected and loaded

## Directory Structure

```
plugins/
└── hausbus_plugin/
    ├── __init__.py          # Package initialization
    ├── protocol.py          # HausBus protocol encoder/decoder
    ├── device_registry.py   # Device discovery and management
    ├── hausbus_plugin.py    # Main plugin class
    └── README.md            # This file
```

## Features

### Protocol Decoding
- Full HausBus frame decoding (RS485)
- Support for all standard ClassIds (Controller, Dimmer, Shutter, etc.)
- Parameter parsing for common functions
- Frame type classification (Command, Result, Event, Error)

### Device Discovery
- Automatic device discovery from traffic
- Device registry with persistence
- Object tracking per device
- Event monitoring

### Command Encoding
- Ping devices
- Get module information
- Discover remote objects
- Control dimmers, RGB lights, shutters
- Raw command support

## Configuration

The plugin supports the following configuration options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| show_raw_data | bool | false | Show raw hex in decoded output |
| auto_discover | bool | true | Auto-discover devices from traffic |
| data_directory | str | ./hausbus_data | Directory for device data |
| sender_device_id | int | 9998 | Device ID for sending commands |

## Usage Example

```python
from plugins.hausbus_plugin import HausBusPlugin

# Initialize plugin
plugin = HausBusPlugin()
plugin.initialize({
    "auto_discover": True,
    "sender_device_id": 9998
})

# Decode a frame
frame_data = bytes.fromhex("00 01 01 00 11 00 01 00 00 00 02 00 81 C8")
decoded = plugin.decode(frame_data)
print(decoded.summary)

# Encode a command
ping_data = plugin.encode("ping", {"device_id": 0x1100})
print(ping_data.hex())

# Get discovered devices
devices = plugin.get_discovered_devices()
for device in devices:
    print(f"Device {device['device_id']}: {device['name']}")
```

## HausBus Protocol Overview

### Frame Structure (RS485)
```
[ControlByte:1][MsgCounter:1][SenderObjectId:4][ReceiverObjectId:4][DataLength:2][FunctionId:1][Params:n]
```

### ObjectId Structure (4 bytes, Little-Endian)
- Bits 0-7: InstanceId
- Bits 8-15: ClassId
- Bits 16-31: DeviceId

### FunctionId Ranges
- 0-127: Commands (requests)
- 128-199: Results (responses)
- 200-254: Events
- 255: Error

### Supported ClassIds
| ID | Name | Description |
|----|------|-------------|
| 0 | Controller | Device controller |
| 5 | Button | Physical button |
| 10 | Shutter | Shutter/blind control |
| 17 | Dimmer | Light dimmer |
| 20 | LogicalButton | Virtual button |
| 22 | RGBDimmer | RGB LED controller |
| 23 | LED | Simple LED |
| 30 | AnalogInput | Analog sensor input |
| 40 | DigitalInput | Digital input |
| 50 | DigitalOutput | Digital output |
| 60 | Temperature | Temperature sensor |
| 61 | Humidity | Humidity sensor |
| 62 | Brightness | Brightness sensor |

## Changelog

### v1.0.0 (2025-01-14)
- Initial release
- Full protocol decoding support
- Device registry with persistence
- Command encoding for common operations
- Integration with RS485 Sniffer plugin API

## License

Part of RS485 Sniffer project.
