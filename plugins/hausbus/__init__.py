"""
HausBus Plugin Package v1.0.0
Protocol decoder and device registry for HausBus home automation.
"""

from .protocol import (
    HausBusProtocol,
    HausBusFrame,
    ObjectId,
    ClassId,
    CLASS_NAMES,
    CLASS_FUNCTIONS,
    parse_params_for_class,
    format_frame_for_display,
)

from .device_registry import (
    DeviceRegistry,
    Device,
    DeviceObject,
)

from .hausbus_plugin import (
    HausBusPlugin,
    get_plugin_class,
)

__version__ = "1.0.0"
__author__ = "RS485 Sniffer Team"

__all__ = [
    # Protocol
    "HausBusProtocol",
    "HausBusFrame",
    "ObjectId",
    "ClassId",
    "CLASS_NAMES",
    "CLASS_FUNCTIONS",
    "parse_params_for_class",
    "format_frame_for_display",
    # Registry
    "DeviceRegistry",
    "Device",
    "DeviceObject",
    # Plugin
    "HausBusPlugin",
    "get_plugin_class",
]
