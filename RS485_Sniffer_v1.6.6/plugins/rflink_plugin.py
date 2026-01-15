"""
RFLink Plugin v1.1.0
Example plugin for RFLink protocol decoding.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Any

try:
    from plugin_api import PluginBase, PluginInfo, DecodedFrame, FrameField
except ImportError:
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
    
    class PluginBase:
        def __init__(self):
            self._gui = None
            self._sniffer = None
        
        @property
        def info(self) -> PluginInfo:
            pass
        
        def on_load(self, gui, sniffer) -> bool:
            self._gui = gui
            self._sniffer = sniffer
            return True
        
        def on_unload(self) -> None:
            pass
        
        def on_frame_received(self, timestamp, data, formatted):
            return None
        
        def create_tab(self, notebook):
            return None


class RFLinkPlugin(PluginBase):
    """RFLink protocol decoder plugin."""
    
    def __init__(self):
        super().__init__()
        self._info = PluginInfo(
            name="RFLink",
            version="1.1.0",
            author="RS485 Sniffer",
            description="RFLink RF protocol decoder"
        )
    
    @property
    def info(self) -> PluginInfo:
        return self._info
    
    def on_frame_received(self, timestamp: str, data: bytes, 
                          formatted: str) -> Optional[DecodedFrame]:
        """Decode RFLink frames."""
        try:
            text = data.decode('ascii', errors='ignore')
            if not text.startswith('20;'):
                return None
            
            parts = text.split(';')
            if len(parts) < 3:
                return None
            
            protocol = parts[2] if len(parts) > 2 else "Unknown"
            
            fields = [FrameField(name="protocol", value=protocol)]
            
            for part in parts[3:]:
                if '=' in part:
                    key, value = part.split('=', 1)
                    fields.append(FrameField(name=key, value=value))
            
            return DecodedFrame(
                valid=True,
                protocol="RFLink",
                frame_type=protocol,
                fields=fields,
                raw_data=data,
                summary=f"[RFLink] {protocol}: {text}"
            )
        except Exception:
            return None


def get_plugin():
    return RFLinkPlugin()
