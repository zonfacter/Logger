"""
Plugin API for RS485 Sniffer v1.6.6
Provides base classes and interfaces for plugin development.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Any, Dict
import logging

__version__ = "1.2.0"

logger = logging.getLogger("PluginAPI")


@dataclass
class PluginInfo:
    """Plugin metadata."""
    name: str
    version: str
    author: str = ""
    description: str = ""


@dataclass
class FrameField:
    """Represents a decoded field within a frame."""
    name: str
    value: Any
    description: str = ""
    raw_bytes: bytes = b""


@dataclass
class DecodedFrame:
    """Result of frame decoding."""
    valid: bool
    protocol: str
    frame_type: str = ""
    fields: List[FrameField] = field(default_factory=list)
    raw_data: bytes = b""
    summary: str = ""
    error: str = ""
    
    def get_field(self, name: str) -> Optional[FrameField]:
        """Get field by name."""
        for f in self.fields:
            if f.name == name:
                return f
        return None


class PluginBase(ABC):
    """
    Base class for RS485 Sniffer plugins.
    
    Plugins must inherit from this class and implement:
    - info property: Return PluginInfo with metadata
    - on_frame_received: Process incoming frames
    
    Optional methods:
    - on_load: Called when plugin is loaded
    - on_unload: Called when plugin is unloaded
    - create_tab: Create a GUI tab for the plugin
    - get_pending_frames: Return additional decoded frames (for multi-frame support)
    """
    
    def __init__(self):
        self._gui = None
        self._sniffer = None
    
    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """Return plugin metadata."""
        pass
    
    def on_load(self, gui, sniffer) -> bool:
        """
        Called when plugin is loaded.
        
        Args:
            gui: Reference to the main GUI (SnifferGUI)
            sniffer: Reference to the Sniffer instance
        
        Returns:
            True if loaded successfully, False otherwise
        """
        self._gui = gui
        self._sniffer = sniffer
        return True
    
    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        pass
    
    def on_frame_received(self, timestamp: str, data: bytes, 
                          formatted: str) -> Optional[DecodedFrame]:
        """
        Process a received frame.
        
        Args:
            timestamp: Frame timestamp string
            data: Raw frame bytes
            formatted: Pre-formatted display string
        
        Returns:
            DecodedFrame if frame was decoded, None otherwise
        """
        return None
    
    def get_pending_frames(self) -> List[DecodedFrame]:
        """
        Return additional decoded frames.
        
        This method is called after on_frame_received to get any
        additional frames that were extracted from buffered data.
        Useful for protocols where multiple frames arrive in one chunk.
        
        Returns:
            List of additional DecodedFrame objects
        """
        return []
    
    def create_tab(self, notebook) -> Optional[Any]:
        """
        Create a GUI tab for the plugin.
        
        Args:
            notebook: ttk.Notebook to add tab to
        
        Returns:
            ttk.Frame for the tab, or None if no tab needed
        """
        return None
    
    def log(self, message: str) -> None:
        """Log a message with plugin name prefix."""
        logger.info(f"[{self.info.name}] {message}")
    
    def send_data(self, data: bytes) -> bool:
        """
        Send data via the sniffer.
        
        Args:
            data: Raw bytes to send
        
        Returns:
            True if sent successfully
        """
        if self._sniffer and hasattr(self._sniffer, 'send'):
            self._sniffer.send(data)
            return True
        return False


def get_plugin():
    """
    Plugin entry point.
    
    Every plugin module must define this function.
    It should return an instance of the plugin class.
    """
    raise NotImplementedError("Plugins must implement get_plugin()")
