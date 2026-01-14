#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RS485 Sniffer - Plugin API v1.1.0
Provides base classes and plugin management for extending the sniffer.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import os
import sys
import importlib
import importlib.util


@dataclass
class PluginInfo:
    """Plugin metadata container."""
    name: str
    version: str
    author: str = "Unknown"
    description: str = ""


class PluginBase(ABC):
    """Abstract base class for all plugins."""
    
    def __init__(self):
        self._enabled: bool = True
        self._gui = None
        self._sniffer = None
        self._config: Dict[str, Any] = {}
    
    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """Return plugin metadata."""
        pass
    
    @property
    def enabled(self) -> bool:
        return self._enabled
    
    @enabled.setter
    def enabled(self, value: bool):
        self._enabled = value
    
    def on_load(self, gui, sniffer) -> bool:
        """Called when plugin is loaded. Return True on success."""
        self._gui = gui
        self._sniffer = sniffer
        return True
    
    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        pass
    
    def on_start(self) -> None:
        """Called when sniffer starts."""
        pass
    
    def on_stop(self) -> None:
        """Called when sniffer stops."""
        pass
    
    def on_frame_received(self, timestamp: str, data: bytes, formatted: str) -> Optional[str]:
        """
        Called for each received frame.
        Return modified string or None for default.
        """
        return None
    
    def on_frame_sent(self, timestamp: str, data: bytes) -> None:
        """Called when data is sent."""
        pass
    
    def create_tab(self, notebook) -> Optional[Any]:
        """Create a tab in the main notebook. Return frame or None."""
        return None
    
    def create_menu(self, menubar) -> Optional[Any]:
        """Create a menu entry. Return menu or None."""
        return None
    
    def get_config(self) -> Dict[str, Any]:
        """Return plugin configuration for saving."""
        return self._config
    
    def set_config(self, config: Dict[str, Any]) -> None:
        """Load saved configuration."""
        self._config = config


class ProtocolDecoder(ABC):
    """Base class for protocol decoders."""
    
    @abstractmethod
    def decode(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Decode raw bytes to structured data."""
        pass
    
    def encode(self, message: Dict[str, Any]) -> Optional[bytes]:
        """Encode structured data to bytes."""
        return None


class PluginManager:
    """Manages plugin discovery, loading, and lifecycle."""
    
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, PluginBase] = {}
        self._gui = None
        self._sniffer = None
        
        # Ensure plugin directory exists
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir, exist_ok=True)
            print(f"[PluginManager] Created plugin directory: {self.plugin_dir}")
        
        # Add to Python path
        abs_plugin_dir = os.path.abspath(self.plugin_dir)
        if abs_plugin_dir not in sys.path:
            sys.path.insert(0, abs_plugin_dir)
            print(f"[PluginManager] Added to path: {abs_plugin_dir}")
    
    def set_references(self, gui, sniffer):
        """Set GUI and sniffer references for plugins."""
        self._gui = gui
        self._sniffer = sniffer
    
    def discover_plugins(self) -> List[str]:
        """Discover available plugins in the plugin directory."""
        discovered = []
        
        if not os.path.exists(self.plugin_dir):
            return discovered
        
        print(f"[PluginManager] Scanning: {os.path.abspath(self.plugin_dir)}")
        
        for item in os.listdir(self.plugin_dir):
            item_path = os.path.join(self.plugin_dir, item)
            
            # Package plugin (directory with __init__.py)
            if os.path.isdir(item_path):
                init_file = os.path.join(item_path, "__init__.py")
                if os.path.exists(init_file):
                    discovered.append(item)
                    print(f"[PluginManager] Found package plugin: {item}")
                else:
                    print(f"[PluginManager] Skipping {item} (no __init__.py)")
            
            # Single-file plugin
            elif item.endswith("_plugin.py"):
                name = item[:-3]  # Remove .py
                discovered.append(name)
                print(f"[PluginManager] Found file plugin: {name}")
        
        return discovered
    
    def load_plugin(self, name: str) -> bool:
        """Load a plugin by name."""
        if name in self.plugins:
            print(f"[PluginManager] Plugin already loaded: {name}")
            return True
        
        try:
            print(f"[PluginManager] Loading plugin: {name}")
            
            # Try to import the module
            module = importlib.import_module(name)
            
            # Reload to get fresh version
            module = importlib.reload(module)
            
            # Find PluginBase subclass
            plugin_class = None
            
            # First check __all__ if defined
            if hasattr(module, "__all__"):
                for export_name in module.__all__:
                    attr = getattr(module, export_name, None)
                    if attr and isinstance(attr, type) and issubclass(attr, PluginBase) and attr is not PluginBase:
                        plugin_class = attr
                        break
            
            # Otherwise scan all attributes
            if not plugin_class:
                for attr_name in dir(module):
                    if attr_name.startswith("_"):
                        continue
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, PluginBase) and attr is not PluginBase:
                        plugin_class = attr
                        break
            
            if not plugin_class:
                print(f"[PluginManager] No PluginBase subclass found in {name}")
                return False
            
            # Instantiate plugin
            plugin = plugin_class()
            plugin._gui = self._gui
            plugin._sniffer = self._sniffer
            
            # Call on_load
            if plugin.on_load(self._gui, self._sniffer):
                self.plugins[name] = plugin
                print(f"[PluginManager] Loaded: {plugin.info.name} v{plugin.info.version}")
                return True
            else:
                print(f"[PluginManager] Plugin {name} on_load() returned False")
                return False
                
        except ImportError as e:
            print(f"[PluginManager] Import error for {name}: {e}")
            import traceback
            traceback.print_exc()
            return False
        except Exception as e:
            print(f"[PluginManager] Error loading {name}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin."""
        if name not in self.plugins:
            return False
        
        try:
            self.plugins[name].on_unload()
            del self.plugins[name]
            print(f"[PluginManager] Unloaded: {name}")
            return True
        except Exception as e:
            print(f"[PluginManager] Error unloading {name}: {e}")
            return False
    
    def get_plugin(self, name: str) -> Optional[PluginBase]:
        """Get a loaded plugin by name."""
        return self.plugins.get(name)
    
    def notify_start(self):
        """Notify all plugins that sniffer started."""
        for plugin in self.plugins.values():
            if plugin.enabled:
                try:
                    plugin.on_start()
                except Exception as e:
                    print(f"[PluginManager] Error in on_start: {e}")
    
    def notify_stop(self):
        """Notify all plugins that sniffer stopped."""
        for plugin in self.plugins.values():
            if plugin.enabled:
                try:
                    plugin.on_stop()
                except Exception as e:
                    print(f"[PluginManager] Error in on_stop: {e}")
    
    def notify_frame_received(self, timestamp: str, data: bytes, formatted: str) -> str:
        """Notify all plugins of received frame. Returns possibly modified string."""
        result = formatted
        for plugin in self.plugins.values():
            if plugin.enabled:
                try:
                    modified = plugin.on_frame_received(timestamp, data, result)
                    if modified is not None:
                        result = modified
                except Exception as e:
                    print(f"[PluginManager] Error in on_frame_received: {e}")
        return result
