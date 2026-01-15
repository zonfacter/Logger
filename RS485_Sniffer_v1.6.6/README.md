# RS485 Sniffer v1.6.6

## Übersicht
RS485 Sniffer ist ein professionelles Tool zum Überwachen und Analysieren von RS485-Kommunikation.

## Neue Features in v1.6.6

### CRITICAL FIX: Multi-Frame Support
- Plugins können jetzt `get_pending_frames()` implementieren
- Mehrere Telegramme in einem Chunk werden korrekt verarbeitet
- Frame-Buffering für fragmentierte Daten

### Verbesserungen
- Besseres Plugin Error-Handling mit detailliertem Logging
- Aktualisiertes HausBus Plugin v1.2.0 mit Frame-Buffering

## Installation

### Standalone (Python)
```bash
pip install pyserial
python rs485_sniffer_v1.6.6.py
```

### Als EXE kompilieren
```bash
pip install pyinstaller
pyinstaller rs485_sniffer.spec
```

## Plugin-Installation

1. Erstelle einen `plugins` Ordner neben der EXE/Script
2. Kopiere Plugin-Dateien in den Ordner:
   - `plugins/hausbus_plugin.py`
   - `plugins/rflink_plugin.py`
3. Starte den Sniffer neu

## Plugin-Entwicklung

### Minimal-Plugin
```python
from plugin_api import PluginBase, PluginInfo, DecodedFrame

class MyPlugin(PluginBase):
    @property
    def info(self):
        return PluginInfo(name="MyPlugin", version="1.0.0")
    
    def on_frame_received(self, timestamp, data, formatted):
        # Decode frame here
        return None
    
    def get_pending_frames(self):
        # Return additional frames if multiple in buffer
        return []

def get_plugin():
    return MyPlugin()
```

## Changelog

### v1.6.6 (2025-01-15)
- CRITICAL FIX: Multi-frame support for plugins (get_pending_frames)
- CRITICAL FIX: Correct handling of multiple telegrams in single chunk
- Added: Plugin pending frames processing after on_frame_received
- Improved: Better plugin error handling with detailed logging

### v1.6.5 (2025-01-15)
- Minor improvements

### v1.6.4 (2025-01-15)
- Bug fixes

## Lizenz
MIT License
