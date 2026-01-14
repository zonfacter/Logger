# RS485 Sniffer v1.6.1

## New Features in v1.6.1

### 🔌 Plugin Manager UI
- New "Plugin Manager" tab in the application
- View all discovered plugins with version info
- Enable/Disable plugins at runtime
- "Open Plugins Folder" button
- "Refresh" button to rescan plugins

### 📏 Telegram Length Display
- Terminal now shows byte count for each message
- Format: `[12:34:56] RX (128B): 02 48 65 6C 6C 6F...`

### 🔧 Plugin Loading Fixes
- Fixed plugin class detection
- Plugins no longer require external imports
- Each plugin is now fully standalone

## Installation

1. Install Python 3.7+ (3.9 for Windows 7)
2. Install pyserial: `pip install pyserial`
3. Extract ZIP to a folder
4. Run: `python rs485_sniffer_v1.6.1.py`

## Included Plugins

### RFLink Plugin v1.1.0
- Decodes RFLink RF gateway protocol
- Shows discovered devices
- Message log with decoded fields

### HausBus Plugin v1.1.0
- Decodes HausBus home automation protocol
- Frame format: STX LEN DST SRC TYPE DATA CRC ETX
- Device registry with message count

## Plugin Development

Plugins are standalone Python modules. Each plugin must:
1. Have an `info` property returning `PluginInfo`
2. Have `on_load(gui, sniffer)` method
3. Optionally have `create_tab(notebook)` method

See included plugins for examples.

## Changelog

### v1.6.1 (2025-01-14)
- Added: Plugin Manager UI tab
- Added: Telegram length display in terminal
- Fixed: Plugin loading and class detection
- Fixed: Plugins are now standalone (no external imports)

### v1.6.0 (2025-01-14)
- Added: Integrated Statistics Panel
- Added: Enhanced Send Panel with preview
- Added: Log Export (.txt, .csv, .log)
- Added: Start/End Byte configuration
