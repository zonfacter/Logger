# RS485 Sniffer v1.6.2

## 🆕 New in v1.6.2: Newline Display Options

Configure how CR/LF characters are displayed in ASCII view:

| Mode | CR LF Display | Example | Description |
|------|---------------|---------|-------------|
| **dots** | `..` | `Hello..World` | Standard - compact view |
| **symbols** | `↵` | `Hello↵World` | Unicode symbols for visual recognition |
| **escape** | `\r\n` | `Hello\r\nWorld` | Escape sequences like in code |
| **hidden** | (nothing) | `HelloWorld` | CR/LF not shown |

### Settings Location
**Settings → Display → ASCII Display Options → Newline Display**

### Display Mode Lock 🔒
- Newline options are **disabled** when Display Mode = "HEX"
- Switch to "ASCII" or "Both" to enable newline options
- Visual indicator shows lock status

### Live Preview
Settings dialog shows a live preview of how CR/LF will be displayed.

## 📦 Package Contents

```
RS485_Sniffer_v1.6.2/
├── rs485_sniffer_v1.6.2.py      # Main application
├── rs485_sniffer_v1.6.2.spec    # PyInstaller config
├── build_exe.bat                 # Build script
├── plugins/
│   ├── rflink/                   # RFLink plugin
│   │   ├── __init__.py
│   │   └── rflink_plugin.py
│   └── hausbus/                  # HausBus plugin
│       ├── __init__.py
│       └── hausbus_plugin.py
└── README.md
```

## 🚀 Quick Start

### Run from Python
```cmd
pip install pyserial
python rs485_sniffer_v1.6.2.py
```

### Build EXE
```cmd
pip install pyinstaller pyserial
build_exe.bat
```

## Changelog

### v1.6.2 (2025-01-14)
- Added: Newline display mode options (dots/symbols/escape/hidden)
- Added: Settings UI for ASCII display options with live preview
- Added: Display mode lock (newline options disabled in HEX mode)
- Added: TAB character handling in ASCII display
- Improved: CR+LF combined handling for cleaner display

### v1.6.1 (2025-01-14)
- Added: Plugin Manager UI tab
- Added: Telegram length display (e.g., "RX (128B):")
- Fixed: Plugin loading

### v1.6.0 (2025-01-14)
- Added: Integrated Statistics Panel
- Added: Enhanced Send Panel
- Added: Log Export
