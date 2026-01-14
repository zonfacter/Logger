# Changelog

## [1.6.1] - 2025-01-14

### Added
- Plugin Manager UI tab (enable/disable/version info)
- Telegram length display in terminal (e.g., "RX (128B):")
- "Open Plugins Folder" button
- "Refresh Plugins" button

### Fixed
- Plugin loading - improved class detection
- Plugin path handling for imports
- Plugins are now fully standalone (no external imports needed)

### Changed
- RFLink Plugin v1.1.0 - standalone version
- HausBus Plugin v1.1.0 - standalone version

## [1.6.0] - 2025-01-14

### Added
- Integrated Statistics Panel (RX/TX frames, bytes, errors, uptime)
- Enhanced Send Panel with live preview
- Log Export with format selection (.txt, .csv, .log)
- Start/End Byte configuration in Settings
- Statistics reset button
- Quick send buttons (ACK, NAK, ENQ, EOT, STX, ETX)

## [1.5.2] - 2025-01-13

### Fixed
- HEX input parsing with parse_hex_input()
- Frame building with build_frame_bytes()
- UTF-8 encoding issues on Windows 7
