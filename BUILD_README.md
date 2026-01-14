# RS485 Sniffer v1.5.1 - Build Instructions

## Voraussetzungen

```bash
pip install pyserial pyinstaller
```

## Build-Optionen

### Option A: Directory Build (EMPFOHLEN)

```bash
pyinstaller rs485_sniffer.spec
```

Ergebnis:
```
dist/
    RS485_Sniffer/
        RS485_Sniffer.exe
        plugin_api.py
        ...DLLs...
```

Nach dem Build:
1. Kopiere den `plugins/` Ordner nach `dist/RS485_Sniffer/`
2. Optional: Kopiere `config.json` nach `dist/RS485_Sniffer/`

### Option B: Single File Build

```bash
pyinstaller --noconsole --onefile rs485_sniffer_v1.5.1.py
```

Ergebnis:
```
dist/
    rs485_sniffer_v1.5.1.exe
```

Nach dem Build - Erstelle diese Struktur:
```
MeinOrdner/
    RS485_Sniffer.exe
    plugin_api.py          <- WICHTIG: Muss neben der EXE liegen!
    config.json            <- Wird automatisch erstellt
    plugins/
        hausbus/
            __init__.py
            hausbus_plugin.py
        rflink/
            __init__.py
            rflink_plugin.py
```

## Verzeichnisstruktur (Entwicklung)

```
rs485_sniffer_v1.5.1.py    <- Hauptprogramm
plugin_api.py              <- Plugin API
rs485_sniffer.spec         <- PyInstaller Konfiguration
config.json                <- Konfiguration (wird erstellt)
plugins/
    __init__.py
    hausbus/
        __init__.py
        hausbus_plugin.py
    rflink/
        __init__.py
        rflink_plugin.py
```

## Debugging

Für Debug-Ausgaben im Terminal:
- Ändere in der .spec Datei: `console=True`
- Oder baue mit: `pyinstaller --console --onefile rs485_sniffer_v1.5.1.py`

## Troubleshooting

### "Plugin API not found"
- Stelle sicher, dass `plugin_api.py` im selben Ordner wie die EXE liegt

### "No plugins found"
- Prüfe, ob der `plugins/` Ordner existiert
- Prüfe, ob jedes Plugin-Unterverzeichnis eine `__init__.py` hat

### Import-Fehler in Plugins
- Plugins müssen `from plugin_api import PluginBase, PluginInfo` verwenden
- Nicht: `from .plugin_api import ...`
