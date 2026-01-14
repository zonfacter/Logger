"""
RFLink Plugin v1.0.0
Dekodiert RFLink-Protokoll, Geraete-Verwaltung, Signalanalyse
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, Any, List
import sys
import os
import re

# Import plugin API from parent directory
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from plugin_api import PluginBase, PluginInfo, ProtocolDecoder


class RFLinkDecoder(ProtocolDecoder):
    """RFLink Protocol Decoder"""
    
    PROTOCOLS = {
        "Oregon": "Oregon Scientific",
        "Kaku": "KlikAanKlikUit",
        "NewKaku": "New KlikAanKlikUit",
        "HomeEasy": "HomeEasy EU",
        "FA500": "Flamingo FA500",
        "Eurodomest": "Eurodomest",
        "Blyss": "Blyss",
        "Conrad": "Conrad RSL",
        "Kambrook": "Kambrook",
        "X10": "X10",
        "Philips": "Philips SBC",
        "Energenie": "Energenie",
        "GDR2": "GDR2",
        "Chuango": "Chuango Security",
        "Auriol": "Auriol",
        "Alecto": "Alecto",
        "Cresta": "Cresta",
        "UPM": "UPM/Esic",
        "TFA": "TFA",
        "LaCrosse": "LaCrosse",
        "DKW2012": "DKW2012",
        "Mebus": "Mebus",
        "Xiron": "Xiron",
        "Prologue": "Prologue",
        "Rubicson": "Rubicson",
        "Imagintronix": "Imagintronix",
        "Mertik": "Mertik Maxitrol",
        "Selectplus": "SelectPlus",
        "Byron": "Byron Doorbell",
        "Pir": "PIR Sensor",
        "Smoke": "Smoke Detector",
    }
    
    def __init__(self):
        self.pattern = re.compile(r"^20;([0-9A-F]{2});([^;]+);(.*)$")
    
    def decode(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Decode RFLink message"""
        try:
            text = data.decode("ascii", errors="ignore").strip()
        except:
            return None
        
        if not text.startswith("20;"):
            return None
        
        match = self.pattern.match(text)
        if not match:
            return None
        
        seq = match.group(1)
        protocol = match.group(2)
        params_str = match.group(3)
        
        params = {}
        for part in params_str.split(";"):
            if "=" in part:
                key, val = part.split("=", 1)
                params[key] = val
            elif part:
                params[part] = True
        
        return {
            "raw": text,
            "sequence": seq,
            "protocol": protocol,
            "protocol_name": self.PROTOCOLS.get(protocol, protocol),
            "params": params,
            "id": params.get("ID", ""),
            "switch": params.get("SWITCH", params.get("SMOKEALERT", "")),
            "cmd": params.get("CMD", ""),
            "temp": self._parse_temp(params.get("TEMP")),
            "hum": params.get("HUM"),
            "batt": params.get("BAT"),
        }
    
    def _parse_temp(self, temp_hex: Optional[str]) -> Optional[float]:
        if not temp_hex:
            return None
        try:
            val = int(temp_hex, 16)
            if val & 0x8000:
                val = -(val & 0x7FFF)
            return val / 10.0
        except:
            return None
    
    def encode(self, message: Dict[str, Any]) -> Optional[bytes]:
        """Encode RFLink command"""
        protocol = message.get("protocol", "")
        device_id = message.get("id", "")
        switch = message.get("switch", "1")
        cmd = message.get("cmd", "ON")
        
        if not protocol or not device_id:
            return None
        
        command = f"10;{protocol};{device_id};{switch};{cmd};\r\n"
        return command.encode("ascii")
    
    def format_decoded(self, decoded: Dict[str, Any]) -> str:
        if not decoded:
            return ""
        
        parts = [f"[RF {decoded['protocol_name']}"]
        
        if decoded.get("id"):
            parts.append(f"ID:{decoded['id']}")
        if decoded.get("switch"):
            parts.append(f"SW:{decoded['switch']}")
        if decoded.get("cmd"):
            parts.append(f"CMD:{decoded['cmd']}")
        if decoded.get("temp") is not None:
            parts.append(f"T:{decoded['temp']:.1f}C")
        if decoded.get("hum"):
            parts.append(f"H:{decoded['hum']}%")
        if decoded.get("batt"):
            parts.append(f"BAT:{decoded['batt']}")
        
        return " ".join(parts) + "]"


class RFLinkPlugin(PluginBase):
    """RFLink Integration Plugin"""
    
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="RFLink",
            version="1.0.0",
            author="RFLink Team",
            description="RFLink Gateway Protokoll Decoder und Geraete-Manager"
        )
    
    def __init__(self):
        super().__init__()
        self.decoder = RFLinkDecoder()
        self.devices: Dict[str, Dict] = {}
        self.tab_frame = None
        self.tree = None
        self.signal_history: List[Dict] = []
        self.max_history = 100
    
    def on_load(self, gui, sniffer) -> bool:
        self._gui = gui
        self._sniffer = sniffer
        self.devices = {}
        self.signal_history = []
        print(f"[RFLink] Plugin v{self.info.version} geladen")
        return True
    
    def on_unload(self) -> None:
        self.devices.clear()
        self.signal_history.clear()
        print("[RFLink] Plugin entladen")
    
    def on_start(self) -> None:
        pass
    
    def on_frame_received(self, timestamp: str, data: bytes, formatted: str):
        decoded = self.decoder.decode(data)
        if decoded:
            device_key = f"{decoded['protocol']}_{decoded['id']}"
            
            if device_key and decoded['id']:
                if device_key not in self.devices:
                    self.devices[device_key] = {
                        "protocol": decoded["protocol"],
                        "protocol_name": decoded["protocol_name"],
                        "id": decoded["id"],
                        "first_seen": timestamp,
                        "rx_count": 0,
                        "last_temp": None,
                        "last_hum": None,
                        "last_cmd": "",
                        "last_switch": "",
                    }
                
                dev = self.devices[device_key]
                dev["rx_count"] += 1
                dev["last_seen"] = timestamp
                
                if decoded.get("temp") is not None:
                    dev["last_temp"] = decoded["temp"]
                if decoded.get("hum"):
                    dev["last_hum"] = decoded["hum"]
                if decoded.get("cmd"):
                    dev["last_cmd"] = decoded["cmd"]
                if decoded.get("switch"):
                    dev["last_switch"] = decoded["switch"]
            
            self.signal_history.append({
                "timestamp": timestamp,
                "decoded": decoded
            })
            if len(self.signal_history) > self.max_history:
                self.signal_history.pop(0)
            
            extra = self.decoder.format_decoded(decoded)
            return f"{formatted} {extra}"
        return None
    
    def create_tab(self, notebook) -> tk.Frame:
        self.tab_frame = ttk.Frame(notebook)
        
        nb = ttk.Notebook(self.tab_frame)
        nb.pack(fill="both", expand=True, padx=5, pady=5)
        
        dev_frame = ttk.Frame(nb)
        nb.add(dev_frame, text="Geraete")
        
        lf = ttk.LabelFrame(dev_frame, text="Erkannte RF-Geraete")
        lf.pack(fill="both", expand=True, padx=5, pady=5)
        
        cols = ("Protokoll", "ID", "Switch", "Temp", "Hum", "Letzter Befehl", "RX", "Zuletzt")
        self.tree = ttk.Treeview(lf, columns=cols, show="headings", height=12)
        
        widths = [100, 80, 60, 60, 50, 80, 50, 100]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w)
        
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        
        bf = ttk.Frame(dev_frame)
        bf.pack(fill="x", padx=5, pady=5)
        ttk.Button(bf, text="Aktualisieren", command=self.refresh_device_list).pack(side="left", padx=5)
        ttk.Button(bf, text="Liste loeschen", command=self.clear_devices).pack(side="left", padx=5)
        
        ctrl_frame = ttk.Frame(nb)
        nb.add(ctrl_frame, text="Steuerung")
        
        sf = ttk.LabelFrame(ctrl_frame, text="Befehl senden")
        sf.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(sf, text="Protokoll:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.proto_var = tk.StringVar(value="NewKaku")
        proto_combo = ttk.Combobox(sf, textvariable=self.proto_var,
                                    values=list(self.decoder.PROTOCOLS.keys()), width=15)
        proto_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(sf, text="ID:").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.id_var = tk.StringVar(value="123456")
        ttk.Entry(sf, textvariable=self.id_var, width=12).grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(sf, text="Switch:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.switch_var = tk.StringVar(value="1")
        ttk.Entry(sf, textvariable=self.switch_var, width=6).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(sf, text="Befehl:").grid(row=1, column=2, padx=5, pady=5, sticky="e")
        self.cmd_var = tk.StringVar(value="ON")
        cmd_combo = ttk.Combobox(sf, textvariable=self.cmd_var,
                                  values=["ON", "OFF", "ALLON", "ALLOFF", "UP", "DOWN", "STOP"], width=10)
        cmd_combo.grid(row=1, column=3, padx=5, pady=5)
        
        ttk.Button(sf, text="Senden", command=self.send_command).grid(row=2, column=0, columnspan=4, pady=10)
        
        self.schedule_refresh()
        return self.tab_frame
    
    def schedule_refresh(self):
        if self.tab_frame and self.tab_frame.winfo_exists():
            self.refresh_device_list()
            self.tab_frame.after(3000, self.schedule_refresh)
    
    def refresh_device_list(self):
        if not self.tree:
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        for key, dev in sorted(self.devices.items()):
            temp_str = f"{dev['last_temp']:.1f}C" if dev.get('last_temp') is not None else ""
            hum_str = f"{dev['last_hum']}%" if dev.get('last_hum') else ""
            self.tree.insert("", "end", values=(
                dev.get("protocol_name", ""),
                dev.get("id", ""),
                dev.get("last_switch", ""),
                temp_str,
                hum_str,
                dev.get("last_cmd", ""),
                dev.get("rx_count", 0),
                dev.get("last_seen", "")
            ), tags=(key,))
    
    def clear_devices(self):
        self.devices.clear()
        self.refresh_device_list()
    
    def send_command(self):
        frame = self.decoder.encode({
            "protocol": self.proto_var.get(),
            "id": self.id_var.get(),
            "switch": self.switch_var.get(),
            "cmd": self.cmd_var.get()
        })
        
        if frame and self._sniffer and self._sniffer.ser and self._sniffer.ser.is_open:
            self._sniffer.ser.write(frame)
            if self._gui:
                self._gui.queue_msg(f"[RFLink] Befehl gesendet: {frame.decode('ascii').strip()}")
        else:
            if self._gui:
                self._gui.queue_msg("[RFLink] Port nicht offen!")
    
    def get_config(self) -> dict:
        return {"max_history": self.max_history}
    
    def set_config(self, config: dict):
        self.max_history = config.get("max_history", 100)
