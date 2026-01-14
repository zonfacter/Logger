"""
HausBus Plugin v1.0.0
Dekodiert HausBus-Protokoll, Netzwerk-Scanner, Status-Abfrage
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, Any
import sys
import os

# Import plugin API from parent directory
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from plugin_api import PluginBase, PluginInfo, ProtocolDecoder


class HausBusDecoder(ProtocolDecoder):
    """HausBus Protocol Decoder"""
    
    COMMANDS = {
        0x01: "GET_STATUS",
        0x02: "SET_CFG",
        0x03: "GET_CFG",
        0x04: "SAVE_CFG",
        0x05: "RESET",
        0x10: "SCAN",
        0x11: "PING",
        0x12: "PONG",
        0x20: "DATA",
        0x21: "ACK",
        0x22: "NACK",
        0xFE: "BOOTLOADER",
        0xFF: "BROADCAST",
    }
    
    def __init__(self, start_byte: int = 0xFE):
        self.start_byte = start_byte
    
    def decode(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Decode HausBus frame"""
        if len(data) < 5:
            return None
        
        if data[0] != self.start_byte:
            return None
        
        length = data[1]
        if len(data) < length + 2:
            return None
        
        calc_checksum = sum(data[:-1]) & 0xFF
        frame_checksum = data[-1]
        
        return {
            "valid": calc_checksum == frame_checksum,
            "start": data[0],
            "length": length,
            "dest_addr": data[2],
            "src_addr": data[3],
            "command": data[4],
            "command_name": self.COMMANDS.get(data[4], f"CMD_{data[4]:02X}"),
            "payload": data[5:-1] if len(data) > 6 else b"",
            "checksum": frame_checksum,
            "checksum_calc": calc_checksum,
        }
    
    def encode(self, message: Dict[str, Any]) -> Optional[bytes]:
        """Encode HausBus frame"""
        dest = message.get("dest_addr", 0xFF)
        src = message.get("src_addr", 0x00)
        cmd = message.get("command", 0x10)
        payload = message.get("payload", b"")
        
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        
        length = 3 + len(payload)
        frame = bytes([self.start_byte, length, dest, src, cmd]) + payload
        checksum = sum(frame) & 0xFF
        
        return frame + bytes([checksum])
    
    def format_decoded(self, decoded: Dict[str, Any]) -> str:
        if not decoded:
            return ""
        valid = "OK" if decoded["valid"] else "CRC!"
        return (f"[HB {decoded['command_name']} "
                f"D:{decoded['dest_addr']:02X} S:{decoded['src_addr']:02X} ({valid})]")


class HausBusPlugin(PluginBase):
    """HausBus Integration Plugin"""
    
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="HausBus",
            version="1.0.0",
            author="HausBus Team",
            description="HausBus Protokoll Decoder, Scanner und Konfigurator"
        )
    
    def __init__(self):
        super().__init__()
        self.decoder = HausBusDecoder()
        self.devices: Dict[int, Dict] = {}
        self.my_address = 0x00
        self.tab_frame = None
        self.tree = None
    
    def on_load(self, gui, sniffer) -> bool:
        self._gui = gui
        self._sniffer = sniffer
        self.devices = {}
        print(f"[HausBus] Plugin v{self.info.version} geladen")
        return True
    
    def on_unload(self) -> None:
        self.devices.clear()
        print("[HausBus] Plugin entladen")
    
    def on_start(self) -> None:
        self.devices.clear()
        if self.tree:
            self.refresh_device_list()
    
    def on_frame_received(self, timestamp: str, data: bytes, formatted: str):
        decoded = self.decoder.decode(data)
        if decoded:
            src = decoded["src_addr"]
            if src != 0x00 and src != 0xFF:
                if src not in self.devices:
                    self.devices[src] = {
                        "first_seen": timestamp,
                        "rx_count": 0,
                        "tx_count": 0,
                        "last_cmd": "",
                        "status": "Online"
                    }
                self.devices[src]["rx_count"] += 1
                self.devices[src]["last_seen"] = timestamp
                self.devices[src]["last_cmd"] = decoded["command_name"]
            
            extra = self.decoder.format_decoded(decoded)
            return f"{formatted} {extra}"
        return None
    
    def on_frame_sent(self, timestamp: str, data: bytes) -> None:
        decoded = self.decoder.decode(data)
        if decoded:
            dest = decoded["dest_addr"]
            if dest in self.devices:
                self.devices[dest]["tx_count"] += 1
    
    def create_tab(self, notebook) -> tk.Frame:
        self.tab_frame = ttk.Frame(notebook)
        
        lf = ttk.LabelFrame(self.tab_frame, text="Gefundene Geraete")
        lf.pack(fill="both", expand=True, padx=10, pady=5)
        
        cols = ("Adresse", "Status", "RX", "TX", "Letzter Befehl", "Zuletzt gesehen")
        self.tree = ttk.Treeview(lf, columns=cols, show="headings", height=10)
        
        widths = [80, 80, 60, 60, 120, 120]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w)
        
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        
        bf = ttk.Frame(self.tab_frame)
        bf.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(bf, text="Netzwerk scannen", command=self.scan_network).pack(side="left", padx=5)
        ttk.Button(bf, text="Ping", command=self.ping_selected).pack(side="left", padx=5)
        ttk.Button(bf, text="Status abfragen", command=self.query_status).pack(side="left", padx=5)
        ttk.Button(bf, text="Aktualisieren", command=self.refresh_device_list).pack(side="right", padx=5)
        
        sf = ttk.LabelFrame(self.tab_frame, text="Befehl senden")
        sf.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(sf, text="Ziel:").grid(row=0, column=0, padx=5, pady=5)
        self.dest_var = tk.StringVar(value="FF")
        ttk.Entry(sf, textvariable=self.dest_var, width=6).grid(row=0, column=1, padx=5)
        
        ttk.Label(sf, text="Befehl:").grid(row=0, column=2, padx=5)
        self.cmd_var = tk.StringVar(value="GET_STATUS")
        cmd_combo = ttk.Combobox(sf, textvariable=self.cmd_var, 
                                  values=list(self.decoder.COMMANDS.values()), width=15)
        cmd_combo.grid(row=0, column=3, padx=5)
        
        ttk.Label(sf, text="Payload (Hex):").grid(row=0, column=4, padx=5)
        self.payload_var = tk.StringVar()
        ttk.Entry(sf, textvariable=self.payload_var, width=30).grid(row=0, column=5, padx=5)
        
        ttk.Button(sf, text="Senden", command=self.send_command).pack(side="right", padx=10, pady=5)
        
        self.schedule_refresh()
        return self.tab_frame
    
    def schedule_refresh(self):
        if self.tab_frame and self.tab_frame.winfo_exists():
            self.refresh_device_list()
            self.tab_frame.after(2000, self.schedule_refresh)
    
    def refresh_device_list(self):
        if not self.tree:
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        for addr, info in sorted(self.devices.items()):
            self.tree.insert("", "end", values=(
                f"0x{addr:02X}",
                info.get("status", "?"),
                info.get("rx_count", 0),
                info.get("tx_count", 0),
                info.get("last_cmd", ""),
                info.get("last_seen", "")
            ), tags=(str(addr),))
    
    def get_selected_address(self) -> Optional[int]:
        sel = self.tree.selection()
        if sel:
            addr_str = self.tree.item(sel[0])["values"][0]
            return int(addr_str, 16)
        return None
    
    def scan_network(self):
        frame = self.decoder.encode({
            "dest_addr": 0xFF,
            "src_addr": self.my_address,
            "command": 0x10
        })
        self._send_frame(frame, "Netzwerk-Scan")
    
    def ping_selected(self):
        addr = self.get_selected_address()
        if addr:
            frame = self.decoder.encode({
                "dest_addr": addr,
                "src_addr": self.my_address,
                "command": 0x11
            })
            self._send_frame(frame, f"Ping an 0x{addr:02X}")
    
    def query_status(self):
        addr = self.get_selected_address()
        if addr:
            frame = self.decoder.encode({
                "dest_addr": addr,
                "src_addr": self.my_address,
                "command": 0x01
            })
            self._send_frame(frame, f"Status-Anfrage an 0x{addr:02X}")
    
    def send_command(self):
        try:
            dest = int(self.dest_var.get(), 16)
        except:
            if self._gui:
                self._gui.queue_msg("[HausBus] Ungueltige Zieladresse")
            return
        
        cmd_name = self.cmd_var.get()
        cmd_code = 0x00
        for code, name in self.decoder.COMMANDS.items():
            if name == cmd_name:
                cmd_code = code
                break
        
        payload = b""
        payload_hex = self.payload_var.get().replace(" ", "")
        if payload_hex:
            try:
                payload = bytes.fromhex(payload_hex)
            except:
                if self._gui:
                    self._gui.queue_msg("[HausBus] Ungueltiger Payload")
                return
        
        frame = self.decoder.encode({
            "dest_addr": dest,
            "src_addr": self.my_address,
            "command": cmd_code,
            "payload": payload
        })
        self._send_frame(frame, f"{cmd_name} an 0x{dest:02X}")
    
    def _send_frame(self, frame: bytes, description: str):
        if frame and self._sniffer and self._sniffer.ser and self._sniffer.ser.is_open:
            self._sniffer.ser.write(frame)
            if self._gui:
                self._gui.queue_msg(f"[HausBus] {description} gesendet")
        else:
            if self._gui:
                self._gui.queue_msg("[HausBus] Port nicht offen!")
    
    def get_config(self) -> dict:
        return {"my_address": self.my_address}
    
    def set_config(self, config: dict):
        self.my_address = config.get("my_address", 0x00)
