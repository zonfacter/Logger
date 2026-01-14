"""
RFLink RAW Signal Decoder Plugin v1.0.0
Dekodiert RFLink RAW Signale und bietet Logik-Interpreter
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, Any, List
import re

try:
    from plugin_api import PluginBase, PluginInfo
except ImportError:
    import sys
    sys.path.insert(0, "..")
    from plugin_api import PluginBase, PluginInfo


class RFLinkDecoder:
    """RFLink Protocol Decoder"""
    
    # Known protocols
    PROTOCOLS = {
        "Oregon": {"pattern": r"20;[0-9A-F]{2};Oregon", "fields": ["id", "temp", "hum", "bat"]},
        "NewKaku": {"pattern": r"20;[0-9A-F]{2};NewKaku", "fields": ["id", "switch", "cmd"]},
        "Kaku": {"pattern": r"20;[0-9A-F]{2};Kaku", "fields": ["id", "switch", "cmd"]},
        "X10": {"pattern": r"20;[0-9A-F]{2};X10", "fields": ["id", "switch", "cmd"]},
        "HomeEasy": {"pattern": r"20;[0-9A-F]{2};HomeEasy", "fields": ["id", "switch", "cmd"]},
        "FA500": {"pattern": r"20;[0-9A-F]{2};FA500", "fields": ["id", "switch", "cmd"]},
        "Eurodomest": {"pattern": r"20;[0-9A-F]{2};Eurodomest", "fields": ["id", "switch", "cmd"]},
        "Blyss": {"pattern": r"20;[0-9A-F]{2};Blyss", "fields": ["id", "switch", "cmd"]},
        "Conrad": {"pattern": r"20;[0-9A-F]{2};Conrad", "fields": ["id", "switch", "cmd"]},
        "Kambrook": {"pattern": r"20;[0-9A-F]{2};Kambrook", "fields": ["id", "switch", "cmd"]},
    }
    
    def __init__(self):
        self.raw_signals: List[Dict] = []
    
    def decode_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Decode RFLink output line"""
        line = line.strip()
        
        # Check for RFLink format: 20;XX;Protocol;...
        if not line.startswith("20;"):
            return None
        
        parts = line.split(";")
        if len(parts) < 3:
            return None
        
        result = {
            "raw": line,
            "sequence": parts[1],
            "protocol": parts[2] if len(parts) > 2 else "Unknown",
            "fields": {}
        }
        
        # Parse key=value pairs
        for part in parts[3:]:
            if "=" in part:
                key, value = part.split("=", 1)
                result["fields"][key] = value
        
        return result
    
    def decode_raw_pulses(self, raw_data: str) -> List[int]:
        """Decode RAW pulse data"""
        # Format: 20;XX;DEBUG;Pulses=XXX;Pulses(uSec)=...
        pulses = []
        
        match = re.search(r"Pulses\(uSec\)=([0-9,]+)", raw_data)
        if match:
            pulse_str = match.group(1)
            pulses = [int(p) for p in pulse_str.split(",") if p.isdigit()]
        
        return pulses
    
    def analyze_pulses(self, pulses: List[int]) -> Dict[str, Any]:
        """Analyze pulse timing patterns"""
        if not pulses:
            return {"error": "No pulses"}
        
        # Calculate statistics
        short_pulses = [p for p in pulses if p < 500]
        long_pulses = [p for p in pulses if p >= 500]
        
        result = {
            "total_pulses": len(pulses),
            "min_pulse": min(pulses) if pulses else 0,
            "max_pulse": max(pulses) if pulses else 0,
            "avg_pulse": sum(pulses) // len(pulses) if pulses else 0,
            "short_count": len(short_pulses),
            "long_count": len(long_pulses),
        }
        
        # Try to detect encoding
        if short_pulses and long_pulses:
            avg_short = sum(short_pulses) // len(short_pulses) if short_pulses else 0
            avg_long = sum(long_pulses) // len(long_pulses) if long_pulses else 0
            
            ratio = avg_long / avg_short if avg_short > 0 else 0
            
            if 2.5 <= ratio <= 3.5:
                result["encoding"] = "Manchester (1:3)"
            elif 1.8 <= ratio <= 2.2:
                result["encoding"] = "PWM (1:2)"
            else:
                result["encoding"] = f"Unknown (ratio: {ratio:.1f})"
        
        return result
    
    def pulses_to_binary(self, pulses: List[int], threshold: int = 500) -> str:
        """Convert pulses to binary string"""
        binary = ""
        for i in range(0, len(pulses) - 1, 2):
            if pulses[i] < threshold:
                binary += "0"
            else:
                binary += "1"
        return binary


class RFLinkPlugin(PluginBase):
    """RFLink RAW Signal Decoder Plugin"""
    
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="RFLink Decoder",
            version="1.0.0",
            author="RF Team",
            description="RFLink RAW Signal Decoder mit Logik-Interpreter"
        )
    
    def __init__(self):
        super().__init__()
        self.decoder = RFLinkDecoder()
        self.signals: List[Dict] = []
        self.tab_frame = None
        self.signal_tree = None
        self.pulse_text = None
        self.analysis_text = None
    
    def on_load(self, gui, sniffer) -> bool:
        self._gui = gui
        self._sniffer = sniffer
        print(f"[RFLink] Plugin v{self.info.version} geladen")
        return True
    
    def on_unload(self) -> None:
        self.signals.clear()
        print("[RFLink] Plugin entladen")
    
    def on_start(self) -> None:
        self.signals.clear()
        if self.signal_tree:
            self.refresh_signal_list()
    
    def on_frame_received(self, timestamp: str, data: bytes, formatted: str):
        """Process received frame - check for RFLink data"""
        try:
            # Try to decode as ASCII
            text = data.decode("ascii", errors="ignore").strip()
            
            decoded = self.decoder.decode_line(text)
            if decoded:
                decoded["timestamp"] = timestamp
                self.signals.append(decoded)
                
                # Limit history
                if len(self.signals) > 1000:
                    self.signals = self.signals[-500:]
                
                # Enhanced display
                proto = decoded["protocol"]
                fields = ", ".join(f"{k}={v}" for k, v in decoded["fields"].items())
                extra = f" [RF: {proto}] {fields}"
                return formatted + extra
        except:
            pass
        
        return None
    
    def create_tab(self, notebook) -> tk.Frame:
        self.tab_frame = ttk.Frame(notebook)
        
        # Create sub-notebook for different views
        sub_notebook = ttk.Notebook(self.tab_frame)
        sub_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Tab 1: Signal List
        self._create_signal_list_tab(sub_notebook)
        
        # Tab 2: RAW Analyzer
        self._create_raw_analyzer_tab(sub_notebook)
        
        # Tab 3: Protocol Reference
        self._create_protocol_ref_tab(sub_notebook)
        
        return self.tab_frame
    
    def _create_signal_list_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Signale")
        
        # Signal list
        cols = ("Zeit", "Protokoll", "Sequenz", "Daten")
        self.signal_tree = ttk.Treeview(frame, columns=cols, show="headings", height=15)
        
        widths = [100, 100, 80, 400]
        for col, w in zip(cols, widths):
            self.signal_tree.heading(col, text=col)
            self.signal_tree.column(col, width=w)
        
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.signal_tree.yview)
        self.signal_tree.configure(yscrollcommand=sb.set)
        
        self.signal_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        sb.pack(side="right", fill="y", pady=5)
        
        self.signal_tree.bind("<<TreeviewSelect>>", self._on_signal_select)
        
        # Buttons
        bf = ttk.Frame(frame)
        bf.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(bf, text="Aktualisieren", command=self.refresh_signal_list).pack(side="left", padx=5)
        ttk.Button(bf, text="Loeschen", command=self.clear_signals).pack(side="left", padx=5)
        ttk.Button(bf, text="Exportieren", command=self.export_signals).pack(side="right", padx=5)
        
        # Detail view
        detail_frame = ttk.LabelFrame(frame, text="Details")
        detail_frame.pack(fill="x", padx=5, pady=5)
        
        self.detail_text = tk.Text(detail_frame, height=5, font=("Consolas", 9))
        self.detail_text.pack(fill="x", padx=5, pady=5)
    
    def _create_raw_analyzer_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="RAW Analyzer")
        
        # Input
        input_frame = ttk.LabelFrame(frame, text="RAW Pulse Daten eingeben")
        input_frame.pack(fill="x", padx=10, pady=5)
        
        self.pulse_text = tk.Text(input_frame, height=4, font=("Consolas", 9))
        self.pulse_text.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(input_frame, text="Analysieren", command=self.analyze_raw).pack(pady=5)
        
        # Analysis output
        analysis_frame = ttk.LabelFrame(frame, text="Analyse-Ergebnis")
        analysis_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.analysis_text = tk.Text(analysis_frame, font=("Consolas", 9))
        self.analysis_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Visualization
        viz_frame = ttk.LabelFrame(frame, text="Puls-Visualisierung")
        viz_frame.pack(fill="x", padx=10, pady=5)
        
        self.viz_canvas = tk.Canvas(viz_frame, height=100, bg="white")
        self.viz_canvas.pack(fill="x", padx=5, pady=5)
    
    def _create_protocol_ref_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Protokoll-Referenz")
        
        # Protocol list
        text = tk.Text(frame, font=("Consolas", 10))
        text.pack(fill="both", expand=True, padx=10, pady=10)
        
        ref_text = "RFLink Protokoll-Referenz\n"
        ref_text += "=" * 50 + "\n\n"
        
        for proto, info in self.decoder.PROTOCOLS.items():
            ref_text += f"{proto}:\n"
            ref_text += f"  Pattern: {info['pattern']}\n"
            ref_text += f"  Felder: {', '.join(info['fields'])}\n\n"
        
        ref_text += "\nRAW Format:\n"
        ref_text += "-" * 30 + "\n"
        ref_text += "20;XX;DEBUG;Pulses=NNN;Pulses(uSec)=p1,p2,p3,...\n\n"
        ref_text += "Pulse-Encoding:\n"
        ref_text += "  Manchester: Short=1, Long=3 (Ratio ~3:1)\n"
        ref_text += "  PWM: Short=1, Long=2 (Ratio ~2:1)\n"
        
        text.insert("1.0", ref_text)
        text.config(state="disabled")
    
    def _on_signal_select(self, event):
        sel = self.signal_tree.selection()
        if sel and self.signals:
            idx = self.signal_tree.index(sel[0])
            if idx < len(self.signals):
                signal = self.signals[idx]
                self.detail_text.delete("1.0", tk.END)
                
                detail = f"Timestamp: {signal.get('timestamp', 'N/A')}\n"
                detail += f"Protocol: {signal.get('protocol', 'N/A')}\n"
                detail += f"Sequence: {signal.get('sequence', 'N/A')}\n"
                detail += f"Fields:\n"
                for k, v in signal.get("fields", {}).items():
                    detail += f"  {k} = {v}\n"
                detail += f"\nRAW: {signal.get('raw', 'N/A')}"
                
                self.detail_text.insert("1.0", detail)
    
    def refresh_signal_list(self):
        if not self.signal_tree:
            return
        
        for item in self.signal_tree.get_children():
            self.signal_tree.delete(item)
        
        for signal in self.signals[-100:]:  # Show last 100
            fields_str = ", ".join(f"{k}={v}" for k, v in signal.get("fields", {}).items())
            self.signal_tree.insert("", "end", values=(
                signal.get("timestamp", ""),
                signal.get("protocol", ""),
                signal.get("sequence", ""),
                fields_str
            ))
    
    def clear_signals(self):
        self.signals.clear()
        self.refresh_signal_list()
        self.detail_text.delete("1.0", tk.END)
    
    def export_signals(self):
        from tkinter import filedialog
        import json
        
        fn = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")]
        )
        if fn:
            if fn.endswith(".json"):
                with open(fn, "w", encoding="utf-8") as f:
                    json.dump(self.signals, f, indent=2)
            else:
                with open(fn, "w", encoding="utf-8") as f:
                    f.write("Timestamp;Protocol;Sequence;Fields\n")
                    for s in self.signals:
                        fields = ";".join(f"{k}={v}" for k, v in s.get("fields", {}).items())
                        f.write(f"{s.get('timestamp','')};{s.get('protocol','')};{s.get('sequence','')};{fields}\n")
            
            self._gui.queue_msg(f"[RFLink] Exportiert: {fn}")
    
    def analyze_raw(self):
        raw_data = self.pulse_text.get("1.0", tk.END).strip()
        if not raw_data:
            return
        
        self.analysis_text.delete("1.0", tk.END)
        
        # Parse pulses
        pulses = self.decoder.decode_raw_pulses(raw_data)
        
        if not pulses:
            # Try comma-separated values
            try:
                pulses = [int(p.strip()) for p in raw_data.split(",") if p.strip().isdigit()]
            except:
                pass
        
        if not pulses:
            self.analysis_text.insert("1.0", "Keine Pulse-Daten gefunden!\n\nFormat:\n- Pulses(uSec)=100,200,300,...\n- Oder: 100,200,300,...")
            return
        
        # Analyze
        analysis = self.decoder.analyze_pulses(pulses)
        
        result = "Pulse-Analyse\n"
        result += "=" * 40 + "\n\n"
        result += f"Anzahl Pulse: {analysis['total_pulses']}\n"
        result += f"Min: {analysis['min_pulse']} us\n"
        result += f"Max: {analysis['max_pulse']} us\n"
        result += f"Durchschnitt: {analysis['avg_pulse']} us\n"
        result += f"Kurze Pulse (<500us): {analysis['short_count']}\n"
        result += f"Lange Pulse (>=500us): {analysis['long_count']}\n"
        result += f"\nErkanntes Encoding: {analysis.get('encoding', 'Unbekannt')}\n"
        
        # Binary conversion
        binary = self.decoder.pulses_to_binary(pulses)
        if binary:
            result += f"\nBinaer-Interpretation:\n{binary}\n"
            result += f"Bits: {len(binary)}\n"
            
            # Try hex conversion
            if len(binary) % 8 == 0:
                hex_str = ""
                for i in range(0, len(binary), 8):
                    byte = int(binary[i:i+8], 2)
                    hex_str += f"{byte:02X} "
                result += f"Hex: {hex_str}\n"
        
        self.analysis_text.insert("1.0", result)
        
        # Visualize
        self._visualize_pulses(pulses)
    
    def _visualize_pulses(self, pulses: List[int]):
        self.viz_canvas.delete("all")
        
        if not pulses:
            return
        
        width = self.viz_canvas.winfo_width() or 600
        height = 100
        
        max_pulse = max(pulses)
        if max_pulse == 0:
            return
        
        # Scale factor
        total_time = sum(pulses)
        x_scale = (width - 20) / total_time if total_time > 0 else 1
        y_scale = (height - 20) / max_pulse
        
        x = 10
        y_base = height - 10
        high = True
        
        for pulse in pulses[:200]:  # Limit to 200 pulses
            pulse_width = max(1, int(pulse * x_scale))
            y = y_base - int(pulse * y_scale) if high else y_base
            
            # Draw pulse
            self.viz_canvas.create_line(x, y_base, x, y, fill="blue", width=1)
            self.viz_canvas.create_line(x, y, x + pulse_width, y, fill="blue", width=1)
            
            x += pulse_width
            high = not high
    
    def get_config(self) -> dict:
        return {
            "signal_count": len(self.signals)
        }
    
    def set_config(self, config: dict):
        pass
