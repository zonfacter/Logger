#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RS485 Sniffer v1.2.0 - HausBus - Fixed real-time display"""

import serial
import serial.tools.list_ports
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from datetime import datetime
import binascii
import queue
from typing import Optional
import sys

__version__ = "1.2.0"

class RS485Sniffer:
    BAUD_RATES = ["9600", "19200", "38400", "57600", "115200",
                  "230400", "250000", "460800", "500000", "921600", "1000000"]
    
    STOPBITS_MAP = {"1": serial.STOPBITS_ONE, "1.5": serial.STOPBITS_ONE_POINT_FIVE, 
                    "2": serial.STOPBITS_TWO}

    def __init__(self, gui):
        self.gui = gui
        self.ser = None
        self.running = False
        self.thread = None
        self.logfile = None
        self.rx_queue = queue.Queue()
        self.break_enabled = True
        self.raw_mode = False
        self.break_byte = b"\xFE"

    @staticmethod
    def get_timestamp():
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def set_break_byte(self, hexstr):
        try:
            b = int(hexstr, 16)
            self.break_byte = bytes([b])
            self.gui.queue_msg(f"Break-Byte: 0x{hexstr.upper()}")
        except:
            self.gui.queue_msg("Ungültiges Break-Byte")

    def start(self):
        if self.running:
            return
        try:
            baudrate = int(self.gui.baud_var.get())
        except:
            self.gui.queue_msg("Ungültige Baudrate!")
            return

        try:
            self.ser = serial.Serial(
                port=self.gui.port_var.get(),
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=self.gui.parity_map[self.gui.parity_var.get()],
                stopbits=self.STOPBITS_MAP.get(self.gui.stopbits_var.get(), serial.STOPBITS_ONE),
                timeout=0.1
            )
        except Exception as e:
            self.gui.queue_msg(f"Fehler: {e}")
            return

        self.running = True
        self.thread = threading.Thread(target=self.reader_thread, daemon=True)
        self.thread.start()
        self.gui.set_running(True)
        self.gui.queue_msg(f"Gestartet @ {baudrate} baud")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        if self.ser:
            self.ser.close()
            self.ser = None
        self.gui.set_running(False)
        self.gui.queue_msg("Gestoppt")

    def reader_thread(self):
        print("[DEBUG] Thread gestartet", file=sys.stderr, flush=True)
        buffer = b""
        while self.running:
            try:
                if not self.ser or not self.ser.is_open:
                    break
                waiting = self.ser.in_waiting
                data = self.ser.read(waiting) if waiting > 0 else self.ser.read(1)
            except Exception as e:
                print(f"[DEBUG] Fehler: {e}", file=sys.stderr, flush=True)
                break

            if not data:
                continue

            print(f"[DEBUG] {len(data)} bytes empfangen", file=sys.stderr, flush=True)

            for byte in data:
                byte_b = bytes([byte])
                if self.raw_mode:
                    ts = self.get_timestamp()
                    self.rx_queue.put(f"{ts} RX {byte_b.hex().upper()}")
                    continue

                buffer += byte_b
                if self.break_enabled and byte_b == self.break_byte:
                    ts = self.get_timestamp()
                    self.rx_queue.put(f"{ts} RX [{len(buffer):3d}] {buffer.hex().upper()}")
                    buffer = b""

        if buffer:
            ts = self.get_timestamp()
            self.rx_queue.put(f"{ts} RX [{len(buffer):3d}] {buffer.hex().upper()} (incomplete)")
        print("[DEBUG] Thread beendet", file=sys.stderr, flush=True)

    def send_data(self):
        if not self.ser:
            return
        raw = self.gui.send_var.get().replace(" ", "")
        try:
            data = binascii.unhexlify(raw)
            self.ser.write(data)
            self.gui.queue_msg(f"{self.get_timestamp()} TX {raw.upper()}")
        except:
            self.gui.queue_msg("TX Fehler")


class SnifferGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"RS485 Sniffer v{__version__}")
        self.sniffer = RS485Sniffer(self)
        self.msg_queue = queue.Queue()
        
        self.parity_map = {"None": serial.PARITY_NONE, "Even": serial.PARITY_EVEN, 
                          "Odd": serial.PARITY_ODD}
        
        self.port_var = tk.StringVar()
        self.baud_var = tk.StringVar(value="19200")
        self.parity_var = tk.StringVar(value="None")
        self.stopbits_var = tk.StringVar(value="1")
        self.break_var = tk.StringVar(value="FE")
        self.break_enabled_var = tk.BooleanVar(value=True)
        self.raw_mode_var = tk.BooleanVar(value=False)
        self.send_var = tk.StringVar()
        
        self.build_gui()
        self.poll_queues()

    def queue_msg(self, text):
        self.msg_queue.put(text)

    def build_gui(self):
        cfg = ttk.LabelFrame(self.root, text="Verbindung")
        cfg.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(cfg, text="Port:").grid(row=0, column=0)
        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_combo = ttk.Combobox(cfg, textvariable=self.port_var, values=ports, width=12)
        if ports: self.port_combo.current(0)
        self.port_combo.grid(row=0, column=1)
        
        ttk.Label(cfg, text="Baud:").grid(row=0, column=2)
        ttk.Combobox(cfg, textvariable=self.baud_var, values=RS485Sniffer.BAUD_RATES, width=10).grid(row=0, column=3)
        
        ttk.Label(cfg, text="Parity:").grid(row=0, column=4)
        ttk.Combobox(cfg, textvariable=self.parity_var, values=["None","Even","Odd"], width=6, state="readonly").grid(row=0, column=5)
        
        ttk.Label(cfg, text="Stop:").grid(row=0, column=6)
        ttk.Combobox(cfg, textvariable=self.stopbits_var, values=["1","1.5","2"], width=4, state="readonly").grid(row=0, column=7)

        fcfg = ttk.LabelFrame(self.root, text="Frame")
        fcfg.pack(fill="x", padx=5, pady=5)
        ttk.Label(fcfg, text="Break:").pack(side="left")
        ttk.Entry(fcfg, textvariable=self.break_var, width=4).pack(side="left")
        ttk.Button(fcfg, text="Set", command=lambda: self.sniffer.set_break_byte(self.break_var.get())).pack(side="left")
        ttk.Checkbutton(fcfg, text="Break", variable=self.break_enabled_var,
                       command=lambda: setattr(self.sniffer, "break_enabled", self.break_enabled_var.get())).pack(side="left")
        ttk.Checkbutton(fcfg, text="RAW", variable=self.raw_mode_var,
                       command=lambda: setattr(self.sniffer, "raw_mode", self.raw_mode_var.get())).pack(side="left")

        tf = ttk.Frame(self.root)
        tf.pack(fill="both", expand=True, padx=5, pady=5)
        sb = ttk.Scrollbar(tf)
        sb.pack(side="right", fill="y")
        self.text = tk.Text(tf, height=20, font=("Consolas", 10), yscrollcommand=sb.set)
        self.text.pack(fill="both", expand=True)
        sb.config(command=self.text.yview)

        bf = ttk.Frame(self.root)
        bf.pack(fill="x", padx=5, pady=5)
        self.start_btn = ttk.Button(bf, text="Start", command=self.sniffer.start)
        self.start_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(bf, text="Stop", command=self.sniffer.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=2)
        ttk.Button(bf, text="Clear", command=lambda: self.text.delete("1.0", tk.END)).pack(side="left", padx=2)

        sf = ttk.LabelFrame(self.root, text="Send (Hex)")
        sf.pack(fill="x", padx=5, pady=5)
        ttk.Entry(sf, textvariable=self.send_var, width=60).pack(side="left", padx=5, pady=5)
        ttk.Button(sf, text="SEND", command=self.sniffer.send_data).pack(side="left")

    def poll_queues(self):
        # RX Queue
        try:
            for _ in range(50):
                line = self.sniffer.rx_queue.get_nowait()
                self.text.insert(tk.END, line + "\n")
                self.text.see(tk.END)
        except queue.Empty:
            pass
        # Msg Queue
        try:
            for _ in range(10):
                msg = self.msg_queue.get_nowait()
                self.text.insert(tk.END, msg + "\n")
                self.text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(50, self.poll_queues)

    def set_running(self, running):
        self.start_btn.config(state="disabled" if running else "normal")
        self.stop_btn.config(state="normal" if running else "disabled")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    print(f"RS485 Sniffer v{__version__} - Debug in Konsole")
    SnifferGUI().run()
