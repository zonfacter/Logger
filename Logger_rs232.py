import serial
import serial.tools.list_ports
import threading
import tkinter as tk
from tkinter import ttk, filedialog
import time
import binascii
import queue


# ==========================================================================================
# RS485 Sniffer Klasse - Lösung C (Thread + Queue)
# ==========================================================================================
class RS485Sniffer:
    def __init__(self, gui):
        self.gui = gui
        self.ser = None
        self.running = False
        self.thread = None
        self.logfile = None

        # Thread-sichere Queue:
        self.rx_queue = queue.Queue()

        # Betriebsarten:
        self.break_enabled = True
        self.raw_mode = False
        self.break_byte = b"\xFE"

    # --------------------------------------------------------------------------------------
    def set_break_byte(self, hexstr):
        try:
            b = int(hexstr, 16)
            self.break_byte = bytes([b])
            self.gui.append(f"Break-Byte gesetzt: {hexstr}\n")
        except:
            self.gui.append("Ungültiges Break-Byte (Hex)\n")

    # --------------------------------------------------------------------------------------
    def open_logfile(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt")
        if filename:
            self.logfile = open(filename, "w", encoding="utf-8")
            self.gui.append(f"Logfile geöffnet: {filename}\n")

    # --------------------------------------------------------------------------------------
    def write_log(self, text):
        if self.logfile:
            self.logfile.write(text + "\n")
            self.logfile.flush()

    # --------------------------------------------------------------------------------------
    def start(self):
        if self.running:
            return

        try:
            self.ser = serial.Serial(
                port=self.gui.port_var.get(),
                baudrate=int(self.gui.baud_var.get()),
                bytesize=serial.EIGHTBITS,
                parity=self.gui.parity_map[self.gui.parity_var.get()],
                stopbits=float(self.gui.stopbits_var.get()),
                timeout=0.01,             # wichtig!
                write_timeout=0.01
            )
        except Exception as e:
            self.gui.append(f"Serial Fehler: {e}\n")
            return

        self.running = True
        self.thread = threading.Thread(target=self.reader_thread, daemon=True)
        self.thread.start()

        self.gui.set_running(True)
        self.gui.append("Sniffer gestartet.\n")

    # --------------------------------------------------------------------------------------
    def stop(self):
        self.running = False
        if self.ser:
            try:
                self.ser.close()
            except:
                pass
            self.ser = None

        self.gui.set_running(False)
        self.gui.append("Sniffer gestoppt.\n")

    # --------------------------------------------------------------------------------------
    # THREAD: RS485 Reader
    # --------------------------------------------------------------------------------------
    def reader_thread(self):
        buffer = b""

        while self.running:
            try:
                data = self.ser.read(256)
            except:
                continue

            if not data:
                continue

            for byte in data:
                byte_b = bytes([byte])

                # RAW-MODUS
                if self.raw_mode:
                    ts = time.strftime("%H:%M:%S.%f")[:-3]
                    line = f"{ts}  RX  {byte_b.hex().upper()}"
                    self.rx_queue.put(line)
                    continue

                # FRAME MODUS
                buffer += byte_b

                if self.break_enabled and byte_b == self.break_byte:
                    ts = time.strftime("%H:%M:%S.%f")[:-3]
                    hexline = buffer.hex().upper()
                    line = f"{ts}  RX  {hexline}"
                    self.rx_queue.put(line)
                    buffer = b""

        # Restbuffer:
        if buffer and not self.raw_mode:
            ts = time.strftime("%H:%M:%S.%f")[:-3]
            hexline = buffer.hex().upper()
            line = f"{ts}  RX  {hexline}"
            self.rx_queue.put(line)

    # --------------------------------------------------------------------------------------
    # TX
    # --------------------------------------------------------------------------------------
    def send_data(self):
        if not self.ser:
            self.gui.append("Schnittstelle nicht offen.\n")
            return

        raw = self.gui.send_var.get().replace(" ", "")
        if len(raw) % 2 != 0:
            self.gui.append("Ungültige Hex-Zahl.\n")
            return

        try:
            data = binascii.unhexlify(raw)
        except:
            self.gui.append("Ungültige Hex-Eingabe.\n")
            return

        self.ser.write(data)
        ts = time.strftime("%H:%M:%S.%f")[:-3]
        self.gui.append(f"{ts}  TX  {raw.upper()}\n")


# ==========================================================================================
# GUI Klasse
# ==========================================================================================
class SnifferGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HausBus RS485 Sniffer - Lösung C")

        self.sniffer = RS485Sniffer(self)

        self.parity_map = {
            "None": serial.PARITY_NONE,
            "Even": serial.PARITY_EVEN,
            "Odd": serial.PARITY_ODD
        }

        self.build_gui()
        self.poll_queue()      # wichtig!!

    # --------------------------------------------------------------------------------------
    def build_gui(self):
        cfg = ttk.Frame(self.root)
        cfg.pack(fill="x")

        ttk.Label(cfg, text="Port:").grid(row=0, column=0)
        self.port_var = tk.StringVar()
        ports = [p.device for p in serial.tools.list_ports.comports()]
        port_box = ttk.Combobox(cfg, textvariable=self.port_var, values=ports, width=15)
        if ports:
            port_box.current(0)
        port_box.grid(row=0, column=1)

        ttk.Label(cfg, text="Baud:").grid(row=0, column=2)
        self.baud_var = tk.StringVar(value="115200")
        baud_box = ttk.Combobox(cfg, textvariable=self.baud_var,
                                values=["9600", "19200", "38400", "57600", "115200"], width=10)
        baud_box.grid(row=0, column=3)

        ttk.Label(cfg, text="Parity:").grid(row=0, column=4)
        self.parity_var = tk.StringVar(value="None")
        parity_box = ttk.Combobox(cfg, textvariable=self.parity_var,
                                  values=["None", "Even", "Odd"], width=7)
        parity_box.grid(row=0, column=5)

        ttk.Label(cfg, text="Stopbits:").grid(row=0, column=6)
        self.stopbits_var = tk.StringVar(value="1")
        stopbits_box = ttk.Combobox(cfg, textvariable=self.stopbits_var,
                                    values=["1", "2"], width=4)
        stopbits_box.grid(row=0, column=7)

        # Break-Byte / RAW
        frame_cfg = ttk.LabelFrame(self.root, text="Frame-Steuerung")
        frame_cfg.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_cfg, text="Break-Byte (Hex):").pack(side="left")
        self.break_var = tk.StringVar(value="FE")
        ttk.Entry(frame_cfg, textvariable=self.break_var, width=5).pack(side="left")

        ttk.Button(frame_cfg, text="Setzen",
                   command=lambda: self.sniffer.set_break_byte(self.break_var.get())).pack(side="left")

        self.break_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_cfg, text="Break aktiv",
                        variable=self.break_enabled_var,
                        command=lambda: setattr(self.sniffer, "break_enabled",
                                                self.break_enabled_var.get())).pack(side="left")

        self.raw_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame_cfg, text="RAW Modus",
                        variable=self.raw_mode_var,
                        command=lambda: setattr(self.sniffer, "raw_mode",
                                                self.raw_mode_var.get())).pack(side="left")

        # Textbox
        self.text = tk.Text(self.root, width=120, height=30)
        self.text.pack(padx=10, pady=10)

        # Buttons
        bf = ttk.Frame(self.root)
        bf.pack()

        self.start_button = ttk.Button(bf, text="Start", command=self.sniffer.start)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(bf, text="Stop", command=self.sniffer.stop, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        ttk.Button(bf, text="Log speichern", command=self.sniffer.open_logfile).pack(side="left", padx=5)

        # Sender
        sf = ttk.LabelFrame(self.root, text="Senden (Hex)")
        sf.pack(fill="x", padx=10, pady=5)

        self.send_var = tk.StringVar()
        ttk.Entry(sf, textvariable=self.send_var, width=80).pack(side="left", pady=5)
        ttk.Button(sf, text="SEND", command=self.sniffer.send_data).pack(side="left", padx=5)

    # --------------------------------------------------------------------------------------
    def poll_queue(self):
        """GUI pollt RX-Queue ohne GUI zu blockieren"""
        try:
            while True:
                line = self.sniffer.rx_queue.get_nowait()
                self.append(line + "\n")
        except queue.Empty:
            pass

        self.root.after(5, self.poll_queue)

    # --------------------------------------------------------------------------------------
    def append(self, text):
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

    # --------------------------------------------------------------------------------------
    def set_running(self, running):
        self.start_button.config(state="disabled" if running else "normal")
        self.stop_button.config(state="normal" if running else "disabled")

    # --------------------------------------------------------------------------------------
    def run(self):
        self.root.mainloop()


# ==========================================================================================
if __name__ == "__main__":
    SnifferGUI().run()
