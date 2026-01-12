import serial
import serial.tools.list_ports
import threading
import tkinter as tk
from tkinter import ttk, filedialog
import time
import binascii


class RS485Sniffer:
    def __init__(self, gui):
        self.gui = gui
        self.ser = None
        self.running = False
        self.logfile = None
        self.thread = None

        # Default Einstellungen (werden NACH GUI-Aufbau gesetzt!)
        self.break_enabled = True
        self.raw_mode = False
        self.break_byte = b"\xFE"   # GUI übernimmt später die Anzeige

    # ----------------------------------------------------------------------
    # BREAK BYTE SETZEN
    # ----------------------------------------------------------------------
    def set_break_byte(self, hexstr):
        try:
            value = int(hexstr, 16)
            self.break_byte = bytes([value])
            self.gui.append(f"Break-Byte gesetzt auf: {hexstr}\n")
        except ValueError:
            self.gui.append("Ungültiges Break-Byte (Hex)! Beispiel: FE\n")

    # ----------------------------------------------------------------------
    # LOGDATEI
    # ----------------------------------------------------------------------
    def open_logfile(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")]
        )
        if filename:
            self.logfile = open(filename, "w", encoding="utf-8")
            self.gui.append(f"Logfile geöffnet: {filename}\n")

    def write_log(self, line):
        if self.logfile:
            self.logfile.write(line + "\n")
            self.logfile.flush()

    # ----------------------------------------------------------------------
    # START
    # ----------------------------------------------------------------------
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
                timeout=0
            )
        except Exception as e:
            self.gui.append(f"Fehler beim Öffnen der Schnittstelle: {e}\n")
            return

        self.running = True
        self.thread = threading.Thread(target=self.reader, daemon=True)
        self.thread.start()

        self.gui.set_running_state(True)
        self.gui.append("Sniffer gestartet.\n")

    # ----------------------------------------------------------------------
    # STOP
    # ----------------------------------------------------------------------
    def stop(self):
        self.running = False
        if self.ser:
            try:
                self.ser.close()
            except:
                pass
            self.ser = None

        self.gui.set_running_state(False)
        self.gui.append("Sniffer gestoppt.\n")

    # ----------------------------------------------------------------------
    # SENDEN
    # ----------------------------------------------------------------------
    def send_data(self):
        if not self.ser:
            self.gui.append("Schnittstelle nicht offen.\n")
            return

        raw = self.gui.send_var.get().strip().replace(" ", "")
        if len(raw) % 2 != 0:
            self.gui.append("Ungültige Hex-Eingabe (ungerade Anzahl Zeichen).\n")
            return

        try:
            data = binascii.unhexlify(raw)
        except:
            self.gui.append("Ungültige Hex-Zeichen.\n")
            return

        self.ser.write(data)
        ts = time.strftime("%H:%M:%S.%f")[:-3]
        self.gui.append(f"{ts}  TX  {raw.upper()}\n")

    # ----------------------------------------------------------------------
    # READER THREAD
    # ----------------------------------------------------------------------
    def reader(self):
        buffer = b""

        while self.running:
            if self.ser and self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)

                for byte in data:
                    byte_b = bytes([byte])

                    # RAW MODE → jedes Byte einzeln ausgeben
                    if self.raw_mode:
                        self.output_frame(byte_b)
                        continue

                    # Paketweise → Break Byte
                    buffer += byte_b

                    if self.break_enabled and byte_b == self.break_byte:
                        self.process_frame(buffer)
                        buffer = b""
            else:
                time.sleep(0.005)

        # Rest ausgeben
        if buffer and not self.raw_mode:
            self.process_frame(buffer)

    # ----------------------------------------------------------------------
    # EIN FRAME AUSGEBEN
    # ----------------------------------------------------------------------
    def output_frame(self, frame):
        hex_string = binascii.hexlify(frame).decode("ascii").upper()
        ts = time.strftime("%H:%M:%S.%f")[:-3]
        line = f"{ts}  RX  {hex_string}"
        self.write_log(line)
        self.gui.append(line + "\n")

    # ----------------------------------------------------------------------
    # EIN PAKET AUSGEBEN (Frame Modus)
    # ----------------------------------------------------------------------
    def process_frame(self, frame):
        hex_string = binascii.hexlify(frame).decode("ascii").upper()
        ts = time.strftime("%H:%M:%S.%f")[:-3]
        line = f"{ts}  RX  {hex_string}"
        self.write_log(line)
        self.gui.append(line + "\n")


# ==================================================================================
# GUI
# ==================================================================================
class SnifferGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HausBus RS485 Sniffer")

        # Sniffer erzeugen
        self.sniffer = RS485Sniffer(self)

        # Parity Mapping
        self.parity_map = {
            "None": serial.PARITY_NONE,
            "Even": serial.PARITY_EVEN,
            "Odd": serial.PARITY_ODD
        }

        # GUI erzeugen
        self.build_gui()

        # Default-Werte übernehmen
        self.sniffer.set_break_byte(self.break_var.get())
        self.sniffer.break_enabled = self.break_enabled_var.get()
        self.sniffer.raw_mode = self.raw_mode_var.get()

    # ----------------------------------------------------------------------
    # GUI BAUEN
    # ----------------------------------------------------------------------
    def build_gui(self):
        # --- CONFIG ---
        cfg = ttk.Frame(self.root)
        cfg.pack(fill="x", padx=8, pady=4)

        # Port
        ttk.Label(cfg, text="Port:").grid(row=0, column=0)
        self.port_var = tk.StringVar()
        port_box = ttk.Combobox(cfg, textvariable=self.port_var, width=18)
        ports = [p.device for p in serial.tools.list_ports.comports()]
        port_box["values"] = ports
        if ports:
            port_box.current(0)
        port_box.grid(row=0, column=1, padx=5)

        # Baudrate
        ttk.Label(cfg, text="Baudrate:").grid(row=0, column=2)
        self.baud_var = tk.StringVar(value="115200")
        baud_box = ttk.Combobox(cfg, textvariable=self.baud_var,
                                values=["9600", "19200", "38400", "57600", "115200"],
                                width=10)
        baud_box.grid(row=0, column=3)

        # Parity
        ttk.Label(cfg, text="Parity:").grid(row=0, column=4)
        self.parity_var = tk.StringVar(value="None")
        parity_box = ttk.Combobox(cfg, textvariable=self.parity_var,
                                  values=["None", "Even", "Odd"], width=7)
        parity_box.grid(row=0, column=5)

        # Stopbits
        ttk.Label(cfg, text="Stopbits:").grid(row=0, column=6)
        self.stopbits_var = tk.StringVar(value="1")
        stopbits_box = ttk.Combobox(cfg, textvariable=self.stopbits_var,
                                    values=["1", "1.5", "2"], width=5)
        stopbits_box.grid(row=0, column=7)

        # --- FRAME / BREAK CONTROL ---
        break_frame = ttk.LabelFrame(self.root, text="Frame-Steuerung")
        break_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(break_frame, text="Break-Byte (Hex):").pack(side="left", padx=5)
        self.break_var = tk.StringVar(value="FE")
        ttk.Entry(break_frame, textvariable=self.break_var, width=5).pack(side="left", padx=5)

        ttk.Button(break_frame, text="Setzen",
                   command=lambda: self.sniffer.set_break_byte(self.break_var.get())).pack(side="left")

        self.break_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(break_frame, text="Break aktiv",
                        variable=self.break_enabled_var,
                        command=self.update_break_flag).pack(side="left", padx=10)

        self.raw_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(break_frame, text="RAW-Modus",
                        variable=self.raw_mode_var,
                        command=self.update_raw_flag).pack(side="left", padx=10)

        # --- TEXT OUTPUT ---
        self.text = tk.Text(self.root, width=120, height=30)
        self.text.pack(padx=10, pady=10)

        # --- BUTTON BAR ---
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill="x", pady=5)

        self.start_button = ttk.Button(btn_frame, text="Start", command=self.sniffer.start)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(btn_frame, text="Stop", state="disabled",
                                      command=self.sniffer.stop)
        self.stop_button.pack(side="left", padx=5)

        ttk.Button(btn_frame, text="Log speichern",
                   command=self.sniffer.open_logfile).pack(side="left", padx=5)

        # --- SENDER ---
        send_frame = ttk.LabelFrame(self.root, text="Senden (Hex)")
        send_frame.pack(fill="x", padx=10, pady=5)

        self.send_var = tk.StringVar()
        ttk.Entry(send_frame, textvariable=self.send_var, width=80).pack(side="left", padx=5)
        ttk.Button(send_frame, text="SEND", command=self.sniffer.send_data).pack(side="left")

    # ----------------------------------------------------------------------
    # HILFSFUNKTIONEN
    # ----------------------------------------------------------------------
    def append(self, text):
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

    def update_break_flag(self):
        self.sniffer.break_enabled = self.break_enabled_var.get()

    def update_raw_flag(self):
        self.sniffer.raw_mode = self.raw_mode_var.get()

    def set_running_state(self, running):
        if running:
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
        else:
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def run(self):
        self.root.mainloop()


# ==================================================================================
# MAIN START
# ==================================================================================
if __name__ == "__main__":
    SnifferGUI().run()
