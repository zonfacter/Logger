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
        self.break_byte = b"\xFE"   # Trigger für Zeilenumbruch

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
            self.gui.append(f"ERROR Öffnen der Schnittstelle: {e}\n")
            return

        self.running = True
        self.thread = threading.Thread(target=self.reader, daemon=True)
        self.thread.start()

        self.gui.set_running_state(True)
        self.gui.append("Sniffer gestartet.\n")

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

    def send_data(self):
        if not self.ser:
            self.gui.append("Schnittstelle nicht offen.\n")
            return

        raw = self.gui.send_var.get().strip().replace(" ", "")
        if len(raw) % 2 != 0:
            self.gui.append("Ungültiges Hex-Byte.\n")
            return

        try:
            data = binascii.unhexlify(raw)
        except:
            self.gui.append("Ungültige Hex-Eingabe.\n")
            return

        self.ser.write(data)
        ts = time.strftime("%H:%M:%S.%f")[:-3]
        self.gui.append(f"{ts}  TX  {raw.upper()}\n")

    def reader(self):
        buffer = b""

        while self.running:
            if self.ser and self.ser.in_waiting:
                data = self.ser.read(self.ser.in_waiting)

                for byte in data:
                    buffer += bytes([byte])

                    # Zeilenumbruch durch definiertes Byte
                    if bytes([byte]) == self.break_byte:
                        self.process_frame(buffer)
                        buffer = b""

            else:
                time.sleep(0.01)

        # Bei Stop Rest buffer ausgeben
        if buffer:
            self.process_frame(buffer)

    def process_frame(self, frame):
        hex_string = binascii.hexlify(frame).decode("ascii").upper()
        ts = time.strftime("%H:%M:%S.%f")[:-3]
        line = f"{ts}  RX  {hex_string}"

        self.write_log(line)
        self.gui.append(line + "\n")


class SnifferGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HausBus RS485 Sniffer")

        self.sniffer = RS485Sniffer(self)

        self.parity_map = {
            "None": serial.PARITY_NONE,
            "Even": serial.PARITY_EVEN,
            "Odd": serial.PARITY_ODD
        }

        self.build_gui()

    def build_gui(self):
        # --- CONFIG FRAME ---
        cfg = ttk.Frame(self.root)
        cfg.pack(fill="x", padx=8, pady=5)

        # Port
        ttk.Label(cfg, text="Port:").grid(row=0, column=0, sticky="w")
        self.port_var = tk.StringVar()
        self.port_box = ttk.Combobox(cfg, textvariable=self.port_var, width=15)
        self.port_box.grid(row=0, column=1, padx=5)

        ports = [p.device for p in serial.tools.list_ports.comports()]
        self.port_box["values"] = ports
        if ports:
            self.port_box.current(0)

        # Baud
        ttk.Label(cfg, text="Baudrate:").grid(row=0, column=2)
        self.baud_var = tk.StringVar(value="115200")
        self.baud_box = ttk.Combobox(cfg, textvariable=self.baud_var, width=10)
        self.baud_box["values"] = ["9600", "19200", "38400", "57600", "115200"]
        self.baud_box.grid(row=0, column=3, padx=5)

        # Parity
        ttk.Label(cfg, text="Parity:").grid(row=0, column=4)
        self.parity_var = tk.StringVar(value="None")
        self.parity_box = ttk.Combobox(cfg, textvariable=self.parity_var, width=8)
        self.parity_box["values"] = ["None", "Even", "Odd"]
        self.parity_box.grid(row=0, column=5, padx=5)

        # Stopbits
        ttk.Label(cfg, text="Stopbits:").grid(row=0, column=6)
        self.stopbits_var = tk.StringVar(value="1")
        self.stopbits_box = ttk.Combobox(cfg, textvariable=self.stopbits_var, width=5)
        self.stopbits_box["values"] = ["1", "2"]
        self.stopbits_box.grid(row=0, column=7, padx=5)

        # --- LOG WINDOW ---
        self.text = tk.Text(self.root, width=120, height=30)
        self.text.pack(padx=10, pady=10)

        # --- BUTTONS ---
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill="x", pady=5)

        self.start_button = ttk.Button(btn_frame, text="Start", command=self.sniffer.start)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(btn_frame, text="Stop", command=self.sniffer.stop, state="disabled")
        self.stop_button.pack(side="left", padx=5)

        ttk.Button(btn_frame, text="Log speichern", command=self.sniffer.open_logfile).pack(side="left", padx=5)

        # --- SENDER ---
        send_frame = ttk.LabelFrame(self.root, text="Senden (Hex)")
        send_frame.pack(fill="x", padx=10, pady=5)

        self.send_var = tk.StringVar()
        self.send_entry = ttk.Entry(send_frame, textvariable=self.send_var, width=70)
        self.send_entry.pack(side="left", padx=5, pady=5)

        self.send_button = ttk.Button(send_frame, text="SEND", command=self.sniffer.send_data)
        self.send_button.pack(side="left", padx=5)

    def append(self, text):
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

    def set_running_state(self, running):
        if running:
            self.start_button.config(state="disabled")
            self.stop_button.config(state="normal")
        else:
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    gui = SnifferGUI()
    gui.run()
