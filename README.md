HausBus UDP Telegramm Migrationsdokumentation

Von ASCII zu UDP-Protokoll - Vollständiger Migrations-Leitfaden

Einführung und Übersicht

1.1 Zweck dieser Dokumentation

Diese Dokumentation beschreibt die vollständige Migration vom HausBus ASCII-Protokoll zum binären UDP-Protokoll. Sie enthält detaillierte Informationen zu:

RGB-Dimmer Modulen
6-Fach Taster Modulen
8-Fach Rolladen Modulen

1.2 Protokoll-Vergleich
ASCII-Protokoll (alt):
Textbasierte Kommunikation
Höherer Overhead durch Zeichenkodierung
Einfacher zu debuggen via Terminal
UDP-Protokoll (neu):
Binäres Format mit geringerem Overhead
Broadcast auf UDP Port 9
Schnellere Verarbeitung
Unterstützt alle Gerätefunktionen

UDP-Telegramm Grundstruktur

2.1 Header-Format

Jedes HausBus UDP-Telegramm beginnt mit einem festen Header:

Offset  Länge   Beschreibung
0-1     2 Byte  Magic Bytes: 0xEF 0xEF
2       1 Byte  Kontrollbyte
3       1 Byte  Message Counter (0-255, rotierend)
4-7     4 Byte  Sender ObjectId (Little-Endian)
8-11    4 Byte  Receiver ObjectId (Little-Endian)
12-13   2 Byte  Data Length (Little-Endian)
14      1 Byte  Function ID
15+     variabel Function Data (Parameter)


2.2 ObjectId Aufbau

Die ObjectId ist ein 32-Bit Wert mit folgender Struktur:

Bits 31-16: DeviceId   (16 Bit) - Eindeutige Geräte-Adresse
Bits 15-8:  ClassId    (8 Bit)  - Gerätetyp/Funktionsklasse
Bits 7-0:   InstanceId (8 Bit)  - Kanal/Instanznummer

Berechnung:
objectId = (deviceId << 16) | (classId << 8) | instanceId

Rückrechnung:
deviceId = (objectId >> 16) & 0xFFFF
classId = (objectId >> 8) & 0xFF
instanceId = objectId & 0xFF


2.3 Function ID Bereiche

| Bereich | Typ | Beschreibung |
|---------|-----|--------------|
| 0-127 | Commands | Befehle an das Gerät |
| 128-199 | Results | Antworten auf Commands |
| 200-255 | Events | Spontane Ereignismeldungen |

RGB-Dimmer Module

3.1 ClassId und Grundlagen
ClassId für RGBDimmer: Wird im System dynamisch vergeben, typischerweise im Bereich der Dimmer-Klassen.

3.2 Datentypen und Enumerationen
EDirection - Dimmrichtung:
class EDirection:
    TO\_DARK = 0      # Dimmen Richtung dunkel
    TO\_LIGHT = 1     # Dimmen Richtung hell
    TOGGLE = 2       # Richtung umschalten
    STOP = 3         # Dimmen stoppen

EErrorCode - Fehlercodes:
class EErrorCode:
    NO\_ERROR = 0
    INVALID\_PARAMETER = 1
    DEVICE\_BUSY = 2
    COMMAND\NOT\SUPPORTED = 3


3.3 Commands (Befehle)

3.3.1 getConfiguration (Function ID: 0)

Fragt die aktuelle Konfiguration ab.
Request:
Byte 0: Function ID = 0
Länge: 1 Byte

Response (Result):
Enthält Dimmzeiten, Min/Max-Werte, PWM-Konfiguration

3.3.2 setConfiguration (Function ID: 1)

Setzt die Dimmer-Konfiguration.
Request:
Byte 0:    Function ID = 1
Byte 1-2:  dimmingTime (Word, Little-Endian) - Dimmzeit in ms
Byte 3:    minBrightness (Byte) - Minimale Helligkeit 0-200
Byte 4:    maxBrightness (Byte) - Maximale Helligkeit 0-200
Byte 5-6:  pwmPeriod (Word) - PWM Periode


3.3.3 getStatus (Function ID: 2)

Fragt den aktuellen Status ab.
Request:
Byte 0: Function ID = 2
Länge: 1 Byte


3.3.4 setBrightness (Function ID: 3)

Setzt die Helligkeit für einen oder alle Kanäle.
Request:
Byte 0:    Function ID = 3
Byte 1:    brightness (Byte) - Helligkeit 0-200 (0=aus, 200=100%)
Byte 2-5:  duration (DWord) - Übergangszeit in ms

Beispiel - Rot auf 50% setzen mit 1 Sekunde Übergang:
data = bytes([
    3,          # Function ID: setBrightness
    100,        # brightness: 100 = 50%
    0xE8, 0x03, 0x00, 0x00  # duration: 1000ms (Little-Endian)
])


3.3.5 start (Function ID: 4)

Startet den Dimmvorgang.
Request:
Byte 0: Function ID = 4
Byte 1: direction (EDirection)

Beispiel - Dimmen starten Richtung hell:
data = bytes([4, 1])  # start, TO\_LIGHT


3.3.6 stop (Function ID: 5)

Stoppt den laufenden Dimmvorgang.
Request:
Byte 0: Function ID = 5
Länge: 1 Byte


3.3.7 setColor (Function ID: 6) - RGB spezifisch

Setzt die RGB-Farbe direkt.
Request:
Byte 0:    Function ID = 6
Byte 1:    red (Byte) - Rot-Anteil 0-200
Byte 2:    green (Byte) - Grün-Anteil 0-200
Byte 3:    blue (Byte) - Blau-Anteil 0-200
Byte 4-7:  duration (DWord) - Übergangszeit in ms

Beispiel - Violett setzen (Rot+Blau):
data = bytes([
    6,          # Function ID: setColor
    200,        # red: 100%
    0,          # green: 0%
    200,        # blue: 100%
    0xF4, 0x01, 0x00, 0x00  # duration: 500ms
])


3.4 Events (Ereignisse)

3.4.1 evOn (Function ID: 200)

Wird gesendet wenn der Dimmer eingeschaltet wird.
Event-Daten:
Byte 0: Function ID = 200
Byte 1: brightness - Aktuelle Helligkeit


3.4.2 evOff (Function ID: 201)

Wird gesendet wenn der Dimmer ausgeschaltet wird.
Event-Daten:
Byte 0: Function ID = 201


3.4.3 evStatus (Function ID: 202)

Statusmeldung mit aktuellen Werten.
Event-Daten:
Byte 0:   Function ID = 202
Byte 1:   brightness - Aktuelle Helligkeit
Byte 2:   direction - Aktuelle Dimmrichtung
Byte 3:   isRunning - Dimmen aktiv (0/1)


3.5 RGB-Dimmer Migrations-Beispiel
ASCII (alt):
SET DIMMER 1 BRIGHTNESS 100
SET DIMMER 1 COLOR 255 0 128

UDP (neu):
import socket
import struct

def build\telegram(sender\id, receiver\id, function\id, data=b''):
    header = bytes([0xEF, 0xEF])  # Magic bytes
    control = bytes([0x00])       # Kontrollbyte
    counter = bytes([0x01])       # Message counter
    
    sender = struct.pack('<I', sender\_id)
    receiver = struct.pack('<I', receiver\_id)
    length = struct.pack('<H', len(data) + 1)
    
    payload = bytes([function\_id]) + data
    
    return header + control + counter + sender + receiver + length + payload

RGB-Dimmer auf Violett setzen
DeviceId=0x5900, ClassId=5 (Dimmer), InstanceId=1
receiver\_objectid = (0x5900 << 16) | (5 << 8) | 1

color\_data = bytes([
    200,  # Red
    0,    # Green
    200,  # Blue
    0xF4, 0x01, 0x00, 0x00  # 500ms duration
])

telegram = build\_telegram(
    sender\_id=0x00000000,
    receiver\id=receiver\objectid,
    function\_id=6,  # setColor
    data=color\_data
)

sock = socket.socket(socket.AF\INET, socket.SOCK\DGRAM)
sock.setsockopt(socket.SOL\SOCKET, socket.SO\BROADCAST, 1)
sock.sendto(telegram, ('255.255.255.255', 9))


6-Fach Taster Module

4.1 ClassId und Architektur

Das 6-Fach Taster Modul verwendet mehrere Klassen:

Button - Physischer Tastereingang
LogicalButton - Logische Tasterzuordnung mit Ereignissen

4.2 Button Enumerationen
EButtonId - Taster-Identifikation:
class EButtonId:
    BUTTON\_1 = 0
    BUTTON\_2 = 1
    BUTTON\_3 = 2
    BUTTON\_4 = 3
    BUTTON\_5 = 4
    BUTTON\_6 = 5

EButtonEvent - Taster-Ereignisse:
class EButtonEvent:
    FREE = 0           # Taster losgelassen
    PRESSED = 1        # Taster gedrückt
    CLICKED = 2        # Kurzer Klick
    DOUBLE\_CLICKED = 3 # Doppelklick
    HOLD\_START = 4     # Langer Druck beginnt
    HOLD\_END = 5       # Langer Druck endet


4.3 Button Commands

4.3.1 getConfiguration (Function ID: 0)
Request:
Byte 0: Function ID = 0

Response enthält:
Entprellzeit
Click-Timeout
Hold-Timeout
Double-Click-Timeout

4.3.2 setConfiguration (Function ID: 1)
Request:
Byte 0:    Function ID = 1
Byte 1-2:  debounceTime (Word) - Entprellzeit in ms
Byte 3-4:  clickTimeout (Word) - Klick-Erkennung in ms
Byte 5-6:  holdTimeout (Word) - Langer Druck in ms
Byte 7-8:  doubleClickTimeout (Word) - Doppelklick-Fenster in ms


4.3.3 getStatus (Function ID: 2)
Request:
Byte 0: Function ID = 2

Response:
Byte 0: pressed - Aktuell gedrückt (0/1)


4.4 LogicalButton Commands

4.4.1 getConfiguration (Function ID: 0)

Holt die Verknüpfungskonfiguration.

4.4.2 setConfiguration (Function ID: 1)

Verknüpft Taster mit Aktoren.
Request:
Byte 0:    Function ID = 1
Byte 1-4:  targetObjectId (DWord) - Ziel-Aktor ObjectId
Byte 5:    onEvent (EButtonEvent) - Auslösendes Ereignis
Byte 6:    action (Byte) - Auszuführende Aktion


4.5 Button Events

4.5.1 evPressed (Function ID: 200)

Taster wurde gedrückt.
Event-Daten:
Byte 0: Function ID = 200
Byte 1: buttonId (EButtonId)


4.5.2 evClicked (Function ID: 201)

Kurzer Klick erkannt.
Event-Daten:
Byte 0: Function ID = 201
Byte 1: buttonId (EButtonId)


4.5.3 evDoubleClicked (Function ID: 202)

Doppelklick erkannt.
Event-Daten:
Byte 0: Function ID = 202
Byte 1: buttonId (EButtonId)


4.5.4 evHoldStart (Function ID: 203)

Langer Tastendruck beginnt.
Event-Daten:
Byte 0: Function ID = 203
Byte 1: buttonId (EButtonId)


4.5.5 evHoldEnd (Function ID: 204)

Langer Tastendruck endet.
Event-Daten:
Byte 0: Function ID = 204
Byte 1: buttonId (EButtonId)
Byte 2-5: holdDuration (DWord) - Dauer in ms


4.5.6 evFree (Function ID: 205)

Taster losgelassen.
Event-Daten:
Byte 0: Function ID = 205
Byte 1: buttonId (EButtonId)


4.6 Taster Migrations-Beispiel
ASCII (alt):
GET BUTTON 1 STATUS
LINK BUTTON 1 CLICK -> DIMMER 1 TOGGLE

UDP (neu):
Event-Listener für Taster
def handle\button\event(data, sender):
    function\_id = data[14]
    
    if function\_id == 200:  # evPressed
        button\_id = data[15]
        print(f"Taster {button\_id + 1} gedrückt")
    
    elif function\_id == 201:  # evClicked
        button\_id = data[15]
        print(f"Taster {button\_id + 1} geklickt")
        # Aktion auslösen
        toggle\dimmer(button\id)
    
    elif function\_id == 203:  # evHoldStart
        button\_id = data[15]
        print(f"Taster {button\_id + 1} wird gehalten")
        start\dimming(button\id)

UDP-Listener starten
sock = socket.socket(socket.AF\INET, socket.SOCK\DGRAM)
sock.bind(('0.0.0.0', 9))

while True:
    data, addr = sock.recvfrom(1024)
    if data[0:2] == bytes([0xEF, 0xEF]):
        handle\button\event(data, addr)


8-Fach Rolladen Module

5.1 ClassId und Grundlagen

Das 8-Fach Rolladen Modul steuert bis zu 8 unabhängige Rolladen/Jalousie-Antriebe.

5.2 Enumerationen
EDirection - Fahrtrichtung:
class EDirection:
    STOP = 0      # Stoppen
    UP = 1        # Hochfahren
    DOWN = 2      # Runterfahren
    TOGGLE = 3    # Richtung umkehren

EState - Rolladen-Zustand:
class EState:
    STOPPED = 0      # Steht
    MOVING\_UP = 1    # Fährt hoch
    MOVING\_DOWN = 2  # Fährt runter
    CALIBRATING = 3  # Kalibrierung läuft

EShutterType - Rolladentyp:
class EShutterType:
    SHUTTER = 0      # Normaler Rolladen
    JALOUSIE = 1     # Jalousie mit Lamellenverstellung
    AWNING = 2       # Markise
    VENETIAN = 3     # Raffstore


5.3 Shutter Commands

5.3.1 getConfiguration (Function ID: 0)
Request:
Byte 0: Function ID = 0

Response:
Byte 0-3:  runTimeUp (DWord) - Laufzeit hoch in ms
Byte 4-7:  runTimeDown (DWord) - Laufzeit runter in ms
Byte 8-11: tiltTime (DWord) - Lamellenverstellzeit in ms
Byte 12:   shutterType (EShutterType)
Byte 13:   reverseDirection (Byte) - Richtung invertiert (0/1)


5.3.2 setConfiguration (Function ID: 1)
Request:
Byte 0:     Function ID = 1
Byte 1-4:   runTimeUp (DWord) - Laufzeit hoch in ms
Byte 5-8:   runTimeDown (DWord) - Laufzeit runter in ms
Byte 9-12:  tiltTime (DWord) - Lamellenverstellzeit in ms
Byte 13:    shutterType (EShutterType)
Byte 14:    reverseDirection (Byte)

Beispiel - Rolladen mit 20s Laufzeit konfigurieren:
data = bytes([
    1,  # Function ID
    0x20, 0x4E, 0x00, 0x00,  # runTimeUp: 20000ms
    0x20, 0x4E, 0x00, 0x00,  # runTimeDown: 20000ms
    0x00, 0x00, 0x00, 0x00,  # tiltTime: 0ms (kein Jalousie)
    0,  # shutterType: SHUTTER
    0   # reverseDirection: false
])


5.3.3 getStatus (Function ID: 2)
Request:
Byte 0: Function ID = 2

Response:
Byte 0:    state (EState) - Aktueller Zustand
Byte 1:    position (Byte) - Position 0-100%
Byte 2:    tiltPosition (Byte) - Lamellenstellung 0-100%
Byte 3:    direction (EDirection) - Letzte Richtung


5.3.4 moveUp (Function ID: 3)

Rolladen hochfahren.
Request:
Byte 0: Function ID = 3


5.3.5 moveDown (Function ID: 4)

Rolladen runterfahren.
Request:
Byte 0: Function ID = 4


5.3.6 stop (Function ID: 5)

Rolladen stoppen.
Request:
Byte 0: Function ID = 5


5.3.7 setPosition (Function ID: 6)

Auf bestimmte Position fahren.
Request:
Byte 0:   Function ID = 6
Byte 1:   position (Byte) - Zielposition 0-100%
Byte 2:   tiltPosition (Byte) - Lamellenstellung 0-100% (nur Jalousie)

Beispiel - Rolladen auf 50% fahren:
data = bytes([6, 50, 0])  # setPosition, 50%, keine Lamellen


5.3.8 moveToTop (Function ID: 7)

Komplett hochfahren (0%).
Request:
Byte 0: Function ID = 7


5.3.9 moveToBottom (Function ID: 8)

Komplett runterfahren (100%).
Request:
Byte 0: Function ID = 8


5.3.10 setTiltPosition (Function ID: 9)

Nur Lamellenstellung ändern (Jalousie).
Request:
Byte 0: Function ID = 9
Byte 1: tiltPosition (Byte) - Lamellenstellung 0-100%


5.3.11 calibrate (Function ID: 10)

Startet Kalibrierungsfahrt.
Request:
Byte 0: Function ID = 10


5.4 Shutter Events

5.4.1 evMovingUp (Function ID: 200)

Rolladen fährt hoch.
Event-Daten:
Byte 0: Function ID = 200
Byte 1: startPosition - Startposition


5.4.2 evMovingDown (Function ID: 201)

Rolladen fährt runter.
Event-Daten:
Byte 0: Function ID = 201
Byte 1: startPosition - Startposition


5.4.3 evStopped (Function ID: 202)

Rolladen gestoppt.
Event-Daten:
Byte 0: Function ID = 202
Byte 1: position - Aktuelle Position
Byte 2: tiltPosition - Lamellenstellung


5.4.4 evPositionReached (Function ID: 203)

Zielposition erreicht.
Event-Daten:
Byte 0: Function ID = 203
Byte 1: position - Erreichte Position
Byte 2: tiltPosition - Lamellenstellung


5.4.5 evTopReached (Function ID: 204)

Obere Endlage erreicht.
Event-Daten:
Byte 0: Function ID = 204


5.4.6 evBottomReached (Function ID: 205)

Untere Endlage erreicht.
Event-Daten:
Byte 0: Function ID = 205


5.4.7 evStatus (Function ID: 206)

Statusmeldung.
Event-Daten:
Byte 0: Function ID = 206
Byte 1: state (EState)
Byte 2: position
Byte 3: tiltPosition
Byte 4: direction


5.5 Rolladen Migrations-Beispiel
ASCII (alt):
SET SHUTTER 1 UP
SET SHUTTER 1 POSITION 50
GET SHUTTER 1 STATUS

UDP (neu):
class ShutterController:
    def \\init\\(self, device\id, instance\id, shutter\class\id=10):
        self.object\id = (device\id << 16) | (shutter\class\id << 8) | instance\_id
        self.sock = socket.socket(socket.AF\INET, socket.SOCK\DGRAM)
        self.sock.setsockopt(socket.SOL\SOCKET, socket.SO\BROADCAST, 1)
        self.counter = 0
    
    def \send(self, function\id, data=b''):
        self.counter = (self.counter + 1) % 256
        
        telegram = bytes([0xEF, 0xEF, 0x00, self.counter])
        telegram += struct.pack('<I', 0)  # Sender
        telegram += struct.pack('<I', self.object\_id)  # Receiver
        telegram += struct.pack('<H', len(data) + 1)  # Length
        telegram += bytes([function\_id]) + data
        
        self.sock.sendto(telegram, ('255.255.255.255', 9))
    
    def move\_up(self):
        """Rolladen hochfahren"""
        self.\_send(3)
    
    def move\_down(self):
        """Rolladen runterfahren"""
        self.\_send(4)
    
    def stop(self):
        """Rolladen stoppen"""
        self.\_send(5)
    
    def set\_position(self, position, tilt=0):
        """Position setzen (0-100%)"""
        self.\_send(6, bytes([position, tilt]))
    
    def move\to\top(self):
        """Komplett hochfahren"""
        self.\_send(7)
    
    def move\to\bottom(self):
        """Komplett runterfahren"""
        self.\_send(8)
    
    def get\_status(self):
        """Status abfragen"""
        self.\_send(2)

Verwendung
shutter1 = ShutterController(device\id=0x5900, instance\id=1)
shutter1.set\_position(50)  # Auf 50% fahren


Vollständige Migrations-Implementierung

6.1 Basis-Klassen

import socket
import struct
import threading
from enum import IntEnum
from typing import Callable, Dict, Optional
from dataclasses import dataclass

class FunctionType(IntEnum):
    COMMAND = 0
    RESULT = 128
    EVENT = 200

@dataclass
class ObjectId:
    device\_id: int
    class\_id: int
    instance\_id: int
    
    @property
    def value(self) -> int:
        return (self.device\id << 16) | (self.class\id << 8) | self.instance\_id
    
    @classmethod
    def from\_value(cls, value: int) -> 'ObjectId':
        return cls(
            device\_id=(value >> 16) & 0xFFFF,
            class\_id=(value >> 8) & 0xFF,
            instance\_id=value & 0xFF
        )
    
    def \\str\\(self):
        return f"Device:{self.device\id:04X} Class:{self.class\id} Instance:{self.instance\_id}"

@dataclass
class Telegram:
    sender: ObjectId
    receiver: ObjectId
    function\_id: int
    data: bytes
    counter: int = 0
    
    @property
    def is\_command(self) -> bool:
        return self.function\_id < 128
    
    @property
    def is\_result(self) -> bool:
        return 128 <= self.function\_id < 200
    
    @property
    def is\_event(self) -> bool:
        return self.function\_id >= 200
    
    def to\_bytes(self) -> bytes:
        header = bytes([0xEF, 0xEF, 0x00, self.counter])
        sender = struct.pack('<I', self.sender.value)
        receiver = struct.pack('<I', self.receiver.value)
        length = struct.pack('<H', len(self.data) + 1)
        payload = bytes([self.function\_id]) + self.data
        return header + sender + receiver + length + payload
    
    @classmethod
    def from\_bytes(cls, data: bytes) -> Optional['Telegram']:
        if len(data) < 15 or data[0:2] != bytes([0xEF, 0xEF]):
            return None
        
        counter = data[3]
        sender = ObjectId.from\_value(struct.unpack('<I', data[4:8])[0])
        receiver = ObjectId.from\_value(struct.unpack('<I', data[8:12])[0])
        length = struct.unpack('<H', data[12:14])[0]
        function\_id = data[14]
        payload = data[15:15+length-1] if length > 1 else b''
        
        return cls(sender, receiver, function\_id, payload, counter)


6.2 HausBus Client

class HausBusClient:
    def \\init\\(self, listen\port: int = 9, broadcast\addr: str = '255.255.255.255'):
        self.listen\port = listen\port
        self.broadcast\addr = broadcast\addr
        self.counter = 0
        self.devices: Dict[int, Dict] = {}
        self.event\_handlers: Dict[int, list] = {}
        self.running = False
        
        # Sende-Socket
        self.send\sock = socket.socket(socket.AF\INET, socket.SOCK\_DGRAM)
        self.send\sock.setsockopt(socket.SOL\SOCKET, socket.SO\_BROADCAST, 1)
        
        # Empfangs-Socket
        self.recv\sock = socket.socket(socket.AF\INET, socket.SOCK\_DGRAM)
        self.recv\sock.setsockopt(socket.SOL\SOCKET, socket.SO\_REUSEADDR, 1)
        self.recv\sock.bind(('0.0.0.0', listen\port))
    
    def send(self, receiver: ObjectId, function\_id: int, data: bytes = b'') -> None:
        self.counter = (self.counter + 1) % 256
        sender = ObjectId(device\id=0, class\id=0, instance\_id=0)
        telegram = Telegram(sender, receiver, function\_id, data, self.counter)
        self.send\sock.sendto(telegram.to\bytes(), (self.broadcast\addr, self.listen\port))
    
    def register\event\handler(self, class\_id: int, handler: Callable[[Telegram], None]) -> None:
        if class\id not in self.event\handlers:
            self.event\handlers[class\id] = []
        self.event\handlers[class\id].append(handler)
    
    def \receive\loop(self):
        while self.running:
            try:
                data, addr = self.recv\_sock.recvfrom(1024)
                telegram = Telegram.from\_bytes(data)
                if telegram and telegram.is\_event:
                    class\id = telegram.sender.class\id
                    if class\id in self.event\handlers:
                        for handler in self.event\handlers[class\id]:
                            handler(telegram)
            except Exception as e:
                print(f"Receive error: {e}")
    
    def start(self):
        self.running = True
        self.recv\thread = threading.Thread(target=self.\receive\_loop, daemon=True)
        self.recv\_thread.start()
    
    def stop(self):
        self.running = False
        self.recv\_sock.close()
        self.send\_sock.close()
    
    def discover\_devices(self):
        """Sendet Broadcast zur Geräte-Erkennung"""
        broadcast\receiver = ObjectId(device\id=0xFFFF, class\id=0xFF, instance\id=0xFF)
        self.send(broadcast\_receiver, 0)  # getModuleId


6.3 Geräte-Wrapper-Klassen

class RGBDimmer:
    CLASS\_ID = 5  # Anpassen an tatsächliche ClassId
    
    def \\init\\(self, client: HausBusClient, device\id: int, instance\id: int):
        self.client = client
        self.object\id = ObjectId(device\id, self.CLASS\ID, instance\id)
    
    def set\brightness(self, brightness: int, duration\ms: int = 0):
        data = bytes([brightness]) + struct.pack('<I', duration\_ms)
        self.client.send(self.object\_id, 3, data)
    
    def set\color(self, red: int, green: int, blue: int, duration\ms: int = 500):
        data = bytes([red, green, blue]) + struct.pack('<I', duration\_ms)
        self.client.send(self.object\_id, 6, data)
    
    def start(self, direction: int):
        self.client.send(self.object\_id, 4, bytes([direction]))
    
    def stop(self):
        self.client.send(self.object\_id, 5)
    
    def on(self, duration\_ms: int = 500):
        self.set\brightness(200, duration\ms)
    
    def off(self, duration\_ms: int = 500):
        self.set\brightness(0, duration\ms)

class Shutter:
    CLASS\_ID = 10  # Anpassen an tatsächliche ClassId
    
    def \\init\\(self, client: HausBusClient, device\id: int, instance\id: int):
        self.client = client
        self.object\id = ObjectId(device\id, self.CLASS\ID, instance\id)
    
    def move\_up(self):
        self.client.send(self.object\_id, 3)
    
    def move\_down(self):
        self.client.send(self.object\_id, 4)
    
    def stop(self):
        self.client.send(self.object\_id, 5)
    
    def set\_position(self, position: int, tilt: int = 0):
        self.client.send(self.object\_id, 6, bytes([position, tilt]))
    
    def move\to\top(self):
        self.client.send(self.object\_id, 7)
    
    def move\to\bottom(self):
        self.client.send(self.object\_id, 8)

class Button:
    CLASS\_ID = 20  # Anpassen an tatsächliche ClassId
    
    def \\init\\(self, client: HausBusClient, device\id: int, instance\id: int):
        self.client = client
        self.object\id = ObjectId(device\id, self.CLASS\ID, instance\id)
        self.on\_click = None
        self.on\double\click = None
        self.on\hold\start = None
        self.on\hold\end = None
        
        # Event-Handler registrieren
        client.register\event\handler(self.CLASS\ID, self.\handle\_event)
    
    def \handle\event(self, telegram: Telegram):
        if telegram.sender.instance\id != self.object\id.instance\_id:
            return
        
        if telegram.function\id == 201 and self.on\click:
            self.on\_click()
        elif telegram.function\id == 202 and self.on\double\_click:
            self.on\double\click()
        elif telegram.function\id == 203 and self.on\hold\_start:
            self.on\hold\start()
        elif telegram.function\id == 204 and self.on\hold\_end:
            self.on\hold\end()


6.4 Vollständiges Anwendungsbeispiel

def main():
    # Client initialisieren
    client = HausBusClient()
    client.start()
    
    # Geräte initialisieren
    rgb\dimmer = RGBDimmer(client, device\id=0x5900, instance\_id=1)
    shutter1 = Shutter(client, device\id=0x5901, instance\id=1)
    shutter2 = Shutter(client, device\id=0x5901, instance\id=2)
    button1 = Button(client, device\id=0x5902, instance\id=1)
    
    # Event-Handler für Taster
    def on\button1\click():
        print("Button 1 clicked - Toggle RGB Dimmer")
        rgb\dimmer.set\color(200, 100, 50, 500)
    
    def on\button1\double\_click():
        print("Button 1 double-clicked - All shutters up")
        shutter1.move\to\top()
        shutter2.move\to\top()
    
    def on\button1\hold():
        print("Button 1 held - Dimmer off")
        rgb\_dimmer.off()
    
    button1.on\click = on\button1\_click
    button1.on\double\click = on\button1\double\_click
    button1.on\hold\start = on\button1\hold
    
    # Beispiel-Kommandos
    print("Setting RGB to warm white...")
    rgb\dimmer.set\color(200, 150, 100, 1000)
    
    print("Moving shutter 1 to 50%...")
    shutter1.set\_position(50)
    
    # Endlosschleife für Event-Verarbeitung
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.stop()
        print("Client stopped")

if \\name\\ == "\\main\\":
    main()


Fehlerbehandlung und Debugging

7.1 Häufige Fehler

| Fehler | Ursache | Lösung |
|--------|---------|--------|
| Keine Antwort | Falsche ObjectId | DeviceId, ClassId, InstanceId prüfen |
| Timeout | Firewall blockiert Port 9 | UDP Port 9 freigeben |
| Falsche Werte | Byte-Order falsch | Little-Endian für Multi-Byte-Werte |
| Events fehlen | Listener nicht aktiv | Socket auf Port 9 binden |

7.2 Debug-Logging

def debug\_telegram(data: bytes, direction: str = "RX"):
    if len(data) < 15:
        print(f"{direction}: Invalid telegram (too short)")
        return
    
    telegram = Telegram.from\_bytes(data)
    if not telegram:
        print(f"{direction}: Failed to parse telegram")
        return
    
    msg\type = "CMD" if telegram.is\command else "RES" if telegram.is\_result else "EVT"
    print(f"{direction} [{msg\_type}] From:{telegram.sender} To:{telegram.receiver} "
          f"Func:{telegram.function\_id} Data:{telegram.data.hex()}")


7.3 Wireshark Filter

Für Netzwerk-Debugging mit Wireshark:

udp.port == 9 && data[0:2] == ef:ef


Anhang

8.1 ClassId Referenztabelle

| ClassId | Beschreibung |
|---------|--------------|
| 1 | Controller |
| 5 | Dimmer |
| 6 | RGBDimmer |
| 10 | Shutter |
| 20 | Button |
| 21 | LogicalButton |
| 30 | Led |
| 40 | TemperatureSensor |
| 41 | HumiditySensor |

Hinweis: Tatsächliche ClassIds können je nach Firmware-Version variieren.

8.2 Migrations-Checkliste

[ ] UDP Port 9 in Firewall freigeben
[ ] Alle Device-IDs aus ASCII-System dokumentieren
[ ] ClassIds für verwendete Gerätetypen ermitteln
[ ] Event-Handler für alle benötigten Ereignisse implementieren
[ ] Alte ASCII-Verknüpfungen in UDP-Format übersetzen
[ ] Testphase mit Parallelbereich (ASCII + UDP)
[ ] Vollständige Migration nach erfolgreichem Test

8.3 Weiterführende Ressourcen

PyHausBus Repository: https://github.com/hausbus/PyHausBus
ioBroker Adapter: https://github.com/hausbus/ioBroker.hausbus\_de

Dokumentversion: 1.0
Erstellt für: HausBus UDP-Protokoll Migration
