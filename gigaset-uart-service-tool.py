import argparse
import sys
import time
import serial

STX, ETX, ACK, DLE, XON, XOFF, NAK = 0x02, 0x03, 0x06, 0x10, 0x11, 0x13, 0x15
ESCAPED_CTRL = {STX, ETX, ACK, DLE, XON, XOFF, NAK}
MAX_PAYLOAD = 0x53
BAUD_SCAN = [57600, 115200, 19200]

MODES = {
    "mode0":   0x00,
    "debug":   0x44,
    "config":  0x3C,
    "test":    0x38,
    "mode4":   0xA5,
    "mode5":   0x93,
    "mode6":   0x53,
    "mode7":   0xD7,
    "mode8":   0xE9,
}

TASK_NAME = {
    0x00: "mac",
    0x01: "bearer-idle",
    0x02: "bearer-traffic",
    0x03: "dlc",
    0x04: "nwk-lce",
    0x05: "nwk-cc",
    0x06: "nwk-mm",
    0x07: "auth",
    0x08: "nwk-router",
    0x09: "nwk-app-bridge-maybe",
    0x0a: "task10",
    0x0b: "task11",
    0x0c: "task12",
    0x0d: "task13",
    0x0e: "task14",
    0x0f: "task15",
    0x10: "task16",
    0x11: "task17",
    0x12: "task18",
    0x13: "task19",
    0x14: "task20",
    0x15: "task21",
    0x16: "task22",
    0x17: "test",
    0x1f: "system",
    0x20: "uart",
    0xff: "-",
}

CRC_SEED = 0xAA55
CRC_TABLE = []

for i in range(256):
    v = i << 8
    for _ in range(8):
        v = ((v << 1) ^ 0x1021) & 0xFFFF if v & 0x8000 else (v << 1) & 0xFFFF
    CRC_TABLE.append(v)

def crc16(data, crc=CRC_SEED):
    for b in data:
        crc = CRC_TABLE[(b ^ (crc >> 8)) & 0xFF] ^ ((crc << 8) & 0xFFFF)
    return crc & 0xFFFF

def build_frame(payload):
    assert len(payload) <= MAX_PAYLOAD

    def escape(b):
        if b in ESCAPED_CTRL:
            return [DLE, b]

        return [b]

    crc = crc16(payload)
    body = bytes(payload) + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    out = bytearray([STX])
    for b in body:
        out.extend(escape(b))
    out.append(ETX)
    return bytes(out)


class Deframer:
    IDLE, IN_FRAME, AWAIT_ETX = 0, 1, 2

    def __init__(self):
        self.state = self.IDLE
        self.escaped = False
        self.buf = bytearray()
        self.crc = CRC_SEED

    def feed(self, byte):
        events = []
        if self.escaped:
            self.escaped = False
            if self.state == self.IN_FRAME:
                self._data(byte)
            return events

        if byte == DLE:
            self.escaped = True
            return events

        if byte == STX:
            self.state = self.IN_FRAME
            self.buf = bytearray()
            self.crc = CRC_SEED
            return events

        if byte == ETX:
            if self.state == self.IN_FRAME and len(self.buf) >= 2:
                payload = self.buf[:-2]
                expected = self.buf[-2] | (self.buf[-1] << 8)
                events.append(("frame", bytes(payload)) if crc16(payload) == expected else ("nak", None))

            self.state = self.IDLE
            return events

        if self.state == self.IN_FRAME:
            if byte in ESCAPED_CTRL:
                self.state = self.IDLE
            else:
                self._data(byte)
        elif byte in (ACK, NAK, XON, XOFF):
            events.append(("ctrl", byte))

        return events

    def _data(self, byte):
        if len(self.buf) < MAX_PAYLOAD + 2:
            self.buf.append(byte)
        else:
            self.state = self.IDLE


class Session:
    def __init__(self, port, baud=57600, timeout=0.02, verbose=False):
        self.ser = serial.Serial(port, baud, timeout=timeout)
        self.deframer = Deframer()
        self.verbose = verbose
        self.tx_seq = 0
        self.pending = []

    def reset_handset(self):
        self.ser.rts = True
        self.ser.dtr = False
        time.sleep(0.1)
        self.ser.reset_input_buffer()
        self.deframer = Deframer()
        self.ser.rts = False

    def _log(self, *a):
        if self.verbose:
            print("   ", *a, file=sys.stderr)

    def _pump(self, deadline):
        while time.monotonic() < deadline:
            chunk = self.ser.read(64)
            for b in chunk:
                for kind, val in self.deframer.feed(b):
                    if kind == "frame":
                        self.ser.write(bytes([ACK]))
                        self._log(f"rx {val.hex()}")
                        self.pending.append(val)
                    elif kind == "nak":
                        self.ser.write(bytes([NAK]))
                    else:
                        self._log(f"ctrl {val:#04x}")
        return self.pending

    def recv(self, timeout=1.0):
        deadline = time.monotonic() + timeout
        while True:
            if self.pending:
                return self.pending.pop(0)
            if time.monotonic() >= deadline:
                return None
            self._pump(min(deadline, time.monotonic() + 0.05))

    def send(self, payload, expect_ack=True, timeout=0.5):
        self._log(f"tx {bytes(payload).hex()}")
        self.ser.write(build_frame(payload))
        if not expect_ack:
            return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for b in self.ser.read(32):
                for kind, val in self.deframer.feed(b):
                    if kind == "ctrl" and val in (ACK, XOFF):
                        return True
                    if kind == "ctrl" and val == NAK:
                        return False
                    if kind == "frame":
                        self.ser.write(bytes([ACK]))
                        self.pending.append(val)
        return False

    def connect(self, mode="debug", new_baud=None):
        magic = MODES[mode]
        self.reset_handset()

        probe = None
        while time.monotonic() < time.monotonic() + 8.0:
            probe = self.recv(timeout=0.25)
            if probe is not None and len(probe) == 1:
                break
            probe = None

        assert probe, "no probe seen"

        seq = probe[0]
        assert self.send(bytes([seq]))

        frame = self.recv(timeout=1.0)
        assert frame is not None and len(frame) == 2
        seq = frame[0]

        reply = bytearray([seq, 0x00, magic])
        if new_baud:
            reply += new_baud.to_bytes(4, "little")
        assert self.send(reply)

        self.tx_seq = (seq + 1) & 0xFF
        if new_baud:
            time.sleep(0.05)
            self.ser.baudrate = new_baud
        return self

    def send_packet(self, data):
        print("[tx_pkt]", (bytes([self.tx_seq]) + bytes(data)).hex())
        ok = self.send(bytes([self.tx_seq]) + bytes(data))
        self.tx_seq = (self.tx_seq + 1) & 0xFF
        return ok

    def recv_packet(self, timeout=1.0):
        frame = self.recv(timeout)
        if not frame: return None
        print("[rx_pkt]", frame.hex(), "=>", frame[1:].hex())
        return frame[1:] if frame else None

    def close(self):
        self.ser.close()


def reassemble(frames):
    out = bytearray()
    cmd = frames[0][0] if frames else None
    for f in frames:
        if len(f) < 2:
            continue
        if f[1] & 0x80:
            out += f[3:3 + f[2]] if len(f) > 2 else b""
        else:
            out += f[2:]
    return cmd, bytes(out)


class Monitor:
    def __init__(self, session: Session):
        self.s = session
        self.running = False

    def ensure_running(self):
        if not self.running:
            self.resume()
            time.sleep(1.0)
            while self.s.recv_packet(timeout=0.3):
                pass
            self.running = True

    def recv_reply(self, cmd, timeout=1.5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pkt = self.s.recv_packet(timeout=0.3)
            if pkt and pkt[0] == cmd:
                return pkt
        return None

    def read_memory(self, addr, length):
        out = bytearray()
        while len(out) < length:
            chunk = self.read_block32(addr + len(out))
            assert chunk
            out += chunk
        return bytes(out[:length])

    def set_trigger(self, index, count, trig_type, obj_id, consume=False):
        t = (trig_type & 0x7F) | (0x80 if consume else 0x00)
        return self.s.send_packet(bytes([0x29, count, index, t, obj_id]))

    def clear_triggers(self):
        return self.s.send_packet(bytes([0x29, 0, 0, 0, 0]))

    def arm_traces(self, queues=(), tasks=(), payload=True, consume=False):
        TRIG_MSG = 1
        TRIG_MSG_ALT = 2
        TRIG_MSG_PAYLOAD = 3
        TRIG_TASK_SWITCH = 4

        entries = [(TRIG_MSG_PAYLOAD if payload else TRIG_MSG, q) for q in queues]
        entries += [(TRIG_TASK_SWITCH, t) for t in tasks]
        assert len(entries) <= 10
        self.ensure_running()
        for i, (t, oid) in enumerate(entries):
            self.set_trigger(i, len(entries), t, oid, consume)
        return len(entries)

    def recv_message(self, cmd=None, timeout=2.5):
        frames, deadline = [], time.monotonic() + timeout
        while time.monotonic() < deadline:
            p = self.s.recv_packet(timeout=0.3)
            if not p or len(p) < 2:
                continue
            if cmd is not None and p[0] != cmd:
                continue
            frames.append(p)
            if p[1] & 0x80:
                return reassemble(frames)
        return (None, b"") if not frames else reassemble(frames)

    def read_block32(self, addr):
        self.ensure_running()
        self.s.send_packet(bytes([0x07, 0x00]) + addr.to_bytes(4, "little"))
        _, body = self.recv_message(0x0F)
        if len(body) < 4 or int.from_bytes(body[0:4], "little") != addr:
            return None
        return body[4:]

    def write_byte(self, addr, value):
        self.ensure_running()
        return self.s.send_packet(
            bytes([0x09, 0x00]) + addr.to_bytes(4, "little") + bytes([value & 0xFF]))

    def write_bytes(self, addr, data):
        for i, b in enumerate(data):
            if not self.write_byte(addr + i, b):
                return False
        return True

    def post_event(self, task_id, mask):
        self.ensure_running()
        return self.s.send_packet(bytes([0x15, task_id]) + (mask & 0xFFFF).to_bytes(2, "little"))

    def resume(self):
        self.running = True
        return self.s.send_packet(bytes([0x24]))

    def set_packet_size(self, size):
        size = min(size, 0x4E)
        return self.s.send_packet(bytes([0x44, 0x01, size, size]))

    def key(self, code):
        self.ensure_running()
        return self.s.send_packet(bytes([0x36, code]))

    def key_repeat(self, count_a, count_b=0):
        self.ensure_running()
        return self.s.send_packet(bytes([0x43, count_a, count_b]))

    def trace_enable(self, on=True):
        self.ensure_running()
        self.s.send_packet(bytes([0x82, 1 if on else 0]))
        return self.s.send_packet(bytes([0x81, 0x02 if on else 0x00]))

def cmd_read(args, mon: Monitor):
    data = mon.read_memory(args.addr, args.length)
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
        print(f"{args.addr + off:08x}  {row.hex(' '):<47}  {text}")

def cmd_write(args, mon: Monitor):
    before = mon.read_memory(args.addr, len(args.values))
    print(f"before: {before.hex(' ')}")

    for i, v in enumerate(args.values):
        mon.write_byte(args.addr + i, v)

    after = mon.read_memory(args.addr, len(args.values))
    print(f"after:  {after.hex(' ')}")

def cmd_trace(args, mon: Monitor):
    queues = args.queue or [0x06, 0x07, 0x08, 0x09, 0x0a]
    tasks = args.task or []

    mon.arm_traces(queues, tasks, consume=args.consume)
    print(f"listening...", file=sys.stderr)

    frames = []
    try:
        last_keepalive = time.monotonic()
        keepalive_interval = 4.0

        while True:
            pkt = mon.s.recv_packet(timeout=0.5)
            now = time.monotonic()

            if now - last_keepalive >= keepalive_interval:
                last_keepalive = now
                try:
                    mon.s.send_packet(bytes([0x15, 0x15, 0x01, 0x00]))
                except Exception:
                    pass

            if not pkt:
                continue
            if len(pkt) >= 2 and not (pkt[1] & 0x80) and pkt[0] in (0x0F, 0x21):
                frames.append(pkt)
                continue
            if frames and pkt[0] == frames[0][0]:
                frames.append(pkt)
                cmd, body = reassemble(frames)
                frames = []
            else:
                cmd, body = reassemble([pkt])

            if cmd != 0xd4:
                print(f"{hex(cmd)}", "=>", body.hex())
    except KeyboardInterrupt:
        pass
    finally:
        mon.clear_triggers()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True)
    parser.add_argument("--baud", type=int, default=57600)
    parser.add_argument("--mode", default="debug", choices=list(MODES))
    parser.add_argument("-v", "--verbose", action="store_true")

    parser_cmd = parser.add_subparsers(dest="cmd", required=True)

    p = parser_cmd.add_parser("read")
    p.add_argument("addr", type=lambda x: int(x, 0))
    p.add_argument("length", type=lambda x: int(x, 0))

    p = parser_cmd.add_parser("write")
    p.add_argument("addr", type=lambda x: int(x, 0))
    p.add_argument("values", nargs="+", type=lambda x: int(x, 0))

    p = parser_cmd.add_parser("trace")
    p.add_argument("--queue", nargs="*", type=lambda x: int(x, 0))
    p.add_argument("--task", nargs="*", type=lambda x: int(x, 0))
    p.add_argument("--consume", action="store_true")

    args = parser.parse_args()

    session = Session(args.port, args.baud, verbose=args.verbose)
    try:
        session.connect(args.mode, 230400)
        mon = Monitor(session)
        handlers = {
            "read": cmd_read,
            "write": cmd_write,
            "trace": cmd_trace,
        }
        handlers[args.cmd](args, mon)
    except Exception as ex:
        print(ex)
    finally:
        session.close()

if __name__ == "__main__":
    main()
