#!/usr/bin/env python3
# =============================================================================
#  MOCK DET DRIP - sync_time.py
#  Seeds the transmitter's DRIP clock from the PC's real UTC clock over serial
#  (ADR 0002). It sends the firmware command:  time <unix_seconds_UTC>
#
#  Priority time source for the bench: the PC clock. If no seed is sent, the
#  firmware falls back to the SIM_DRIP_TIME_BASE constant (may be stale).
#
#  IMPORTANT: a serial port can be held by only ONE program. Close the Arduino
#  Serial Monitor before running this. (Alternatively, just type `time <unix>`
#  in the Serial Monitor yourself - this script only automates that.)
#
#  Usage:
#     python sync_time.py --port COM4            # transmitter console @115200
#     python sync_time.py --port COM4 --wait 3   # wait longer for boot
# =============================================================================
import argparse
import sys
import time

try:
    import serial   # pyserial (same dependency arduino_logger.py uses)
except Exception:
    sys.exit("sync_time.py needs pyserial:  pip install pyserial")


def main():
    ap = argparse.ArgumentParser(description="Seed the transmitter DRIP clock "
                                             "from the PC clock over serial.")
    ap.add_argument("--port", required=True, help="transmitter serial port (e.g. COM4)")
    ap.add_argument("--baud", type=int, default=115200, help="console baud (default 115200)")
    ap.add_argument("--wait", type=float, default=2.0,
                    help="seconds to wait after opening, to let the board boot")
    args = ap.parse_args()

    try:
        with serial.Serial(args.port, args.baud, timeout=1) as s:
            time.sleep(args.wait)                 # let the ESP32 finish booting
            now = int(time.time())                # Unix seconds, UTC by definition
            s.write(f"time {now}\n".encode())
            print(f"sent: time {now}")
            # Echo the board's reply for a couple of seconds so you see it seed.
            t0 = time.time()
            while time.time() - t0 < 2.0:
                line = s.readline().decode(errors="replace").strip()
                if line:
                    print(f"  {line}")
    except serial.SerialException as e:
        sys.exit(f"cannot open {args.port}: {e}  "
                 f"(is the Arduino Serial Monitor still open?)")


if __name__ == "__main__":
    main()
