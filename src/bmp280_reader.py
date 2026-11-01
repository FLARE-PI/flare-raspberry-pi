#!/usr/bin/env python3
"""Small dependency-free BMP280 reader using the Linux i2c-dev interface."""

import argparse
import fcntl
import json
import os
import time
from datetime import datetime, timezone

I2C_SLAVE = 0x0703
CHIP_ID_REGISTER = 0xD0
EXPECTED_CHIP_ID = 0x58


def _u16(data, offset):
    return data[offset] | (data[offset + 1] << 8)


def _s16(data, offset):
    value = _u16(data, offset)
    return value - 65536 if value & 0x8000 else value


class BMP280:
    """Read calibrated temperature and pressure from one BMP280 sensor."""

    def __init__(self, device="/dev/i2c-1", address=0x76):
        self.device = device
        self.address = address
        self.fd = None
        self.calibration = None

    def __enter__(self):
        self.fd = os.open(self.device, os.O_RDWR)
        fcntl.ioctl(self.fd, I2C_SLAVE, self.address)
        chip_id = self.read_register(CHIP_ID_REGISTER, 1)[0]
        if chip_id != EXPECTED_CHIP_ID:
            self.close()
            raise RuntimeError(
                "unexpected BMP280 chip ID 0x%02x at 0x%02x (expected 0x%02x)"
                % (chip_id, self.address, EXPECTED_CHIP_ID)
            )
        self.calibration = self._read_calibration()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read_register(self, register, length):
        os.write(self.fd, bytes((register,)))
        data = os.read(self.fd, length)
        if len(data) != length:
            raise RuntimeError("short I2C read from register 0x%02x" % register)
        return data

    def write_register(self, register, value):
        written = os.write(self.fd, bytes((register, value)))
        if written != 2:
            raise RuntimeError("short I2C write to register 0x%02x" % register)

    def _read_calibration(self):
        data = self.read_register(0x88, 24)
        return {
            "T1": _u16(data, 0), "T2": _s16(data, 2), "T3": _s16(data, 4),
            "P1": _u16(data, 6), "P2": _s16(data, 8), "P3": _s16(data, 10),
            "P4": _s16(data, 12), "P5": _s16(data, 14), "P6": _s16(data, 16),
            "P7": _s16(data, 18), "P8": _s16(data, 20), "P9": _s16(data, 22),
        }

    def sample(self):
        # x1 temperature/pressure oversampling, forced conversion mode.
        self.write_register(0xF4, 0x25)
        deadline = time.monotonic() + 0.2
        while self.read_register(0xF3, 1)[0] & 0x08:
            if time.monotonic() >= deadline:
                raise RuntimeError("BMP280 conversion did not complete")
            time.sleep(0.002)

        data = self.read_register(0xF7, 6)
        raw_pressure = (data[0] << 12) | (data[1] << 4) | (data[2] >> 4)
        raw_temperature = (data[3] << 12) | (data[4] << 4) | (data[5] >> 4)
        temperature_c, t_fine = self._compensate_temperature(raw_temperature)
        pressure_hpa = self._compensate_pressure(raw_pressure, t_fine)
        if not -40.0 <= temperature_c <= 85.0:
            raise RuntimeError("BMP280 temperature outside sensor range: %.3f C" % temperature_c)
        if not 300.0 <= pressure_hpa <= 1100.0:
            raise RuntimeError("BMP280 pressure outside plausible range: %.3f hPa" % pressure_hpa)
        return {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "temperature_c": round(temperature_c, 3),
            "pressure_hpa": round(pressure_hpa, 3),
            "raw_temperature": raw_temperature,
            "raw_pressure": raw_pressure,
        }

    def _compensate_temperature(self, raw):
        c = self.calibration
        var1 = (raw / 16384.0 - c["T1"] / 1024.0) * c["T2"]
        var2 = ((raw / 131072.0 - c["T1"] / 8192.0) ** 2) * c["T3"]
        t_fine = var1 + var2
        return t_fine / 5120.0, t_fine

    def _compensate_pressure(self, raw, t_fine):
        c = self.calibration
        var1 = t_fine / 2.0 - 64000.0
        var2 = var1 * var1 * c["P6"] / 32768.0
        var2 = var2 + var1 * c["P5"] * 2.0
        var2 = var2 / 4.0 + c["P4"] * 65536.0
        var1 = (c["P3"] * var1 * var1 / 524288.0 + c["P2"] * var1) / 524288.0
        var1 = (1.0 + var1 / 32768.0) * c["P1"]
        if var1 == 0:
            raise RuntimeError("BMP280 pressure calibration has zero divisor")
        pressure = 1048576.0 - raw
        pressure = (pressure - var2 / 4096.0) * 6250.0 / var1
        var1 = c["P9"] * pressure * pressure / 2147483648.0
        var2 = pressure * c["P8"] / 32768.0
        return (pressure + (var1 + var2 + c["P7"]) / 16.0) / 100.0


def parse_address(value):
    return int(value, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", default="/dev/i2c-1")
    parser.add_argument("--address", type=parse_address, default=0x76)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    if args.samples < 1 or args.interval < 0:
        parser.error("samples must be positive and interval must not be negative")
    with BMP280(args.device, args.address) as sensor:
        for index in range(args.samples):
            print(json.dumps(sensor.sample(), sort_keys=True))
            if index + 1 < args.samples:
                time.sleep(args.interval)


if __name__ == "__main__":
    main()
