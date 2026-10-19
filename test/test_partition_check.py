import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PartitionTests(unittest.TestCase):
    def test_application_slot_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            image = bytearray(1_072_528)
            image[0] = 0xe9
            struct.pack_into("<H", image, 12, 9)
            binary = root / "app.bin"
            binary.write_bytes(image)
            table = root / "table.csv"
            table.write_text("app0,app,test,0x10000,0x150000\napp1,app,ota_0,0x170000,0x110000\n")
            command = [sys.executable, str(ROOT / "scripts/check_launcher_partition.py"), str(binary), str(table)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("app1", result.stdout)
            table.write_text("app0,app,test,0x10000,0x150000\napp1,app,ota_0,0x170000,0x100000\n")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            # A large resident Launcher partition is not an installable OTA slot.
            table.write_text("app0,app,test,0x10000,0x600000\n")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            raw = struct.pack("<HBBII16sI", 0x50aa, 0, 0x10, 0x170000, 0x110000, b"app1", 0) + bytes([255]) * 32
            raw_table = root / "partitions.bin"
            raw_table.write_bytes(raw)
            command[-1] = str(raw_table)
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertNotEqual(subprocess.run(command + ["--label", "app0"], capture_output=True).returncode, 0)
            raw_table.write_bytes(b"invalid" * 10)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            raw_table.write_bytes(raw)
            image[12] = 0
            binary.write_bytes(image)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
