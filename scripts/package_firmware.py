"""Package only the application image. No bootloader or partition table."""
Import("env")
from pathlib import Path
import hashlib
import json
import re
import shutil

env.Append(LINKFLAGS=["-flto"])


def package(source, target, env):
    binary = Path(str(target[0]))
    if binary.read_bytes()[0] != 0xE9:
        raise RuntimeError("Expected an ESP application image")
    if binary.stat().st_size > 0x180000:
        raise RuntimeError("Application exceeds the conservative 1.5 MiB build guard")
    project = Path(env.subst("$PROJECT_DIR"))
    version = re.search(r'kFirmwareVersion\s*=\s*"([^"]+)"',
                        (project / "include" / "RadarTypes.h").read_text()).group(1)
    output = project / "dist"
    output.mkdir(exist_ok=True)
    variant = "RadarADV" if env["PIOENV"] == "cardputer_adv" else "Radar"
    name = f"{variant}-{version}.bin"
    destination = output / name
    shutil.copyfile(binary, destination)
    metadata = {"file": name, "bytes": destination.stat().st_size,
                "required_aligned_app_partition_bytes": (destination.stat().st_size + 65535) & ~65535,
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                "format": "ESP32-S3 application only; no bootloader or partition table"}
    (output / (name + ".json")).write_text(json.dumps(metadata, indent=2) + "\n")


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", package)
