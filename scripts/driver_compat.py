"""Build-local, SHA-pinned symbol interposition for the transport-only experiment."""
Import("env")
from pathlib import Path
import hashlib
import re
import shutil
import struct
import subprocess

if env["PIOENV"].endswith("_transport"):
    sdk = Path(env.PioPlatform().get_package_dir("framework-arduinoespressif32")) / "tools/sdk/esp32s3/lib/libnet80211.a"
    expected = "6aae206c85e9009a24cd1f28ce535e2a2d578d9687fe2dc77d4697d45ebc8d0f"
    if hashlib.sha256(sdk.read_bytes()).hexdigest() != expected:
        raise RuntimeError("Transport experiment requires the reviewed ESP32-S3 IDF 4.4.7 archive")
    directory = Path(env.subst("$BUILD_DIR")) / "driver-compat"
    directory.mkdir(parents=True, exist_ok=True)
    tools = Path(env.PioPlatform().get_package_dir("toolchain-xtensa-esp32s3")) / "bin"
    def run(name, *args):
        return subprocess.check_output([str(tools / ("xtensa-esp32s3-elf-" + name)), *map(str, args)], cwd=directory, text=True)
    run("ar", "x", sdk, "ieee80211_output.o")
    obj = directory / "ieee80211_output.o"
    if hashlib.sha256(obj.read_bytes()).hexdigest() != "d45eb112858cebda77262402b7436db5aa8313df06e28fc78c2e6f40891d9574":
        raise RuntimeError("Unexpected raw TX object")
    # Keep every instruction and relocation. Add an alias to the original function and weaken only its public symbol.
    run("objcopy", "--weaken-symbol=ieee80211_raw_frame_sanity_check",
        "--add-symbol=radar_stock_raw_frame_check=.text.ieee80211_raw_frame_sanity_check:0x5c,global,function", obj)
    library = directory / sdk.name
    shutil.copyfile(sdk, library)
    run("ar", "r", library, obj)
    env.Prepend(LIBPATH=[str(directory)])

    def verify(source, target, env):
        elf = Path(str(target[0])).resolve()
        symbols = {}
        for line in run("nm", "--defined-only", elf).splitlines():
            fields = line.split()
            if len(fields) == 3:
                symbols[fields[2]] = (int(fields[0], 16), fields[1])
        name = "ieee80211_raw_frame_sanity_check"
        wrapper = symbols.get(name)
        stock = symbols.get("radar_stock_raw_frame_check")
        if not wrapper or wrapper[1] != "T" or not stock or wrapper[0] == stock[0]:
            raise RuntimeError("Missing strong compatibility wrapper or original check")
        dis = run("objdump", "-d", "--disassemble=esp_wifi_80211_tx", elf)
        direct = re.search(r"call8\s+([0-9a-f]+)\s+<ieee80211_raw_frame_sanity_check>", dis)
        resolved = int(direct[1], 16) if direct else None
        if not direct:
            literal = re.search(r"l32r\s+a8,\s*([0-9a-f]+)", dis)
            if not literal:
                raise RuntimeError("Cannot verify the raw TX call site")
            address = int(literal[1], 16)
            data = elf.read_bytes()
            section_offset = struct.unpack_from("<I", data, 32)[0]
            entry_size, count = struct.unpack_from("<HH", data, 46)
            for i in range(count):
                _, kind, _, start, offset, size = struct.unpack_from("<6I", data, section_offset + i * entry_size)
                if kind != 8 and start <= address < start + size:
                    resolved = struct.unpack_from("<I", data, offset + address - start)[0]
                    break
        if resolved != wrapper[0]:
            raise RuntimeError("Raw TX does not call the compatibility wrapper")
        if hashlib.sha256(sdk.read_bytes()).hexdigest() != expected:
            raise RuntimeError("Global SDK archive changed")
        print("PASS: transport raw TX calls the strong scoped wrapper; original check retained; global SDK unchanged")
    env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", verify)
