#!/usr/bin/env python3
"""Render production UI previews with synthetic data, not device screenshots.

Run after installing the pinned cardputer_adv PlatformIO dependencies.
Uses the existing host backends, the project's M5GFX GLCD font and stdlib PNG output.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile
import zlib

ROOT = Path(__file__).resolve().parent.parent
FONT_ROOT = ROOT / '.pio/libdeps/cardputer_adv/M5GFX'
FONT_SOURCE = FONT_ROOT / 'src/lgfx/Fonts/glcdfont.h'
COLORS = ((0, 0, 0), (255, 255, 255), (255, 182, 0), (0, 0, 123), (0, 255, 255))


def png(path, pixels, width, height):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))

    scanlines = b''.join(b'\0' + bytes(pixels[y * width * 3:(y + 1) * width * 3]) for y in range(height))
    path.write_bytes(b'\x89PNG\r\n\x1a\n' +
                     chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) +
                     chunk(b'IDAT', zlib.compress(scanlines, 9)) + chunk(b'IEND', b''))


def main():
    if not FONT_SOURCE.is_file():
        raise SystemExit('Build cardputer_adv first to install the pinned M5GFX dependency.')
    pinned = re.search(r'm5stack/M5GFX@([^\s]+)', (ROOT / 'platformio.ini').read_text())[1]
    assert json.loads((FONT_ROOT / 'library.json').read_text())['version'] == pinned
    font_text = FONT_SOURCE.read_text()
    glyphs = re.search(r'font\[\].*?=\s*\{(.*?)\};', font_text, re.S)[1]
    glyphs = re.sub(r'//[^\n]*|/\*.*?\*/', '', glyphs, flags=re.S)
    font = bytes(int(value, 16) for value in re.findall(r'0x([0-9a-fA-F]{2})', glyphs))
    assert len(font) >= 128 * 5
    sources = ('IeParser', 'WpsParser', 'BroadcomDetector', 'AccessPointStore',
               'Serialization', 'WifiScanner', 'Export', 'DisplayUi', 'WpsProbe')
    with tempfile.TemporaryDirectory(prefix='broadcom-ui-previews-') as temporary:
        executable = Path(temporary) / 'capture-ui'
        subprocess.run([os.environ.get('CXX', 'clang++'), '-std=c++17', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-DRADAR_COUNTRY="PL"', '-DRADAR_ADV=1', '-Iinclude', '-Itest/stubs', '-Itest',
                        'scripts/render_readme_screenshots.cpp', *[f'src/{source}.cpp' for source in sources],
                        '-o', str(executable)], cwd=ROOT, check=True)
        captured = json.loads(subprocess.check_output([str(executable)], text=True))
    output = ROOT / 'docs/images'
    output.mkdir(parents=True, exist_ok=True)
    for screen in captured['screens']:
        assert len(screen['rows']) == 9
        pixels = bytearray(240 * 135 * 3)
        for row, content in enumerate(screen['rows']):
            text = content['text']
            assert len(text) <= 26 and all(32 <= ord(character) < 127 for character in text)
            background = bytes(COLORS[content['background']])
            foreground = bytes(COLORS[content['foreground']])
            start = row * 15 * 240 * 3
            pixels[start:start + 15 * 240 * 3] = background * (15 * 240)
            for position, character in enumerate(text):
                for column in range(5):
                    bitmap = font[ord(character) * 5 + column]
                    for bit in range(8):
                        if not bitmap & (1 << bit):
                            continue
                        for y in range(row * 15 + 1 + bit * 3 // 2, row * 15 + 1 + (bit + 1) * 3 // 2):
                            for x in range(position * 9 + column * 3 // 2, position * 9 + (column + 1) * 3 // 2):
                                index = (y * 240 + x) * 3
                                pixels[index:index + 3] = foreground
        enlarged = bytearray()
        for y in range(135):
            scanline = b''.join(bytes(pixels[(y * 240 + x) * 3:(y * 240 + x + 1) * 3]) * 3 for x in range(240))
            enlarged.extend(scanline * 3)
        png(output / screen['file'], enlarged, 720, 405)
        print('Rendered:', screen['file'])
    captured['provenance'] = {'synthetic_networks': True, 'hardware_capture': False,
                              'native_size': [240, 135], 'image_scale': 3, 'font_scale': 1.5,
                              'm5gfx_version': pinned, 'font_sha256': hashlib.sha256(FONT_SOURCE.read_bytes()).hexdigest()}
    (output / 'preview-data.json').write_text(json.dumps(captured, indent=2) + '\n')


if __name__ == '__main__':
    main()
