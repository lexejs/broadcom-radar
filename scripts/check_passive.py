#!/usr/bin/env python3
"""Fail if production code adds an unreviewed Wi-Fi API or active network layer."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWED = {
    "esp_wifi_init", "esp_wifi_set_storage", "esp_wifi_set_mode", "esp_wifi_set_config",
    "esp_wifi_set_country_code", "esp_wifi_get_country", "esp_wifi_start", "esp_wifi_set_ps",
    "esp_wifi_set_promiscuous_filter", "esp_wifi_set_promiscuous_rx_cb",
    "esp_wifi_set_channel", "esp_wifi_set_promiscuous",
}
used = set()
for path in sorted(list((ROOT / "src").glob("*.cpp")) + list((ROOT / "include").glob("*.h"))):
    content = path.read_text()
    used |= set(re.findall(r"\b(esp_wifi_\w+)\s*\(", content))
    if re.search(r"#\s*include\s*[<\"](?:WiFi|HTTPClient|WebServer|AsyncTCP|esp_supplicant|esp_wps|lwip/)", content):
        raise SystemExit(f"Network layer forbidden in {path.name}")
    if re.search(r"\b(?:sendto|sendmsg|socket|esp_netif_create_default_wifi_sta|esp_wifi_internal_tx|esp_wifi_80211_tx)\s*\(", content):
        raise SystemExit(f"Active networking forbidden in {path.name}")
if used != ALLOWED:
    raise SystemExit(f"Wi-Fi API changes require review: added={used - ALLOWED}, missing={ALLOWED - used}")
print(f"PASS: production Wi-Fi API allowlist ({len(used)} APIs); no active network layer")
