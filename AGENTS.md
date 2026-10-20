# Repository instructions

Broadcom Radar is ESP32-S3 firmware for M5Stack Cardputer ADV and original Cardputer. Read `README.md`, `RESEARCH.md` and the affected source before making changes. Keep changes small and preserve behavior outside the requested scope.

## Intended use and result boundaries

- Support security inventory and testing of networks the operator owns or has explicit permission to assess, including planning vendor firmware updates.
- Radar collects evidence. It does not install router updates or verify that a vulnerability has been fixed.
- A changed or missing label after a vendor update is a new observation, not proof that a vulnerability was fixed. Check vendor advisories and the installed firmware version separately.
- `BRCM`, `BRCM+WPS`, `WPS`, `NONE` and `WAIT` describe observations. No label establishes vulnerability, patch status or safety. `HOSTAPD_LIKE` and `BRCM_WPS_LIKE` are uncalibrated behavior candidates, not confirmed process identities.
- Keep application API checks, simulated tests, device observations and independent radio measurements distinct. Never turn an API audit into a claim of complete RF silence.

## Firmware boundaries

- Default `cardputer_adv` and `cardputer` builds remain passive. Preserve the explicit API allowlist in `scripts/check_passive.py`; do not add active scanning, connections or transmission to the default path.
- Experimental `*_probe`, `*_transport` and `*_fingerprint` builds are separate opt-ins. Preserve `RADAR_WPS_PROBE`, `RADAR_DRIVER_COMPAT` and `RADAR_TRANSPORT_ONLY` gates. A test requires a selected target and explicit keyboard confirmation; detection and filters must never start it automatically.
- Preserve bounded sessions, target validation, own-station cleanup, cancellation and scanner restoration. Do not broaden protocol behavior or driver compatibility without an explicit request and matching validation.
- Keep Wi-Fi callbacks limited to bounded copying and primitive metadata. Parse, draw and write SD files in the main loop. Preserve checked IE/TLV lengths, bounded queues and explicit overflow counters.
- Keep evidence and raw SSID bytes intact. UI filters and shortened labels must not change stored records, classification or exports.

## Display and export

- Preserve changed-row rendering and wait for DMA before reusing the row canvas. Keyboard-hint footers belong only on the main network list.
- Screen blanking must preserve reception, hopping and saves. The first wake key is consumed through release. Do not claim measured power savings without measurement.
- Automatic detection archives, manual scan exports and experimental reports have different scopes. Keep partial-write handling, existing-file preservation and report identity intact.
- Use synthetic network identifiers in new examples and previews. Label rendered previews clearly; do not present them as device photos or hardware validation. Keep collected exports and credentials out of Git.

## Validation

Run the most specific useful checks for the changed behavior. Report what actually ran and what remains unverified.

- Core firmware, UI or export changes: `bash scripts/test_host.sh` (ASan/UBSan, passive API audit and independent export decoding).
- Build affected hardware and modes with PlatformIO Core 6.1.19 and the dependencies pinned in `platformio.ini`. ADV and original Cardputer use different keyboard readers. CI builds all eight environments.
- UI preview changes: run `python3 scripts/render_readme_screenshots.py`; inspect the generated PNGs, provenance and synthetic-data caption. The renderer requires the pinned M5GFX dependency from an ADV build; generating previews is not firmware validation.
- Documentation-only changes: check links, section anchors, Markdown rendering and `git diff --check`. Use a local preview or the GitHub Markdown API without publishing. Local firmware rebuilds are unnecessary when firmware and build inputs are unchanged.
- Do not treat host tests, SD delivery readback or successful installation as proof of device startup, RF behavior, battery accuracy, recovery or long-duration stability.

## Launcher delivery

- Package application-only images and exact size/SHA-256 manifests. Do not distribute a bootloader, partition table, merged flash image or erase-flash procedure as a Radar update. Keep the direct-upload guard enabled.
- Check the actual target partition against the image and its aligned-size requirement. Preserve resident Launcher, other applications and data; flash capacity alone does not establish a fitting slot.
- Reuse explicit authorization already given for the current task, within its stated scope. A file-upload request covers SD delivery by default. Installation, booting, rebooting and repartitioning require explicit authorization for those actions. Verify SD delivery by listing and byte-for-byte readback.

## Git and public documentation

- Inspect status, target branch, upstream history and the exact diff before Git mutations. Follow the maintainer's explicit branch, commit and publication instructions. Never force-push, rewrite published history, alter timestamps or move existing tags without an explicit request.
- Keep each completed, validated change in a separate commit when committing is authorized. For feedback on a delivered version, tag that exact delivered commit and distinguish documentation feedback from device runtime evidence.
- Bump the Radar patch-level version (`x.y.Z`) for firmware behavior changes and rebuild matching artifacts. Documentation and preview-only edits do not require a firmware version bump. When publication is authorized, attach binaries as Release assets rather than source-history files.
- Keep public text and code in English. Keep the README friendly: recommended downloads, first steps and result meanings first; technical details below. Preserve the authorized-use notice, source attribution, dependency licenses and validation limits. Do not add machine-specific paths or private configuration.
