# syna-00a2

Experimental Linux driver for the Synaptics 06cb:00a2 fingerprint reader (tested on a ThinkPad L380 Yoga), as a libfprint-TOD module for `fprintd-tod`.

- Fingerprint templates live on the sensor, which does the matching. The host keeps only (uid, finger), with no images.
- It reuses the sensor's existing pairing. The keys derive from the laptop's DMI product name and serial.
- After a miss followed by a match, the driver stores the matching touch as a fresh template (up to 8 per finger), so it keeps up with day-to-day changes.

## Install (NixOS flake)

```nix
# inputs (flake.nix)
syna-00a2.url = "github:mawkler/agent-skills/syna-00a2";
syna-00a2.inputs.nixpkgs.follows = "nixpkgs";

# configuration
services.fprintd.tod = {
  enable = true;
  driver = inputs.syna-00a2.packages.${pkgs.stdenv.hostPlatform.system}.default;
};
```

Then enroll with `fprintd-enroll -f right-index-finger`. Logs: `journalctl -u fprintd | rg syna_00a2`.

## Layout

- `src/`: protocol library and a CLI for experiments
- `tod/`: the libfprint-TOD module (Rust C ABI with a small C GObject shim)
- `tools/tod_test.py`: test harness that runs without fprintd
- `docs/on-chip-driver.md`: design, findings and known risks

Build and test with `nix build` or `cargo test --workspace`.

## AI disclosure

This driver was developed by an LLM (Claude Opus 5.5 in Claude Code), with
[REA-FS](https://github.com/pierspad/REA-FS), and tested on the hardware by a
human.
