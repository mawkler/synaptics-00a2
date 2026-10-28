# syna-00a2

Experimental Linux driver for the Synaptics 06cb:00a2 fingerprint reader
(tested on a ThinkPad L380 Yoga), as a libfprint-TOD module for `fprintd-tod`.

- Fingerprint templates live on the sensor, which does the matching. The host
  keeps only (uid, finger), with no images.
- It reuses the sensor's existing pairing. The keys derive from the laptop's
  DMI product name and serial.
- After a miss followed by a match, the driver stores the matching touch as a
  fresh template (up to 3 per finger), so it keeps up with day-to-day changes.

## Install (NixOS flake)

```nix
# inputs
syna-00a2.url = "git+file:///path/to/syna-00a2?ref=main";
syna-00a2.inputs.nixpkgs.follows = "nixpkgs";

# configuration
services.fprintd.tod = {
  enable = true;
  driver = inputs.syna-00a2.packages.${pkgs.stdenv.hostPlatform.system}.default;
};
```

Then enroll with `fprintd-enroll -f right-index-finger`. Logs:
`journalctl -u fprintd | rg syna_00a2`.

## Layout

- `src/`: protocol library and a CLI for experiments
- `tod/`: the libfprint-TOD module (Rust C ABI with a small C GObject shim)
- `tools/tod_test.py`: test harness that runs without fprintd
- `docs/on-chip-driver.md`: design, findings and known risks

Build and test with `nix build` or `cargo test --workspace`.

License: LGPL-2.1-or-later (see `LICENSE`, `LICENSES/`).
