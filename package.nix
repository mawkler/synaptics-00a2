# SPDX-License-Identifier: LGPL-2.1-or-later
# The libfprint-TOD driver module, for services.fprintd.tod.driver. Builds
# against the libfprint-tod that fprintd-tod uses (callPackage passes it).
{
  lib,
  rustPlatform,
  pkg-config,
  libfprint-tod,
  glib,
  gusb,
  libusb1,
}:

rustPlatform.buildRustPackage {
  pname = "libfprint-2-tod1-syna-00a2";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./tod
      # The unit tests include their vectors from here
      ./tests
      ./LICENSE
      ./LICENSES
    ];
  };

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    libfprint-tod
    glib
    gusb
    libusb1
  ];

  # Only the module; the research CLI isn't needed
  cargoBuildFlags = [
    "-p"
    "syna-00a2-tod"
  ];
  # The module itself can't link a test binary (test = false); the library's
  # tests run offline
  cargoTestFlags = [
    "-p"
    "syna-00a2"
  ];

  # cargoInstallHook puts cdylibs in $out/lib; the TOD loader looks in
  # driverPath
  postInstall = ''
    mkdir -p $out/lib/libfprint-2/tod-1
    mv $out/lib/libsyna_00a2_tod.so $out/lib/libfprint-2/tod-1/
  '';

  passthru.driverPath = "/lib/libfprint-2/tod-1";

  meta = {
    description = "libfprint-TOD driver for the Synaptics 06cb:00a2 fingerprint reader";
    license = lib.licenses.lgpl21Plus;
    platforms = lib.platforms.linux;
  };
}
