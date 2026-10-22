{
  description = "libfprint-TOD driver for the Synaptics 06cb:00a2 fingerprint reader";

  # A consumer sets `inputs.nixpkgs.follows`, so the module builds against the
  # libfprint-tod its fprintd-tod uses
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    {
      packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.callPackage ./package.nix { };
    };
}
