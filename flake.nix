{
  description = "libfprint-TOD driver for the Synaptics 06cb:00a2 fingerprint reader";

  # A consumer sets `inputs.nixpkgs.follows`, so the module builds against the
  # libfprint-tod its fprintd-tod uses
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    {
      packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.callPackage ./package.nix { };

      # fprintd with this driver, built with the system's own pkgs
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.syna-00a2;
        in
        {
          options.services.syna-00a2 = {
            enable = lib.mkEnableOption "fprintd with the syna-00a2 driver for the Synaptics 06cb:00a2 reader";
            refresh = lib.mkEnableOption ''
              template refresh: a match right after a miss stores the matching
              touch as a new template. A false accept right after a miss then
              keeps matching that other finger until newer refreshes replace it
            '';
          };
          config = lib.mkIf cfg.enable {
            services.fprintd = {
              enable = true;
              tod = {
                enable = true;
                driver = pkgs.callPackage ./package.nix { };
              };
            };
            systemd.services.fprintd.environment = lib.mkIf cfg.refresh { SYNA_00A2_REFRESH = "1"; };
          };
        };
    };
}
