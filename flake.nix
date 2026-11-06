{
  description = "risala: a line-based chat protocol, its server, and librisala";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      perSystem =
        { pkgs, lib, ... }:
        {
          formatter = pkgs.nixfmt-tree;

          devShells.default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                # Rust
                cargo
                rustc
                clippy
                rustfmt
                rust-analyzer
                cargo-nextest

                # Native deps and tools
                pkg-config
                sqlite
                openssl # for `openssl s_client`, the protocol's reference "client"
                curl
              ]
              ++ lib.optionals stdenv.isLinux [
                # GNOME client (gtk4-rs + libadwaita)
                gtk4
                libadwaita
                glib
                blueprint-compiler
              ];

            env.RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          };
        };
    };
}
