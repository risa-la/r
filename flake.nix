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
        {
          config,
          pkgs,
          lib,
          ...
        }:
        let
          inherit (pkgs) rustPlatform;

          version = (lib.importTOML ./Cargo.toml).workspace.package.version;

          # Only what cargo needs, so editing docs does not force a rebuild.
          # The proto tests read SPEC.md and README.md from the repo root.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates
              ./SPEC.md
              ./README.md
            ];
          };

          # Vendored crates, shared by the package and every cargo check.
          cargoDeps = rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };

          # A derivation that runs a cargo command over the workspace and
          # produces an empty output.
          cargoCheck =
            name: args:
            rustPlatform.buildRustPackage (
              {
                pname = "risala-${name}";
                inherit version src cargoDeps;
                auditable = false;
                doCheck = false;
                installPhase = "touch $out";
              }
              // args
            );
        in
        {
          formatter = pkgs.nixfmt-tree;

          packages = {
            risalad = rustPlatform.buildRustPackage {
              pname = "risalad";
              inherit version src cargoDeps;
              cargoBuildFlags = [
                "-p"
                "risala-server"
              ];
              # The workspace tests run in checks.tests.
              cargoTestFlags = [
                "-p"
                "risala-server"
              ];
              meta = {
                description = "The risala chat server";
                license = lib.licenses.asl20;
                mainProgram = "risalad";
              };
            };
            default = config.packages.risalad;
          };

          checks = {
            inherit (config.packages) risalad;

            fmt = cargoCheck "fmt" {
              nativeBuildInputs = [ pkgs.rustfmt ];
              buildPhase = ''
                runHook preBuild
                cargo fmt --all --check
                runHook postBuild
              '';
            };

            clippy = cargoCheck "clippy" {
              nativeBuildInputs = [ pkgs.clippy ];
              buildPhase = ''
                runHook preBuild
                cargo clippy --workspace --all-targets --offline -- -D warnings
                runHook postBuild
              '';
            };

            tests = cargoCheck "tests" {
              # Some tests use `openssl` when it is on PATH.
              nativeCheckInputs = [ pkgs.openssl ];
              doCheck = true;
              buildPhase = ''
                runHook preBuild
                cargo test --workspace --offline --no-run
                runHook postBuild
              '';
              checkPhase = ''
                runHook preCheck
                cargo test --workspace --offline
                runHook postCheck
              '';
            };

            # REUSE compliance of every tracked file, not just the cargo ones.
            reuse = pkgs.runCommand "risala-reuse" { nativeBuildInputs = [ pkgs.reuse ]; } ''
              cd ${./.}
              reuse lint
              touch $out
            '';

            nixfmt =
              pkgs.runCommand "risala-nixfmt"
                {
                  nativeBuildInputs = [ pkgs.nixfmt-tree ];
                }
                ''
                  cp -r --no-preserve=mode ${./.} tree
                  cd tree
                  treefmt --ci --tree-root .
                  touch $out
                '';
          };

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
                cargo-fuzz

                # Native deps and tools
                pkg-config
                sqlite
                openssl # for `openssl s_client`, the protocol's reference "client"
                curl
                reuse
              ]
              ++ lib.optionals stdenv.hostPlatform.isLinux [
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
