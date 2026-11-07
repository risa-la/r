{
  perSystem =
    { pkgs, lib, ... }:
    let
      inherit (builtins) toJSON;
      inherit (pkgs.stdenv.hostPlatform) isDarwin isAarch64;
      sweetpad = import ./sweetpad.nix { inherit pkgs lib; };
      toolchain = import ./toolchain.nix;
      source = lib.fileset.toSource {
        root = ../.;
        fileset = lib.fileset.unions [
          ../Sources
          ../Resources
          ../Tests
          ../Risala.xcodeproj/project.pbxproj
          ../Risala.xcodeproj/xcshareddata/xcschemes/Risala.xcscheme
          ../sweetpad.toml
        ];
      };
      buildApp =
        platform:
        pkgs.stdenvNoCC.mkDerivation {
          pname = "risala-${platform}";
          version = "0.1.0-xcode-${toolchain.version}-${toolchain.build}";
          src = source;
          # Apple SDKs and tools are supplied by the host, not the Nix store.
          __noChroot = true;
          nativeBuildInputs = [ sweetpad ];
          dontConfigure = true;
          dontFixup = true;
          DEVELOPER_DIR = toolchain.developerDir;
          buildPhase = ''
            runHook preBuild
            unset SDKROOT MACOSX_DEPLOYMENT_TARGET
            export PATH="$PATH:/usr/bin:/bin:/usr/sbin:/sbin"
            test "$(/usr/bin/xcodebuild -version)" = "$(printf 'Xcode ${toolchain.version}\nBuild version ${toolchain.build}')"
            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"
            sweetpad build --non-interactive --configuration Release \
              --destination '${
                if platform == "macos" then "generic/platform=macOS" else "generic/platform=iOS Simulator"
              }' \
              -- -derivedDataPath "$TMPDIR/build" CODE_SIGNING_ALLOWED=NO \
              ARCHS=${if isAarch64 then "arm64" else "x86_64"} \
              'OTHER_SWIFT_FLAGS=$(inherited) -disable-sandbox' > "$TMPDIR/build.log" 2>&1 \
              || { cat "$TMPDIR/build.log"; exit 1; }
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/Applications $out/nix-support
            cp -R "$TMPDIR/build/Build/Products/Release${
              lib.optionalString (platform == "ios") "-iphonesimulator"
            }/Risala.app" $out/Applications/
            resources="$out/Applications/Risala.app/${
              lib.optionalString (platform == "macos") "Contents/Resources/"
            }"
            test -f "$resources/Assets.car"
            test -f "$resources/en.lproj/Localizable.strings"
            test -f "$resources/ar.lproj/Localizable.strings"
            cp "$TMPDIR/build.log" $out/nix-support/build.log
            cp ${pkgs.writeText "toolchain.json" (toJSON toolchain)} $out/nix-support/toolchain.json
            runHook postInstall
          '';
        };
    in
    {
      packages = lib.optionalAttrs isDarwin {
        apple-dev = sweetpad;
        apple-macos = buildApp "macos";
        apple-ios = buildApp "ios";
      };
      apps = lib.optionalAttrs isDarwin {
        apple = {
          type = "app";
          program = lib.getExe sweetpad;
        };
      };
    };
}
