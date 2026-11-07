{ pkgs, lib }:
pkgs.stdenvNoCC.mkDerivation rec {
  pname = "sweetpad";
  version = "0.1.17";
  src = pkgs.fetchurl {
    url = "https://github.com/sweetpad-dev/sweetpad/releases/download/cli-v${version}/sweetpad-cli-${version}-macos-universal.tar.gz";
    hash = "sha256-Abm5nLY5aGg2TJ4XXT9YWRN8Vtz3XkyKd6eC6UMi/XQ=";
  };
  sourceRoot = ".";
  dontBuild = true;
  dontFixup = true;
  installPhase = ''
    runHook preInstall
    install -Dm755 sweetpad $out/bin/sweetpad
    install -Dm755 sweetpad-dap $out/bin/sweetpad-dap
    runHook postInstall
  '';
  meta = {
    description = "Headless Apple development CLI";
    homepage = "https://sweetpad.hyzyla.dev";
    license = lib.licenses.mit;
    platforms = lib.platforms.darwin;
    mainProgram = "sweetpad";
  };
}
