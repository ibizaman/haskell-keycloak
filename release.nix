{ compiler ? "ghc865"
, pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/f0d8828b86c8105f722e9b1cceec50bcba1c9df6.tar.gz") {}
}:

let
  inherit (pkgs.haskell.lib) dontCheck;

  haskellPackages = pkgs.haskell.packages.${compiler}.override {
    overrides = self: super: rec {
      haskell-keycloak = self.callCabal2nix "haskell-keycloak" ./. { };
      Cabal = dontCheck (self.callHackage "Cabal" "3.2.1.0" {});
      generic-data = dontCheck (self.callHackage "generic-data" "0.7.0.0" {});
    };
  };

  shellHaskellPackages = pkgs.haskell.packages.${compiler}.override {
    overrides = self: super: rec {
      Cabal = dontCheck (self.callHackage "Cabal" "3.2.1.0" {});
      # hpack = dontCheck (self.callHackage "hpack" "0.34.4" {});
    };
  };

  project = haskellPackages.haskell-keycloak;
in
{
  inherit project;

  shell = haskellPackages.shellFor {
    packages = p: with p; [
      project
    ];
    buildInputs = with shellHaskellPackages; [
      Cabal
      stack
      haskell-language-server
    ];
    withHoogle = true;
  };
}
