let
  hsPkgs = import ./default.nix {};
in
  hsPkgs.shellFor {
      packages = ps: [ps.haskell-keycloak];
      withHoogle = true;
  }
