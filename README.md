# Although not exactly equivalent to my initial goal, you should probably use https://github.com/adorsys/keycloak-config-cli instead.

# Haskell Keycloack

This project is a command-line interface to configure a Keycloak
instance.


# Installation

## From Source

Both options will produce an executable where the linker is in
/nix/store. Use the `build-release` Makefile target to produce an
executable linked to the default linux linker.

### Using Nix

```bash
$ nix-build

# Executable is in ./result/bin/haskell-keycloak-exe
```

### Using stack

```bash
stack build
```

Or

```bash
stack --nix build
```
