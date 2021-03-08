.PHONY: aur aur-push aur-make build build-release test run hoogle-build hoogle-generate hoogle-serve cachix-enable cachix-push

build:
	stack --nix build

build-release:
	nix-build
	cp result/bin/haskell-keycloak-exe keycloak
	chmod 755 keycloak
	patchelf --set-interpreter /lib/ld-linux-x86-64.so.2 keycloak
	patchelf --set-rpath /lib keycloak

test:
	stack --nix test

run:
	stack --nix run

hoogle-build:
	stack --nix build --haddock --haddock-deps

hoogle-generate:
	stack --nix hoogle -- generate --quiet --local

hoogle-serve:
	stack --nix hoogle -- server --local --port=65000 --no-security-headers

cachix-enable:
	cachix use ibizaman

cachix-push:
	nix-build | cachix push ibizaman
	nix-build shell.nix | cachix push ibizaman

hackage-prepare:
	nix-shell --run "cabal check" || exit 1
	stack sdist --tar-dir . --tar-dir .


aur:
	cd aur && ./update-aur.sh

aur-push:
	git submodule foreach 'git push'

aur-make:
	cd aur && rm keycloak.zip && makepkg -f
