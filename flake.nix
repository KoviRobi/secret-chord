{
  description = "A simple forth interpreter for playing around with";

  inputs.nixpkgs.url = "nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let

      # to work with older version of flakes
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      # Generate a user-friendly version number.
      version = builtins.substring 0 8 lastModifiedDate;

      # System types to support.
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; overlays = [ self.overlay ]; });

    in

    {

      # A Nixpkgs overlay.
      overlay = final: prev: {

        fth = with final; stdenv_32bit.mkDerivation rec {
          pname = "fth";
          inherit version;

          src = ./.;

          buildInputs = [
            pkgsi686Linux.readline
          ];
          nativeBuildInputs = [
            pkg-config
            noweb
          ];
        };

      };

      # Provide some binary packages for selected system types.
      packages = forAllSystems (system:
        {
          inherit (nixpkgsFor.${system}) fth;
        });

      devShells = forAllSystems
        (system: {
          default = nixpkgsFor.${system}.fth.overrideAttrs (old: {
            buildInputs = [
              nixpkgsFor.${system}.clang-tools
            ] ++ old.buildInputs;
          });
        });

      # The default package for 'nix build'. This makes sense if the
      # flake provides only one package or there is a clear "main"
      # package.
      defaultPackage = forAllSystems (system: self.packages.${system}.fth);
    };
}
