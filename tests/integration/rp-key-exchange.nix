{
  lib,
  pkgs,
  config,
  ...
}:

let
  cfg = config.services.rosenpassKeyExchange;
in
{
  options.services.rosenpassKeyExchange = {
    create = lib.mkEnableOption "rosenpass key-exchange";
    enable = lib.mkOption {
      type = lib.types.bool;
      description = "Should the service be enabled";
      default = true;
    };
    config = lib.mkOption {
      type = lib.types.path;
      description = "Path to rosenpass configuration";
    };
    rosenpassVersion = lib.mkOption {
      type = lib.types.package;
      description = "Rosenpass package to use";
    };
  };

  config = lib.mkIf cfg.create {
    systemd.services.rp-exchange = {
      description = "Rosenpass Key Exchanger";
      wantedBy = [ ] ++ lib.optional cfg.enable "multi-user.target"; # If we set enable to this, then the service will be masked and cannot be enabled. Doing it this way allows us to enable it.
      requires = [ "network-online.target" ];
      script = ''
        ${cfg.rosenpassVersion}/bin/rosenpass exchange-config ${cfg.config}
      '';
      serviceConfig = {
        Restart = "always";
        RestartSec = 1;
      };
    };
  };
}
