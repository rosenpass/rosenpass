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
    enable = lib.mkEnableOption "rosenpass key-exchange";
    config = lib.mkOption {
      type = lib.types.path;
      description = "Path to rosenpass configuration";
    };
    rosenpassVersion = lib.mkOption {
      type = lib.types.package;
      description = "Rosenpass package to use";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.rp-exchange = {
      description = "Rosenpass Key Exchanger";
      wantedBy = [ "multi-user.target" ];
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
