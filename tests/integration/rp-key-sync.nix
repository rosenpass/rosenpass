{ pkgs, lib, config, ... }:

let
  cfg = config.services.rosenpassKeySync;
  servicePrefix = "rp-key-sync-";
  timerPrefix = "rp-key-sync-timer-";
  rpKeySyncOpts = { name, ... }: {
    options = {
      enable = lib.mkEnableOption "RP Keysync for ${name}";

      wgInterface = lib.mkOption {
        type = lib.types.str;
        description = "Wireguard interface name";
      };

      rpHost = lib.mkOption {
        type = lib.types.str;
        description = "network address of the host that runs rosenpass";
      };
      peerPubkey = lib.mkOption {
        type = lib.types.str;
        description = "Public key of wireguard peer";
      };
      remoteKeyPath = lib.mkOption {
        type = lib.types.path;
        description = "Location of the .osk file on the key exchange server";
      };
    };
  };
in
{
  options.services.rosenpassKeySync = {
    instances = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule rpKeySyncOpts);
      default = {};
      description = "RP key sync instances";
    };
  };

  config = {
    systemd.services = lib.mapAttrs' (instanceName: instanceCfg: {
      name = "${servicePrefix}${instanceName}";
      value = {
        description = "Rosenpass Key Downloader ${instanceName}";
        wantedBy = [ "multi-user.target" ];
        requires = [ "network-online.target" ];
        script = ''
          set -euo pipefail
          ${pkgs.openssh}/bin/ssh ${instanceCfg.rpHost} "cat ${instanceCfg.remoteKeyPath}" \
            | ${pkgs.wireguard-tools}/bin/wg \
              set ${instanceCfg.wgInterface} \
              peer ${instanceCfg.peerPubkey} \
              preshared-key /dev/stdin
        '';
        serviceConfig = {
          Restart = "always";
          RestartSec = 10;
        };
      };
    }) (lib.filterAttrs (_: cfg: cfg.enable) cfg.instances);

    systemd.timers = lib.mapAttrs' (instanceName: instanceCfg: {
      name = "${timerPrefix}${instanceName}";
      value = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          requires = [ "network-online.target" ];
          OnUnitActiveSec = "1m";
          Unit = "${servicePrefix}${instanceName}.service";
        };
      };
    }) (lib.filterAttrs (_: cfg: cfg.enable) cfg.instances);
  };
}
