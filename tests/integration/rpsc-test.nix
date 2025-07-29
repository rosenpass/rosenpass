{ pkgs, lib, multiPeer ? false, ... }:
let
  wgInterface = "mywg";
  wgPort = 51820;
  rpPort = 51821;

  demoRosenpassKeys = ./rosenpass-keys;
  rosenpassKeyFolder = "/var/secrets";
  keyExchangePathAB = "/root/peer-ab.osk";
  keyExchangePathBA = "/root/peer-ba.osk";
  keyExchangePathAC = "/root/peer-ac.osk";
  keyExchangePathCA = "/root/peer-ca.osk";
  keyExchangePathBC = "/root/peer-bc.osk";
  keyExchangePathCB = "/root/peer-cb.osk";

  staticConfig = {
    peerA = {
      innerIp = "10.100.0.1";
      privateKey = "cB+EYXqf63F+8Kqn3Q1dr9ds5tQi4PkQU+WfLpZf2nU=";
      publicKey = "+gsv8wlhKGKXUOYTw5r2tPpSr7CEeVBgH/kxZzeo9E8=";
      rosenpassConfig = builtins.toFile "peer-a.toml" (''
        public_key = "${rosenpassKeyFolder}/self.pk"
        secret_key = "${rosenpassKeyFolder}/self.sk"
        listen = ["[::]:${builtins.toString rpPort}"]
        verbosity = "Verbose"

        [[peers]]
        public_key = "${rosenpassKeyFolder}/peer-b.pk"
        endpoint = "peerbkeyexchanger:${builtins.toString rpPort}"
        key_out = "${keyExchangePathAB}"
      '' + (lib.optionalString multiPeer ''
        [[peers]]
        public_key = "${rosenpassKeyFolder}/peer-c.pk"
        endpoint = "peerckeyexchanger:${builtins.toString rpPort}"
        key_out = "${keyExchangePathAC}"
      ''));
    };
    peerB = {
      innerIp = "10.100.0.2";
      privateKey = "sL+9z4HAzkV01QYTQX5TA645PV8Vprk09vNNWSKjjW4=";
      publicKey = "ZErZhjoSTiLCfPXl3TcnWyfvUtjP1mIQUH+2sRxI/wE=";
      rosenpassConfig = builtins.toFile "peer-b.toml" (''
        public_key = "${rosenpassKeyFolder}/self.pk"
        secret_key = "${rosenpassKeyFolder}/self.sk"
        listen = ["[::]:${builtins.toString rpPort}"]
        verbosity = "Verbose"

        [[peers]]
        public_key = "${rosenpassKeyFolder}/peer-a.pk"
        endpoint = "peerakeyexchanger:${builtins.toString rpPort}"
        key_out = "${keyExchangePathBA}"
      '' + (lib.optionalString multiPeer ''
        [[peers]]
        public_key = "${rosenpassKeyFolder}/peer-c.pk"
        endpoint = "peerckeyexchanger:${builtins.toString rpPort}"
        key_out = "${keyExchangePathBC}"
      ''));
    };
  } // lib.optionalAttrs multiPeer {
    peerC = {
      innerIp = "10.100.0.3";
      privateKey = "gOrlrKattR+hdpGc/0X2qFXWSbw0hW7AMLzb68cWBmI=";
      publicKey = "23S38TaISe+GlrNJL5DyoN+EC6g2fSYbT1Kt1LUxhRA=";
      rosenpassConfig = builtins.toFile "peer-c.toml" ''
        public_key = "${rosenpassKeyFolder}/self.pk"
        secret_key = "${rosenpassKeyFolder}/self.sk"
        listen = ["[::]:${builtins.toString rpPort}"]
        verbosity = "Verbose"

        [[peers]]
        public_key = "${rosenpassKeyFolder}/peer-a.pk"
        endpoint = "peerakeyexchanger:${builtins.toString rpPort}"
        key_out = "${keyExchangePathCA}"
        [[peers]]
        public_key = "${rosenpassKeyFolder}/peer-b.pk"
        endpoint = "peerckeyexchanger:${builtins.toString rpPort}"
        key_out = "${keyExchangePathCB}"
      '';
    };
  };

  inherit (import (pkgs.path + "/nixos/tests/ssh-keys.nix") pkgs)
    snakeOilPublicKey
    snakeOilPrivateKey;

  # All hosts in this scenario use the same key pair
  # The script takes the host as parameter and prepares passwordless login
  prepareSshLogin = pkgs.writeShellScriptBin "prepare-ssh-login" ''
    set -euo pipefail
    mkdir -p /root/.ssh
    cp ${snakeOilPrivateKey} /root/.ssh/id_ecdsa
    chmod 0400 /root/.ssh/id_ecdsa
    ${pkgs.openssh}/bin/ssh -o StrictHostKeyChecking=no "$1" true
  '';

  tcgModule = {pkgs, ...}: lib.mkIf (pkgs.stdenv.hostPlatform.system == "aarch64-linux") {
    virtualisation.qemu.options = [
      "-machine" "accel=tcg,thread=multi"
      "-cpu" "max"
    ];
  };
in
{
  name = "rosenpass with key exchangers";
  defaults = {
    imports = [
      ./rp-key-exchange.nix
      ./rp-key-sync.nix
      tcgModule
    ];

    systemd.tmpfiles.rules = [
      "d ${rosenpassKeyFolder} 0400 root root - -"
    ];
  };

  nodes = {
    # Server and client create the actual wireguard tunnel
    peerA = {
      networking.wireguard.interfaces.${wgInterface} = {
        listenPort = wgPort;
        ips = [ "${staticConfig.peerA.innerIp}/24" ];
        inherit (staticConfig.peerA) privateKey;
        peers = [
          {
            inherit (staticConfig.peerB) publicKey;
            allowedIPs = [ "${staticConfig.peerB.innerIp}/32" ];
            presharedKey = "AR/yvSvMAzW6eS27PsRHUMWwC8cLhaD96t42cysxrb0=";
          } # TODO document that we use mismatching presahred keys on purpose
        ] ++ ( lib.optional multiPeer
          {
            inherit (staticConfig.peerC) publicKey;
            allowedIPs = [ "${staticConfig.peerC.innerIp}/32" ];
            presharedKey = "LfWvJCN8h7NhS+JWRG7GMIY20JxUV4WUs7MJ45ZGoCE=";
          } # TODO document that we use mismatching presahred keys on purpose
        );
      };
      networking.firewall.allowedUDPPorts = [ wgPort ];

      services.rosenpassKeySync.instances = {
        AB = {
          enable = true;
          inherit wgInterface;
          rpHost = "peerakeyexchanger";
          peerPubkey = staticConfig.peerB.publicKey;
          remoteKeyPath = keyExchangePathAB;
        };
      } // lib.optionalAttrs multiPeer {
        AC = {
          enable = true;
          inherit wgInterface;
          rpHost = "peerakeyexchanger";
          peerPubkey = staticConfig.peerC.publicKey;
          remoteKeyPath = keyExchangePathAC;
        };
      };
    };
    peerB = {
      networking.wireguard.interfaces.${wgInterface} = {
        listenPort = wgPort;
        ips = [ "${staticConfig.peerB.innerIp}/24" ];
        inherit (staticConfig.peerB) privateKey;
        peers = [
          {
            inherit (staticConfig.peerA) publicKey;
            allowedIPs = [ "${staticConfig.peerA.innerIp}/32" ];
            endpoint = "peerA:${builtins.toString wgPort}";
            presharedKey = "o25fjoIOI623cnRyhvD4YEGtuSY4BFRZmY3UHvZ0BCA=";
            # TODO document that we use mismatching presahred keys on purpose
          }
        ] ++ ( lib.optional multiPeer
          {
            inherit (staticConfig.peerC) publicKey;
            allowedIPs = [ "${staticConfig.peerC.innerIp}/32" ];
            presharedKey = "GsYTUd/4Ph7wMy5r+W1no9yGe0UeZlmCPeiyu4tb6yM=";
            # TODO document that we use mismatching presahred keys on purpose
          }
        );
      };
      networking.firewall.allowedUDPPorts = [ wgPort ];

      services.rosenpassKeySync.instances = {
        BA = {
          enable = true;
          inherit wgInterface;
          rpHost = "peerbkeyexchanger";
          peerPubkey = staticConfig.peerA.publicKey;
          remoteKeyPath = keyExchangePathBA;
        };
      } // lib.optionalAttrs multiPeer {
        BC = {
          enable = true;
          inherit wgInterface;
          rpHost = "peerbkeyexchanger";
          peerPubkey = staticConfig.peerC.publicKey;
          remoteKeyPath = keyExchangePathBC;
        };
      };
    };

    # These two are associated with server and client in a way that
    # server and client log into each of them to get their tunnel keys
    # managed
    peerakeyexchanger = {
      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [ snakeOilPublicKey ];
      networking.firewall.allowedUDPPorts = [ rpPort ];

      services.rosenpassKeyExchange = {
        enable = true;
        config = staticConfig.peerA.rosenpassConfig;
        rosenpassVersion = pkgs.rosenpass-peer-a;
      };
    };

    peerbkeyexchanger = {
      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [ snakeOilPublicKey ];

      services.rosenpassKeyExchange = {
        enable = true;
        config = staticConfig.peerB.rosenpassConfig;
        rosenpassVersion = pkgs.rosenpass-peer-b;
      };
    };
  } // lib.optionalAttrs multiPeer {
    peerC = {
      networking.wireguard.interfaces.${wgInterface} = {
        listenPort = wgPort;
        ips = [ "${staticConfig.peerC.innerIp}/24" ];
        inherit (staticConfig.peerC) privateKey;
        peers = [
          {
            inherit (staticConfig.peerA) publicKey;
            allowedIPs = [ "${staticConfig.peerA.innerIp}/32" ];
            endpoint = "peerA:${builtins.toString wgPort}";
            presharedKey = "s9aIG1pY6nj2lH6p61tP8WRETNgQvoTfgel5BmVjYeI=";
          } # TODO document that we use mismatching presahred keys on purpose
          {
            inherit (staticConfig.peerB) publicKey;
            allowedIPs = [ "${staticConfig.peerB.innerIp}/32" ];
            endpoint = "peerB:${builtins.toString wgPort}";
            presharedKey = "DYlFqWg/M6EfnMolBO+b4DFNrRyS6YWr4lM/2xRE1FQ=";
          } # TODO document that we use mismatching presahred keys on purpose
        ];
      };
      networking.firewall.allowedUDPPorts = [ wgPort ];

      services.rosenpassKeySync.instances = {
        CA = {
          enable = true;
          inherit wgInterface;
          rpHost = "peerckeyexchanger";
          peerPubkey = staticConfig.peerA.publicKey;
          remoteKeyPath = keyExchangePathCA;
        };
        CB = {
          enable = true;
          inherit wgInterface;
          rpHost = "peerckeyexchanger";
          peerPubkey = staticConfig.peerB.publicKey;
          remoteKeyPath = keyExchangePathCB;
        };
      };
    };
    peerckeyexchanger = {
      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [ snakeOilPublicKey ];
      networking.firewall.allowedUDPPorts = [ rpPort ];

      services.rosenpassKeyExchange = {
        enable = true;
        config = staticConfig.peerC.rosenpassConfig;
        rosenpassVersion = pkgs.rosenpass-peer-c;
      };
    };
  };

  interactive = {
    defaults = {
      users.extraUsers.root.initialPassword = "";
      services.openssh = {
        enable = true;
        settings = {
          PermitRootLogin = "yes";
          PermitEmptyPasswords = "yes";
        };
      };
      security.pam.services.sshd.allowNullPassword = true;
      environment.systemPackages = [
        prepareSshLogin

        (pkgs.writeSellScriptBin "install-rosenpass-keys" (''
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-a.sk peerakeyexchanger:${rosenpassKeyFolder}/self.sk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-a.pk peerakeyexchanger:${rosenpassKeyFolder}/self.pk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-b.pk peerakeyexchanger:${rosenpassKeyFolder}/peer-b.pk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-b.sk peerbkeyexchanger:${rosenpassKeyFolder}/self.sk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-b.pk peerbkeyexchanger:${rosenpassKeyFolder}/self.pk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-a.pk peerbkeyexchanger:${rosenpassKeyFolder}/peer-a.pk
        '' + lib.optionalString multiPeer ''
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-c.sk peerckeyexchanger:${rosenpassKeyFolder}/self.sk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-c.pk peerckeyexchanger:${rosenpassKeyFolder}/self.pk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-a.pk peerckeyexchanger:${rosenpassKeyFolder}/peer-a.pk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-b.pk peerckeyexchanger:${rosenpassKeyFolder}/peer-b.pk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-c.pk peerakeyexchanger:${rosenpassKeyFolder}/peer-c.pk
          ${pkgs.openssh}/bin/scp ${demoRosenpassKeys}/peer-c.pk peerbkeyexchanger:${rosenpassKeyFolder}/peer-c.pk
        ''
        ))

        (pkgs.writeShellScriptBin "watch-wg" ''
          ${pkgs.procps}/bin/watch -n1 \
            ${pkgs.wireguard-tools}/bin/wg show all preshared-keys
        '')
      ];
    };
    nodes.peerA = {
      virtualisation.forwardPorts = [
        { from = "host"; host.port = 2222; guest.port = 22; }
      ];
    };
    nodes.peerB = {
      virtualisation.forwardPorts = [
        { from = "host"; host.port = 2223; guest.port = 22; }
      ];
    };
    nodes.peerC = {
      virtualisation.forwardPorts = [
        { from = "host"; host.port = 2224; guest.port = 22; }
      ];
    };
  };

  testScript = (''
    start_all()

    PEER_A_IP = "${builtins.toString staticConfig.peerA.innerIp}"
    PEER_B_IP = "${builtins.toString staticConfig.peerB.innerIp}"
    '' + lib.optionalString multiPeer ''
      PEER_C_IP = "${builtins.toString staticConfig.peerC.innerIp}"
    '' + ''

    for m in [peerA, peerB, peerakeyexchanger, peerbkeyexchanger]:
      m.wait_for_unit("network-online.target")
    ''
      + lib.optionalString multiPeer ''
      for m in [peerC, peerckeyexchanger]:
        m.wait_for_unit("network-online.target")
    '' + ''

    # The wireguard connection can't work because the sync services fail on
    # non-recognized SSH host keys, and we didn't deploy the secrets.
    peerB.fail("ping -c 1 ${staticConfig.peerA.innerIp}")
    peerA.fail("ping -c 1 ${staticConfig.peerB.innerIp}")
    ''
      + lib.optionalString multiPeer ''
      peerA.fail(f"ping -c 1 {PEER_C_IP}")
      peerB.fail(f"ping -c 1 {PEER_C_IP}")
      peerC.fail(f"ping -c 1 {PEER_A_IP}")
      peerC.fail(f"ping -c 1 {PEER_B_IP}")
    '' + ''

    # In admin-reality, this should be done with your favorite secret
    # provisioning/deployment tool
    peerakeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-a.sk ${rosenpassKeyFolder}/self.sk"
    )
    peerakeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-a.pk ${rosenpassKeyFolder}/self.pk"
    )
    peerakeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-b.pk ${rosenpassKeyFolder}/peer-b.pk"
    )
    peerbkeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-b.sk ${rosenpassKeyFolder}/self.sk"
    )
    peerbkeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-b.pk ${rosenpassKeyFolder}/self.pk"
    )
    peerbkeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-a.pk ${rosenpassKeyFolder}/peer-a.pk"
    )
    ''
      + lib.optionalString multiPeer ''
    peerakeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-c.pk ${rosenpassKeyFolder}/peer-c.pk"
    )
    peerbkeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-c.pk ${rosenpassKeyFolder}/peer-c.pk"
    )
    peerckeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-c.sk ${rosenpassKeyFolder}/self.sk"
    )
    peerckeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-c.pk ${rosenpassKeyFolder}/self.pk"
    )
    peerckeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-a.pk ${rosenpassKeyFolder}/peer-a.pk"
    )
    peerckeyexchanger.succeed(
      "cp ${demoRosenpassKeys}/peer-b.pk ${rosenpassKeyFolder}/peer-b.pk"
    )
    '' + ''


    # Until now, the services must have failed due to lack of keys
    peerakeyexchanger.succeed("systemctl restart rp-exchange.service")
    peerbkeyexchanger.succeed("systemctl restart rp-exchange.service")
    ''
      + lib.optionalString multiPeer ''
    peerckeyexchanger.succeed("systemctl restart rp-exchange.service")
    '' + ''

    # In reality, admins would carefully manage known SSH host keys with
    # their favorite secret provisioning/deployment tool
    peerA.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerakeyexchanger")
    peerB.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerbkeyexchanger")
    ''
      + lib.optionalString multiPeer ''
    peerC.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerckeyexchanger")
    '' + ''
    for m in [peerbkeyexchanger, peerakeyexchanger]:
      m.wait_for_unit("rp-exchange.service")

    ''
      + lib.optionalString multiPeer ''
    peerckeyexchanger.wait_for_unit("rp-exchange.service")
    '' + ''
    peerA.wait_for_unit("rp-key-sync-AB.service")
    peerB.wait_for_unit("rp-key-sync-BA.service")
    ''
      + lib.optionalString multiPeer ''
    peerA.wait_for_unit("rp-key-sync-AC.service")
    peerB.wait_for_unit("rp-key-sync-BC.service")
    peerC.wait_for_unit("rp-key-sync-CA.service")
    peerC.wait_for_unit("rp-key-sync-CB.service")
    '' + ''

    # Voila!
    peerA.succeed("ping -c 1 ${staticConfig.peerB.innerIp}")
    peerB.succeed("ping -c 1 ${staticConfig.peerA.innerIp}")
    ''
      + lib.optionalString multiPeer ''
    peerA.succeed("ping -c 1 ${staticConfig.peerC.innerIp}")
    peerB.succeed("ping -c 1 ${staticConfig.peerC.innerIp}")
    peerC.succeed("ping -c 1 ${staticConfig.peerA.innerIp}")
    peerC.succeed("ping -c 1 ${staticConfig.peerB.innerIp}")
  '');
}
