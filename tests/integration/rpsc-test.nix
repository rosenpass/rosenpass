{
  pkgs,
  lib,
  multiPeer ? false,
  ...
}:
let
  wgInterface = "mywg";
  wgPort = 51820;
  rpPort = 51821;

  rosenpassKeyFolder = "/var/secrets";
  wireguardKeyFolder = "/var/wgKeys";
  keyExchangePathAB = "/root/peer-ab.osk";
  keyExchangePathBA = "/root/peer-ba.osk";
  keyExchangePathAC = "/root/peer-ac.osk";
  keyExchangePathCA = "/root/peer-ca.osk";
  keyExchangePathBC = "/root/peer-bc.osk";
  keyExchangePathCB = "/root/peer-cb.osk";

  getConfigFileVersion =
    rosenpassVersion:
    let
      configFileVersion =
        if builtins.hasAttr "configFileVersion" rosenpassVersion then
          rosenpassVersion.configFileVersion
        else
          "0";
    in
    configFileVersion;

  peerAConfigFileVersion = getConfigFileVersion pkgs.rosenpass-peer-a;
  peerBConfigFileVersion = getConfigFileVersion pkgs.rosenpass-peer-b;
  peerCConfigFileVersion = if multiPeer then getConfigFileVersion pkgs.rosenpass-peer-c else null;

  staticConfig =
    {
      peerA = {
        innerIp = "10.100.0.1";
        wgPrivateKeyFile = "${wireguardKeyFolder}/peerA.sk";
        wgPublicKeyFile = "${wireguardKeyFolder}/peerA.pk";
        rosenpassConfig = builtins.toFile "peer-a.toml" (
          ''
            public_key = "${rosenpassKeyFolder}/self.pk"
            secret_key = "${rosenpassKeyFolder}/self.sk"
            listen = ["[::]:${builtins.toString rpPort}"]
            verbosity = "Verbose"

            [[peers]]
            public_key = "${rosenpassKeyFolder}/peer-b.pk"
            endpoint = "peerbkeyexchanger:${builtins.toString rpPort}"
            key_out = "${keyExchangePathAB}"
          ''
          + (lib.optionalString multiPeer ''
            [[peers]]
            public_key = "${rosenpassKeyFolder}/peer-c.pk"
            endpoint = "peerckeyexchanger:${builtins.toString rpPort}"
            key_out = "${keyExchangePathAC}"
          '')
        );
      };
      peerB = {
        innerIp = "10.100.0.2";
        wgPrivateKeyFile = "${wireguardKeyFolder}/peerB.sk";
        wgPublicKeyFile = "${wireguardKeyFolder}/peerB.pk";
        rosenpassConfig = builtins.toFile "peer-b.toml" (
          ''
            public_key = "${rosenpassKeyFolder}/self.pk"
            secret_key = "${rosenpassKeyFolder}/self.sk"
            listen = ["[::]:${builtins.toString rpPort}"]
            verbosity = "Verbose"

            [[peers]]
            public_key = "${rosenpassKeyFolder}/peer-a.pk"
            endpoint = "peerakeyexchanger:${builtins.toString rpPort}"
            key_out = "${keyExchangePathBA}"
          ''
          + (lib.optionalString multiPeer ''
            [[peers]]
            public_key = "${rosenpassKeyFolder}/peer-c.pk"
            endpoint = "peerckeyexchanger:${builtins.toString rpPort}"
            key_out = "${keyExchangePathBC}"
          '')
        );
      };
    }
    // lib.optionalAttrs multiPeer {
      # peerC is only defined if we are in a multiPeer context.
      peerC = {
        innerIp = "10.100.0.3";
        wgPrivateKeyFile = "${wireguardKeyFolder}/peerC.sk";
        wgPublicKeyFile = "${wireguardKeyFolder}/peerC.pk";
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
    snakeOilPrivateKey
    ;

  # All hosts in this scenario use the same key pair
  # The script takes the host as parameter and prepares passwordless login
  prepareSshLogin = pkgs.writeShellScriptBin "prepare-ssh-login" ''
    set -euo pipefail
    mkdir -p /root/.ssh
    cp ${snakeOilPrivateKey} /root/.ssh/id_ecdsa
    chmod 0400 /root/.ssh/id_ecdsa
    ${pkgs.openssh}/bin/ssh -o StrictHostKeyChecking=no "$1" true
  '';
in
{
  name = "rosenpass with key exchangers";
  defaults = {
    imports = [
      ./rp-key-exchange.nix
      ./rp-key-sync.nix
    ];

    systemd.tmpfiles.rules = [ "d ${rosenpassKeyFolder} 0400 root root - -" ];
  };

  nodes =
    {
      # peerA and peerB are the only neccessary peers unless we are in the multiPeer test.
      peerA = {
        networking.firewall.allowedUDPPorts = [ wgPort ];

        # Each instance of the key sync service loads a symmetric key from a rosenpass keyexchanger node and sets it as the preshared key for the appropriate wireguard tunnel.
        services.rosenpassKeySync.instances =
          {
            AB = {
              create = true;
              enable = false;
              inherit wgInterface;
              rpHost = "peerakeyexchanger";
              peerPubkeyFile = staticConfig.peerB.wgPublicKeyFile;
              remoteKeyPath = keyExchangePathAB;
              endpoint = "peerB:${builtins.toString wgPort}";
              allowedIps = "${staticConfig.peerB.innerIp}/32";
            };
          }
          // lib.optionalAttrs multiPeer {
            AC = {
              create = true;
              enable = false;
              inherit wgInterface;
              rpHost = "peerakeyexchanger";
              peerPubkeyFile = staticConfig.peerC.wgPublicKeyFile;
              remoteKeyPath = keyExchangePathAC;
              endpoint = "peerC:${builtins.toString wgPort}";
              allowedIps = "${staticConfig.peerC.innerIp}/32";
            };
          };
      };
      peerB = {
        networking.firewall.allowedUDPPorts = [ wgPort ];

        # Each instance of the key sync service loads a symmetric key from a rosenpass keyexchanger node and sets it as the preshared key for the appropriate wireguard tunnel.
        services.rosenpassKeySync.instances =
          {
            BA = {
              create = true;
              enable = false;
              inherit wgInterface;
              rpHost = "peerbkeyexchanger";
              peerPubkeyFile = staticConfig.peerA.wgPublicKeyFile;
              remoteKeyPath = keyExchangePathBA;
              endpoint = "peerA:${builtins.toString wgPort}";
              allowedIps = "${staticConfig.peerA.innerIp}/32";
            };
          }
          // lib.optionalAttrs multiPeer {
            BC = {
              create = true;
              enable = false;
              inherit wgInterface;
              rpHost = "peerbkeyexchanger";
              peerPubkeyFile = staticConfig.peerC.wgPublicKeyFile;
              remoteKeyPath = keyExchangePathBC;
              endpoint = "peerC:${builtins.toString wgPort}";
              allowedIps = "${staticConfig.peerC.innerIp}/32";
            };
          };
      };

      # The key exchanger node for peerA is the node that actually runs rosenpass. It takes the rosenpass confguration for peerA and runs it.
      # The key sync services of peerA will ssh into this node and download the exchanged keys from here.
      peerakeyexchanger = {
        services.openssh.enable = true;
        users.users.root.openssh.authorizedKeys.keys = [ snakeOilPublicKey ];
        networking.firewall.allowedUDPPorts = [ rpPort ];

        services.rosenpassKeyExchange = {
          create = true;
          enable = false;
          config = staticConfig.peerA.rosenpassConfig;
          rosenpassVersion = pkgs.rosenpass-peer-a;
        };
      };

      # The key exchanger node for peerB is the node that actually runs rosenpass. It takes the rosenpass confguration for peerB and runs it.
      # The key sync services of peerB will ssh into this node and download the exchanged keys from here.
      peerbkeyexchanger = {
        services.openssh.enable = true;
        users.users.root.openssh.authorizedKeys.keys = [ snakeOilPublicKey ];

        services.rosenpassKeyExchange = {
          create = true;
          enable = false;
          config = staticConfig.peerB.rosenpassConfig;
          rosenpassVersion = pkgs.rosenpass-peer-b;
        };
      };
    }
    // lib.optionalAttrs multiPeer {
      peerC = {
        networking.firewall.allowedUDPPorts = [ wgPort ];

        # Each instance of the key sync service loads a symmetric key from a rosenpass keyexchanger node and sets it as the preshared key for the appropriate wireguard tunnel.
        services.rosenpassKeySync.instances = {
          CA = {
            create = true;
            enable = false;
            inherit wgInterface;
            rpHost = "peerckeyexchanger";
            peerPubkeyFile = staticConfig.peerA.wgPublicKeyFile;
            remoteKeyPath = keyExchangePathCA;
            endpoint = "peerA:${builtins.toString wgPort}";
            allowedIps = "${staticConfig.peerA.innerIp}/32";
          };
          CB = {
            create = true;
            enable = false;
            inherit wgInterface;
            rpHost = "peerckeyexchanger";
            peerPubkeyFile = staticConfig.peerB.wgPublicKeyFile;
            remoteKeyPath = keyExchangePathCB;
            endpoint = "peerB:${builtins.toString wgPort}";
            allowedIps = "${staticConfig.peerB.innerIp}/32";
          };
        };
      };

      # The key exchanger node for peerC is the node that actually runs rosenpass. It takes the rosenpass confguration for peerC and runs it.
      # The key sync services of peerC will ssh into this node and download the exchanged keys from here.
      peerckeyexchanger = {
        services.openssh.enable = true;
        users.users.root.openssh.authorizedKeys.keys = [ snakeOilPublicKey ];
        networking.firewall.allowedUDPPorts = [ rpPort ];

        services.rosenpassKeyExchange = {
          create = true;
          enable = false;
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
        (pkgs.writeShellScriptBin "watch-wg" ''
          ${pkgs.procps}/bin/watch -n1 \
            ${pkgs.wireguard-tools}/bin/wg show all preshared-keys
        '')
      ];
    };
    nodes.peerA = {
      virtualisation.forwardPorts = [
        {
          from = "host";
          host.port = 2222;
          guest.port = 22;
        }
      ];
    };
    nodes.peerB = {
      virtualisation.forwardPorts = [
        {
          from = "host";
          host.port = 2223;
          guest.port = 22;
        }
      ];
    };
    nodes.peerC = {
      virtualisation.forwardPorts = [
        {
          from = "host";
          host.port = 2224;
          guest.port = 22;
        }
      ];
    };
  };

  testScript = (''
    start_all()

    print("""Config file versions supported by peers
      peerA: ${peerAConfigFileVersion}
      peerB: ${peerBConfigFileVersion}
      ${lib.optionalString multiPeer ''
        peerC: ${peerCConfigFileVersion}
      ''}
    """)

    for m in [peerA, peerB, peerakeyexchanger, peerbkeyexchanger]:
      m.wait_for_unit("network-online.target")

    ${lib.optionalString multiPeer ''
      for m in [peerC, peerckeyexchanger]:
        m.wait_for_unit("network-online.target")
    ''}

    # Generate the normal wireguard key pairs
    peerA.succeed("mkdir ${wireguardKeyFolder}")
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg genkey > ${staticConfig.peerA.wgPrivateKeyFile}")
    peerA.succeed("cat ${staticConfig.peerA.wgPrivateKeyFile} | ${pkgs.wireguard-tools}/bin/wg pubkey > ${staticConfig.peerA.wgPublicKeyFile}")
    peerAWgSk = peerA.succeed("cat ${staticConfig.peerA.wgPrivateKeyFile} | tr -d '\n'")
    peerAWgPk = peerA.succeed("cat ${staticConfig.peerA.wgPublicKeyFile} | tr -d '\n'")
    peerA.succeed("echo -n AR/yvSvMAzW6eS27PsRHUMWwC8cLhaD96t42cysxrb0= > ${wireguardKeyFolder}/peerB.psk")

    peerB.succeed("mkdir ${wireguardKeyFolder}")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg genkey > ${staticConfig.peerB.wgPrivateKeyFile}")
    peerB.succeed("cat ${staticConfig.peerB.wgPrivateKeyFile} | ${pkgs.wireguard-tools}/bin/wg pubkey > ${staticConfig.peerB.wgPublicKeyFile}")
    peerBWgSk = peerB.succeed("cat ${staticConfig.peerB.wgPrivateKeyFile} | tr -d '\n'")
    peerBWgPk = peerB.succeed("cat ${staticConfig.peerB.wgPublicKeyFile} | tr -d '\n'")
    peerB.succeed("echo -n o25fjoIOI623cnRyhvD4YEGtuSY4BFRZmY3UHvZ0BCA= > ${wireguardKeyFolder}/peerA.psk")
    ${lib.optionalString multiPeer ''
      peerC.succeed("mkdir ${wireguardKeyFolder}")
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg genkey > ${staticConfig.peerC.wgPrivateKeyFile}")
      peerC.succeed("cat ${staticConfig.peerC.wgPrivateKeyFile} | ${pkgs.wireguard-tools}/bin/wg pubkey > ${staticConfig.peerC.wgPublicKeyFile}")
      peerCWgSk = peerC.succeed("cat ${staticConfig.peerC.wgPrivateKeyFile} | tr -d '\n'")
      peerCWgPk = peerC.succeed("cat ${staticConfig.peerC.wgPublicKeyFile} | tr -d '\n'")
      peerA.succeed("echo -n LfWvJCN8h7NhS+JWRG7GMIY20JxUV4WUs7MJ45ZGoCE= > ${wireguardKeyFolder}/peerC.psk")
      peerB.succeed("echo -n GsYTUd/4Ph7wMy5r+W1no9yGe0UeZlmCPeiyu4tb6yM= > ${wireguardKeyFolder}/peerC.psk")
      peerC.succeed("echo -n s9aIG1pY6nj2lH6p61tP8WRETNgQvoTfgel5BmVjYeI= > ${wireguardKeyFolder}/peerA.psk")
      peerC.succeed("echo -n DYlFqWg/M6EfnMolBO+b4DFNrRyS6YWr4lM/2xRE1FQ= > ${wireguardKeyFolder}/peerB.psk")
    ''}

    # Distribute the respective public keys
    peerA.succeed(f"echo -n {peerBWgPk} > ${wireguardKeyFolder}/peerB.pk")
    peerB.succeed(f"echo -n {peerAWgPk} > ${wireguardKeyFolder}/peerA.pk")
    ${lib.optionalString multiPeer ''
      peerA.succeed(f"echo -n {peerCWgPk} > ${wireguardKeyFolder}/peerC.pk")
      peerB.succeed(f"echo -n {peerCWgPk} > ${wireguardKeyFolder}/peerC.pk")
      peerC.succeed(f"echo -n {peerAWgPk} > ${wireguardKeyFolder}/peerA.pk")
      peerC.succeed(f"echo -n {peerBWgPk} > ${wireguardKeyFolder}/peerB.pk")
    ''}

    # Make the wireguard public keys readable for the key-sync service.
    peerA.succeed("chmod -R 0555 ${wireguardKeyFolder}")
    peerB.succeed("chmod -R 0555 ${wireguardKeyFolder}")
    ${lib.optionalString multiPeer ''
      peerC.succeed("chmod -R 0555 ${wireguardKeyFolder}")
    ''}

    # Set up wireguard on peerA
    peerA.succeed("ip link add ${wgInterface} type wireguard")
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg set ${wgInterface} private-key ${staticConfig.peerA.wgPrivateKeyFile} listen-port ${builtins.toString wgPort}")
    peerA.succeed(f"${pkgs.wireguard-tools}/bin/wg set ${wgInterface} peer {peerBWgPk} allowed-ips ${staticConfig.peerB.innerIp}/32 endpoint peerB:${builtins.toString wgPort} preshared-key ${wireguardKeyFolder}/peerB.psk")
    ${lib.optionalString multiPeer ''
      peerA.succeed(f"${pkgs.wireguard-tools}/bin/wg set ${wgInterface} peer {peerCWgPk} allowed-ips ${staticConfig.peerC.innerIp}/32 endpoint peerC:${builtins.toString wgPort} preshared-key ${wireguardKeyFolder}/peerC.psk")
    ''}
    peerA.succeed("ip addr add ${staticConfig.peerA.innerIp}/32 dev ${wgInterface}")
    peerA.succeed("ip link set ${wgInterface} up")
    peerA.succeed("ip route add ${staticConfig.peerB.innerIp} dev ${wgInterface} scope link")
    ${lib.optionalString multiPeer ''
      peerA.succeed("ip route add ${staticConfig.peerC.innerIp} dev ${wgInterface} scope link")
    ''}

    # Set up wireguard on peerB
    peerB.succeed("ip link add ${wgInterface} type wireguard")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg set ${wgInterface} private-key ${staticConfig.peerB.wgPrivateKeyFile} listen-port ${builtins.toString wgPort}")
    peerB.succeed(f"${pkgs.wireguard-tools}/bin/wg set ${wgInterface} peer {peerAWgPk} allowed-ips ${staticConfig.peerA.innerIp}/32 endpoint peerA:${builtins.toString wgPort} preshared-key ${wireguardKeyFolder}/peerA.psk")
    ${lib.optionalString multiPeer ''
      peerB.succeed(f"${pkgs.wireguard-tools}/bin/wg set ${wgInterface} peer {peerCWgPk} allowed-ips ${staticConfig.peerC.innerIp}/32 endpoint peerC:${builtins.toString wgPort} preshared-key ${wireguardKeyFolder}/peerC.psk")
    ''}
    peerB.succeed("ip addr add ${staticConfig.peerB.innerIp}/32 dev ${wgInterface}")
    peerB.succeed("ip link set ${wgInterface} up")
    peerB.succeed("ip route add ${staticConfig.peerA.innerIp} dev ${wgInterface} scope link")
    ${lib.optionalString multiPeer ''
      peerB.succeed("ip route add ${staticConfig.peerC.innerIp} dev ${wgInterface} scope link")
    ''}

    # Set up wireguard on peerC
    ${lib.optionalString multiPeer ''
      peerC.succeed("ip link add ${wgInterface} type wireguard")
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg set ${wgInterface} private-key ${staticConfig.peerC.wgPrivateKeyFile} listen-port ${builtins.toString wgPort}")
      peerC.succeed(f"${pkgs.wireguard-tools}/bin/wg set ${wgInterface} peer {peerAWgPk} allowed-ips ${staticConfig.peerA.innerIp}/32 endpoint peerA:${builtins.toString wgPort} preshared-key ${wireguardKeyFolder}/peerA.psk")
      peerC.succeed(f"${pkgs.wireguard-tools}/bin/wg set ${wgInterface} peer {peerBWgPk} allowed-ips ${staticConfig.peerB.innerIp}/32 endpoint peerB:${builtins.toString wgPort} preshared-key ${wireguardKeyFolder}/peerB.psk")
      peerC.succeed("ip addr add ${staticConfig.peerC.innerIp}/32 dev ${wgInterface}")
      peerC.succeed("ip link set ${wgInterface} up")
      peerC.succeed("ip route add ${staticConfig.peerA.innerIp} dev ${wgInterface} scope link")
      peerC.succeed("ip route add ${staticConfig.peerB.innerIp} dev ${wgInterface} scope link")
    ''}

    # Dump current state of WireGuard tunnels
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ''}
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ''}

    # Dump current network config
    peerA.succeed("ip addr 1>&2")
    peerA.succeed("ip route 1>&2")
    peerakeyexchanger.succeed("ip addr 1>&2")
    peerakeyexchanger.succeed("ip route 1>&2")

    peerB.succeed("ip addr 1>&2")
    peerB.succeed("ip route 1>&2")
    peerbkeyexchanger.succeed("ip addr 1>&2")
    peerbkeyexchanger.succeed("ip route 1>&2")

    ${lib.optionalString multiPeer ''
      peerC.succeed("ip addr 1>&2")
      peerC.succeed("ip route 1>&2")
      peerckeyexchanger.succeed("ip addr 1>&2")
      peerckeyexchanger.succeed("ip route 1>&2")
    ''}

    # The wireguard connection can't work because the sync services fail on
    # non-recognized SSH host keys, we didn't deploy the secrets and because the preshared keyes don't match.
    peerB.fail("ping -W 2 -c 1 ${staticConfig.peerA.innerIp}")
    peerA.fail("ping -W 2 -c 1 ${staticConfig.peerB.innerIp}")
    ${lib.optionalString multiPeer ''
      peerA.fail("ping -W 2 -c 1 ${staticConfig.peerC.innerIp}")
      peerB.fail("ping -W 2 -c 1 ${staticConfig.peerC.innerIp}")
      peerC.fail("ping -W 2 -c 1 ${staticConfig.peerA.innerIp}")
      peerC.fail("ping -W 2 -c 1 ${staticConfig.peerB.innerIp}")
    ''}

    # In admin-reality, this should be done with your favorite secret
    # provisioning/deployment tool
    # In reality, admins would carefully manage known SSH host keys with
    # their favorite secret provisioning/deployment tool
    peerA.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerakeyexchanger")
    peerB.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerbkeyexchanger")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerckeyexchanger")
    ''}
    peerakeyexchanger.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerbkeyexchanger")
    peerbkeyexchanger.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerakeyexchanger")
    ${lib.optionalString multiPeer ''
      peerakeyexchanger.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerckeyexchanger")
      peerbkeyexchanger.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerckeyexchanger")
      peerckeyexchanger.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerakeyexchanger")
      peerckeyexchanger.succeed("${prepareSshLogin}/bin/prepare-ssh-login peerbkeyexchanger")
    ''}

    # Generate the rosenpass key pairs.
    peerakeyexchanger.succeed(
      "${pkgs.rosenpass-peer-a}/bin/rosenpass gen-keys -p ${rosenpassKeyFolder}/self.pk -s ${rosenpassKeyFolder}/self.sk"
    )
    peerbkeyexchanger.succeed(
      "${pkgs.rosenpass-peer-b}/bin/rosenpass gen-keys -p ${rosenpassKeyFolder}/self.pk -s ${rosenpassKeyFolder}/self.sk"
    )
    ${lib.optionalString multiPeer ''
      peerckeyexchanger.succeed(
        "${pkgs.rosenpass-peer-c}/bin/rosenpass gen-keys -p ${rosenpassKeyFolder}/self.pk -s ${rosenpassKeyFolder}/self.sk"
      )
    ''}

    peerakeyexchanger.succeed(
      "scp ${rosenpassKeyFolder}/self.pk peerbkeyexchanger:${rosenpassKeyFolder}/peer-a.pk"
    )
    peerbkeyexchanger.succeed(
      "scp ${rosenpassKeyFolder}/self.pk peerakeyexchanger:${rosenpassKeyFolder}/peer-b.pk"
    )
    ${lib.optionalString multiPeer ''
      peerakeyexchanger.succeed(
        "scp ${rosenpassKeyFolder}/self.pk peerckeyexchanger:${rosenpassKeyFolder}/peer-a.pk"
      )
      peerbkeyexchanger.succeed(
        "scp ${rosenpassKeyFolder}/self.pk peerckeyexchanger:${rosenpassKeyFolder}/peer-b.pk"
      )
      peerckeyexchanger.succeed(
        "scp ${rosenpassKeyFolder}/self.pk peerakeyexchanger:${rosenpassKeyFolder}/peer-c.pk"
      )
      peerckeyexchanger.succeed(
        "scp ${rosenpassKeyFolder}/self.pk peerbkeyexchanger:${rosenpassKeyFolder}/peer-c.pk"
      )
    ''}

    # Until now, the services were disbaled and didn't start (using the enable option of the services)
    peerakeyexchanger.succeed("systemctl start rp-exchange.service")
    peerbkeyexchanger.succeed("systemctl start rp-exchange.service")

    ${lib.optionalString multiPeer ''
      peerckeyexchanger.succeed("systemctl start rp-exchange.service")
    ''}

    # Wait for the service to have started.
    for m in [peerbkeyexchanger, peerakeyexchanger]:
      m.wait_for_unit("rp-exchange.service")

    ${lib.optionalString multiPeer ''
      peerckeyexchanger.wait_for_unit("rp-exchange.service")
    ''}

    # Dump current network config
    peerA.succeed("ip addr 1>&2")
    peerA.succeed("ip route 1>&2")
    peerakeyexchanger.succeed("ip addr 1>&2")
    peerakeyexchanger.succeed("ip route 1>&2")

    peerB.succeed("ip addr 1>&2")
    peerB.succeed("ip route 1>&2")
    peerbkeyexchanger.succeed("ip addr 1>&2")
    peerbkeyexchanger.succeed("ip route 1>&2")

    ${lib.optionalString multiPeer ''
      peerC.succeed("ip addr 1>&2")
      peerC.succeed("ip route 1>&2")
      peerckeyexchanger.succeed("ip addr 1>&2")
      peerckeyexchanger.succeed("ip route 1>&2")
    ''}

    # Dump current state of WireGuard tunnels
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ''}
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ''}

    # Start key sync services and wait for them to start.
    peerA.succeed("systemctl start rp-key-sync-AB.service")
    peerB.succeed("systemctl start rp-key-sync-BA.service")

    ${lib.optionalString multiPeer ''
      peerA.succeed("systemctl start rp-key-sync-AC.service")
      peerB.succeed("systemctl start rp-key-sync-BC.service")
      peerC.succeed("systemctl start rp-key-sync-CA.service")
      peerC.succeed("systemctl start rp-key-sync-CB.service")
    ''}

    peerA.wait_for_unit("rp-key-sync-AB.service")
    peerB.wait_for_unit("rp-key-sync-BA.service")

    ${lib.optionalString multiPeer ''
      peerA.wait_for_unit("rp-key-sync-AC.service")
      peerB.wait_for_unit("rp-key-sync-BC.service")
      peerC.wait_for_unit("rp-key-sync-CA.service")
      peerC.wait_for_unit("rp-key-sync-CB.service")
    ''}

    # Dump current network config
    peerA.succeed("ip addr 1>&2")
    peerA.succeed("ip route 1>&2")
    peerakeyexchanger.succeed("ip addr 1>&2")
    peerakeyexchanger.succeed("ip route 1>&2")

    peerB.succeed("ip addr 1>&2")
    peerB.succeed("ip route 1>&2")
    peerbkeyexchanger.succeed("ip addr 1>&2")
    peerbkeyexchanger.succeed("ip route 1>&2")

    ${lib.optionalString multiPeer ''
      peerC.succeed("ip addr 1>&2")
      peerC.succeed("ip route 1>&2")
      peerckeyexchanger.succeed("ip addr 1>&2")
      peerckeyexchanger.succeed("ip route 1>&2")
    ''}

    # Dump current state of WireGuard tunnels
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ''}
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ''}

    # Voila!
    peerB.succeed("ping -c 1 -W 10 ${staticConfig.peerA.innerIp}")
    ${lib.optionalString multiPeer ''
      peerC.succeed("ping -c 1 -W 10 ${staticConfig.peerA.innerIp}")
      peerC.succeed("ping -c 1 -W 10 ${staticConfig.peerB.innerIp}")
      peerA.succeed("ping -c 1 -W 10 ${staticConfig.peerC.innerIp}")
      peerB.succeed("ping -c 1 -W 10 ${staticConfig.peerC.innerIp}")
    ''}
    peerA.succeed("ping -c 1 -W 10 ${staticConfig.peerB.innerIp}")

    # Dump current state of WireGuard tunnels
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all 1>&2")
    ''}
    peerA.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    peerB.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ${lib.optionalString multiPeer ''
      peerC.succeed("${pkgs.wireguard-tools}/bin/wg show all preshared-keys 1>&2")
    ''}

  '');
}
