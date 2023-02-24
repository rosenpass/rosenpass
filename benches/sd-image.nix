{ config, lib, pkgs, modulesPath, rosenpass-flake-packages, ... }:

let
  user = "user";
  benchInterface = "eth0";
  wlanApInterface = "wlan0";
  password = "rosenpass";
  apNet = "10.187.1.1/24";
in
{
  imports = [
    (modulesPath + "/installer/sd-card/sd-image-aarch64.nix")
  ];

  system.stateVersion = "22.11";

  # Do not compress the image as we want to use it straight away
  sdImage = {
    imageBaseName = config.networking.hostName;
    compressImage = false;
  };


  #
  ### User Configuration ###
  #
  users = {
    mutableUsers = false;
    extraUsers = {
      user = {
        isNormalUser = true;
        extraGroups = [ "wheel" ];
        inherit password;
      };
    };
  };


  #
  ### Network Configuration ###
  #
  networking = {
    hostName = "rp-bench";
    # disable standard dhcpcd
    useDHCP = false;
    # enable systemd-networkd
    useNetworkd = true;
    # disable the firewall
    firewall.enable = lib.mkDefault false;
    wireless = {
      enable = true;
      extraConfig = "p2p_disabled=1";
      userControlled.enable = true;
      networks.${config.networking.hostName} = {
        psk = password;
        authProtocols = [ "WPA-PSK" ];
        extraConfig = "mode=2";
      };
    };
  };
  # systemd networkd configuration
  systemd.network = {
    enable = true;
    networks = {
      "10-wireless-ap" = {
        matchConfig.Name = wlanApInterface;
        networkConfig.MulticastDNS = true;
        address = [ apNet ];
        networkConfig.DHCPServer = "yes";
        dhcpServerConfig = {
          EmitDNS = false;
          PoolOffset = 100;
          PoolSize = 100;
        };
      };
      "99-main" = {
        matchConfig.Name = "en* eth*";
        networkConfig.MulticastDNS = true;
      };
    };
  };
  # disable annoying systemd service that always fails
  systemd.services."systemd-networkd-wait-online".enable = false;


  #
  ### Miscellaneous ####
  #
  services.openssh = {
    enable = true;
    passwordAuthentication = true;
  };

  environment.systemPackages = with pkgs; [
    wireguard-tools
    vim
    iperf
    rosenpass-flake-packages.rosenpass
  ];


  #
  ### Actual Benchmark ###
  #
  services.iperf3.enable = true;
  systemd.services.rosenpass-benchmark = {
    path = with pkgs; [
      config.boot.kernelPackages.perf
      rosenpass-flake-packages.rosenpass
    ];
    environment.USERNAME = user;
    environment.PASSWORD = password;
    environment.BENCH_INTERFACE = benchInterface;
    serviceConfig.Exec = rosenpass-flake-packages.rosenpass-bench;
  };
}
