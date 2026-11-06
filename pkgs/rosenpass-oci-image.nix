{
  dockerTools,
  buildEnv,
  rosenpass,
  wireguard-tools,
}:

dockerTools.buildImage {
  name = rosenpass.name + "-oci";
  copyToRoot = buildEnv {
    name = "image-root";
    paths = [
      rosenpass
      # required by rp command:
      wireguard-tools
    ];
    pathsToLink = [ "/bin" ];
  };
  config.Cmd = [ "/bin/rosenpass" ];
}
