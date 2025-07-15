{
  dockerTools,
  buildEnv,
  rosenpass,
}:

dockerTools.buildImage {
  name = rosenpass.name + "-oci";
  copyToRoot = buildEnv {
    name = "image-root";
    paths = [ rosenpass ];
    pathsToLink = [ "/bin" ];
  };
  config.Cmd = [ "/bin/rosenpass" ];
}
