NAME

  {0} – Perform post-quantum secure key exchanges for wireguard and other services.

SYNOPSIS

  {0} [ COMMAND ] [ OPTIONS ]... [ ARGS ]...

DESCRIPTION
  {0} performs cryptographic key exchanges that are secure against quantum-computers and outputs the keys.
  These keys can then be passed to various services such as wireguard or other vpn services
  as pre-shared-keys to achieve security against attackers with quantum computers.

  This is a research project and quantum computers are not thought to become practical in less than ten years.
  If you are not specifically tasked with developing post-quantum secure systems, you probably do not need this tool.

COMMANDS
  
  keygen private-key <file-path> public-key <file-path>
    Generate a keypair to use in the exchange command later. Send the public-key file to your communication partner
    and keep the private-key file a secret!
  
  exchange private-key <file-path> public-key <file-path> [ OPTIONS ]... PEER...\n"
    Start a process to exchange keys with the specified peers. You should specify at least one peer.

    OPTIONS
      listen <ip>[:<port>]
        Instructs {0} to listen on the specified interface and port. By default {0} will listen on all interfaces and select a random port.

      verbose
        Extra logging

    PEER := peer public-key <file-path> [endpoint <ip>[:<port>]] [preshared-key <file-path>] [outfile <file-path>] [wireguard <dev> <peer> <extra_params>]
      Instructs {0} to exchange keys with the given peer and write the resulting PSK into the given output file.
      You must either specify the outfile or wireguard output option.

      endpoint <ip>[:<port>]
        Specifies the address where the peer can be reached. This will be automatically updated after the first sucessfull
        key exchange with the peer. If this is unspecified, the peer must initiate the connection.

      preshared-key <file-path>
        You may specifie a pre-shared key which will be mixied into the final secret.

      outfile <file-path>
        You may specify a file to write the exchanged keys to. If this option is specified, {0} will
        write a notification to standard out every time the key is updated.

      wireguard <dev> <peer> <extra_params>
        This allows you to directly specify a wireguard peer to deploy the pre-shared-key to.
        You may specify extra parameters you would pass to `wg set` besides the preshared-key parameter which is used by {0}.
        This makes it possible to add peers entirely from {0}.
