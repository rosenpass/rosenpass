# Rosenpass

Rosenpass is used to create post-quantum-secure VPNs. Rosenpass computes a shared key, [Wireguard](https://www.wireguard.com/papers/wireguard.pdf) uses the shared key to establish a secure connection. Rosenpass can also be used without WireGuard, deriving post-quantum-secure symmetric keys for another application.
The Rosenpass protocol builds on “Post-quantum WireGuard” ([PQWG](https://eprint.iacr.org/2020/379)) and improves it by using a cookie mechanism to provide security against state disruption attacks.

The rosenpass tool is written in Rust and uses liboqs. The tool establishes a symmetric key and provides it to WireGuard. Since it supplies WireGuard with key through the PSK feature using Rosenpass+WireGuard is cryptographically no less secure than using WireGuard on its own ("hybrid security"). Rosenpass refreshes the symmetric key every two minutes.

As with any application a small risk of critical security issues (such as buffer overflows, remote code execution) exists; the Rosenpass application is written in the Rust programming language which is much less prone to such issues. Rosenpass can also write keys to files instead of supplying them to WireGuard With a bit of scripting the stand alone mode of the implementation can be used to run the application in a Container, VM or on another host. This mode can also be used to integrate tools other than WireGuard with Rosenpass.

The `rp` tool written in Rust makes it easy to create a VPN using WireGuard and Rosenpass.

`rp` is easy to get started with but has a few drawbacks; it runs as root, demanding access to both WireGuard
and Rosenpass private keys, takes control of the interface and works with exactly one interface. If you do not feel confident about running Rosenpass as root, you should use the stand-alone mode to create a more secure setup using containers, jails, or virtual machines.

## Building the Docker Image

Clone the Rosenpass repository:

```
git clone https://github.com/rosenpass/rosenpass
cd rosenpass
```

Use the `docker-buildscript.sh` script to build images from the source.

```bash
bash docker-buildscript.sh
docker images

| REPOSITORY                   | TAG              | IMAGE ID       | CREATED         | SIZE   |
|------------------------------|------------------|----------------|-----------------|--------|
| ghcr.io/rosenpass/rp         | commit-aeb0671   | dc2997662d2c   | 9 hours ago     | 93.2MB |
| ghcr.io/rosenpass/rosenpass  | commit-aeb0671   | 65ccc5e5b9fb   | 9 hours ago     | 93.6MB |
```

Set environment variable `TAG_AS_RELEASE=true` to tag the built images with the current versions.

Set environment variable `TAG_AS_LATEST=true` to tag the built images as latest.

```bash
export TAG_AS_RELEASE=true
export TAG_AS_LATEST=true
bash docker-buildscript.sh
docker images

| REPOSITORY                  | TAG            | IMAGE ID     | CREATED     | SIZE   |
|-----------------------------|----------------|--------------|-------------|--------|
| ghcr.io/rosenpass/rp        | 0.2.1          | 253338c948ab | 9 hours ago | 93.2MB |
| ghcr.io/rosenpass/rp        | commit-05f0ac0 | 253338c948ab | 9 hours ago | 93.2MB |
| ghcr.io/rosenpass/rp        | latest         | 253338c948ab | 9 hours ago | 93.2MB |
| ghcr.io/rosenpass/rosenpass | 0.3.0-dev      | 6958e24fd240 | 9 hours ago | 93.6MB |
| ghcr.io/rosenpass/rosenpass | commit-05f0ac0 | 6958e24fd240 | 9 hours ago | 93.6MB |
| ghcr.io/rosenpass/rosenpass | latest         | 6958e24fd240 | 9 hours ago | 93.6MB |
```

## Usage - Standalone Key Exchange

The `ghcr.io/rosenpass/rosenpass` image can be used in a server-client setup to exchange quantum-secure shared keys.
This setup uses rosenpass as a standalone application, without using any other component such as wireguard.
What follows, is a simple setup for illustrative purposes.

Create a docker network that is used to connect the containers:

```bash
docker network create -d bridge rp
export NET=rp
```

Generate the server and client key pairs:

```bash
mkdir ./workdir-client ./workdir-server
docker run -it --rm -v ./workdir-server:/workdir ghcr.io/rosenpass/rosenpass \
    gen-keys --public-key=workdir/server-public --secret-key=workdir/server-secret
docker run -it --rm -v ./workdir-client:/workdir ghcr.io/rosenpass/rosenpass \
    gen-keys --public-key=workdir/client-public --secret-key=workdir/client-secret
# share the public keys between client and server
 cp workdir-client/client-public workdir-server/client-public
 cp workdir-server/server-public workdir-client/server-public
```

Start the server container:

```bash
docker run  --name "rpserver" --network ${NET} \
    -it --rm -v ./workdir-server:/workdir ghcr.io/rosenpass/rosenpass \
    exchange \
    private-key workdir/server-secret \
    public-key  workdir/server-public \
    listen 0.0.0.0:9999 \
    peer public-key workdir/client-public \
    outfile workdir/server-sharedkey
```

Find out the ip address of the server container:

```bash
EP="rpserver"
EP=$(docker inspect --format '{{ .NetworkSettings.Networks.rp.IPAddress }}' $EP)
```

Run the client container and perform the key exchange:

```bash
docker run --name "rpclient"  --network ${NET} \
    -it --rm -v ./workdir-client:/workdir ghcr.io/rosenpass/rosenpass \
    exchange \
    private-key workdir/client-secret \
    public-key  workdir/client-public \
    peer public-key workdir/server-public endpoint ${EP}:9999 \
    outfile workdir/client-sharedkey
```

Now the containers will exchange shared keys and each put them into their respective outfile.

Comparing the outfiles shows that these shared keys equal:

```bash
cmp workdir/server-sharedkey workdir/client-sharedkey
```

It is now possible to set add these keys as pre-shared keys within a wireguard interface.

```bash
PREKEY=$(cat workdir/client-sharedkey)
wg set <interface> peer <peer-public-key> preshared-key <(echo "$PREKEY")
```

## Usage - Combined with wireguard

The `ghcr.io/rosenpass/rp` image can be used to build a VPN with WireGuard and Rosenpass.
In this example, we run two containers on the same system and connect them with a bridge network within the docker overlay network.

Create the named docker network, to be able to connect the containers.

Create a docker network that is used to connect the containers:

```bash
docker network create -d bridge rp
export NET=rp
```

Generate the server and client secret keys and extract public keys.

```bash
mkdir -p ./workdir-server ./workdir-client

# server
docker run -it --rm -v ./workdir-server:/workdir ghcr.io/rosenpass/rp \
    genkey workdir/server.rosenpass-secret
docker run -it --rm -v ./workdir-server:/workdir ghcr.io/rosenpass/rp \
    pubkey workdir/server.rosenpass-secret workdir/server.rosenpass-public

# client
docker run -it --rm -v ./workdir-client:/workdir ghcr.io/rosenpass/rp \
    genkey workdir/client.rosenpass-secret
docker run -it --rm -v ./workdir-client:/workdir ghcr.io/rosenpass/rp \
    pubkey workdir/client.rosenpass-secret workdir/client.rosenpass-public

# share the public keys between client and server
cp workdir-client/client.rosenpass-public workdir-server/client.rosenpass-public
cp workdir-server/server.rosenpass-public workdir-client/server.rosenpass-public
```

Start the server container.
Note that the `NET_ADMIN` capability is neccessary, the rp command will create and manage wireguard interfaces.
Also make sure the `wireguard` kernel module is loaded by the host. (`lsmod | grep wireguard`)

```bash
docker run  --name "rpserver" --network ${NET} -it -d --rm -v ./workdir-server:/workdir \
    --cap-add=NET_ADMIN \
    ghcr.io/rosenpass/rp \
    exchange workdir/server.rosenpass-secret dev rosenpass0 \
    listen 0.0.0.0:9999 peer workdir/client.rosenpass-public allowed-ips 10.0.0.0/8
```

Now find out the ip-address of the server container and then start the client container:

```bash
EP="rpserver"
EP=$(docker inspect --format '{{ .NetworkSettings.Networks.rp.IPAddress }}' $EP)
docker run --name "rpclient"  --network ${NET} -it -d --rm -v ./workdir-client:/workdir \
    --cap-add=NET_ADMIN \
    ghcr.io/rosenpass/rp \
    exchange workdir/client.rosenpass-secret dev rosenpass1 \
    peer workdir/server.rosenpass-public endpoint ${EP}:9999 allowed-ips 10.0.0.1
```

Inside the docker containers assign the IP addresses:

```bash
# server
docker exec -it rpserver ip a add 10.0.0.1/24 dev rosenpass0

# client
docker exec -it rpclient ip a add 10.0.0.2/24 dev rosenpass1
```

Done! The two containers should now be connected through a wireguard VPN (Port 1000) with pre-shared keys exchanged by rosenpass (Port 9999).

Now, test the connection by starting a shell inside the client container, and ping the server through the VPN:

```bash
# client
docker exec -it rpclient bash
apt update; apt install iputils-ping
ping 10.0.0.1
```

The ping command should continuously show ping-logs:

```
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.119 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.132 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.394 ms
...
```

While the ping is running, you may stop the server container, and verify that the ping-log halts. In another terminal do:

```
docker stop -t 1 rpserver
```

## Contributing

The rosenpass project is maintained on [Github](https://github.com/rosenpass/rosenpass).

Contributions are generally welcome. Join our [Matrix Chat](https://matrix.to/#/#rosenpass:matrix.org) if you are looking for guidance on how to contribute or for people to collaborate with.

We also have a – as of now, very minimal – [contributors guide](https://github.com/rosenpass/rosenpass/blob/main/CONTRIBUTING.md).

## Acknowledgements

Funded through <a href="https://nlnet.nl/">NLNet</a> with financial support for the European Commission's <a href="https://nlnet.nl/assure">NGI Assure</a> program.
