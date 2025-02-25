# Rosenpass in Docker

Rosenpass provides post-quantum-secure key exchange for VPNs. It generates symmetric keys used by [WireGuard](https://www.wireguard.com/papers/wireguard.pdf) or other applications. The protocol enhances "Post-Quantum WireGuard" ([PQWG](https://eprint.iacr.org/2020/379)) with a cookie mechanism for better security against state disruption attacks.

Prebuilt Docker images are available for easy deployment:

- [`ghcr.io/rosenpass/rosenpass`](https://github.com/rosenpass/rosenpass/pkgs/container/rosenpass) – the core key exchange tool
- [`ghcr.io/rosenpass/rp`](https://github.com/rosenpass/rosenpass/pkgs/container/rp) – a frontend for setting up WireGuard VPNs

The entrypoint of the `rosenpass` image is the `rosenpass` executable, whose documentation can be found [here](https://rosenpass.eu/docs/rosenpass-tool/manuals/rp_manual/).  
Similarly, the entrypoint of the `rp` image is the `rp` executable, with its documentation available [here](https://rosenpass.eu/docs/rosenpass-tool/manuals/rp1/).

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
cmp workdir-server/server-sharedkey workdir-client/client-sharedkey
```

It is now possible to set add these keys as pre-shared keys within a wireguard interface.
For example as the server,

```bash
PREKEY=$(cat workdir-server/server-sharedkey)
wg set <server-interface> peer <client-peer-public-key> preshared-key <(echo "$PREKEY")
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
cp -r workdir-client/client.rosenpass-public workdir-server/client.rosenpass-public
cp -r workdir-server/server.rosenpass-public workdir-client/server.rosenpass-public
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

## Building the Docker Images Locally

Clone the Rosenpass repository:

```
git clone https://github.com/rosenpass/rosenpass
cd rosenpass
```

Build the rp image from the root of the repository as follows:

```
docker build -f .docker/Dockerfile -t ghcr.io/rosenpass/rp --target rp .
```

Build the rosenpass image from the root of the repostiry with the following command:

```
docker build -f .docker/Dockerfile -t ghcr.io/rosenpass/rosenpass --target rosenpass .
```
