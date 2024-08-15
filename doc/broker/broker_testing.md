## Experimental Broker Feature Testing

In order to test the experimental broker feature, a few manual steps are needed. These will soon be replaced with a revision to the integration test to allow it to optionally use the broker feature, but for the moment manual testing is the only option.

To manually test the broker feature, start by building Rosenpass with the broker feature:

```bash
cd rosenpass
cargo build --features=experimental_broker_api
```

Next, generate keys for two parties using the example Rosenpass configuration files

```bash
PATH="$PWD/target/debug:$PATH" rosenpass gen-keys config-examples/peer-a-config.toml
PATH="$PWD/target/debug:$PATH" rosenpass gen-keys config-examples/peer-b-config.toml
```

Now, open a second terminal and run the following in one (not using the broker):

```bash
PATH="$PWD/target/debug:$PATH" rosenpass exchange-config config-examples/peer-a-config.toml
```

and the following in the other (spawning a broker and communicating with it via socketpair(2)):

```bash
cd rosenpass
PATH="$PWD/target/debug:$PATH" rosenpass --psk_broker_spawn exchange-config config-examples/peer-a-config.toml
```

You should see the two parties exchange keys, and can view the shared PSK via `wg show`.

In order to test using a Unix socket at a provided path instead, replace the above command with this:

```bash
PATH="$PWD/target/debug:$PATH" rosenpass --psk_broker_path broker.sock exchange-config config-examples/peer-a-config.toml
```

Then, in a third terminal, run the following

```bash
cd rosenpass
PATH="$PWD/target/debug:$PATH" rosenpass-wireguard-broker-socket-handler --listen-path broker.sock
```

You should see the two parties exchange keys.

The `--psk_broker_fd` feature can be similarly tested, but would require a separate script providing an open file descriptor to do so.
