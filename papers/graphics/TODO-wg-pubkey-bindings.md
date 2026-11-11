# Figure updates for the protocol context / WireGuard public key binding

This document describes which figures need an update due to the WireGuard pubkey binding. It first gives some background information (particularly interesting for a cryptographer) and then describes which figures need changes.

## Background (what has changed from a cryptographer's view?)

The following changes have been made to the protocol and are already mentioned in the whitepaper's text. They now need to be reflected in the graphics.

### General Protocol Change

We rename the current psk field from "pre shared key" to "context". We call this field the "protocol context".

`psk` -> `ctx`

We use the following definitions; all of these apply to the hash chain/hash tree protocol model:

```
# The protocol context is fully defined by the protocol
# The special "output" variable compresses the protocol context into one token
ctx  = lhash("context", "protocol context", "output", ctxc, ctxi, ctxr)

# These three protocol context variables are used to define the overall protocol context (labeled "output" above)
ctxc = lhash("context", "protocol context", "common"   , psk , adc)
ctxi = lhash("context", "protocol context", "initiator", spki, adi)
ctxr = lhash("context", "protocol context", "responder", spkr, adr)

# The additional data is thought of as user-specific
adc = lhash("context", "additional data", "user", "common",    uadc…)
adi = lhash("context", "additional data", "user", "initiator", uadi…)
adr = lhash("context", "additional data", "user", "responder", uadr…)

# Inputs actually given by the user
uadc : [[u8]] # User specified common additional data
uadi : [[u8]] # User specified initiator additional data
uadr : [[u8]] # User specified responder additional data
psk  : [u8;32] # the PSK specified by the user just like before the change
```

`uadc`/`uadi`/`uadr` are currently empty data and may later be read from a config file.

### Protocol Change Around The WireGuard Protocol Extension

For use with WireGuard we modify the following fields in the following way:

```
adc = lhash("context", "additional data", "user", "common",    "rosenpass.eu", "wireguard psk", uadc…)
adi = lhash("context", "additional data", "user", "initiator", "rosenpass.eu", "wireguard psk", wg_spki, uadi…)
adr = lhash("context", "additional data", "user", "responder", "rosenpass.eu", "wireguard psk", wg_spkr, uadr…)
```

## Figures To Update

Two whitepaper figures need to be updated to reflect this change.

### Fig. 3: Rosenpass Hashing Tree

The hashing tree needs three changes.

Additional notes / hints for tasks 2+3:

- `wg_spki`, `wg_spkr`, `uadc`, `uadi`, `uadr` are input variables.
- the outputs `ctxc`, `ctxi`, `ctxr` are fed back into the chain which outputs `ctx` – could require an arrow that moves from the right to the left and looks a bit strange(?)

#### Task 1

In the `InitHello` column, almost at the bottom: rename `psk` to `ctx`.

#### Task 2

In the `Global Domains` columns, almost at the top: add a new label `"context"` between `PROTOCOL` and `"mac"`. Also, expand it to the following tree:

- `"context"`
  - `"protocol context"`
    - `"common"`, `psk`, `adc` → `ctxc`
    - `"initiator"`, `spki`, `adi` → `ctxi`
    - `"responder"`, `spkr`, `adr` → `ctxr`
    - `"output"`, `ctxc`, `ctxi`, `ctxr` → `ctx`
  - `"additional data"`
    - `"user"`
      - `"common"`
        - `uadc` → `adc`
        - `uadi` → `adi`
        - `uadr` → `adr`

#### Task 3

We also need to mention that **only in the Wireguard protocol extension** the part _after_ `"additional data"` changes like this:

- `"context"`
  - `"additional data"`
    - `"user"`
      - `"common"`, `"rosenpass.eu"`, `"wireguard psk"`, `uadc` → `adc`
      - `"initiator"`, `"rosenpass.eu"`, `"wireguard psk"`, `wg_spki`, `uadi` → `adi`
      - `"responder"`, `"rosenpass.eu"`, `"wireguard psk"`, `wg_spkr`, `uadr` → `adr`

This means, that the variant after `"additional data"` in the WireGuard extension is _not_ compatible with the variant without the WireGuard extension.

I have a feeling that Fig. 3 does not have enough space left for that so we should move it to the extension section and into its own figure(?)

### Fig. 4: Rosenpass Message Handling Code

The `InitHello` part needs these changes:

1. initiator step IHI7: rename `psk` to `ctx`
2. responder step IHR6: rename `psk` to `ctx`
3. responder step IHR7:
   1. in the code: rename `psk` to `ctx`
   2. in the description: rename `PSK` to `the protocol context`
   3. in the description: remove `as optional` (ctx is no longer optional)
