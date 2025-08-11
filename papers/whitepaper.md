---
template: rosenpass
title: Rosenpass
author:
- Karolin Varner = Rosenpass e.V., Max Planck Institute for Security and Privacy (MPI-SP)
- Benjamin Lipp = Rosenpass e.V., Max Planck Institute for Security and Privacy (MPI-SP)
- Wanja Zaeske
- Lisa Schmidt = {Scientific Illustrator – \\url{mullana.de}}
- Prabhpreet Dua
abstract: |
       Rosenpass is a post-quantum-secure authenticated key exchange protocol. Its main practical use case is creating post-quantum-secure VPNs by combining WireGuard and Rosenpass.

       In this combination, Rosenpass generates a post-quantum-secure shared key every two minutes that is then used by WireGuard (WG) [@wg] to establish a secure connection. Rosenpass can also be used without WireGuard, providing post-quantum-secure symmetric keys for other applications, as long as the other application accepts a pre-shared key and provides cryptographic security based on the pre-shared key alone.

       The Rosenpass protocol builds on “Post-quantum WireGuard” (PQWG) [@pqwg] and improves it by using a cookie mechanism to provide security against state disruption attacks. From a cryptographic perspective, Rosenpass can be thought of as a post-quantum secure variant of the Noise IK[@noise] key exchange. \say{Noise IK} means that the protocol makes both parties authenticate themselves, but that the initiator knows before the protocol starts which other party they are communicating with. There is no negotiation step where the responder communicates their identity to the initiator.

       The Rosenpass project consists of a protocol description, an implementation written in Rust, and a symbolic analysis of the protocol’s security using ProVerif [@proverif]. We are working on a cryptographic security proof using CryptoVerif [@cryptoverif].

       This document is a guide for engineers and researchers implementing the protocol.
---

\enlargethispage{5mm}
\setupimage{label=img:KeyExchangeProt,width=.9\linewidth}
![Rosenpass Key Exchange Protocol](graphics/rosenpass-wp-key-exchange-protocol-rgb.svg)

\setupimage{label=img:MessageTypes}
![Rosenpass Message Types](graphics/rosenpass-wp-message-types-rgb.svg)

\clearpage

\addtocontents{toc}{\string\setcounter{tocdepth}{\string\sectionnumdepth}}
\setcounter{secnumdepth}{\sectionnumdepth}

# Security

Rosenpass inherits most security properties from Post-Quantum WireGuard (PQWG). The security properties mentioned here are covered by the symbolic analysis in the Rosenpass repository.

## Secrecy
Three key encapsulations using the keypairs `sski`/`spki`, `sskr`/`spkr`, and `eski`/`epki` provide secrecy (see Section \ref{variables} for an introduction of the variables). Their respective ciphertexts are called `scti`, `sctr`, and `ectr` and the resulting keys are called `spti`, `sptr`, `epti`. A single secure encapsulation is sufficient to provide secrecy. We use two different KEMs (Key Encapsulation Mechanisms; see Section \ref{skem}): Kyber and Classic McEliece.

## Authenticity

The key encapsulation using the keypair `sskr`/`spkr` authenticates the responder from the perspective of the initiator. The KEM encapsulation `sski`/`spki` authenticates the initiator from the perspective of the responder. Authenticity is based on the security of Classic McEliece alone.

## Secrecy and Authenticity based on a Pre-Shared Symmetric Key

We allow the use of a pre-shared key (`psk`) as protocol input. Even if all asymmetric security primitives turn out to be insecure, providing a secure `psk` will have Rosenpass authenticate both peers, and output a secure shared key.

## Forward Secrecy

Forward secrecy refers to secrecy of past sessions in case all static keys are leaked. Imagine an attacker recording the network messages sent between two devices, developing an interest in some particular exchange,  and stealing both computers in an attempt to decrypt that conversation. By stealing the hardware, the attacker gains access to `sski`, `sskr`, and the symmetric secret `psk`. Since the ephemeral keypair `eski`/`epki` is generated on the fly and deleted after the execution of the protocol, it cannot be recovered by stealing the devices, and thus, Rosenpass provides forward secrecy. Forward secrecy relies on the security of Kyber and on proper zeroization, i.e., the implementation must erase all temporary variables.

## Security against State Disruption Attacks {#statedis}

Both WG and PQWG are vulnerable to state disruption attacks; they rely on a timestamp to protect against replay of the first protocol message. An attacker who can tamper with the local time of the protocol initiator can inhibit future handshakes [@statedis], rendering the initiator’s static keypair practically useless. Due to the use of the insecure NTP protocol, real-world deployments are vulnerable to this attack [@statedis_cve]. Lacking a reliable way to detect retransmission, we remove the replay protection mechanism and store the responder state in an encrypted cookie called “the biscuit” instead. Since the responder does not store any session-dependent state until the initiator is interactively authenticated, there is no state to disrupt in an attack.

Note that while Rosenpass is secure against state disruption, using it does not protect WireGuard against the attack. Therefore, the hybrid Rosenpass/WireGuard setup recommended for deployment is still vulnerable.

\addtocontents{toc}{\string\setcounter{tocdepth}{\string\subsectionnumdepth}}
\setcounter{secnumdepth}{\subsubsectionnumdepth}

# Protocol Description

## Cryptographic Building Blocks

All symmetric keys and hash values used in Rosenpass are 32 bytes long.


### Hash {#hash}

A keyed hash function with one 32-byte input, one variable-size input, and one 32-byte output. As keyed hash function we offer two options that can be configured on a peer-basis, with Blake2s being the default:

1. the HMAC construction [@rfc_hmac] with BLAKE2s [@rfc_blake2] as the inner hash function.
2. the SHAKE256 extendable output function (XOF) [@SHAKE256] truncated to a 32-byte output. The result is produced be concatenating the 32-byte input with the variable-size input in this order.

```pseudorust
hash(key, data) -> key
```

### AEAD

Authenticated encryption with additional data for use with sequential nonces. We use ChaCha20Poly1305 [@rfc_chachapoly] in the implementation.

```pseudorust
AEAD::enc(key, nonce, plaintext, additional_data) -> ciphertext
AEAD::dec(key, nonce, ciphertext, additional_data) -> plaintext
```

### XAEAD

Authenticated encryption with additional data for use with random nonces. We use XChaCha20Poly1305 [@draft_xchachapoly] in the implementation, a construction also used by WireGuard.


```pseudorust
XAEAD::enc(key, nonce, plaintext, additional_data) -> ciphertext
XAEAD::dec(key, nonce, ciphertext, additional_data) -> plaintext
```

### SKEM {#skem}

“Key Encapsulation Mechanism” (KEM) is the name of an interface widely used in post-quantum-secure protocols. KEMs can be seen as asymmetric encryption specifically for symmetric keys. Rosenpass uses two different KEMs. SKEM is the key encapsulation mechanism used with the static keypairs in Rosenpass. The public keys of these keypairs are not transmitted over the wire during the protocol. We use Classic McEliece 460896 [@mceliece] which claims to be as hard to break as 192-bit AES. As one of the oldest post-quantum-secure KEMs, it enjoys wide trust among cryptographers, but it has not been chosen for standardization by NIST. Its ciphertexts and private keys are small (188 bytes and 13568 bytes), and its public keys are large (524160 bytes). This fits our use case: public keys are exchanged out-of-band, and only the small ciphertexts have to be transmitted during the handshake.

```pseudorust
SKEM::enc(public_key) -> (ciphertext, shared_key)
SKEM::dec(secret_key, ciphertext) -> shared_key
```

### EKEM

Key encapsulation mechanism used with the ephemeral KEM keypairs in Rosenpass. The public keys of these keypairs need to be transmitted over the wire during the protocol. We use Kyber-512 [@kyber], which has been selected in the NIST post-quantum cryptography competition and claims to be as hard to break as 128-bit AES. Its ciphertexts, public keys, and private keys are 768, 800, and 1632 bytes long, respectively, providing a good balance for our use case as both a public key and a ciphertext have to be transmitted during the handshake.

```pseudorust
EKEM::enc(public_key) -> (ciphertext, shared_key)
EKEM::dec(secret_key, ciphertext) -> shared_key
```

Using a combination of two KEMs – Classic McEliece for static keys and Kyber for ephemeral keys – results in large static public keys, but allows us to fit all network messages into a single IPv6 frame.

Rosenpass uses libsodium [@libsodium] as cryptographic backend for hash, AEAD, and XAEAD, and liboqs [@liboqs] for the post-quantum-secure KEMs.

## Protocol Roles {#roles}

The protocol specifies two roles: initiator and responder.

* initiator – The party that starts a handshake.
* responder – The party that does not start a handshake.

There is no particular mechanism to negotiate which party acts in which role; just like the WireGuard protocol, the Rosenpass protocol uses no distinction between client and server. In this vein, the initiator is not the protocol client; instead, the initiator is whichever party happened to start the key exchange.

Implementations should be careful to ensure that having two ongoing key exchanges—one in the initiator role and one in the responder role—does not lead to implementation bugs.

## Packages {#packages}

The packages, their contents, and their type IDs are graphically represented in Fig. \ref{img:MessageTypes}. Their purposes are:

* \textbf{Envelope} – This is not a package on its own; it is the envelope all the other packages are put into.
* \textbf{InitHello} – First package of the handshake, from initiator to responder.
* \textbf{RespHello} – Second package of the handshake, from responder to initiator.
* \textbf{InitConf} – Third package of the handshake, from initiator to responder.
* \textbf{EmptyData} – Empty payload package. Used as acknowledgment to abort data retransmission (see Secs. \ref{payload-keys}, \ref{packet-loss}, and function `enter_live()` in Sec. \ref{fn:enter_live}).
* \textbf{Data} – Transmission of actual payload data is not used in Rosenpass, but the package is still specified since it is part of WireGuard (see Sec. \ref{payload-keys} and function `enter_live()` in Sec. \ref{fn:enter_live}).
* \textbf{CookieReply} – Used for proof-of-IP-ownership-based denial-of-service mitigation (see Sec. \ref{dos-mitigation}).
* \textbf{biscuit} – This is not a stand-alone package; instead, it is an encrypted fragment present in \textbf{RespHello} and \textbf{InitConf}.

## Endianness {#endianess}

Unless otherwise specified, all integer values in the Rosenpass protocol use little-endian encoding.

## Variables and Domain Separators {#variables}

### KEM Keypairs and Ciphertexts

Rosenpass uses multiple keypairs, ciphertexts, and plaintexts for key encapsulation: a static keypair for each peer, and an ephemeral keypair on the initiator's side. We use a common naming scheme to refer to these variables:

\begin{namepartpicture}
\namepart{s=Static,e=Ephemeral}
\namepart[3.5cm]{sk=Secret Key,pk=Public Key,pt=Plaintext,ct=Ciphertext}
\namepart[7cm]{i=Initiator,r=Responder,m=Mine,t=Theirs}
\begin{scope}[decoration={brace,amplitude=5mm},thick]
\namebraceright{s}{e}
\namebraceleft{sk}{ct}
\namebraceright{sk}{ct}
\namebraceleft{i}{t}
\end{scope}
\end{namepartpicture}

These values use a naming scheme consisting of four lower-case characters. The first character indicates whether the key is static `s` or ephemeral `e`. The second character is an `s` or a `p` for secret or public. The third character is always a `k`. The fourth and final character is an `i`, `r`, `m`, or `t`, for `initiator`, `responder`, `mine`, or `theirs`. The initiator's static public key for instance is `spki`. During execution of the protocol, three KEM ciphertexts are produced: `scti`, `sctr`, and `ecti`.

Besides the initiator and responder roles, we define the roles `mine` and `theirs` (`m`/`t`). These are sometimes used in the code when the assignment to initiator or responder roles is flexible. As an example, “this server's” static secret key is `sskm`, and the peer's public key is `spkt`.


### IDs {#peer-ids}

Rosenpass uses two types of ID variables. See Figure \ref{img:HashingTree} for how the IDs are calculated.

\begin{namepartpicture}
\namepart{sid=Session ID, pid=Peer ID}
\namepart[3.5cm]{i=Initiator,r=Responder,m=Mine,t=Theirs}
\begin{scope}[decoration={brace,amplitude=5mm},thick]
\namebraceright{sid}{pid}
\namebraceleft{i}{t}
\end{scope}
\end{namepartpicture}

The first lower-case character indicates whether the variable is a session ID (`sid`) or a peer ID (`pid`). The final character indicates the role using the characters `i`, `r`, `m`, or `t`, for `initiator`, `responder`, `mine`, or `theirs` respectively.

### Symmetric Keys {#symmetric-keys}

Rosenpass uses two main symmetric key variables `psk` and `osk` in its interface, and maintains the entire handshake state in a variable called the chaining key.

* `psk`: A pre-shared key that can be optionally supplied as input to Rosenpass.
* `osk`: The output shared key, generated by Rosenpass. The main use case is to supply the key to WireGuard for use as its pre-shared key.
* `ck`: The chaining key. This refers to various intermediate keys produced during the execution of the protocol, before the final `osk` is produced.

We mix all key material (e.g. `psk`) into the chaining key and derive symmetric keys such as `osk` from it. We authenticate public values by mixing them into the chaining key; in particular, we include the entire protocol transcript in the chaining key, i.e., all values transmitted over the network.

The protocol allows for multiple `osk`s to be generated; each of these keys is labeled with a domain separator to make sure different key usages are always given separate keys. The domain separator for using Rosenpass and WireGuard together is a token generated using the domain separator sequence `["rosenpass.eu", "wireguard psk"]` (see Fig. \ref{img:HashingTree}), as described in \ref{protocol-extension-wireguard-psk}. Third-parties using Rosenpass-keys for other purposes are asked to define their own protocol-extensions. Standard protocol extensions are described in \ref{protocol-extensions}.

#### Symmetric Keys and Nonces for payload data transmission {#payload-keys}

Keys generated by the Rosenpass key exchange could be used for encryption of payload data if post-quantum security but not hybrid post-quantum security is a goal. Despite this, we do not generally offer payload transmission in the protocol. Instead, the Rosenpass protocol focuses on providing a key exchange, letting external applications handle data transmission. When used with WireGuard, the default use case, this integration also ensures hybrid security.

Still we specify the `Data` and `EmptyData` packets. `Data` is not used, but we still specify it as the same packet is also present in WireGuard. `EmptyData` is used for packet retransmission (see Sec. \ref{packet-loss}).

We also specify how symmetric keys are generated for payload encryption. See Sec. {#live-session-state} and the function `enter_live()` (Sec. \ref{fn:enter_live}).

Keys and nonces for this purpose use the following naming scheme:

\begin{namepartpicture}
\namepart{tx=Transmission,rx=Reception}
\namepart[3.5cm]{k=Key,n=Nonce}
\namepart[7cm]{i=Initiator,r=Responder,m=Mine,t=Theirs}
\begin{scope}[decoration={brace,amplitude=5mm},thick]
\namebraceright{tx}{rx}
\namebraceleft{k}{n}
\namebraceright{k}{n}
\namebraceleft{i}{t}
\end{scope}
\end{namepartpicture}

Note that this scheme is deliberately redundant. For instance, when we are the initiator, then `txki = rxki = txkm = rxkt`. I.e. the initiator's transmission key is the responder's reception key. Since we are the initiator, the initiator's transmission key is also the transmission key of `mine` and the reception key of `theirs`.

There also is a -- now deprecated -- naming scheme:

\begin{namepartpicture}
\namepart{ini=Initiator,res=Responder,hs=Handshake}
\SingleNamePart[3.5cm]{enc}{\textunderscore{}enc}{Encryption}
\begin{scope}[decoration={brace,amplitude=5mm},thick]
\namebraceright{ini}{hs}
\namebraceleft{enc}{enc}
\end{scope}
\end{namepartpicture}

`ini_enc = txki = rxkr` and `res_enc = txkr = rxki`, but this usage is deprecated. The third name `hs_enc` is for encryption as part of the key exchange itself; this name is still in use.

### Labels

Fig. \ref{img:HashingTree} specifies multiple domain separators for various uses.

* `PROTOCOL` (`[0, PROTOCOL]`) – The global domain separator; used to generate more domain separators.

Immediately below the global domain separator, you can find:

* `"mac"` – Network package integrity verification and pre-authentication with `spkt`. See Sec. \ref{envelope-mac-field}.
* `"cookie"` – Denial of Service mitigation through proof-of-ip ownership. See Sec. \ref{dos-mitigation}.
* `"peer id"` – Generation of peer ids. See Sec. \ref{peer-ids}.
* `"biscuit additional data"` – Storing the protocol state in encrypted cookies so the responder is stateless. See Sec. \ref{hs-state-and-biscuits}.
* `"chaining key init"` – Starting point for the execution of the actual rosenpass protocol.
* `"chaining key extract"` – Key derivation from the current protocol state, the chaining key. See Sec. \ref{symmetric-keys}.

Below `"chaining key extract"`, there are multiple labels, generating domain separators for deriving keys for various purposes during the execution of the protocol.

It is important to understand that there are two phases for these labels, e.g. applying the `"mix"` label produces a random fixed-size hash value we call `mix`. Not the label `"mix"` but the resulting hash value is used to derive keys during protocol execution. This allows us to use very complicated label structures for key derivation without losing efficiency.

The different labels are:

* `"mix"` – Mixing further values into the chaining key; i.e. into the protocol state.
* `"user"` – Labels for external uses; these are what generate the `osk` (output shared key). See Sec. \ref{symmetric-keys}.
* `"handshake encryption"` – Used when encrypting data using a shared key as part of the protocol execution; e.g. used to generate the `auth` (authentication tag) fields in protocol packages.
* `"initiator handshake encryption"` and `"responder handshake encryption"` – For transmission of data after the key-exchange finishes. See Sec. \ref{symmetric-keys}.

## Hashes

Rosenpass uses a cryptographic hash function for multiple purposes:

* Computing the message authentication code in the message envelope as in WireGuard
* Computing the cookie to guard against denial of service attacks. This is a feature adopted from WireGuard, but not yet included in the implementation of Rosenpass.
* Computing the peer ID
* Key derivation during and after the handshake
* Computing the additional data for the biscuit encryption, to provide some privacy for its contents

Recall from Section \ref{hash} that rosenpass supports using either BLAKE2s or SHAKE256 as hash function, which can be configured for each peer ID. However, as noted above, rosenpass uses a hash function to compute the peer ID and thus also to access the configuration for a peer ID. This is an issue when receiving an `InitHello`-message, because the correct hash function is not known when a responder receives this message and at the same the responders needs it in order to compute the peer ID and by that also identfy the hash function for that peer. The reference implementation resolves this issue by first trying to derive the peer ID using SHAKE256. If that does not work (i.e. leads to an AEAD decryption error), the reference implementation tries again with BLAKE2s. The reference implementation verifies that the hash function matches the one confgured for the peer. Similarly, if the correct peer ID is not cached when receiving an InitConf message, the reference implementation proceeds in the same manner.

Using one hash function for multiple purposes can cause real-world security issues and even key recovery attacks [@oraclecloning]. We choose a tree-based domain separation scheme based on a keyed hash function – the previously introduced primitive `hash` – to make sure all our hash function calls can be seen as distinct.

\setupimage{landscape,fullpage,label=img:HashingTree}
![Rosenpass Hashing Tree](graphics/rosenpass-wp-hashing-tree-rgb.svg)

Each tree node $\circ{}$ in Figure \ref{img:HashingTree} represents the application of the keyed hash function, using the previous chaining key value as first parameter. The root of the tree is the zero key. In level one, the `PROTOCOL` identifier is applied to the zero key to generate a label unique across cryptographic protocols (unless the same label is deliberately used elsewhere). In level two, purpose identifiers are applied to the protocol label to generate labels to use with each separate hash function application within the Rosenpass protocol. The following layers contain the inputs used in each separate usage of the hash function: Beneath the identifiers `"mac"`, `"cookie"`, `"peer id"`, and `"biscuit additional data"` are hash functions or message authentication codes with a small number of inputs. The second, third, and fourth column in Figure \ref{img:HashingTree} cover the long sequential branch beneath the identifier `"chaining key init"` representing the entire protocol execution, one column for each message processed during the handshake. The leaves beneath `"chaining key extract"` in the left column represent pseudo-random labels for use when extracting values from the chaining key during the protocol execution. These values such as `mix >` appear as outputs in the left column, and then as inputs `< mix` in the other three columns.

The protocol identifier depends on the hash function used with the respective peer is defined as follows if BLAKE2s [@rfc_blake2] is used:

```pseudorust
PROTOCOL = "rosenpass 1 rosenpass.eu aead=chachapoly1305 hash=blake2s ekem=kyber512 skem=mceliece460896 xaead=xchachapoly1305"
```

If SHAKE256 [@SHAKE256] is used, `blake2s` is replaced by `shake256` in `PROTOCOL`. Since every tree node represents a sequence of `hash` calls, the node beneath `"handshake encryption"` called `hs_enc` can be written as follows:

```pseudorust
hs_enc = hash(hash(hash(0, PROTOCOL), "chaining key extract"), "handshake encryption")
```

First, the protocol identifier `PROTOCOL` is applied, then the purpose identifier `"chaining key extract"` is applied to the protocol label, and finally `"handshake encryption"` is applied to the purpose label.

To simplify notation of these long nested calls to hash, we allow use of the `hash` function with variadic parameters and introduce the shorthand `lhash` to wrap the usage of the `hash(0, PROTOCOL)` value:

```pseudorust
hash(a, b, c…) = hash(hash(a, b), c…)
lhash(a…) = hash(hash(0, PROTOCOL), a…)
```

The notation `x…` denotes expansion of one or more parameters.
This gives us two alternative ways to denote the value of the `hs_enc` node:

```pseudorust
hs_enc = hash(hash(hash(0, PROTOCOL), "chaining key extract"), "handshake encryption")
       = hash(0, PROTOCOL, "chaining key extract", "handshake encryption")
       = lhash("chaining key extract", "handshake encryption")
```

## Server State

### Global

The server needs to store the following variables:

* `sskm`
* `spkm`
* `biscuit_key` – Randomly chosen key used to encrypt biscuits
* `biscuit_ctr` – Retransmission protection for biscuits
* `cookie_secret`- A randomized cookie secret to derive cookies sent to peer when under load. This secret changes every 120 seconds

Not mandated per se, but required in practice:

* `peers` – A lookup table mapping the peer ID to the internal peer structure
* `index` – A lookup table mapping the session ID to the ongoing initiator handshake or live session

### Peer

For each peer, the server stores:

* `psk` – The pre-shared key used with the peer
* `spkt` – The peer's public key
* `biscuit_used` – The `biscuit_no` from the last biscuit accepted for the peer as part of InitConf processing
* `hash_function` – The hash function, SHAKE256 or BLAKE2s, used with the peer.

### Handshake State and Biscuits {#hs-state-and-biscuits}

The initiator stores the following local state for each ongoing handshake:

* A reference to the peer structure
* A state indicator to keep track of the next message expected from the responder
* `sidi` – Initiator session ID
* `sidr` – Responder session ID
* `ck` – The chaining key
* `eski` – The initiator's ephemeral secret key
* `epki` – The initiator's ephemeral public key
* `cookie_value`- Cookie value sent by an initiator peer under load, used to compute cookie field in outgoing handshake to peer under load. This value expires 120 seconds from when a peer sends this value using the CookieReply message

The responder stores no state. While the responder has access to all of the above variables except for `eski`, the responder discards them after generating the RespHello message. Instead, the responder state is contained inside a cookie called a biscuit. This value is returned to the responder inside the InitConf packet. The biscuit consists of:

* `pidi` – The initiator's peer ID
* `biscuit_no` – The biscuit number, derived from the server's `biscuit_ctr`; used for retransmission detection of biscuits
* `ck` – The chaining key

The biscuit is encrypted with the `XAEAD` primitive and a randomly chosen nonce. The values `sidi` and `sidr` are transmitted publicly as part of InitConf, so they do not need to be present in the biscuit, but they are added to the biscuit's additional data to make sure the correct values are transmitted as part of InitConf.

The `biscuit_key` used to encrypt biscuits should be rotated every two minutes. Implementations should keep two biscuit keys in memory at any given time to avoid having to drop packages when `biscuit_key` is rotated.

### Live Session State {#live-session-state}

These variables are used after the handshake terminates for encryption of the \textbf{Data} and \textbf{EmptyData} packages.
\textbf{EmptyData} is used as an acknowledgement package to terminate package retransmission (see Sec. \ref{packet-loss}).
\textbf{Data} would be used for transmission of actual payload, but this feature is currently not specified for Rosenpass. Despite this, we do specify the however as it is also part of WireGuard.

* `ck` – The chaining key
* `sidm` – Our session ID (“mine”)
* `txkm` – Our transmission key
* `txnm` – Our transmission nonce
* `sidt` – Peer's session ID (“theirs”)
* `txkt` – Peer's transmission key
* `txnt` – Peer's transmission nonce

## Helper Functions {#functions}

Given the peer ID, look up the peer and load the peer's variables.

```pseudorust
fn lookup_peer(pid);
```

Given the session ID, look up the handshake or live session and load the peer's variables.

```pseudorust
fn lookup_session(sid);
```

The protocol framework used by Rosenpass allows arbitrarily many different keys to be extracted using labels for each key. The `extract_key` function is used to derive protocol-internal keys, its labels are under the “chaining key extract” node in Figure \ref{img:HashingTree}. The export key function is used to export application keys.

Third-party applications using the protocol are supposed to define a protocol extension (see \ref{protocol-extensions}) and choose a globally unique label, such as their domain name for custom labels of their own. The Rosenpass project itself uses the `["rosenpass.eu"]` namespace in the WireGuard PSK protocol extension (see \ref{protocol-extension-wireguard-psk}).

Applications can cache or statically compile the pseudo-random label values into their binary to improve performance.

```pseudorust
fn extract_key(l…) {
    hash(ck, lhash("chaining key extract", l…))
}

fn export_key(l…) {
    extract_key("user", l…)
}
```

A helper function is used to mix secrets and public values into the handshake state. A variadic variant can be used as a short hand for multiple calls `mix(a, b, c) = mix(a); mix(b); mix(c)`.

```pseudorust
fn mix(d) {
    ck ← hash(extract_key("mix"), d)
}

fn mix(d, rest…) {
    mix(d)
    mix(rest…)
}
```

A helper function provides encrypted transmission of data based on the current chaining key during the handshake. The function is also used to create an authentication tag to certify that both peers share the same chaining key value.

```pseudorust
fn encrypt_and_mix(pt) {
    let k = extract_key("handshake encryption");
    let n = 0;
    let ad = empty();
    let ct = AEAD::enc(k, n, pt, ad)
    mix(ct);
    ct
}

fn decrypt_and_mix(ct) {
    let k = extract_key("handshake encryption");
    let n = 0;
    let ad = empty();
    let pt = AEAD::dec(k, n, ct, ad)
    mix(ct);
    pt
}
```

Rosenpass is built with KEMs, not with NIKEs (Diffie-Hellman-style operations); the encaps/decaps helpers can be used both with the SKEM as well as with the EKEM.

```pseudorust
fn encaps_and_mix<T: KEM>(pk) {
    let (ct, shk) = T::enc(pk);
    mix(pk, ct, shk);
    ct
}

fn decaps_and_mix<T: KEM>(sk, pk, ct) {
    let shk = T::dec(sk, ct);
    mix(pk, ct, shk);
}
```

The biscuit store/load functions have to deal with the `biscuit_ctr`\slash`biscuit_used`\slash`biscuit_no` variables as a means to enable replay protection for biscuits. The peer ID `pidi` is added to the biscuit and used while loading the biscuit to find the peer data. The values `sidi` and `sidr` are added to the additional data to make sure they are not tampered with.
\enlargethispage{.5\baselineskip}

```pseudorust
fn store_biscuit() {
    biscuit_ctr ← biscuit_ctr + 1;

    let k = biscuit_key;
    let n = random_nonce();
    let pt = Biscuit {
      pidi: lhash("peer id", spki),
      biscuit_no: biscuit_ctr,
      ck: ck,
    };
    let ad = lhash(
      "biscuit additional data",
      spkr, sidi, sidr);
    let ct = XAEAD::enc(k, n, pt, ad);
    let nct = concat(n, ct);

    mix(nct)
    nct
}
```
Note that the `mix(nct)` call updates the chaining key, but that update does not make it into the biscuit. Therefore, `mix(nct)` is reapplied in `load_biscuit`. The responder handshake code also needs to reapply any other operations modifying `ck` after calling `store_biscuit`. The handshake code on the initiator's side also needs to call `mix(nct)`.


```pseudorust
fn load_biscuit(nct) {
    // Decrypt the biscuit
    let k = biscuit_key;
    let (n, ct) = nct;
    let ad = lhash(
      "biscuit additional data",
      spkr, sidi, sidr);
    let pt : Biscuit = XAEAD::dec(k, n, ct, ad);

    // Find the peer and apply retransmission protection
    lookup_peer(pt.peerid);

    // In December 2024, the InitConf retransmission mechanisim was redesigned
    // in a backwards-compatible way. See the changelog.
    //
    // -- 2024-11-30, Karolin Varner
    if (protocol_version!(< "0.3.0")) {
        // Ensure that the biscuit is used only once
        assert(pt.biscuit_no >= peer.biscuit_used);
    }

    // Restore the chaining key
    ck ← pt.ck;
    mix(nct);

    // Expose the biscuit no,
    // so the handshake code can differentiate
    // retransmission requests and first time handshake completion
    pt.biscuit_no
}
```

\phantomsection\label{fn:enter_live}

Entering the live session is very simple in Rosenpass – we just use `extract_key` with dedicated identifiers to derive initiator and responder keys.

```pseudorust
fn enter_live() {
    txki ← extract_key("initiator payload encryption");
    txkr ← extract_key("responder payload encryption");
    txnm ← 0;
    txnt ← 0;

    // Setup output keys for protocol extensions such as the
    // WireGuard PSK protocol extension.
    setup_osks();
}
```

The final step `setup_osks()` can be defined by protocol extensions (see \ref{protocol-extensions}) to set up `osk`s for custom use cases. By default, the WireGuard PSK (see \ref{protocol-extension-wireguard-psk}) is active.

```pseudorust
fn setup_osks() {
    ... // Defined by protocol extensions
}
```

## Message Encoding and Decoding

The steps to actually execute the handshake are given in Figure \ref{img:HandlingCode}. This figure contains the initiator code and the responder code; instructions corresponding to each other are shown side by side. We use the following numbering scheme for instructions:

\begin{namepartpicture}
\namepart{IH=InitHello,RH=RespHello,IC=InitConf}
\namepart[3.5cm]{I=Initiator,R=Responder}
\SingleNamePart[7cm]{N}{[0-9]}{Number}
\begin{scope}[decoration={brace,amplitude=5mm},thick]
\namebraceright{IH}{IC}
\namebraceleft{I}{R}
\namebraceright{I}{R}
\draw[decorate,decoration={amplitude=3mm}]([xshift=-7mm]N.south west)--([xshift=-7mm]N.north west) ;
\end{scope}
\end{namepartpicture}

All steps have side effects (as specified in the function definitions). In general, they perform some cryptographic operation and mix the parameters and the result into the chaining key.

The responder code handling InitConf needs to deal with the biscuits and package retransmission. Steps ICR1 and ICR2 are both concerned with restoring the responder chaining key from a biscuit, corresponding to the steps RHR6 and RHR7, respectively.

ICR5 and ICR6 perform biscuit replay protection using the biscuit number. This is not handled in `load_biscuit()` itself because there is the case that `biscuit_no = biscuit_used` which needs to be dealt with for retransmission handling.

### Denial of Service Mitigation and Cookies {#dos-mitigation}

Rosenpass derives its cookie-based DoS mitigation technique for a responder when receiving InitHello messages from Wireguard [@wg].

When the responder is under load, it may choose to not process further InitHello handshake messages, but instead to respond with a cookie reply message (see Figure \ref{img:MessageTypes}).

The sender of the exchange then uses this cookie in order to resend the message and have it accepted the following time by the reciever.

For an initiator, Rosenpass ignores all messages when under load.

#### Cookie Reply Message

The cookie reply message is sent by the responder on receiving an InitHello message when under load. It consists of the `sidi` of the initiator, a random 24-byte bitstring `nonce` and encrypting `cookie_value` into a `cookie_encrypted` reply field, which consists of the following:

```pseudorust
cookie_value = lhash("cookie-value", cookie_secret, initiator_host_info)[0..16]
cookie_encrypted = XAEAD(lhash("cookie-key", spkm), nonce, cookie_value, mac_peer)
```

where `cookie_secret` is a secret variable that changes every two minutes to a random value. Moreover, `lhash` is always instantiated with SHAKE256 when computing `cookie_value` for compatability reasons.  `initiator_host_info` is used to identify the initiator host, and is implementation-specific for the client. This paramaters used to identify the host must be carefully chosen to ensure there is a unique mapping, especially when using IPv4 and IPv6 addresses to identify the host (such as taking care of IPv6 link-local addresses). `cookie_value` is a truncated 16 byte value from the above hash operation. `mac_peer` is the `mac` field of the peer's handshake message to which message is the reply.

#### Envelope `mac` Field {#envelope-mac-field}

Similar to `mac.1` in Wireguard handshake messages, the `mac` field of a Rosenpass envelope from a handshake packet sender's point of view consists of the following:

```pseudorust
mac = lhash("mac", spkt, MAC_WIRE_DATA)[0..16]
```

where `MAC_WIRE_DATA` represents all bytes of msg prior to `mac` field in the envelope.

If a client receives an invalid `mac` value for any message, it will discard the message.

#### Envelope cookie field

The initiator, on receiving a CookieReply message, decrypts `cookie_encrypted` and stores the `cookie_value` for the session into `peer[sid].cookie_value` for a limited time (120 seconds). This value is then used to set `cookie` field set for subsequent messages and retransmissions to the responder as follows:

```pseudorust
if (peer.cookie_value.is_none()  ||  seconds_since_update(peer[sid].cookie_value) >= 120) {
    cookie.zeroize(); //zeroed out 16 bytes bitstring
}
else {
    cookie = lhash("cookie",peer.cookie_value.unwrap(),COOKIE_WIRE_DATA)
}
```

Here, `seconds_since_update(peer.cookie_value)` is the amount of time in seconds ellapsed since last cookie was received, and `COOKIE_WIRE_DATA` are the message contents of all bytes of the retransmitted message prior to the `cookie` field.

The inititator can use an invalid value for the `cookie` value, when the responder is not under load, and the responder must ignore this value.
However, when the responder is under load, it may reject InitHello messages with the invalid `cookie` value, and issue a cookie reply message.

### Conditions to trigger DoS Mechanism

This whitepaper does not mandate any specific mechanism to detect responder contention (also mentioned as the under load condition) that would trigger use of the cookie mechanism.

For the reference implemenation, Rosenpass has derived inspiration from the Linux implementation of Wireguard.  This implementation suggests that the reciever keep track of the number of messages it is processing at a given time.

On receiving an incoming message, if the length of the message queue to be processed exceeds a threshold `MAX_QUEUED_INCOMING_HANDSHAKES_THRESHOLD`, the client is considered under load and its state is stored as under load. In addition, the timestamp of this instant when the client was last under load is stored. When recieving subsequent messages, if the client is still in an under load state, the client will check if the time ellpased since the client was last under load has exceeded `LAST_UNDER_LOAD_WINDOW` seconds. If this is the case, the client will update its state to normal operation, and process the message in a normal fashion.

Currently, the following constants are derived from the Linux kernel implementation of Wireguard:

```pseudorust
MAX_QUEUED_INCOMING_HANDSHAKES_THRESHOLD = 4096
LAST_UNDER_LOAD_WINDOW = 1 //seconds
```

## Dealing with Packet Loss {#packet-loss}

The initiator deals with packet loss by storing the messages it sends to the responder and retransmitting them in randomized, exponentially increasing intervals until they get a response. Receiving RespHello terminates retransmission of InitHello. A Data or EmptyData message serves as acknowledgement of receiving InitConf and terminates its retransmission.

The responder uses less complex form of the same mechanism: The responder never retransmits RespHello, instead the responder generates a new RespHello message if InitHello is retransmitted. Responder confirmation messages of completed handshake (EmptyData) messages are retransmitted by storing the most recent InitConf messages (or their hashes) and caching the associated EmptyData messages. Through this cache, InitConf retransmission is detected and the associated EmptyData message is retransmitted.

### Interaction with cookie reply system

The cookie reply system does not interfere with the retransmission logic discussed above.

When the initator is under load, it will ignore processing any incoming messages.

When a responder is under load and it receives an InitHello handshake message, the InitHello message will be discarded and a cookie reply message is sent. The initiator, then on the reciept of the cookie reply message, will store a decrypted `cookie_value` to set the `cookie` field to subsequently sent messages. As per the retransmission mechanism above, the initiator will send a retransmitted InitHello message with a valid `cookie` value appended. On receiving the retransmitted handshake message, the responder will validate the `cookie` value and resume with the handshake process.

When the responder is under load and it recieves an InitConf message, the message will be directly processed without checking the validity of the cookie field.

# Protocol extensions {#protocol-extensions}

The main extension point for the Rosenpass protocol is to generate `osk`s (speak output shared keys, see Sec. \ref{symmetric-keys}) for purposes other than using them to secure WireGuard. By default, the Rosenpass application generates keys for the WireGuard PSK (see \ref{protocol-extension-wireguard-psk}). It would not be impossible to use the keys generated for WireGuard in other use cases, but this might lead to attacks[@oraclecloning]. Specifying a custom protocol extension in practice just means settling on alternative domain separators (see Sec. \ref{symmetric-keys}, Fig. \ref{img:HashingTree}).

## Using custom domain separators in the Rosenpass application

The Rosenpass application supports protocol extensions to change the OSK domain separator without modification of the source code.

The following example configuration file can be used to execute Rosenpass in outfile mode with custom domain separators.
In this mode, the Rosenpass application will write keys to the file specified with `key_out` and send notifications when new keys are exchanged via standard out.
This can be used to embed Rosenpass into third-party application.

```toml
# peer-a.toml
public_key = "peer-a.pk"
secret_key = "peer-a.sk"
listen = ["[::1]:6789"]
verbosity = "Verbose"

[[peers]]
public_key = "peer-b.pk"
key_out = "peer-a.osk" # path to store the key
osk_organization = "myorg.com"
osk_label = ["My Custom Messenger app", "Backend VPN Example Subusecase"]
```

## Extension: WireGuard PSK {#protocol-extension-wireguard-psk}

The WireGuard PSK protocol extension is active by default; this is the mode where Rosenpass is used to provide post-quantum security for WireGuard. Hybrid security (i.e. redundant pre-quantum and post-quantum security) is achieved because WireGuard provides pre-quantum security, with or without Rosenpass.

This extension uses the `"rosenpass.eu"` namespace for user-labels and specifies a single additional user-label:

* `["rosenpass.eu", "wireguard psk"]`

The label's full domain separator is

* `[PROTOCOL, "user", "rosenpass.eu", "wireguard psk"]`

and can be seen in Figure \ref{img:HashingTree}.

We require two extra per-peer configuration variables:

* `wireguard_interface` — Name of a local network interface. Identifies local WireGuard interface we are supplying a PSK to.
* `wireguard_peer` — A WireGuard public key. Identifies the particular WireGuard peer whose connection we are supplying PSKs for.

When creating the WireGuard interface for use with Rosenpass, the PSK used by WireGuard must be initialized to a random value; otherwise, WireGuard can establish an insecure key before Rosenpass had a change to exchange its own key.

```pseudorust
fn on_wireguard_setup() {
    // We use a random PSK to make sure the other side will never
    // have a matching PSK when the WireGuard interface is created.
    //
    // Never use a fixed value here as this would lead to an attack!
    let fake_wireguard_psk = random_key();

    // How the interface is create
    let wg_peer = WireGuard::setup_peer()
        .public_key(wireguard_peer)
        ... // Supply any custom peerconfiguration
        .psk(fake_wireguard_psk);

    // The random PSK must be supplied before the
    // WireGuard interface comes up
    WireGuard::setup_interface()
        .name(wireguard_interface)
        ... // Supply any custom configuration
        .add_peer(wg_peer)
        .create();
}
```

Every time a key is successfully negotiated, we upload the key to WireGuard.
For this protocol extension, the `setup_osks()` function is thus defined as:

```pseudorust
fn setup_osks() {
    // Generate WireGuard OSK (output shared key) from Rosenpass'
    // perspective, respectively the PSK (preshared key) from
    // WireGuard's perspective
    let wireguard_psk = export_key("rosenpass.eu", "wireguard psk");

    /// Supply the PSK to WireGuard
    WireGuard::get_interface(wireguard_interface)
        .get_peer(wireguard_peer)
        .set_psk(wireguard_psk);
}
```

The Rosenpass protocol uses key renegotiation, just like WireGuard.
If no new `osk` is produced within a set amount of time, the OSK generated by Rosenpass times out.
In this case, the WireGuard PSK must be overwritten with a random key.
This interaction is visualized in Figure \ref{img:ExtWireguardPSKHybridSecurity}.

```pseudorust
fn on_key_timeout() {
    // Generate a random – deliberately invalid – WireGuard PSK.
    // Never use a fixed value here as this would lead to an attack!
    let fake_wireguard_psk = random_key();

    // Securely erase the PSK currently used by WireGuard by
    // overwriting it with the fake key we just generated.
    WireGuard::get_interface(wireguard_interface)
        .get_peer(wireguard_peer)
        .set_psk(fake_wireguard_psk);
}
```

\setupimage{label=img:ExtWireguardPSKHybridSecurity,fullpage}
![Rosenpass + WireGuard: Hybrid Security](graphics/rosenpass-wireguard-hybrid-security.pdf)

# Changelog

### 0.3.x

#### 2025-08-10 – Applying fixes from Steffen Vogel proof reading of the whitepaper

\vspace{0.5em}

Author: Karolin varner

Issue: [#68](https://github.com/rosenpass/rosenpass/issues/68)

PR: [#664](https://github.com/rosenpass/rosenpass/)

\vspace{0.5em}

Early in the project lifetime, Steffen Vogel successfully implemented a [port of the Rosenpass protocol in [go](https://github.com/cunicu/go-rosenpass).
This implementation has not received an in-depth review from a cryptography implementation perspective, which is why we (the Rosenpass project) are not yet recommending this implementation for production usage;
still, creating this implementation was a great achievement.

During the process, Steffen discovered a large number of possible improvements for the whitepaper. With this update, we are addressing those issues.

Changes, in particular:

1. Added a comprehensive reference about labels used in the protocol
2. Added a comprehensive reference about symmetric keys and nonces used for encryption/decryption (`txki`, `txni`, `ini_enc`, `hs_enc`, …)
3. Added a comprehensive reference about packages used.
4. Added an explaining paragraph to section "Live Session State".
5. Added a section about protocol roles.
6. Brief section about endianness.
7. In Fig. 5: Rosenpass Message Handling Code; in IHR5 we replace


    ``` {=tex}
    \begin{quote}
        \begin{minted}{pseudorust}
        decaps_and_mix<SKEM>(sskr, spkr, ct1)
        \end{minted}
    \end{quote}

    ```

    by

    ``` {=tex}
    \begin{quote}
        \begin{minted}{pseudorust}
        decaps_and_mix<SKEM>(sskr, spkr, sctr)
        \end{minted}
    \end{quote}
    ```

8. In `load_biscuit()`, there was a typo doing an incorrect comparison between `biscuit_no` and `biscuit_used`. This is not a security issue, as a verbatim implementation would simply have lead to a non-functional implementation. We replace

    ``` {=tex}
    \begin{quote}
        \begin{minted}{pseudorust}
        assert(pt.biscuit_no <= peer.biscuit_used);
        \end{minted}
    \end{quote}

    ```

    by

    ``` {=tex}
    \begin{quote}
        \begin{minted}{pseudorust}
        assert(pt.biscuit_no >= peer.biscuit_used);
        \end{minted}
    \end{quote}
    ```

9. In the whitepaper we used the labels `"initiator session encryption"` and `"responder session encryption"`, but in the implementation we used `"initiator handshake encryption"` and `"responder handshake encryption"`. While the whitepaper was correct and the implementation was not, we opt to harmonize the whitepaper with the implementation to avoid a breaking change.

#### 2025-06-24 – Specifying the `osk` used for WireGuard as a protocol extension

\vspace{0.5em}

Author: Karolin varner

PR: [#664](https://github.com/rosenpass/rosenpass/pull/664)

\vspace{0.5em}

We introduce the concept of protocol extensions to make the option of using Rosenpass for purposes other than encrypting WireGuard more explicit. This captures the status-quo in a better way and does not constitute a functional change of the protocol.

When we designed the Rosenpass protocol, we built it with support for alternative `osk`-labels in mind.
This is why we specified the domain separator for the `osk` to be `[PROTOCOL, "user", "rosenpass.eu", "wireguard psk"]`.
By choosing alternative values for the namespace (e.g. `"myorg.eu"` instead of `"rosenpass.eu`) and the label (e.g. `"MyApp Symmetric Encryption"`), the protocol could easily accommodate alternative usage scenarios.

By introducing the concept of protocol extensions, we make this possibility explicit.

1. Reworded the abstract to make it clearer that Rosenpass can be used for other purposes than to secure WireGuard
2. Reworded Section Symmetric Keys, adding references to the new section on protocol extension
3. Added a `setup_osks()` function in section Hashes, to make the reference to protocol extensions explicit
4. Added a new section on protocol extensions and the standard extension for using Rosenpass with WireGuard
5. Added a new graphic to showcase how Rosenpass and WireGuard interact
5. Minor formatting and intra-document references fixes

#### 2025-05-22 - SHAKE256 keyed hash
\vspace{0.5em}

Author: David Niehues

PR: [#653](https://github.com/rosenpass/rosenpass/pull/653)

\vspace{0.5em}

We document the support for SHAKE256 with prepended key as an alternative to BLAKE2s with HMAC.

Previously, BLAKE2s with HMAC was the only supported keyed hash function. Recently, SHAKE256 was added as an option. SHAKE256 is used as a keyed hash function by prepending the key to the variable-length data and then evaluating SHAKE256.
In order to maintain compatablity without introducing an explcit version number in the protocol messages, SHAKE256 is truncated to 32 bytes. In the update to the whitepaper, we explain where and how SHAKE256 is used. That is:

1. We explain that SHAKE256 or BLAKE2s can be configured to be used on a peer basis.
2. We explain under which circumstances, the reference implementation tries both hash functions for messages in order to determine the correct hash function.
3. We document that the cookie mechanism always uses SHAKE256.


#### 2024-10-30 – InitConf retransmission updates

\vspace{0.5em}

Author: Karolin Varner

Issue: [#331](https://github.com/rosenpass/rosenpass/issues/331)

PR: [#513](https://github.com/rosenpass/rosenpass/pull/513)

\vspace{0.5em}

We redesign the InitConf retransmission mechanism to use a hash table. This avoids the need for the InitConf handling code to account for InitConf retransmission specifically and moves the retransmission logic into less-sensitive code.

Previously, we would specifically account for InitConf retransmission in the InitConf handling code by checking the biscuit number: If the biscuit number was higher than any previously seen biscuit number, then this must be a new key-exchange being completed; if the biscuit number was exactly the highest seen biscuit number, then the InitConf message is interpreted as an InitConf retransmission; in this case, an entirely new EmptyData (responder confirmation) message was generated as confirmation that InitConf has been received and that the initiator can now cease opportunistic retransmission of InitConf.

This mechanism was a bit brittle; even leading to a very minor but still relevant security issue, necessitating the release of Rosenpass maintenance version 0.2.2 with a [fix for the problem](https://github.com/rosenpass/rosenpass/pull/329). We had processed the InitConf message, correctly identifying that InitConf was a retransmission, but we failed to pass this information on to the rest of the code base, leading to double emission of the same "hey, we have a new cryptographic session key" even if the `outfile` option was used to integrate Rosenpass into some external application. If this event was used anywhere to reset a nonce, then this could have led to a nonce-misuse, although for the use with WireGuard this is not an issue.

By removing all retransmission handling code from the cryptographic protocol, we are taking structural measures to exclude the possibilities of similar issues.

- In section "Dealing With Package Loss" we replace

    \begin{quote}
        The responder does not need to do anything special to handle RespHello retransmission – if the RespHello package is lost, the initiator retransmits InitHello and the responder can generate another RespHello package from that. InitConf retransmission needs to be handled specifically in the responder code because accepting an InitConf retransmission would reset the live session including the nonce counter, which would cause nonce reuse. Implementations must detect the case that `biscuit_no = biscuit_used` in ICR5, skip execution of ICR6 and ICR7, and just transmit another EmptyData package to confirm that the initiator can stop transmitting InitConf.
    \end{quote}

    by

    \begin{quote}
        The responder uses less complex form of the same mechanism: The responder never retransmits RespHello, instead the responder generates a new RespHello message if InitHello is retransmitted. Responder confirmation messages of completed handshake (EmptyData) messages are retransmitted by storing the most recent InitConf messages (or their hashes) and caching the associated EmptyData messages. Through this cache, InitConf retransmission is detected and the associated EmptyData message is retransmitted.
    \end{quote}

- In function `load_biscuit` we replace

    ``` {=tex}
    \begin{quote}
        \begin{minted}{pseudorust}
        assert(pt.biscuit_no <= peer.biscuit_used);
        \end{minted}
    \end{quote}
    ```

    by

    ``` {=tex}
    \begin{quote}
        \begin{minted}{pseudorust}
        // In December 2024, the InitConf retransmission mechanisim was redesigned
        // in a backwards-compatible way. See the changelog.
        //
        // -- 2024-11-30, Karolin Varner
        if (protocol_version!(< "0.3.0")) {
            // Ensure that the biscuit is used only once
            assert(pt.biscuit_no <= peer.biscuit_used);
        }
        \end{minted}
    \end{quote}
    ```

#### 2024-04-16 – Denial of Service Mitigation

\vspace{0.5em}

Author: Prabhpreet Dua

Issue: [#137](https://github.com/rosenpass/rosenpass/issues/137)

PR: [#142](https://github.com/rosenpass/rosenpass/pull/142)

\vspace{0.5em}

- Added denial of service mitigation using the WireGuard cookie mechanism
- Added section "Denial of Service Mitigation and Cookies", and modify "Dealing with Packet Loss" for DoS cookie mechanism

\printbibliography

\setupimage{landscape,fullpage,label=img:HandlingCode}
![Rosenpass Message Handling Code](graphics/rosenpass-wp-message-handling-code-rgb.svg)

