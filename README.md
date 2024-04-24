[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][CRYPTID]
[![](https://img.shields.io/badge/project-provenance-purple.svg?style=flat-square)][PROVENANCE]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][MULTIFORMATS]
[![](https://img.shields.io/badge/License-Functional_Source_1.1-red)][FSL]
![](https://github.com/cryptidtech/bs/actions/workflows/rust.yml/badge.svg)

# BetterSign

## Introduction

BetterSign (`bs`) is a new signing tool designed to use provenance based
identity and decentralized global PKI solutions. This tool has a set of
primary goals:

* Support the new provenance based decentralized identity system...
  * Integrate with IPFS to look up and retrieve identity provenance logs
  * Embed a WACC VM to support full plog validation
  * Provide functions for creating and managing provenance log identities
* Maximize compatibility by...
  * Supporting keyrings of all types (e.g. GPG, SSH_AUTH_SOCK, HSMs, etc)
  * Supporting signature formats of all types (e.g. GPG, Multisig, etc)
* Seamlessly integrate with other tools by...
  * Supporting status outputs of all types (e.g. `gpg --status-fd`, etc)

## Provenance Based Identity

The current web-of-trust and global PKI systems are constructed from buliding
blocks that are too fragile to create a global regime for transmitting trust
through time and space. Among the many design problems, the current systems
operate without consideration for the element of time and therefore lack the
ability to prove the history of control and modification of any digital data,
let alone cryptographic keys. With the creation of blockchains and distributed
consensus popularizing the idea of immutable records of transactions over time,
we've learned the value of maintaining logs to document the provenance of data
over large spans of time despite the unbounded memory requirement that results.
In a world where there is old data signed with old keys, there must be some
cryptographically verifiable record preserving and linking old keys to the new
keys; provenance logs are design to be the simplest and most decentralized
solution for that.

To finally improve the global PKI system, it seems logical to start from
scratch and construct an identity solution based entirely off of a provenace
logging structure. It also is apparent that identity based transactions are
either 1-party or 3-party transactions and therefore do not require the
distributed consensus necessary for trustful 2-party transactions. This opens
the door for provenance logs that grow in trust in several ways. They can
accumulate 1st party self-attestations along with proofs of work (i.e. content
creation of all kinds or verifiable acts of service). They may also record
references to 3rd party corroborating attestation sources for realtime,
late-bidning verification from multiple trustworthy societal institutions or
organizations. In the end, this solution is very good at overcoming the
analog-to-digital problem of encoding trust. The security rests in the
statistical improbability of corrupting and/or falsifying proof from an
increasing number of trustworth insitutions while also making verification
time-sensitive and responsive to shifting facts on the ground. This
corroboration based security model gives statistical assurances of trust and is
the natural trust model for provenance logs.

Provenance logs are a form of time-based log with the added feature of
cryptographically enforced write priviledges which may be delegated and
revoked. By borrowing the idea of lock and unlock scripts from Bitcoin, each
entry in a provenance log has a set of cryptographic conditions encoded as a
lock script that the next entry must satisfy by providing an unlock script and
proof data. The details of this mechanism is described in detail in the
[provenance log specification][PROVSPEC] and the [provenance log implementation
README][PROVREADME].

## Metastable Systems

> *metastable* (adj) — being in a long-lived stable state that arrises
> spontaneously from and persists despite chaotic conditions

When discussing distributed systems we speak of networks of peers connected
together with links. A network consists of peers with links that reference
other peers. The links are an identifier that may reference the peer, a service
provided by a peer, or data stored by a peer. A link does not necessarily imply
an active network connection but does imply that one will be created when the
link is used to execute the distributed functions of the network.

All distributed systems are chaotic in nature meaning that the range and trends
in network behavior observed over time are impossible to predict from the
current conditions. However, distributed systems may be categorized into two
buckets based on their long-term stability and resilience in the face of the
corrosive effects of time. One category—*unstable* systems—are those that exist
at a point in time but due to the design characteristics dictating peer and
link behavior they are *not* biased towards stability and never trend towards
*metastability*. These unstable systems often have many small localized
networks of peers but they never seem to conglomerate into a single long-term
network. You never get *THE* network—as in *THE* World Wide Web—arrising
spontaneously from *unstable* preconditions. The primary example of an
*unstable* network is the global identity "Web of Trust". Despite decades old
standards and long-established market conditions, we still do not have *THE*
Web of Trust. This is likely due to the characteristics of pubkey links.

The other category—*metastable* systems—are those with peer and node
characteristics that bias the chaos towards the accretion of a single, stable
network. These *metastable* networks start with a set of preconditions that
make *THE* network innevitable from the common usage patterns. The primary
example in this category is *THE* World Wide Web. This is also likely due to
the characteristics of URL links in the system.

One key insight that comes from comparing pubkey links with URL links is that
pubkeys links can only be in one of two states—*valid* or *invalid*—while URLs
typically can be in one of three states—*valid*, *invalid* or *partially
valid*. URLs in the World Wide Web have a *partially valid* third state where
the full URL (e.g. https://example.com/foo/bar/baz) is invalid but the domain
name portion alone (e.g. https://example.com/) is valid. More importantly, the
URL with just the domain name has a much longer life span of validity and
because most web sites have a content discovery mechansim (i.e. search), it is
very often possible to take a partially valid URL and restore it back to a
valid URL. If the website uses TLS and https, then the restoration of the
partially valid link into a valid link can be done securely, unilaterally by
the remote peer.

A simple example is this: you have a partially invalid link to a product on
Amazon so instead of giving up, you shorten the URL to the valid
`https://amazon.com` part and you use the search to either find the new link to
the product or you find URLs to other similar products. The net effect is that
what appears to be an invalid URL is often just a partially invalid URL that is
restorable to a valid URL. URLs on the World Wide Web form a kind of
"restorable" link which biases the whole network towards the formation of
*THE* World Wide Web. Despite the fact that web servers come and go at random
and web pages come and go at random, this one little distinction in link
behavior is why there is a single, stable World Wide Web that has persisted for
30+ years. When you tell your friends that you are starting a blog, they never
ask you "which web are you putting it on?" Why? Because there is effectively
only one web.

In contrast, pubkey links in the Web of Trust do not have a *partially valid*
state and are therefore never "restorable" to a valid state without some other
communication external to the network. Once a pubkey becomes invalid, there is
no secure way—short of in-person interaction—to communicate a new valid pubkey
link to the remote peer. I think this lack of restorable links is the primary
reason why *THE* Web of Trust does not exist. The confirmation of this comes
when you generate a GPG key pair and tell your friends to use it. They usually
ask, "Which key server did you upload it to?" This is an indication that *THE*
Web of Trust doesn't exist.

Imagine if the World Wide Web used domain names that changed to new, random
values often. What if "amazon.com" changed to a random string of characters
every few weeks or months. So this week the Amazon website is at
"https://f332a87bb7375ae2" and several weeks later it is at
"https://8bee21d435df4434". The World Wide Web as we know it would cease to
exist simply because the links are not valid long enough—and are not securely
restorable—for *THE* World Wide Web to hold together as a metastable network.
This single observation suggests that distributed systems using public keys as
links do not trend towards metastability. The primary means around this
situation in p2p networks is with bootstrappers that track and maintain a
global list of peers and peers themselves don't expect peer identifiers to
remain stable over long periods of time. Each time a peer rejoins a network
they first contact the bootstrapper and get the latest list of peer
identifiers. This centralization is a direct consequence of poor link design
and exposes p2p networks to corporate and governmental capture and control.

Metastable networks exist without any fixed infrastructure and have no points
of leverage where corporations and/or governments can exert their will. They
are truly a "wedge technology" because they drive a wedge between
corporations/governments and their primary tool for maintaining money/power:
the Internet. Metastable networks force corporations and governments into
choosing between keeping the Internet on and accepting metastable networks
outside of their control or turning the Internet off and accepting the loss of
power and money without the Internet to maintain it.

### Don't Use Public Keys as Links

Public key pairs are subject to attack and compromise in a number of ways
necessitating regular rotation and occassional recovery to ensure a high degree
of security and resiliency. Using public keys as links means that whenever a
key is rotated or revoked, any external references using the pubkey link
becomes invalid. Using public keys as links creates tightly coupled and fragile
distributed systems.

Why do we use public keys as links? The answer is that they are a compact and
convenient value with two primary properties:

1. Public keys have enough entropy that collisions between randomly generated
   keys are all but impossible.
2. A public key is a cryptographic commitment to a verification function (e.g.
   public key digital signature) that verifies other data and binds control of
   that other data to the controller of the public key pair.

Public keys solve the problem of cryptographically enforced proof-of-control
while also being collision resistent even with uncoordinated random generation.
However their vulnerability to attack and compromise makes them bad links for
distributed systems. Key rotation is good security hygiene. It is also the
primary reason why *THE* Web of Trust doesn't exist.

### A Better Identifer

Given the two primary properties of public keys listed above, it is conceivable
that another type of identifer can be constructed with those same properties
while also lacking the vulnerabilities and limited time durability. All we have
to do is construct a tuple identifer from a large random value—commonly called
a nonce—and a cryptographic commitment to a verification function. By combining
content addressable storage and WASM as universally executable code, any WASM
code that verifies data using cryptography will suffice as a verification
function. The WASM is hashed to create a content address (e.g. CID) that is
both an immutable identifier for retrieving the WASM code but also a
cryptographic verification method to ensure that the WASM code has not been
modified.

Combining the nonce and the content address of a WASM verification function
gives us an identifier that is both unique and also a cryptographic commitment
to a verification function; the same set of properties as public keys. However
this new identifer is not based off of key material and is not subject to
compromise resulting in an identifier that remains valid and unchanged over
long periods of time. Any change in the WASM code is detectable. Any change in
the nonce creates a different identifier. The only way for one of these new
identifiers to remain relevant over time is to remain unchanged.

Generalizing this idea to being a nonce combined with a content address (CID)
gives us a new identifier called a "Verifiable Long-lived ADdress" or
[VLAD][VLAD].

When using a VLAD to identify an arbitrary piece of data, the CID in the VLAD 
must refer to WASM code that, when executed, verifies the validity of the data
it references. VLADs can replace pubkeys in a distributed hash table (DHT) such
as the [IPNS DHT][IPNS]. Using VLADs as well as pubkeys is IPNS version 3.
Below is an illustration of this IPNSv3 structure:

```
╔══════════════════════════════════[ IPNSv3 ]══════════════════════════════════╗
║                                                                              ║
║  ╭────────────────────────[Distributed Hash Table]────────────────────────╮  ║
║  │                                                                        │  ║
║  │ ╭─[VLAD]──┬────────────╮                           ╭─[Mutable Value]─╮ │  ║
║  │ │ <nonce> │ <WASM CID> │ ──────── maps to ───────> │      <CID>      │ │  ║
║  │ ╰─────────┴───┬────────╯                           ╰────────┬────────╯ │  ║
║  │               │                                             │          │  ║
║  ╰───────────────│─────────────────────────────────────────────│──────────╯  ║
║                  │                                             │             ║
║                  │                                             │             ║
║             references                                    references         ║
║  ╭───────────────│─────────────────────────────────────────────│──────────╮  ║ 
║  │               v                                             v          │  ║
║  │ ╭─[WASM]─────────╮                               ╭─[Data]────────────╮ │  ║
║  │ │ (module        │                               │ 10010111010100100 │ │  ║
║  │ │   (func $main  │                               │ 00110111100011110 │ │  ║
║  │ │     return     │  ───────── verifies ────────> │ 11101101101010011 │ │  ║
║  │ │   )            │                               │ 11111010011010001 │ │  ║
║  │ │ )              │                               │ 01101101000100001 │ │  ║
║  │ ╰────────────────╯                               ╰───────────────────╯ │  ║
║  ╰───────────────────────[Content Addressable Storage]────────────────────╯  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

By mapping a VLAD to a mutable "forward pointer" CID, we create a system for
decoupling the identifer from the verification function. This opens up the
possibility of making the verification function into a "driver" that
understands a given IPLD data structure in order to verify it.

The WASM driver is a simple way to iteratively verify new blocks as they are
added to the IPLD data structure thus ensuring the whole structure is valid. If
the new block verifies as valid then the mutable forward pointer CID can be
updated to point at the new block.

Also, if the driver WASM code yields the CID of each data block in an IPLD data
structure as it verifies them, we also get an automated way to construct CAR
files of arbitrary IPLD data structures without having to hard code drivers or
dictating IPLD schemas to make the links generically readable. For instance, we
could get rid of the custom CID data type tag in the DAG-CBOR encoding. The
drivers themselves are stored in IPFS along side the IPLD data structures they
understand.

A further improvment to strengthen the security of this design is to make the
nonce in the VLAD a detached digital signature over the CID inside the VLAD.
The digital signature is verified by a public key stored in the first data
block of the IPLD data structure that the VLAD references. This creates a
cryptographic binding of the VLAD to the IPLD data structure in a verifiable
and non-repudiable way. If the secret key used to generate the signature is
destroyed immediately afterward, it is impossible for an attacker to forge a
new VLAD for a given IPLD data structure. The basic approach is to use a WASM
script that is executed to validate every block in the IPLD data structure as
they are appended. The WASM script is used by the IPNS system to determine if a
new block of data is a valid update to the IPLD data structure and the mutable
forward pointer CID should be updated to point at the new block. There is no
prescribed way to do the verification of updates but it should probably use
cryptography to maintain control over who can add new data blocks. In the next
section we will look at how [provenance logs][PROVREADME] use additional WASM
lock and unlock scripts to control the updates to the log itself. Below is a
modified diagram showing how a signed VLAD is used to bind itself to the IPLD
data structure.

```
╔════════════════════════════[ IPNSv3 Signed VLAD ]════════════════════════════╗
║                                                                              ║
║  ╭────────────────────────[Distributed Hash Table]────────────────────────╮  ║
║  │                                                                        │  ║
║  │ ╭─[VLAD]──────┬──────────────╮                     ╭─[Mutable Value]─╮ │  ║
║  │ │   <Sig of> ──> <WASM CID>  │ ───── maps to ────> │      <CID>      │ │  ║
║  │ ╰─────────────┴────────────┬─╯                     ╰─┬───────────────╯ │  ║
║  │          ^                 │                         │                 │  ║
║  ╰──────────│─────────────────│─────────────────────────│─────────────────╯  ║
║             │  ╭─ references ─╯                         ╰ references ╮       ║
║             │  │                                                     │       ║ 
║             ╰───── verifies ──╮                                      │       ║ 
║  ╭─────────────│──────────────│──────────────────────────────────────│────╮  ║ 
║  │             v              │                                      v    │  ║
║  │ ╭─[WASM]─────────╮         │      ╭─[IPLD]────────╮  ╭─[IPLD]────────╮ │  ║
║  │ │ (module        │         │    X── Prev          │<── Prev          │ │  ║
║  │ │   (func $main  │         ╰─────── Eph. Pubkey   │  │ 1111101001101 │ │  ║
║  │ │     return     │                │ 1111000111100 │  │ 0111100011110 │ │  ║
║  │ │   )            │ ─ verifies ──> │ 0110110100010 │  │ 0011011110001 │ │  ║
║  │ │ )              │                │ 1101010011000 │  │ 1101101000100 │ │  ║
║  │ ╰────────────────╯                ╰───────────────╯  ╰───────────────╯ │  ║
║  ╰───────────────────────[Content Addressable Storage]────────────────────╯  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### VLADs in Provenance Logs

When using a VLAD to identify a provenance log, the CID in the VLAD is the 
content address of the WASM lock script for validating the first entry in the
provenance log and the nonce in the VLAD is a detached digital signature over
the CID created with an ephemeral key pair. The ephemeral public key is stored
in the first entry.

Preferably the digital signature is an ECDSA/EdDSA signature for compactness
but in high security applications where quantum resistance is desired, a
one-time Lamport signature is used. This increases the size of the VLAD to just
over 8KB in size but gains quantum resistance. Because Lamport signatures are
one-time use signatures, the first entry must be signed with a separate key
pair than the ephemeral key pair used to sign the VLAD. This changes slightly
the procedure for creating the VLAD and first entry. The ephemeral Lamport key
pair is generated first and used to sign the CID to the first lock script and
create the VLAD. Another Lamport key pair is generated to use for signing the
first entry. The first entry must contain the VLAD, the ephemeral public key,
and the first entry signing public key before it is signed. In high security
use cases, the WASM code used for validating the first entry does three things:
it verifies the signature in the VLAD using the ephemeral public key, it checks
that the CID in the VLAD matches its own CID, and it checks the signature over
the first entry.

The first entry of the provenance log contains the ephemeral public key to
verify the digital signature in the VLAD and confirm that the CID to the WASM
lock script hasn't changed. This gives a closed loop verification that
cryptographically binds the VLAD to the provenance log at both the first and
most recent entry. When updating the mutable value in the DHT, the DHT PUT
contains just the CID of the new head entry for the provenance log. Since the
DHT already contains the CID of the current head, it will go through the normal
provenance log validation check and attempt to validate the new entry. If the
validation succeeds, then the new CID is stored as the value associated with
the VLAD. If not, the DHT value is not updated.

Below is a diagram showing how signed VLADs are bound to, and reference, a
provenance log stored in content addressable storage.

```
╔═════════════════════════[ Provenance Log and VLAD ]══════════════════════════╗
║                                                                              ║
║  ╭────────────────────────[Distributed Hash Table]────────────────────────╮  ║
║  │                                                                        │  ║
║  │ ╭─[VLAD]──────┬──────────────╮                     ╭─[Mutable Value]─╮ │  ║
║  │ │   <Sig of> ───> <WASM CID> │ ───── maps to ────> │      <CID>      │ │  ║
║  │ ╰─────────────┴────────────┬─╯                     ╰─┬───────────────╯ │  ║
║  │          ^                 │                         │                 │  ║
║  ╰──────────│─────────────────│─────────────────────────│─────────────────╯  ║
║             │  ╭─ references ─╯                         ╰ references ╮       ║
║             │  │                                                     │       ║ 
║             ╰───── verifies ──╮                                      │       ║ 
║  ╭─────────────│──────────────│──────────────────────────────────────│────╮  ║ 
║  │             v              │                                      v    │  ║
║  │ ╭─[WASM]─────────╮         │      ╭─[Foot]────────╮  ╭─[Head]────────╮ │  ║
║  │ │ (module        │         │      │ Seqno 0       │  │ Seqno 1       │ │  ║
║  │ │   (func $main  │         │    X── Prev NULL     │<── Prev          │ │  ║
║  │ │     return     │         ╰─────── Eph. Pubkey   │  │               │ │  ║
║  │ │   )            │ ─ verifies ──> │               │  │               │ │  ║
║  │ │ )              │                │               │  │               │ │  ║
║  │ ╰────────────────╯                ╰───────────────╯  ╰───────────────╯ │  ║
║  ╰───────────────────────[Content Addressable Storage]────────────────────╯  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

#### Encoding

To reduce the tight binding and fragility of VLADs, they are encoded using the
self-describiing [multiformats standard][MULTIFORMATS]. A VLAD therefore begins
with the multicodec sigil identifying itself as a VLAD (e.g. `0x07`) followed
by two multiformat encoded values, a nonce (e.g. `0x3b`) followed by a content
addres CID (e.g. `0x01` v1, `0x02` v2, or `0x03` v3). Below are examples of
different VLADs.

A [nonce][NONCE] is encoded using the multicodec sigil `0x3b` followed by a
varuint specifying the number of octets in the nonce followed by the nonce
octets; like so:

```
  number of nonce
       octets
         │
0x3b <varuint> N(octet)
 │                 │
nonce        variable number
sigil        of nonce octets
```

A "plain" VLAD consisting of a nonce and CID looks like:

```
   nonce data
        │
0x07 <nonce> <cid>
 │             │
VLAD      WASM content
sigil       address
```

A "signed" VLAD consisting of a [multisig][MULTISIG] encoded signature nonce
and CID looks like following:

```
        nonce data
            │
0x07 <multisig nonce> <cid>
 │                      │
VLAD              WASM content
sigil                address


                          number of
                        multisig octets
                              │
<multisig nonce> ::= 0x3b <varuint> <multisig>
                      ╱                 │
            nonce sigil          multisig octets


             multisig    optional combined
              sigil      signature message
                │                 │
<multisig> ::= 0x39 <varuint> <message> <attributes>
                       ╱                      │
          signing codec              signature attributes


<message> ::= <varbytes>


                        variable number of attributes
                                      │
                            ──────────┴──────────
                           ╱                     ╲
<attributes> ::= <varuint> N(<varuint> <varbytes>)
                    ╱           ╱           │
   count of attributes    attribute     attribute
                         identifier       value


<varbytes> ::= <varuint> <multisig octets>
                  ╱              │
          count of          variable number
            octets         of multisig octets
```

In signed VLADs the multisig is a detached signature so the message is always a
zero-length varbytes.

### VLADs as Used with Provenance Logs 

The construction of a new provenance log consists of a series of steps to 
ensure that the first entry in the provenance log binds together all of the
necessary parts for a provenance log based global PKI system while also
ensuring that nobody can forge a valid competing first entry. VLADs are the
identifier used in this new PKI regime. They not only refer to its associated
provenance log but they also serve as identifier in the more dynamic global
distributed hash table (DHT) used to provide mutable forward references that
always point at the most recent entry in a provenance log.

It is important to point out that the VLAD associated with a provenance log
will stay the same for the entire lifespan of the provenance log. This means it
is a perfect long-lived identifier for identifying the person or process that
controls the provenance log. Mapping the VLAD to the provenance log is the job
of mutable forward pointer and the provenance log contains the accumulated
state associated with the identity.

Using VLADs as the links in a PKI distributed system makes it metastable.
Provenance logs track key histories. With IPNSv3, the public key associated
with a digital signature is mapped to the CID of the provenance log entry when
the public key was the current key. Since every entry in the provenance log
contains the VLAD for the provenance log, that VLAD is mapped to the CID of the
head of the provenance log which gets the whole provenance log. This makes
public keys into "restorable" links binding a global Web of Trust together into
a metastable network.

The steps for creating the first entry in a provenance log are as follows:

#### VLAD Creation

1. Create/select the WASM lock script to use for validating the first entry in
   the provenance log and hash it to get its CID. If using Lamport signatures
   for the VLAD and first entry, choose a lock script that verifies the
   signature over the VLAD using the public key stored under `/ephemeral` and
   also verifies the signature over the first entry using the public key stored
   under `/ephemeralself`. Lamport signatures are one-time signatures so we
   need two key pairs.
2. Generate an ephemeral cryptographic public key pair. Use one-time Lamport
   keys for quantum resistance.
3. Create a detached digital signature of the WASM lock script CID using the
   ephemeral key pair.
4. Encode the digital signature in the multisig multiformat and create a VLAD
   with a multisig nonce and the WASM CID values.

#### First Entry Creation (Non-forked)

1. Generate a new public key pair to advertise as the current signing key in
   the provenance log. Optionally, you may want set up a Lamport threshold
   signature group, giving key shares to each of the trusted group members.
   Setting up the lock script with the threshold signature has the highes
   precedence allows "social recovery" of provenance log control should your
   signing key be compromised.
2. Create the first entry setting the "vlad" field to the newly constructed
   VLAD value.
3. Set the "prev" and "lipmaa" fields to NULL CIDs.
4. Sets the "seqno" field to 0.
5. Add an update operation to the "ops" list that sets `/pubkey` to the public
   key value to the public key generated in step 1 encoded in the multikey
   format. Optionally add an update operation that sets the `/tpubkey` to the
   threshold public get generated in step 1. Also add an update operation that
   sets the values for anything else related to the use of this provenance log.
   There must be an update operation setting the `/ephemeral` value to the
   ephemeral public key generated when creating the VLAD. If using Lamport
   signatures, it is also necessary to generate an ephemeral key pair to sign
   the first entry in the log with. There must be an update operation to
   setting the `/ephemeralself` value to this public key.
6. Add the `/` WACC WASM lock script that checks the conditions that the next
   entry in the log must meet to be valid. Add in any other WASM lock scripts
   for any other branches/leaves in the key-value pair store.
7. Set the "unlock" field to the WACC WASM script that uses the data in the
   first entry of the provenance log to satisfy the WASM lock script referenced
   by the VLAD CID.
8. Calculate a digital signature over the entire entry. If using Lamport
   signatures use the `/ephemeralself` key pair, otherwise use the `/ephemeral`
   key pair.
9. Encode the digital signature in the multisig multiformat and assign the
   value to the "proof" field in the entry.
10. DESTROY THE `/ephemeral` and `/ephemeralself` PRIVATE KEYS USING APPROPRIATE
    DELETION METHODS.
11. Calculate the content address for the first entry and encode it as a CID.
12. Store the first entry in a content addressable storage system appropriate
    for the context in which the provenance log identity will have meaning. If
    this is intended to be an Internet identity, store it in a globally
    readable content addressable storage network such as [IPFS][IPFS].
13. Add the CID for the first entry as the value associated with the VLAD in
    the VLAD to CID mapping system used for this application.

The first entry in the provenance log is self-signed by an ephemeral key pair
that is destroyed immediately after it is used to sign the first entry and
VLAD. This prevents anybody else from creating a validly signed first entry and
VLAD by compromising the ephemeral key pair.

### Key Rotation in Provenance Logs 

At some point in the future, the advertised public key must be rotated. This is 
done simply by doing the following:

1. Generate a new public key pair.
2. Create a new provenance log entry and fill in the "vlad", "prev", "lipmaa",
   "seqno", "ops", "lock" and "unlock" fields appropriately. The "ops" list
   must contain an update operation that sets the `/pubkey` value to the new
   advertised public key encoded in multikey format.
3. Generate the proof required to satisfy the conditions of the lock script in
   the previous entry that governs the `/pubkey` leaf in the key-value store.
4. Calculate the content address for the new entry and encode it as a CID.
5. Store the new entry in the content addressable storage along with the 
   previous entries in the provenance log.
6. Submit a PUT message to the DHT to update the CID associated with the VLAD.
   It will attempt to validate the new entry and if it does validate, the VLAD
   mapping service will update the CID value to the new CID.

### Key Revocation in Provenance Logs 

By convention there is a primary advertised public key stored under the
`/pubkey` key in the virtual key-value store associated with the provenance
log. There is no limitation to the number of advertised public keys or any
other data associated with the provenance log and the identity it represents.

Key rotation using an update operation to update `/pubkey` effectively revokes
the previously advertised public key. However there are cases where an explicit
key revocation is desired; usually due to a compromised key pair. To signal an
explicit revocation, just add a delete operation to the ops list, deleting the
public key from the virtual key-value store, before adding the new value using
an update operation. This will signal to others that any signature created
using the key pair after the creation of this entry cannot be trusted. To
ensure the correct ordering of events, it is recommended to record the VLAD
value in a public blockchain as a wallclock timestamp proof and then record the
URL to the blockchain transaction under the `/timestamp` key-path. A service
such as [Open Timestamps][OPENTIMESTAMPS] makes this a straightforward
operation. This allows anybody to prove that the key revocation happened no
later than the wall clock time of the public blockchain transaction. This is
helpful to prove the correct order of events in the future when maximum
security is required. Typically, the public blockchain timestamp is only done
when a key is compromised.

To be clear, the ops list for a key revocation with timestamp looks like the
following:

```json
"ops": [
  { "delete": [ "/pubkey" ] },
  { "update": [ "/timestamp", { "str": [ "https://link.to/tx" ] } ] },
  { "update": [ "/pubkey", { "data": [ "<multikey pubkey>" ] } ] }
]
```

## Fixing Git Cryptography with Provenance Logs

There are many problems with Git's reliance on GPG and OpenSSH for its signing
tools. The primary problems are that most people who clone a repo do not have
all of the public keys of the commit signers nor do they want to spend the time
it takes to manually download the public keys from key servers. Even if there
is a way to automate the difficult task of enumerating and downloading the
public keys, they can't necessarily trust that the keys are the real keys used
by the commit signers due to a lack of provenance.

The solution to this problem is to store provenance logs that track the key
histories of all contributors in the Git repo itself. This makes a repo
self-verifiable; cloning a repo is the PKI operation as well.

[CRYPTID]: https://cryptid.tech/
[MULTIFORMATS]: https://github.com/multiformats/multiformats/
[FSL]: https://github.com/cryptidtech/bs/blob/main/LICENSE.md
[PROVSPECS]: https://github.com/cryptidtech/provenance-specifications/
[PROVREADME]: https://github.com/cryptidtech/provenance-log/blob/main/README.md
[IPNS]: https://docs.ipfs.tech/concepts/ipns/
[NONCE]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/nonce.md
[VLAD]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/vlad.md
[IPFS]: https://ipfs.tech/
