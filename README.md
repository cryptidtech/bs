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

When discussing distributed systems we speak of networks or graphs of peers or
nodes connected together with links or identifiers. I choose to use the terms
networks, peers, and links throughout the rest of this documents. A network
consists of peers that have links that reference other peers. The links may
reference the peer, a service provided by a peer, or data stored by a peer. A
link does not necessarily imply an active network connection but does imply
that one will be created when the link is used to execute the distributed
functions of the network.

All distributed systems are chaotic in nature meaning that the range and trends
in network behavior observed over time are impossible to predict from the
current conditions. However, distributed systems may be categorized into two
buckets based on their long-term stability and resilience in the face of the
corrosive effects of time on the ephemeral nature of digital systems. One
category—*unstable* systems—are those that exist but due to the set of their
peer and link characteristics they are *not* biased towards stability and never
achieve *metastability*. These unstable systems often have many small localized
networks of peers but they never seem to conglomerate together into a single
long-term network that includes most of the peers. You never get **THE**
network arrising spontaneously from *unstable* preconditions. The primary
example in this category is the global "Web of Trust". Despite decades old
established standards and market conditions demanding global identity
solutions, we still do not have **THE** web of trust. This is likely due to the
characteristics of pubkey links in the system.

The other category—*metastable* systems—are those build with peer and node
characteristics that bias the chaos towards the accretion of a single stable
network over time. These *metastable* networks start with a set of
preconditions that make **THE** network innevitable from the common usage
patterns of the peer software. The primary example in this category is the
World Wide Web. This is also likely due to th echaracteristics of URL links in
the system.

One key insight that comes from comparing pubkey links with URL links is that
pubkeys links can only be in one of two states—*valid* or *invalid*—while URLs
typically can be in one of three states—*valid*, *invalid* or *partially
valid*. URLs in the World Wide Web have a *partially valid* third state where
the full URL (e.g. https://example.com/foo/bar/baz) is invalid but the domain
name portion alone (e.g. https://example.com/) is valid. More importantly, the
URL with just the domain name has a much longer life span of validity and
because most web sites have a content discovery mechansim (i.e. search) built
into the home page, it is very often possible to take a partially valid URL and
restore it back to a valid URL. A simple example is this: you have an invalid
link to a product on Amazon so instead of giving up, you shorten the URL to
just https://amazon.com and you use the search to either find the new link to
the product or you find URLs other similar products. The net effect is that
what appears to be an invalid URL is often just a partially invalid URL that is
restorable to a valid URL. URLs on the World Wide Web form a kind of
"restorable" link in the distributed system that biases the whole network
towards the formation of **THE** World Wide Web. 

In contrast, pubkey link in the Web of Trust do not have a *partially valid*
state and are therefore never "restorable" to a valid state without some other
communication external to the network. More importantly, once a pubkey becomes
invalid, there is no secure way—short of in-person interaction—to communicate a
new valid link in a trustworthy way. This lack of restorable links I think is
the primary reason why **THE** Web of Trust does not exist.

Imagine if the World Wide Web used domain names that changed to new, random
values often. What if "amazon.com" changed to a random string of characters
every few weeks or months. So this week the Amazon website is at
"https://f332a87bb7375ae2" and several weeks later it is at
"https://8bee21d435df4434". The World Wide Web as we know it would cease to
exist simply because the links are not valid long enough for **THE** World Wide
Web to hold together as a metastable network. This single observation suggests
that distributed systems using public keys as links do not trend towards
metastability. I think this is the primary reason why we have *THE* World Wide
Web, but we do not have *THE* Web of Rrust nor even *THE* p2p Network.

### Don't Use Public Keys as Links

Public key pairs are subject to attack and compromise in a number of ways
necessitating regular rotation and occassional recovery to ensure a high degree
of security and resiliency. Using public keys as links means that whenever a
key is rotated or revoked, any external references using the public key link
becomes invalid. Using public keys as links creates tightly coupled and fragile
distributed systems.

Why do we use public keys as links? The answer is that they are a compact and
convenient value with two primary properties:

1. Public keys have enough entropy that collisions between randomly generated
   keys are all but impossible.
2. A public key is a cryptographic commitment to a validation function (e.g.
   public key digital signature) that can be used to verify other data and bind
   ownership of that other data to the controller of the public key pair.

It is plain to see that public keys solve the problem of cryptographically
enforced proof-of-control while also being collision resistent even with
uncoordinated random generation. However their vulnerability to attack and
compromise makes them bad links for distributed systems that wish to form
long-term metastable networks without any fixed infrastructure. Key rotation is
good security hygiene. It is also the primary reason why the Web of Trust built
on GPG isn't metastable.

### A Better Identifer

Given the two primary properties of public keys listed above, it is conceivable
that another type of identifer can be constructed with those same properties
while also lacking the vulnerabilities and limited time durability. All we have
to do is construct a tuple identifer from a large random value—commonly called
a nonce—and a cryptographic commitment to a validation function. By combining
content addressable storage and WASM as universally executable code, any WASM
code that validates data using cryptography may be hashed to create a content
address (e.g. CID) that is both an immutable identifier for retrieving the WASM
code but also a cryptographic verification method to ensure that the WASM code
has not been modified at all.

Combining the nonce and the content address of a WASM validation function gives
us an identifier that is both unique and also a cryptographic commitment to a
validation function; the same set of properties as public keys. However this
new identifer is not based off of key material and is not subject to compromise
resulting in an identifier that remains valid and unchanged over long periods
of time. Any change in the WASM code is detectable. Any change in the nonce
creates a different identifier. The only way for one of these new identifiers
to remain relevant over time is to remain unchanged.

Generalizing this idea to being a nonce combined with a content address (CID)
gives us a new identifier called a "Verifiable Long-lived ADdress" or
[VLAD][VLAD].

When using a VLAD to identify an arbitrary piece of data, the CID in the VLAD 
must refer to WASM code that, when executed, verifies the validity of the data 
and/or any updates to the data. If the WASM code is used to verify updates to
the data then VLADs used as keys in a distributed hash table (DHT) work
similarly to how public keys work in the [IPNS DHT][IPNS]. Think of this as
IPNS version 3. Below is an illustration of this theoretical IPNSv3 structure:

```
╔══════════════════════════════════[ IPNSv3 ]══════════════════════════════════╗
║                                                                              ║
║  ╭────────────────────────[Distributed Hash Table]────────────────────────╮  ║
║  │                                                                        │  ║
║  │ ╭─[VLAD]──┬────────────╮                           ╭─[Mutable Value]─╮ │  ║
║  │ │ <nonce> │ <WASM CID> │ ──────── maps to ───────ᐳ │      <CID>      │ │  ║
║  │ ╰─────────┴───┬────────╯                           ╰────────┬────────╯ │  ║
║  │               │                                             │          │  ║
║  ╰───────────────│─────────────────────────────────────────────│──────────╯  ║
║                  │                                             │             ║
║                  │                                             │             ║
║                  │                                             │             ║
║                  │                                             │             ║
║             references                                    references         ║
║  ╭───────────────│─────────────────────────────────────────────│──────────╮  ║ 
║  │               ᐯ                                             ᐯ          │  ║
║  │ ╭─[WASM]─────────╮                               ╭─[Data]────────────╮ │  ║
║  │ │ (module        │                               │ 10010111010100100 │ │  ║
║  │ │   (func $main  │                               │ 00110111100011110 │ │  ║
║  │ │     return     │                               │ 11101101101010011 │ │  ║
║  │ │   )            │                               │ 11111010011010001 │ │  ║
║  │ │ )              │                               │ 01101101000100001 │ │  ║
║  │ ╰────────────────╯                               ╰───────────────────╯ │  ║
║  ╰───────────────────────[Content Addressable Storage]────────────────────╯  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

When using a VLAD to identify a provenance log, the CID in the VLAD is the 
content address of the WASM lock script for validating the first entry in the 
provenance log and the nonce in the VLAD is a detached digital signature over
the CID created with the ephemeral key pair used to self-sign the first entry.
Preferably the digital signature is an ECDSA/EdDSA signature for compactness
but in high security applications a one-time Lamport signature is used. This
increases the size of the VLAD to just over 8KB in size but is quantum
resistant. 

Provenance log VLADS are useful in a DHT for mapping VLADs to the CID of the
current head of the provenance log. Because provenance logs handle validation
of the next entry in the log by themselves, the CID in the VLAD points to the
WASM lock script used to validate the first entry of the provenance log. This 
allows the VLAD to translate into both the latest entry in the provenance log—
and thus the whole provenance log—as well as the WASM lock script to validate 
the first entry of the provenance log. The first entry of the provenance log 
contains the ephemeral public key to verify the digital signature in the VLAD
and confirm that the CID to the WASM lock script hasn't changed. This gives a
closed loop verification that cryptographically binds the VLAD to the
provenance log at both the first and most recent entry. When updating the
mutable value in the DHT, the DHT PUT contains just the CID of the new head
entry for the provenance log. Since the DHT already contains the CID of the
current head, it will go through the normal provenance log validation check and
attempt to validate the new entry. If the validation succeeds, then the new CID
is stored as the value associated with the VLAD. If not, the DHT value is not
updated.

```
╔═════════════════════════[ Provenance Log and VLAD ]══════════════════════════╗
║                                                                              ║
║  ╭────────────────────────[Distributed Hash Table]────────────────────────╮  ║
║  │                                                                        │  ║
║  │ ╭─[VLAD]──────┬──────────────╮                     ╭─[Mutable Value]─╮ │  ║
║  │ │ <Sig Over> ───ᐳ <WASM CID> │ ───── maps to ────ᐳ │      <CID>      │ │  ║
║  │ ╰─────────────┴────────────┬─╯                     ╰─┬───────────────╯ │  ║
║  │          ᐱ                 │                         │                 │  ║
║  ╰──────────│─────────────────│─────────────────────────│─────────────────╯  ║
║             │  ╭─ references ─╯                         ╰ references ╮       ║
║             │  │                                                     │       ║ 
║             ├──── validates ──╮                                      │       ║ 
║  ╭──────────│──│──────────────│──────────────────────────────────────│────╮  ║ 
║  │          │  ᐯ              │                                      ᐯ    │  ║
║  │ ╭─[WASM]─┴───────╮         │      ╭─[Foot]────────╮  ╭─[Head]────────╮ │  ║
║  │ │ (module        │         │      │ Seqno 0       │  │ Seqno 1       │ │  ║
║  │ │   (func $main  │         │      │ Prev NULL     │ᐸ── Prev          │ │  ║
║  │ │     return     │         ╰─────── Eph. Pubkey   │  │               │ │  ║
║  │ │   )            │ ─ validates ─ᐳ │               │  │               │ │  ║
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
by two multiformat encoded values, a nonce (e.g. `0x3b`) or a multisig (e.g.
`0x39`) followed by a content addres CID (e.g. `0x01` v1, `0x02` v2, or `0x03`
v3). Below are examples of different VLADs.

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

A "signature" VLAD consisting of a multisig encoded signature and CID looks
like:

```
             WASM content
vlad sigil     address 
 │                │
0x07 <multisig> <cid>


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
public keys into "restorable" links binding a global web of trust together
using provenance logs to store key histories and VLADs as the long-lived
identifier for the provenance log.

The steps for creating the first entry in a provenance log are as follows:

#### VLAD Creation

1. Create/select the WASM lock script to use for validating the first entry in 
   the provenance log and hash it to get its CID.
2. Generate an ephemeral cryptographic public key pair. Use one-time Lamport
   keys for quantum resistance.
3. Create a detached digital signature of the WASM lock script CID using the
   ephemeral key pair.
4. Encode the digital signature in the multisig multiformat and reate a VLAD
   with the multisig and the WASM CID values.

#### First Entry Creation (Non-forked)

1. Generate a new public key pair to advertise as the current signing key in
   the provenance log. Optionally, you may want set up a Lamport threshold
   signature group, giving key shares to each of the trusted group members.
   Setting up the lock script with the threshold signature has the highes
   precedence allows "social recovery" of provenance log control should your
   signing key be compromised.
2. Create the first entry setting the "vlad" field to the newly constructed
   VLAD value.
3. Set the "prev" and "lipmaa" fields to NULL.
4. Sets the "seqno" field to 0.
5. Add an update operation to the "ops" list that sets `/pubkey` to the public
   key value to the public key generated in step 1 encoded in the multikey
   format. Optionally add an update operation taht sets the `/tpubkey` to the
   threshold public get generated in step 1. Also add an update operations that
   sets the values for anything else related to the use of this provenance log.
   There must be an update operation setting the `/ephemeral` value to the
   ephemeral public key generated when creating the VLAD.
6. Add the `/` WACC WASM lock script that checks the conditions that the next
   entry in the log must meet to be valid. Add in any other WASM lock scripts
   for any other branches/leaves in the key-value pair store.
7. Set the "unlock" field to the WACC WASM script that uses the data in the
   first entry of the provenance log to satisfy the WASM lock script referenced
   by the VLAD CID.
8. Calculate a digital signature over the entire entry.
9. Encode the digital signature in the multisig multiformat and assign the
   value to the "proof" field in the entry.
10. DESTROY THE EPHEMERAL PRIVATE KEY USING APPROPRIATE DELETION METHODS.
11. Calculate the content address for the first entry and encode it as a CID.
12. Store the first entry in a content addressable storage system appropriate
    for the context in which the provenance log identity will have meaning. If
    this is intended to be an internet identity, store it in a globally
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
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats/
[FSL]: https://github.com/cryptidtech/bs/blob/main/LICENSE.md
[PROVSPECS]: https://github.com/cryptidtech/provenance-specifications/
[PROVREADME]: https://github.com/cryptidtech/provenance-log/blob/main/README.md
[IPNS]: https://docs.ipfs.tech/concepts/ipns/
[NONCE]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/nonce.md
[VLAD]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/vlad.md
[IPFS]: https://ipfs.tech/
