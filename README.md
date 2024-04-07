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

The current web-of-trust and global PKI systems are too fragile and not
ubiquitous enough to create a global regime for transmitting trust through time
and space. The problem is that the current systems were designed without the
element of time and therefore without the ability to prove the history of
control and modification of any digital data. With the creation of blockchains
and distributed consensus popularizing the idea of immutable records of
transactions over time, we've learned the value of keeping track of provenance
regardless of the unlimited time span and unbounded memory requirement.

To finally improve the global PKI system, it seems logical to start from
scratch and construct an identity solution based entirely off of a provenace
logging structure. It also is apparent that identity based transactions are
either 1-party or 3-party transactions and therefore do not require distributed
consensus to have trustful 2-party transactions. This opens the door for
provenance logs that are 1st party self-assertions that grow in trust by
recording proofs of work (i.e. content creation of all kinds or verifiable acts
of service) in their provenence logs. Similarly, provenance logs may grow in
trust by recording 3rd party proofs from multiple trustworthy societal
institutions or organizations. Because of the general nature of provenance logs
it is possible to have a mix of both 1st party and 3rd party proofs to grow the
trust of a given provenance log. In the end, this solution is very good at
overcoming the anolog-to-digital problem of encoding trust. The security rests
in the statistical improbability of corrupting and/or falsifying proof from an
increasing number of trustworth insitutions. This corroboration based security
model gives statistical assurances of trust and is the natural trust model for
provenance logs designed to accumulate proofs over time.

Provenance logs are a form of time-based log with the added feature of
cryptographically enforced write priviledges. By borrowing the idea of lock and
unlock scripts from Bitcoin, each entry in a provenance log has a set of
cryptographic conditions—encoded as a lock scripts—that the next entry must
satisfy—by providing an unlock script and proofs—to be valid. The details of
this mechanism is described in detail in the [provenance log
specification][PROVSPEC] and the [provenance log implementation
README][PROVREADME].

One perpetual challenge in distributed identity systems is the identifiers used
to refer to an entity in the system. GPG uses public keys and key fingerprints.
Newer systems have been adopting DIDs which ultimately rest on public keys.
What follows is a discussion about identifiers, lessons learned, and a new
system invented specifically for a new provenance log based identity system.

### Don't Use Public Keys as Identifiers

One of the greatest failings of the current web-of-trust is the use of public 
keys as identifiers. Public key pairs are subject to attack and compromise in a
number of ways necessitating regular rotation and occassional recovery to
ensure a high degree of security and resiliency. Using public keys as
identifiers means that whenever a key is rotated or revoked, any external
references using the public key identifier becomes broken. Using public keys
as identifiers creates tightly coupled and fragile distributed systems.

Why do we use public keys as identifiers? The answer is that they are a compact
and convenient value with two primary properties:

1. Public keys have enough entropy that collisions are all but impossible.
2. A public key is a cryptographic commitment to a validation function (e.g.
   public key digital signature) that can be used to verify other data and
   bind ownership of that other data to the controller of the public key pair.

It is plain to see that public keys solve the problem of cryptographically
enforced proof-of-control while also being great random identifiers. However
their vulnerability to attack and compromise makes them bad identifers for
distributed systems that require loose coupling and resiliency over large spans
of time. Key rotation is good security hygiene. It is also the primary reason
why the web-of-trust isn't anti-fragile.

Imagine if the web used domain names and URLs that changed often. What if
"amazon.com" changed to a random string of characters every few weeks or
months. The world wide web as we know it would cease to exist simply because
the linking between computers—the URLs themselves—are no longer valid long
enough for the single web to hold together as a network. This single
observation suggests that distributed systems that use public keys as the links
between computers do not trend towards stability. I think this is the primary
reason why we have *THE* web, but we do not have *THE* web of trust nor *THE*
p2p network.

### A Better Identifer

Given the two primary properties of public keys listed above, it is conceivable
that another type of identifer can be constructed with those same properties
while also lacking the vulnerabilities and limited time durability. All we have
to do is construct a tuple identifer from a large random value—commonly called
a nonce—and a cryptographic commitment to a validation function. By combining
content addressable storage and WASM as universally executable code, any WASM
code that validates data using cryptography may be hashed to create a content
address that is both an immutable identifier for retrieving the WASM code but
also a cryptographic verification method to ensure that the WASM code has not
been modified and retains its original form down to the bit.

Combining the nonce and the content address of a WASM validation function gives
us an identifier that is both unique and a cryptographic commitment to a
validation function; the same set of primary properties as public keys. However
this new identifer is not based off of key material and is not subject to
compromise resulting in an identifier that remains valid and unchanged over
long periods of time. Any change in the WASM code is detectable. Any change in
the nonce creates a different identifier. The only way for one of these new
identifiers to remain relevant over time is to remain unchanged.

Generalizing this idea to being a nonce combined with a content address (CID)
gives us a new identifier called a "Verifiable Long-lived ADdress" or "VLAD".

When using a VLAD to identify an arbitrary piece of data, the CID in the VLAD 
must refer to WASM code that, when executed, verifies the validity of the data 
and/or any updates to the data. If the WASM code is used to verify updates to 
the data then VLADs used as keys in a distributed hash table (DHT) work 
similarly to how public keys work in the [IPNS DHT][IPNS]. Think of this as 
IPNS version 3. Below is an illustration of this theoretical IPNSv3 structure:

```
╭────────────────────────────[IPNSv3]────────────────────────────╮
│                                                                │
│ ╭─[VLAD key]─┬────────────╮                  ╭─[CID value]───╮ │
│ │   <nonce>  │ <WASM CID> │ ───────────────→ │ <mutable CID> │ │
│ ╰────────────┴─┬──────────╯                  ╰─────┬─────────╯ │
│                │                                   │           │
╰────────────────│───────────────────────────────────│───────────╯
╭────────────────│─[Content Addressable Storage]─────│───────────╮
│                │                                   │           │
│ ╭─[WASM Code]──┴────╮                    ╭─[Data]──┴─────────╮ │
│ │ (module           │                    │ 10010111010100100 │ │
│ │   (func $main     │                    │ 00110111100011110 │ │
│ │     return        │ ──── validates ──→ │ 11101101101010011 │ │
│ │   )               │                    │ 11111010011010001 │ │
│ │ )                 │                    │ 01101101000100001 │ │
│ ╰───────────────────╯                    ╰───────────────────╯ │
│                                                                │
╰────────────────────────────────────────────────────────────────╯
```

When using a VLAD to identify a provenance log, the CID in the VLAD is the 
content address of the WASM lock script for validating the first entry in the 
provenance log and the nonce in the VLAD is a detached digital signature over
the CID created with the ephemeral key pair used to self-sign the first entry.
Preferably the digital signature is an ECDSA/EdDSA signature for compactness.
The signature has the same amount of entropy as a random nonce but has the
added benefit of allowing the creator of the VLAD to prove they created it.

Provenance log VLADS are useful in a DHT for mapping VLADs to the CID of the
current head of the provenance log. Because provenance logs handle validation
of the next entry in the log by themselves, the CID in the VLAD points to the
WASM lock script used to validate the first entry of the provenance log. This 
allows the VLAD to translate into both the latest entry in the provenance log—
and thus the whole provenance log—as well as the WASM lock script to validate 
the first entry of the provenance log. The first entry of the provenance log 
contains the ephemeral public key to verify the digital signature in the VLAD 
nonce and confirm that the CID to the WASM lock script hasn't changed.

```
╭────────────────────────────[IPNSv3]────────────────────────────╮
│                                                                │
│ ╭─[VLAD key]─┬────────────╮                  ╭─[CID value]───╮ │
│ │ <Multisig> │ <Plog CID> │  ─────────────→  │ <mutable CID> │ │
│ ╰────────────┴─┬──────────╯                  ╰──────────────┬╯ │
│                │                                            │  │
╰────────────────│────────────────────────────────────────────│──╯
╭────────────────│─[Content Addressable Storage]──────────────│──╮
│                │                                            │  │
│ ╭─[Lock WASM]──┴╮               ╭─[First]────╮   ╭─[Latest]─┴╮ │
│ │ (module       │               │ Prev Null  │ ←── Prev      │ │
│ │   (func $lock │               │ Seqno 0    │   │ Seqno: 1  │ │
│ │     return    │ ─ validates → │ Lock ────────→ │           │ │
│ │   )           │               │            │   │           │ │
│ │ )             │               │            │   │           │ │
│ ╰───────────────╯               ╰────────────╯   ╰───────────╯ │
│                                                                │
╰────────────────────────────────────────────────────────────────╯
```

#### Encoding

To reduce the tight binding and fragility of VLADs, they are encoded using the
emerging multiformats standard. A VLAD therefore begins with the multicodec
sigil identifying itself as a VLAD (e.g. `0x07`) followed by two multiformat
encoded values, a nonce (e.g. `0x3b`) or a multisig (e.g. `0x39`) followed by a
content addres CID (e.g. `0x01` v1, `0x02` v2, or `0x03` v3). Below are
examples of different VLADs.

A nonce is encoded using the multicodec sigil `0x3b` followed by a varuint
specifying the number of octets in the nonce followed by the nonce octets; like
so:

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
0x07 <nonce> <CID>
 │             │
VLAD      WASM content
sigil       address
```

A "signature" VLAD consisting of a multisig encoded signature and CID looks
like:

```
                   WASM content
vlad sigil           address 
 │                      │
0x07 <multisig nonce> <cid>
            │
  nonce wrapped multisig

<multisig nonce> ::= 0x3b <varbytes>
                     ╱
          nonce sigil

<varbytes> ::= <varuint> <multisig octets>
                  ╱              │
          count of          variable number
            octets         of multisig octets
```

### VLADs as Used with Provenance Logs 

The construction of a new provenance log consists of a series of steps to 
ensure that the first entry in the provenance log bind together all of the 
necessary parts for a provenance log based global PKI system to function while 
also ensuring that nobody can forge a valid competing first entry. VLADs are 
the identifier used in this new PKI regime. They not only refer to its
associated provenance log but they also serve as identifier in the more 
dynamic global distributed hash table (DHT) used to provide mutable forward 
references that always point at the most recent entry in a provenance log.

It is important to point out that the VLAD associated with a provenance log
will stay the same for the entire lifespan of the provenance log. This means it
is a perfect long-lived identifier for identifying the person or process that
controls the provenance log. Mapping the VLAD to the provenance log is the job
of mutable forward pointer and the provenance log contains the accumulated
state associated with the identity.

The steps for creating the first entry in a provenance log are as follows:

#### VLAD Creation

1. Create/select the WASM lock script to use for validating the first entry in 
   the provenance log and get its CID.
2. Generate an ephemeral cryptographic public key pair.
3. Create a detached digital signature of the WASM lock script CID using the
   ephemeral key pair.
4. Encode the digital signature in the multisig multiformat and initialize a 
   nonce multiformat value with it. Create a VLAD with the nonce and CID
   values.

#### First Entry Creation 

1. Generate a new public key pair that will be the first key pair advertised by 
   the provenance log.
2. Create the first entry setting the "vlad" field to the newly constructed
   VLAD value.
3. Set the "prev" and "lipmaa" fields to NULL.
4. Sets the "seqno" field to 0.
5. Add an update operation to the "ops" list that sets `/pubkey` to the public 
   key value to the public key generated in step 1 encoded in the multikey
   format. Also add an update operations that sets the values for anything else
   related to the use of this provenance log. There must be an update operation
   setting the `/ephemeral` value to the ephemeral public key generated when
   creating the VLAD.
6. Add the `/` WACC WASM lock script that checks the conditions that the next
   entry in the log must meet to be valid. Add in any other WASM lock scripts
   for any other namespaces/leaves in the key-value pair store.
7. Set the "unlock" field to the CID of the WACC WASM script that uses the data
   in the first entry of the provenance log to satisfy the WASM lock script 
   referenced by the VLAD CID.
8. Calculate a digital signature over the "vlad", "prev", "lipmaa", "seqno", 
   "ops", "lock" and "unlock" fields using the ephemeral key pair used in the 
   creation of the VLAD.
9. Encode the digital signature in the multisig multiformat and assign the value 
   to the "proof" field in the entry.
10. DESTROY THE EPHEMERAL PRIVATE KEY USING APPROPRIATE DELETION METHODS.
11. Calculate the content address for the first entry and encode it as a CID.
12. Store the first entry in a content addressable storage system appropriate
    for the context in which the provenance log identity will have meaning. If 
    this is intended to be an internet identity, store it in a globally
    readable content addressable storage network.
13. Add the CID for the first entry as the value associated with the VLAD in 
    the VLAD to CID mapping system used for this application.

The first entry in the provenance log is self-signed by an ephemeral key pair 
that is destroyed immediately after its use in signing the first entry and
creating the VLAD. This prevents anybody else from creating a validly signed
first entry and VLAD by compromising the ephemeral key pair. The first entry
contains the ephemeral public key used to verify the self-signature over the
first entry created with the ephemeral key pair. It is also used to validate
the signature portion of the VLAD.

### Key Rotation in Provenance Logs 

At some point in the future, the advertised public key must be rotated. This is 
done simply by doing the following:

1. Generate a new public key pair.
2. Create a new provenance log entry and fill in the "vlad", "prev", "lipmaa",
   "seqno", "ops", "lock" and "unlock" fields appropriately. The "ops" list
   must contain an update operation that sets the "pubkey" value to the new
   advertised public key encoded in multikey format.
3. Generate the proof required to satisfy the conditions of the lock script in
   the previous entry that governs the `/pubkey` leaf in the key-value store.
4. Calculate the content address for the new entry and encode it as a CID.
5. Store the new entry in the content addressable storage along with the 
   previous entries in the provenance log.
6. Submit the VLAD and CID of the new entry to the VLAD mapping service. It 
   will attempt to validate the new entry and if it does validate, the VLAD 
   mapping service will update the CID value to the new CID.

### Key Revocation in Provenance Logs 

By convention there is a primary advertised public key stored under the
`/pubkey` key in the virtual key-value store associated with the provenance
log. There is no limitation to the number of advertised public keys or any
other data associated with the provenance log and the identity it represents.

Key rotation for any advertised public key effectively revokes the previously 
advertised public key. However there are cases where an explicit key revocation 
is desired; usually due to a compromised key pair. To signal an explicit 
revocation, just add a delete operation to the ops list, deleting the public 
key from the virtual key-value store, before adding the new value using an 
update operation. This will signal to others that any signature created using 
the key pair after the creation of this entry cannot be trusted. To ensure 
the correct ordering of events, it is recommended to record the VLAD value in 
a public blockchain as a wallclock timestamp proof and then record the 
URL to the transaction using an update operation in the ops list under the 
`/timestamp` key. A service such as [Open Timestamps][OPENTIMESTAMPS] makes
this a straightforward operation. This allows anybody to prove that the key
revocation happened no later than the wall clock time of the public blockchain
transaction. This is helpful to prove the correct order of events in the
future when the maximum security is required. Typically, the public blockchain 
timestamp is only done when a key is compromised.

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
is a way to automate the difficult task of generating a list of key IDs from
a Git repo and the user downloads the public keys, they can't necessarily trust
that the keys are the real keys used by the commit signers due to a lack of
provenance on those keys.

The solution to this problem is to store the public keys in the Git repo itself
and to track the keys as you would any source code file in the repo. This makes
a repo self-verifiable; cloning a repo is the PKI operation as well. One nice
feature of Git is that commits are stored in a content addresable storage so it 
is natural that provenance log entries are stored in the repo using the 
normal commit process.

[CRYPTID]: https://cryptid.tech/
[PROVENANCE]: https://github.com/cryptidtech/provenance-specifications/
[MULTIFORMATS]: https://github.com/multiformats/multiformats/
[FSL]: https://github.com/cryptidtech/bs/blob/main/LICENSE.md
[PROVSPECS]: https://github.com/cryptidtech/provenance-specifications/
[PROVREADME]: https://github.com/cryptidtech/provenance-log/blob/main/README.md
[IPNS]: https://docs.ipfs.tech/concepts/ipns/
