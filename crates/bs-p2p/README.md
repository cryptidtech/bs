# BetterSign p2p Network Layer

This crate implements the libp2p networking layer for BetterSign. It is used by
the `bs-bootstrap` public bootstrapping peer application and the BetterSign
`cli` application. If you are writing a new application that needs to talk to
the BetterSign network, you should use the `bs-peer` crate instead. It exposes
a simple, "batteries included", interface to this crate. This crate is the
low-level and detail oriented interface to the BetterSign p2p network.
