# Example WAST Scripts

This folder contains example lock and unlock scripts in WASM text format. The
unlock script compiles the signed message and pushes the proof on the stack to
set up for the lock script. The lock script does the standard version, 
threshold signature, pubkey signature, and preimage checks.
