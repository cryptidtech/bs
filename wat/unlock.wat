;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc push functions
  (import "wacc" "_push" (func $push (param i32 i32) (result i32)))

  ;; unlock script function
  (func $main (export "for_great_justice") (param) (result i32)
    ;; Push(<"/entry/">), this clones the current entry, sets the
    ;; "/entry/proof" value to an empty Vec<u8> then serializes the entry to a
    ;; Vec<u8> and pushes that onto the stack. Whether the proof is a digital
    ;; signature or a preimage, this is a necessary data to verify the proof.
    ;; In the digital signature case, the lock script will call check_signature
    ;; to verify the digital signature of the entry using the specified public
    ;; key; this can be a threshold signature or a pubkey signature. In the
    ;; preimage case the lock script will call check_preimage which
    ;; concatenates this data with the proof data H(<"/entry/"> ||
    ;; <"/entry/proof">) and hash it to see if it matches the hash referenced
    ;; by the key passed to check_preimage.
    i32.const 0 i32.const 7 call $push

    ;; "/entry/proof", this data is either a digital signature over <"/entry/">
    ;; or the data to be concatenated with <"/entry/"> and hashed.
    i32.const 7
    i32.const 12
    call $push

    ;; Created Stack
    ;; ┌──────────────────┐
    ;; │ <"/entry/proof"> │
    ;; ├──────────────────┤
    ;; │ <"/entry/">      │
    ;; ├──────────────────┤
    ;; │        ┆         │
    ;; ┆                  ┆

    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                   [NAME]                  [IDX] [LEN]
  (data (i32.const  0) "/entry/"  )       ;;     0     7
  (data (i32.const  7) "/entry/proof"  )  ;;     7     12
)
